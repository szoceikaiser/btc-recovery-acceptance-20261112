"""Observation-local immutable cache and fail-closed provider quota headers.

No token introspection or provider support claim. A new job does not create a
new hourly allowance; the installation's aggregate hour model covers all jobs.
"""
from copy import deepcopy
import re
import urllib.error


class QuotaStopped(RuntimeError):
    pass


class Headers:
    def __init__(self):
        self.stopped = False
        self.observations = []

    def before(self):
        if self.stopped:
            raise QuotaStopped('Provider quota stopped this observation')

    def observe(self, headers, status=200):
        # Never retain response bodies, request headers, URLs or credentials.
        headers = headers or {}
        row = {'status': status}
        for name in ('X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Used',
                     'X-RateLimit-Reset', 'X-RateLimit-Resource', 'Retry-After'):
            value = headers.get(name)
            if value is not None:
                value = str(value)
                if len(value) > 80 or not re.fullmatch(r'[A-Za-z0-9 .,:+-]+', value):
                    self.stopped = True
                    raise QuotaStopped('Invalid provider quota header')
                row[name.lower()] = value
        self.observations.append(row)
        for name in ('limit','remaining','used','reset'):
            value=row.get('x-ratelimit-'+name)
            if value is not None and not value.isdigit():
                self.stopped=True
                raise QuotaStopped('Invalid numeric provider quota header')
        remaining = row.get('x-ratelimit-remaining')
        if remaining is not None and (not remaining.isdigit() or int(remaining) == 0):
            self.stopped = True
        # Reset is evidence only: no sleeping, retry, token switch or new deadline.
        if status in (403, 429) or 'retry-after' in row:
            self.stopped = True
            raise QuotaStopped('Provider primary/secondary limit; no retry')


def immutable(route):
    return bool(re.fullmatch(
        r'/repos/[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+/(?:git/(?:commits|blobs)/[0-9a-f]{40}'
        r'|git/trees/[0-9a-f]{40}\?recursive=1|contents/[A-Za-z0-9._/-]+\?ref=[0-9a-f]{40}'
        r'|compare/[0-9a-f]{40}\.\.\.[0-9a-f]{40}\?per_page=1)', route))


def cached(client, route):
    value = getattr(client, 'immutable_cache', {}).get(route)
    return deepcopy(value) if value is not None else None


def remember(client, route, value):
    cache = getattr(client, 'immutable_cache', None)
    if cache is not None and immutable(route):
        from production_contract import canonical
        size=len(canonical(value).encode())
        if size>8*1024*1024: return
        sizes=getattr(client,'immutable_cache_sizes',{})
        while cache and sum(sizes.values())+size>8*1024*1024:
            old=next(iter(cache));cache.pop(old);sizes.pop(old,None)
        cache[route] = deepcopy(value)
        sizes[route]=size;client.immutable_cache_sizes=sizes


def bind(client, token, guard=None):
    import os
    if (not token or token != os.environ.get('GITHUB_TOKEN') or '\n' in token or '\r' in token):
        raise ValueError('Existing automatic GITHUB_TOKEN required')
    client.public_read_token = token
    client.anonymous_reads = False
    client.immutable_cache = {}
    client.quota_headers = guard or Headers()
    client.git_refs = True
    return client


def git_ref(client, repo, branch, opener, timeout, limit):
    """Explicit authenticated read-only Git advertisement; never REST fallback.

    Returned ref is matched exactly; packet bytes, SHA and protocol are checked.
    Git service rate attribution remains a provider acceptance item.
    """
    import base64
    import urllib.request
    from public_access import read_bytes
    if not re.fullmatch(r'[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+',repo) or not re.fullmatch(r'[A-Za-z0-9_-]+',branch):
        raise ValueError('Exact public Git ref scope required')
    client.quota_headers.before()
    request=urllib.request.Request('https://github.com/'+repo+'.git/info/refs?service=git-upload-pack',headers={
        'Authorization':'Basic '+base64.b64encode(('x-access-token:'+client.public_read_token).encode()).decode(),
        'User-Agent':'btc-bound-public-ref','Accept':'application/x-git-upload-pack-advertisement'})
    try: raw=read_bytes(opener,request,timeout,min(limit,2*1024*1024),quota=client.quota_headers)
    except urllib.error.HTTPError as exc:
        client.quota_headers.observe(exc.headers,exc.code)
        raise QuotaStopped('Bound public Git read unavailable') from None
    client._response_bytes=len(raw)
    pos=0;lines=[]
    while pos<len(raw):
        header=raw[pos:pos+4]
        if not re.fullmatch(b'[0-9a-f]{4}',header): raise ValueError('Git packet header')
        size=int(header,16);pos+=4
        if size==0: continue
        if not 4<=size<=65524 or pos+size-4>len(raw): raise ValueError('Git packet size')
        lines.append(raw[pos:pos+size-4]);pos+=size-4
    if not lines or lines.pop(0)!=b'# service=git-upload-pack\n': raise ValueError('Git v0 advertisement required')
    wanted=('refs/heads/'+branch).encode();found=[]
    for row in lines:
        row=row.rstrip(b'\n').split(b'\0',1)[0]
        pin,sep,ref=row.partition(b' ')
        if not sep or not re.fullmatch(b'[0-9a-f]{40}',pin): raise ValueError('Git ref identity')
        if ref==wanted: found.append(pin.decode())
    if len(found)!=1: raise ValueError('Exact Git branch absent/duplicate')
    return {'ref':'refs/heads/'+branch,'object':{'type':'commit','sha':found[0]}}


def raw_file(client, route, expected, opener, timeout, limit):
    """Pinned public raw bytes, requiring an independently supplied content hash."""
    import base64
    import hashlib
    import urllib.parse
    import urllib.request
    from public_access import read_bytes,tail_allowed
    parts=route.split('/',4);tail='/'+parts[4]
    if not tail_allowed(tail) or not tail.startswith('/contents/'): raise ValueError('Pinned raw route')
    u=urllib.parse.urlsplit(tail);pin=urllib.parse.parse_qs(u.query)['ref'][0]
    url='https://raw.githubusercontent.com/'+'/'.join(parts[2:4])+'/'+pin+'/'+u.path.removeprefix('/contents/')
    req=urllib.request.Request(url,headers={'Authorization':'Bearer '+client.public_read_token,'User-Agent':'btc-pinned-public-raw'})
    client.quota_headers.before()
    try: raw=read_bytes(opener,req,timeout,limit,quota=client.quota_headers)
    except urllib.error.HTTPError as exc:
        client.quota_headers.observe(exc.headers,exc.code)
        raise QuotaStopped('Pinned public raw unavailable') from None
    blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    if ((expected.get('blob') and blob!=expected['blob']) or
            (expected.get('sha256') and hashlib.sha256(raw).hexdigest()!=expected['sha256']) or
            not any(expected.values())): raise ValueError('Pinned raw bytes differ')
    client._response_bytes=len(raw)
    return {'type':'file','encoding':'base64','sha':blob,'content':base64.b64encode(raw).decode()}


def read_only_environment():
    import os
    if any(os.environ.get(k) for k in ('BTC_DELIVERY_GITHUB_TOKEN','BTC_HOSTED_BACKUP_WRITE_TOKEN',
            'BTC_HOSTED_RECEIPT_WRITE_TOKEN','TELEGRAM_BOT_TOKEN','BTC_PAGES_STORE_READ_TOKEN',
            'BTC_MONITOR_STORE_READ_TOKEN','BTC_MONITOR_BACKUP_READ_TOKEN')):
        raise ValueError('Writer or obsolete manual reader injection refused')
