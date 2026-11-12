"""Explicit public bindings and bounded automatic-jobtoken rules evidence.

GET repo permissions are deliberately irrelevant. Hidden bypass settings need a
separate sealed human review; public API equality cannot attest hidden drift.
This is an admission check, never repository setup or credential introspection.
"""
import json
import re
import threading
import time
import urllib.parse
from production_contract import digest

HEX = r'[0-9a-f]{40}'
REQUIRED = {'deletion', 'non_fast_forward', 'required_linear_history'}
MAX_PAGES = 4


def read_bytes(opener, request, timeout, limit, headers=None, quota=None):
    """Bound even a trickling public response by the caller's remaining time."""
    done = threading.Event(); values = []
    def work():
        try:
            with opener(request, timeout=timeout) as response:
                if quota is not None: quota.observe(getattr(response,'headers',{}),getattr(response,'status',200))
                if headers is not None:
                    headers['link']=response.headers.get('Link','') if hasattr(response,'headers') else ''
                raw = response.read(limit+1)
                if len(raw)>limit: raise ValueError('Public response byte bound')
                values.append(raw)
        except BaseException as exc: values.append(exc)
        finally: done.set()
    threading.Thread(target=work, daemon=True).start()
    if timeout<=0 or not done.wait(timeout): raise TimeoutError('Public HTTP wall deadline')
    if isinstance(values[0], BaseException): raise values[0]
    return values[0]


def tail_allowed(tail, metadata=False):
    """Finite protocol route grammar; no redirects, arbitrary query or paths."""
    data = [r'', r'/git/ref/heads/[A-Za-z0-9_-]+',
            r'/git/(?:commits|blobs)/'+HEX, r'/git/trees/'+HEX+r'\?recursive=1',
            r'/compare/'+HEX+r'\.\.\.'+HEX+r'\?per_page=1',
            r'/rules/branches/[A-Za-z0-9_-]+\?per_page=100&page=[1-4]',
            r'/rulesets/[1-9][0-9]*']
    if any(re.fullmatch(p,tail) for p in data): return True
    if tail.startswith('/contents/'):
        u=urllib.parse.urlsplit(tail); path=urllib.parse.unquote(u.path[len('/contents/'):])
        parts=path.split('/')
        if (not re.fullmatch(r'[A-Za-z0-9._/-]{1,240}',path) or
                any(p in ('','.','..','.git') for p in parts)): return False
        return bool(re.fullmatch(r'ref='+HEX,u.query))
    if metadata:
        return any(re.fullmatch(p,tail) for p in (
            r'/actions/runs/[1-9][0-9]*',
            r'/actions/runs/[1-9][0-9]*/attempts/1/jobs\?per_page=100&page=1',
            r'/actions/workflows/[a-z-]+\.yml/runs\?per_page=100&page=1&created=[A-Za-z0-9%.:+-]+'))
    return False


def target(access, repo, branch):
    if access.get('schema')!='btc-public-access-v1' or access.get('enabled') is not True:
        raise ValueError('Explicit public access review required')
    t=access['repositories'][repo]
    if (set(t)!={'id','visibility','branches'} or type(t['id']) is not int or t['id']<=0
            or t['visibility']!='public' or branch not in t['branches']
            or not re.fullmatch(r'[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+',repo)
            or not re.fullmatch(r'[A-Za-z0-9_-]+',branch)):
        raise ValueError('Exact public repository ID/branch required')
    return t


def deployment(access, value):
    if value.get('public_access_sha256')!=digest(access):
        raise ValueError('Public review must be pinned in the durable deployment')
    for repo,branch in ((value['private_store_repository'],value['store_branch']),
            (value['private_store_repository'],value['fence_branch']),
            (value['code_repository'],value['code_ref'].removeprefix('refs/heads/'))):
        target(access,repo,branch)


def get(client, repo, tail):
    if hasattr(client,'request'): return client.request('GET',repo,tail)
    return client._request('GET',client._route(repo,tail))


def repository(client, access, repo, branch):
    t=target(access,repo,branch);m=get(client,repo,'')
    if (type(m.get('id')) is not int or m['id']!=t['id'] or m.get('full_name')!=repo
            or m.get('private') is not False or m.get('visibility')!='public'):
        raise ValueError('Actual public repository identity/visibility differs')
    # permissions may be absent, or describe an owner rather than PAT capability.


def review_hash(value):
    return digest({k:v for k,v in value.items() if k!='sha256'})


def exact_protected_targets(access, repo, branch, conditions, ruleset_id, public_sha256):
    """A shared ruleset may cover only individually reviewed protected refs.

    The complete ordered condition object is still pinned by public_sha256.
    No wildcard, default/all-branch marker, exclusion or unreviewed ref allowed.
    """
    if not isinstance(conditions,dict) or set(conditions)!={'ref_name'}: return False
    names=conditions['ref_name']
    if not isinstance(names,dict) or set(names)!={'include','exclude'} or names['exclude']!=[]: return False
    refs=names['include']
    if (not isinstance(refs,list) or not 1<=len(refs)<=4
            or any(not isinstance(ref,str) or not re.fullmatch(r'refs/heads/[A-Za-z0-9_-]+',ref) for ref in refs)
            or len(set(refs))!=len(refs) or 'refs/heads/'+branch not in refs): return False
    for ref in refs:
        name=ref.removeprefix('refs/heads/')
        pin=access.get('protections',{}).get(repo+'@'+name,{})
        if (name not in access['repositories'][repo]['branches'] or pin.get('repository')!=repo
                or pin.get('repository_id')!=access['repositories'][repo]['id'] or pin.get('branch')!=name
                or not re.fullmatch(r'[0-9a-f]{64}',pin.get('active_rules_sha256') or '')
                or pin.get('rulesets',{}).get(str(ruleset_id),{}).get('public_sha256')!=public_sha256): return False
    return True


def protection(client, access, repo, branch):
    t=target(access,repo,branch);p=access['protections'][repo+'@'+branch]
    if (p.get('repository_id')!=t['id'] or p.get('branch')!=branch
            or p.get('repository')!=repo): raise ValueError('Protection review target differs')
    rules=[]
    for page in range(1,MAX_PAGES+1):
        rows=get(client,repo,f'/rules/branches/{branch}?per_page=100&page={page}')
        if not isinstance(rows,list) or len(rows)>100: raise ValueError('Incomplete rules page')
        link=getattr(client,'_response_link','')
        if link:
            if len(link)>4096: raise ValueError('Pagination header byte bound')
            entries=link.split(',')
            for entry in entries:
                match=re.fullmatch(r'\s*<([^>]+)>;\s*rel="(next|prev|first|last)"\s*',entry)
                if not match: raise ValueError('Unreviewable pagination header')
                url,rel=match.groups()
                expected='https://api.github.com/repos/'+repo+'/rules/branches/'+branch+'?per_page=100&page='
                if not url.startswith(expected) or not re.fullmatch('[1-9][0-9]*',url[len(expected):]):
                    raise ValueError('Foreign pagination target')
                if rel=='next' and (len(rows)!=100 or url!=expected+str(page+1)):
                    raise ValueError('Incomplete or changed pagination')
        rules.extend(rows)
        if len(rows)<100: break
    else: raise ValueError('Rules pagination not complete within bound')
    if (not REQUIRED.issubset({r['type'] for r in rules}) or
            digest(rules)!=p.get('active_rules_sha256')):
        raise ValueError('Missing or changed active exact-branch rules')
    if any(r.get('ruleset_source_type')!='Repository' or r.get('ruleset_source')!=repo for r in rules):
        raise ValueError('Foreign or inherited rules require a separate supported review')
    ids={r['ruleset_id'] for r in rules}
    if {str(i) for i in ids}!=set(p['rulesets']): raise ValueError('Ruleset coverage differs')
    if not 1<=len(ids)<=4: raise ValueError('Ruleset count bound')
    for rid in sorted(ids):
        if type(rid) is not int or rid<=0: raise ValueError('Ruleset identity required')
        rs=get(client,repo,'/rulesets/'+str(rid));expected=p['rulesets'][str(rid)]
        # Authenticated GitHub reads add caller-specific presentation metadata.
        # Only the actually observed non-bypass value is admitted; it never
        # replaces the separate reviewed bypass_actors evidence below.
        if 'current_user_can_bypass' in rs and rs['current_user_can_bypass']!='never':
            raise ValueError('Caller bypass capability requires a separate review')
        visible={k:v for k,v in rs.items() if k not in ('bypass_actors','current_user_can_bypass')}
        if (rs.get('id')!=rid or rs.get('target')!='branch' or rs.get('enforcement')!='active'
                or rs.get('source_type')!='Repository' or rs.get('source')!=repo
                or not exact_protected_targets(access,repo,branch,rs.get('conditions'),rid,digest(visible))
                or digest(visible)!=expected.get('public_sha256')):
            raise ValueError('Changed/inactive/foreign ruleset')
        if 'bypass_actors' in rs and rs['bypass_actors']!=[]: raise ValueError('Ruleset bypass refused')
        # Missing bypass_actors is UNKNOWN. It is never converted into [].
        proof=expected.get('bypass_review',{})
        if (proof.get('schema')!='btc-bypass-review-v1' or proof.get('repository')!=repo
                or proof.get('repository_id')!=t['id'] or proof.get('branch')!=branch
                or proof.get('ruleset_id')!=rid or proof.get('public_sha256')!=digest(visible)
                or proof.get('bypass_actors')!=[] or proof.get('status')!='actually-reviewed'
                or not proof.get('reviewer') or not proof.get('reviewed_at')
                or not re.fullmatch(r'[0-9a-f]{64}',proof.get('evidence_sha256') or '')
                or proof.get('sha256')!=review_hash(proof)):
            raise ValueError('Separate actual bypass review unresolved')


def credential(access, role, repo, branches):
    """Sealed setup evidence, never a claim inferred from GET permissions."""
    r=access.get('credential_reviews',{}).get(role,{})
    if (r.get('schema')!='btc-writer-review-v1' or r.get('role')!=role
            or r.get('repository_id')!=access['repositories'][repo]['id']
            or r.get('repositories')!=[repo] or sorted(r.get('branches',[]))!=sorted(branches)
            or r.get('permissions')!={'contents':'write','metadata':'read'}
            or r.get('credential_type') not in ('fine-grained-pat','github-app')
            or r.get('status')!='actually-reviewed' or not r.get('reviewer')
            or not r.get('credential_reference') or not r.get('reviewed_at')
            or r.get('other_repository_write') is not False
            or not re.fullmatch(r'[0-9a-f]{64}',r.get('evidence_sha256') or '')
            or r.get('sha256')!=review_hash(r)):
        raise ValueError('Actual minimal writer setup review unresolved')
    refs=[v.get('credential_reference') for v in access['credential_reviews'].values() if v.get('credential_reference')]
    if len(refs)!=len(set(refs)): raise ValueError('Separate writer identities required')


def check(client, access, bindings, protected=()):
    """Only explicitly requested repos/branches; no discovery or fallback."""
    seen=set()
    for repo,branch in bindings:
        target(access,repo,branch)
        if repo not in seen: repository(client,access,repo,branch);seen.add(repo)
    for repo,branch in protected: protection(client,access,repo,branch)


def preflight(access, bindings, protected, quota=None):
    """Pages setup evidence budget, separate from its unchanged 12 data GETs.

    At most 24 GET / 20 seconds / 48 MiB reserved; automatic jobtoken only.
    Monitor and sender use their existing shared budgets instead.
    """
    from github_delivery import GitHubContentsClient
    from production_confirmation import ProductionContentsClient
    class Reader(GitHubContentsClient):
        open_request=staticmethod(ProductionContentsClient.open_request)
        response_byte_limit=2*1024*1024
        def __init__(self):
            import os
            from job_quota import bind
            super().__init__(os.environ.get('GITHUB_TOKEN'),timeout=3)
            bind(self,os.environ.get('GITHUB_TOKEN'),quota)
            self.count=0;self.started=time.monotonic()
            self.repos={repo for repo,_ in bindings}
        def _request(self,method,route,payload=None):
            left=20-(time.monotonic()-self.started)
            if (method!='GET' or payload is not None or self.count>=24 or left<=0 or
                    not any(route==self._route(r,'') or route.startswith(self._route(r,'/')) for r in self.repos)):
                raise ValueError('Public preflight budget/scope')
            self.count+=1;self.timeout=min(3,left)
            return super()._request(method,route)
    reader=Reader();check(reader,access,bindings,protected)
    return reader.count
