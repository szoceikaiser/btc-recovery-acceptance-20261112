"""Bind changing entry commits to immutable production code and reviewed YAML.

No permissive head comparison. A changed entry needs authenticated immutable
workflow bytes AND ancestry of the fixed checkout pin. Clients retain budgets.
"""
import base64
import hashlib
import re
import urllib.parse
import os
import time
from github_delivery import GitHubContentsClient
from production_confirmation import ProductionContentsClient


class EntryReader(GitHubContentsClient):
    """Separate code-only binding budget: 3GET/0write, 6MiB, 20s total."""
    open_request=staticmethod(ProductionContentsClient.open_request)
    def __init__(self,token,repo,quota=None):
        super().__init__(token,timeout=3);self.repo=repo;self.gets=0;self.started=time.monotonic()
        from job_quota import bind
        bind(self,token,quota);self.metadata_routes=True
    def _request(self,method,route,payload=None):
        from public_access import tail_allowed
        tail=route.removeprefix(self._route(self.repo,''))
        left=20-(time.monotonic()-self.started)
        if method!='GET' or payload is not None or self.gets>=3 or left<=0 or not route.startswith(self._route(self.repo,'/')) or not tail_allowed(tail,True):
            raise ValueError('Code-only entry binding budget/scope')
        self.gets+=1;self.timeout=min(3,left)
        result=super()._request(method,route)
        if time.monotonic()-self.started>20: raise ValueError('Entry total deadline')
        return result


def actual(client,repo,ref,code_sha,workflow,workflow_sha256):
    expected={'GITHUB_REPOSITORY':repo,'GITHUB_REF':ref,'GITHUB_RUN_ATTEMPT':'1',
              'GITHUB_WORKFLOW_REF':repo+'/'+workflow+'@'+ref}
    if any(os.environ.get(k)!=v for k,v in expected.items()) or not re.fullmatch('[1-9][0-9]*',os.environ.get('GITHUB_RUN_ID','')):
        raise ValueError('Actual reviewed entry differs')
    value=get(client,repo,'/actions/runs/'+os.environ['GITHUB_RUN_ID'])
    if (str(value['id'])!=os.environ['GITHUB_RUN_ID'] or value['run_attempt']!=1 or value['path']!=workflow
            or value['repository']['full_name']!=repo or value['head_sha']!=os.environ.get('GITHUB_SHA')
            or value['head_branch']!=ref.removeprefix('refs/heads/') or value['event']!=os.environ.get('GITHUB_EVENT_NAME')):
        raise ValueError('Actual immutable run metadata differs')
    verify(client,repo,value['head_sha'],code_sha,workflow,workflow_sha256)


def get(client,repo,tail):
    if hasattr(client,'request'): return client.request('GET',repo,tail)
    return client._request('GET',GitHubContentsClient._route(repo,tail))


def verify(client,repo,entry_sha,code_sha,workflow,workflow_sha256=None):
    if any(not re.fullmatch('[0-9a-f]{40}',v or '') for v in (entry_sha,code_sha)):
        raise ValueError('Immutable entry/code SHA required')
    # Backward compatible strict binding for existing callers without a reviewed
    # workflow digest. New hosted installation always supplies the digest.
    if not workflow_sha256:
        if entry_sha!=code_sha: raise ValueError('Unreviewed changing entry commit')
        return
    if (not re.fullmatch('[0-9a-f]{64}',workflow_sha256) or
            not re.fullmatch(r'\.github/workflows/[a-z-]+\.yml',workflow)):
        raise ValueError('Reviewed workflow path/hash required')
    if hasattr(client,'public_read_token'):
        raw=client.read_pinned(repo,entry_sha,workflow,sha256=workflow_sha256)['body']
        item={'type':'file','encoding':'base64','content':base64.b64encode(raw).decode(),
              'sha':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
    else: item=get(client,repo,'/contents/'+workflow+'?'+urllib.parse.urlencode({'ref':entry_sha}))
    if item.get('type')!='file' or item.get('encoding')!='base64': raise ValueError('Workflow bytes missing')
    raw=base64.b64decode(''.join(item['content'].split()),validate=True)
    blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    if len(raw)>64*1024 or item['sha']!=blob or hashlib.sha256(raw).hexdigest()!=workflow_sha256:
        raise ValueError('Actual entry workflow changed from review')
    if entry_sha!=code_sha:
        value=get(client,repo,'/compare/'+code_sha+'...'+entry_sha+'?per_page=1')
        if (value['base_commit']['sha']!=code_sha or value['merge_base_commit']['sha']!=code_sha
                or value['status'] not in ('ahead','identical')):
            raise ValueError('Entry does not descend from reviewed production code')
