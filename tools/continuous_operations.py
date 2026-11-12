"""Bounded close-only recovery with a durable local SQLite capability.

No stream write, owner takeover, sender, slot replacement or dispatcher. The
next *new* regular Signal/Watch is admitted only by the unchanged runtime gate
plus the explicit recovery marker check. Run under pinned_delivery_entry.py.
"""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time
import urllib.request
import urllib.error
import actions_delivery as actions
import github_delivery as github
import safe_recovery as recovery
from production_contract import canonical,digest

MAX_GET=160

@contextmanager
def database(path):
    db=sqlite3.connect(path,timeout=0)
    try:
        db.execute('PRAGMA synchronous=FULL')
        with db:yield db
    finally:db.close()

class Client(github.GitHubContentsClient):
    """One incident, one fence PUT; reservations survive restart and ambiguity."""
    def __init__(self,token,policy,journal,incident,opener=None,clock=None):
        super().__init__(token,timeout=3)
        recovery.require(re.fullmatch('[0-9a-f]{40}',incident) is not None)
        recovery.require(policy['schema']=='btc-continuous-recovery-v1' and policy['enabled'] is True
            and policy.get('activation_reviewed') is True)
        self.policy=policy;self.path=Path(journal);self.incident=incident;self.clock=clock or time.time
        self.repo=policy['deployment']['private_store_repository'];self.code=policy['deployment']['code_repository']
        self.open_request=opener or no_redirect_transport()
        self.path.parent.mkdir(parents=True,exist_ok=True)
        with database(self.path) as db:
            db.execute('CREATE TABLE IF NOT EXISTS operation (identity TEXT, deadline REAL, gets INTEGER, requests INTEGER)')
            db.execute('CREATE TABLE IF NOT EXISTS reservation (body BLOB, oldblob TEXT, stream TEXT, sent INTEGER)')
            db.execute('CREATE TABLE IF NOT EXISTS evidence (run TEXT, jobs TEXT, old_fence BLOB, stream TEXT)')
            identity=digest({'policy':policy,'incident':incident})
            row=db.execute('SELECT identity FROM operation').fetchone()
            recovery.require(row is None or row==(identity,))
            if row is None:db.execute('INSERT INTO operation VALUES (?,?,0,0)',(identity,self.clock()+900))
    def _request(self,method,route,payload=None):
        store=route==self._route(self.repo,'') or route.startswith(self._route(self.repo,'/'))
        code=route==self._route(self.code,'') or route.startswith(self._route(self.code,'/'))
        if method=='GET':
            recovery.require(payload is None and (store or code))
            tail=route.removeprefix(self._route(self.repo if store else self.code,''))
            if store:
                d=self.policy['deployment']
                recovery.require(tail in ('','/git/ref/heads/'+d['store_branch'],'/git/ref/heads/'+d['fence_branch'])
                    or re.fullmatch(r'/rules/branches/[A-Za-z0-9_-]+\?per_page=100&page=[1-4]',tail)
                    or re.fullmatch(r'/rulesets/[1-9][0-9]*',tail)
                    or re.fullmatch(r'/git/commits/[0-9a-f]{40}',tail)
                    or re.fullmatch(r'/compare/[0-9a-f]{40}\.\.\.[0-9a-f]{40}\?per_page=1',tail)
                    or re.fullmatch(r'/contents/delivery/(stream|actions-fence)\.json\?ref=[0-9a-f]{40}',tail))
            else:
                recovery.require(tail=='' or tail.startswith(('/actions/runs','/contents/.github/workflows/','/compare/','/rules/branches/','/rulesets/')))
        else:
            recovery.require(method=='PUT' and store and route==self._route(self.repo,'/contents/'+actions.FENCE_PATH))
            with database(self.path) as db:
                row=db.execute('SELECT body,oldblob,stream,sent FROM reservation').fetchone()
                recovery.require(row and row[3]==0 and payload['branch']==self.policy['deployment']['fence_branch']
                    and payload['sha']==row[1] and base64.b64decode(payload['content'])==row[0])
                db.execute('UPDATE reservation SET sent=1')
        with database(self.path) as db:
            db.execute('BEGIN IMMEDIATE')
            identity,deadline,gets,requests=db.execute('SELECT * FROM operation').fetchone()
            recovery.require(self.clock()<deadline and gets<MAX_GET and requests<MAX_GET+1)
            db.execute('UPDATE operation SET gets=?,requests=?',(gets+(method=='GET'),requests+1))
        if code:
            # Code metadata is public. The Store writer is NEVER sent there.
            request=urllib.request.Request('https://api.github.com'+route,method='GET',
                headers={'Accept':'application/vnd.github+json','User-Agent':'btc-close-only-recovery'})
            try:
                with self.open_request(request,timeout=3) as response:
                    recovery.require(response.headers.get('X-RateLimit-Resource')=='core'
                        and int(response.headers.get('X-RateLimit-Remaining','0'))>=8)
                    raw=response.read(2*1024*1024+1)
                recovery.require(len(raw)<=2*1024*1024)
                return json.loads(raw)
            except (urllib.error.URLError,OSError,ValueError):
                raise github.StoreUnavailable('Public worker evidence unavailable') from None
        return super()._request(method,route,payload)

def no_redirect_transport():
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):raise OSError('Redirect refused')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    def bounded(request,timeout):
        # Eager bounded response: even a peer trickling bytes cannot prolong a
        # socket timeout forever. Daemon I/O cannot keep a lost runner alive.
        from public_access import read_bytes
        headers={}
        def open_and_capture(req,timeout):
            response=opener.open(req,timeout=timeout)
            for key in ('X-RateLimit-Resource','X-RateLimit-Remaining','Link'):
                value=response.headers.get(key)
                if value is not None:headers[key]=value
            return response
        raw=read_bytes(open_and_capture,request,timeout,2*1024*1024)
        response=io.BytesIO(raw);response.headers=headers
        return response
    return bounded

def worker_evidence(client,run):
    from github_freshness import utc_ms
    meta=client._request('GET',client._route(client.code,'/actions/runs/'+run['id']))
    recovery.require(meta['status']=='completed' and meta['conclusion'] in ('failure','cancelled','success')
        and str(meta['id'])==run['id'] and meta['run_attempt']==1 and meta['run_number']==run['number']
        and meta['path']==run['workflow'] and meta['repository']['full_name']==client.code
        and meta['head_branch']==client.policy['deployment']['code_ref'].removeprefix('refs/heads/'))
    from reviewed_actions_entry import verify
    verify(client,client.code,meta['head_sha'],client.policy['deployment']['code_sha'],run['workflow'],
           client.policy['entry_workflows'][run['workflow']])
    jobs=client._request('GET',client._route(client.code,'/actions/runs/'+run['id']+'/attempts/1/jobs?per_page=100&page=1'))
    recovery.require(1<=jobs['total_count']==len(jobs['jobs'])<=20)
    for job in jobs['jobs']:
        recovery.require(job['status']=='completed' and str(job['run_id'])==run['id'] and job['run_attempt']==1
            and job['head_sha']==meta['head_sha'] and job.get('completed_at')
            and 'self-hosted' not in job['labels'] and 'ubuntu-24.04' in job['labels']
            and utc_ms(job['completed_at'])<=int(client.clock()*1000))
    for status in ('in_progress','waiting','requested','pending','queued'):
        queued=client._request('GET',client._route(client.code,'/actions/runs?status='+status+'&per_page=100&page=1'))
        items=queued['workflow_runs']
        recovery.require(queued['total_count']==len(items) and len(items)<100)
        own=getattr(client,'self_run',None)
        for item in items:
            recovery.require(own is not None and all(item.get(key)==own[key] for key in
                ('id','head_sha','path','run_attempt')) and item.get('repository',{}).get('full_name')==client.code)
    return meta,jobs

def observe(client):
    d=client.policy['deployment']
    import public_access
    public_access.deployment(client.policy['public_access'],d)
    branches=[(client.repo,d['store_branch']),(client.repo,d['fence_branch'])]
    public_access.check(client,client.policy['public_access'],branches,branches)
    code=[(client.code,d['code_ref'].removeprefix('refs/heads/'))]
    public_access.check(client,client.policy['public_access'],code,code)
    fence_record=client.read(client.repo,d['fence_branch'],actions.FENCE_PATH)
    fence=actions.parse_fence(fence_record,d)
    store=github.read_only(client,client.repo,d['store_branch'],d['store_id'])
    recovery.require(not store.blocked())
    if fence['phase']=='open':
        recovery.require(fence_record['commit_sha']==client.incident)
        recovery.completed(store._envelope,d,fence['run'])
        binding=store.snapshot['control']['health']['successful_runs'][fence['run']['kind']]
        prior=store.read_revision(binding['completion'])
        recovery.require(prior['control']['health']['completion_candidate']==binding['run'])
        meta,jobs=worker_evidence(client,fence['run'])
    else:meta=jobs=None
    return fence_record,fence,store,meta,jobs

def recover(client):
    first=observe(client);record,fence,store,meta,jobs=first
    with database(client.path) as db:reserved=db.execute('SELECT body,oldblob,stream,sent FROM reservation').fetchone()
    if reserved:
        # Even a reservation before actual transport consumes this incident.
        # Only exact persisted bytes and direct parent establish completion.
        recovery.require(record['body']==reserved[0] and store._record['commit_sha']==reserved[2]
            and client.parents(client.repo,record['commit_sha'])==[client.incident])
        recovery.validate(fence,store._envelope,store.confirmed_record())
        return {'state':'recovered-await-fresh-regular-run','writes':0,'fence_commit':record['commit_sha'],
                'stream_commit':store._record['commit_sha'],'historical_run':fence['run']['id']}
    recovery.require(fence['phase']=='open')
    review=dict(old_fence_commit=record['commit_sha'],old_fence_sha256=hashlib.sha256(record['body']).hexdigest(),
        run_sha256=digest(meta),jobs_sha256=digest(jobs),policy_sha256=digest(client.policy),
        confirmed_at_ms=int(client.clock()*1000),workers_terminated=True,run_completed=True)
    candidate=recovery.candidate(fence,store._envelope,store.confirmed_record(),review,secrets.token_hex(16))
    raw=canonical(candidate).encode()
    recovery.require(len(raw)<=actions.MAX_FENCE_BYTES)
    with database(client.path) as db:
        db.execute('BEGIN IMMEDIATE')
        recovery.require(not db.execute('SELECT * FROM reservation').fetchone())
        db.execute('INSERT INTO reservation VALUES (?,?,?,0)',(raw,record['blob_sha'],store._record['commit_sha']))
        db.execute('INSERT INTO evidence VALUES (?,?,?,?)',
            (canonical(meta),canonical(jobs),record['body'],canonical(store.confirmed_record())))
    second=observe(client)
    recovery.require(second[0]==record and second[2]._record==store._record and second[3:]==first[3:])
    payload=dict(message='close-only recovery '+candidate['write_id'],branch=client.policy['deployment']['fence_branch'],
                 sha=record['blob_sha'],content=base64.b64encode(raw).decode())
    try:client._request('PUT',client._route(client.repo,'/contents/'+actions.FENCE_PATH),payload)
    except github.StoreUnavailable:pass
    # Lost reply resolution is the SAME entry path, from actual stored state.
    return recover(client)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy',required=True,type=Path)
    parser.add_argument('--state-dir',type=Path)
    parser.add_argument('--incident-fence')
    parser.add_argument('--github',action='store_true')
    parser.add_argument('--execute',action='store_true')
    parser.add_argument('--result-file',type=Path)
    args=parser.parse_args();policy=json.loads(args.policy.read_bytes())
    if args.github:
        recovery.require(policy.get('enabled') is True and policy.get('activation_reviewed') is True
            and policy['journal']['reviewed'] is True and policy['journal']['seed_commit'])
        recovery.require(digest(policy['deployment'])=='81b176a9cce3822bc5b5daf0d4dad95c154b7b51b528e1d9b6e70954dd8f23a9')
        import github_recovery
        client=github_recovery.Network(policy,os.environ.get('BTC_DELIVERY_GITHUB_TOKEN'),os.environ.get('GITHUB_TOKEN'))
        identity=github_recovery.bind_self(client,os.environ)
        result=github_recovery.run(client,identity)
        if args.result_file:
            with args.result_file.open('x',encoding='utf-8') as out:out.write(canonical(result)+'\n')
        return
    recovery.require(args.state_dir is not None and args.incident_fence is not None)
    recovery.require(re.fullmatch('[0-9a-f]{40}',args.incident_fence) is not None)
    journal=args.state_dir/(args.incident_fence+'.sqlite')
    def emit(value):
        raw=canonical(value)
        if args.result_file:
            # A fresh evidence file, never overwrite earlier operational proof.
            with args.result_file.open('x',encoding='utf-8') as out:
                out.write(raw+'\n');out.flush();os.fsync(out.fileno())
        print(raw)
    if not args.execute:
        emit({'phase':'preview','enabled':policy.get('enabled') is True,'journal':str(journal),
            'write_scope':'one fence close; no stream/owner/send/dispatch','journal_created':False});return
    recovery.require(policy.get('enabled') is True and policy.get('activation_reviewed') is True)
    # The operator policy cannot retarget the production CLI. Synthetic tests
    # exercise the library with their own bindings, never this deployment pin.
    recovery.require(digest(policy['deployment'])=='81b176a9cce3822bc5b5daf0d4dad95c154b7b51b528e1d9b6e70954dd8f23a9')
    # Read only during a later separately approved operational execution.
    token=os.environ.get('BTC_DELIVERY_GITHUB_TOKEN')
    client=Client(token,policy,journal,args.incident_fence)
    emit(recover(client))

if __name__=='__main__':
    try:main()
    except BaseException:
        print('operations phase=recovery reason=blocked_or_unconfirmed; preserve journal; no retry')
        raise SystemExit(20) from None
