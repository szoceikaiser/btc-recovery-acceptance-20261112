"""GitHub-hosted automatic recovery. Journal CAS, not runner disk, is authority.

No strategy calls or dispatches. Credentials are only injected by a later
approved workflow. All public output is produced by the reviewed loader.
"""
import base64
from copy import deepcopy
import hashlib
import json
import os
import re
import secrets
import time
import urllib.parse
import actions_delivery as actions
import github_delivery as g
import github_recovery_journal as ledger
import safe_recovery as safe
from production_contract import canonical,digest

def locator(record,envelope):
    return dict(adapter='github',repo=envelope['repo'],branch=envelope['branch'],path=g.STORE_PATH,
        store_id=envelope['store_id'],revision=envelope['revision'],commit_sha=record['commit_sha'],
        blob_sha=record['blob_sha'],snapshot_digest=envelope['body_digest'])

class Network(g.GitHubContentsClient):
    """Finite routes, two business writes at most, separately scoped journal."""
    def __init__(self,policy,store_token,metadata_token,opener=None,clock=None):
        super().__init__(store_token,timeout=3)
        from continuous_operations import no_redirect_transport
        self.policy=policy;self.repo=policy['deployment']['private_store_repository']
        self.code=policy['deployment']['code_repository'];self.clock=clock or (lambda:int(time.time()*1000))
        self.open_request=opener or no_redirect_transport();self.journal=None;self.self_run=None
        self.started=time.monotonic();self.bootstrap=0;self.control_puts=0;self.capability=None
        self.metadata=g.GitHubContentsClient(metadata_token,timeout=3);self.metadata.open_request=self.open_request
    def _request(self,method,route,payload=None):
        safe.require(time.monotonic()-self.started<120)
        code=route==self._route(self.code,'') or route.startswith(self._route(self.code,'/'))
        store=route==self._route(self.repo,'') or route.startswith(self._route(self.repo,'/'))
        safe.require(code or store)
        tail=route.removeprefix(self._route(self.code if code else self.repo,''))
        control='/contents/recovery/incidents/' in tail
        if method=='GET':
            safe.require(payload is None)
            if self.journal:self.journal.before_read()
            else:self.bootstrap+=1;safe.require(self.bootstrap<=32)
            if code:
                safe.require(tail=='' or tail.startswith(('/actions/runs','/contents/.github/workflows/','/compare/','/rules/')) or tail.startswith('/rulesets/'))
            else:
                d=self.policy['deployment'];branches=(d['store_branch'],d['fence_branch'],self.policy['journal']['branch'])
                safe.require(tail=='' or tail in tuple('/git/ref/heads/'+b for b in branches)
                    or re.fullmatch(r'/contents/(delivery/(stream|actions-fence)\.json|recovery/incidents/[0-9a-f]{40}\.json)\?ref=[0-9a-f]{40}',tail)
                    or re.fullmatch(r'/git/commits/[0-9a-f]{40}',tail)
                    or re.fullmatch(r'/compare/[0-9a-f]{40}\.\.\.[0-9a-f]{40}\?per_page=1',tail)
                    or tail.startswith(('/rules/branches/','/rulesets/')))
        elif control:
            self.control_puts+=1;safe.require(method=='PUT' and self.control_puts<=8
                and payload['branch']==self.policy['journal']['branch']
                and re.fullmatch(r'/contents/recovery/incidents/[0-9a-f]{40}\.json',tail))
        else:
            safe.require(method=='PUT' and self.capability is not None)
            expected=self.capability
            safe.require(route==self._route(self.repo,'/contents/'+expected['path'])
                and payload['branch']==expected['branch'] and payload['sha']==expected['old']['blob_sha']
                and base64.b64decode(payload['content'])==canonical(expected['body']).encode())
            self.capability=None
        self.timeout=min(3,max(0,120-(time.monotonic()-self.started)))
        if self.journal:self.timeout=min(self.timeout,max(0,(self.journal.deadline-self.clock())/1000))
        safe.require(self.timeout>0)
        self.metadata.timeout=self.timeout
        result=self.metadata._request(method,route,payload) if code else super()._request(method,route,payload)
        safe.require(time.monotonic()-self.started<120)
        if self.journal:safe.require(self.clock()<self.journal.deadline)
        return result

class ContentsJournal:
    def __init__(self,client):self.client=client
    def read(self,path):
        c=self.client
        try:record=c.read(c.repo,c.policy['journal']['branch'],path)
        except g.StoreHTTPFailure as exc:
            if str(exc)=='GitHub store HTTP 404':return None
            raise
        return record['blob_sha'],json.loads(record['body'])
    def cas(self,path,blob,value):
        c=self.client;raw=canonical(value).encode();safe.require(len(raw)<=600*1024)
        payload=dict(message='recovery journal '+value['transaction'],
            branch=c.policy['journal']['branch'],content=base64.b64encode(raw).decode())
        if blob:payload['sha']=blob
        c._request('PUT',c._route(c.repo,'/contents/'+path),payload)

def bind_self(client,environment):
    """Exclude exactly this validated recoveryrun/job, never another writer."""
    from reviewed_actions_entry import verify
    p=client.policy['recovery_entry'];rid=environment['GITHUB_RUN_ID'];attempt=environment['GITHUB_RUN_ATTEMPT']
    safe.require(re.fullmatch('[1-9][0-9]*',rid) is not None
        and p['repository']==client.code and p['code_sha']==client.policy['deployment']['code_sha']
        and p['workflow']=='.github/workflows/recovery.yml'
        and environment['GITHUB_REPOSITORY']==client.code and environment['GITHUB_REF']=='refs/heads/'+p['branch']
        and environment['GITHUB_WORKFLOW_REF']==client.code+'/'+p['workflow']+'@refs/heads/'+p['branch']
        and attempt in ('1','2','3') and environment['GITHUB_JOB']=='recover')
    meta=client._request('GET',client._route(client.code,'/actions/runs/'+rid))
    safe.require(str(meta['id'])==rid and meta['path']==p['workflow'] and meta['run_attempt']==int(attempt)
        and meta['head_sha']==environment['GITHUB_SHA'] and meta['status']=='in_progress'
        and meta['repository']['full_name']==client.code and meta['head_branch']==p['branch'])
    verify(client,client.code,meta['head_sha'],p['code_sha'],p['workflow'],p['workflow_sha256'])
    jobs=client._request('GET',client._route(client.code,'/actions/runs/'+rid+'/attempts/'+attempt+'/jobs?per_page=100&page=1'))
    safe.require(jobs['total_count']==1 and len(jobs['jobs'])==1)
    job=jobs['jobs'][0]
    safe.require(job['name']=='recover' and str(job['run_id'])==rid and job['run_attempt']==int(attempt)
        and job['head_sha']==meta['head_sha'] and job['status']=='in_progress'
        and 'ubuntu-24.04' in job['labels'] and 'self-hosted' not in job['labels'])
    client.self_run={key:meta[key] for key in ('id','path','head_sha','run_attempt')}
    return dict(run_id=rid,attempt=attempt,job_id=str(job['id']),entry=meta['head_sha'])

def inspect(client):
    d=client.policy['deployment'];repo=client.repo
    record=client.read(repo,d['fence_branch'],actions.FENCE_PATH)
    fence=actions.parse_fence(record,d)
    source=client.read(repo,d['store_branch']);envelope=json.loads(source['body'])
    # Parse the actual envelope with the regular adapter before planning.
    parser=g.GitHubStore(client,repo,d['store_branch'],d['store_id'],'read-only','1')
    parser._parse(source)
    return record,fence,source,envelope

def verify_guards(client,fence,envelope):
    import public_access
    from continuous_operations import worker_evidence
    d=client.policy['deployment'];public_access.deployment(client.policy['public_access'],d)
    branches=[(client.repo,d['store_branch']),(client.repo,d['fence_branch'])]
    public_access.check(client,client.policy['public_access'],branches,branches)
    public_access.check(client,client.policy['journal']['public_access'],[(client.repo,client.policy['journal']['branch'])],
                        [(client.repo,client.policy['journal']['branch'])])
    public_access.credential(client.policy['journal']['public_access'],'recovery_journal_write',client.repo,[client.policy['journal']['branch']])
    safe.require(client.policy['journal']['public_access']['credential_reviews']['recovery_journal_write']['credential_reference']
        ==client.policy['journal']['credential_reference'])
    safe.receipts(envelope['snapshot'])
    owner=envelope['snapshot']['control']['owner']
    if owner is None:
        safe.completed(envelope,d,fence['run'])
        store=g.read_only(client,client.repo,d['store_branch'],d['store_id'])
        safe.require(store._envelope==envelope)
        completed=store.snapshot['control']['health']['successful_runs'][fence['run']['kind']]
        prior=store.read_revision(completed['completion'])
        safe.require(prior['control']['health']['completion_candidate']==completed['run'])
    else:safe.require(safe.owner_matches(owner,fence['run'],d))
    return worker_evidence(client,fence['run'])

def confirmed_write(client,journal,key,old,body,path,branch,stream_head):
    """Reserve once on the server, then independently resolve saved state."""
    state=journal.read()[1];reservation=state['writes'].get(key)
    if reservation:
        safe.require(reservation['body']==body and reservation['old']==old)
    else:
        reservation=journal.reserve_write(key,old,body)
        # Reconfirm actual heads immediately before the sole business PUT.
        current=client.read(client.repo,branch,path)
        stream=client.read(client.repo,client.policy['deployment']['store_branch'])
        safe.require(all(current[key]==value for key,value in old.items()) and stream['commit_sha']==stream_head)
        client.capability=dict(path=path,branch=branch,old=old,body=body)
        payload=dict(message='reviewed recovery '+key,branch=branch,sha=old['blob_sha'],
                     content=base64.b64encode(canonical(body).encode()).decode())
        try:client._request('PUT',client._route(client.repo,'/contents/'+path),payload)
        except g.StoreUnavailable:pass
    saved=client.read(client.repo,branch,path)
    safe.require(saved['body']==canonical(body).encode() and saved['commit_sha']!=old['commit_sha']
        and client.parents(client.repo,saved['commit_sha'])==[old['commit_sha']])
    safe.require(client.read(client.repo,branch,path)==saved)
    if reservation.get('status')!='confirmed':journal.confirm(key,{k:v for k,v in saved.items() if k!='body'})
    return saved

def run(client,identity):
    """Discover current incident; each source worker gets one immutable fence key."""
    journal_config=client.policy['journal']
    safe.require(journal_config['repository']==client.repo and journal_config['branch']=='recovery-journal-live'
        and journal_config['reviewed'] is True
        and journal_config['credential_reference']=='github-fine-grained-pat:21186996'
        and journal_config['required_permissions']=={'contents':'write','metadata':'read'})
    ref=client._request('GET',client._route(client.repo,'/git/ref/heads/'+journal_config['branch']))
    safe.require(client.is_ancestor(client.repo,journal_config['seed_commit'],ref['object']['sha']))
    f,fence,s,envelope=inspect(client)
    proof=(fence.get('completion') or {}).get('recovery')
    if fence['phase']=='closed' and proof is None:return {'phase':'no-open-incident','writes':0}
    incident=proof['old_fence_commit'] if proof else f['commit_sha'];deadline=client.clock()+900000
    transport=ContentsJournal(client)
    existing=transport.read('recovery/incidents/'+incident+'.json')
    if existing:deadline=existing[1]['deadline_ms']
    journal=ledger.Journal(transport,incident,digest(client.policy),deadline,client.clock)
    journal.acquire(identity);client.journal=journal
    state=journal.read()[1];plan=state['plan']
    if fence['phase']=='closed':
        safe.require(plan and state['writes'].get('fence',{}).get('body')==fence
            and client.parents(client.repo,f['commit_sha'])==[incident])
        safe.validate(fence,envelope,locator(s,envelope))
        if state['writes']['fence']['status']!='confirmed':journal.confirm('fence',{k:v for k,v in f.items() if k!='body'})
        return dict(phase='already-confirmed-no-write',stream_commit=s['commit_sha'],fence_commit=f['commit_sha'])
    if plan is None:
        meta,jobs=verify_guards(client,fence,envelope)
        review=dict(old_fence_commit=incident,old_fence_sha256=hashlib.sha256(f['body']).hexdigest(),
            run_sha256=digest(meta),jobs_sha256=digest(jobs),policy_sha256=digest(client.policy),
            confirmed_at_ms=client.clock(),workers_terminated=True,run_completed=True)
        owner=envelope['snapshot']['control']['owner']
        release=event=None
        if owner is not None:
            review.update(old_owner=owner,old_revision=envelope['revision'],old_snapshot_digest=envelope['body_digest'],old_stream_commit=s['commit_sha'])
            release,event=safe.release_owner(envelope,fence['run'],client.policy['deployment'],review,secrets.token_hex(16))
        plan=dict(fence={k:v for k,v in f.items() if k!='body'},fence_body=fence,
            stream={k:v for k,v in s.items() if k!='body'},stream_body=envelope,review=review,
            release=release,owner_event=event,close_write_id=secrets.token_hex(16))
        journal.plan(plan)
    else:
        safe.require(f['commit_sha']==plan['fence']['commit_sha'])
        # Recheck live workers, receipts, rule evidence after runner loss. For an
        # already released owner use the exact original snapshot/owner binding.
        verify_guards(client,plan['fence_body'],plan['stream_body'])
    # Independent complete reobservation before either business mutation.
    current=inspect(client)
    safe.require(current[0]['commit_sha']==plan['fence']['commit_sha'])
    if plan['release'] is not None:
        released=confirmed_write(client,journal,'stream',plan['stream'],plan['release'],g.STORE_PATH,
            client.policy['deployment']['store_branch'],plan['stream']['commit_sha'])
        env=plan['release'];loc=locator(released,env)
        close=safe.owner_candidate(plan['fence_body'],env,loc,plan['review'],plan['owner_event'],plan['close_write_id'])
    else:
        safe.require(current[2]['commit_sha']==plan['stream']['commit_sha'])
        released=current[2];env=plan['stream_body'];loc=locator(released,env)
        close=safe.candidate(plan['fence_body'],env,loc,plan['review'],plan['close_write_id'])
    closed=confirmed_write(client,journal,'fence',plan['fence'],close,actions.FENCE_PATH,
        client.policy['deployment']['fence_branch'],released['commit_sha'])
    safe.validate(close,env,loc)
    return dict(phase='recovered-await-fresh-regular-run',outcome=close['completion'].get('outcome','reconciled'),
                incident=incident,stream_commit=released['commit_sha'],fence_commit=closed['commit_sha'])
