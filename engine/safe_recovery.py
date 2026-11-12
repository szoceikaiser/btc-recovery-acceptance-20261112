"""Close-only recovery after completed business work. Never own, send or replay.

The only supported mutation closes an open fence against an independently
confirmed successful stream after all workers have ended. Historical aborted
maintenance remains a separate, unchanged validator.
"""
from copy import deepcopy
import hashlib
import re
from types import SimpleNamespace
from production_contract import canonical,digest,validate_v2

SCHEMA='btc-close-only-recovery-v1'
OWNER_SCHEMA='btc-owner-abort-recovery-v1'

def require(ok):
    if not ok:raise ValueError('Recovery evidence refused')

def receipts(snapshot):
    validate_v2(snapshot)
    messages=[message for state in [snapshot['engine'],*snapshot['commands'].values()]
              for message in state.get('_delivery',{}).get('messages',[])]
    require(all(message['status']=='confirmed' and type(message.get('receipt')) is int
        and message['receipt']>0 and message.get('attempts')==1
        and message.get('target')==snapshot['control']['target_binding'] for message in messages))
    return digest(messages)

def completed(envelope,deployment,run):
    snapshot=envelope['snapshot'];control=snapshot['control'];validate_v2(snapshot)
    require(control['owner'] is None and control['mode']=='active'
        and not control['health'].get('restore_requires_reconciliation')
        and all(control[key]==deployment[key] for key in ('code_sha','config_sha256','store_id','bot_identity'))
        and run['kind'] in ('signal','watch') and run['attempt']=='1')
    from produktion_actions_runner import verify_health
    verify_health(SimpleNamespace(snapshot=snapshot),deployment,run)
    finished=control['health']['successful_runs'][run['kind']]['run']
    require(control['health'].get('completion_candidate')==finished)
    if run['kind']=='signal':
        require(snapshot['engine']['last_signal_ts']==int(run['expected_start_ms'])//14400000*14400000-14400000)
    else:
        require(finished['started_ms']<=finished['watch_observed_ms']<=finished['finished_ms']
            and finished['watch_candle_open_ms']==finished['watch_observed_ms']//14400000*14400000)
    return receipts(snapshot)

def validate(value,envelope,locator):
    proof=value['completion']['recovery'];run=value['run']
    owner=proof['schema']==OWNER_SCHEMA
    require(proof['schema'] in (SCHEMA,OWNER_SCHEMA) and value['phase']=='closed'
        and (value['completion'].get('outcome')=='aborted' if owner else 'outcome' not in value['completion'])
        and proof['failed_run']==run['id']
        and type(proof['confirmed_at_ms']) is int and proof['confirmed_at_ms']>0
        and all(re.fullmatch('[0-9a-f]{64}',proof[key]) for key in
                ('old_fence_sha256','run_sha256','jobs_sha256','policy_sha256','receipts_sha256'))
        and re.fullmatch('[0-9a-f]{40}',proof['old_fence_commit'])
        and value['completion']['stream']==locator
        and envelope['revision']==locator['revision']
        and envelope['body_digest']==digest(envelope['snapshot'])==locator['snapshot_digest']
        and all(locator[key]==expected for key,expected in {
            'adapter':'github','repo':value['deployment']['private_store_repository'],
            'branch':value['deployment']['store_branch'],'path':'delivery/stream.json',
            'store_id':value['deployment']['store_id']}.items())
        and re.fullmatch('[0-9a-f]{40}',locator['commit_sha'])
        and hashlib.sha1(b'blob '+str(len(canonical(envelope).encode())).encode()+b'\0'
                         +canonical(envelope).encode()).hexdigest()==locator['blob_sha'])
    if owner:
        snapshot=deepcopy(envelope['snapshot']);control=snapshot['control']
        require(control['owner'] is None and envelope['revision']==proof['old_revision']+1
            and re.fullmatch('[0-9a-f]{40}',proof['old_stream_commit'])
            and envelope['parent_digest']==proof['old_snapshot_digest']
            and receipts(snapshot)==proof['receipts_sha256'])
        event=control['owner_events'].pop()
        if not control['owner_events']:del control['owner_events']
        require(event==proof['owner_event'])
        control['owner']=proof['old_owner']
        require(digest(snapshot)==proof['old_snapshot_digest'])
        require(owner_matches(proof['old_owner'],run,value['deployment']))
    else:require(completed(envelope,value['deployment'],run)==proof['receipts_sha256'])
    old=deepcopy(value);old.update(phase='open',completion=None,write_id=proof['old_write_id'])
    require(hashlib.sha256(canonical(old).encode()).hexdigest()==proof['old_fence_sha256'])

def candidate(old,envelope,locator,review,write_id):
    require(old['phase']=='open' and old['completion'] is None)
    require(review['workers_terminated'] is True and review['run_completed'] is True)
    proof={key:review[key] for key in ('old_fence_commit','old_fence_sha256','run_sha256',
        'jobs_sha256','policy_sha256','confirmed_at_ms')}
    proof.update(schema=SCHEMA,old_write_id=old['write_id'],failed_run=old['run']['id'],
                 receipts_sha256=completed(envelope,old['deployment'],old['run']))
    value={**deepcopy(old),'phase':'closed','write_id':write_id,
           'completion':{'stream':deepcopy(locator),'recovery':proof}}
    validate(value,envelope,locator)
    return value

def owner_matches(owner,run,deployment):
    return (isinstance(owner,dict) and owner.get('repository')==deployment['private_store_repository']
        and ('workflow' not in owner or owner['workflow']==run['workflow']) and owner.get('run_id')==run['id']
        and owner.get('run_attempt')=='1' and bool(owner.get('nonce')))

def release_owner(envelope,run,deployment,evidence,write_id):
    """Only control.owner + one review event; exact original snapshot retained."""
    receipts(envelope['snapshot']);control=envelope['snapshot']['control']
    require(owner_matches(control['owner'],run,deployment) and run['kind'] in ('signal','watch')
        and control['mode']=='active' and not control['health'].get('restore_requires_reconciliation')
        and all(control[k]==deployment[k] for k in ('code_sha','config_sha256','store_id','bot_identity')))
    result=deepcopy(envelope);c=result['snapshot']['control']
    event=dict(old_owner=deepcopy(c['owner']),reviewer='bound-github-recovery',
        evidence_sha256=digest(evidence),converted_sending=0,at_revision=envelope['revision'])
    c['owner']=None;c.setdefault('owner_events',[]).append(event)
    result.update(revision=envelope['revision']+1,parent_digest=envelope['body_digest'],
        body_digest=digest(result['snapshot']),write_id=write_id)
    validate_v2(result['snapshot'])
    return result,event

def owner_candidate(old,released,locator,review,event,write_id):
    proof={key:review[key] for key in ('old_fence_commit','old_fence_sha256','run_sha256',
        'jobs_sha256','policy_sha256','confirmed_at_ms','old_revision','old_snapshot_digest','old_owner','old_stream_commit')}
    proof.update(schema=OWNER_SCHEMA,old_write_id=old['write_id'],failed_run=old['run']['id'],
                 receipts_sha256=receipts(released['snapshot']),owner_event=event)
    value={**deepcopy(old),'phase':'closed','write_id':write_id,
           'completion':{'stream':deepcopy(locator),'outcome':'aborted','recovery':proof}}
    validate(value,released,locator);return value
