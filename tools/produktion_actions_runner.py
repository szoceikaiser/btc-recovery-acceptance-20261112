"""Disabled-by-default hosted Actions entry; no local persistence/bootstrap."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'engine'), str(ROOT/'tools')]
import actions_delivery as actions
import github_delivery as github
import actions_schedule as schedule
import public_access as public
import produktion_runner as runner
from production_contract import canonical, digest, effective_config


def check_code_pin(code_sha,budget=None):
    import p3_backup_chain as b
    budget=budget or b.Budget()
    head=b.git(ROOT,budget,'rev-parse','HEAD').decode().strip()
    changed=b.git(ROOT,budget,'status','--porcelain','--untracked-files=all',
                  '--','engine','tools','ops','site').decode()
    if head != code_sha or changed:
        raise ValueError('Checked-out runtime code differs from reviewed clean commit')


def validate(runtime, kind, data_dir):
    if runtime.get('enabled') is not True:
        raise ValueError('Hosted Actions runtime is disabled')
    if runtime.get('python_version') and tuple(runtime['python_version'])!=sys.version_info[:3]:
        raise ValueError('Reviewed Python runtime differs')
    if (runtime.get('schema') != actions.POLICY or kind not in ('signal','watch','lage')
            or runtime.get('workflows') != actions.WORKFLOWS
            or runtime.get('confirmation_policy') != actions.POLICY
            or runtime.get('store_path') != github.STORE_PATH
            or runtime.get('fence_path') != actions.FENCE_PATH
            or not re.fullmatch('[0-9a-f]{64}', runtime.get('activation_review_sha256') or '')):
        raise ValueError('Explicit reviewed Actions activation binding required')
    workflow = os.environ.get('BTC_DELIVERY_WORKFLOW')
    if actions.WORKFLOWS.get(workflow) != kind:
        raise ValueError('Workflow does not admit this operation')
    if kind == 'lage' and os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch':
        raise ValueError('Lage requires its own manual Actions entry')
    fields = {'BTC_DELIVERY_ADAPTER': 'github',
              'BTC_DELIVERY_GITHUB_REPO': runtime.get('private_store_repository'),
              'BTC_DELIVERY_GITHUB_BRANCH': runtime.get('store_branch'),
              'BTC_DELIVERY_FENCE_BRANCH': runtime.get('fence_branch'),
              'BTC_DELIVERY_STORE_ID': runtime.get('store_id'),
              'BTC_DELIVERY_CODE_SHA': runtime.get('code_sha'),
              'BTC_DELIVERY_BOT_IDENTITY': runtime.get('bot_identity'),
              'BTC_DELIVERY_RUN_REPOSITORY': runtime.get('code_repository'),
              'BTC_DELIVERY_WORKFLOW': workflow,
              'BTC_DELIVERY_CONFIRMATION_POLICY': actions.POLICY}
    if any(not v or os.environ.get(k) != v for k,v in fields.items()):
        raise ValueError('Actions environment differs from reviewed deployment')
    if runtime['fence_branch'] == runtime['store_branch']:
        raise ValueError('Separate fence branch preserves accepted store backup format')
    for actual, pinned in (('GITHUB_REPOSITORY','BTC_DELIVERY_RUN_REPOSITORY'),
                          ('GITHUB_RUN_ID','BTC_DELIVERY_RUN_ID'),
                          ('GITHUB_RUN_ATTEMPT','BTC_DELIVERY_RUN_ATTEMPT')):
        if not os.environ.get(actual) or os.environ[actual] != os.environ.get(pinned):
            raise ValueError('Actual Actions run binding differs')
    if (os.environ.get('GITHUB_SHA')!=runtime['code_sha'] and
            not runtime.get('entry_workflows',{}).get(workflow)):
        raise ValueError('Changing entry requires reviewed workflow binding')
    if (os.environ.get('GITHUB_REF') != runtime.get('code_ref')
            or os.environ.get('GITHUB_WORKFLOW_REF') != runtime['code_repository']+'/'
                +workflow+'@'+runtime['code_ref']
            or os.environ.get('GITHUB_RUN_ATTEMPT') != '1'
            or not re.fullmatch('[1-9][0-9]*', os.environ.get('GITHUB_RUN_NUMBER',''))
            or not re.fullmatch('[1-9][0-9]*', os.environ.get('GITHUB_RUN_ID',''))
            or not re.fullmatch('[0-9a-f]{40}', runtime.get('code_sha') or '')
            or any(os.environ.get(k) for k in ('BTC_DELIVERY_STORE',
                    'BTC_DELIVERY_CONFIRMATION_CONFIG','BTC_DELIVERY_REQUEST_JOURNAL'))):
        raise ValueError('Hosted run/ref/attempt or persistence binding refused')
    root = Path(os.environ.get('BTC_DELIVERY_RUNNER_ROOT',''))
    if not root.is_absolute() or not Path(data_dir).resolve().is_relative_to(root.resolve()):
        raise ValueError('Absolute contained runner projection required')
    if runtime.get('schedule_contract') != schedule.CONTRACT:
        raise ValueError('Reviewed fixed schedule contract required')
    if any(not os.environ.get(k) for k in ('BTC_DELIVERY_GITHUB_TOKEN',
             'TELEGRAM_BOT_TOKEN','TELEGRAM_CHAT_ID')):
        raise ValueError('Production environment incomplete')
    if not os.environ.get('GITHUB_TOKEN') or os.environ['GITHUB_TOKEN']==os.environ['BTC_DELIVERY_GITHUB_TOKEN']:
        raise ValueError('Separate automatic codejob metadata token required')
    config = json.loads(Path(data_dir,'config.json').read_text(encoding='utf-8'))
    if digest(effective_config(config)) != runtime.get('config_sha256'):
        raise ValueError('Effective strategy configuration differs')
    check_code_pin(runtime['code_sha'])
    public.deployment(runtime['public_access'],runtime)
    return fields


def deployment(runtime):
    # Fixed size deployment pin, including budgets, ref, strategy and review.
    return {k: runtime[k] for k in ('code_repository','code_ref','workflows',
        'private_store_repository','store_branch','fence_branch','store_id','store_path','fence_path',
        'code_sha','config_sha256','bot_identity','activation_review_sha256',
        'confirmation_policy','confirmation_budgets','schedule_contract','public_access_sha256')}


def read_run_metadata(client, repository, run_id, tail=None):
    tail='/actions/runs/'+run_id if tail is None else tail
    if repository!=os.environ.get('GITHUB_REPOSITORY') or not public.tail_allowed(tail,True):
        raise ValueError('Codejob-only metadata scope required')
    reader = github.GitHubContentsClient(os.environ.get('GITHUB_TOKEN'))
    from job_quota import bind
    bind(reader,os.environ.get('GITHUB_TOKEN'),client.quota_headers)
    reader.metadata_routes=True
    reader.open_request = client.open_request
    reader.response_byte_limit = client.response_byte_limit
    reader._response_bytes = 0
    route = reader._route(repository, tail)
    request_id, reader.timeout = client.journal.reserve('GET', route, 0, None)
    try:
        result = reader._request('GET', route)
        client.journal.finish(request_id, reader._response_bytes, 'completed')
        return result
    except Exception:
        client.journal.halt()
        raise


def run_runtime(runtime_path, kind, data_dir, **fixtures):
    runtime = json.loads(Path(runtime_path).read_text(encoding='utf-8'))
    fields = validate(runtime, kind, data_dir)
    now = int(time.time()*1000)
    policy = {**runtime['confirmation_budgets'], 'deadline_utc_ms': now+900000}
    binding = {'repo':runtime['private_store_repository'], 'branch':runtime['store_branch'],
               'store_id':runtime['store_id'], 'run_id':os.environ['GITHUB_RUN_ID'],
               'run_attempt':'1', 'code_sha':runtime['code_sha']}
    operation_id = digest({'repository': runtime['code_repository'],
                           'workflow': fields['BTC_DELIVERY_WORKFLOW'], 'run_id': binding['run_id']})
    prior_operation_id = os.environ.get('BTC_DELIVERY_OPERATION_ID')
    if kind == 'lage' and os.environ.get('BTC_DELIVERY_OPERATION_ID', operation_id) != operation_id:
        raise ValueError('Manual command identity must be derived from this Actions run')
    # Snapshot exact factory environment; all clients in this process share counters.
    fields.update({k: os.environ.get(k,'') for k in (
        'BTC_DELIVERY_RUN_ID','BTC_DELIVERY_RUN_ATTEMPT','BTC_DELIVERY_RUNNER_ROOT',
        'BTC_DELIVERY_EXPECTED_START_MS','GITHUB_REPOSITORY','GITHUB_SHA','GITHUB_REF',
        'GITHUB_WORKFLOW_REF','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_RUN_NUMBER',
        'GITHUB_EVENT_NAME')})
    if kind == 'lage':
        fields['BTC_DELIVERY_OPERATION_ID'] = operation_id
    client = actions.ActionsClient(os.environ['BTC_DELIVERY_GITHUB_TOKEN'],
                                   actions.RunBudget(policy,binding), fields)
    from job_quota import bind
    bind(client,os.environ.get('GITHUB_TOKEN'))
    access=runtime['public_access'];repo=binding['repo']
    branches=[runtime['store_branch'],runtime['fence_branch']]
    public.credential(access,'sender_write',repo,branches)
    public.check(client,access,[(repo,v) for v in branches],[(repo,v) for v in branches])
    # One actual GET charged to the SAME accepted Actions run budget. Never use
    # step start, run_started_at or a claimed scheduled_at to invent a new slot.
    meta = read_run_metadata(client, runtime['code_repository'], binding['run_id'])
    if (str(meta['id']) != binding['run_id'] or meta['run_attempt'] != 1
            or str(meta['run_number']) != os.environ['GITHUB_RUN_NUMBER']
            or meta['repository']['full_name'] != runtime['code_repository']
            or meta['head_sha'] != os.environ.get('GITHUB_SHA')
            or meta['head_branch'] != runtime['code_ref'].removeprefix('refs/heads/')
            or meta['path'] != fields['BTC_DELIVERY_WORKFLOW']
            or meta['event'] != os.environ['GITHUB_EVENT_NAME']):
        raise ValueError('Actual run metadata differs from entry binding')
    from reviewed_actions_entry import verify
    class ChargedReader:
        def request(self,method,repo,tail):
            if method!='GET': raise ValueError('Entry reader is GET-only')
            return read_run_metadata(client,repo,binding['run_id'],tail)
    public.repository(ChargedReader(),access,runtime['code_repository'],runtime['code_ref'].removeprefix('refs/heads/'))
    verify(ChargedReader(),runtime['code_repository'],meta['head_sha'],runtime['code_sha'],
           fields['BTC_DELIVERY_WORKFLOW'],runtime.get('entry_workflows',{}).get(fields['BTC_DELIVERY_WORKFLOW']))
    client.reviewed_entry=(meta['head_sha'],runtime['code_sha'],fields['BTC_DELIVERY_WORKFLOW'])
    slot = schedule.bind(kind, meta, int(time.time()*1000),
                         os.environ.get('BTC_ACTIONS_EXPLICIT_START_MS',''))
    os.environ['BTC_DELIVERY_EXPECTED_START_MS'] = str(slot)
    fields['BTC_DELIVERY_EXPECTED_START_MS'] = str(slot)
    client.environment = dict(fields)
    # Queue delay consumes the original obligation's remaining time.
    policy['deadline_utc_ms'] = min(policy['deadline_utc_ms'],
        slot+900000 if kind=='lage' else schedule.deadline(kind,slot))
    client.journal.policy['deadline_utc_ms'] = policy['deadline_utc_ms']
    run = {'number':int(os.environ['GITHUB_RUN_NUMBER']), 'id':binding['run_id'], 'attempt':'1',
           'workflow': fields['BTC_DELIVERY_WORKFLOW'],
           'kind':kind, 'expected_start_ms':os.environ['BTC_DELIVERY_EXPECTED_START_MS'],
           'deadline_utc_ms':policy['deadline_utc_ms']}
    pin = deployment(runtime)
    client.acquire(pin,run)
    if kind == 'lage':
        os.environ['BTC_DELIVERY_OPERATION_ID'] = operation_id
    scope = actions.active_client.set(client)
    try:
        result = runner.run_checked(kind, Path(data_dir), **fixtures)
        store = github.read_only(client,binding['repo'],binding['branch'],binding['store_id'])
        if store.snapshot['control'].get('owner') is not None or store.blocked() or client.journal.halted:
            raise github.StoreConflict('Incomplete/uncertain stream keeps Actions fence open')
        if kind == 'lage':
            actions.verify_command(store.snapshot, client, operation_id)
        else:
            verify_health(store, runtime, run)
        client.close(pin,store.confirmed_record())
        return {'result':result, 'get':client.journal.get, 'put':client.journal.put,
                'request_bytes':client.journal.request, 'response_reserve':client.journal.response}
    finally:
        client.admitted = False
        actions.active_client.reset(scope)
        if kind == 'lage':
            if prior_operation_id is None:
                os.environ.pop('BTC_DELIVERY_OPERATION_ID', None)
            else:
                os.environ['BTC_DELIVERY_OPERATION_ID'] = prior_operation_id


def verify_health(store, runtime, run):
    health = store.snapshot['control']['health']
    finished = health.get('successful_runs',{}).get(run['kind'],{}).get('run',{})
    current = health.get('current_run',{})
    if (current.get('status') != 'completed' or finished.get('status') != 'completed'
            or any(current.get(k) != v or finished.get(k) != v for k,v in (
                ('run_id',run['id']),('run_attempt','1'),('kind',run['kind']),
                ('repository',runtime['code_repository']),('workflow',run['workflow']),
                ('code_sha',runtime['code_sha']),('config_sha256',runtime['config_sha256']),
                ('expected_start_ms',int(run['expected_start_ms']))))):
        raise github.StoreConflict('Exact successful engine run attestation missing')


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--runtime',required=True)
    p.add_argument('--kind',choices=('signal','watch','lage'),required=True)
    p.add_argument('--data-dir',required=True)
    a = p.parse_args()
    try: run_runtime(a.runtime,a.kind,a.data_dir)
    except Exception:
        print('Hosted Actions refused or halted; operator review required.',file=sys.stderr)
        sys.exit(20)
