"""Hosted-runner admission fence on a separate branch in the store repository.

No resume: attempt 1 only, increasing run_number independently per workflow,
open fence has no TTL. Counters may be volatile because admission survives
every subsequent request and a replacement process cannot enter that run.
"""
from contextvars import ContextVar
import base64
import json
import secrets
import time

from production_contract import canonical, digest
from production_confirmation import ProductionContentsClient, validate_policy
from github_delivery import StoreUnavailable, StoreConflict, StoreHTTPFailure

POLICY = 'github-actions-fence-v2'
FENCE_PATH = 'delivery/actions-fence.json'
MAX_FENCE_BYTES = 8192
WORKFLOWS = {'.github/workflows/signal.yml': 'signal',
             '.github/workflows/watch.yml': 'watch',
             '.github/workflows/lage.yml': 'lage'}
active_client = ContextVar('hosted_actions_client', default=None)


def command_binding(client, operation_id):
    return {'schema': 'actions-lage-completion-v1', 'operation_id': operation_id,
            'repository': client.environment['BTC_DELIVERY_RUN_REPOSITORY'],
            'code_sha': client.environment['BTC_DELIVERY_CODE_SHA'], 'run': client.run}


def command_evidence(snapshot, entry):
    messages = entry['_delivery']['messages']
    if (entry['result'] is None or not messages
            or any(m['status'] != 'confirmed' or type(m.get('receipt')) is not int
                   or m['receipt'] <= 0 or m.get('target') != snapshot['control']['target_binding']
                   or m.get('attempts') != 1 for m in messages)):
        raise StoreConflict('Exact Lage command has no fully confirmed outbox')
    return {'outbox_sha256': digest(entry['_delivery']), 'result_sha256': digest(entry['result']),
            'engine_sha256': digest(snapshot['engine']), 'watch_sha256': digest(snapshot['watch']),
            'config_sha256': snapshot['control']['config_sha256']}


def verify_command(snapshot, client, operation_id):
    from telegram_outbox import identity
    entry = snapshot['commands'].get(identity('command', 'lage', 0, operation_id))
    if not entry or entry.get('actions_completion') != {
            **command_binding(client, operation_id), **command_evidence(snapshot, entry)}:
        raise StoreConflict('Exact Lage completion attestation missing')


def seed_fence(deployment, cursors=None):
    """Offline bytes only; separately reviewed bootstrap, no API creation."""
    if deployment.get('workflows') != WORKFLOWS:
        raise ValueError('Exact bounded workflow/kind bindings required')
    body = canonical({'schema': POLICY, 'deployment': deployment, 'phase': 'closed',
                      'cursors': cursors if cursors is not None else {w: {'number': 0, 'id': None} for w in WORKFLOWS},
                      'run': None,
                      'write_id': 'offline-seed', 'completion': None}).encode()
    parse_fence({'body':body},deployment)
    if len(body) > MAX_FENCE_BYTES: raise ValueError('Fence seed too large')
    return body


def parse_fence(record, deployment):
    if len(record['body']) > MAX_FENCE_BYTES:
        raise StoreUnavailable('Fence too large')
    try:
        value = json.loads(record['body'])
        cursors = value['cursors']
        if (record['body'] != canonical(value).encode() or value.get('schema') != POLICY
                or value.get('deployment') != deployment or value.get('phase') not in ('open','closed')
                or deployment.get('workflows') != WORKFLOWS or set(cursors) != set(WORKFLOWS)
                or any(type(c.get('number')) is not int or c['number'] < 0
                       or (c['number'] == 0 and c.get('id') is not None)
                       or (c['number'] > 0 and (not isinstance(c.get('id'), str)
                                               or not c['id'].isdigit())) for c in cursors.values())):
            raise ValueError('shape')
        run = value['run']
        if run is None:
            if value['phase'] != 'closed' or value['completion'] is not None:
                raise ValueError('seed')
        elif (run.get('workflow') not in WORKFLOWS or run.get('kind') != WORKFLOWS[run['workflow']]
              or run.get('attempt') != '1' or cursors[run['workflow']] != {'number': run['number'], 'id': run['id']}
              or not run['number']):
            raise ValueError('run')
        completion = value.get('completion') or {}
        if 'recovery' in completion:
            from safe_recovery import SCHEMA,OWNER_SCHEMA
            schema=completion['recovery'].get('schema')
            if (value['phase']!='closed' or schema not in (SCHEMA,OWNER_SCHEMA)
                    or (completion.get('outcome')!='aborted' if schema==OWNER_SCHEMA else 'outcome' in completion)):
                raise ValueError('Recovery shape')
        if 'outcome' in completion and 'recovery' not in completion:
            from aborted_maintenance import review_evidence
            if completion['outcome'] != 'aborted' or value['phase'] != 'closed':
                raise ValueError('maintenance outcome')
            review_evidence(completion['maintenance']['review'])
        return value
    except (ValueError, KeyError, TypeError, AttributeError):
        raise StoreConflict('Fence identity/shape mismatch') from None


class RunBudget:
    def __init__(self, policy, binding, clock=None):
        # Reuse accepted hard bounds; this policy deliberately selects three reads.
        self.policy = dict(validate_policy(policy))
        self.binding = dict(binding)
        self.clock = clock or (lambda: int(time.time()*1000))
        self.started = self.highwater = self.clock()
        if not 0 < policy['deadline_utc_ms']-self.started <= 900000:
            raise ValueError('Fresh fifteen-minute run deadline required')
        self.get = self.put = self.request = self.response = 0
        self.case = None
        self.pending = None
        self.halted = False

    def guard(self):
        now = self.clock()
        if self.halted or self.pending or not self.highwater <= now < self.policy['deadline_utc_ms']:
            raise StoreUnavailable('Actions budget/outcome/deadline blocked')
        self.highwater = now
        return now

    def begin_case(self, write_id, payload_size):
        self.guard(); p = self.policy
        if (self.case or self.get+11 > p['run_get_limit'] or self.put+1 > p['run_put_limit']
                or payload_size > p['request_byte_limit']
                or self.request+payload_size > p['run_request_byte_limit']
                or self.response+12*p['response_byte_limit'] > p['run_response_byte_limit']):
            raise StoreUnavailable('Complete Actions write/readback reserve unavailable')
        self.case = [write_id, 0, 0]

    def reserve(self, method, route, size, case_id):
        now = self.guard(); p = self.policy
        if (method not in ('GET','PUT') or size > p['request_byte_limit']
                or self.get+(method=='GET') > p['run_get_limit']
                or self.put+(method=='PUT') > p['run_put_limit']
                or self.request+size > p['run_request_byte_limit']
                or self.response+p['response_byte_limit'] > p['run_response_byte_limit']
                or (method=='PUT' and not case_id)
                or (case_id and (not self.case or self.case[0]!=case_id
                    or self.case[1]+(method=='GET') > 11 or self.case[2]+(method=='PUT') > 1))):
            self.halted = True
            raise StoreUnavailable('Actions request/byte budget exhausted')
        self.get += method=='GET'; self.put += method=='PUT'
        self.request += size; self.response += p['response_byte_limit']
        if case_id:
            self.case[1] += method=='GET'; self.case[2] += method=='PUT'
        self.pending = self.get+self.put
        return self.pending, min(p['timeout_seconds'], (p['deadline_utc_ms']-now)/1000)

    def finish(self, request_id, response_bytes, status):
        now = self.clock()
        if (request_id != self.pending or not self.highwater <= now < self.policy['deadline_utc_ms']
                or response_bytes > self.policy['response_byte_limit']):
            self.halted = True
            raise StoreUnavailable('Actions response crossed deadline/byte budget')
        self.pending = None; self.highwater = now

    def complete_case(self, write_id):
        self.guard()
        if not self.case or self.case[0] != write_id:
            raise StoreUnavailable('Actions case mismatch')
        self.case = None

    def halt(self):
        self.halted = True


class ActionsClient(ProductionContentsClient):
    def __init__(self, token, budget, environment):
        super().__init__(token, budget)
        self.environment = dict(environment)
        self.admitted = False
        self.fence_branch = environment['BTC_DELIVERY_FENCE_BRANCH']

    def read(self, repo, branch, path='delivery/stream.json'):
        expected = {FENCE_PATH:self.fence_branch,
                    'delivery/stream.json':self.journal.binding['branch']}
        if repo != self.journal.binding['repo'] or expected.get(path) != branch:
            raise StoreUnavailable('Actions read branch/path differs from binding')
        return super().read(repo,branch,path)

    def update(self, repo, branch, expected_blob_sha, body, write_id, path='delivery/stream.json'):
        if not self.admitted:
            raise StoreUnavailable('Business write outside admitted Actions run')
        return super().update(repo,branch,expected_blob_sha,body,write_id,path)

    def fence_write(self, old, value):
        body = canonical(value).encode()
        if len(body) > MAX_FENCE_BYTES: raise StoreUnavailable('Fence too large')
        write_id = value['write_id']
        payload = {'message': 'actions fence '+write_id, 'content': base64.b64encode(body).decode(),
                   'sha': old['blob_sha'], 'branch': self.fence_branch}
        self.journal.begin_case(write_id, len(canonical(payload).encode()))
        self.case_id = write_id
        repo, branch = self.journal.binding['repo'], self.fence_branch
        try:
            try:
                result = self._request('PUT', self._route(repo, '/contents/'+FENCE_PATH), payload)
                expected = result['commit']['sha']
            except StoreHTTPFailure: raise
            except StoreUnavailable: expected = None
            for attempt in range(3):
                observed = self.read(repo, branch, FENCE_PATH)
                if observed == old and attempt < 2: continue
                if (observed['body'] != body or observed == old
                        or (expected is not None and observed['commit_sha'] != expected)
                        or self.parents(repo, observed['commit_sha']) != [old['commit_sha']]):
                    raise StoreConflict('Fence mutation not confirmed')
                self.finalize_confirmation(repo, branch, observed['commit_sha'])
                return observed
            raise StoreConflict('Fence still old')
        except BaseException:
            self.journal.halt()
            raise

    def fence_read(self, deployment):
        record = self.read(self.journal.binding['repo'], self.fence_branch, FENCE_PATH)
        return record, parse_fence(record, deployment)

    def acquire(self, deployment, run):
        record, value = self.fence_read(deployment)
        workflow = run.get('workflow')
        if (workflow not in WORKFLOWS or run.get('kind') != WORKFLOWS[workflow]
                or type(run.get('number')) is not int or run['number'] <= 0
                or not isinstance(run.get('id'), str) or not run['id'].isdigit()
                or run.get('attempt') != '1'):
            raise StoreConflict('Unknown workflow or wrong operation binding')
        if (value['phase'] != 'closed' or run['number'] <= value['cursors'][workflow]['number']
                or any(c['id'] == run['id'] for c in value['cursors'].values())):
            raise StoreConflict('Open/old/repeated Actions run requires operator review')
        if 'recovery' in (value.get('completion') or {}):
            from safe_recovery import validate
            observed=self.read(deployment['private_store_repository'],deployment['store_branch'])
            loc=value['completion']['stream'];proof=value['completion']['recovery']
            if (observed['commit_sha']!=loc['commit_sha'] or observed['blob_sha']!=loc['blob_sha']
                    or self.parents(deployment['private_store_repository'],record['commit_sha'])!=[proof['old_fence_commit']]
                    or run['kind'] not in ('signal','watch')
                    or int(run.get('expected_start_ms','0'))<=proof['confirmed_at_ms']):
                raise StoreConflict('Fresh regular run after close-only recovery required')
            validate(value,json.loads(observed['body']),loc)
            if proof['schema']=='btc-owner-abort-recovery-v1' and self.parents(
                    deployment['private_store_repository'],observed['commit_sha'])!=[proof['old_stream_commit']]:
                raise StoreConflict('Released owner stream parent differs')
        if (value.get('completion') or {}).get('outcome') == 'aborted' and 'recovery' not in value['completion']:
            from aborted_maintenance import validate_pair, STREAM_PIN, FENCE_PIN
            completion = value['completion']
            observed = self.read(deployment['private_store_repository'], deployment['store_branch'])
            envelope = json.loads(observed['body'])
            loc = completion['stream']
            if (observed['commit_sha'] != loc['commit_sha'] or observed['blob_sha'] != loc['blob_sha']
                    or self.parents(deployment['private_store_repository'], observed['commit_sha']) != [STREAM_PIN]
                    or self.parents(deployment['private_store_repository'], record['commit_sha']) != [FENCE_PIN]
                    or run.get('kind') not in ('signal','watch')
                    or int(run.get('expected_start_ms', '0')) <= completion['maintenance']['review']['stopped_at_ms']):
                raise StoreConflict('Fresh regular run after confirmed maintenance required')
            validate_pair(value, envelope, loc)
        self.run = dict(run)
        self.fence = {**value, 'phase': 'open', 'run': dict(run),
                      'cursors': {**value['cursors'], workflow: {'number': run['number'], 'id': run['id']}},
                      'write_id': secrets.token_hex(16), 'completion': None}
        self.fence_write(record, self.fence)
        self.admitted = True

    def close(self, deployment, completion):
        record, value = self.fence_read(deployment)
        if value != self.fence or self.journal.case or self.journal.pending:
            raise StoreConflict('Actions fence changed or case unfinished')
        closed = {**value, 'phase': 'closed', 'write_id': secrets.token_hex(16),
                  'completion': {'stream': completion, 'get_before_close': self.journal.get,
                                 'put_before_close': self.journal.put,
                                 'request_bytes_before_close': self.journal.request,
                                 'response_reserve_before_close': self.journal.response}}
        # There are no business operations after this write, even if reply is lost.
        self.admitted = False
        self.fence_write(record, closed)


def configured_actions_client(token, environment):
    client = active_client.get()
    if (client is None or not client.admitted or client.token != token
            or any(environment.get(k) != v for k,v in client.environment.items())):
        raise ValueError('Hosted Actions factory requires the exact admitted runtime scope')
    client.journal.guard()
    return client
