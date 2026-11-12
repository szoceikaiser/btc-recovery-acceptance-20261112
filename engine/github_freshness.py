"""Bounded GET-only GitHub metadata reader; no credential discovery."""
from datetime import datetime, timezone
import time
import urllib.parse
from freshness import MAX_RUNS, LATE_MS, occurrence, dispatch_slot
from github_delivery import GitHubContentsClient, StoreUnavailable

MAX_READS = 32
MAX_TOTAL_SECONDS = 20
MAX_JOBS = 20


class ReadBudget:
    """One shared budget across separately scoped store/code/backup credentials."""
    def __init__(self):
        self.requests = 0
        self.started = time.monotonic()


class ReadOnlyClient(GitHubContentsClient):
    def __init__(self, token, budget=None):
        super().__init__(token, timeout=3)
        self.budget = budget or ReadBudget()

    @property
    def requests(self): return self.budget.requests

    @requests.setter
    def requests(self, value): self.budget.requests = value

    @property
    def started(self): return self.budget.started

    @started.setter
    def started(self, value): self.budget.started = value

    def _request(self, method, route, payload=None):
        if method != 'GET' or payload is not None:
            raise StoreUnavailable('Read-only boundary refused mutation')
        if self.requests >= MAX_READS or time.monotonic()-self.started > MAX_TOTAL_SECONDS:
            raise StoreUnavailable('Monitor request budget exhausted')
        self.requests += 1
        result = super()._request(method, route)
        if time.monotonic()-self.started > MAX_TOTAL_SECONDS:
            raise StoreUnavailable('Monitor time budget exhausted')
        return result


def utc_ms(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
        raise ValueError('UTC metadata required')
    return int(parsed.timestamp()*1000)


def iso(ms):
    return datetime.fromtimestamp(ms/1000, timezone.utc).isoformat().replace('+00:00', 'Z')


def read_runs(client, policy, now):
    result = {}
    for kind in ('signal', 'watch'):
        s = policy['schedules'][kind]
        due = occurrence(s, now-LATE_MS+(s.get('close_offset_ms', 0) if kind == 'signal' else 0))
        if due is None: raise ValueError('Schedule has no established occurrence')
        query = urllib.parse.urlencode({'per_page': MAX_RUNS, 'page': 1,
            'created': iso(due)+'..'+iso(now)})
        # No success/head/branch filter: wrong or failed newer runs must stay visible.
        route = client._route(s['repository'], '/actions/workflows/'
            +urllib.parse.quote(s['workflow'].rsplit('/', 1)[-1], safe='')+'/runs')
        raw = client._request('GET', route+'?'+query)
        items = raw['workflow_runs']
        if raw['total_count'] != len(items) or len(items) >= MAX_RUNS:
            raise StoreUnavailable('Run query incomplete')
        if not items:
            result[kind] = []; continue
        normalized = []
        for item in items:
            prefix = 'p3:'+kind+':'
            if not item['display_title'].startswith(prefix):
                raise ValueError('Explicit schedule slot missing from run title')
            epoch_seconds = item['display_title'][len(prefix):]
            slot = dispatch_slot(s, epoch_seconds)
            if item['event'] != 'workflow_dispatch':
                raise ValueError('Unexpected production trigger')
            normalized.append({'repository': item['repository']['full_name'], 'workflow': item['path'],
                'branch': item['head_branch'], 'head_sha': item['head_sha'],
                'run_id': str(item['id']), 'run_attempt': str(item['run_attempt']),
                'expected_start_ms': slot, 'created_ms': utc_ms(item['created_at']),
                'started_ms': utc_ms(item.get('run_started_at') or item['created_at']),
                'status': item['status'], 'conclusion': item['conclusion']})
        newest = max(normalized, key=lambda r: (r['created_ms'], int(r['run_attempt']), r['run_id']))
        due_runs = [r for r in normalized if r['expected_start_ms'] == due]
        selected = [newest]
        if due_runs:
            due_run = max(due_runs, key=lambda r: (r['created_ms'], int(r['run_attempt'])))
            if due_run != newest: selected.append(due_run)
        for run in selected:
            if run['status'] != 'completed' or run['conclusion'] != 'success': continue
            route = client._route(s['repository'], '/actions/runs/'+run['run_id']
                +'/attempts/'+run['run_attempt']+'/jobs?per_page=100&page=1')
            jobs = client._request('GET', route)
            if not 1 <= len(jobs['jobs']) <= MAX_JOBS or jobs['total_count'] != len(jobs['jobs']):
                raise StoreUnavailable('Job query incomplete')
            for j in jobs['jobs']:
                if (str(j['run_id']) != run['run_id'] or str(j['run_attempt']) != run['run_attempt']
                        or j['head_sha'] != run['head_sha'] or j['status'] != 'completed'
                        or j['conclusion'] != 'success'):
                    raise ValueError('Job completion identity mismatch')
            run['completed_ms'] = max(utc_ms(j['completed_at']) for j in jobs['jobs'])
        result[kind] = normalized
    return result


def read_backup(client, policy):
    """Consistent private backup receipt; full history was verified at backup time."""
    import json
    from production_contract import digest
    target = policy['backup_store']
    record = client.read(target['repo'], target['branch'], target['receipt_path'])
    if len(record['body']) > 64*1024:
        raise ValueError('Backup receipt size limit')
    receipt = json.loads(record['body'])
    if receipt['schema'] != 'p3-verified-backup-receipt-v2' or receipt['status'] != 'confirmed':
        raise ValueError('Verified backup receipt missing')
    manifest = receipt['manifest']
    if digest(manifest) != receipt['manifest_sha256']:
        raise ValueError('Backup manifest digest mismatch')
    hashes=manifest.get('package_manifest_sha256',[])
    import re
    if (not 1<=len(hashes)<=512 or any(not isinstance(h,str) or not re.fullmatch('[0-9a-f]{64}',h) for h in hashes)
            or len(set(hashes))!=len(hashes) or manifest.get('package_count')!=len(hashes)
            or manifest.get('chain_sha256')!=digest(hashes)
            or receipt.get('verified_chain_sha256')!=manifest.get('chain_sha256')
            or manifest.get('history_count')!=manifest['revision']+1
            or receipt.get('verified_source_pin')!=manifest['pin']
            or receipt.get('verified_source_revision')!=manifest['revision']
            or receipt.get('upload_readback_verified') is not True):
        raise ValueError('Complete verified backup chain missing')
    if (manifest['schema'] != 'p3-backup-set-v2'
            or manifest['identity']['repo'] != policy['store']['repo']
            or manifest['identity']['branch'] != policy['store']['branch']
            or manifest['identity']['store_id'] != policy['identity']['store_id']
            or manifest['identity']['stream_id'] != policy['identity']['stream_id']
            or manifest['stream_id'] != policy['identity']['stream_id']
            or manifest['store_path'] != policy['store']['path']):
        raise ValueError('Backup source identity mismatch')
    return {'status':'confirmed','store_id':manifest['identity']['store_id'],
        'code_sha':manifest['code_sha'],'config_sha256':manifest['config_sha256'],
        'expected_start_ms':receipt['expected_start_ms'],'verified_ms':receipt['verified_ms'],
        'manifest_sha256':receipt['manifest_sha256'],'store_commit_sha':manifest['pin'],
        'snapshot_digest':manifest['snapshot_digest'],'source_revision':manifest['revision'],
        'history_verified':receipt['history_verified'],
        'restore_blocked_verified':receipt['restore_blocked_verified'],
        'backup_commit_sha':record['commit_sha']}
