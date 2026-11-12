"""One-shot synthetic GitHub recovery acceptance. No production CLI or credentials."""

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from types import SimpleNamespace

SOURCE_HASH = '88e5a5ed7a248f86b556ec9ae1730a94a2af517c7a4dfcecd6709c905751fba8'
TEST_REPO = 'btc-recovery-acceptance-20261112'
CODE = 'recovery-test-code'
JOURNAL = 'recovery-test-journal'
WORKFLOW = '.github/workflows/recovery.yml'
WORKER = '.github/workflows/signal.yml'
CASES = ('safe', 'uncertain')
PROD_IDS = {1309164619, 1420314517, 1420315667, 1420316189}
PROD_BRANCHES = {'main', 'delivery-stream-live', 'delivery-fence-live',
                 'reviewed-migration-live', 'recovery-journal-live',
                 'verified-pair-live', 'verified-receipts-live'}


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def pin(value, length):
    return isinstance(value, str) and re.fullmatch(f'[0-9a-f]{{{length}}}', value)


def test_repository(repo, repo_id):
    require(re.fullmatch(r'[a-zA-Z0-9-]+/' + TEST_REPO, repo)
            and type(repo_id) is int and repo_id > 0 and repo_id not in PROD_IDS,
            'synthetic repository required')


def branches(case):
    require(case in CASES, 'unknown synthetic case')
    return 'recovery-test-stream-' + case, 'recovery-test-fence-' + case


def add_paths(root):
    sys.path[:0] = [str(root / 'engine'), str(root / 'tools')]


def load(root):
    # Adapt two equality pins and distinguish store reads in the single-repo
    # topology. Verify the original bytes before applying these exact edits.
    source = (root / 'tools/github_recovery.py').read_bytes()
    require(sha(source) == SOURCE_HASH, 'reviewed executor bytes differ')
    for old, new in (
        (b"branch']=='recovery-journal-live'", b"branch']=='recovery-test-journal'"),
        (b"=='github-fine-grained-pat:21186996'", b"==_test_writer_reference"),
        (b'            if code:\n', b'            if code and not _test_store_read(tail):\n'),
    ):
        require(source.count(old) == 1, 'executor adaptation differs')
        source = source.replace(old, new)
    import github_recovery as original
    adapted = dict(vars(original))
    adapted['_test_store_read'] = lambda tail: tail.startswith(
        ('/git/ref/heads/', '/git/commits/', '/contents/delivery/', '/contents/recovery/incidents/'))
    exec(compile(source, '<isolated github_recovery>', 'exec'), adapted)
    return SimpleNamespace(**adapted)


def writer_reference(repo_id):
    return f'github-actions-installation:repository:{repo_id}:job:recover'


def binding(repo, case, code_sha, access):
    from actions_delivery import WORKFLOWS
    from production_contract import digest

    stream, fence = branches(case)
    return dict(private_store_repository=repo, code_repository=repo,
                code_ref='refs/heads/' + CODE, code_sha=code_sha, store_branch=stream,
                fence_branch=fence, store_id='synthetic-recovery-20261112-' + case,
                bot_identity='synthetic-only:no-bot', public_access_sha256=digest(access),
                config_sha256=digest(fixture_config()), workflows=WORKFLOWS)


def fixture_config():
    return dict(muster_cvd='usd', bias_short=False, ausbruch_ruecktest=False)


def worker_run(meta, repo):
    from github_freshness import utc_ms

    require(meta['repository']['full_name'] == repo and meta['head_branch'] == CODE
            and meta['event'] == 'workflow_dispatch' and meta['path'] == WORKER
            and meta['status'] == 'completed' and meta['conclusion'] == 'failure'
            and meta['run_attempt'] == 1 and pin(meta['head_sha'], 40)
            and all(type(meta[k]) is int and meta[k] > 0 for k in ('id', 'run_number')),
            'synthetic historical worker differs')
    return dict(kind='signal', workflow=WORKER, id=str(meta['id']), number=meta['run_number'],
                attempt='1', expected_start_ms=utc_ms(meta['created_at']) // 60000 * 60000)


def fixture(deployment, run, case):
    from position_state import Position, pos_to_state
    from production_contract import digest
    from telegram_outbox import enqueue

    at = run['expected_start_ms']
    close = at // 14400000 * 14400000 - 14400000
    target = sha(b'synthetic-only:no-recipient')
    delivery = dict(version=1, messages=[], signals={'signals': []}, oi_history=[])
    enqueue(delivery, 'fixture', 'synthetic', 0, {'synthetic': True}, 'SYNTHETIC ONLY')
    delivery['messages'][0].update(status='confirmed', attempts=1, target=target, receipt=17)
    if case == 'uncertain':
        delivery['messages'][0].update(status='uncertain', receipt=None, reason='synthetic_unknown')
    current = dict(repository=deployment['code_repository'], workflow=WORKER,
                   run_id=run['id'], run_attempt='1', kind='signal', expected_start_ms=at,
                   code_sha=deployment['code_sha'], config_sha256=deployment['config_sha256'],
                   status='completed', started_ms=at, finished_ms=at + 1)
    complete = dict(current, revision=0, last_signal_ts=close)
    control = {key: deployment[key] for key in ('store_id', 'bot_identity', 'code_sha', 'config_sha256')}
    control.update(stream_id=deployment['store_id'], target_binding=target, mode='active',
                   owner=None, reconciliations=[], health=dict(current_run=current, completion_candidate=complete),
                   migration=dict(migration_id='synthetic', B=close, W=close + 14400000,
                                  history_sha256=digest({'signals': []}), history_count=0,
                                  source_hashes={}, unknowns=[], gates={}, legacy_delivery='unknown_no_replay'))
    return dict(version=2, watch={}, commands={}, control=control,
                engine=dict(pos_to_state(Position()), config=fixture_config(),
                            _delivery=delivery, last_signal_ts=close)), complete


def commit_file(git_dir, path, raw, parent=None):
    """Create local, unreferenced objects only. No checkout, ref update or push."""
    def git(*args, data=b''):
        return subprocess.check_output(
            ['git', '--git-dir', str(git_dir), '-c', 'user.name=Synthetic Recovery',
             '-c', 'user.email=recovery-test@example.invalid', *args], input=data
        ).decode().strip()

    object_id = git('hash-object', '-w', '--stdin', data=raw)
    tree = None
    for name in reversed(path.split('/')):
        line = f'040000 tree {tree}\t{name}\n' if tree else f'100644 blob {object_id}\t{name}\n'
        tree = git('mktree', data=line.encode())
    parents = ['-p', parent] if parent else []
    commit = git('commit-tree', tree, *parents, data=b'SYNTHETIC recovery acceptance\n')
    return dict(commit_sha=commit, blob_sha=object_id, sha256=sha(raw))


def seed(root, settings, meta, jobs, git_dir):
    add_paths(root)
    from actions_delivery import FENCE_PATH, parse_fence, seed_fence
    from github_delivery import SCHEMA, STORE_PATH, GitHubStore
    from production_contract import canonical, digest

    repo, repo_id, code = (settings[key] for key in ('repository', 'repository_id', 'code_sha'))
    test_repository(repo, repo_id)
    require(pin(code, 40) and git_dir.name == 'recovery-seeds.git' and not git_dir.exists()
            and not git_dir.is_symlink() and git_dir.parent.is_dir()
            and not any(os.environ.get(key) for key in ('GIT_DIR', 'GIT_COMMON_DIR', 'GIT_OBJECT_DIRECTORY',
                                                        'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_WORK_TREE')),
            'new separate local Git object store required')
    run = worker_run(meta, repo)
    job = jobs['jobs'][0]
    require(meta['repository']['id'] == repo_id and jobs['total_count'] == len(jobs['jobs']) == 1
            and job['run_id'] == meta['id'] and job['run_attempt'] == 1
            and job['head_sha'] == meta['head_sha'] and job['status'] == 'completed'
            and job['conclusion'] == 'failure' and job['name'] == 'synthetic-worker'
            and 'ubuntu-24.04' in job['labels'] and 'self-hosted' not in job['labels']
            and type(job['id']) is int and job['id'] > 0, 'synthetic worker job differs')
    recovery = load(root)
    subprocess.run(['git', 'init', '--quiet', '--bare', '--object-format=sha1', str(git_dir)], check=True)
    refs = {JOURNAL: commit_file(git_dir, 'recovery/seed.json', b'{"synthetic":true}')}
    for case in CASES:
        d = binding(repo, case, code, settings['public_access'][case])
        snapshot, complete = fixture(d, run, case)
        env = dict(schema=SCHEMA, repo=repo, branch=d['store_branch'], store_id=d['store_id'],
                   revision=0, parent_digest='0' * 64, write_id='synthetic-completion',
                   body_digest=digest(snapshot), snapshot=snapshot)
        raw = canonical(env).encode()
        GitHubStore(None, repo, d['store_branch'], d['store_id'], 'read-only', '1')._parse({'body': raw})
        prior = commit_file(git_dir, STORE_PATH, raw)
        snapshot['control']['health']['successful_runs'] = {
            'signal': dict(run=complete, completion=recovery.locator(prior, env))}
        env.update(revision=1, write_id='synthetic-success-binding',
                   parent_digest=env['body_digest'], body_digest=digest(snapshot))
        refs[d['store_branch']] = commit_file(git_dir, STORE_PATH, canonical(env).encode(), prior['commit_sha'])
        fence = json.loads(seed_fence(d))
        fence['cursors'][WORKER] = dict(number=run['number'], id=run['id'])
        fence.update(phase='open', run=run, write_id='synthetic-open-' + case)
        raw = canonical(fence).encode()
        parse_fence({'body': raw}, d)
        refs[d['fence_branch']] = commit_file(git_dir, FENCE_PATH, raw)
    return dict(refs=refs, worker=dict(run=run, entry=meta['head_sha'], repository_id=repo_id,
                                      job_id=job['id'], run_sha256=digest(meta), jobs_sha256=digest(jobs)))


def build_policy(settings, seeds, case):
    repo, repo_id, code = (settings[key] for key in ('repository', 'repository_id', 'code_sha'))
    test_repository(repo, repo_id)
    d = binding(repo, case, code, settings['public_access'][case])
    require(pin(code, 40) and pin(settings['recovery_workflow_sha256'], 64)
            and pin(settings['worker_workflow_sha256'], 64), 'reviewed commit and workflow hashes required')
    require(seeds['worker']['repository_id'] == repo_id, 'worker repository ID differs')
    for branch in (d['store_branch'], d['fence_branch'], JOURNAL):
        item = seeds['refs'][branch]
        require(branch not in PROD_BRANCHES and pin(item['commit_sha'], 40)
                and pin(item['blob_sha'], 40) and pin(item['sha256'], 64), 'exact synthetic seed pins required')
    return dict(schema='btc-continuous-recovery-v1', enabled=True, activation_reviewed=True,
                deployment=d, public_access=settings['public_access'][case],
                entry_workflows={WORKER: settings['worker_workflow_sha256']},
                recovery_entry=dict(repository=repo, branch=CODE, code_sha=code,
                                    workflow=WORKFLOW, workflow_sha256=settings['recovery_workflow_sha256']),
                journal=dict(repository=repo, branch=JOURNAL, reviewed=True,
                             seed_commit=seeds['refs'][JOURNAL]['commit_sha'],
                             public_access=settings['journal_access'], credential_reference=writer_reference(repo_id),
                             required_permissions={'contents': 'write', 'metadata': 'read'}))


def matches(record, expected):
    return pins(record) == expected


def pins(record):
    return dict(commit_sha=record['commit_sha'], blob_sha=record['blob_sha'], sha256=sha(record['body']))


def protection(client, policy, repo_id):
    import public_access as access

    d, journal = policy['deployment'], policy['journal']
    repo = d['private_store_repository']
    business = [(repo, d['store_branch']), (repo, d['fence_branch'])]
    for proof, targets in ((policy['public_access'], business), (journal['public_access'], [(repo, JOURNAL)])):
        require(set(proof['repositories']) == {repo}
                and proof['repositories'][repo]['id'] == repo_id, 'foreign protection evidence')
        for _, branch in targets:
            access.protection(client, proof, repo, branch)
    access.repository(client, policy['public_access'], repo, d['store_branch'])
    access.deployment(policy['public_access'], d)
    access.credential(journal['public_access'], 'recovery_journal_write', repo, [JOURNAL])
    require(journal['public_access']['credential_reviews']['recovery_journal_write']['credential_reference']
            == journal['credential_reference'], 'synthetic writer review differs')


def execute(root, settings, seeds, case, entry, environment, token, opener=None):
    add_paths(root)
    from continuous_operations import worker_evidence
    from production_contract import canonical, digest

    started = time.monotonic()
    recovery = load(root)
    policy = build_policy(settings, seeds, case)
    d = policy['deployment']
    repo, repo_id = settings['repository'], settings['repository_id']
    require(pin(entry, 40) and environment.get('GITHUB_SHA') == entry
            and environment.get('GITHUB_WORKFLOW_SHA') == entry
            and environment.get('GITHUB_REPOSITORY_ID') == str(repo_id)
            and environment.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
            and environment.get('GITHUB_RUN_ATTEMPT') == '1'
            and environment.get('GITHUB_API_URL') == 'https://api.github.com',
            'reviewed GitHub runner identity required')
    stream, fence = branches(case)
    original_fence = seeds['refs'][fence]['commit_sha']
    journal_path = 'recovery/incidents/' + original_fence + '.json'
    expected_puts = {'journal': 4 if case == 'safe' else 1, 'fence': int(case == 'safe')}
    puts = dict.fromkeys(expected_puts, 0)
    recovery.run.__globals__['_test_writer_reference'] = writer_reference(repo_id)

    class Guarded(recovery.Network):
        def __init__(self, write=False):
            super().__init__(policy, token, token, opener=opener)
            self.started = started
            self.write = write

        def _request(self, method, route, payload=None):
            # The library's same-repository classification normally selects the
            # metadata token first. Here it is deliberately the SAME job token;
            # maintain an outer route boundary even for this collapsed topology.
            prefix = self._route(repo, '')
            require(route == prefix or route.startswith(prefix + '/'), 'foreign API repository')
            tail = route[len(prefix):]
            if method == 'GET':
                fixed = ('', '/git/ref/heads/' + stream, '/git/ref/heads/' + fence,
                         '/git/ref/heads/' + JOURNAL)
                contents = (recovery.g.STORE_PATH, recovery.actions.FENCE_PATH, journal_path,
                            WORKFLOW, WORKER)
                file_route = any(re.fullmatch('/contents/' + re.escape(path) + r'\?ref=[0-9a-f]{40}', tail)
                                 for path in contents)
                ref_rules = any(re.fullmatch(r'/rules/branches/' + branch + r'\?per_page=100&page=[1-4]', tail)
                                for branch in (stream, fence, JOURNAL))
                metadata = re.fullmatch(
                    r'/actions/runs(?:/[1-9][0-9]*(?:/attempts/1/jobs\?per_page=100&page=1)?'
                    r'|\?status=(?:in_progress|waiting|requested|pending|queued)&per_page=100&page=1)', tail)
                other = re.fullmatch(r'/rulesets/[1-9][0-9]*|/git/commits/[0-9a-f]{40}'
                                     r'|/compare/[0-9a-f]{40}\.\.\.[0-9a-f]{40}\?per_page=1', tail)
                require(tail in fixed or file_route or ref_rules or metadata or other, 'unreviewed read route')
            else:
                key = {('/contents/' + journal_path, JOURNAL): 'journal',
                       ('/contents/' + recovery.actions.FENCE_PATH, fence): 'fence'}.get(
                           (tail, (payload or {}).get('branch')))
                require(self.write and method == 'PUT' and key in puts and puts[key] < expected_puts[key],
                        'unreviewed write route, branch or budget')
                require(recovery.bind_self(self, environment) == identity, 'runner/job changed before write')
                protection(self, policy, repo_id)
                require(self._request('GET', prefix + '/git/ref/heads/' + stream)['object']['sha']
                        == seeds['refs'][stream]['commit_sha'], 'synthetic stream moved before write')
                if puts['fence'] == 0:
                    require(self._request('GET', prefix + '/git/ref/heads/' + fence)['object']['sha']
                            == original_fence, 'synthetic fence moved before write')
                puts[key] += 1
            value = super()._request(method, route, payload)
            if tail == '/actions/runs/' + environment['GITHUB_RUN_ID']:
                require(value['repository']['id'] == repo_id and value['event'] == 'workflow_dispatch',
                        'actual runner repository or event differs')
            return value

    before = Guarded()
    identity = recovery.bind_self(before, environment)
    protection(before, policy, repo_id)
    f, open_fence, s, envelope = recovery.inspect(before)
    require(matches(f, seeds['refs'][fence]) and matches(s, seeds['refs'][stream])
            and open_fence['phase'] == 'open' and open_fence['run'] == seeds['worker']['run'],
            'fixture head, body or worker differs')
    # The preceding positive case may have advanced the journal.
    seed_ref = seeds['refs'][JOURNAL]
    head = before._request('GET', before._route(repo, '/git/ref/heads/' + JOURNAL))['object']['sha']
    require((case != 'safe' or head == seed_ref['commit_sha'])
            and before.is_ancestor(repo, seed_ref['commit_sha'], head)
            and recovery.ContentsJournal(before).read(journal_path) is None,
            'journal seed/history differs or incident already exists')
    meta, jobs = worker_evidence(before, open_fence['run'])
    require(worker_run(meta, repo) == open_fence['run'] and meta['head_sha'] == seeds['worker']['entry']
            and meta['repository']['id'] == repo_id and jobs['total_count'] == 1
            and jobs['jobs'][0]['id'] == seeds['worker']['job_id']
            and jobs['jobs'][0]['name'] == 'synthetic-worker'
            and jobs['jobs'][0]['conclusion'] == 'failure'
            and digest(meta) == seeds['worker']['run_sha256']
            and digest(jobs) == seeds['worker']['jobs_sha256'], 'historical runner/job differs')
    snapshot, complete = fixture(d, open_fence['run'], case)
    found = deepcopy(envelope['snapshot'])
    completion = found['control']['health'].pop('successful_runs')['signal']
    require(found == snapshot and completion['run'] == complete, 'synthetic snapshot differs')
    client = Guarded(write=True)
    require(recovery.bind_self(client, environment) == identity, 'runner/job changed')
    try:
        result = recovery.run(client, identity)
    except ValueError as exc:
        frames = []
        tb = exc.__traceback__
        while tb is not None:
            frames.append(tb.tb_frame.f_code)
            tb = tb.tb_next
        require(case == 'uncertain' and frames[-2:] ==
                [recovery.safe.receipts.__code__, recovery.safe.require.__code__],
                'executor refusal outside the delivery receipt check')
        result = dict(phase='blocked-uncertain')

    after = Guarded()
    new_f, state, new_s, new_env = recovery.inspect(after)
    journal = after.read(repo, JOURNAL, journal_path)
    ledger = json.loads(journal['body'])
    require(puts == expected_puts and new_s == s and journal['body'] == canonical(ledger).encode()
            and ledger['schema'] == 'btc-recovery-journal-v1'
            and ledger['incident'] == original_fence and ledger['policy_sha256'] == digest(policy)
            and re.fullmatch('[0-9a-f]{32}', ledger['transaction'])
            and ledger['reserved_gets'] == 128 and len(ledger['leases']) == 1
            and ledger['leases'][0]['identity'] == identity
            and ledger['leases'][0]['reserved_gets'] == 128
            and 0 < ledger['deadline_ms'] - ledger['leases'][0]['at_ms'] <= 900000
            and after.is_ancestor(repo, seed_ref['commit_sha'], journal['commit_sha']),
            'write budget or journal binding differs')
    if case == 'safe':
        recovery.safe.validate(state, new_env, recovery.locator(new_s, new_env))
        proof = state['completion']['recovery']
        write = ledger['writes']['fence']
        require(result['phase'] == 'recovered-await-fresh-regular-run' and result['outcome'] == 'reconciled'
                and result['incident'] == original_fence and result['stream_commit'] == s['commit_sha']
                and result['fence_commit'] == new_f['commit_sha']
                and set(ledger['writes']) == {'fence'} and ledger['plan']['release'] is None
                and write['status'] == 'confirmed' and write['commit_sha'] == new_f['commit_sha']
                and write['body'] == state and write['body_sha256'] == sha(new_f['body'])
                and write['identity'] == identity and write['old']['blob_sha'] == f['blob_sha']
                and write['old']['commit_sha'] == f['commit_sha']
                and len(ledger['events']) == 1 and ledger['events'][0]['phase'] == 'fence-confirmed'
                and ledger['events'][0]['commit_sha'] == new_f['commit_sha']
                and proof['old_fence_commit'] == original_fence and proof['old_fence_sha256'] == sha(f['body'])
                and proof['run_sha256'] == digest(meta) and proof['jobs_sha256'] == digest(jobs)
                and proof['policy_sha256'] == digest(policy)
                and after.parents(repo, new_f['commit_sha']) == [original_fence], 'confirmation proof differs')
    else:
        require(result['phase'] == 'blocked-uncertain' and new_f == f and state['phase'] == 'open'
                and ledger['plan'] is None and ledger['writes'] == {} and ledger['events'] == [],
                'uncertain delivery changed business state')
    return dict(case=case, result=result, identity=identity, repository=repo, repository_id=repo_id,
                worker=dict(run=open_fence['run'], entry=meta['head_sha'], job_id=jobs['jobs'][0]['id'],
                            run_sha256=digest(meta), jobs_sha256=digest(jobs)),
                stream=dict(branch=stream, before=pins(s), after=pins(new_s)),
                fence=dict(branch=fence, before=pins(f), after=pins(new_f)),
                journal=dict(branch=JOURNAL, path=journal_path, pins=pins(journal), transaction=ledger['transaction'],
                             deadline_ms=ledger['deadline_ms']),
                policy_sha256=digest(policy), puts=puts,
                gets=dict(preflight=before.bootstrap, bootstrap=client.bootstrap,
                          lease=128 - client.journal.remaining, readback=after.bootstrap))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--settings', type=Path, required=True)
    commands = p.add_subparsers(dest='command', required=True)
    setup = commands.add_parser('seed')
    setup.add_argument('--worker', type=Path, required=True)
    setup.add_argument('--jobs', type=Path, required=True)
    setup.add_argument('--git-dir', type=Path, required=True)
    run = commands.add_parser('run')
    run.add_argument('--seeds', type=Path, required=True)
    run.add_argument('--case', choices=CASES, required=True)
    args = p.parse_args()
    raw = args.settings.read_bytes()
    settings = json.loads(raw)
    if args.command == 'seed':
        result = seed(args.root, settings, json.loads(args.worker.read_bytes()),
                      json.loads(args.jobs.read_bytes()), args.git_dir)
    else:
        seeds = args.seeds.read_bytes()
        require(sha(raw) == os.environ.get('TEST_SETTINGS_SHA256')
                and sha(seeds) == os.environ.get('TEST_SEEDS_SHA256'), 'reviewed input hashes differ')
        result = execute(args.root, settings, json.loads(seeds), args.case,
                         os.environ.get('TEST_ENTRY_SHA'), os.environ, os.environ.get('GITHUB_TOKEN'))
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
