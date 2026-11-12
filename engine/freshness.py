"""Pure deadline evaluator and read-only orchestration. No HTTP listener."""
from copy import deepcopy
from production_contract import CANDLE_MS, validate_v2

MINUTE = 60000
MAX_RUN_MS = 15 * MINUTE
LATE_MS = 45 * MINUTE
BACKUP_MS = 26 * 60 * MINUTE
MAX_RUNS = 100


def occurrence(schedule, at):
    """Explicit UTC period/phase; phase describes START, never candle open."""
    period, phase, first = (schedule[k] for k in ('period_ms', 'phase_ms', 'first_start_ms'))
    if (any(type(x) is not int for x in (period, phase, first)) or period <= 0
            or not 0 <= phase < period or first % period != phase):
        raise ValueError('Invalid pinned UTC schedule')
    result = ((at-phase)//period)*period+phase
    return result if result >= first else None


def response(error=None):
    return {'http_status': 503 if error else 200, 'body': {
        'schema': 'p3-freshness-v1', 'healthy': error is None,
        'error_class': error or 'ok'}}


def dispatch_slot(schedule, epoch_seconds):
    """cron-job.org substitutes %cjo:unixtime% once in the dispatch body."""
    if not isinstance(epoch_seconds,str) or not epoch_seconds.isdigit():
        raise ValueError('Explicit dispatch epoch required')
    dispatched = int(epoch_seconds)*1000
    slot = occurrence(schedule, dispatched)
    if slot is None or not slot <= dispatched < slot+2*MINUTE:
        raise ValueError('Dispatch outside pinned two-minute start window')
    return slot


def evaluate(snapshot, revision, read_revision, runs, policy, now, backup):
    """Inputs are synthetic or supplied by a later authenticated bounded reader."""
    try:
        validate_v2(snapshot)
        c = snapshot['control']; expected = policy['identity']
        if type(now) is not int or now < 0 or type(revision) is not int:
            return response('invalid_input')
        if any(c[k] != expected[k] for k in ('store_id', 'stream_id', 'code_sha', 'config_sha256')):
            return response('identity_mismatch')
        if c['mode'] != 'active' or c['health'].get('restore_requires_reconciliation'):
            return response('stream_blocked')
        if any(m['status'] in ('sending', 'uncertain')
                for s in [snapshot['engine'], *snapshot['commands'].values()]
                for m in s.get('_delivery', {}).get('messages', [])):
            return response('uncertain_delivery')
        if any(m['status'] != 'confirmed'
                for s in [snapshot['engine'], *snapshot['commands'].values()]
                for m in s.get('_delivery', {}).get('messages', [])):
            return response('delivery_incomplete')
        if c['health'].get('consecutive_mutex_conflicts',0)>=2:
            return response('mutex_conflicts')
        current = c['health'].get('current_run')
        if current and current['status'] != 'completed':
            return response('run_overdue' if current['status'] == 'running'
                and now-current['started_ms'] > MAX_RUN_MS else 'run_unfinished')
        if c.get('owner') is not None:
            return response('store_owned')
        for kind in ('signal', 'watch'):
            schedule = policy['schedules'][kind]
            # Before a new start deadline, the preceding obligation stays in force.
            offset = schedule.get('close_offset_ms', 0) if kind == 'signal' else 0
            due = occurrence(schedule, now-LATE_MS+offset)
            if due is None:
                return response('schedule_not_established')
            metadata = runs[kind]
            if not isinstance(metadata, list) or len(metadata) > MAX_RUNS:
                return response('run_query_incomplete')
            relevant = [r for r in metadata if r['expected_start_ms'] >= due]
            if not relevant:
                return response(kind+'_missing_start')
            latest = max(metadata, key=lambda r: (r['created_ms'], int(r['run_attempt']), r['run_id']))
            newest = latest
            due_runs = [r for r in relevant if r['expected_start_ms'] == due]
            if not due_runs: return response(kind+'_missing_start')
            due_run = max(due_runs, key=lambda r: (r['created_ms'], int(r['run_attempt'])))
            selected = [newest] if due_run == newest else [newest, due_run]
            for latest in selected:
                if any(latest[k] != schedule[k] for k in ('repository', 'workflow', 'branch')) or latest['head_sha'] != c['code_sha']:
                    return response('run_identity_mismatch')
                slot = latest['expected_start_ms']
                deadline = slot-offset+LATE_MS
                if occurrence(schedule, slot) != slot or not slot <= latest['created_ms'] <= deadline:
                    return response('run_schedule_mismatch')
                if latest['status'] != 'completed':
                    return response('run_overdue' if now-latest['started_ms'] > MAX_RUN_MS else 'run_unfinished')
                if latest['conclusion'] != 'success':
                    return response('run_failed')
                if not (slot <= latest['created_ms'] <= latest['started_ms'] <= latest['completed_ms'] <= now):
                    return response('run_time_mismatch')
                if latest['completed_ms']-latest['started_ms'] > MAX_RUN_MS:
                    return response('run_overdue')
                bound = (c['health'].get('successful_runs', {}).get(kind) if latest is newest else c['health'].get('completed_runs', {}).get(kind, {}).get(str(slot)))
                if not bound:
                    return response('completion_missing')
                run, locator = bound['run'], bound['completion']
                for k in ('repository', 'workflow', 'run_id', 'run_attempt', 'expected_start_ms'):
                    if run[k] != latest[k]:
                        return response('completion_run_mismatch')
                if (run['kind'] != kind or run['status'] != 'completed' or not run['nonce']
                        or any(run[k] != c[k] for k in ('store_id', 'stream_id', 'code_sha', 'config_sha256'))):
                    return response('completion_identity_mismatch')
                if (locator['store_id'] != c['store_id'] or locator['adapter'] != policy['store']['adapter']
                        or any(locator.get(k) != v for k, v in policy['store'].items())
                        or type(locator['revision']) is not int or not 0 <= locator['revision'] < revision
                        or locator['revision'] != run['revision']):
                    return response('completion_revision_mismatch')
                if not (latest['started_ms'] <= run['started_ms'] <= run['finished_ms'] <= latest['completed_ms']):
                    return response('completion_time_mismatch')
                if run['finished_ms'] > deadline:
                    return response('completion_overdue')
                completed_snapshot = read_revision(locator)
                validate_v2(completed_snapshot)
                if (completed_snapshot['control']['health']['completion_candidate'] != run
                        or any(completed_snapshot['control'][k] != c[k]
                               for k in ('store_id', 'stream_id', 'code_sha', 'config_sha256'))):
                    return response('completion_revision_mismatch')
                if kind == 'signal':
                    # Signal schedule follows CLOSE + offset. Candle.ts remains OPEN.
                    close = slot-schedule['close_offset_ms']
                    if close % CANDLE_MS or run['last_signal_ts'] != close-CANDLE_MS:
                        return response('signal_candle_mismatch')
                elif (run['watch_candle_open_ms'] != run['watch_observed_ms']//CANDLE_MS*CANDLE_MS
                        or not run['started_ms'] <= run['watch_observed_ms'] <= run['finished_ms']):
                    return response('watch_observation_mismatch')
        # Daily backup has two hours grace: 26h from its expected occurrence,
        # never 26h from a delayed successful receipt.
        if (not backup or backup['status'] != 'confirmed'
                or occurrence(policy['schedules']['backup'], backup['expected_start_ms']) != backup['expected_start_ms']
                or any(backup[k] != c[k] for k in ('store_id', 'code_sha', 'config_sha256'))
                or not backup['expected_start_ms'] <= backup['verified_ms'] <= now
                or now-backup['expected_start_ms'] > BACKUP_MS
                or not backup.get('manifest_sha256') or not backup.get('store_commit_sha')
                or not backup.get('history_verified') is True
                or not backup.get('restore_blocked_verified') is True
                or not 0 <= backup['source_revision'] <= revision):
            return response('backup_overdue')
        return response()
    except (KeyError, TypeError, ValueError, OverflowError):
        return response('invalid_input')
    except Exception:
        return response('api_or_store_unavailable')


def check_github(client, runs_reader, backup_reader, policy, now):
    """Later endpoint boundary; an injected reader must return complete metadata."""
    try:
        from github_delivery import read_only
        target = policy['store']
        store = read_only(client, target['repo'], target['branch'],
                          policy['identity']['store_id'], target['path'])
        head = deepcopy(store._record)
        runs = runs_reader()
        backup = backup_reader()
        if backup:
            # Backup must pin an actual ancestor of this authoritative store.
            source_pin = backup['store_commit_sha']
            if not client.is_ancestor(target['repo'], source_pin, head['commit_sha']):
                return response('backup_source_mismatch')
            source = store._parse(client.read_at(target['repo'], source_pin, target['path']))
            if (source['revision'] != backup['source_revision']
                    or source['body_digest'] != backup['snapshot_digest']):
                return response('backup_source_mismatch')
        result = evaluate(store.snapshot, store.revision, store.read_revision,
                          runs, policy, now, backup)
        if runs_reader() != runs:
            return response('runs_moved_during_check')
        # A moving head makes the combined observation inconclusive, never healthy.
        if client.read(target['repo'], target['branch'], target['path']) != head:
            return response('store_moved_during_check')
        return result
    except Exception:
        return response('api_or_store_unavailable')
