"""One-time aborted Watch closure. Pure validators/builders; no I/O or sender.

Caller must independently confirm both CAS writes and stopped-writer evidence.
An aborted closure is never an engine success or a healthy observation.
"""
from copy import deepcopy
import hashlib
import re
from production_contract import canonical, digest, validate_v2
from github_delivery import StoreConflict

SCHEMA = 'btc-aborted-watch-39700885866-v1'
STREAM_PIN = '830a939cd673f6cc97be8cc85b32e57a513c21eb'
FENCE_PIN = '656d569b94597830c8931d9fe9e4642a7b59870c'
STREAM_HASH = '60d3c004ca0717d71243a68d73fceb77182c2cfeb41a62aabed82cf735a05a57'
FENCE_HASH = '2b5065170f94e13a850c2fa09f03db70f4e77a0855d62ad3606177e12a0a05a5'
SNAPSHOT = '6aa398d6cd3f879efc3e235930ea524eb57bebcfa499b5d5d57e41926c5fc1ef'

def require(ok):
    if not ok:
        raise StoreConflict('Aborted maintenance binding/evidence refused')

def receipts(snapshot):
    messages = [m for s in [snapshot['engine'], *snapshot['commands'].values()]
                for m in s.get('_delivery', {}).get('messages', [])]
    require(len(messages) == 18 and all(m['status'] == 'confirmed'
        and type(m.get('receipt')) is int and m['receipt'] > 0
        and m.get('attempts') == 1 and m.get('target') == snapshot['control']['target_binding']
        for m in messages))
    return digest(messages)

def review_evidence(review):
    require(review.get('schema') == SCHEMA and bool(review.get('reviewer'))
        and review.get('stream_pin') == STREAM_PIN and review.get('fence_pin') == FENCE_PIN
        and review.get('failed_run') == '39700885866'
        and type(review.get('stopped_at_ms')) is int and review['stopped_at_ms'] > 0
        and all(review.get(k) is True for k in ('triggers_paused','workers_terminated','run_completed'))
        and all(re.fullmatch('[0-9a-f]{64}', review.get(k, '')) for k in
                ('pause_evidence_sha256','termination_evidence_sha256','failed_run_evidence_sha256')))

def preflight(stream_record, fence_record, review):
    import json
    review_evidence(review)
    require(stream_record['commit_sha'] == STREAM_PIN and fence_record['commit_sha'] == FENCE_PIN
        and hashlib.sha256(stream_record['body']).hexdigest() == STREAM_HASH
        and hashlib.sha256(fence_record['body']).hexdigest() == FENCE_HASH)
    stream = json.loads(stream_record['body']); fence = json.loads(fence_record['body'])
    validate_v2(stream['snapshot']); receipts(stream['snapshot'])
    require(review.get('old_owner') == stream['snapshot']['control']['owner'])
    return stream, fence

def takeover_evidence(review):
    review_evidence(review)
    return {**review, 'evidence_sha256': digest(review)}

def validate_pair(fence, envelope, locator):
    """Validate the released snapshot, exact predecessor and aborted receipt."""
    c = fence['completion']; m = c['maintenance']; review = m['review']
    review_evidence(review)
    require(c.get('outcome') == 'aborted' and fence['phase'] == 'closed'
        and fence['run']['id'] == '39700885866' and fence['run']['kind'] == 'watch'
        and envelope['revision'] == 1802 and c['stream'] == locator
        and locator['revision'] == 1802 and locator['snapshot_digest'] == envelope['body_digest']
        and envelope['parent_digest'] == SNAPSHOT
        and digest(envelope['snapshot']) == envelope['body_digest']
        and all(locator.get(k) == v for k, v in {
            'adapter':'github', 'repo':'szoceikaiser/btc-delivery-store',
            'branch':'delivery-stream-live', 'path':'delivery/stream.json',
            'store_id':'btc-signal-app-live-store-20261018'}.items())
        and all(envelope.get(k) == locator[k] for k in ('repo','branch','store_id'))
        and re.fullmatch('[0-9a-f]{40}', locator.get('commit_sha', ''))
        and locator['commit_sha'] != STREAM_PIN
        and hashlib.sha1(b'blob '+str(len(canonical(envelope).encode())).encode()+b'\0'
                         +canonical(envelope).encode()).hexdigest() == locator.get('blob_sha'))
    snapshot = deepcopy(envelope['snapshot']); validate_v2(snapshot)
    require(snapshot['control']['owner'] is None and receipts(snapshot) == m['receipts_sha256'])
    event = snapshot['control']['owner_events'].pop()
    if not snapshot['control']['owner_events']:
        del snapshot['control']['owner_events']
    require(event == dict(old_owner=review['old_owner'], reviewer=review['reviewer'],
        evidence_sha256=digest(review), converted_sending=0, at_revision=1801))
    snapshot['control']['owner'] = review['old_owner']
    require(digest(snapshot) == SNAPSHOT)
    # Reconstruct exact old fence: no changed run, cursor, deployment or counters.
    old = deepcopy(fence); old.update(phase='open', completion=None, write_id=m['old_write_id'])
    require(hashlib.sha256(canonical(old).encode()).hexdigest() == FENCE_HASH)

def close_candidate(old_fence, released, locator, review, write_id):
    """Only after independent confirmation of the actual S1 commit/parent."""
    review_evidence(review)
    require(bool(write_id) and locator['commit_sha'] != STREAM_PIN)
    result = deepcopy(old_fence)
    result.update(phase='closed', write_id=write_id, completion={
        'outcome':'aborted', 'stream':deepcopy(locator), 'maintenance':{
            'review':deepcopy(review), 'old_write_id':old_fence['write_id'],
            'receipts_sha256':receipts(released['snapshot'])}})
    validate_pair(result, released, locator)
    return result

def refuse_healthy(fence):
    if (fence.get('completion') or {}).get('outcome') == 'aborted':
        raise ValueError('Maintenance aborted; fresh successful regular run required')

def next_step(stream_record, fence_record, review):
    """Read-only crash recovery decision. Requires independently checked parents.

    No return value authorizes a write; it names the only potentially next step.
    Reconfirm quiescence and the signed review evidence before using it.
    """
    import json
    review_evidence(review)
    if stream_record['commit_sha'] == STREAM_PIN:
        preflight(stream_record, fence_record, review)
        return 'takeover'
    require(stream_record.get('parents') == [STREAM_PIN])
    envelope = json.loads(stream_record['body'])
    require(stream_record['body'] == canonical(envelope).encode())
    locator = dict(adapter='github', repo=envelope['repo'], branch=envelope['branch'],
        path='delivery/stream.json', store_id=envelope['store_id'], revision=envelope['revision'],
        commit_sha=stream_record['commit_sha'], blob_sha=stream_record['blob_sha'],
        snapshot_digest=envelope['body_digest'])
    fence = json.loads(fence_record['body'])
    if fence_record['commit_sha'] == FENCE_PIN:
        require(hashlib.sha256(fence_record['body']).hexdigest() == FENCE_HASH)
        close_candidate(fence, envelope, locator, review, 'LOCAL-VALIDATION-ONLY')
        return 'close-aborted-only; do-not-repeat-takeover'
    require(fence_record.get('parents') == [FENCE_PIN]
        and fence_record['body'] == canonical(fence).encode()
        and fence['completion']['maintenance']['review'] == review)
    validate_pair(fence, envelope, locator)
    return 'already-confirmed; no-write'
