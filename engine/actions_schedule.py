"""One immutable UTC obligation contract for entry and monitor.

created_at is the Actions run creation time, NOT a promised cron fire time.
The optional millisecond input preserves an external scheduler's original slot.
"""
from freshness import MINUTE

HOUR = 60*MINUTE
CONTRACT = 'btc-actions-slots-v1'
SPECS = {'signal': (4*HOUR, (2*MINUTE, 32*MINUTE)),
         'watch': (15*MINUTE, (8*MINUTE,)),
         'backup': (24*HOUR, (0,))}


def slot_at(kind, timestamp):
    period, phases = SPECS[kind]
    return max((timestamp-phase)//period*period+phase for phase in phases)


def valid_slot(kind, slot):
    return type(slot) is int and slot > 0 and slot == slot_at(kind, slot)


def deadline(kind, slot):
    if not valid_slot(kind, slot):
        raise ValueError('Invalid fixed UTC occurrence')
    # Preserve the old signal close_offset rule: 45m from candle CLOSE.
    if kind == 'signal':
        return slot//(4*HOUR)*(4*HOUR)+45*MINUTE
    return slot+({'watch':15*MINUTE, 'backup':26*HOUR}[kind])


def due_slots(kind, now, first):
    if not valid_slot(kind, first):
        raise ValueError('Reviewed first occurrence required')
    if kind == 'signal':
        close = (now-45*MINUTE)//(4*HOUR)*(4*HOUR)
        slots = [close+p for p in SPECS[kind][1]]
    elif kind == 'watch':
        slots = [slot_at(kind, now-15*MINUTE)]
    else:
        # Daily receipt may remain valid for exactly 26h, as in p3.
        slots = [slot_at(kind, now-26*HOUR)]
    return [s for s in slots if s >= first]


def run_slot(kind, metadata, explicit=''):
    from github_freshness import utc_ms
    if metadata['event'] not in ('schedule', 'workflow_dispatch') or metadata['run_attempt'] != 1:
        raise ValueError('Unsupported trigger/attempt')
    created = utc_ms(metadata['created_at'])
    title = metadata['display_title']
    prefix = 'btc-v2:'+kind+':'
    if not title.startswith(prefix):
        raise ValueError('Bound run title missing')
    marker = title[len(prefix):]
    if marker == 'created':
        if explicit:
            raise ValueError('Explicit input/title mismatch')
        slot = slot_at(kind, created)
    else:
        if (not marker.isdigit() or (explicit and marker != explicit)
                or metadata['event'] != 'workflow_dispatch'):
            raise ValueError('Invalid explicit occurrence')
        slot = int(marker)
    if not valid_slot(kind, slot) or not slot <= created <= deadline(kind, slot):
        raise ValueError('Original occurrence already late or in future')
    return slot


def bind(kind, metadata, now, explicit=''):
    from github_freshness import utc_ms
    if kind == 'lage':
        if metadata['event'] != 'workflow_dispatch' or metadata['run_attempt'] != 1:
            raise ValueError('Manual Lage required')
        slot = utc_ms(metadata['created_at'])
        end = slot+15*MINUTE
    else:
        slot = run_slot(kind, metadata, explicit)
        end = deadline(kind, slot)
    if not slot <= now <= end:
        raise ValueError('Bounded waiting time exceeded; no replacement slot')
    return slot
