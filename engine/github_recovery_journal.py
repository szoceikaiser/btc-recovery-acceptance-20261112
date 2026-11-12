"""Server-side CAS journal. No local disk is authoritative for a recovery.

Transport implements read(path)->(blob,JSON)|None and cas(path,blob,JSON).
An uncertain CAS is resolved by reading its unique transaction, never retrying.
Every lease prepays its entire read and wallclock allowance before business I/O.
"""
from copy import deepcopy
import secrets
from production_contract import digest

def require(ok):
    if not ok:raise ValueError('Persistent recovery reservation refused')

class Journal:
    def __init__(self,transport,incident,policy_sha256,deadline_ms,clock):
        self.transport=transport;self.path='recovery/incidents/'+incident+'.json'
        self.incident=incident;self.policy=policy_sha256;self.deadline=deadline_ms;self.clock=clock
        self.remaining=0;self.lease=None
    def read(self):
        row=self.transport.read(self.path)
        if row:
            value=row[1]
            require(value['incident']==self.incident and value['policy_sha256']==self.policy
                    and value['deadline_ms']==self.deadline)
        return row
    def change(self,mutate):
        row=self.read();blob,value=row if row else (None,dict(schema='btc-recovery-journal-v1',
            incident=self.incident,policy_sha256=self.policy,deadline_ms=self.deadline,
            leases=[],reserved_gets=0,writes={},plan=None,events=[]))
        candidate=deepcopy(value);mutate(candidate)
        transaction=secrets.token_hex(16);candidate['transaction']=transaction
        try:self.transport.cas(self.path,blob,candidate)
        except Exception:pass
        observed=self.read()
        require(observed and observed[1].get('transaction')==transaction and observed[1]==candidate)
        return candidate
    def acquire(self,identity):
        require(self.clock()<self.deadline)
        def reserve(value):
            require(len(value['leases'])<3 and value['reserved_gets']+128<=384
                and identity not in [entry['identity'] for entry in value['leases']])
            value['leases'].append(dict(identity=identity,at_ms=self.clock(),reserved_gets=128))
            value['reserved_gets']+=128
        self.change(reserve);self.remaining=128;self.lease=identity
    def before_read(self):
        require(self.lease and self.remaining>0 and self.clock()<self.deadline)
        self.remaining-=1
    def plan(self,plan):
        def store(value):
            require(self.lease is not None)
            if value['plan'] is None:value['plan']=plan
            else:require(value['plan']==plan)
        return self.change(store)['plan']
    def reserve_write(self,key,old,body):
        require(self.clock()<self.deadline and self.lease)
        def reserve(value):
            require(key in ('stream','fence') and key not in value['writes'])
            value['writes'][key]=dict(old=old,body_sha256=digest(body),body=body,
                                      identity=self.lease,at_ms=self.clock(),status='reserved')
        return self.change(reserve)['writes'][key]
    def confirm(self,key,record):
        def confirm(value):
            require(key in value['writes'])
            value['writes'][key]['status']='confirmed'
            value['writes'][key]['commit_sha']=record['commit_sha']
            value['events'].append(dict(phase=key+'-confirmed',commit_sha=record['commit_sha'],at_ms=self.clock()))
        self.change(confirm)
