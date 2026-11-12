"""Offline v2 backup: immutable bounded Git increments and verified full restore.

No network, credentials, receipt upload, automatic replay or activation. The
v1 implementation remains available separately, with its original limits.
"""
from contextlib import contextmanager
from copy import deepcopy
import ctypes
from functools import lru_cache
import hashlib
import io
from itertools import islice
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'engine'))
import durable_delivery as durable
import github_delivery as github
from production_contract import canonical, digest
from produktion_store import verify_package

MIB = 1024*1024
MAX_COMMITS = 256
MAX_UNPACKED = 64*MIB
MAX_PACKAGE = 20*MIB
MAX_SEGMENTS = 512
MAX_SET_BYTES = 8*1024*MIB
MAX_MANIFEST = 128*1024
MAX_PYTHON_RSS = 256*MIB
MAX_GIT_RSS = 192*MIB
STEP_SECONDS = 120
TOTAL_SECONDS = 1800
ZERO = '0'*64
HEX40 = re.compile(r'^[0-9a-f]{40}$')
HEX64 = re.compile(r'^[0-9a-f]{64}$')


from local_publication import publish_new


def remove_staging(path, parent):
    path=Path(path); parent=Path(parent).resolve()
    if path.is_symlink() or path.resolve().parent!=parent:
        raise ValueError('Unsafe staging cleanup')
    def writable(fn, name, exc):
        if Path(name).resolve().is_relative_to(path.resolve()):
            os.chmod(name,stat.S_IWRITE|stat.S_IREAD);fn(name)
        else:raise ValueError('Unsafe cleanup entry')
    shutil.rmtree(path,onexc=writable)


@lru_cache(maxsize=1)
def windows_memory_api():
    from ctypes import wintypes
    class Counters(ctypes.Structure):
        _fields_ = [('cb',wintypes.DWORD),('faults',wintypes.DWORD)] + [
            (n,ctypes.c_size_t) for n in ('peak','working','qpp','qpu','qnp','qnu','page','peakpage')]
    k = ctypes.WinDLL('kernel32', use_last_error=True)
    k.OpenProcess.restype = wintypes.HANDLE
    k.OpenProcess.argtypes = [wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    p = ctypes.WinDLL('psapi', use_last_error=True)
    p.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE,ctypes.POINTER(Counters),wintypes.DWORD]
    return k,p,Counters


def rss(pid):
    if os.name == 'nt':
        k,p,Counters=windows_memory_api()
        handle = k.OpenProcess(0x1000|0x10,False,pid)
        if not handle: return 0
        try:
            c = Counters(); c.cb = ctypes.sizeof(c)
            return c.working if p.GetProcessMemoryInfo(handle,ctypes.byref(c),c.cb) else 0
        finally: k.CloseHandle(handle)
    try:
        return int(Path('/proc',str(pid),'statm').read_text().split()[1])*os.sysconf('SC_PAGE_SIZE')
    except (OSError,ValueError):
        raise RuntimeError('RSS measurement unavailable')


class Budget:
    def __init__(self):
        self.start = time.monotonic()
        self.python_peak = self.git_peak = 0
        self.steps = 0

    def check(self):
        used = rss(os.getpid())
        self.python_peak = max(self.python_peak, used)
        if not used: raise RuntimeError('RSS measurement unavailable')
        if used > MAX_PYTHON_RSS: raise ValueError('Python memory budget')
        if time.monotonic()-self.start > TOTAL_SECONDS: raise ValueError('Total time budget')

    def metrics(self):
        self.check()
        return dict(seconds=round(time.monotonic()-self.start,3), python_peak_rss=self.python_peak,
                    git_peak_rss=self.git_peak, git_steps=self.steps)


@lru_cache(maxsize=1)
def windows_job_api():
        from ctypes import wintypes as w
        class Basic(ctypes.Structure):
            _fields_=[('per_process',ctypes.c_longlong),('per_job',ctypes.c_longlong),
                ('flags',w.DWORD),('min_ws',ctypes.c_size_t),('max_ws',ctypes.c_size_t),
                ('active',w.DWORD),('affinity',ctypes.c_size_t),('priority',w.DWORD),('scheduling',w.DWORD)]
        class IO(ctypes.Structure):
            _fields_=[(n,ctypes.c_ulonglong) for n in ('read','write','other','rbytes','wbytes','obytes')]
        class Limits(ctypes.Structure):
            _fields_=[('basic',Basic),('io',IO),('process_memory',ctypes.c_size_t),
                ('job_memory',ctypes.c_size_t),('peak_process',ctypes.c_size_t),('peak_job',ctypes.c_size_t)]
        class Pids(ctypes.Structure):
            _fields_=[('assigned',w.DWORD),('count',w.DWORD),('pids',ctypes.c_size_t*64)]
        k=ctypes.WinDLL('kernel32',use_last_error=True)
        k.CreateJobObjectW.restype=w.HANDLE
        k.CreateJobObjectW.argtypes=[ctypes.c_void_p,w.LPCWSTR]
        k.SetInformationJobObject.argtypes=[w.HANDLE,ctypes.c_int,ctypes.c_void_p,w.DWORD]
        k.AssignProcessToJobObject.argtypes=[w.HANDLE,w.HANDLE]
        k.TerminateJobObject.argtypes=[w.HANDLE,w.UINT]
        k.QueryInformationJobObject.argtypes=[w.HANDLE,ctypes.c_int,ctypes.c_void_p,w.DWORD,ctypes.c_void_p]
        k.CloseHandle.argtypes=[w.HANDLE]
        resume=ctypes.WinDLL('ntdll').NtResumeProcess
        resume.argtypes=[w.HANDLE];resume.restype=ctypes.c_long
        return k,Limits,Pids,resume


class ProcessTree:
    """Windows job owns Git launcher AND its children; no orphaned pipes."""
    def __init__(self,p):
        self.p=p;self.handle=None
        if os.name!='nt':return
        from ctypes import wintypes as w
        self.k,Limits,self.Pids,resume=windows_job_api()
        self.handle=self.k.CreateJobObjectW(None,None)
        limits=Limits();limits.basic.flags=0x2000|0x200;limits.job_memory=MAX_GIT_RSS
        if (not self.handle or not self.k.SetInformationJobObject(self.handle,9,ctypes.byref(limits),ctypes.sizeof(limits))
                or not self.k.AssignProcessToJobObject(self.handle,w.HANDLE(int(p._handle)))):
            self.close();p.kill();raise RuntimeError('Cannot enforce Git process-tree limits')
        if resume(w.HANDLE(int(p._handle)))!=0:
            self.kill();self.close();raise RuntimeError('Cannot start guarded Git process')

    def memory(self):
        if not self.handle:
            total=count=0
            for item in Path('/proc').iterdir():
                if not item.name.isdigit():continue
                try:
                    fields=(item/'stat').read_text().rpartition(')')[2].split()
                    if int(fields[2])==self.p.pid:
                        total+=rss(int(item.name));count+=1
                except (OSError,IndexError,ValueError):continue
                # Do not catch the deliberate limit failure as a vanished PID.
                if count>64: raise ValueError('Git process-tree limit')
            return total
        ids=self.Pids()
        if not self.k.QueryInformationJobObject(self.handle,3,ctypes.byref(ids),ctypes.sizeof(ids),None):
            raise RuntimeError('Git process-tree measurement failed')
        if ids.count>64:raise ValueError('Git process-tree limit')
        return sum(rss(pid) for pid in ids.pids[:ids.count])

    def kill(self):
        if self.handle:self.k.TerminateJobObject(self.handle,1)
        else:
            try:os.killpg(self.p.pid,signal.SIGKILL)
            except ProcessLookupError:pass

    def close(self):
        if self.handle:self.k.CloseHandle(self.handle);self.handle=None


@contextmanager
def process(repo, args, budget, env=None, file_limit=None):
    budget.check(); budget.steps += 1
    command = ['git','-c','safe.directory='+Path(repo).resolve().as_posix(),
        '-c','pack.threads=1','-c','pack.windowMemory=32m','-c','pack.deltaCacheSize=16m',
        '-c','core.hooksPath='+('NUL' if os.name=='nt' else '/dev/null'),'-c','core.fsmonitor=false',
        '-c','core.longpaths=true',
        '-c','protocol.allow=never','-c','protocol.file.allow=always',
        '-c','core.autocrlf=false','-C',str(repo),*args]
    # No inherited alternate object stores, replace refs, or injected Git options.
    clean = {k:os.environ[k] for k in (
        'PATH','SystemRoot','SYSTEMROOT','WINDIR','TEMP','TMP','TMPDIR','LANG','LC_ALL') if k in os.environ}
    clean['GIT_NO_REPLACE_OBJECTS'] = '1'
    clean['GIT_CONFIG_NOSYSTEM']='1';clean['GIT_CONFIG_GLOBAL']=os.devnull
    if env: clean.update(env)
    with tempfile.TemporaryFile() as errors:
        if file_limit and os.name!='nt':
            # No preexec_fn in this HTTP-threaded parent: a fork-time Python
            # import lock could otherwise bypass the launch watchdog entirely.
            wrapper=('import os,resource,sys;'
                f'resource.setrlimit(resource.RLIMIT_FSIZE,({file_limit},{file_limit}));'
                f'resource.setrlimit(resource.RLIMIT_AS,({MAX_GIT_RSS},{MAX_GIT_RSS}));'
                'os.execvp(sys.argv[1],sys.argv[1:])')
            command=[sys.executable,'-c',wrapper,*command]
        p = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=errors, env=clean,creationflags=0x4 if os.name=='nt' else 0,
                             start_new_session=os.name!='nt')
        tree=ProcessTree(p)
        stopped = threading.Event(); failure = []; began = time.monotonic()
        def watch():
            while not stopped.wait(.05):
                try:
                    budget.check()
                    if p.poll() is not None: return
                    used = tree.memory(); budget.git_peak = max(budget.git_peak,used)
                    if used > MAX_GIT_RSS: raise ValueError('Git memory budget')
                    if time.monotonic()-began > STEP_SECONDS: raise ValueError('Git step time budget')
                except BaseException as exc:
                    failure.append(exc); tree.kill(); return
        thread = threading.Thread(target=watch, daemon=True); thread.start()
        try:
            yield p
            if p.stdin and not p.stdin.closed: p.stdin.close()
            p.wait(timeout=STEP_SECONDS)
            if failure: raise failure[0]
            if p.returncode:
                errors.seek(0)
                raise ValueError('Local Git step failed: '+errors.read(2048).decode(errors='replace'))
            budget.check()
        finally:
            if p.poll() is None: tree.kill()
            p.wait(); stopped.set(); thread.join()
            tree.close()
            if p.stdin and not p.stdin.closed: p.stdin.close()
            p.stdout.close()


def read_bounded(stream, limit):
    """Grow with received bytes, never preallocate the entire allowed response.

    Read one excess byte to distinguish exact EOF from a truncated transfer.
    The surrounding HTTP deadline / Git process watchdog still bounds stalls.
    """
    if type(limit) is not int or limit < 0: raise ValueError('Invalid byte limit')
    with io.BytesIO() as out:
        while True:
            chunk=stream.read(min(65536,limit-out.tell()+1))
            if not chunk: return out.getvalue()
            if len(chunk)>limit-out.tell(): raise ValueError('Response byte limit')
            out.write(chunk)


def git(repo, budget, *args):
    with process(repo, args, budget) as p:
        p.stdin.close()
        out = read_bounded(p.stdout,16*MIB)
    return out


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(MIB),b''): h.update(b)
    return h.hexdigest()


def write_json(path, value):
    with Path(path).open('x',encoding='utf-8',newline='\n') as f:
        f.write(canonical(value)+'\n'); f.flush(); os.fsync(f.fileno())


def read_json(path):
    path = Path(path)
    if path.is_symlink() or path.stat().st_size > MAX_MANIFEST: raise ValueError('Manifest size/type')
    raw = path.read_bytes(); value = json.loads(raw)
    if raw != (canonical(value)+'\n').encode(): raise ValueError('Noncanonical manifest')
    return value


@contextmanager
def batch(repo, budget):
    with process(repo, ['cat-file','--batch'], budget) as p:
        def read(name, kind, limit):
            p.stdin.write((name+'\n').encode()); p.stdin.flush()
            header = p.stdout.readline(256).decode().strip().split()
            if len(header)!=3 or header[1]!=kind or not header[2].isdigit():
                raise ValueError('Git object missing/type')
            size = int(header[2])
            if size>limit: raise ValueError('Git object size budget')
            body = p.stdout.read(size)
            if len(body)!=size or p.stdout.read(1)!=b'\n': raise ValueError('Short Git object')
            return body
        yield read


def parser(identity):
    if set(identity)!={'repo','branch','store_id','stream_id'} or not all(
            isinstance(v,str) and v for v in identity.values()): raise ValueError('Backup identity')
    return github.GitHubStore(None,identity['repo'],identity['branch'],identity['store_id'],'verify','1')


def inspect(read, commit, identity, parse):
    raw = read(commit,'commit',16384)
    headers=raw.split(b'\n\n',1)[0].splitlines()
    parents = [line[7:].decode() for line in headers if line.startswith(b'parent ')]
    trees=[line[5:].decode() for line in headers if line.startswith(b'tree ')]
    if len(trees)!=1:raise ValueError('Commit tree missing')
    # The dedicated state branch contains exactly delivery/stream.json. This
    # bounds ALL uncompressed objects, not only the JSON while hiding huge blobs.
    tree=read(trees[0],'tree',4096);prefix=b'40000 delivery\0'
    if len(tree)!=len(prefix)+20 or not tree.startswith(prefix):raise ValueError('Unexpected store tree')
    leaf=read(tree[-20:].hex(),'tree',4096);prefix=b'100644 stream.json\0'
    if len(leaf)!=len(prefix)+20 or not leaf.startswith(prefix):raise ValueError('Unexpected store files')
    body = read(commit+':'+github.STORE_PATH,'blob',github.MAX_BYTES)
    env = parse._parse({'body':body})
    if env['snapshot']['control']['stream_id']!=identity['stream_id']: raise ValueError('Stream identity')
    return parents, body, env


def commits(repo, pin, prior, budget):
    if not HEX40.fullmatch(pin) or (prior and not HEX40.fullmatch(prior)): raise ValueError('Commit pin')
    args = ['rev-list','--reverse','--topo-order',pin]
    if prior: args.append('^'+prior)
    # Bounded IDs only (<=131072), never historical bodies. Close rev-list
    # before package work so its deadline is not charged for downstream work.
    rows=git(repo,budget,*args).splitlines()
    if len(rows)>MAX_SEGMENTS*MAX_COMMITS: raise ValueError('Total commit budget')
    for row in rows:
        commit=row.decode()
        if not HEX40.fullmatch(commit): raise ValueError('Commit list')
        yield commit


def lineage(env, parents, prior_pin, prior_revision, prior_digest):
    if (parents!=([prior_pin] if prior_pin else []) or env['revision']!=prior_revision+1
            or env['parent_digest']!=prior_digest): raise ValueError('Complete history lineage required')
    if not prior_pin and (env['snapshot']['control']['mode']!='blocked'
            or env['snapshot']['control']['owner'] is not None): raise ValueError('Blocked seed required')


def row_bytes(pin, parent, env):
    return (canonical([pin,parent,env['revision'],env['parent_digest'],env['body_digest']])+'\n').encode()


def inventory(folder, exclude_manifest=True):
    result = {}
    total=0
    for p in sorted(Path(folder).rglob('*')):
        if p.is_symlink(): raise ValueError('Package symlink')
        if p.is_file() and (not exclude_manifest or p.relative_to(folder).as_posix()!='segment.json'):
            size=p.stat().st_size;total+=size
            if len(result)>=64 or total>MAX_PACKAGE:raise ValueError('Package inventory budget')
            result[p.relative_to(folder).as_posix()] = {'bytes':size,'sha256':sha(p)}
    return result


def load_segments(root, identity, budget=None):
    budget=budget or Budget()
    parts = Path(root)/'packages'
    files = sorted(p for p in parts.iterdir() if not p.name.startswith('.')) if parts.exists() else []
    if len(files)>MAX_SEGMENTS: raise ValueError('Segment count budget')
    manifests=[]; previous=ZERO; prior_pin=None; revision=-1; total=0
    for i,p in enumerate(files):
        budget.check()
        if p.name!=f'{i:06d}' or not p.is_dir() or p.is_symlink(): raise ValueError('Missing/interchanged package')
        m=read_json(p/'segment.json')
        if (m['schema']!='p3-backup-segment-v2' or m['identity']!=identity or m['index']!=i
                or m['previous_manifest_sha256']!=previous or m['parent_pin']!=prior_pin
                or m['first_revision']!=revision+1 or not 1<=m['count']<=MAX_COMMITS
                or m['revision']!=revision+m['count'] or not HEX40.fullmatch(m['pin'])
                or not 0<m['unpacked_bytes']<=MAX_UNPACKED): raise ValueError('Segment chain mismatch')
        actual=inventory(p)
        if actual!=m['files'] or 'history.bundle' not in actual or 'stream.json' not in actual:
            raise ValueError('Package inventory/hash mismatch')
        if (i==0) != any(n.startswith('migration/') for n in actual): raise ValueError('Migration placement')
        size=sum(v['bytes'] for v in actual.values())+(p/'segment.json').stat().st_size
        if size>MAX_PACKAGE: raise ValueError('Package byte budget')
        total+=size
        if total>MAX_SET_BYTES: raise ValueError('Set byte budget')
        manifests.append(m); previous=digest(m); prior_pin=m['pin']; revision=m['revision']
    return manifests,total


def set_manifest(manifests, total):
    if not manifests: raise ValueError('Empty package set')
    m=manifests[-1]; c=m['control']
    hashes=[digest(x) for x in manifests]
    return dict(schema='p3-backup-set-v2',identity=m['identity'],store_path=github.STORE_PATH,
        stream_id=m['identity']['stream_id'],pin=m['pin'],revision=m['revision'],
        snapshot_digest=m['snapshot_digest'],code_sha=c['code_sha'],config_sha256=c['config_sha256'],
        migration_id=c['migration_id'],target_binding=c['target_binding'],bot_identity=c['bot_identity'],
        history_count=sum(x['count'] for x in manifests),package_count=len(hashes),
        package_manifest_sha256=hashes,chain_sha256=digest(hashes),package_bytes=total,
        unpacked_bytes=sum(x['unpacked_bytes'] for x in manifests),
        warnings=[key for key,used,limit in [('packages',len(hashes),MAX_SEGMENTS),
            ('set_bytes',total,MAX_SET_BYTES)] if used>=.8*limit])


def control(env):
    c=env['snapshot']['control']
    return {**{k:c[k] for k in ('code_sha','config_sha256','target_binding','bot_identity')},
            'migration_id':c['migration']['migration_id']}


def restore_verified(root, manifest, target, required_pin, required_revision, identity, budget=None):
    """Fresh full restore from packages only; required identity/pin are independent."""
    budget=budget or Budget(); target=Path(target).resolve(); root=Path(root).resolve()
    if type(required_revision) is not int or required_revision<0:raise ValueError('Independent revision required')
    if target.exists(): raise FileExistsError(target)
    manifests,total=load_segments(root,identity,budget)
    if (set_manifest(manifests,total)!=manifest or manifest['pin']!=required_pin
            or manifest['revision']!=required_revision): raise ValueError('Required complete latest set missing')
    parse=parser(identity)
    stage=Path(tempfile.mkdtemp(prefix='.p3-v2-restore-',dir=target.parent))
    try:
        repo=stage/'verification-repository';repo.mkdir()
        git(repo,budget,'init','--bare')
        prior_pin=None; prior_rev=-1; prior_digest=ZERO; count=0
        for i,m in enumerate(manifests):
            budget.check(); package=root/'packages'/f'{i:06d}'
            bundle=package/'history.bundle'
            # Check declared bundle prerequisite exactly, not merely satisfiable.
            with bundle.open('rb') as f:
                header=f.readline(); prereq=[]; refs=[]
                if header!=b'# v2 git bundle\n': raise ValueError('Bundle version')
                for _ in range(16):
                    line=f.readline(8192)
                    if line==b'\n': break
                    if line.startswith(b'-'): prereq.append(line[1:].split()[0].decode())
                    else: refs.append(line.decode().strip())
                else: raise ValueError('Bundle header limit')
            if prereq!=([prior_pin] if prior_pin else []) or refs!=[m['pin']+' refs/heads/backup']:
                raise ValueError('Bundle dependency/ref mismatch')
            git(repo,budget,'bundle','verify',str(bundle))
            git(repo,budget,'bundle','unbundle',str(bundle))
            h=hashlib.sha256(); unpacked=0; segment_count=0
            with batch(repo,budget) as read:
                for pin in commits(repo,m['pin'],prior_pin,budget):
                    parents,body,env=inspect(read,pin,identity,parse)
                    lineage(env,parents,prior_pin,prior_rev,prior_digest)
                    h.update(row_bytes(pin,prior_pin,env));unpacked+=len(body);segment_count+=1
                    if segment_count>MAX_COMMITS or unpacked>MAX_UNPACKED: raise ValueError('History step budget')
                    prior_pin=pin;prior_rev=env['revision'];prior_digest=env['body_digest'];count+=1
                    budget.check()
            if (segment_count!=m['count'] or unpacked!=m['unpacked_bytes'] or h.hexdigest()!=m['history_sha256']
                    or prior_pin!=m['pin'] or prior_rev!=m['revision'] or prior_digest!=m['snapshot_digest']
                    or body!=(package/'stream.json').read_bytes() or control(env)!=m['control']):
                raise ValueError('Verified segment mismatch')
            git(repo,budget,'update-ref','refs/heads/backup',prior_pin)
        git(repo,budget,'fsck','--full','--no-reflogs')
        if count!=required_revision+1 or count!=manifest['history_count']: raise ValueError('Full history count')
        migrated=verify_package(root/'packages/000000/migration')
        if migrated['control']['migration']['migration_id']!=manifest['migration_id']:
            raise ValueError('Migration identity mismatch')
        snapshot=deepcopy(env['snapshot']);snapshot['control'].update(mode='blocked',owner=None)
        snapshot['control']['health'].update(restore_requires_reconciliation=True,
            restored_from_commit=required_pin,restored_from_revision=required_revision,
            successful_runs={},completed_runs={})
        for state in [snapshot['engine'],*snapshot['commands'].values()]:
            for msg in state.get('_delivery',{}).get('messages',[]):
                if msg['status']=='sending': msg.update(status='uncertain',reason='blocked_restore')
        durable.provision(stage/'blocked-store',identity['store_id'],snapshot)
        with durable.read_only_volume(stage/'blocked-store',identity['store_id']) as check:
            if check.snapshot!=snapshot: raise ValueError('Blocked restore readback')
        git(repo,budget,'config','remote.origin.pushurl','DISABLED-OFFLINE-RESTORE')
        publish_new(stage,target,budget)
        return dict(mode='blocked',history_verified=True,restore_blocked_verified=True,
            pin=required_pin,revision=required_revision,history_count=count,git_fsck=True,
            manifest_sha256=digest(manifest),chain_sha256=manifest['chain_sha256'],**budget.metrics())
    finally:
        if stage.exists(): remove_staging(stage,target.parent)


def append_local(repo, branch, pin, revision, identity, migration, root, *, fault=None, budget=None):
    """Resume immutable packages, fully verify, then publish LOCAL evidence only."""
    repo=Path(repo).resolve();root=Path(root).resolve();budget=budget or Budget();parse=parser(identity)
    if type(revision) is not int or revision<0:raise ValueError('Independent revision required')
    def event(name):
        if fault: fault(name)
        budget.check()
    if branch!=identity['branch'] or git(repo,budget,'rev-parse','refs/heads/'+branch).decode().strip()!=pin:
        raise ValueError('Source head differs from required pin')
    if git(repo,budget,'rev-parse','--is-bare-repository').strip()!=b'true' and git(repo,budget,'status','--porcelain').strip():
        raise ValueError('Source checkout not clean')
    root.mkdir(exist_ok=True); (root/'packages').mkdir(exist_ok=True);(root/'completions').mkdir(exist_ok=True)
    # Exclusive operation owner does not expire. A killed worker leaves this lock
    # for explicit offline review/removal; no time-based stealing.
    lock=root/'.writer-lock'
    with lock.open('x') as f: f.write('offline backup owner; interrupted owner requires explicit review\n')
    try:
        manifests,total=load_segments(root,identity,budget)
        prior_pin=manifests[-1]['pin'] if manifests else None
        prior_rev=manifests[-1]['revision'] if manifests else -1
        prior_digest=manifests[-1]['snapshot_digest'] if manifests else ZERO
        if prior_pin: git(repo,budget,'merge-base','--is-ancestor',prior_pin,pin)
        with batch(repo,budget) as read:
            _,_,latest=inspect(read,pin,identity,parse)
        if latest['revision']!=revision: raise ValueError('Independent source revision mismatch')
        inventory(migration,exclude_manifest=False)
        migrated=verify_package(migration)
        if migrated['control']['migration']['migration_id']!=control(latest)['migration_id']:
            raise ValueError('Migration identity mismatch')
        pending=[]; unpacked=0
        def publish():
            nonlocal pending,unpacked,total
            if not pending:return
            index=len(manifests)
            if index>=MAX_SEGMENTS: raise ValueError('Segment count budget')
            stage=Path(tempfile.mkdtemp(prefix='.pending-',dir=root/'packages'))
            try:
                scratch=stage/'scratch';scratch.mkdir();git(scratch,budget,'init','--bare')
                objects=git(repo,budget,'rev-parse','--path-format=absolute','--git-path','objects').decode().strip()
                (scratch/'objects/info/alternates').write_bytes((Path(objects).as_posix()+'\n').encode())
                end=pending[-1];start=pending[0]
                git(scratch,budget,'update-ref','refs/heads/backup',end['pin'])
                args=['bundle','create',str(stage/'history.bundle'),'refs/heads/backup']
                if start['parent']: args.append('^'+start['parent'])
                git(scratch,budget,*args)
                git(scratch,budget,'bundle','verify',str(stage/'history.bundle'))
                # Verify new pack object checksums independently of source alternates.
                git(scratch,budget,'bundle','unbundle',str(stage/'history.bundle'))
                remove_staging(scratch,stage)
                (stage/'stream.json').write_bytes(end['body'])
                if index==0: shutil.copytree(migration,stage/'migration')
                h=hashlib.sha256()
                for row in pending:h.update(row['row'])
                m=dict(schema='p3-backup-segment-v2',index=index,identity=identity,
                    previous_manifest_sha256=digest(manifests[-1]) if manifests else ZERO,
                    parent_pin=start['parent'],first_revision=start['revision'],pin=end['pin'],
                    revision=end['revision'],snapshot_digest=end['digest'],control=end['control'],
                    count=len(pending),unpacked_bytes=unpacked,history_sha256=h.hexdigest(),files=inventory(stage))
                m['warnings']=[key for key,used,limit in [
                    ('package_payload_bytes',sum(x['bytes'] for x in m['files'].values()),MAX_PACKAGE),
                    ('unpacked_bytes',unpacked,MAX_UNPACKED),('latest_body_bytes',len(end['body']),github.MAX_BYTES)]
                    if used>=.8*limit]
                write_json(stage/'segment.json',m)
                size=sum(x['bytes'] for x in m['files'].values())+(stage/'segment.json').stat().st_size
                if size>MAX_PACKAGE or total+size>MAX_SET_BYTES: raise ValueError('Package/set byte budget')
                if inventory(stage)!=m['files'] or read_json(stage/'segment.json')!=m: raise ValueError('Package readback')
                event('before_package_publish');publish_new(stage,root/'packages'/f'{index:06d}',budget)
                manifests.append(m);total+=size;pending=[];unpacked=0
                event('after_package_publish')
            finally:
                if stage.exists():remove_staging(stage,root/'packages')
        ids=iter(commits(repo,pin,prior_pin,budget))
        while group:=list(islice(ids,MAX_COMMITS)):
            with batch(repo,budget) as read:
                for current in group:
                    parents,body,env=inspect(read,current,identity,parse)
                    lineage(env,parents,prior_pin,prior_rev,prior_digest)
                    if len(body)>MAX_UNPACKED: raise ValueError('Single body exceeds processing step budget')
                    if pending and (len(pending)>=MAX_COMMITS or unpacked+len(body)>MAX_UNPACKED):publish()
                    # Keep only latest body; previous entries retain small digest metadata.
                    if pending:pending[-1].pop('body',None)
                    pending.append(dict(pin=current,parent=prior_pin,revision=env['revision'],digest=env['body_digest'],
                        body=body,control=control(env),row=row_bytes(current,prior_pin,env)))
                    unpacked+=len(body);prior_pin=current;prior_rev=env['revision'];prior_digest=env['body_digest']
                    budget.check()
        publish()
        m=set_manifest(manifests,total)
        event('before_full_restore')
        # Temporary restored clone is verification evidence, not the backup payload.
        with tempfile.TemporaryDirectory(prefix='.verify-',dir=root) as verify:
            result=restore_verified(root,m,Path(verify)/'restored',pin,revision,identity,budget)
        after,after_bytes=load_segments(root,identity,budget)
        if set_manifest(after,after_bytes)!=m:raise ValueError('Package set changed during verification')
        if git(repo,budget,'rev-parse','refs/heads/'+branch).decode().strip()!=pin:
            raise ValueError('Source moved before completion')
        receipt=dict(schema='p3-local-backup-verification-v2',status='local_verified',
            manifest=m,manifest_sha256=digest(m),history_verified=True,restore_blocked_verified=True,
            real_upload_verified=False,verification=result)
        final=root/'completions'/f'{revision:012d}-{digest(m)}'
        if final.exists():
            if read_json(final/'manifest.json')!=m:raise ValueError('Completion collision')
        else:
            stage=Path(tempfile.mkdtemp(prefix='.pending-',dir=root/'completions'))
            try:
                write_json(stage/'manifest.json',m);write_json(stage/'local-verification.json',receipt)
                event('before_completion_publish');publish_new(stage,final,budget)
            finally:
                if stage.exists():remove_staging(stage,root/'completions')
        return dict(manifest=m,completion=str(final),metrics=budget.metrics())
    finally:
        lock.unlink()
