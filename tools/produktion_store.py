"""Explicit P2 package provisioning, always blocked and never in place."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import shutil

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'engine'))
import durable_delivery as durable
from production_contract import canonical, validate_v2


def verify_package(package):
    package=Path(package)
    lines=(package/'SHA256SUMS').read_text(encoding='utf-8').splitlines()
    names=set()
    for line in lines:
        digest,sep,name=line.partition('  ')
        if not sep or name in names or Path(name).is_absolute() or '..' in Path(name).parts:
            raise ValueError('Invalid package hash manifest')
        names.add(name)
        if hashlib.sha256((package/name).read_bytes()).hexdigest()!=digest:
            raise ValueError('Package hash mismatch: '+name)
    required={'snapshot.v2.json','migration-report.json','migration-manifest.json',
              'source/state.json','source/signals.json','source/oi_history.json',
              'source/config-source.json','source/config-target.json'}
    if not required<=names:
        raise ValueError('Incomplete migration package')
    snapshot=json.loads((package/'snapshot.v2.json').read_text(encoding='utf-8'))
    report=json.loads((package/'migration-report.json').read_text(encoding='utf-8'))
    validate_v2(snapshot)
    if report.get('conversion_valid') is not True or snapshot['control']['mode']!='blocked':
        raise ValueError('Unreviewed or unblocked migration package')
    if snapshot['control']['migration']!=json.loads((package/'migration-manifest.json').read_text(encoding='utf-8')):
        raise ValueError('Migration manifest mismatch')
    return snapshot


def provision(package, target):
    snapshot=verify_package(package)
    target=Path(target)
    if target.exists():
        raise FileExistsError(target)
    if target.resolve().is_relative_to(Path(package).resolve()):
        raise ValueError('Store must be outside immutable migration package')
    stage=Path(tempfile.mkdtemp(prefix='.produktion-store-',dir=target.parent))
    try:
        durable.provision(stage/'store',snapshot['control']['store_id'],snapshot)
        with durable.VolumeStore(stage/'store',snapshot['control']['store_id']) as check:
            if check.snapshot!=snapshot:
                raise ValueError('Provision verification failed')
        from local_publication import publish_new
        publish_new(stage/'store',target)
    finally:
        shutil.rmtree(stage)
    return {'store_id':snapshot['control']['store_id'],'mode':'blocked','path':str(Path(target).resolve())}


if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('command',choices=['provision'])
    p.add_argument('--package',required=True)
    p.add_argument('--target',required=True)
    a=p.parse_args()
    print(canonical(provision(a.package,a.target)))
