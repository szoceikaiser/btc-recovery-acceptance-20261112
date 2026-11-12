"""Publish a verified new local directory; never retries a network/Git action."""
import os,time
from pathlib import Path

def publish_new(source,target,budget=None):
    for attempt in range(10):
        if budget is not None:budget.check()
        if Path(target).exists():raise FileExistsError(target)
        try:
            Path(source).rename(target)
            return
        except PermissionError:
            if os.name!='nt' or attempt==9:raise
            time.sleep(.1)
