#!/usr/bin/env python3
"""Read-only process/mount reference check for an explicit retirement plan.

Run in the host namespace when sandboxed commands cannot see other tasks.
This script never deletes files and never reads or records process arguments.
"""
from pathlib import Path
import argparse
import errno
import json
import os
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--plan', type=Path, required=True, help='project results JSON with targets: [[relative_path, reason], ...]')
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
plan_path = args.plan.resolve()
assert plan_path.is_relative_to(root / 'results'), 'Plan must be in project results'
plan = json.loads(plan_path.read_text())
targets = []
for relative, reason in plan['targets']:
    path = Path(relative)
    assert relative and reason and not path.is_absolute() and '..' not in path.parts and path.as_posix() == relative
    assert (root / relative).resolve().is_relative_to(root), 'Target escapes project'
    targets.append(str(root / relative))
assert targets and len(targets) == len(set(targets))


def matches(value):
    value = value.removesuffix(' (deleted)')
    return any(value == target or value.startswith(target + '/') for target in targets)


hits = []
inspected, denied, exited = 0, 0, 0
for proc in Path('/proc').iterdir():
    if not proc.name.isdigit():
        continue
    inspected += 1
    links = [proc / 'cwd', proc / 'exe', proc / 'root']
    try:
        links.extend((proc / 'fd').iterdir())
    except PermissionError:
        denied += 1
    except (FileNotFoundError, ProcessLookupError):
        continue
    for link in links:
        try:
            value = os.readlink(link)
            if matches(value):
                hits.append({'pid': int(proc.name), 'reference': str(link), 'path': value})
        except PermissionError:
            denied += 1
        except (FileNotFoundError, ProcessLookupError, OSError):
            pass
    try:
        for line in (proc / 'maps').read_text().splitlines():
            columns = line.split(None, 5)
            if len(columns) == 6 and matches(columns[5]):
                hits.append({'pid': int(proc.name), 'reference': 'maps', 'path': columns[5]})
        mounts = (proc / 'mountinfo').read_text()
        for target in targets:
            if target in mounts:
                hits.append({'pid': int(proc.name), 'reference': 'mountinfo', 'path': target})
    except PermissionError:
        denied += 1
    except (FileNotFoundError, ProcessLookupError):
        pass
    except OSError as error:
        # A zombie can still appear in /proc while mountinfo reports EINVAL.
        try:
            state = (proc / 'stat').read_text().rsplit(')', 1)[1].split()[0]
        except (FileNotFoundError, ProcessLookupError):
            state = 'X'
        if error.errno != errno.EINVAL or state not in {'Z', 'X'}:
            raise
        exited += 1
receipt = {'protocol': 'osv-validation-artifact-reference-check/v1', 'checked_at_unix': int(time.time()),
           'plan': str(plan_path.relative_to(root)), 'passed': not hits and not denied,
           'processes_inspected': inspected, 'denied_process_checks': denied,
           'pid_namespace': os.readlink('/proc/self/ns/pid'),
           'mount_namespace': os.readlink('/proc/self/ns/mnt'),
           'confirmed_exited_processes_skipped': exited, 'references': hits,
           'process_arguments_read_or_recorded': False}
(plan_path.parent / 'host-reference-check.json').write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps(receipt))
raise SystemExit(0 if receipt['passed'] else 1)
