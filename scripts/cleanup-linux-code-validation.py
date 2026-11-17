#!/usr/bin/env python3
"""Delete only this phase's finished validation copies and build objects."""
import argparse
import json
import os
from pathlib import Path
import shutil
import stat

from linux_code_runtime_closure import inventory, sha

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / 'build/validation/code-contexts'
OUT = ROOT / 'results/2026-11-05-linux-code-runtime/retirement'


def targets():
    selected = [WORK / ('runtime-amd64-' + revision) / 'rootfs' for revision in ['r1', 'r2', 'r3']]
    for prefix, revisions in [('runtime-arm64-', ['r1', 'r2', 'r3']), ('kernel-arm64-', ['r5', 'r6'])]:
        for revision in revisions:
            selected += [WORK / (prefix + revision) / 'rootfs', WORK / (prefix + revision) / 'initrd.cpio']
    selected += [ROOT / 'build/linux-code-runtime' / arch / 'obj' for arch in ['amd64', 'arm64']]
    selected += [ROOT / 'build/linux-code-runtime/source']
    return selected


def unused(selected):
    prefixes = [str(path) for path in selected]
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        mount = line.split()[4]
        if any(mount == prefix or mount.startswith(prefix + '/') for prefix in prefixes):
            raise ValueError('selected verification path still contains a mount: ' + mount)
    for process in Path('/proc').iterdir():
        if not process.name.isdigit() or int(process.name) == os.getpid():
            continue
        try:
            command = (process / 'cmdline').read_bytes().replace(b'\0', b' ').decode(errors='replace')
            if any(prefix in command for prefix in prefixes):
                raise ValueError('active process references a selected path: PID ' + process.name)
            references = [process / 'cwd', process / 'exe'] + list((process / 'fd').iterdir())
            for reference in references:
                try:
                    value = os.readlink(reference)
                except (FileNotFoundError, PermissionError, OSError):
                    continue
                if any(value == prefix or value.startswith(prefix + '/') for prefix in prefixes):
                    raise ValueError('active process holds selected path: PID ' + process.name)
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--resume', action='store_true', help='resume only the exact saved incomplete retirement plan')
    args = parser.parse_args()
    if (OUT / 'receipt.json').exists() or (OUT.exists() and not args.resume):
        raise ValueError('retirement exists; only an explicit incomplete-plan resume is allowed')
    previous = json.loads((OUT / 'before.json').read_text()) if args.resume else None
    native = ROOT / 'results/2026-11-05-code-kernel-prototype/r6/native-receipt.json'
    arm = ROOT / 'results/2026-11-05-code-kernel-prototype/r6/arm64-receipt.json'
    receipts = [json.loads(path.read_text()) for path in [native, arm]]
    if not all(item['passed'] for item in receipts):
        raise ValueError('native and ARM prototype validation must both have passed')
    assets = {}
    for arch, receipt in zip(['amd64', 'arm64'], receipts):
        asset = ROOT / 'assets/runtimes/linux-code' / ('linux-' + arch)
        record = asset / 'runtime-inventory.json'
        sealed = json.loads(record.read_text())
        if sha(record) != receipt['runtime_inventory_sha256'] or inventory(asset / 'rootfs') != sealed['files']:
            raise ValueError('actual runtime no longer matches the accepted functional evidence')
        assets[str(record.relative_to(ROOT))] = sha(record)
        for name, digest in receipt['inputs_sha256'].items():
            if sha(ROOT / name) != digest:
                raise ValueError('prototype inputs changed since acceptance: ' + name)
    selected = targets()
    for path in selected:
        if ((not path.exists() and not args.resume) or path.is_symlink()
                or not path.is_relative_to(ROOT / 'build')):
            raise ValueError('expected an existing exact generated path: ' + str(path))
    unused(selected)
    rows = []
    for path in selected:
        if not path.exists():
            continue
        files = list(path.rglob('*')) if path.is_dir() else [path]
        statuses = [item.lstat() for item in files]
        rows.append({'path': str(path.relative_to(ROOT)),
                     'regular_file_bytes': sum(item.st_size for item in statuses if stat.S_ISREG(item.st_mode)),
                     'allocated_file_bytes': sum(item.st_blocks * 512 for item in statuses if stat.S_ISREG(item.st_mode)),
                     'entries': len(files)})
    report = {'protocol': 'osv-linux-code-validation-retirement/v1', 'applied': args.apply,
              'selected': rows, 'regular_file_bytes': sum(row['regular_file_bytes'] for row in rows),
              'allocated_file_bytes': sum(row['allocated_file_bytes'] for row in rows),
              'retained_actual_runtime_inventories': assets,
              'functional_receipts': {str(path.relative_to(ROOT)): sha(path) for path in [native, arm]},
              'active_path_references': 0, 'active_selected_mounts': 0,
              'net_shared_filesystem_gain_measured': False}
    if previous:
        if ({row['path'] for row in previous['selected']} != {str(path.relative_to(ROOT)) for path in selected}
                or previous['retained_actual_runtime_inventories'] != assets
                or previous['functional_receipts'] != report['functional_receipts']):
            raise ValueError('resume differs from the frozen selected paths or accepted evidence')
        remaining = report['regular_file_bytes']
        report = previous
        report.update(applied=args.apply, resumed_after_permission_failure=True,
                      remaining_regular_file_bytes_at_resume=remaining)
    if not args.apply:
        print(json.dumps(report, indent=2))
        return
    if not previous:
        OUT.mkdir(parents=True)
    # Keep all small raw logs/receipts/input snapshots. Never copy huge fixture
    # roots or cpio images back into the evidence archive being preserved.
    evidence = [path for path in WORK.iterdir() if path.is_file() and path.suffix in {'.json', '.log', '.py', '.js'}]
    for directory in WORK.iterdir():
        if directory.is_dir():
            evidence += [path for path in directory.iterdir() if path.is_file() and path.suffix in {'.json', '.log'}]
            if (directory / 'inputs').is_dir():
                evidence += [path for path in (directory / 'inputs').rglob('*') if path.is_file()]
    for arch in ['amd64', 'arm64']:
        obj = ROOT / 'build/linux-code-runtime' / arch / 'obj'
        evidence += [obj / name for name in ['config.log', 'config.status', 'pyconfig.h', 'Makefile'] if (obj / name).is_file()]
    archived = dict(report.get('archived_evidence_sha256', {}))
    for source in evidence:
        target = OUT / 'evidence' / source.relative_to(ROOT)
        if previous and target.exists():
            if sha(target) == sha(source):
                continue
            target = OUT / 'resume-evidence' / source.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        archived[str(target.relative_to(ROOT))] = sha(target)
    report['archived_evidence_sha256'] = archived
    if not previous:
        (OUT / 'before.json').write_text(json.dumps(report, indent=2) + '\n')
    unused(selected)
    for path in selected:
        if not path.exists():
            continue
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
    if any(path.exists() or path.is_symlink() for path in selected):
        raise ValueError('some selected verification copies remain')
    for name, digest in assets.items():
        record = ROOT / name
        if sha(record) != digest or inventory(record.parent / 'rootfs') != json.loads(record.read_text())['files']:
            raise ValueError('retirement changed an actual runtime asset')
    report['all_selected_absent'] = True
    report['retained_actual_runtime_files_verified'] = True
    report['cleanup_script_sha256'] = sha(Path(__file__))
    (OUT / 'receipt.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ['applied', 'regular_file_bytes', 'allocated_file_bytes',
          'all_selected_absent', 'retained_actual_runtime_files_verified']}))


if __name__ == '__main__':
    main()
