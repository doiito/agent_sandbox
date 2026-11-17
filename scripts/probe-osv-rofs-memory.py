#!/usr/bin/env python3
"""Same-image KVM comparison of upstream ROFS cache policies; diagnostic only."""
import argparse
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import time

from startup_benchmark import validation_lock

spec = importlib.util.spec_from_file_location('rofs_wire', Path(__file__).with_name('e2e-osv-job-agent.py'))
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)


def sha(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--template', type=Path, required=True)
    parser.add_argument('--payload', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--payload-sha256', required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--compact', action='store_true')
    parser.add_argument('--allocator', action='store_true')
    parser.add_argument('--capacity', action='store_true')
    parser.add_argument('--io', action='store_true')
    parser.add_argument('--residency', action='store_true')
    parser.add_argument('--tracemalloc', action='store_true')
    parser.add_argument('--bytecode', action='store_true')
    parser.add_argument('--integrity', action='store_true')
    parser.add_argument('--bytecode-case', choices=('footprint', 'cache_contract', 'full_science'))
    parser.add_argument('--kernel', type=Path)
    parser.add_argument('--kernel-sha256')
    args = parser.parse_args()
    if args.bytecode_case and not args.bytecode:
        raise ValueError('--bytecode-case requires --bytecode')
    if (os.geteuid() != 0 or args.root.parent != Path('/var/lib') or args.root.exists() or
            not re.fullmatch(r'osv-rofs-memory-validation-20261102-[a-z0-9]+', args.root.name) or
            subprocess.check_output(['/sbin/ip', 'route', 'show']).strip()):
        raise SystemExit('requires root, fresh fixture and no outbound routes')
    for lookup in (pwd.getpwuid, grp.getgrgid):
        try:
            lookup(232050)
        except KeyError:
            continue
        raise SystemExit('validation identity already assigned')
    manifest_path = args.template/'artifacts/manifest.test.json'
    if sha(manifest_path) != args.manifest_sha256 or sha(args.payload) != args.payload_sha256:
        raise ValueError('pinned diagnostic inputs changed')
    manifest = json.loads(manifest_path.read_text())
    if manifest['entrypoints'] != ['/python3.12.so'] or manifest['backend'] != 'firecracker-osv':
        raise ValueError('unexpected scientific template')
    for key in ('kernel', 'image'):
        if sha(args.template/'artifacts'/manifest[key]['path']) != manifest[key]['sha256']:
            raise ValueError('template kernel/image changed')
    for name in ('firecracker', 'jailer'):
        if sha(args.template/'bin'/name) != manifest[name+'_sha256']:
            raise ValueError('pinned VMM changed')
    if bool(args.kernel) != bool(args.kernel_sha256) or (args.compact and not args.kernel):
        raise ValueError('compact experiment requires an explicitly pinned candidate kernel')
    if args.kernel and sha(args.kernel) != args.kernel_sha256:
        raise ValueError('candidate kernel changed')
    payload = json.loads(args.payload.read_text())
    required = {'full_science', 'footprint'}
    if args.compact:
        required.add('sparse')
    if args.allocator:
        required.add('allocator')
    if args.residency:
        required.add('residency')
    if args.tracemalloc:
        required.add('tracemalloc')
    if args.bytecode:
        required.add('cache_contract')
    if args.integrity:
        required.add('integrity')
    if sum((args.compact, args.allocator, args.capacity, args.io, args.residency, args.tracemalloc, args.bytecode, args.integrity)) > 1 or set(payload) != required:
        raise ValueError('unexpected diagnostic payload')
    for code in payload.values():
        if len(code.encode()) > 4096 or any(ord(ch) < 32 for ch in code):
            raise ValueError('diagnostic code exceeds the original argument limits')
    with validation_lock(None):
        exercise(args, manifest, payload)


def exercise(args, manifest, payload):
    root = args.root
    root.mkdir(mode=0o755)
    (root/'results').mkdir(mode=0o700)
    local = root/'input'
    local.mkdir()
    (local/'bin').mkdir()
    for relative, target in ((manifest['kernel']['path'], 'loader-stripped.elf'),
                             (manifest['image']['path'], 'osv-native-agent.raw')):
        source = args.kernel if target == 'loader-stripped.elf' and args.kernel else args.template/'artifacts'/relative
        shutil.copyfile(source, local/target)
        (local/target).chmod(0o444)
    for name in ('firecracker', 'jailer'):
        shutil.copyfile(args.template/'bin'/name, local/'bin'/name)
        (local/'bin'/name).chmod(0o755)
    report = {'suite': 'osv-rofs-memory-diagnostic/v1', 'production_validated': False,
        'performance_gate_evidence': False, 'product_memory_gate_evidence': False,
        'input_authentication': 'pinned manifest SHA256 and artifact hashes',
        'manifest_sha256': args.manifest_sha256, 'payload_sha256': args.payload_sha256,
        'script_sha256': sha(Path(__file__)), 'wire_script_sha256': sha(Path(wire.__file__)),
        'kernel_sha256': args.kernel_sha256 or manifest['kernel']['sha256'],
        'candidate_kernel_override': bool(args.kernel), 'image_sha256': manifest['image']['sha256'],
        'no_routes': True, 'cases': [], 'measurement_complete': False, 'cache_effect_supported': False}
    cases = [('cached-512-footprint', 512, (), 'footprint'),
             ('uncached-512-footprint', 512, ('--disable_rofs_cache',), 'footprint'),
             ('cached-64-full-science', 64, (), 'full_science'),
             ('uncached-64-full-science', 64, ('--disable_rofs_cache',), 'full_science')]
    if args.compact:
        compact = ('--disable_rofs_cache', '--sandbox-small-pages')
        cases = [('default-512-sparse', 512, (), 'sparse'),
                 ('compact-512-sparse', 512, ('--sandbox-small-pages',), 'sparse'),
                 ('uncached-512-footprint', 512, ('--disable_rofs_cache',), 'footprint'),
                 ('compact-uncached-512-footprint', 512, compact, 'footprint'),
                 ('compact-uncached-64-full-science', 64, compact, 'full_science')]
    if args.allocator:
        cases = [('cached-512-allocator', 512, (), 'allocator'),
                 ('uncached-512-allocator', 512, ('--disable_rofs_cache',), 'allocator')]
    if args.capacity:
        cases = [('uncached-128-full-science', 128, ('--disable_rofs_cache',), 'full_science'),
                 ('uncached-128-footprint', 128, ('--disable_rofs_cache',), 'footprint')]
    if args.io:
        cases = [('cached-512-full-science-io', 512, (), 'full_science'),
                 ('uncached-512-full-science-io', 512, ('--disable_rofs_cache',), 'full_science')]
    if args.residency:
        cases = [('uncached-512-residency', 512, ('--disable_rofs_cache',), 'residency'),
                 ('uncached-128-residency', 128, ('--disable_rofs_cache',), 'residency')]
    if args.tracemalloc:
        cases = [('uncached-512-tracemalloc', 512, ('--disable_rofs_cache',), 'tracemalloc')]
    if args.bytecode:
        cases = [('uncached-512-footprint', 512, ('--disable_rofs_cache',), 'footprint'),
                 ('uncached-128-cache-contract', 128, ('--disable_rofs_cache',), 'cache_contract'),
                 ('uncached-64-full-science', 64, ('--disable_rofs_cache',), 'full_science')]
        if args.bytecode_case:
            cases = [case for case in cases if case[3] == args.bytecode_case]
            report['diagnostic_case_selection'] = args.bytecode_case
    if args.integrity:
        cases = [('cached-128-integrity', 128, (), 'integrity'),
                 ('uncached-128-integrity', 128, ('--disable_rofs_cache',), 'integrity')]
    parent = Path('/sys/fs/cgroup')/root.name
    try:
        for number, (name, memory, options, kind) in enumerate(cases):
            started = time.monotonic()
            row = wire.run_case(local, number, name, 0, root=root, uid=232050,
                binaries=local/'bin', timeout_ms=30000, socket_timeout=31, stop_timeout=5,
                entrypoint='/python3.12.so', module_arguments=('-c', payload[kind]),
                memory_mib=memory, boot_options=options, report_capture_bytes=16384 if kind in ('allocator', 'residency', 'tracemalloc') else 4096,
                max_capture=16384 if kind in ('allocator', 'residency', 'tracemalloc') else 4096,
                observe_io=args.io,
                stdout_marker=(b'MINCORE_VALIDATED', b'RESIDENCY_PROBE_OK', b'SCIENCE_VERSIONS_OK', b'NUMPY_LINALG_OK', b'PANDAS_OK') if kind == 'residency'
                    else (b'TRACEMALLOC_PROBE_OK', b'SCIENCE_VERSIONS_OK', b'NUMPY_LINALG_OK', b'PANDAS_OK') if kind == 'tracemalloc'
                    else (b'CACHE_CONTRACT_OK', b'SCIENCE_VERSIONS_OK', b'NUMPY_LINALG_OK', b'PANDAS_OK') if kind == 'cache_contract'
                    else (b'ROFS_INTEGRITY_OK',) if kind == 'integrity'
                    else (b'ALLOCATOR_PROBE_OK', b'NUMPY_LINALG_OK', b'PANDAS_OK') if kind == 'allocator'
                    else (b'SPARSE_MMAP_OK',) if kind == 'sparse' else (b'NUMPY_LINALG_OK', b'PANDAS_OK',
                    b'after-gc' if kind == 'footprint' else b'SCIENCE_VERSIONS_OK'))
            if kind == 'sparse' and row['ok']:
                sample = next(json.loads(line.split(' ', 1)[1]) for line in row['stdout'].splitlines()
                              if line.startswith('SPARSE_RESULT '))
                small = '--sandbox-small-pages' in options
                row['sparse_measurement'] = sample
                if not (sample['touch_delta_bytes'] <= 2*1048576 if small else sample['touch_delta_bytes'] >= 16*1048576):
                    row['ok'] = False
                    row['error'] = 'sparse mapping physical growth did not match the selected policy'
            row['name'] = name
            row['wall_ms_including_fixture_copy'] = round((time.monotonic()-started)*1000, 3)
            leaf = parent/f'osv-job-{number}'
            deadline = time.monotonic()+5
            while leaf.exists() and (leaf/'cgroup.procs').read_text().strip() and time.monotonic() < deadline:
                time.sleep(.02)
            row['remaining_pids'] = (leaf/'cgroup.procs').read_text().split() if leaf.exists() else []
            if leaf.exists() and not row['remaining_pids']:
                leaf.rmdir()
            if row['remaining_pids']:
                raise RuntimeError('diagnostic VM left live cgroup members')
            report['cases'].append(row)
            print(json.dumps({'case': name, 'ok': row['ok'], 'error': row.get('error')}), flush=True)
        report['measurement_complete'] = True
        if args.residency:
            report['residency_probe_passed'] = all(row['ok'] for row in report['cases'])
        elif args.tracemalloc:
            report['tracemalloc_probe_passed'] = all(row['ok'] for row in report['cases'])
        elif args.bytecode:
            report['bytecode_probe_passed'] = all(row['ok'] for row in report['cases'])
        elif args.integrity:
            report['integrity_probe_passed'] = all(row['ok'] for row in report['cases'])
        elif args.io:
            report['io_probe_passed'] = all(row['ok'] for row in report['cases'])
        elif args.capacity:
            report['capacity_probe_passed'] = all(row['ok'] for row in report['cases'])
        elif args.allocator:
            report['allocator_probe_complete'] = all(row['ok'] for row in report['cases'])
        elif args.compact:
            report['compact_effect_supported'] = all(row['ok'] for row in report['cases'])
        else:
            report['cache_effect_supported'] = (all(row['ok'] for row in report['cases'][:2]) and
                not report['cases'][2]['ok'] and report['cases'][3]['ok'])
    finally:
        if parent.exists() and not list(parent.glob('osv-job-*')) and not (parent/'cgroup.procs').read_text().strip():
            parent.rmdir()
        report['cgroup_removed'] = not parent.exists()
        (root/'results/report.json').write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps({key: report[key] for key in ('measurement_complete', 'cache_effect_supported', 'cgroup_removed')}), flush=True)
    if not report['measurement_complete'] or not report['cgroup_removed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
