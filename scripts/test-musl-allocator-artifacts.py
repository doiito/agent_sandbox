#!/usr/bin/env python3
"""Exercise publication rejection using actual compiled allocator artifacts."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--architecture', choices=('amd64', 'arm64'), required=True)
    parser.add_argument('--system', type=Path)
    parser.add_argument('--normal', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    rows = []
    complete = False

    def check(label, arguments, accepted):
        result = subprocess.run(['python3', str(ROOT/'scripts/check-musl-allocator.py'), *arguments],
                                capture_output=True, text=True)
        passed = (result.returncode == 0) == accepted
        rows.append({'case': label, 'passed': passed, 'accepted': result.returncode == 0,
                     'error': result.stderr[-1800:]})
        if not passed:
            raise RuntimeError('allocator publication check failed: ' + label)

    def refresh(directory):
        inventory = directory/'SHA256SUMS'
        names = [line.split('  ', 1)[1] for line in inventory.read_text().splitlines()]
        inventory.write_text(''.join(hashlib.sha256((directory/name).read_bytes()).hexdigest() +
                                     '  ' + name + '\n' for name in names))

    try:
        check('valid-build', ['--architecture', args.architecture, '--artifacts', str(args.artifacts)], True)
        other = 'arm64' if args.architecture == 'amd64' else 'amd64'
        check('wrong-architecture', ['--architecture', other, '--artifacts', str(args.artifacts)], False)
        helper = args.artifacts / 'osv-workload-supervisor'
        mapping = args.artifacts / 'supervisor-link-map.txt'
        check('valid-supervisor', ['--architecture', args.architecture, '--supervisor', str(helper),
                                  '--supervisor-link-map', str(mapping)], True)
        check('supervisor-wrong-architecture', ['--architecture', other, '--supervisor', str(helper),
                                              '--supervisor-link-map', str(mapping)], False)
        check('reject-agent-as-supervisor', ['--architecture', args.architecture,
              '--supervisor', str(args.artifacts / 'agent-init'), '--supervisor-link-map', str(mapping)], False)
        for name in ('system', 'normal'):
            binary = getattr(args, name)
            if binary:
                check('reject-'+name, ['--architecture', args.architecture, '--binary', str(binary)], False)
        for mutation in ('binary', 'security', 'compiler-date', 'link-input', 'source',
                         'supervisor-binary', 'supervisor-identity', 'supervisor-map', 'missing-supervisor'):
            with tempfile.TemporaryDirectory(prefix='osv-allocator-negative-') as work:
                directory = Path(work)/'artifacts'
                shutil.copytree(args.artifacts, directory)
                if mutation == 'binary':
                    path = directory/'agent-init'
                    data = bytearray(path.read_bytes())
                    data[-1] ^= 1
                    path.write_bytes(data)
                elif mutation == 'link-input':
                    path = directory/'build-libraries/libmimalloc.a'
                    path.write_bytes(path.read_bytes()+b'tampered')
                elif mutation == 'supervisor-binary':
                    path = directory/'osv-workload-supervisor'
                    path.write_bytes(path.read_bytes()+b'tampered')
                elif mutation == 'supervisor-map':
                    path = directory/'supervisor-link-map.txt'
                    path.write_text(path.read_text()+'\nlibmimalloc unexpected linked input\n')
                elif mutation == 'missing-supervisor':
                    (directory/'osv-workload-supervisor').unlink()
                    path = directory/'SHA256SUMS'
                    path.write_text(''.join(line+'\n' for line in path.read_text().splitlines()
                                            if line.split('  ', 1)[1] != 'osv-workload-supervisor'))
                else:
                    path = directory/'build-provenance.json'
                    data = json.loads(path.read_text())
                    if mutation == 'security':
                        data['secure_level'] = 0
                    elif mutation == 'compiler-date':
                        data['c_preprocessor_date'] = 'compiler ignored reproducible date'
                    elif mutation == 'supervisor-identity':
                        data['components']['osv-workload-supervisor']['allocator'] = 'mimalloc'
                    else:
                        data['source_sha256']['runtime-allocator/src/lib.rs'] = '0'*64
                    path.write_text(json.dumps(data)+'\n')
                # Rehash the modified files: provenance must catch more than a stale checksum list.
                refresh(directory)
                check('reject-changed-'+mutation, ['--architecture', args.architecture,
                                                  '--artifacts', str(directory)], False)
        complete = True
    finally:
        args.report.write_text(json.dumps({'suite': 'musl-allocator-publication-rejection/v1',
                                          'architecture': args.architecture, 'cases': rows,
                                          'passed': complete and bool(rows) and all(r['passed'] for r in rows)}, indent=2)+'\n')
    print(f'Allocator publication positive/negative checks passed: {len(rows)}')


if __name__ == '__main__':
    main()
