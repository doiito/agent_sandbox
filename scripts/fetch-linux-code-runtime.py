#!/usr/bin/env python3
"""Fetch pinned code-runtime inputs; --offline verifies the project cache only."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ASSET = ROOT / 'assets/runtimes/linux-code'


def sha(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--offline', action='store_true')
    args = parser.parse_args()
    lock = json.loads((ASSET / 'source-lock.json').read_text())
    assert lock['protocol'] == 'osv-linux-code-runtime-sources/v1'
    for entry in lock['files']:
        target = ROOT / entry['path']
        assert target.resolve().is_relative_to(ROOT) and not target.is_symlink()
        if target.exists():
            assert target.is_file() and sha(target) == entry['sha256'], entry['path']
            continue
        if args.offline:
            raise SystemExit('missing pinned offline input: ' + entry['path'])
        assert entry['url'].startswith(('https://nodejs.org/download/release/v22.23.4/',
                                        'https://files.pythonhosted.org/'))
        target.parent.mkdir(parents=True, exist_ok=True)
        partial = target.with_name(target.name + '.partial')
        result = subprocess.run(['curl', '--fail', '--location', '--silent', '--show-error',
                                 '--connect-timeout', '15', '--max-time', '240', '--retry', '2',
                                 '--output', str(partial), entry['url']])
        if result.returncode:
            partial.unlink(missing_ok=True)
            raise SystemExit(result.returncode)
        if partial.stat().st_size > 128 * 1024 * 1024 or sha(partial) != entry['sha256']:
            partial.unlink()
            raise SystemExit('runtime source digest/size mismatch: ' + entry['path'])
        partial.replace(target)
        print('Verified ' + target.name, flush=True)
    print('All ' + str(len(lock['files'])) + ' pinned runtime inputs verified', flush=True)


if __name__ == '__main__':
    main()
