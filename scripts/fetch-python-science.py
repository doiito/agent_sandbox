#!/usr/bin/env python3
"""Fetch only the reviewed Python template lock; runtime installation is offline."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / 'osv-native/templates/python-3.12-science/lock.json'
SOURCES = ROOT / 'assets/osv-native/python-3.12-science/sources'


def read_lock():
    lock = json.loads(LOCK.read_text())
    if (lock.get('protocol') != 'osv-python-science-sources/v1' or
            lock.get('architecture') != 'x86_64' or lock.get('python_abi') != 'cp312'):
        raise ValueError('unsupported Python template source lock')
    projects = set()
    filenames = set()
    for item in lock['files']:
        name, version, filename = (item[k] for k in ('project', 'version', 'filename'))
        if (not re.fullmatch(r'[A-Za-z0-9_.+-]+', filename) or filename in filenames or
                name in projects or not re.fullmatch(r'[0-9a-f]{64}', item['sha256']) or
                not re.fullmatch(r'[0-9]+(?:\.[0-9A-Za-z]+)+', version)):
            raise ValueError('invalid or duplicate locked source')
        url = urlsplit(item['url'])
        if (url.scheme != 'https' or url.hostname not in ('www.python.org', 'files.pythonhosted.org') or
                url.username or url.password or url.port or url.query or url.fragment or
                url.path.rsplit('/', 1)[-1] != filename):
            raise ValueError('unapproved source URL')
        if item['kind'] not in ('source', 'wheel'):
            raise ValueError('unsupported source kind')
        projects.add(name)
        filenames.add(filename)
    if projects != {'CPython', 'numpy', 'pandas', 'python-dateutil', 'six'}:
        raise ValueError('incomplete Python science dependency lock')
    return lock


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def verify(path, expected):
    if path.is_symlink() or not path.is_file() or digest(path) != expected:
        raise ValueError(f'locked source digest mismatch: {path.name}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fetch', action='store_true', help='allow explicit download of missing locked files')
    args = parser.parse_args()
    lock = read_lock()
    SOURCES.mkdir(parents=True, exist_ok=True)
    for item in lock['files']:
        target = SOURCES / item['filename']
        if target.exists() or target.is_symlink():
            verify(target, item['sha256'])
        elif args.fetch:
            temporary = target.with_name(target.name + '.download')
            # Exclusive creation rejects pre-existing files and symlinks. A failed
            # transfer is discarded, so it can never masquerade as a cached source.
            with temporary.open('xb') as sink:
                try:
                    subprocess.run(['curl', '--fail', '--location', '--silent', '--show-error',
                                    '--proto', '=https', '--proto-redir', '=https',
                                    '--connect-timeout', '15', '--max-time', '180',
                                    item['url']], stdout=sink, check=True)
                    sink.flush()
                    verify(temporary, item['sha256'])
                    temporary.rename(target)
                finally:
                    temporary.unlink(missing_ok=True)
        else:
            raise FileNotFoundError(f'missing {target}; run this script with --fetch during asset preparation')
        print(f'verified {item["project"]} {item["version"]}: {target.relative_to(ROOT)}')
    (SOURCES / 'SHA256SUMS').write_text(''.join(
        f'{item["sha256"]}  {item["filename"]}\n' for item in lock['files']))


if __name__ == '__main__':
    main()
