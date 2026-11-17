#!/usr/bin/env python3
"""Restore one historical signed tar, verifying its original bytes and digest."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('package', help='original signed tar filename')
args = parser.parse_args()
index = json.loads((root/'dist/archive/index.json').read_text())
matches = [row for row in index['archives'] if Path(row['original_path']).name == args.package]
if len(matches) != 1:
    raise SystemExit('package must name one recorded archive')
row = matches[0]
source, destination = root/row['archive_path'], root/row['original_path']
if not source.resolve().is_relative_to(root) or not destination.resolve().is_relative_to(root):
    raise SystemExit('archive path leaves the project')
if source.parent.resolve() != (root/'dist/archive').resolve() or destination.parent.resolve() not in (
        (root/'dist').resolve(), (root/'build/offline-obsolete').resolve()):
    raise SystemExit('archive entry is outside the recorded release directories')
def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()
if destination.exists():
    if sha(destination) != row['original_sha256']:
        raise SystemExit('existing destination differs; refusing to overwrite')
    print('already restored: '+str(destination))
    raise SystemExit(0)
if sha(source) != row['archive_sha256']:
    raise SystemExit('compressed archive digest mismatch')
destination.parent.mkdir(parents=True, exist_ok=True)
partial = destination.with_name(destination.name+'.restore-part')
digest, count = hashlib.sha256(), 0
created = False
try:
    with gzip.open(source, 'rb') as archived, partial.open('xb') as output:
        created = True
        for block in iter(lambda: archived.read(1024*1024), b''):
            digest.update(block)
            count += len(block)
            if count > row['original_bytes']:
                raise RuntimeError('restored tar exceeds the recorded size')
            output.write(block)
    if count != row['original_bytes'] or digest.hexdigest() != row['original_sha256']:
        raise RuntimeError('restored tar digest/size mismatch')
    partial.chmod(0o644)
    os.replace(partial, destination)
finally:
    if created:
        partial.unlink(missing_ok=True)
print('restored: '+str(destination))
