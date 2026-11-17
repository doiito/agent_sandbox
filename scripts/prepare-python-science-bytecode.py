#!/usr/bin/env python3
"""Clone a sealed science closure and add checked-hash, optimize=0 bytecode."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import py_compile
import shutil
import struct
import subprocess
import sys


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--asset', type=Path, required=True)
    parser.add_argument('--in-place',action='store_true')
    args = parser.parse_args()
    if sys.version_info[:3] != (3, 12, 16) or sys.flags.optimize != 0 or sys.implementation.cache_tag != 'cpython-312':
        raise ValueError('requires the pinned CPython 3.12.16 interpreter with optimize=0')
    source = args.source.resolve(strict=True)
    asset = args.asset.resolve()
    if args.in_place:
        if source != asset/'rootfs' or (asset/'pre-bytecode-inventory.json').exists():
            raise ValueError('in-place preparation requires asset/rootfs and a fresh base inventory')
    elif asset.exists() or asset.is_relative_to(source) or source.is_relative_to(asset):
        raise ValueError('requires a fresh asset directory outside the source closure')
    root = Path(__file__).resolve().parents[1]
    closure_path = root/'scripts/python_science_closure.py'
    spec = importlib.util.spec_from_file_location('science_closure', closure_path)
    closure = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(closure)
    original = json.loads((source/'runtime-inventory.json').read_text())
    closure.verify(source, original)
    base_sha = sha(source/'runtime-inventory.json')
    target = asset/'rootfs'
    if args.in_place:
        shutil.copyfile(source/'runtime-inventory.json',asset/'pre-bytecode-inventory.json')
    else:
        shutil.copytree(source, target, copy_function=os.link, symlinks=True)
    # Detach the only existing file that will be regenerated. Existing source,
    # libraries and provenance remain untouched, including mode and timestamps.
    (target/'runtime-inventory.json').unlink()
    rows = []
    for path in sorted((target/'opt/python/lib/python3.12').rglob('*.py')):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f'unsupported Python source inode: {path}')
        guest = '/'+str(path.relative_to(target))
        output = Path(importlib.util.cache_from_source(str(path), optimization=''))
        if output.exists():
            raise ValueError(f'pre-existing bytecode: {output}')
        py_compile.compile(str(path), cfile=str(output), dfile=guest, doraise=True,
            optimize=0, invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH)
        data = output.read_bytes()
        source_bytes = path.read_bytes()
        expected_hash = importlib.util.source_hash(source_bytes)
        if data[:4] != importlib.util.MAGIC_NUMBER or struct.unpack('<I', data[4:8])[0] != 3 or data[8:16] != expected_hash:
            raise ValueError(f'bytecode header/source mismatch: {guest}')
        rows.append({'source': guest, 'source_sha256': sha(path),
            'bytecode': '/'+str(output.relative_to(target)), 'bytecode_sha256': sha(output),
            'source_hash': expected_hash.hex(), 'size': len(data)})
    if not rows:
        raise ValueError('empty bytecode closure')
    record = {'protocol': 'osv-python-checked-bytecode/v1',
        'python_version': list(sys.version_info[:3]), 'cache_tag': sys.implementation.cache_tag,
        'optimization': 0, 'magic': importlib.util.MAGIC_NUMBER.hex(), 'flags': 3,
        'source_inventory_sha256': base_sha,
        'compiler_sha256': sha(source/'opt/python/bin/python3.12'),
        'libpython_sha256': sha(source/'opt/python/lib/libpython3.12.so.1.0'),
        'preparer_sha256': sha(Path(__file__)), 'files': rows}
    (target/'bytecode-provenance.json').write_text(json.dumps(record, indent=2)+'\n')
    subprocess.run([sys.executable,'-B',str(root/'scripts/verify-python-science-bytecode.py'),
        '--rootfs',str(target),'--output',str(target/'bytecode-verification.json')],check=True)
    subprocess.run([sys.executable, '-B', str(closure_path), 'seal', str(target),
        '--output', str(asset/'runtime-inventory.json')], check=True)
    subprocess.run([sys.executable, '-B', str(closure_path), 'verify', str(target),
        '--output', str(asset/'runtime-inventory.json')], check=True)
    if not args.in_place:
        closure.verify(source, original)
    print(json.dumps({'bytecode_files': len(rows), 'bytecode_bytes': sum(row['size'] for row in rows),
        'source_inventory_sha256': base_sha, 'original_closure_unchanged': not args.in_place,
        'new_inventory_sha256': sha(asset/'runtime-inventory.json')}), flush=True)


if __name__ == '__main__':
    main()
