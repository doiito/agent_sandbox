#!/usr/bin/env python3
"""Verify checked-hash bytecode against fresh optimize=0 source compilation."""
import argparse
import hashlib
import importlib.util
import json
import marshal
from pathlib import Path
import struct
import sys
import types


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_code(actual, expected, filename):
    if not isinstance(actual, types.CodeType) or actual != expected or actual.co_filename != filename:
        raise ValueError('bytecode differs from optimize=0 source compilation: '+filename)
    nested_actual = [item for item in actual.co_consts if isinstance(item, types.CodeType)]
    nested_expected = [item for item in expected.co_consts if isinstance(item, types.CodeType)]
    if len(nested_actual) != len(nested_expected):
        raise ValueError('nested code mismatch: '+filename)
    for left, right in zip(nested_actual, nested_expected):
        verify_code(left, right, filename)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    rootfs = args.rootfs.resolve(strict=True)
    document = json.loads((rootfs/'bytecode-provenance.json').read_text())
    if (sys.version_info[:3] != (3, 12, 16) or sys.flags.optimize != 0 or
            document['protocol'] != 'osv-python-checked-bytecode/v1' or
            document['optimization'] != 0 or document['flags'] != 3 or
            document['magic'] != importlib.util.MAGIC_NUMBER.hex() or
            sha(Path(sys.executable).resolve(strict=True)) != document['compiler_sha256'] or
            sha(Path(sys.base_prefix)/'lib/libpython3.12.so.1.0') != document['libpython_sha256']):
        raise ValueError('compiler or bytecode policy mismatch')
    # A valid checked-hash header alone cannot distinguish stripped assertions
    # or docs. Ensure the semantic comparison rejects that case.
    probe = b'"DOC"\nassert __debug__\ndef f():\n    "FUNCTION_DOC"\n    assert __debug__\n'
    for optimization in (1, 2):
        try:
            verify_code(compile(probe, '<probe>', 'exec', optimize=optimization),
                compile(probe, '<probe>', 'exec', optimize=0), '<probe>')
        except ValueError:
            pass
        else:
            raise ValueError('optimized-code rejection control failed')
    sources, caches = set(), set()
    for row in document['files']:
        guest = row['source']
        if not guest.startswith('/opt/python/lib/python3.12/') or not guest.endswith('.py'):
            raise ValueError('unexpected source path')
        source = rootfs/guest.lstrip('/')
        cache = rootfs/row['bytecode'].lstrip('/')
        if (source.is_symlink() or cache.is_symlink() or not source.resolve().is_relative_to(rootfs) or
                not cache.resolve().is_relative_to(rootfs) or guest in sources or row['bytecode'] in caches or
                cache != Path(importlib.util.cache_from_source(str(source), optimization=''))):
            raise ValueError('duplicate, escaping or noncanonical bytecode path')
        data = cache.read_bytes()
        text = source.read_bytes()
        if (len(data) != row['size'] or sha(source) != row['source_sha256'] or sha(cache) != row['bytecode_sha256'] or
                data[:4] != importlib.util.MAGIC_NUMBER or struct.unpack('<I', data[4:8])[0] != 3 or
                data[8:16] != importlib.util.source_hash(text) or data[8:16].hex() != row['source_hash']):
            raise ValueError('bytecode source/header/digest mismatch: '+guest)
        verify_code(marshal.loads(data[16:]), compile(text, guest, 'exec', dont_inherit=True, optimize=0), guest)
        sources.add(guest)
        caches.add(row['bytecode'])
    actual_sources = {'/'+str(path.relative_to(rootfs)) for path in (rootfs/'opt/python/lib/python3.12').rglob('*.py')}
    actual_caches = {'/'+str(path.relative_to(rootfs)) for path in rootfs.rglob('*.pyc')}
    if not sources or sources != actual_sources or caches != actual_caches:
        raise ValueError('bytecode inventory is incomplete')
    report = {'protocol': 'osv-python-checked-bytecode-verification/v1', 'build_reference_only': True,
        'production_validated': False, 'bytecode_files': len(caches), 'source_compilation_equal': True,
        'optimized_code_rejected': True, 'compiler_sha256': document['compiler_sha256'],
        'provenance_sha256': sha(rootfs/'bytecode-provenance.json'), 'verifier_sha256': sha(Path(__file__))}
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report), flush=True)


if __name__ == '__main__':
    main()
