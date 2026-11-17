#!/usr/bin/env python3
"""Linux build reference for checked bytecode; never OSv acceptance."""
import argparse
import ast
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import py_compile
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scratch', type=Path, required=True)
    parser.add_argument('--rootfs', type=Path, required=True)
    args = parser.parse_args()
    assert sys.version_info[:3] == (3, 12, 16) and sys.flags.optimize == 0 and __debug__
    try:
        assert False, 'ASSERTIONS_RETAINED'
    except AssertionError as error:
        assert str(error) == 'ASSERTIONS_RETAINED'
    else:
        raise RuntimeError('assert was removed')
    lib = Path(sys.prefix)/'lib/python3.12'
    record = json.loads((args.rootfs/'bytecode-provenance.json').read_text())
    assert record['optimization'] == 0 and record['flags'] == 3
    original = importlib.machinery.SourceFileLoader.source_to_code
    blocked = []

    def checked(self, data, path, *, _optimize=-1):
        if Path(path).is_relative_to(lib):
            blocked.append(path)
            raise AssertionError('a sealed source was recompiled: '+path)
        return original(self, data, path, _optimize=_optimize)

    importlib.machinery.SourceFileLoader.source_to_code = checked
    root = Path(__file__).resolve().parents[1]
    tree = ast.parse((root/'scripts/e2e-osv-python-science.py').read_text())
    workloads = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == 'WORKLOADS' for target in node.targets))
    for name, code in workloads:
        exec(compile(code, '<reference-'+name+'>', 'exec', optimize=0), {})
    import numpy
    import pandas
    assert numpy.ndarray.__doc__ and pandas.DataFrame.__doc__
    loaded = [module for module in tuple(sys.modules.values())
        if getattr(module, '__file__', '').endswith('.py') and Path(module.__file__).is_relative_to(lib)
        and getattr(getattr(module, '__spec__', None), 'origin', None) != 'frozen']
    assert loaded and not blocked
    for module in loaded:
        assert Path(module.__cached__).is_file(), module.__name__
    # Same source length and restored mtime: only the source hash detects this
    # stale cache. -B keeps the old cache in place so the check cannot self-heal.
    args.scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='checked-pyc-', dir=args.scratch) as scratch:
        path = Path(scratch)/'case.py'
        path.write_text('VALUE = 42\n')
        py_compile.compile(str(path), doraise=True, optimize=0,
            invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH)
        cache = Path(importlib.util.cache_from_source(str(path)))
        before = cache.read_bytes()
        stamp = path.stat()
        def load_value():
            loader = importlib.machinery.SourceFileLoader('checked_case', str(path))
            return loader.get_code('checked_case')
        namespace = {}
        exec(load_value(), namespace)
        assert namespace['VALUE'] == 42
        path.write_text('VALUE = 43\n')
        os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        namespace = {}
        exec(load_value(), namespace)
        assert namespace['VALUE'] == 43 and cache.read_bytes() == before
    print(json.dumps({'linux_build_reference_only': True, 'source_recompile_blocked': True,
        'loaded_source_modules': len(loaded), 'same_size_mtime_invalidation_passed': True,
        'assertions_retained': True, 'numpy_doc_sha256': hashlib.sha256(numpy.ndarray.__doc__.encode()).hexdigest(),
        'pandas_doc_sha256': hashlib.sha256(pandas.DataFrame.__doc__.encode()).hexdigest()}), flush=True)


if __name__ == '__main__':
    main()
