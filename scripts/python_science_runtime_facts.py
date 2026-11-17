#!/usr/bin/env python3
"""Read version exports from the actual pinned Linux build artifacts."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import sys


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    rootfs = args.rootfs.resolve(strict=True)
    if sys.version_info[:3] != (3, 12, 16) or sys.flags.optimize or not sys.dont_write_bytecode:
        raise ValueError('requires pinned CPython 3.12.16, optimize=0 and -B')
    if sha(Path(sys.executable)) != sha(rootfs/'opt/python/bin/python3.12'):
        raise ValueError('interpreter differs from runtime')
    os.environ['OPENBLAS_NUM_THREADS'] = '1'
    os.environ['OMP_NUM_THREADS'] = '1'
    import numpy
    import pandas
    import pyexpat
    import _decimal
    library = rootfs/'opt/python/lib/python3.12/site-packages/numpy.libs/libscipy_openblas64_-f48b354e.so'
    blas = ctypes.CDLL(str(library))
    blas.scipy_openblas_get_config64_.restype = ctypes.c_char_p
    configuration = blas.scipy_openblas_get_config64_().decode('ascii')
    match = re.search(r'\bOpenBLAS (\S+)', configuration)
    if not match:
        raise ValueError('missing OpenBLAS version export')
    version = [ctypes.c_int64() for _ in range(3)]
    blas.scipy_LAPACKE_ilaver64_.argtypes = [ctypes.POINTER(ctypes.c_int64)]*3
    blas.scipy_LAPACKE_ilaver64_.restype = None
    blas.scipy_LAPACKE_ilaver64_(*(ctypes.byref(value) for value in version))
    if not (0 < version[0].value < 100 and all(0 <= value.value < 1000 for value in version[1:])):
        raise ValueError('invalid LAPACK version export')
    files = {'/opt/python/bin/python3.12': sha(rootfs/'opt/python/bin/python3.12'),
        '/opt/python/lib/libpython3.12.so.1.0':sha(rootfs/'opt/python/lib/libpython3.12.so.1.0'),
        '/'+str(library.relative_to(rootfs)):sha(library)}
    for module in (pyexpat, _decimal):
        guest = '/opt/python/'+str(Path(module.__file__).relative_to(sys.prefix))
        if sha(Path(module.__file__)) != sha(rootfs/guest.lstrip('/')):
            raise ValueError('version export comes from an external module')
        files[guest] = sha(Path(module.__file__))
    document = {'protocol':'osv-runtime-version-facts/v1', 'linux_build_reference_only':True,
        'python':'3.12.16', 'numpy':numpy.__version__, 'pandas':pandas.__version__,
        'expat':pyexpat.EXPAT_VERSION.removeprefix('expat_'), 'mpdecimal':_decimal.__libmpdec_version__,
        'openblas':match.group(1), 'openblas_configuration':configuration,
        'openblas_threads':blas.scipy_openblas_get_num_threads64_(),
        'lapack':'.'.join(str(value.value) for value in version),
        'files_sha256':files, 'generator_sha256':sha(Path(__file__))}
    args.output.write_text(json.dumps(document,indent=2)+'\n')
    print(json.dumps(document),flush=True)


if __name__ == '__main__':
    main()
