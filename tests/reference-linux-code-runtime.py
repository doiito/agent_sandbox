#!/opt/python/bin/python3.12
"""Real runtime checks inside the isolated target root, with no package fetches."""
import bz2
import ctypes
import decimal
import hashlib
import json
import lzma
import multiprocessing
import os
from pathlib import Path
import platform
import readline
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import zlib

import numpy as np
import pandas as pd


def check(name, function):
    result = function()
    if result is not True:
        raise AssertionError(name + ': ' + repr(result))
    print('PASS runtime-' + name, flush=True)


def python_science():
    matrix = np.array([[1., 2.], [3., 4.]])
    assert np.allclose(matrix @ matrix, [[7, 10], [15, 22]])
    assert abs(np.linalg.det(matrix) + 2) < 1e-10
    frame = pd.DataFrame({'group': ['a', 'b', 'a'], 'value': [3, 4, 5]})
    assert frame.groupby('group')['value'].sum().to_dict() == {'a': 8, 'b': 4}
    with tempfile.TemporaryDirectory(dir='/workspace') as work:
        path = Path(work) / '科学.csv'
        frame.to_csv(path, index=False)
        assert pd.read_csv(path).to_dict('list') == frame.to_dict('list')
    return True


def python_stdlib():
    content = '离线运行时\n'.encode()
    for module in (bz2, lzma, zlib):
        assert module.decompress(module.compress(content)) == content
    assert hashlib.sha256(b'abc').hexdigest() == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    with sqlite3.connect(':memory:') as db:
        assert db.execute('select 6 * 7').fetchone()[0] == 42
    assert ctypes.CDLL(None).strlen(b'offline') == 7
    assert decimal.Decimal('0.1') + decimal.Decimal('0.2') == decimal.Decimal('0.3')
    assert len(ssl.create_default_context().get_ca_certs()) > 50
    with socket.socket() as _:
        pass
    # Multiprocessing semaphore/shared-memory support must exist in cross builds.
    with multiprocessing.Semaphore(1):
        pass
    return True


def child_process():
    child = subprocess.run([sys.executable, '-B', '-c',
                            'import sys; print("child ready"); print("child error",file=sys.stderr)'],
                           input='input\n', text=True, capture_output=True, timeout=15, check=True)
    assert child.stdout == 'child ready\n' and child.stderr == 'child error\n'
    return True


def node_and_typescript():
    node = '/opt/node/bin/node'
    script = r'''
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const cp = require('node:child_process');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const ts = require('/opt/typescript/lib/typescript.js');
assert.equal(process.version, 'v22.23.4');
assert.equal(ts.version, '5.9.3');
assert.equal(zlib.gunzipSync(zlib.gzipSync('offline')).toString(), 'offline');
assert.equal(crypto.createHash('sha256').update('offline').digest('hex').length, 64);
const context = vm.createContext({});
const code = ts.transpileModule('let value: number = 40; value += 2; value', {
  compilerOptions: {target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS}
}).outputText;
assert.equal(vm.runInContext(code, context), 42);
assert.equal(vm.runInContext('value + 1', context), 43);
fs.writeFileSync('/workspace/node-离线.txt', 'verified');
assert.equal(fs.readFileSync('/workspace/node-离线.txt', 'utf8'), 'verified');
fs.unlinkSync('/workspace/node-离线.txt');
const child = cp.spawnSync(process.execPath, ['-e', 'process.stdout.write("child ready")'], {encoding:'utf8'});
assert.equal(child.status, 0); assert.equal(child.stdout, 'child ready');
(async () => {assert.equal(await Promise.resolve(42), 42); console.log('NODE_RUNTIME_PASS');})()
  .catch(error => {console.error(error); process.exitCode = 1;});
'''
    output = subprocess.check_output([node, '-e', script], text=True, timeout=90)
    assert output == 'NODE_RUNTIME_PASS\n', output
    npm = subprocess.check_output([node, '/opt/node/lib/node_modules/npm/bin/npm-cli.js', '--version'],
                                  text=True, timeout=60).strip()
    assert npm and npm.split('.')[0].isdigit(), npm
    tsc = subprocess.check_output([node, '/opt/typescript/bin/tsc', '--version'], text=True, timeout=60)
    assert tsc.strip() == 'Version 5.9.3', tsc
    print('RUNTIME_NODE_FACTS ' + json.dumps({'node': '22.23.4', 'npm': npm, 'typescript': '5.9.3'}), flush=True)
    return True


def main():
    assert sys.version_info[:3] == (3, 12, 16), sys.version
    assert np.__version__ == '2.5.4' and pd.__version__ == '3.1.0'
    assert platform.machine() in {'x86_64', 'aarch64'}
    assert os.geteuid() == 10000, 'runtime reference must use the ordinary guest user'
    os.chdir('/workspace')
    print('RUNTIME_PYTHON_FACTS ' + json.dumps({'python': platform.python_version(),
          'architecture': platform.machine(), 'numpy': np.__version__, 'pandas': pd.__version__,
          'ssl': ssl.OPENSSL_VERSION, 'sqlite': sqlite3.sqlite_version}), flush=True)
    check('stdlib', python_stdlib)
    check('science', python_science)
    check('subprocess', child_process)
    pip = subprocess.check_output([sys.executable, '-B', '-m', 'pip', '--version'], text=True, timeout=60)
    assert pip.startswith('pip ') and '/opt/python/lib/python3.12/site-packages/pip' in pip, pip
    print('PASS runtime-pip ' + pip.strip(), flush=True)
    check('node-typescript-npm', node_and_typescript)
    print('LINUX_CODE_RUNTIME_REFERENCE_PASS', flush=True)


if __name__ == '__main__':
    main()
