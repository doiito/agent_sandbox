#!/usr/bin/env python3
"""Exercise the real .so CLI entrypoint on Linux; never OSv acceptance."""
import argparse
import importlib.util
import os
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--entry', type=Path, required=True)
    parser.add_argument('--module', type=Path, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('science_cases', Path(__file__).with_name('e2e-osv-python-science.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    cases = [(name, ['-c', code], 0, re.search(r'print\("([A-Z_]+)"\)', code).group(1), '', b'')
             for name, code in module.WORKLOADS]
    cases.extend([
        ('version-option', ['-V'], 0, 'Python 3.12.16', '', b''),
        ('module-option', ['-m', 'json.tool'], 0, '"value": 42', '', b'{"value":42}'),
        ('argv-stdin-isolation', ['-c', 'import os,sys; assert sys.argv==["-c","one arg","\u6c49\u5b57"]; assert sys.stdin.buffer.read()==b"A\\x00B\\xff"; assert sys.flags.isolated and sys.flags.ignore_environment and sys.flags.no_user_site; assert "/attacker" not in sys.path; assert os.environ["SCIENCE_MARKER"]=="ok"; print("CLI_OK")', 'one arg', '\u6c49\u5b57'], 0, 'CLI_OK', '', b'A\0B\xff'),
        ('stderr-exit', ['-c', 'import sys; print("OUT"); print("ERR",file=sys.stderr); sys.exit(7)'], 7, 'OUT', 'ERR', b''),
        ('exception', ['-c', 'raise RuntimeError("EXPECTED_EXCEPTION")'], 1, '', 'EXPECTED_EXCEPTION', b''),
    ])
    for name, arguments, exit_code, stdout, stderr, stdin in cases:
        env = dict(os.environ, SCIENCE_MARKER='ok', PYTHONHOME='/attacker', PYTHONPATH='/attacker')
        result = subprocess.run([str(args.entry), str(args.module), *arguments], env=env,
            input=stdin, capture_output=True, timeout=30)
        if (result.returncode != exit_code or stdout.encode() not in result.stdout or stderr.encode() not in result.stderr):
            raise RuntimeError(f'{name}: exit={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}')
        print('LINUX_SHARED_MODULE_REFERENCE_ONLY', name, 'PASS', flush=True)


if __name__ == '__main__':
    main()
