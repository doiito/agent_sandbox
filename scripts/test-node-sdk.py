#!/usr/bin/env python3
"""Require all declared SDK cases, rather than only a test-file exit status."""
from pathlib import Path
import hashlib
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
sources=sorted((ROOT/'sdk/node').glob('test-*.mjs'))
expected=[name for source in sources for name in re.findall(r"(?m)^test\('([^']+)'",source.read_text())]
assert expected and len(expected)==len(set(expected)), 'SDK test names must be unique'
# These cases mock transport in one process. Explicit isolation also prevents
# a child-file summary from being mistaken for the named cases on Node 22.
help_text=subprocess.check_output(['node','--help'],text=True)
isolation=[]
for flag in ('--test-isolation','--experimental-test-isolation'):
    if flag+'=' in help_text:
        isolation=[flag+'=none']
        break
run=subprocess.run(['node','--test',*isolation,'--test-reporter=junit',*map(str,sources)],capture_output=True,text=True,cwd=ROOT)
sys.stderr.write(run.stderr)
if run.returncode:
    sys.stdout.write(run.stdout)
    raise SystemExit(run.returncode)
report=ET.fromstring(run.stdout)
cases=report.findall('.//testcase')
names=[case.attrib['name'] for case in cases]
if len(names)!=len(expected) or set(names)!=set(expected) or any(list(case) for case in cases):
    raise SystemExit(f'Node SDK cases did not all run successfully: expected={len(expected)} observed={len(names)}')
print(f'Node SDK: {len(names)} named cases passed')
compiler = ROOT/'assets/build/typescript'
lock = json.loads((compiler/'source-lock.json').read_text())
assert hashlib.sha256((compiler/'typescript-5.9.3.tgz').read_bytes()).hexdigest() == lock['archive_sha256']
assert hashlib.sha256((compiler/'package/lib/_tsc.js').read_bytes()).hexdigest() == lock['compiler_sha256']
subprocess.run(['node', str(compiler/'package/lib/tsc.js'), '-p', 'sdk/node/tsconfig.test.json'],
               cwd=ROOT, check=True)
print('Node SDK: TypeScript declarations passed')
