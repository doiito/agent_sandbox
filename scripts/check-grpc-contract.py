#!/usr/bin/env python3
"""Check pinned tools, regenerated bindings and the independent compiled ABI offline."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(command):
    subprocess.run(list(map(str, command)), cwd=ROOT, env=dict(os.environ, GOPROXY='off', GOTOOLCHAIN='local'), check=True)


def main():
    protoc_root = ROOT / 'assets/build/protoc/33.0'
    lock = json.loads((protoc_root / 'lock.json').read_text())
    assert lock['official_published_digest_verified']
    assert sha(protoc_root / 'LICENSE') == lock['license_sha256']
    for name, digest in lock['files'].items():
        assert sha(protoc_root / name) == digest, name
    tools = ROOT / 'assets/build/go-tools'
    plugins = json.loads((tools / 'lock.json').read_text())
    for name, entry in plugins['tools'].items():
        assert sha(tools / 'bin' / name) == entry['sha256'], name
    run([sys.executable, '-B', ROOT / 'scripts/generate-grpc-contract.py', '--check'])
    with tempfile.TemporaryDirectory(prefix='osv-grpc-generated-check-', dir='/tmp') as temporary:
        work = Path(temporary)
        run([protoc_root / 'bin/protoc', '-I', ROOT,
             '--plugin=protoc-gen-go=' + str(tools / 'bin/protoc-gen-go'),
             '--plugin=protoc-gen-go-grpc=' + str(tools / 'bin/protoc-gen-go-grpc'),
             '--go_out=' + str(work), '--go_opt=paths=source_relative',
             '--go-grpc_out=' + str(work), '--go-grpc_opt=paths=source_relative',
             '--descriptor_set_out=' + str(work / 'control.descriptor.pb'),
             '--include_source_info', '--include_imports', 'api/control/v1/control.proto'])
        for name in ['control.pb.go', 'control_grpc.pb.go']:
            assert sha(work / 'api/control/v1' / name) == sha(ROOT / 'api/control/v1' / name), 'stale generated binding: ' + name
        assert sha(work / 'control.descriptor.pb') == sha(ROOT / 'api/control/v1/control.descriptor.pb'), 'stale descriptor'
        baseline = ROOT / 'api/control/v1/abi-baseline.pb'
        assert sha(baseline) == (ROOT / 'api/control/v1/abi-baseline.sha256').read_text().split()[0]
        run(['go', 'run', './cmd/osv-grpc-contract', '-baseline', baseline, '-current', work / 'control.descriptor.pb'])
    print('Pinned native gRPC generation, complete operations and compiled ABI checked offline')


if __name__ == '__main__':
    main()
