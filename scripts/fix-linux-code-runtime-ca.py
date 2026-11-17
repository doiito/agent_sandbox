#!/usr/bin/env python3
"""Record and fix the default OpenSSL CA lookup of the first build assets."""
import json
from pathlib import Path
import shutil

from linux_code_runtime_closure import inventory, sha

ROOT = Path(__file__).resolve().parents[1]
for architecture in ['amd64', 'arm64']:
    asset = ROOT / 'assets/runtimes/linux-code' / ('linux-' + architecture)
    rootfs = asset / 'rootfs'
    seal = asset / 'runtime-inventory.json'
    record = json.loads(seal.read_text())
    if 'finalization' in record:
        raise ValueError('CA finalization was already applied')
    if record['files'] != inventory(rootfs):
        raise ValueError('cannot finalize a changed build asset')
    parent = sha(seal)
    history = asset / 'build-history'
    history.mkdir()
    shutil.copyfile(seal, history / 'runtime-inventory.r1.json')
    snapshot = ROOT / 'build/validation/code-contexts/build-linux-code-runtime.r1.py'
    if sha(snapshot) != record['inputs_sha256']['scripts/build-linux-code-runtime.py']:
        raise ValueError('original build script snapshot mismatch')
    shutil.copyfile(snapshot, history / snapshot.name)
    ssl = rootfs / 'usr/lib/ssl'
    ssl.mkdir()
    (ssl / 'cert.pem').symlink_to('../../../etc/ssl/certs/ca-certificates.crt')
    (ssl / 'certs').symlink_to('../../../etc/ssl/certs')
    record['files'] = inventory(rootfs)
    record['finalization'] = {'protocol': 'osv-linux-code-runtime-ca-fix/v1',
                              'parent_inventory_sha256': parent, 'script_sha256': sha(Path(__file__)),
                              'changes': ['/usr/lib/ssl/cert.pem', '/usr/lib/ssl/certs']}
    seal.write_text(json.dumps(record, indent=2) + '\n')
    (asset / 'SHA256SUMS').write_text(sha(seal) + '  runtime-inventory.json\n')
    print('Finalized default OpenSSL CA lookup: ' + architecture)
