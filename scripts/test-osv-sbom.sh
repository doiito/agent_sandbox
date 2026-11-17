#!/usr/bin/env bash
set -euo pipefail

workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
export GOCACHE=${GOCACHE:-/tmp/osv-sandbox-go-cache}
work=$(mktemp -d /tmp/osv-sbom-test.XXXXXXXX)
trap 'rm -rf "$work"' EXIT
for name in kernel rootfs agent module api launcher firecracker jailer; do
    printf 'OSv SBOM fixture %s\n' "$name" > "$work/$name"
done
cd "$workspace"
go run ./cmd/osv-sbom \
    -profile osv -osv-upstream-commit 0e34e4dc2b278b7f64e4169abbf297b7de46fb6b \
    -kernel "$work/kernel" -rootfs "$work/rootfs" -agent "$work/agent" \
    -module "/module.so=$work/module" -api "$work/api" -launcher "$work/launcher" \
    -firecracker "$work/firecracker" -jailer "$work/jailer" \
    -output "$work/sbom.json" >/dev/null
python3 - "$work/sbom.json" "$work/rootfs" <<'PY'
import hashlib
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text())
components = {item['name']: item for item in document['components']}
required = {'osv-kernel', 'osv-rootfs', 'osv-job-agent', 'osv-module/module.so',
            'OSv', 'firecracker', 'jailer', 'osv-sandboxd', 'osv-sandbox-launcher'}
if set(components) != required:
    raise SystemExit(f'OSv SBOM components do not match the signed template: {set(components)}')
if components['OSv']['version'] != '0e34e4dc2b278b7f64e4169abbf297b7de46fb6b':
    raise SystemExit('OSv upstream source revision missing')
expected = hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest()
if components['osv-rootfs']['hashes'] != [{'alg': 'SHA-256', 'content': expected}]:
    raise SystemExit('OSv rootfs hash missing')
PY
echo 'OSv SBOM profile semantics passed'
cp assets/allocators/mimalloc/source-lock.json "$work/allocator-policy.json"
printf 'actual-linker-input-fixture\n' > "$work/libmimalloc.a"
python3 - "$work" <<'PY'
from pathlib import Path
import hashlib
import json
import sys
work = Path(sys.argv[1])
(work/'allocator-provenance.json').write_text(json.dumps({
    'protocol': 'osv-musl-guest-build/v1', 'c_version': 30302, 'secure_level': 4,
    'libmimalloc_archive_sha256': hashlib.sha256((work/'libmimalloc.a').read_bytes()).hexdigest()}))
PY
common=(-kernel "$work/kernel" -rootfs "$work/rootfs" -agent "$work/agent" \
    -api "$work/api" -launcher "$work/launcher" -firecracker "$work/firecracker" -jailer "$work/jailer")
allocator=(-allocator-policy "$work/allocator-policy.json" -allocator-archive "$work/libmimalloc.a" \
    -allocator-provenance "$work/allocator-provenance.json")
go run ./cmd/osv-sbom "${common[@]}" "${allocator[@]}" -output "$work/linux.json" > /dev/null
python3 - "$work/linux.json" "$work/libmimalloc.a" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
items = {c['name']: c for c in json.loads(Path(sys.argv[1]).read_text())['components']}
assert items['mimalloc']['version'] == '0.1.52'
assert items['libmimalloc-sys']['version'] == '0.1.49'
assert items['mimalloc-c-static']['version'] == '3.3.2'
assert items['mimalloc-c-static']['hashes'][0]['content'] == hashlib.sha256(Path(sys.argv[2]).read_bytes()).hexdigest()
assert 'musl-guest-build-provenance' in items and 'mimalloc-source-policy' in items
PY
if go run ./cmd/osv-sbom "${common[@]}" "${allocator[@]}" -profile osv \
    -osv-upstream-commit 0e34e4dc2b278b7f64e4169abbf297b7de46fb6b \
    -module "/module.so=$work/module" -output "$work/rejected.json" > "$work/rejected.log" 2>&1; then
    echo 'Linux allocator incorrectly accepted in OSv SBOM' >&2; exit 1
fi
rg -q 'OSv SBOM cannot declare the Linux musl allocator' "$work/rejected.log"
printf 'changed-linker-input\n' >> "$work/libmimalloc.a"
if go run ./cmd/osv-sbom "${common[@]}" "${allocator[@]}" -output "$work/rejected.json" > "$work/rejected.log" 2>&1; then
    echo 'stale allocator provenance accepted' >&2; exit 1
fi
rg -q 'does not match hardened C 3.3.2 linker input' "$work/rejected.log"
echo 'Linux allocator SBOM source/linker binding and OSv separation passed'
printf 'standalone-supervisor-fixture\n' > "$work/supervisor"
python3 - "$work" <<'PY'
from pathlib import Path
import hashlib,json,sys
work=Path(sys.argv[1]); path=work/'allocator-provenance.json'; data=json.loads(path.read_text())
data['protocol']='osv-musl-guest-build/v2'
data['libmimalloc_archive_sha256']=hashlib.sha256((work/'libmimalloc.a').read_bytes()).hexdigest()
data['components']={'osv-workload-supervisor':{'allocator':'system','sha256':hashlib.sha256((work/'supervisor').read_bytes()).hexdigest()}}
path.write_text(json.dumps(data))
PY
go run ./cmd/osv-sbom "${common[@]}" "${allocator[@]}" -workload-supervisor "$work/supervisor" \
    -output "$work/supervisor-sbom.json" > /dev/null
python3 - "$work/supervisor-sbom.json" "$work/supervisor" <<'PY'
import hashlib,json,sys
from pathlib import Path
items={item['name']:item for item in json.loads(Path(sys.argv[1]).read_text())['components']}
helper=items['osv-workload-supervisor']
assert helper['hashes'][0]['content']==hashlib.sha256(Path(sys.argv[2]).read_bytes()).hexdigest()
assert {'name':'osv:allocator','value':'system'} in helper['properties']
PY
if go run ./cmd/osv-sbom "${common[@]}" "${allocator[@]}" -output "$work/rejected.json" > "$work/rejected.log" 2>&1; then
    echo 'v2 provenance accepted without its supervisor' >&2; exit 1
fi
rg -q 'requires the standalone workload supervisor' "$work/rejected.log"
for mutation in identity digest; do
    python3 - "$work/allocator-provenance.json" "$mutation" <<'PY'
import json,sys
from pathlib import Path
path=Path(sys.argv[1]); data=json.loads(path.read_text()); helper=data['components']['osv-workload-supervisor']
helper['allocator']='mimalloc' if sys.argv[2]=='identity' else 'system'
if sys.argv[2]=='digest': helper['sha256']='0'*64
path.write_text(json.dumps(data))
PY
    if go run ./cmd/osv-sbom "${common[@]}" "${allocator[@]}" -workload-supervisor "$work/supervisor" \
        -output "$work/rejected.json" > "$work/rejected.log" 2>&1; then
        echo 'incorrect supervisor identity or digest accepted' >&2; exit 1
    fi
    rg -q 'supervisor allocator or artifact differs from provenance' "$work/rejected.log"
done
echo 'Standalone supervisor SBOM identity, hash and omission rejection passed'
