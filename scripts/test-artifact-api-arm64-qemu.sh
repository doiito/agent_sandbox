#!/usr/bin/env bash
set -euo pipefail
workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=${ARTIFACT_API_QEMU_WORK:-$workspace/build/validation/artifact-api-arm64}
kernel=${ARM64_QEMU_KERNEL:-$workspace/build/validation/qemu-arm64/Image}
cd "$workspace"
python3 - "$workspace" "$work" "$kernel" <<'PY'
from pathlib import Path
import sys
root,work,kernel=map(lambda v:Path(v).resolve(),sys.argv[1:])
assert work.is_relative_to(root/'build/validation') and not work.exists(), 'require fresh project validation directory'
assert kernel.is_file(), 'require project ARM64 initrd kernel'
PY
mkdir -p "$work/initrd/bin" "$work/initrd/tests/fixtures"
export GOCACHE=${GOCACHE:-/tmp/osv-sandbox-go-cache}
export GOPROXY=off GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=arm64
go test -c -trimpath -buildvcs=false -o "$work/initrd/bin/artifact-host-tests" ./internal/sandbox
go test -c -trimpath -buildvcs=false -o "$work/initrd/bin/artifact-grpc-tests" ./internal/controlgrpc
go test -c -trimpath -buildvcs=false -o "$work/initrd/bin/artifact-mcp-tests" ./internal/mcp
go build -trimpath -buildvcs=false -o "$work/initrd/init" ./tests/qemu-artifact-api-init
cp assets/offline/linux-arm64/guest/busybox "$work/initrd/bin/busybox"
chmod 0755 "$work/initrd/bin/busybox"
cp tests/fixtures/inference-sdk.json "$work/initrd/tests/fixtures/inference-sdk.json"
(
    cd "$work/initrd"
    find . -print0 | cpio --null --create --format=newc --quiet > "$work/initrd.cpio"
)
timeout 150s qemu-system-aarch64 -machine virt -cpu cortex-a72 -m 768M -nic none \
    -nographic -no-reboot -kernel "$kernel" -initrd "$work/initrd.cpio" \
    -append 'console=ttyAMA0 rdinit=/init panic=1' > "$work/qemu.log" 2>&1
rg '^ARM64_ARTIFACT_API_' "$work/qemu.log"
rg -q '^ARM64_ARTIFACT_API_PASS' "$work/qemu.log"
echo "ARM64 artifact API evidence: $work/qemu.log"
