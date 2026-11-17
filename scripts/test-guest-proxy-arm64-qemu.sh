#!/usr/bin/env bash
set -euo pipefail
workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kernel=${ARM64_QEMU_KERNEL:-$workspace/build/validation/qemu-arm64/Image}
work=${GUEST_PROXY_QEMU_WORK:-$workspace/build/validation/guest-proxy-arm64}
if [[ ! -f "$kernel" || -e "$work" ]]; then
    echo 'Require a local ARM64 initrd kernel and a fresh validation work directory' >&2
    exit 2
fi
python3 - "$workspace" "$work" <<'PY'
from pathlib import Path
import sys
root, work = map(lambda p: Path(p).resolve(), sys.argv[1:])
if not work.is_relative_to(root / 'build/validation'):
    raise SystemExit('QEMU scratch must be within project build/validation')
PY
mkdir -p "$work/initrd/bin" "$work/initrd/proc" "$work/initrd/tmp"
cd "$workspace"
export GOCACHE=${GOCACHE:-/tmp/osv-sandbox-go-cache}
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c -trimpath -buildvcs=false \
    -o "$work/initrd/bin/proxy-tests" ./internal/sandbox
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false \
    -o "$work/initrd/init" ./tests/qemu-guest-proxy-init
cp assets/offline/linux-arm64/guest/busybox "$work/initrd/bin/busybox"
chmod 0755 "$work/initrd/bin/busybox"
(
    cd "$work/initrd"
    find . -print0 | cpio --null --create --format=newc --quiet > "$work/initrd.cpio"
)
timeout 75s qemu-system-aarch64 -machine virt -cpu cortex-a72 -m 512M -nic none \
    -nographic -no-reboot -kernel "$kernel" -initrd "$work/initrd.cpio" \
    -append 'console=ttyAMA0 rdinit=/init panic=1' > "$work/qemu.log" 2>&1
rg '^(--- PASS:|--- FAIL:|ARM64_GUEST_PROXY_CORE_)' "$work/qemu.log"
rg -q '^ARM64_GUEST_PROXY_CORE_PASS' "$work/qemu.log"
echo "ARM64 host proxy core evidence: $work/qemu.log"
