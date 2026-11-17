#!/usr/bin/env bash
set -euo pipefail
workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kernel=${ARM64_QEMU_KERNEL:?set ARM64_QEMU_KERNEL to a validated Linux Image}
binary=${INFERENCE_ARM64_TEST_BINARY:?set INFERENCE_ARM64_TEST_BINARY to the frozen static ARM64 test ELF}
work=${INFERENCE_ARM64_QEMU_WORK:?set INFERENCE_ARM64_QEMU_WORK to a fresh verification directory}
if [[ ! -f "$kernel" || ! -f "$binary" || -e "$work" ]]; then
    echo 'inference QEMU requires a kernel, test ELF, and fresh work directory' >&2
    exit 2
fi
readelf -h "$binary" | rg -q 'Machine:.*AArch64'
if readelf -l "$binary" | rg -q INTERP; then
    echo 'inference QEMU requires a static test ELF' >&2
    exit 2
fi
mkdir -p "$work/initrd/bin" "$work/initrd/dev" "$work/initrd/proc" "$work/initrd/tmp" "$work/initrd/tests/fixtures"
cp "$workspace/assets/offline/linux-arm64/guest/busybox" "$work/initrd/bin/busybox"
cp "$binary" "$work/initrd/bin/inference-tests"
cp "$workspace/tests/fixtures/inference-sdk.json" "$work/initrd/tests/fixtures/inference-sdk.json"
cp "$workspace/tests/fixtures/egress-outer-policy-rejection.json" "$work/initrd/tests/fixtures/egress-outer-policy-rejection.json"
chmod 0755 "$work/initrd/bin/"*
cat > "$work/initrd/init" <<'SH'
#!/bin/busybox sh
/bin/busybox mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t tmpfs tmpfs /tmp
/bin/busybox chmod 1777 /tmp
/bin/busybox ifconfig lo 127.0.0.1 netmask 255.0.0.0 up
GOMAXPROCS=2 TMPDIR=/tmp /bin/inference-tests -test.v -test.run '^TestInference' -test.timeout=180s
tests=$?
if [ "$tests" = 0 ]; then
    echo OSV_INFERENCE_CORE_ARM64_PASS
else
    echo OSV_INFERENCE_CORE_ARM64_FAIL
fi
/bin/busybox poweroff -f
while true; do /bin/busybox sleep 1; done
SH
chmod 0755 "$work/initrd/init"
(
    cd "$work/initrd"
    find . -print0 | cpio --null --create --format=newc --quiet | gzip -n > "$work/initrd.cpio.gz"
)
set +e
timeout 240s qemu-system-aarch64 -machine virt -cpu cortex-a72 -m 1024M -smp 2 -nic none \
    -nographic -no-reboot -kernel "$kernel" -initrd "$work/initrd.cpio.gz" \
    -append 'console=ttyAMA0 rdinit=/init panic=1' > "$work/qemu.log" 2>&1
qemu_status=$?
set -e
test "$qemu_status" = 0
rg -q '^OSV_INFERENCE_CORE_ARM64_PASS' "$work/qemu.log"
if rg -q '^OSV_INFERENCE_CORE_ARM64_FAIL|^--- FAIL:|DATA RACE' "$work/qemu.log"; then
    echo 'ARM64 inference core reported failure' >&2
    exit 1
fi
echo "ARM64 inference core functional evidence: $work/qemu.log"
