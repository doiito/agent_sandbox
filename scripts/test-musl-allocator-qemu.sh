#!/usr/bin/env bash
set -euo pipefail
workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kernel=${ARM64_QEMU_KERNEL:?set ARM64_QEMU_KERNEL to a validated ARM64 Linux Image}
target_dir=${CARGO_TARGET_DIR:-$workspace/build/validation/mimalloc/target-arm64}
work=${ALLOCATOR_QEMU_WORK:-$workspace/build/validation/mimalloc/qemu}
if [[ ! -f "$kernel" || -e "$work" ]]; then
    echo 'allocator QEMU requires a kernel and a fresh work directory' >&2
    exit 2
fi
cd "$workspace"
test_binary=$(cargo test --manifest-path runtime-allocator/Cargo.toml --locked --offline \
    --release --features mimalloc --target aarch64-unknown-linux-musl \
    --target-dir "$target_dir" --no-run --message-format=json | python3 -c \
    'import json,sys; print(next(v["executable"] for v in map(json.loads,sys.stdin) if v.get("reason")=="compiler-artifact" and v.get("profile",{}).get("test") and v.get("executable")))')
cargo build --manifest-path runtime-allocator/Cargo.toml --locked --offline --release \
    --features mimalloc --example allocator-bench --target aarch64-unknown-linux-musl --target-dir "$target_dir"
mkdir -p "$work/initrd/bin" "$work/initrd/dev" "$work/initrd/proc" "$work/initrd/tmp"
cp "$test_binary" "$work/initrd/bin/allocator-tests"
cp "$target_dir/aarch64-unknown-linux-musl/release/examples/allocator-bench" "$work/initrd/bin/allocator-bench"
cp assets/offline/linux-arm64/guest/busybox "$work/initrd/bin/busybox"
chmod 0755 "$work/initrd/bin/"*
for binary in "$work/initrd/bin/"*; do
    readelf -h "$binary" | rg -q 'Machine:.*AArch64'
    if readelf -l "$binary" | rg -q INTERP; then echo 'QEMU test requires static executables' >&2; exit 1; fi
done
cat > "$work/initrd/init" <<'SH'
#!/bin/busybox sh
/bin/busybox mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
/bin/busybox mount -t proc proc /proc
/bin/allocator-tests --test-threads=1
tests=$?
/bin/allocator-bench churn 1 1024
bench=$?
if [ "$tests" = 0 ] && [ "$bench" = 0 ]; then
    echo OSV_MIMALLOC_QEMU_PASS
else
    echo OSV_MIMALLOC_QEMU_FAIL
fi
/bin/busybox poweroff -f
while true; do /bin/busybox sleep 1; done
SH
chmod 0755 "$work/initrd/init"
(
    cd "$work/initrd"
    find . -print0 | cpio --null --create --format=newc --quiet > "$work/initrd.cpio"
)
timeout 120s qemu-system-aarch64 -machine virt -cpu cortex-a72 -m 768M -nic none \
    -nographic -no-reboot -kernel "$kernel" -initrd "$work/initrd.cpio" \
    -append 'console=ttyAMA0 rdinit=/init panic=1' > "$work/qemu.log" 2>&1 || true
rg -q '^OSV_MIMALLOC_QEMU_PASS' "$work/qemu.log"
rg -q '4 passed; 0 failed' "$work/qemu.log"
rg -q '"allocator":"mimalloc","c_version":30302,"secure_level":4,"architecture":"aarch64"' "$work/qemu.log"
echo "ARM64 mimalloc unit evidence: $work/qemu.log"
