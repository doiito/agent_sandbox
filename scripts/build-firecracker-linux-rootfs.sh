#!/usr/bin/env bash
set -euo pipefail

workspace_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
output=${LINUX_ROOTFS_OUTPUT:-"$workspace_dir/build/linux-agent-rootfs.ext4"}
target_dir=${CARGO_TARGET_DIR:-"$workspace_dir/linux-guest/target"}
arch=${LINUX_GUEST_ARCH:-$(uname -m)}
case "$arch" in
    x86_64|amd64) arch=x86_64; docker_arch=amd64 ;;
    aarch64|arm64) arch=aarch64; docker_arch=arm64 ;;
    *) echo "unsupported Linux guest architecture: $arch" >&2; exit 2 ;;
esac
rust_target=${arch}-unknown-linux-musl
cd "$workspace_dir"
LINUX_GUEST_BUSYBOX=${LINUX_GUEST_BUSYBOX:-$workspace_dir/assets/offline/linux-$docker_arch/guest/busybox}
build_context=$(mktemp -d)
cleanup() {
    rm -rf "$build_context"
}
trap cleanup EXIT

agent="$target_dir/$rust_target/release/agent-init"
supervisor="$target_dir/$rust_target/release/osv-workload-supervisor"
if [[ -n ${MUSL_GUEST_ASSETS:-} ]]; then
    python3 scripts/check-musl-allocator.py --architecture "$docker_arch" \
        --artifacts "$MUSL_GUEST_ASSETS" > /dev/null
    agent="$MUSL_GUEST_ASSETS/agent-init"
    supervisor="$MUSL_GUEST_ASSETS/osv-workload-supervisor"
else
    cargo build --manifest-path "$workspace_dir/linux-guest/Cargo.toml" --locked --offline --features mimalloc \
        --release --target "$rust_target" --target-dir "$target_dir"
    python3 scripts/check-musl-allocator.py --architecture "$docker_arch" \
        --binary "$agent" > /dev/null
    supervisor_map="$build_context/supervisor-link-map.txt"
    if [[ "$arch" == x86_64 ]]; then map_arg="-Wl,-Map=$supervisor_map"; else map_arg="-Map=$supervisor_map"; fi
    cargo rustc --manifest-path "$workspace_dir/linux-guest/Cargo.toml" --locked --offline --features mimalloc \
        --release --target "$rust_target" --target-dir "$target_dir" --bin osv-workload-supervisor \
        -- -C "link-arg=$map_arg"
    python3 scripts/check-musl-allocator.py --architecture "$docker_arch" \
        --supervisor "$supervisor" --supervisor-link-map "$supervisor_map" > /dev/null
fi
busybox=${LINUX_GUEST_BUSYBOX}
bash_assets=${BASH_ASSETS:-$workspace_dir/assets/bash/artifacts/linux-$docker_arch}
python3 scripts/check-static-bash.py --architecture "$docker_arch" --artifacts "$bash_assets" > /dev/null
if [[ ! -f "$busybox" ]]; then echo "missing static BusyBox: $busybox" >&2; exit 2; fi
expected_machine='Advanced Micro Devices X86-64'
if [[ "$arch" == aarch64 ]]; then expected_machine='AArch64'; fi
if ! readelf -h "$busybox" | rg -q "Machine:.*$expected_machine"; then
    echo "BusyBox architecture does not match $arch" >&2
    exit 2
fi
if readelf -l "$busybox" | rg -q INTERP; then
    echo 'BusyBox must be statically linked' >&2
    exit 2
fi
rootfs="$build_context/rootfs"
mkdir -p "$rootfs/bin" "$rootfs/sbin" "$rootfs/usr/bin" "$rootfs/usr/local/bin" \
    "$rootfs/etc" "$rootfs/proc" "$rootfs/sys" "$rootfs/dev" "$rootfs/run" \
    "$rootfs/tmp" "$rootfs/workspace" "$rootfs/input"
cp "$busybox" "$rootfs/bin/busybox"
for applet in sh ash echo printf true false sleep cat ls id uname env pwd \
    mkdir touch rm cp mv dd head tail yes wc grep sed awk find xargs sync poweroff wget nc chmod; do
    ln -s busybox "$rootfs/bin/$applet"
done
cp "$workspace_dir/linux-guest/rootfs/etc/passwd" "$rootfs/etc/passwd"
cp "$workspace_dir/linux-guest/rootfs/etc/group" "$rootfs/etc/group"
cp "$agent" "$rootfs/sbin/agent-init"
cp "$supervisor" "$rootfs/sbin/osv-workload-supervisor"
http_client=${LINUX_GUEST_HTTP_BIN:-$workspace_dir/build/linux-http/linux-$docker_arch/osv-http}
if [[ -z ${LINUX_GUEST_HTTP_BIN:-} ]]; then
    mkdir -p "$(dirname "$http_client")"
    GOCACHE=${GOCACHE:-/tmp/osv-sandbox-go-cache} CGO_ENABLED=0 GOOS=linux GOARCH="$docker_arch" \
        go build -buildvcs=false -trimpath -o "$http_client" ./cmd/osv-http
fi
if ! readelf -h "$http_client" | rg -q "Machine:.*$expected_machine" || readelf -l "$http_client" | rg -q INTERP; then
    echo 'guest HTTP client must be static and match the target architecture' >&2; exit 2
fi
cp "$http_client" "$rootfs/usr/bin/osv-http"
chmod 0755 "$rootfs/usr/bin/osv-http"
mkdir -p "$rootfs/etc/ssl/certs"
cp "$workspace_dir/assets/trust/mozilla-2026-10-20/cacert.pem" "$rootfs/etc/ssl/certs/ca-certificates.crt"
cp "$bash_assets/bash" "$rootfs/bin/bash"
chmod 0755 "$rootfs/bin/bash"
chmod 0755 "$rootfs/bin/busybox" "$rootfs/sbin/agent-init" "$rootfs/sbin/osv-workload-supervisor"
chmod 1777 "$rootfs/tmp"
chmod 0755 "$rootfs/workspace"
mkdir -p "$(dirname "$output")"
truncate -s 64M "$output"
mkfs.ext4 -q -F -O '^has_journal' -L agent-rootfs -d "$rootfs" "$output"
e2fsck -fn "$output"
sha256sum "$output"
