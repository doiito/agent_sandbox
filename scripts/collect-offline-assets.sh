#!/usr/bin/env bash
set -euo pipefail

workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
arch=${OFFLINE_ARCH:-}
case "$arch" in amd64|arm64) ;; *) echo 'OFFLINE_ARCH must be amd64 or arm64' >&2; exit 2 ;; esac
for required in FIRECRACKER_BIN JAILER_BIN KERNEL_IMAGE ROOTFS_IMAGE \
    GUEST_AGENT_BIN MKFS_BUNDLE_DIR; do
    if [[ -z ${!required:-} || ! -f ${!required} && ! -d ${!required} ]]; then
        echo "missing $required" >&2
        exit 2
    fi
done
asset="$workspace/assets/offline/linux-$arch"
if [[ -e "$asset/bin" || -e "$asset/artifacts" ]]; then
    echo "offline asset directory already contains a candidate: $asset" >&2
    exit 2
fi
mkdir -p "$asset/bin" "$asset/lib" "$asset/artifacts" "$asset/guest"
cp "$FIRECRACKER_BIN" "$asset/bin/firecracker"
cp "$JAILER_BIN" "$asset/bin/jailer"
cp "$MKFS_BUNDLE_DIR/bin/mkfs.ext4" "$asset/bin/mkfs.ext4"
cp "$MKFS_BUNDLE_DIR/lib/"* "$asset/lib/"
cp "$KERNEL_IMAGE" "$asset/artifacts/kernel"
cp "$ROOTFS_IMAGE" "$asset/artifacts/rootfs.ext4"
cp "$GUEST_AGENT_BIN" "$asset/guest/agent-init"
(
    cd "$asset"
    find bin lib artifacts guest -type f -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)
echo "$asset"
