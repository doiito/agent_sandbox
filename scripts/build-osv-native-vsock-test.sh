#!/usr/bin/env bash
set -euo pipefail

workspace_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
builder_image=${OSV_NATIVE_BUILDER_IMAGE:-osv-sandbox-native-builder:ubuntu22.04}
jobs=${OSV_NATIVE_JOBS:-4}

bash "$workspace_dir/scripts/build-osv-native-kernel.sh"

docker run --rm --network none -v "$workspace_dir:/work" -w /work/osv-upstream \
    "$builder_image" ./scripts/build "-j$jobs" fs=rofs image=vsock-test \
    fs_size_mb=64 conf_dot_file=/work/osv-native/conf/agent-sandbox.config \
    bootfs_manifest=../osv-native/conf/agent-sandbox-bootfs.manifest

release="$workspace_dir/osv-upstream/build/release.x64"
test -s "$release/usr.img"
test -s "$release/loader-stripped.elf"
qemu-img convert -f qcow2 -O raw "$release/usr.img" "$release/osv-native-vsock.raw"
test "$(stat -c %s "$release/osv-native-vsock.raw")" -eq 67108864
sha256sum "$release/loader-stripped.elf" "$release/usr.img" \
    "$release/osv-native-vsock.raw" "$workspace_dir/osv-upstream/apps/vsock-test/vsock-test.so" \
    "$workspace_dir/osv-upstream/apps/vsock-test/task-probe.so"
