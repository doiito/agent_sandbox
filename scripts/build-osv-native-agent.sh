#!/usr/bin/env bash
set -euo pipefail

workspace_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
builder_image=${OSV_NATIVE_BUILDER_IMAGE:-osv-sandbox-native-builder:ubuntu22.04}
jobs=${OSV_NATIVE_JOBS:-4}
if [[ ! "$jobs" =~ ^[1-9][0-9]*$ ]] || (( jobs > 16 )); then
    echo 'OSV_NATIVE_JOBS must be between 1 and 16' >&2
    exit 2
fi

bash "$workspace_dir/scripts/build-osv-native-kernel.sh"
docker run --rm --network none -v "$workspace_dir:/work" -w /work/osv-upstream \
    "$builder_image" ./scripts/build "-j$jobs" fs=rofs image=job-agent \
    fs_size_mb=64 conf_dot_file=/work/osv-native/conf/agent-sandbox.config \
    bootfs_manifest=../osv-native/conf/agent-sandbox-bootfs.manifest

release="$workspace_dir/osv-upstream/build/release.x64"
test -s "$release/usr.img"
test -s "$release/loader-stripped.elf"
qemu-img convert -f qcow2 -O raw "$release/usr.img" "$release/osv-native-agent.raw"
test "$(stat -c %s "$release/osv-native-agent.raw")" -eq 67108864
sha256sum "$release/loader-stripped.elf" "$release/osv-native-agent.raw" \
    "$workspace_dir/osv-upstream/apps/job-agent/osv-job-agent.so" \
    "$workspace_dir/osv-upstream/apps/job-agent/task-probe.so"

asset="$workspace_dir/assets/osv-native/linux-amd64"
mkdir -p "$asset/modules"
cp "$release/loader-stripped.elf" "$asset/kernel.elf"
cp "$release/osv-native-agent.raw" "$asset/rootfs.raw"
cp "$workspace_dir/osv-upstream/apps/job-agent/osv-job-agent.so" "$asset/modules/osv-job-agent.so"
cp "$workspace_dir/osv-upstream/apps/job-agent/task-probe.so" "$asset/modules/task-probe.so"
(
    cd "$asset"
    sha256sum kernel.elf rootfs.raw modules/osv-job-agent.so modules/task-probe.so > SHA256SUMS
    sha256sum -c SHA256SUMS --quiet
)
