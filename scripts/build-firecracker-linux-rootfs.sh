#!/usr/bin/env bash
set -euo pipefail

workspace_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
image_tag=${LINUX_GUEST_BUILDER_IMAGE:-firecracker-linux-guest-builder:debian12}
output=${LINUX_ROOTFS_OUTPUT:-"$workspace_dir/build/linux-agent-rootfs.ext4"}
build_context=$(mktemp -d)
container_id=
cleanup() {
    if [[ -n "$container_id" ]]; then
        docker rm -f "$container_id" >/dev/null
    fi
    rm -rf "$build_context"
}
trap cleanup EXIT

cargo build --manifest-path "$workspace_dir/linux-guest/Cargo.toml" --locked \
    --release --target x86_64-unknown-linux-musl
mkdir -p "$build_context/deploy" "$build_context/linux-guest/rootfs/etc" \
    "$build_context/linux-guest/target/x86_64-unknown-linux-musl/release"
cp "$workspace_dir/deploy/linux-guest-rootfs.Dockerfile" "$build_context/deploy/"
cp "$workspace_dir/linux-guest/rootfs/etc/passwd" "$build_context/linux-guest/rootfs/etc/"
cp "$workspace_dir/linux-guest/rootfs/etc/group" "$build_context/linux-guest/rootfs/etc/"
cp "$workspace_dir/linux-guest/target/x86_64-unknown-linux-musl/release/agent-init" \
    "$build_context/linux-guest/target/x86_64-unknown-linux-musl/release/"
docker build -f "$build_context/deploy/linux-guest-rootfs.Dockerfile" \
    -t "$image_tag" "$build_context"
mkdir -p "$(dirname "$output")"
container_id=$(docker create "$image_tag" /unused)
docker cp "$container_id:/linux-agent-rootfs.ext4" "$output"
e2fsck -fn "$output"
sha256sum "$output"
