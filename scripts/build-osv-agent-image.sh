#!/usr/bin/env bash
set -euo pipefail

workspace_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
osv_dir=${OSV_DIR:-"$workspace_dir/osv-upstream"}
agent_binary=${AGENT_BINARY:-"$workspace_dir/guest/target/x86_64-unknown-linux-musl/release/osv-agent-executor"}
export CCACHE_DIR=${CCACHE_DIR:-/tmp/osv-sandbox-ccache}

if [[ ! -x "$agent_binary" ]]; then
    cargo build --manifest-path "$workspace_dir/guest/Cargo.toml" \
        --locked --release --target x86_64-unknown-linux-musl
fi

if [[ ! -x "$osv_dir/scripts/build" ]]; then
    echo "OSv source tree not found at $osv_dir" >&2
    exit 1
fi

module_dir="$osv_dir/modules/agent-sandbox"
mkdir -p "$module_dir"
cp "$workspace_dir/osv-module/agent-sandbox/module.py" "$module_dir/module.py"

if git -C "$osv_dir" submodule status | grep -q '^-'; then
    echo "OSv submodules are missing; run: git -C $osv_dir submodule update --init --recursive" >&2
    exit 1
fi

(
    cd "$osv_dir"
    OSV_AGENT_BINARY="$agent_binary" ./scripts/build fs=rofs image=agent-sandbox
)

echo "kernel=$osv_dir/build/release/loader-stripped.elf"
echo "image=$osv_dir/build/release/usr.img"
sha256sum "$osv_dir/build/release/loader-stripped.elf" "$osv_dir/build/release/usr.img"

if command -v qemu-img >/dev/null 2>&1; then
    qemu-img convert -O raw "$osv_dir/build/release/usr.img" "$osv_dir/build/release/osv.raw"
    echo "firecracker_image=$osv_dir/build/release/osv.raw"
    sha256sum "$osv_dir/build/release/osv.raw"
fi
