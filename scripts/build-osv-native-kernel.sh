#!/usr/bin/env bash
set -euo pipefail

workspace_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
osv_dir="$workspace_dir/osv-upstream"
builder_image=${OSV_NATIVE_BUILDER_IMAGE:-osv-sandbox-native-builder:ubuntu22.04}
jobs=${OSV_NATIVE_JOBS:-4}

if [[ ! "$jobs" =~ ^[1-9][0-9]*$ ]] || (( jobs > 16 )); then
    echo "OSV_NATIVE_JOBS must be between 1 and 16" >&2
    exit 2
fi

bash "$workspace_dir/scripts/fetch-osv-native-upstream.sh"
python3 "$workspace_dir/scripts/apply-osv-native.py" --osv-dir "$osv_dir"

docker run --rm --network none -v "$workspace_dir:/work" -w /work/osv-upstream \
    "$builder_image" make -f conf/Makefile -j1 config \
    conf_dot_file=/work/osv-native/conf/agent-sandbox.config

config="$osv_dir/build/release.x64/gen/config/kernel_conf.mk"
driver_config="$osv_dir/build/release.x64/gen/include/osv/drivers_config.h"
for expected in 'conf_drivers_profile=agent-sandbox' 'conf_hide_symbols=1'; do
    if ! grep -qx "$expected" "$config"; then
        echo "unexpected OSv config: missing $expected" >&2
        exit 1
    fi
done
if ! grep -qx '# CONF_networking_stack is not set' "$osv_dir/build/release.x64/.config"; then
    echo "unexpected OSv config: network stack enabled" >&2
    exit 1
fi

docker run --rm --network none -v "$workspace_dir:/work" -w /work/osv-upstream \
    "$builder_image" make "-j$jobs" fs=rofs \
    bootfs_manifest=../osv-native/conf/agent-sandbox-bootfs.manifest \
    build/release.x64/loader-stripped.elf

for expected in '#define CONF_drivers_virtio_vsock 1' '#define CONF_drivers_virtio_net 0' '#define CONF_drivers_pci 0'; do
    if ! grep -qx "$expected" "$driver_config"; then
        echo "unexpected OSv driver config: missing $expected" >&2
        exit 1
    fi
done

kernel="$osv_dir/build/release.x64/loader-stripped.elf"
test -s "$kernel"
symbols=$(readelf --dyn-syms --wide "$kernel")
for expected in osv_vsock_listen osv_vsock_accept osv_vsock_connect osv_vsock_recv \
    osv_vsock_send osv_vsock_shutdown osv_vsock_close osv_vsock_cid \
    osv_sandbox_run_module osv_sandbox_register_exit_callback osv_sandbox_mount_inputs_v1; do
    if ! grep -Eq " FUNC[[:space:]]+GLOBAL DEFAULT[[:space:]]+[0-9]+ $expected$" <<<"$symbols"; then
        echo "missing exported kernel symbol: $expected" >&2
        exit 1
    fi
done
sha256sum "$kernel"
