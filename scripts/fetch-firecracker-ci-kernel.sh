#!/usr/bin/env bash
set -euo pipefail

architecture=${ARCHITECTURE:-$(uname -m)}
kernel_series=${FIRECRACKER_KERNEL_SERIES:-6.18}
artifact_base=${FIRECRACKER_ARTIFACT_BASE:-https://s3.amazonaws.com/spec.ccfc.min}
output=${LINUX_KERNEL_OUTPUT:-build/vmlinux-firecracker}

prefix=$(curl -fsSL "$artifact_base?list-type=2&prefix=firecracker-ci/&delimiter=/" \
    | grep -oP '(?<=<Prefix>)firecracker-ci/[0-9]{8}-[^/]+/(?=</Prefix>)' \
    | sort | tail -1)
kernel_key=$(curl -fsSL "$artifact_base?list-type=2&prefix=${prefix}${architecture}/vmlinux-${kernel_series}." \
	| grep -oP "(?<=<Key>)(${prefix}${architecture}/vmlinux-${kernel_series//./\\.}\.[0-9]{1,3})(?=</Key>)" \
    | sort -V | tail -1)
if [[ -z "$kernel_key" ]]; then
    echo "No Firecracker CI kernel found for $architecture" >&2
    exit 1
fi
mkdir -p "$(dirname "$output")"
curl -fL "$artifact_base/$kernel_key" -o "$output"
chmod 0444 "$output"
echo "source=$artifact_base/$kernel_key"
sha256sum "$output"
