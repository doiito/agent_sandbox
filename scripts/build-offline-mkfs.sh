#!/usr/bin/env bash
set -euo pipefail

workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
arch=${1:-}
output=${2:-}
case "$arch" in
    amd64|arm64) ;;
    *) echo 'usage: build-offline-mkfs.sh amd64|arm64 OUTPUT_DIR' >&2; exit 2 ;;
esac
if [[ -z "$output" ]]; then echo 'missing output directory' >&2; exit 2; fi
tag="osv-offline-mkfs:bookworm-$arch"
docker build -f "$workspace/deploy/offline-mkfs.Dockerfile" \
    --build-arg "DEBIAN_ARCH=$arch" -t "$tag" "$workspace"
mkdir -p "$output"
container=$(docker create "$tag" /unused)
trap 'docker rm -f "$container" >/dev/null' EXIT
docker cp "$container:/bin" "$output/"
docker cp "$container:/lib" "$output/"
readelf -h "$output/bin/mkfs.ext4" | rg 'Machine:'
find "$output/lib" -maxdepth 1 -type f -print | sort
