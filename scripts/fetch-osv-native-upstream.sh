#!/usr/bin/env bash
set -euo pipefail

workspace_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
target="$workspace_dir/osv-upstream"
pin=0e34e4dc2b278b7f64e4169abbf297b7de46fb6b

if [[ ! -e "$target" ]]; then
    git clone --filter=blob:none --no-checkout \
        https://github.com/cloudius-systems/osv.git "$target"
    git -C "$target" fetch --depth=1 origin "$pin"
    git -C "$target" checkout --detach "$pin"
fi
if [[ ! -d "$target/.git" ]]; then
    echo "not an OSv checkout: $target" >&2
    exit 1
fi
actual=$(git -C "$target" rev-parse HEAD)
if [[ "$actual" != "$pin" ]]; then
    echo "OSv checkout is $actual; expected $pin (refusing to overwrite)" >&2
    exit 1
fi

required=(musl_0.9.12 musl_1.2.1 kbuild external/x64/acpica apps)
for path in "${required[@]}"; do
    if [[ $(git -C "$target" submodule status -- "$path") == -* ]]; then
        git -C "$target" submodule update --init --checkout -- "$path"
    fi
done
while read -r path expected; do
    actual=$(git -C "$target/$path" rev-parse HEAD)
    if [[ "$actual" != "$expected" ]]; then
        echo "submodule $path is $actual; expected $expected" >&2
        exit 1
    fi
done <<'PINS'
musl_0.9.12 372a948b8139c6583045b2cd91b6b91fcb2e5881
musl_1.2.1 73cc775bee53300c7cf759f37580220b18ac13d3
kbuild 9f1d27a86879d1fa0944f426f5fa20c6be8de9da
external/x64/acpica 3e45e0f2383cabdc00275c00a12ea8797f285c30
apps b2d53b348c15ee1c1a05b1f23fe4f4702dc9cbef
PINS

echo "Pinned OSv source and required submodules verified: $pin"
