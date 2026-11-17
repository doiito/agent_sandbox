#!/usr/bin/env bash
set -euo pipefail
# Upstream's version diagnostics include __DATE__/__TIME__; keep linker inputs reproducible.
export SOURCE_DATE_EPOCH=0
date_flags=('-D__DATE__="Jan  1 1970"' '-D__TIME__="00:00:00"' -Wno-builtin-macro-redefined)
workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
privacy_flags=("-ffile-prefix-map=$workspace=/src/osv-sandbox" "-fdebug-prefix-map=$workspace=/src/osv-sandbox"
               "-ffile-prefix-map=${HOME:?missing build home}=/toolchain/home")
arch=${1:?missing C target architecture}
shift
case "$arch" in
    x86_64) isa_flags=(-march=x86-64 -mtune=generic) ;;
    aarch64) isa_flags=(-march=armv8-a -mno-outline-atomics) ;;
    *) echo 'unsupported mimalloc C target' >&2; exit 2 ;;
esac
sysroot="$workspace/assets/allocators/mimalloc/sysroots/$arch"
if [[ ! -f "$sysroot/headers-manifest.json" || ! -f "$sysroot/include/stdlib.h" ]]; then
    echo 'prepare the project C sysroots with python3 scripts/prepare-musl-headers.py' >&2
    exit 2
fi
compiler=${OSV_MUSL_CLANG:-clang}
if [[ "$arch" == aarch64 ]] && ! "$compiler" --print-targets | rg -q 'aarch64'; then
    image=${OSV_MUSL_C_BUILDER_IMAGE:-osv-sandbox-musl-c-builder:ubuntu22.04}
    if ! docker image inspect "$image" >/dev/null 2>&1; then
        echo 'AArch64 C backend missing; prepare deploy/musl-c-builder.Dockerfile or select a capable OSV_MUSL_CLANG' >&2
        exit 2
    fi
    mounts=(-v "$workspace:$workspace")
    if [[ -n ${OUT_DIR:-} ]]; then
        mounts+=(-v "$OUT_DIR:$OUT_DIR")
    fi
    exec docker run --rm -i --network none -e SOURCE_DATE_EPOCH "${mounts[@]}" -w "$PWD" "$image" \
        clang-14 "--target=$arch-unknown-linux-musl" "--sysroot=$sysroot" "${isa_flags[@]}" "${date_flags[@]}" "${privacy_flags[@]}" "$@"
fi
exec "$compiler" "--target=$arch-unknown-linux-musl" "--sysroot=$sysroot" "${isa_flags[@]}" "${date_flags[@]}" "${privacy_flags[@]}" "$@"
