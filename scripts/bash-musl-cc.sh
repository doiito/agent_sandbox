#!/usr/bin/env bash
set -euo pipefail
workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
arch=${OSV_BASH_ARCH:?set OSV_BASH_ARCH}
case "$arch" in x86_64|aarch64) ;; *) exit 2 ;; esac
lib="$workspace/assets/bash/toolchain/$arch/lib"
compiler="$workspace/scripts/musl-cc-$arch.sh"
export OUT_DIR="$PWD"
for arg in "$@"; do
    case "$arg" in -c|-E|-S|--version|-v|-dumpmachine|-dumpversion|-print-*) exec "$compiler" "$@" ;; esac
done
exec "$compiler" -static -fuse-ld=lld -nostdlib \
    "$lib/crt1.o" "$lib/crti.o" "$lib/crtbegin.o" "$@" \
    -Wl,--start-group "$lib/libc.a" "$lib/libgcc.a" "$lib/libgcc_eh.a" -Wl,--end-group \
    "$lib/crtend.o" "$lib/crtn.o"
