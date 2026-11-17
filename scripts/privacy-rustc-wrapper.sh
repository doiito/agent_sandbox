#!/usr/bin/env bash
set -euo pipefail
compiler=${1:?missing Rust compiler}
shift
workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
exec "$compiler" "--remap-path-prefix=$workspace=/src/osv-sandbox" \
    "--remap-path-prefix=${HOME:?missing build home}=/toolchain/home" "$@"
