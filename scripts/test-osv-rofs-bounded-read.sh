#!/usr/bin/env bash
set -euo pipefail
workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
output="$workspace/build/validation/rofs-bounded-read"
mkdir -p "$output"
${CXX:-c++} -std=c++17 -O1 -g -Wall -Wextra -Werror \
    -fsanitize=address,undefined -fno-omit-frame-pointer \
    "$workspace/tests/osv-rofs-bounded-read.cc" -o "$output/test"
"$output/test"
echo 'ROFS bounded read: content, offsets, EOF, allocation and IO/copy failures passed'
