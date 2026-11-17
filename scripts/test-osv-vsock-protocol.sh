#!/usr/bin/env bash
set -euo pipefail
workspace_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
output=$(mktemp /tmp/osv-vsock-protocol.XXXXXX)
trap 'rm -f "$output"' EXIT
"${CXX:-g++}" -std=c++14 -Wall -Wextra -Werror -O1 -g -UNDEBUG \
    -fsanitize=address,undefined -fno-omit-frame-pointer \
    "$workspace_dir/osv-native/tests/protocol_test.cc" -o "$output"
"$output"
