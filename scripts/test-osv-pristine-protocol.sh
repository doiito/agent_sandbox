#!/usr/bin/env bash
set -euo pipefail
workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
output=$(mktemp /tmp/osv-pristine-protocol.XXXXXXXX)
trap 'rm -f "$output"' EXIT
"${CC:-gcc}" -std=c11 -Wall -Wextra -Werror -O1 -g -UNDEBUG \
    -fsanitize=address,undefined -fno-omit-frame-pointer \
    -I"$workspace/osv-native/include" \
    "$workspace/osv-native/tests/pristine_test.c" -o "$output"
"$output" "$workspace/tests/fixtures/osv-pristine-wire-v1.txt"
"${CC:-gcc}" -std=c11 -Wall -Wextra -Werror -O1 -g -UNDEBUG \
    -fsanitize=address,undefined -fno-omit-frame-pointer \
    -I"$workspace/osv-native/include" \
    "$workspace/osv-native/tests/pristine_inputs_test.c" -o "$output"
"$output" "$workspace/tests/fixtures/osv-pristine-inputs-wire-v1.txt"
