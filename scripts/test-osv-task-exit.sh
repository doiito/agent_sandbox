#!/usr/bin/env bash
set -euo pipefail
workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d /tmp/osv-task-exit-unit.XXXXXXXX)
trap 'rm -rf "$work"' EXIT
"${CXX:-c++}" -std=gnu++11 -O2 -Wall -Wextra -Werror -pthread \
    -I"$workspace/osv-native/include" "$workspace/tests/osv-exit-bridge.cc" -o "$work/binding"
"${CC:-cc}" -std=gnu11 -O2 -Wall -Wextra -Werror -pthread \
    "$workspace/tests/osv-task-completion.c" -o "$work/completion"
"$work/binding"
"$work/completion"
