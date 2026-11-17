#!/usr/bin/env bash
set -euo pipefail
workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d /tmp/osv-clock-sleep-unit.XXXXXXXX)
trap 'rm -rf "$work"' EXIT
"${CXX:-c++}" -std=gnu++11 -O1 -g -Wall -Wextra -Werror -pthread \
    -fsanitize=undefined -fno-omit-frame-pointer \
    "$workspace/tests/osv-clock-sleep.cc" -o "$work/tests"
"$work/tests"
