#!/usr/bin/env bash
set -euo pipefail
workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d /tmp/osv-pipe-stat-unit.XXXXXXXX)
trap 'rm -rf "$work"' EXIT
"${CXX:-c++}" -std=gnu++11 -O2 -Wall -Wextra -Werror -pthread \
    "$workspace/tests/osv-pipe-stat-metadata.cc" -o "$work/metadata-tests"
"$work/metadata-tests"
