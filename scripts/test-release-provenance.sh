#!/usr/bin/env bash
set -euo pipefail

workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
marker=$(mktemp "$workspace/.release-provenance-test.XXXXXXXX")
trap 'rm -f "$marker"' EXIT

common=(RELEASE_ARCH=amd64 RELEASE_VERSION=provenance-test
        RELEASE_VALID_UNTIL=2027-04-01T00:00:00Z
        RELEASE_PRIVATE_KEY=/nonexistent ARTIFACT_PRIVATE_KEY=/nonexistent)
output=$(env "${common[@]}" RELEASE_OUTPUT=/tmp/provenance.test-signed.tar \
    bash "$workspace/scripts/build-offline-release.sh" 2>&1) && {
    echo 'dirty formal release unexpectedly accepted' >&2
    exit 1
}
[[ $output == *'formal release requires a clean Git worktree'* ]] || {
    echo "unexpected dirty-worktree rejection: $output" >&2
    exit 1
}
output=$(env "${common[@]}" RELEASE_ALLOW_DIRTY_TEST=1 \
    RELEASE_OUTPUT=/tmp/provenance.tar \
    bash "$workspace/scripts/build-offline-release.sh" 2>&1) && {
    echo 'dirty candidate with formal filename unexpectedly accepted' >&2
    exit 1
}
[[ $output == *'dirty test candidate output must end in .test-signed.tar'* ]] || {
    echo "unexpected test-candidate rejection: $output" >&2
    exit 1
}
echo 'release provenance negative checks passed'
