#!/usr/bin/env bash
set -euo pipefail

failed=0
check() {
    local description=$1
    shift
    if "$@" >/dev/null 2>&1; then
        printf 'OK   %s\n' "$description"
    else
        printf 'FAIL %s\n' "$description"
        failed=1
    fi
}

check "KVM read/write" test -r /dev/kvm
check "KVM writable" test -w /dev/kvm
check "cgroup v2" test -f /sys/fs/cgroup/cgroup.controllers
for controller in cpu io memory pids; do
    check "cgroup controller $controller" grep -qw "$controller" /sys/fs/cgroup/cgroup.controllers
done
check "swap disabled" sh -c '! tail -n +2 /proc/swaps | grep -q .'
check "Firecracker installed" test -x /usr/local/bin/firecracker
check "jailer installed" test -x /usr/local/bin/jailer
if command -v systemd-analyze >/dev/null 2>&1; then
    check "launcher unit syntax" systemd-analyze verify deploy/systemd/osv-sandbox-launcher.service
    check "API unit syntax" systemd-analyze verify deploy/systemd/osv-sandboxd-production.service
fi
if grep -Rqs '^Vulnerable' /sys/devices/system/cpu/vulnerabilities 2>/dev/null; then
    printf 'FAIL unmitigated CPU vulnerability reported\n'
    failed=1
else
    printf 'OK   CPU vulnerability reports\n'
fi
exit "$failed"
