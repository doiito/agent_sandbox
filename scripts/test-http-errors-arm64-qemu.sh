#!/usr/bin/env bash
set -euo pipefail
workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kernel=${ARM64_QEMU_KERNEL:?set ARM64_QEMU_KERNEL to a validated Linux Image}
binary=${HTTP_ERRORS_ARM64_TEST_BINARY:?set HTTP_ERRORS_ARM64_TEST_BINARY to the frozen test ELF}
api=${HTTP_ERRORS_ARM64_API_BINARY:?set HTTP_ERRORS_ARM64_API_BINARY to the actual API ELF}
probe=${HTTP_ERRORS_ARM64_PROCESS_PROBE:?set HTTP_ERRORS_ARM64_PROCESS_PROBE to the verification ELF}
pki=${HTTP_ERRORS_TEST_PKI:?set HTTP_ERRORS_TEST_PKI to disposable verification TLS fixtures}
work=${HTTP_ERRORS_ARM64_QEMU_WORK:?set HTTP_ERRORS_ARM64_QEMU_WORK to a fresh verification directory}
schema_cli=${HTTP_CONTRACT_ARM64_CLI:-}
test -f "$kernel"
test ! -e "$work"
for input in "$binary" "$api" "$probe"; do
    readelf -h "$input" | rg -q 'Machine:.*AArch64'
    if readelf -l "$input" | rg -q INTERP; then
        echo 'HTTP contract QEMU requires static ARM64 binaries' >&2
        exit 2
    fi
done
if [[ -n "$schema_cli" ]]; then
    readelf -h "$schema_cli" | rg -q 'Machine:.*AArch64'
    if readelf -l "$schema_cli" | rg -q INTERP; then
        echo 'HTTP schema QEMU requires a static ARM64 contract CLI' >&2
        exit 2
    fi
fi
mkdir -p "$work/initrd/bin" "$work/initrd/dev" "$work/initrd/proc" "$work/initrd/tmp" "$work/initrd/pki"
cp "$workspace/assets/offline/linux-arm64/guest/busybox" "$work/initrd/bin/busybox"
cp "$binary" "$work/initrd/bin/http-error-tests"
cp "$api" "$work/initrd/bin/osv-sandboxd"
cp "$probe" "$work/initrd/bin/process-probe"
cp "$workspace/examples/config.production.json" "$work/initrd/config.production.json"
if [[ -n "$schema_cli" ]]; then
    mkdir -p "$work/initrd/internal/sandbox"
    cp "$schema_cli" "$work/initrd/bin/api-contract"
    cp "$workspace/internal/sandbox/http.go" "$work/initrd/internal/sandbox/http.go"
    cp "$workspace/api/contracts/openapi.json" "$work/initrd/openapi.json"
fi
for name in ca.crt server.crt server.key client.crt client.key; do
    cp "$pki/$name" "$work/initrd/pki/$name"
done
chmod 0755 "$work/initrd/bin/"*
cat > "$work/initrd/init" <<'SH'
#!/bin/busybox sh
/bin/busybox mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t tmpfs tmpfs /tmp
/bin/busybox chmod 1777 /tmp
/bin/busybox ifconfig lo 127.0.0.1 netmask 255.0.0.0 up
selection='^TestHTTPErrorContract(EveryRegisteredRoutePreservesMethodAllow|AuthenticationPrecedesRouteClassification|VersionBoundaryAndRoutingPrivacy|PreservesRedirectsConnectAndBusinessWildcards|MTLSHTTP1AndHTTP2Wire|RoutingOTLPStatusesAreFailuresWithoutRawURL)$|^TestOTLPAPIThreeSignalsUseTrustedMetadataAndNeverRawRequestData$'
GOMAXPROCS=2 TMPDIR=/tmp /bin/http-error-tests -test.v -test.run "$selection" -test.timeout=180s
tests=$?
if [ -f /bin/api-contract ]; then
    /bin/api-contract -source-root / -check -output /openapi.json
    schema=$?
    GOMAXPROCS=2 TMPDIR=/tmp /bin/http-error-tests -test.v -test.run '^TestRESTWireContractInferenceErrorPreservesInvocation$' -test.timeout=30s
    wire=$?
    if [ "$schema" = 0 ] && [ "$wire" = 0 ]; then
        echo OSV_REST_WIRE_CONTRACT_ARM64_PASS
    else
        tests=1
        echo OSV_REST_WIRE_CONTRACT_ARM64_FAIL
    fi
fi
/bin/process-probe -api /bin/osv-sandboxd -pki /pki -config-template /config.production.json -work /contract-work -output /process.json
process=$?
if [ -f /process.json ]; then /bin/busybox cat /process.json; fi
if [ "$tests" = 0 ] && [ "$process" = 0 ]; then
    echo OSV_HTTP_ERROR_CONTRACT_ARM64_PASS
else
    echo OSV_HTTP_ERROR_CONTRACT_ARM64_FAIL
fi
/bin/busybox poweroff -f
while true; do /bin/busybox sleep 1; done
SH
chmod 0755 "$work/initrd/init"
(
    cd "$work/initrd"
    find . -print0 | cpio --null --create --format=newc --quiet | gzip -n > "$work/initrd.cpio.gz"
)
set +e
timeout 240s qemu-system-aarch64 -machine virt -cpu cortex-a72 -m 1024M -smp 2 -nic none \
    -nographic -no-reboot -kernel "$kernel" -initrd "$work/initrd.cpio.gz" \
    -append 'console=ttyAMA0 rdinit=/init panic=1' > "$work/qemu.log" 2>&1
qemu_status=$?
set -e
test "$qemu_status" = 0
rg -q '^OSV_HTTP_ERROR_CONTRACT_ARM64_PASS' "$work/qemu.log"
if rg -q '^OSV_HTTP_ERROR_CONTRACT_ARM64_FAIL|^--- FAIL:|DATA RACE' "$work/qemu.log"; then
    echo 'ARM64 HTTP error contract reported failure' >&2
    exit 1
fi
echo "ARM64 HTTP error contract functional evidence: $work/qemu.log"
