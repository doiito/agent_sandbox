#!/usr/bin/env bash
set -euo pipefail

workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kernel=${ARM64_QEMU_KERNEL:-}
if [[ -z "$kernel" || ! -f "$kernel" ]]; then
    echo 'set ARM64_QEMU_KERNEL to an ARM64 Linux Image with initrd support' >&2
    exit 2
fi
work=$(mktemp -d /tmp/osv-arm64-qemu.XXXXXXXX)
stage="$work/stage"
initrd="$work/initrd"
mkdir -p "$stage/bin" "$stage/artifacts" "$stage/config" "$stage/systemd" \
    "$stage/sdk/python" "$stage/sdk/node" "$initrd/bin" "$initrd/tmp" "$initrd/tests/fixtures"
cp "$workspace/tests/fixtures/osv-pristine-wire-v1.txt" "$initrd/tests/fixtures/"
cp "$workspace/tests/fixtures/inference-sdk.json" "$initrd/tests/fixtures/"
cp "$workspace/tests/fixtures/egress-outer-policy-rejection.json" "$initrd/tests/fixtures/"
cp "$workspace/assets/offline/linux-arm64/guest/busybox" "$initrd/bin/busybox"
if [[ -n ${ARM64_QEMU_ARTIFACT_PUBLIC_KEY:-} ]]; then
    cp "$ARM64_QEMU_ARTIFACT_PUBLIC_KEY" "$initrd/artifact.public"
fi
chmod 0755 "$initrd/bin/busybox"
if [[ -n ${ARM64_QEMU_GUEST_HTTP:-} ]]; then
    cp "$ARM64_QEMU_GUEST_HTTP" "$initrd/bin/guest-http"
    mkdir -p "$initrd/etc/ssl/certs"
    cp "$workspace/assets/trust/mozilla-2026-10-20/cacert.pem" "$initrd/etc/ssl/certs/ca-certificates.crt"
fi
cp "$workspace/assets/bash/artifacts/linux-arm64/bash" "$initrd/bin/bash"
chmod 0755 "$initrd/bin/bash"
for applet in sh sleep yes head; do
    ln -s busybox "$initrd/bin/$applet"
done
if [[ -n ${ARM64_QEMU_MODULE_DIR:-} ]]; then
    mkdir -p "$initrd/modules"
    for name in crc32c_generic crc16 mbcache jbd2 ext4 loop; do
        cp "$ARM64_QEMU_MODULE_DIR/$name.ko" "$initrd/modules/$name.ko"
    done
fi
export GOCACHE=${GOCACHE:-/tmp/osv-offline-qemu-go-cache}
export CGO_ENABLED=0

cd "$workspace"
for name in osv-sandboxd osv-sandbox-launcher osv-offline-release; do
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -buildvcs=false -trimpath \
        -o "$stage/bin/$name" "./cmd/$name"
done
# Protocol fixture: real ARM64 application/installer binaries; these stand-ins
# exercise package architecture and signature checks, not a Firecracker VM.
for name in firecracker jailer mkfs.ext4; do
    cp "$stage/bin/osv-offline-release" "$stage/bin/$name"
done
for name in kernel rootfs.ext4 manifest.json manifest.json.sig sbom.cdx.json; do
    printf 'ARM64 QEMU release protocol fixture: %s\n' "$name" > "$stage/artifacts/$name"
done
printf '{}\n' > "$stage/config/config.production.json.template"
cp deploy/systemd/osv-sandboxd-production.service "$stage/systemd/osv-sandboxd.service"
cp deploy/systemd/osv-sandbox-launcher.service "$stage/systemd/osv-sandbox-launcher.service"
cp sdk/python/osv_sandbox_client.py "$stage/sdk/python/osv_sandbox_client.py"
sha256sum sdk/python/osv_sandbox_client.py > "$initrd/sdk.sha256"
cp sdk/node/index.js sdk/node/index.d.ts sdk/node/package.json "$stage/sdk/node/"
sha256sum sdk/node/index.js > "$initrd/node-sdk.sha256"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -buildvcs=false -trimpath \
    -o "$initrd/init" ./tests/qemu-arm64-init
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c \
    -o "$initrd/bin/capacity-tests" ./internal/sandbox
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c \
    -o "$initrd/bin/mcp-tests" ./internal/mcp
python3 scripts/test-mcp-stdio.py --fixtures-only "$initrd/mcp"
cp "$stage/bin/osv-offline-release" "$initrd/bin/"
agent_tests=$(cargo test \
    --manifest-path linux-guest/Cargo.toml --locked --offline --release \
    --target aarch64-unknown-linux-musl --no-run --message-format=json \
    | python3 -c 'import json,sys; print(next(x["executable"] for x in list(map(json.loads,sys.stdin)) if x.get("reason")=="compiler-artifact" and x.get("target",{}).get("name")=="agent-init" and x.get("executable") and x.get("profile",{}).get("test")))')
if [[ -z "$agent_tests" ]]; then echo 'ARM64 agent test binary missing' >&2; exit 1; fi
cp "$agent_tests" "$initrd/bin/agent-tests"
allocator_tests=$(cargo test --manifest-path runtime-allocator/Cargo.toml --locked --offline --release \
    --target aarch64-unknown-linux-musl --no-run --message-format=json | python3 -c \
    'import json,sys; print(next(x["executable"] for x in list(map(json.loads,sys.stdin)) if x.get("reason")=="compiler-artifact" and x.get("executable") and x.get("profile",{}).get("test")))')
cp "$allocator_tests" "$initrd/bin/allocator-tests"

if [[ -n ${ARM64_QEMU_BUNDLE:-} ]]; then
    if [[ -z ${ARM64_QEMU_PUBLIC_KEY:-} ]]; then echo 'ARM64_QEMU_PUBLIC_KEY required' >&2; exit 2; fi
    cp "$ARM64_QEMU_BUNDLE" "$initrd/release.tar"
    cp "$ARM64_QEMU_PUBLIC_KEY" "$initrd/release.public"
else
    go run ./cmd/osv-offline-release keygen \
        -private-key "$work/release.private" -public-key "$work/release.public"
    go run ./cmd/osv-offline-release pack -source "$stage" -archive "$work/release.tar" \
        -private-key "$work/release.private" -version qemu-arm64 -arch arm64 -commit qemu-fixture \
        -valid-until "$(date -u -d '+30 days' +%Y-%m-%dT%H:%M:%SZ)"
    cp "$work/release.tar" "$initrd/release.tar"
    cp "$work/release.public" "$initrd/release.public"
fi
(
    cd "$initrd"
    find . -print0 | cpio --null --create --format=newc --quiet > "$work/initrd.cpio"
)
timeout 120s qemu-system-aarch64 -machine virt -cpu cortex-a72 -m 1536M -nic none \
    -nographic -no-reboot -kernel "$kernel" -initrd "$work/initrd.cpio" \
    -append 'console=ttyAMA0 rdinit=/init panic=1' > "$work/qemu.log" 2>&1 || true
rg 'ARM64_QEMU|PASS |FAIL ' "$work/qemu.log" || true
if ! rg -q '^ARM64_QEMU_TEST_PASS' "$work/qemu.log"; then
    echo "ARM64 QEMU test failed; evidence: $work/qemu.log" >&2
    exit 1
fi
if [[ -n ${ARM64_QEMU_BUNDLE:-} ]] && ! rg -q '^PASS bundled-mkfs' "$work/qemu.log"; then
    echo "Bundled ARM64 mkfs test failed; evidence: $work/qemu.log" >&2
    exit 1
fi
if ! rg -q '^PASS bundled-sdk' "$work/qemu.log"; then
    echo "Bundled Python SDK check failed; evidence: $work/qemu.log" >&2
    exit 1
fi
if ! rg -q '^PASS bundled-node-sdk' "$work/qemu.log"; then
    echo "Bundled Node SDK check failed; evidence: $work/qemu.log" >&2
    exit 1
fi
if [[ -n ${ARM64_QEMU_BUNDLE:-} ]] && ! rg -q '^PASS bundled-mcp-stdio' "$work/qemu.log"; then
    echo "Bundled ARM64 MCP stdio test failed; evidence: $work/qemu.log" >&2
    exit 1
fi
if [[ -n ${ARM64_QEMU_BUNDLE:-} ]] && ! rg -q '^PASS bundled-egress-fetch' "$work/qemu.log"; then
    echo "Bundled ARM64 egress fetch test failed; evidence: $work/qemu.log" >&2
    exit 1
fi
if ! rg -q '^PASS musl-mimalloc' "$work/qemu.log"; then
    echo "Static ARM64 allocator functionality failed; evidence: $work/qemu.log" >&2
    exit 1
fi
if [[ ${ARM64_QEMU_REQUIRE_OCI:-0} == 1 ]] && ! rg -q '^PASS bundled-template-oci' "$work/qemu.log"; then
    echo "Bundled ARM64 OCI tool test failed; evidence: $work/qemu.log" >&2
    exit 1
fi
echo "ARM64 QEMU evidence: $work/qemu.log"
