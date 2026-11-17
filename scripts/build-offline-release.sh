#!/usr/bin/env bash
set -euo pipefail

workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
arch=${RELEASE_ARCH:-}
version=${RELEASE_VERSION:-}
valid_until=${RELEASE_VALID_UNTIL:-}
output=${RELEASE_OUTPUT:-}
security_profile=${RELEASE_SECURITY_PROFILE:-baseline}
export GOCACHE=${GOCACHE:-/tmp/osv-offline-release-go-cache}
export CGO_ENABLED=0
guest_proxy=${RELEASE_GUEST_PROXY:-0}
file_watch=${RELEASE_FILE_WATCH:-0}
port_forward=${RELEASE_PORT_FORWARD:-0}
workspace_artifacts=${RELEASE_WORKSPACE_ARTIFACTS:-0}
osv_python=${RELEASE_OSV_PYTHON:-0}
linux_code=${RELEASE_LINUX_CODE:-0}
inference=${RELEASE_INFERENCE:-0}
case "$inference" in 0|1) ;; *) echo 'RELEASE_INFERENCE must be 0 or 1' >&2; exit 2 ;; esac
case "$linux_code" in 0|1) ;; *) echo 'RELEASE_LINUX_CODE must be 0 or 1' >&2; exit 2 ;; esac
case "$osv_python" in 0|1) ;; *) echo 'RELEASE_OSV_PYTHON must be 0 or 1' >&2; exit 2 ;; esac
case "$guest_proxy" in 0|1) ;; *) echo 'RELEASE_GUEST_PROXY must be 0 or 1' >&2; exit 2 ;; esac
case "$file_watch" in 0|1) ;; *) echo 'RELEASE_FILE_WATCH must be 0 or 1' >&2; exit 2 ;; esac
case "$port_forward" in 0|1) ;; *) echo 'RELEASE_PORT_FORWARD must be 0 or 1' >&2; exit 2 ;; esac
case "$workspace_artifacts" in 0|1) ;; *) echo 'RELEASE_WORKSPACE_ARTIFACTS must be 0 or 1' >&2; exit 2 ;; esac
case "$security_profile" in baseline|extended) ;; *) echo 'RELEASE_SECURITY_PROFILE must be baseline or extended' >&2; exit 2 ;; esac
case "$arch" in amd64|arm64) ;; *) echo 'RELEASE_ARCH must be amd64 or arm64' >&2; exit 2 ;; esac
if [[ "$inference" == 1 && ( "$guest_proxy" != 1 || "$linux_code" != 1 ) ]]; then
    echo 'RELEASE_INFERENCE requires RELEASE_GUEST_PROXY=1 and RELEASE_LINUX_CODE=1' >&2
    exit 2
fi
if [[ "$inference" == 1 && "$osv_python" == 1 && -z ${RELEASE_OSV_PYTHON_ASSETS:-} ]]; then
    echo 'inference requires an explicitly selected RELEASE_OSV_PYTHON_ASSETS v7 image' >&2
    exit 2
fi
if [[ "$osv_python" == 1 && "$arch" != amd64 ]]; then
    echo 'the locked OSv Python science template is available only for amd64' >&2
    exit 2
fi
asset="$workspace/assets/offline/linux-$arch"
FIRECRACKER_BIN=${FIRECRACKER_BIN:-$asset/bin/firecracker}
JAILER_BIN=${JAILER_BIN:-$asset/bin/jailer}
KERNEL_IMAGE=${KERNEL_IMAGE:-$asset/artifacts/kernel}
ROOTFS_IMAGE=${ROOTFS_IMAGE:-$asset/artifacts/rootfs.ext4}
GUEST_AGENT_BIN=${GUEST_AGENT_BIN:-$asset/guest/agent-init}
MUSL_GUEST_ASSETS=${MUSL_GUEST_ASSETS:-$workspace/assets/allocators/mimalloc/artifacts/linux-$arch}
BASH_ASSETS=${BASH_ASSETS:-$workspace/assets/bash/artifacts/linux-$arch}
MKFS_BUNDLE_DIR=${MKFS_BUNDLE_DIR:-$asset}
for required in RELEASE_VERSION RELEASE_VALID_UNTIL RELEASE_OUTPUT RELEASE_PRIVATE_KEY \
    ARTIFACT_PRIVATE_KEY; do
    if [[ -z ${!required:-} ]]; then echo "missing $required" >&2; exit 2; fi
done
release_commit=$(git -C "$workspace" rev-parse --verify HEAD)
release_dirty=$(git -C "$workspace" status --porcelain --untracked-files=all)
if [[ ${RELEASE_ALLOW_DIRTY_TEST:-0} == 1 ]]; then
    if [[ $output != *.test-signed.tar ]]; then
        echo 'dirty test candidate output must end in .test-signed.tar' >&2
        exit 2
    fi
    release_commit="$release_commit-dirty-test"
elif [[ -n "$release_dirty" ]]; then
    echo 'formal release requires a clean Git worktree; set RELEASE_ALLOW_DIRTY_TEST=1 only for test-signed candidates' >&2
    exit 2
fi
gate_plan_dir=
cleanup_gate_plan() {
    if [[ -n "$gate_plan_dir" ]]; then rm -rf -- "$gate_plan_dir"; fi
}
trap cleanup_gate_plan EXIT
if [[ ${RELEASE_ALLOW_DIRTY_TEST:-0} != 1 ]]; then
    if [[ "$security_profile" == extended && ( -z ${RELEASE_SECURITY_SNAPSHOT:-} || -z ${RELEASE_SECURITY_SNAPSHOT_SHA256:-} ) ]]; then
        echo 'formal release requires RELEASE_SECURITY_SNAPSHOT and externally pinned RELEASE_SECURITY_SNAPSHOT_SHA256' >&2
        exit 2
    fi
    for required in RELEASE_STARTUP_CANDIDATE RELEASE_VALIDATED_CANDIDATE RELEASE_CANDIDATE_PUBLIC_KEY RELEASE_PRIVACY_POLICY; do
        if [[ -z ${!required:-} ]]; then echo "formal release missing $required" >&2; exit 2; fi
    done
    python3 "$workspace/scripts/check-startup-gates.py" --require-target --candidate "$RELEASE_STARTUP_CANDIDATE"
    gate_plan_dir=$(mktemp -d /tmp/osv-release-candidate-gate.XXXXXXXX)
    python3 "$workspace/scripts/release_candidate_gate.py" preflight \
        --startup "$RELEASE_STARTUP_CANDIDATE" --candidate "$RELEASE_VALIDATED_CANDIDATE" \
        --public-key "$RELEASE_CANDIDATE_PUBLIC_KEY" --arch "$arch" --output "$gate_plan_dir/plan.json"
    SOURCE_DATE_EPOCH=$(python3 - "$gate_plan_dir/plan.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['target']['build']['epoch'])
PY
)
else
    gate_plan_dir=$(mktemp -d /tmp/osv-release-candidate-gate.XXXXXXXX)
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(date -u +%s)}
fi
export SOURCE_DATE_EPOCH
python3 "$workspace/scripts/release_candidate_gate.py" build-info --epoch "$SOURCE_DATE_EPOCH" --output "$gate_plan_dir/build-before.json"
if [[ -f "$asset/SHA256SUMS" ]]; then
    (cd "$asset" && sha256sum -c SHA256SUMS --quiet)
fi
python3 "$workspace/scripts/check-musl-allocator.py" --architecture "$arch" \
    --artifacts "$MUSL_GUEST_ASSETS" > /dev/null
if ! cmp -s "$GUEST_AGENT_BIN" "$MUSL_GUEST_ASSETS/agent-init"; then
    echo 'release agent differs from the verified mimalloc build' >&2
    exit 1
fi
guest_features=()
if [[ "$workspace_artifacts" == 1 ]]; then
    python3 - "$workspace" "$MUSL_GUEST_ASSETS/build-provenance.json" <<'PY'
import hashlib,json
from pathlib import Path
import sys
root=Path(sys.argv[1]);sources=json.loads(Path(sys.argv[2]).read_text())['source_sha256']
modules=sorted((root/'linux-guest/src/artifacts').glob('*.rs'))+[root/'linux-guest/src/main.rs']
assert len(modules)>=5, 'missing artifact service implementation'
for module in modules:
    name=str(module.relative_to(root))
    assert sources.get(name)==hashlib.sha256(module.read_bytes()).hexdigest(), 'artifacts require rebuilt source-bound guest: '+name
PY
    guest_features+=(-agent-feature workspace-artifacts-v1)
fi
if [[ "$port_forward" == 1 ]]; then
    python3 - "$workspace" "$MUSL_GUEST_ASSETS/build-provenance.json" <<'PY'
import hashlib,json
from pathlib import Path
import sys
root=Path(sys.argv[1]);sources=json.loads(Path(sys.argv[2]).read_text())['source_sha256']
modules=sorted((root/'linux-guest/src/port_service').glob('*.rs'))+[root/'linux-guest/src/main.rs']
assert len(modules)>=5, 'missing port service implementation'
for module in modules:
    name=str(module.relative_to(root))
    assert sources.get(name)==hashlib.sha256(module.read_bytes()).hexdigest(), 'ports require rebuilt source-bound guest: '+name
PY
    guest_features+=(-agent-feature port-forward-v1)
fi
if [[ "$guest_proxy" == 1 ]]; then
    python3 - "$workspace" "$MUSL_GUEST_ASSETS/build-provenance.json" <<'PY'
import hashlib,json
from pathlib import Path
import sys
root=Path(sys.argv[1]);provenance=json.loads(Path(sys.argv[2]).read_text());name='linux-guest/src/network_proxy.rs'
assert provenance['source_sha256'].get(name)==hashlib.sha256((root/name).read_bytes()).hexdigest(), 'guest proxy requires rebuilt source-bound guest'
PY
    guest_features+=(-agent-feature vsock-proxy-v1)
fi
if [[ "$file_watch" == 1 ]]; then
    python3 - "$workspace" "$MUSL_GUEST_ASSETS/build-provenance.json" <<'PY'
import hashlib,json
from pathlib import Path
import sys
root=Path(sys.argv[1]);sources=json.loads(Path(sys.argv[2]).read_text())['source_sha256']
modules=sorted((root/'linux-guest/src/file_watch').glob('*.rs'))
assert len(modules)==3, 'missing guest watch modules'
for module in modules:
    name=str(module.relative_to(root))
    assert sources.get(name)==hashlib.sha256(module.read_bytes()).hexdigest(), 'file watch requires rebuilt source-bound guest: '+name
PY
    guest_features+=(-agent-feature workspace-watch-v1)
fi
if [[ "$arch" == amd64 ]]; then
    readelf -h "$KERNEL_IMAGE" | rg -q 'Machine:.*Advanced Micro Devices X86-64'
else
    file "$KERNEL_IMAGE" | rg -q 'ARM64 boot executable Image'
fi
checkdir=$(mktemp -d /tmp/osv-offline-rootfs-check.XXXXXXXX)
debugfs -R "dump /sbin/agent-init $checkdir/agent-init" "$ROOTFS_IMAGE" >/dev/null 2>&1
debugfs -R "dump /sbin/osv-workload-supervisor $checkdir/osv-workload-supervisor" "$ROOTFS_IMAGE" >/dev/null 2>&1
if ! cmp -s "$checkdir/osv-workload-supervisor" "$MUSL_GUEST_ASSETS/osv-workload-supervisor"; then
    echo 'rootfs supervisor differs from the selected static build' >&2
    exit 1
fi
python3 "$workspace/scripts/check-static-bash.py" --architecture "$arch" --artifacts "$BASH_ASSETS" > /dev/null
debugfs -R "dump /bin/bash $checkdir/bash" "$ROOTFS_IMAGE" >/dev/null 2>&1
if ! cmp -s "$checkdir/bash" "$BASH_ASSETS/bash"; then echo 'rootfs Bash differs from selected static build' >&2; exit 1; fi
if ! cmp -s "$checkdir/agent-init" "$GUEST_AGENT_BIN"; then
    echo 'rootfs agent differs from the selected target-architecture agent' >&2
    exit 1
fi
guest_http=()
if [[ "$guest_proxy" == 1 ]]; then
    debugfs -R "dump /usr/bin/osv-http $checkdir/osv-http" "$ROOTFS_IMAGE" >/dev/null 2>&1
    debugfs -R "dump /etc/ssl/certs/ca-certificates.crt $checkdir/roots.crt" "$ROOTFS_IMAGE" >/dev/null 2>&1
    if ! cmp -s "$checkdir/roots.crt" "$workspace/assets/trust/mozilla-2026-10-20/cacert.pem"; then
        echo 'guest proxy rootfs must contain pinned offline public CA data' >&2; exit 1
    fi
    guest_http=(-guest-http "$checkdir/osv-http")
fi
stage=${RELEASE_STAGE_DIR:-$(mktemp -d /tmp/osv-offline-release.XXXXXXXX)}
if [[ -e "$stage/bin" || -e "$stage/artifacts" ]]; then
    echo "release stage must be empty: $stage" >&2
    exit 2
fi
mkdir -p "$stage/bin" "$stage/artifacts" "$stage/lib" "$stage/config" \
    "$stage/systemd" "$stage/docs" "$stage/examples" "$stage/sdk/python" "$stage/sdk/node"
export GOCACHE=${GOCACHE:-/tmp/osv-offline-release-go-cache}
# All release tooling is pure Go, including nested catalog signing/BOM commands.
export CGO_ENABLED=0
cd "$workspace"
go run ./cmd/osv-api-contract --check
python3 -B scripts/check-api-contract.py
python3 -B scripts/check-grpc-contract.py
for name in osv-sandboxd osv-sandbox-launcher osv-offline-release osv-sandbox-mcp osv-sandbox-egress osv-template-oci; do
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -mod=vendor -buildvcs=false -trimpath \
        -o "$stage/bin/$name" "./cmd/$name"
done
cp "$FIRECRACKER_BIN" "$stage/bin/firecracker"
cp "$JAILER_BIN" "$stage/bin/jailer"
cp "$MKFS_BUNDLE_DIR/bin/mkfs.ext4" "$stage/bin/mkfs.ext4"
cp "$MKFS_BUNDLE_DIR/lib/"* "$stage/lib/"
cp "$KERNEL_IMAGE" "$stage/artifacts/kernel"
cp "$ROOTFS_IMAGE" "$stage/artifacts/rootfs.ext4"
cp docs/PRODUCTION.zh-CN.md "$stage/docs/PRODUCTION.zh-CN.md"
cp docs/MCP.zh-CN.md "$stage/docs/MCP.zh-CN.md"
cp docs/EGRESS.zh-CN.md "$stage/docs/EGRESS.zh-CN.md"
mkdir -p "$stage/docs/contracts"
cp api/contracts/openapi.json "$stage/docs/contracts/openapi.json"
cmp api/contracts/openapi.json "$stage/docs/contracts/openapi.json"
mkdir -p "$stage/docs/contracts/api/control/v1"
cp api/control/v1/control.proto "$stage/docs/contracts/api/control/v1/"
cp api/control/v1/control.descriptor.pb "$stage/docs/contracts/"
cp docs/GRPC.zh-CN.md "$stage/docs/GRPC.zh-CN.md"
awk '/^## 开发与验收状态$/{exit} {print}' docs/API-CONTRACTS.zh-CN.md > "$stage/docs/API-CONTRACTS.zh-CN.md"
cp examples/mcp.production.json "$stage/examples/mcp.production.json"
cp examples/egress.production.json "$stage/examples/egress.production.json"
cp assets/trust/mozilla-2026-10-20/cacert.pem "$stage/examples/egress-public-roots.crt"
cp assets/trust/mozilla-2026-10-20/LICENSE "$stage/docs/egress-roots-LICENSE.txt"
cp assets/trust/mozilla-2026-10-20/source-lock.json "$stage/docs/egress-roots-source-lock.json"
cp "$BASH_ASSETS/LICENSE" "$stage/docs/bash-LICENSE.txt"
cp "$BASH_ASSETS/source-lock.json" "$stage/docs/bash-source-lock.json"
cp "$BASH_ASSETS/build-provenance.json" "$stage/docs/bash-build-provenance.json"
cp assets/bash/source/bash-5.3.tar.gz "$stage/docs/bash-5.3.tar.gz"
cp "$MUSL_GUEST_ASSETS/allocator-policy.json" "$stage/docs/mimalloc-policy.json"
cp "$MUSL_GUEST_ASSETS/build-provenance.json" "$stage/docs/musl-guest-build-provenance.json"
cp "$MUSL_GUEST_ASSETS/compiler-transcript.txt" "$stage/docs/mimalloc-compiler-transcript.txt"
for license in rust sys c; do
    cp "$MUSL_GUEST_ASSETS/licenses/mimalloc-$license.txt" "$stage/docs/mimalloc-$license-LICENSE.txt"
done
cp examples/auth.production.json examples/config.production.json "$stage/examples/"
cp sdk/python/README.md "$stage/docs/PYTHON-SDK.md"
cp docs/PREVIEW.zh-CN.md "$stage/docs/PREVIEW.zh-CN.md"
awk '/^## 开发与验收状态$/{exit} {print}' docs/OCI-TEMPLATES.zh-CN.md > "$stage/docs/OCI-TEMPLATES.zh-CN.md"
awk '/^## 开发与验收状态$/{exit} {print}' docs/OTLP.zh-CN.md > "$stage/docs/OTLP.zh-CN.md"
cp sdk/python/osv_sandbox_client.py "$stage/sdk/python/osv_sandbox_client.py"
cp sdk/node/README.md "$stage/docs/NODE-SDK.md"
cp sdk/node/index.js sdk/node/index.d.ts sdk/node/package.json "$stage/sdk/node/"
RELEASE_STAGE="$stage" python3 - <<'PY'
import os
from pathlib import Path
import re

stage = Path(os.environ['RELEASE_STAGE'])
pattern = re.compile(r'\[([^\]]+)\]\(([^)]+)\)')
for document in (stage / 'docs').glob('*.md'):
    def bundled_link(match):
        label, target = match.groups()
        if target.startswith(('https://', 'http://', '#')):
            return match.group()
        path = (document.parent / target.split('#', 1)[0]).resolve()
        if path.is_relative_to(stage.resolve()) and path.is_file():
            return match.group()
        return label
    document.write_text(pattern.sub(bundled_link, document.read_text()))
PY
sed 's|/usr/local/bin/osv-sandboxd|/opt/osv-sandbox/current/bin/osv-sandboxd|; s|/usr/share/doc/osv-sandbox/PRODUCTION.zh-CN.md|/opt/osv-sandbox/current/docs/PRODUCTION.zh-CN.md|' \
    deploy/systemd/osv-sandboxd-production.service > "$stage/systemd/osv-sandboxd.service"
sed 's|/usr/local/libexec/osv-sandbox-launcher|/opt/osv-sandbox/current/bin/osv-sandbox-launcher|; s|/usr/share/doc/osv-sandbox/PRODUCTION.zh-CN.md|/opt/osv-sandbox/current/docs/PRODUCTION.zh-CN.md|; s|/var/lib/osv-sandbox/artifacts|/opt/osv-sandbox/current/artifacts|; s|StateDirectory=osv-sandbox$|StateDirectory=osv-sandbox/run|' \
    deploy/systemd/osv-sandbox-launcher.service > "$stage/systemd/osv-sandbox-launcher.service"

loader=ld-linux-x86-64.so.2
template_boms=()
inference_args=()
if [[ "$inference" == 1 ]]; then inference_args+=(--inference); fi
if [[ "$osv_python" == 1 ]]; then
    osv_python_assets=${RELEASE_OSV_PYTHON_ASSETS:-$workspace/assets/osv-native/python-3.12-science/candidates/clock-sleep-r1}
    python3 scripts/stage-osv-catalog-template.py "${inference_args[@]}" --stage "$stage" --assets "$osv_python_assets" --private-key "$ARTIFACT_PRIVATE_KEY"
    template_boms+=(-template-bom "python-science=$stage/templates/python-science")
fi
if [[ "$linux_code" == 1 ]]; then
    linux_code_assets=${RELEASE_LINUX_CODE_ASSETS:?RELEASE_LINUX_CODE_ASSETS must select a project-owned code image matching the guest build}
    code_port_args=()
    if [[ "$port_forward" == 1 ]]; then code_port_args+=(--ports); fi
    if [[ "$workspace_artifacts" == 1 ]]; then code_port_args+=(--artifacts); fi
    python3 scripts/stage-linux-code-template.py "${code_port_args[@]}" "${inference_args[@]}" --stage "$stage" --assets "$linux_code_assets" \
        --architecture "$arch" --kernel "$KERNEL_IMAGE" --musl-assets "$MUSL_GUEST_ASSETS" \
        --bash-assets "$BASH_ASSETS" --private-key "$ARTIFACT_PRIVATE_KEY" --valid-for "${ARTIFACT_VALID_FOR:-8760h}"
    template_boms+=(-template-bom "linux-code=$stage/templates/linux-code")
fi
sed 's|/usr/local/bin/osv-sandbox-egress|/opt/osv-sandbox/current/bin/osv-sandbox-egress|; s|/usr/share/doc/osv-sandbox/EGRESS.zh-CN.md|/opt/osv-sandbox/current/docs/EGRESS.zh-CN.md|' \
    deploy/systemd/osv-sandbox-egress.service > "$stage/systemd/osv-sandbox-egress.service"
if [[ "$arch" == arm64 ]]; then loader=ld-linux-aarch64.so.1; fi
RELEASE_STAGE="$stage" RELEASE_LOADER="$loader" python3 - <<'PY'
import hashlib, json, os
from pathlib import Path

stage = Path(os.environ['RELEASE_STAGE'])
loader = os.environ['RELEASE_LOADER']
config = json.loads(Path('examples/config.production.json').read_text())
config['artifact_root'] = '/opt/osv-sandbox/current/artifacts'
config['hypervisor_path'] = '/opt/osv-sandbox/current/bin/firecracker'
config['jailer']['path'] = '/opt/osv-sandbox/current/bin/jailer'
config['linux_guest']['mkfs_path'] = '/opt/osv-sandbox/current/bin/mkfs.ext4'
config['linux_guest']['mkfs_loader_path'] = '/opt/osv-sandbox/current/lib/' + loader
config['linux_guest']['mkfs_library_path'] = '/opt/osv-sandbox/current/lib'
config['kernel'] = {'path': 'kernel', 'sha256': hashlib.sha256((stage/'artifacts/kernel').read_bytes()).hexdigest()}
config['image'] = {'path': 'rootfs.ext4', 'sha256': hashlib.sha256((stage/'artifacts/rootfs.ext4').read_bytes()).hexdigest(), 'format': 'raw'}
config['artifact_manifest']['path'] = 'manifest.json'
config['artifact_manifest']['signature_path'] = 'manifest.json.sig'
config['artifact_manifest']['sbom_path'] = 'sbom.cdx.json'
(stage/'config/config.production.json.template').write_text(json.dumps(config, indent=2) + '\n')
catalogs = sorted((stage/'templates').glob('*/template.json'))
if catalogs:
    config['templates'] = [json.loads(catalog.read_text()) for catalog in catalogs]
    (stage/'config/config.production.json.template').write_text(json.dumps(config, indent=2) + '\n')
PY

CGO_ENABLED=0 go run ./cmd/osv-sbom \
    "${template_boms[@]}" \
    "${guest_http[@]}" \
    -output "$stage/artifacts/sbom.cdx.json" \
    -kernel "$stage/artifacts/kernel" -rootfs "$stage/artifacts/rootfs.ext4" \
    -agent "$GUEST_AGENT_BIN" -api "$stage/bin/osv-sandboxd" \
    -workload-supervisor "$MUSL_GUEST_ASSETS/osv-workload-supervisor" \
    -api-go-licenses "$stage/docs/GO-MODULE-LICENSES.txt" \
    -launcher "$stage/bin/osv-sandbox-launcher" \
    -mcp "$stage/bin/osv-sandbox-mcp" \
    -egress "$stage/bin/osv-sandbox-egress" \
    -template-oci "$stage/bin/osv-template-oci" \
    -egress-roots "$stage/examples/egress-public-roots.crt" \
    -egress-roots-provenance "$stage/docs/egress-roots-source-lock.json" \
    -egress-roots-license "$stage/docs/egress-roots-LICENSE.txt" \
    -firecracker "$stage/bin/firecracker" -jailer "$stage/bin/jailer" \
    -client-sdk "$stage/sdk/python/osv_sandbox_client.py" \
    -client-node-js "$stage/sdk/node/index.js" \
    -client-node-types "$stage/sdk/node/index.d.ts" \
    -allocator-policy "$stage/docs/mimalloc-policy.json" \
    -allocator-archive "$MUSL_GUEST_ASSETS/build-libraries/libmimalloc.a" \
    -allocator-provenance "$stage/docs/musl-guest-build-provenance.json" \
    -bash "$BASH_ASSETS/bash" -bash-source-lock "$stage/docs/bash-source-lock.json"
rm -rf "$checkdir"
if [[ ${RELEASE_ALLOW_DIRTY_TEST:-0} != 1 && "$security_profile" == extended ]]; then
    python3 scripts/vulnerability_evidence.py replay --sbom "$stage/artifacts/sbom.cdx.json" \
        --snapshot "$RELEASE_SECURITY_SNAPSHOT" --snapshot-sha256 "$RELEASE_SECURITY_SNAPSHOT_SHA256" \
        --output "$stage/docs/vulnerability-report.json"
fi
python3 "$workspace/scripts/release_candidate_gate.py" build-info --epoch "$SOURCE_DATE_EPOCH" --output "$gate_plan_dir/build-after.json"
if ! cmp -s "$gate_plan_dir/build-before.json" "$gate_plan_dir/build-after.json"; then
    echo 'release source or compiler changed during the build' >&2
    exit 1
fi
RELEASE_STAGE="$stage" RELEASE_SECURITY_PROFILE="$security_profile" RELEASE_BUILD_INFO="$gate_plan_dir/build-before.json" python3 - <<'PY'
import json,os
from pathlib import Path
stage=Path(os.environ['RELEASE_STAGE'])
profile=os.environ['RELEASE_SECURITY_PROFILE']
(stage/'docs/security-profile.json').write_text(json.dumps({
    'protocol':'osv-release-security-profile/v1','profile':profile,
    'extended_scan_required':profile=='extended',
    'extended_scan_report_present':(stage/'docs/vulnerability-report.json').is_file(),
    'scope_adjustment':'User requested functional delivery first with baseline security on 2026-11-03',
    'release_build':json.loads(Path(os.environ['RELEASE_BUILD_INFO']).read_text())
},indent=2)+'\n')
PY
CGO_ENABLED=0 go run ./cmd/osv-artifact-manifest \
    "${guest_features[@]}" \
    -artifact-root "$stage/artifacts" -kernel kernel -image rootfs.ext4 \
    -firecracker "$stage/bin/firecracker" -jailer "$stage/bin/jailer" \
    -sbom sbom.cdx.json -private-key "$ARTIFACT_PRIVATE_KEY" \
    -output "$stage/artifacts/manifest.json" -valid-for "${ARTIFACT_VALID_FOR:-8760h}"
RELEASE_VALID_UNTIL="$valid_until" RELEASE_STAGE="$stage" python3 - <<'PY'
import datetime, json, os
from pathlib import Path

manifest = json.loads((Path(os.environ['RELEASE_STAGE'])/'artifacts/manifest.json').read_text())
release_expiry = datetime.datetime.fromisoformat(os.environ['RELEASE_VALID_UNTIL'].replace('Z', '+00:00'))
artifact_expiry = datetime.datetime.fromisoformat(manifest['expires_at'].replace('Z', '+00:00'))
if release_expiry > artifact_expiry:
    raise SystemExit('release expiry must not exceed signed artifact expiry')
PY
pack_reference=()
if [[ ${RELEASE_PUBLICATION:-0} == 1 || ${RELEASE_ALLOW_DIRTY_TEST:-0} != 1 ]]; then
    if [[ -z ${RELEASE_PRIVACY_POLICY:-} ]]; then echo 'public release requires a private publication policy' >&2; exit 2; fi
    python3 "$workspace/scripts/check-publication-privacy.py" --tree "$stage" \
        --private-policy "$RELEASE_PRIVACY_POLICY" --output "$gate_plan_dir/privacy-audit.json"
fi
if [[ ${RELEASE_ALLOW_DIRTY_TEST:-0} != 1 ]]; then
    python3 "$workspace/scripts/release_candidate_gate.py" compare --plan "$gate_plan_dir/plan.json" \
        --stage "$stage" --output "$gate_plan_dir/reference-manifest.json"
    pack_reference=(-reference-manifest "$gate_plan_dir/reference-manifest.json")
fi
CGO_ENABLED=0 go run ./cmd/osv-offline-release pack "${pack_reference[@]}" \
    -source "$stage" -archive "$output" -private-key "$RELEASE_PRIVATE_KEY" \
    -version "$version" -arch "$arch" -commit "$release_commit" \
    -valid-until "$valid_until"
echo "stage=$stage"
sha256sum "$output"
