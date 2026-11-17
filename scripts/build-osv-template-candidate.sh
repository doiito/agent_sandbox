#!/usr/bin/env bash
set -euo pipefail

workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
profile=${OSV_TEMPLATE_TEST_PROFILE:-native}
rofs_cache=${OSV_TEMPLATE_TEST_ROFS_CACHE:-}
if [[ -n "$rofs_cache" && "$rofs_cache" != disabled ]]; then
    echo 'OSV_TEMPLATE_TEST_ROFS_CACHE must be empty or disabled' >&2
    exit 2
fi
case "$profile" in
    native)
        if [[ -n "${OSV_TEMPLATE_TEST_ASSET_RELATIVE:-}" ]]; then
            echo 'custom runtime asset path is only supported for the Python science profile' >&2
            exit 2
        fi
        asset="$workspace/assets/osv-native/linux-amd64"
        module=task-probe.so
        ;;
    python-3.12-science)
        asset_relative=${OSV_TEMPLATE_TEST_ASSET_RELATIVE:-assets/osv-native/python-3.12-science/linux-amd64}
        if [[ ! "$asset_relative" =~ ^assets/osv-native/python-3\.12-science/(linux-amd64|candidates/[a-z0-9][a-z0-9-]{0,79})$ ]]; then
            echo 'invalid OSV_TEMPLATE_TEST_ASSET_RELATIVE' >&2
            exit 2
        fi
        asset="$workspace/$asset_relative"
        module=python3.12.so
        python3 "$workspace/scripts/python_science_closure.py" verify "$asset/rootfs" \
            --output "$asset/runtime-inventory.json"
        if [[ ! -f "$asset/runtime-sbom-input.json" ]]; then
            echo 'Python science template requires the runtime component SBOM from the current build pipeline' >&2
            exit 2
        fi
        ;;
    *) echo 'unsupported OSV_TEMPLATE_TEST_PROFILE' >&2; exit 2 ;;
esac
vmm="$workspace/assets/offline/linux-amd64"
output=${OSV_TEMPLATE_TEST_OUTPUT:-$workspace/dist/osv-native-template-r1-linux-amd64-test}
private=${OSV_TEMPLATE_TEST_PRIVATE_KEY:-}
public=${OSV_TEMPLATE_TEST_PUBLIC_KEY:-}
commit=0e34e4dc2b278b7f64e4169abbf297b7de46fb6b
if [[ -z "$private" || -z "$public" || ! -f "$private" || ! -f "$public" ]]; then
    echo 'OSV_TEMPLATE_TEST_PRIVATE_KEY and OSV_TEMPLATE_TEST_PUBLIC_KEY are required' >&2
    exit 2
fi
if [[ "$output" != "$workspace"/dist/*-test || -e "$output" ]]; then
    echo 'test candidate output must be a new *-test directory under project dist/' >&2
    exit 2
fi
(cd "$asset" && sha256sum -c SHA256SUMS --quiet)
(cd "$vmm" && sha256sum -c SHA256SUMS --quiet)
mkdir -p "$output/bin" "$output/artifacts"
cp "$asset/kernel.elf" "$output/artifacts/kernel.elf"
cp "$asset/rootfs.raw" "$output/artifacts/rootfs.raw"
cp "$asset/modules/osv-job-agent.so" "$output/artifacts/osv-job-agent.so"
cp "$asset/modules/$module" "$output/artifacts/$module"
if [[ "$profile" == python-3.12-science ]]; then
    cp "$asset/runtime-inventory.json" "$output/artifacts/runtime-inventory.json"
fi
cp "$vmm/bin/firecracker" "$vmm/bin/jailer" "$output/bin/"
export GOCACHE=${GOCACHE:-/tmp/osv-sandbox-go-cache}
cd "$workspace"
for name in osv-sandboxd osv-sandbox-launcher; do
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath \
        -o "$output/bin/$name" "./cmd/$name"
done
runtime_sbom=()
if [[ "$profile" == python-3.12-science ]]; then
    runtime_sbom=(-runtime-components "$asset/runtime-sbom-input.json" -runtime-inventory "$asset/runtime-inventory.json")
fi
go run ./cmd/osv-sbom -profile osv -osv-upstream-commit "$commit" "${runtime_sbom[@]}" \
    -kernel "$output/artifacts/kernel.elf" -rootfs "$output/artifacts/rootfs.raw" \
    -agent "$output/artifacts/osv-job-agent.so" -module "/$module=$output/artifacts/$module" \
    -api "$output/bin/osv-sandboxd" -launcher "$output/bin/osv-sandbox-launcher" \
    -firecracker "$output/bin/firecracker" -jailer "$output/bin/jailer" \
    -output "$output/artifacts/sbom.cdx.json"
go run ./cmd/osv-artifact-manifest -backend firecracker-osv \
    -osv-upstream-commit "$commit" -osv-rofs-cache "$rofs_cache" -entrypoint "/$module" \
    -agent-feature environment -agent-feature pristine-v1 -agent-feature stdin \
    -artifact-root "$output/artifacts" -kernel kernel.elf -image rootfs.raw \
    -firecracker "$output/bin/firecracker" -jailer "$output/bin/jailer" \
    -sbom sbom.cdx.json -private-key "$private" \
    -output "$output/artifacts/manifest.test.json" -valid-for 720h
cp "$public" "$output/artifact-test.public"
echo "OSv test-signed template candidate: $output"
sha256sum "$output/artifacts/manifest.test.json" "$output/artifacts/manifest.test.json.sig" \
    "$output/artifacts/sbom.cdx.json"
