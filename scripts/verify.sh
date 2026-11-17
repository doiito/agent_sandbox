#!/usr/bin/env bash
set -euo pipefail

workspace_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$workspace_dir"
export GOCACHE=${GOCACHE:-/tmp/osv-sandbox-go-cache}
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/tmp/osv-sandbox-cargo-target}
mode=${1:-ci}
if [[ "$mode" != quick && "$mode" != ci ]]; then
    echo 'usage: scripts/verify.sh [quick|ci]' >&2
    exit 2
fi

bash -n scripts/*.sh deploy/*.sh
python3 -c 'import json,glob; [json.load(open(path)) for path in glob.glob("examples/*.json")]'

unformatted=$(gofmt -l api/control cmd internal tests/osv-preproduction tests/otlp-probe)
if [[ -n "$unformatted" ]]; then
    printf 'Go files need formatting:\n%s\n' "$unformatted" >&2
    exit 1
fi
python3 scripts/check-docs.py
go run ./cmd/osv-api-contract --check
python3 -B scripts/check-api-contract.py
python3 -B -m unittest discover -s tests -p 'test_api_contract.py'
python3 -B scripts/check-grpc-contract.py
python3 -B -m unittest discover -s tests -p 'test_grpc_contract.py'
python3 scripts/check-e2b-matrix.py
python3 scripts/check-startup-gates.py
python3 scripts/check-musl-allocator.py > /dev/null
python3 -m unittest discover -s tests -p 'test_startup_benchmark.py'
python3 -B -m unittest discover -s tests -p 'test_startup_gates.py'
python3 -B -m unittest discover -s tests -p 'test_validation_job.py'
python3 -B -m unittest discover -s tests -p 'test_egress_fixture_readiness.py'
python3 -B -m unittest discover -s tests -p 'test_oci_template_fixture.py'
python3 -B -m unittest discover -s tests -p 'test_allocator_comparison_fixture.py'
python3 -m unittest discover -s tests -p 'test_linux_vsock_timing.py'
python3 -m unittest discover -s tests -p 'test_startup_trace.py'
python3 -m unittest discover -s tests -p 'test_cgroup_membership_probe.py'
python3 -m unittest discover -s tests -p 'test_python_science_closure.py'
python3 -m unittest discover -s tests -p 'test_linux_code_runtime_closure.py'
python3 -m unittest discover -s tests -p 'test_code_kernel_interrupt.py'
python3 -m unittest discover -s tests -p 'test_code_kernel_idle.py'
python3 -m unittest discover -s tests -p 'test_runtime_provenance.py'
python3 -m unittest discover -s tests -p 'test_rofs_inventory.py'
python3 -B -m unittest discover -s tests -p 'test_osv_input_profile.py'
python3 -m unittest discover -s tests -p 'test_sbom_schema.py'
python3 -m unittest discover -s tests -p 'test_vulnerability_evidence.py'
python3 -m unittest discover -s tests -p 'test_release_security_gate.py'
python3 -B -m unittest discover -s tests -p 'test_release_candidate_gate.py'
python3 -B -m unittest discover -s tests -p 'test_publication_privacy.py'
python3 -m unittest discover -s tests -p 'test_osv_pipe_probe.py'
python3 -m unittest discover -s tests -p 'test_osv_science_result.py'
python3 -m unittest discover -s sdk/python -p 'test_*.py'
python3 scripts/test-node-sdk.py
python3 scripts/build-guest-inference-sdk.py --check
python3 -m unittest discover -s tests -p 'test_guest_inference.py'
python3 -m unittest discover -s tests -p 'test_guest_inference_image.py'
node --test tests/test_guest_inference_node.cjs
bash scripts/test-release-provenance.sh
bash scripts/test-osv-sbom.sh
bash scripts/test-osv-pristine-protocol.sh
bash scripts/test-osv-pipe-stat-metadata.sh
bash scripts/test-osv-clock-sleep.sh
bash scripts/test-osv-task-exit.sh
bash scripts/test-osv-rofs-bounded-read.sh
go test -timeout=120s ./cmd/... ./internal/... ./tests/osv-preproduction ./tests/otlp-probe
python3 scripts/test-mcp-stdio.py
python3 scripts/test-egress-process.py
cargo test --manifest-path guest/Cargo.toml --locked
cargo test --manifest-path linux-guest/Cargo.toml --locked
if [[ "$mode" == quick ]]; then
    exit 0
fi
go vet ./cmd/... ./internal/... ./tests/osv-preproduction ./tests/otlp-probe
CGO_ENABLED=1 go test -race -timeout=120s ./internal/... ./cmd/osv-sandboxd
cargo clippy --manifest-path guest/Cargo.toml --locked --all-targets -- -D warnings
cargo clippy --manifest-path linux-guest/Cargo.toml --locked --all-targets -- -D warnings
CGO_ENABLED=0 go build -buildvcs=false -trimpath ./cmd/...
cargo build --manifest-path guest/Cargo.toml --locked --release --target x86_64-unknown-linux-musl
cargo build --manifest-path linux-guest/Cargo.toml --locked --release --target x86_64-unknown-linux-musl
supervisor_map="$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/supervisor-ci-link-map.txt"
cargo rustc --manifest-path linux-guest/Cargo.toml --locked --offline --release \
    --bin osv-workload-supervisor --target x86_64-unknown-linux-musl -- -C "link-arg=-Wl,-Map=$supervisor_map"
cargo test --manifest-path runtime-allocator/Cargo.toml --locked --offline --target x86_64-unknown-linux-musl
cargo test --manifest-path linux-guest/Cargo.toml --locked --offline --target x86_64-unknown-linux-musl
cargo clippy --manifest-path runtime-allocator/Cargo.toml --locked --offline --all-targets --target x86_64-unknown-linux-musl -- -D warnings
python3 scripts/check-musl-allocator.py --architecture amd64 \
    --binary "$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/agent-init" \
    --binary "$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/osv-agent-executor" \
    --supervisor "$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/osv-workload-supervisor" \
    --supervisor-link-map "$supervisor_map" > /dev/null
python3 - "$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/osv-workload-supervisor" <<'PY'
import subprocess,sys
for arguments in ([], ['--unknown'], ['--workload-supervisor'], ['--workload-supervisor','extra']):
    value=subprocess.run([sys.argv[1], *arguments], capture_output=True, timeout=3)
    assert value.returncode==2 and not value.stdout and not value.stderr, 'supervisor private entry accepted'
PY
"$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/osv-agent-executor" \
    --sandbox-job-id 0123456789abcdef01234567 echo 'hello world' 'a;b'
