#!/usr/bin/env bash
set -euo pipefail

workspace_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$workspace_dir"
export GOCACHE=${GOCACHE:-/tmp/osv-sandbox-go-cache}
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/tmp/osv-sandbox-cargo-target}
export CGO_ENABLED=0

bash -n scripts/*.sh deploy/*.sh
python3 -c 'import json,glob; [json.load(open(path)) for path in glob.glob("examples/*.json")]'

gofmt -w cmd internal
go test ./cmd/... ./internal/...
go vet ./cmd/... ./internal/...
go test -run '^$' -bench BenchmarkBuildQEMUArgs -benchmem ./internal/sandbox
go build -buildvcs=false -trimpath -o /tmp/osv-sandboxd ./cmd/osv-sandboxd
go build -buildvcs=false -trimpath -o /tmp/osv-sandbox-launcher ./cmd/osv-sandbox-launcher
go build -buildvcs=false -trimpath -o /tmp/osv-artifact-manifest ./cmd/osv-artifact-manifest
go build -buildvcs=false -trimpath -o /tmp/osv-sbom ./cmd/osv-sbom
cargo test --manifest-path guest/Cargo.toml --locked
cargo build --manifest-path guest/Cargo.toml --locked --release --target x86_64-unknown-linux-musl
"$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/osv-agent-executor" \
    --sandbox-job-id 0123456789abcdef01234567 echo 'hello world' 'a;b'
cargo test --manifest-path linux-guest/Cargo.toml --locked
cargo clippy --manifest-path linux-guest/Cargo.toml --locked --all-targets -- -D warnings
cargo build --manifest-path linux-guest/Cargo.toml --locked --release --target x86_64-unknown-linux-musl
