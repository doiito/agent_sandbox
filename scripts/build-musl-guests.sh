#!/usr/bin/env bash
set -euo pipefail
workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
arch=${1:-$(uname -m)}
case "$arch" in
    x86_64|amd64) arch=amd64; rust_arch=x86_64 ;;
    aarch64|arm64) arch=arm64; rust_arch=aarch64 ;;
    *) echo 'musl guest target must be amd64 or arm64' >&2; exit 2 ;;
esac
target="$rust_arch-unknown-linux-musl"
target_dir=${CARGO_TARGET_DIR:-$workspace/build/musl-target}
output=${MUSL_GUEST_OUTPUT:-$workspace/assets/allocators/mimalloc/artifacts/linux-$arch}
work="$workspace/build/musl-provenance/$arch"
cd "$workspace"
export CC_ENABLE_DEBUG_OUTPUT=1
export RUSTC_WRAPPER="$workspace/scripts/privacy-rustc-wrapper.sh"
python3 - "$workspace" "$output" <<'PY'
from pathlib import Path
import sys
root, output = map(lambda p: Path(p).resolve(), sys.argv[1:])
if not output.is_relative_to(root) or output.exists():
    raise SystemExit('musl guest output must be a fresh directory within the project')
PY
python3 scripts/check-musl-allocator.py > /dev/null
mkdir -p "$work"
for package in guest linux-guest; do
    cargo build --manifest-path "$package/Cargo.toml" --locked --offline --features mimalloc \
        --release --target "$target" --target-dir "$target_dir" --message-format=json > "$work/$package.jsonl"
done
supervisor_map="$work/supervisor-link-map.txt"
if [[ "$arch" == amd64 ]]; then map_arg="-Wl,-Map=$supervisor_map"; else map_arg="-Map=$supervisor_map"; fi
cargo rustc --manifest-path linux-guest/Cargo.toml --locked --offline --features mimalloc \
    --release --target "$target" --target-dir "$target_dir" --bin osv-workload-supervisor \
    --message-format=json -- -C "link-arg=$map_arg" > "$work/supervisor.jsonl"
mkdir -p "$output/build-libraries" "$output/licenses"
cp "$target_dir/$target/release/agent-init" "$output/agent-init"
cp "$target_dir/$target/release/osv-agent-executor" "$output/osv-agent-executor"
cp "$target_dir/$target/release/osv-workload-supervisor" "$output/osv-workload-supervisor"
cp "$supervisor_map" "$output/supervisor-link-map.txt"
python3 - "$work/linux-guest.jsonl" "$output" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
events = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines()]
outputs = {event['out_dir'] for event in events if event.get('reason') == 'build-script-executed' and
           'libmimalloc-sys' in event.get('package_id', '')}
if len(outputs) != 1:
    raise SystemExit('ambiguous or missing mimalloc linker input')
archive = Path(outputs.pop()) / 'libmimalloc.a'
output = Path(sys.argv[2])
shutil.copyfile(archive, output / 'build-libraries/libmimalloc.a')
build_log = archive.parent.parent / 'output'
if not build_log.is_file():
    raise SystemExit('missing allocator compiler transcript')
# Preserve the complete raw transcript only in the private validation workspace.
# Public build provenance retains the actual flags with operator paths normalized.
shutil.copyfile(build_log, Path(sys.argv[1]).parent / 'compiler-transcript-private.txt')
text = build_log.read_text().replace(str(Path.cwd()), '<workspace>')
text = text.replace(str(Path.home()), '<build-home>')
text = text.replace(os.environ.get('CARGO_TARGET_DIR', str(Path.cwd()/'build/musl-target')), '<build-target>')
(output / 'compiler-transcript.txt').write_text(text)
PY
python3 - "$workspace" "$target" "$output" <<'PY'
import hashlib
import json
from pathlib import Path
import subprocess
import sys
root, target, output = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()
rust_sysroot = Path(subprocess.check_output(['rustc', '--print', 'sysroot'], text=True).strip())
libc = rust_sysroot / 'lib/rustlib' / target / 'lib/self-contained/libc.a'
compiler = root / ('scripts/musl-cc-aarch64.sh' if target.startswith('aarch64') else 'scripts/musl-cc-x86_64.sh')
compiler_date = subprocess.check_output([str(compiler), '-E', '-P', '-x', 'c', '-'],
                                       input='__DATE__ __TIME__\n', text=True).strip()
if compiler_date != '"Jan  1 1970" "00:00:00"':
    raise SystemExit('C compiler ignored the reproducible build date')
inputs = ['.cargo/config.toml', 'scripts/musl-cc.sh', 'scripts/check-musl-allocator.py',
          'scripts/privacy-rustc-wrapper.sh',
          'scripts/build-musl-guests.sh', 'runtime-allocator/Cargo.toml', 'runtime-allocator/Cargo.lock',
          'runtime-allocator/src/lib.rs', 'guest/Cargo.toml', 'guest/Cargo.lock', 'guest/src/main.rs',
          'linux-guest/Cargo.toml', 'linux-guest/Cargo.lock', 'linux-guest/src/main.rs', 'linux-guest/src/pristine.rs',
          'linux-guest/src/workspace_mutations.rs', 'linux-guest/src/streaming.rs', 'linux-guest/src/command_stdin.rs', 'linux-guest/src/job_stdin.rs']
# Keep every Rust module bound, including newly introduced guest features.
inputs = sorted(set(inputs) | {str(path.relative_to(root)) for crate in ('runtime-allocator','guest','linux-guest')
                             for path in (root/crate/'src').rglob('*.rs') if path.is_file()})
report = {'protocol': 'osv-musl-guest-build/v2', 'target': target,
          'allocator': 'mimalloc', 'c_version': 30302, 'secure_level': 4,
          'source_date_epoch': 0,
          'c_preprocessor_date': compiler_date,
          'rustc': subprocess.check_output(['rustc', '-vV'], text=True),
          'c_compiler': subprocess.check_output([str(compiler), '--version'], text=True),
          'rust_target_libc_sha256': sha(libc), 'libmimalloc_archive_sha256': sha(output/'build-libraries/libmimalloc.a'),
          'compiler_transcript_sha256': sha(output/'compiler-transcript.txt'),
          'source_sha256': {name: sha(root/name) for name in inputs},
          'components': {name: {'allocator': 'mimalloc', 'c_version': 30302, 'secure_level': 4,
                               'sha256': sha(output/name)} for name in ('agent-init','osv-agent-executor')}}
report['components']['osv-workload-supervisor'] = {'allocator': 'system',
    'sha256': sha(output/'osv-workload-supervisor'), 'link_map_sha256': sha(output/'supervisor-link-map.txt')}
(output/'build-provenance.json').write_text(json.dumps(report, indent=2)+'\n')
PY
cp assets/allocators/mimalloc/source-lock.json "$output/allocator-policy.json"
cp assets/build/cargo-vendor/mimalloc-0.1.52/LICENSE.txt "$output/licenses/mimalloc-rust.txt"
cp assets/build/cargo-vendor/libmimalloc-sys-0.1.49/LICENSE.txt "$output/licenses/mimalloc-sys.txt"
cp assets/build/cargo-vendor/libmimalloc-sys-0.1.49/c_src/mimalloc/v3/LICENSE "$output/licenses/mimalloc-c.txt"
python3 scripts/check-musl-allocator.py --architecture "$arch" \
    --binary "$output/agent-init" --binary "$output/osv-agent-executor" \
    --supervisor "$output/osv-workload-supervisor" --supervisor-link-map "$output/supervisor-link-map.txt" \
    --report "$output/build-check.json"
(
    cd "$output"
    sha256sum agent-init osv-agent-executor osv-workload-supervisor supervisor-link-map.txt \
        allocator-policy.json build-check.json build-provenance.json compiler-transcript.txt \
        build-libraries/libmimalloc.a licenses/* > SHA256SUMS
    sha256sum -c SHA256SUMS --quiet
)
python3 scripts/check-musl-allocator.py --architecture "$arch" --artifacts "$output" > /dev/null
echo "Static mimalloc guest assets: $output"
