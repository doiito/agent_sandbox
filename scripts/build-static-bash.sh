#!/usr/bin/env bash
set -euo pipefail
workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
case "${1:?amd64 or arm64}" in amd64) arch=x86_64; package_arch=amd64 ;; arm64) arch=aarch64; package_arch=arm64 ;; *) exit 2 ;; esac
output=${BASH_OUTPUT:-$workspace/assets/bash/artifacts/linux-$package_arch}
work=${BASH_BUILD_DIR:-$workspace/build/bash-$package_arch}
output=$(realpath -m "$output")
work=$(realpath -m "$work")
if [[ -e "$output" || -e "$work" ]]; then echo 'Bash build/output must be fresh' >&2; exit 2; fi
python3 - "$workspace" <<'PY'
import hashlib,json,sys
from pathlib import Path
r=Path(sys.argv[1]);lock=json.loads((r/'assets/bash/source-lock.json').read_text())
assert hashlib.sha256((r/'assets/bash/source/bash-5.3.tar.gz').read_bytes()).hexdigest()==lock['sha256']
PY
(cd "$workspace/assets/bash/toolchain/$arch" && sha256sum -c SHA256SUMS --quiet)
mkdir -p "$work" "$output"
export OSV_BASH_ARCH="$arch"
export SOURCE_DATE_EPOCH=0
cd "$work"
CC="$workspace/scripts/bash-musl-cc.sh" AR=llvm-ar RANLIB=llvm-ranlib \
    CFLAGS='-O2 -fno-pie' LDFLAGS='-no-pie' \
    bash "$workspace/assets/bash/source/bash-5.3/configure" \
      --build=x86_64-pc-linux-gnu --host="$arch-unknown-linux-musl" \
      --enable-static-link --disable-nls --disable-readline --without-bash-malloc > configure.log 2>&1
make -j4 > make.log 2>&1
cp bash "$output/bash"
cp "$workspace/assets/bash/source/bash-5.3/COPYING" "$output/LICENSE"
cp "$workspace/assets/bash/source-lock.json" "$output/source-lock.json"
cp config.h "$output/config.h"
python3 - "$workspace" "$output" "$arch" <<'PY'
from pathlib import Path
import hashlib,json,subprocess,sys
r,o,arch=Path(sys.argv[1]),Path(sys.argv[2]),sys.argv[3]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
headers=subprocess.check_output(['readelf','-h',str(o/'bash')],text=True)
assert ('AArch64' if arch=='aarch64' else 'Advanced Micro Devices X86-64') in headers
assert 'INTERP' not in subprocess.check_output(['readelf','-l',str(o/'bash')],text=True)
assert 'NEEDED' not in subprocess.check_output(['readelf','-d',str(o/'bash')],text=True)
report={'protocol':'osv-static-bash/v1','architecture':arch,'version':'5.3','allocator':'musl libc; not claimed mimalloc',
        'source_lock_sha256':sha(r/'assets/bash/source-lock.json'),'binary_sha256':sha(o/'bash'),
        'link_input_sha256':{p.name:sha(p) for p in (r/'assets/bash/toolchain'/arch/'lib').iterdir()},
        'compiler_script_sha256':sha(r/'scripts/bash-musl-cc.sh'),'build_script_sha256':sha(r/'scripts/build-static-bash.sh')}
(o/'build-provenance.json').write_text(json.dumps(report,indent=2)+'\n')
PY
sha256sum "$output/bash"
