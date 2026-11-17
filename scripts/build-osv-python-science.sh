#!/usr/bin/env bash
set -euo pipefail

workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
image=${OSV_PYTHON_BUILDER_IMAGE:-osv-sandbox-python-science-builder:ubuntu22.04}
asset_relative=${OSV_PYTHON_ASSET_RELATIVE:-assets/osv-native/python-3.12-science/linux-amd64}
if [[ ! "$asset_relative" =~ ^assets/osv-native/python-3\.12-science/(linux-amd64|candidates/[a-z0-9][a-z0-9-]{0,79})$ ]]; then
    echo 'invalid OSV_PYTHON_ASSET_RELATIVE' >&2
    exit 2
fi
asset="$workspace/$asset_relative"
source_dir="$workspace/assets/osv-native/python-3.12-science/sources"
work_relative=build/python-3.12-science
if [[ "$asset_relative" != assets/osv-native/python-3.12-science/linux-amd64 ]]; then
    work_relative="build/python-3.12-science-${asset_relative##*/}"
fi
work="$workspace/$work_relative"
jobs=${OSV_NATIVE_JOBS:-4}
inference_sdk=${OSV_PYTHON_INFERENCE_SDK:-0}
if [[ "$inference_sdk" != 0 && "$inference_sdk" != 1 ]]; then
    echo 'OSV_PYTHON_INFERENCE_SDK must be 0 or 1' >&2
    exit 2
fi
if [[ ! "$jobs" =~ ^[1-9][0-9]*$ ]] || (( jobs > 16 )); then
    echo 'OSV_NATIVE_JOBS must be between 1 and 16' >&2
    exit 2
fi
cd "$workspace"
python3 scripts/fetch-python-science.py

if [[ "${1:-}" == --inside-runtime-build ]]; then
    if [[ -e "$asset/rootfs" ]]; then
        echo 'Python runtime build requires a fresh asset/rootfs directory' >&2
        exit 2
    fi
    mkdir -p "$work/source" "$work/obj" "$asset/rootfs"
    export SOURCE_DATE_EPOCH=0
    tar -xf "$source_dir/Python-3.12.16.tar.xz" -C "$work/source" --strip-components=1
    cd "$work/obj"
    "$work/source/configure" --prefix=/opt/python --enable-shared \
        --without-ensurepip --with-system-ffi
    make "-j$jobs"
    make "-j$jobs" install "COMPILEALL_OPTS=-j$jobs" DESTDIR="$asset/rootfs"
    cc -std=c11 -D_POSIX_C_SOURCE=200809L -O2 -Wall -Wextra -Werror -fPIC -shared \
        -I"$asset/rootfs/opt/python/include/python3.12" \
        -L"$asset/rootfs/opt/python/lib" -Wl,-rpath,/opt/python/lib \
        -o "$asset/rootfs/python3.12.so" "$workspace/osv-native/apps/python-science/main.c" -lpython3.12
    cc -std=c11 -O2 -Wall -Wextra -Werror -o "$work/module-entry" \
        "$workspace/tests/python-science-module-entry.c" -ldl
    cd "$workspace"
    # Retain source licenses, exclude only build files, tests and caches.
    cp "$work/source/LICENSE" "$asset/rootfs/opt/python/LICENSE"
    python3 - "$asset/rootfs" <<'PY'
from pathlib import Path
import shutil
import sys
root = Path(sys.argv[1])
excluded = {'test', 'tests', '__pycache__', 'idlelib', 'ensurepip', 'pkgconfig'}
for path in sorted(root.rglob('*'), reverse=True):
    if path.is_dir() and not path.is_symlink() and (path.name in excluded or path.name.startswith('config-') or path == root / 'opt/python/include'):
        shutil.rmtree(path)
    elif path.is_file() and path.suffix in ('.a', '.pyc', '.pyo'):
        path.unlink()
PY
    python3 scripts/python_science_provenance.py --capture-cpython --rootfs "$asset/rootfs" \
        --output "$asset/cpython-install-inventory.json"
    python3 scripts/python_science_closure.py wheels "$asset/rootfs"
    if [[ "$inference_sdk" == 1 ]]; then
        python3 - "$asset" <<'PY'
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path.cwd()/'scripts'))
import guest_inference_image
asset=Path(sys.argv[1])
profile=guest_inference_image.install(asset/'rootfs','firecracker-osv','amd64')
(asset/'guest-inference.json').write_text(json.dumps(profile,indent=2)+'\n')
PY
    fi
    python3 - "$asset/rootfs/build-provenance.json" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
inputs = ['scripts/build-osv-python-science.sh', 'scripts/python_science_closure.py',
          'scripts/fetch-python-science.py', 'osv-native/apps/python-science/main.c',
          'osv-native/templates/python-3.12-science/lock.json', 'deploy/osv-python-science-builder.Dockerfile',
          'tests/python-science-module-entry.c', 'scripts/reference-python-science.py',
          'scripts/python_science_provenance.py', 'scripts/python_science_runtime_facts.py',
          'scripts/prepare-python-science-bytecode.py', 'scripts/verify-python-science-bytecode.py']
if os.environ.get('OSV_PYTHON_INFERENCE_SDK') == '1':
    sys.path.insert(0,str(Path.cwd()/'scripts'))
    import guest_inference_image
    inputs=sorted(set(inputs)|set(guest_inference_image.input_names('firecracker-osv')))
document = {'protocol': 'osv-python-science-build/v1', 'builder_image_id': os.environ['OSV_PYTHON_BUILDER_ID'],
            'source_date_epoch': 0,
            'compiler': subprocess.check_output(['cc', '--version'], text=True),
            'packages': subprocess.check_output(['dpkg-query', '-W', '-f', '${binary:Package}=${Version}\n'], text=True).splitlines(),
            'inputs_sha256': {name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in inputs}}
Path(sys.argv[1]).write_text(json.dumps(document, indent=2) + '\n')
PY
    python3 scripts/python_science_closure.py resolve "$asset/rootfs"
    PYTHONHOME="$asset/rootfs/opt/python" LD_LIBRARY_PATH="$asset/rootfs/opt/python/lib" \
        "$asset/rootfs/opt/python/bin/python3.12" -B scripts/python_science_runtime_facts.py \
        --rootfs "$asset/rootfs" --output "$asset/rootfs/runtime-version-facts.json"
    python3 scripts/python_science_provenance.py --rootfs "$asset/rootfs" \
        --builder-image-id "$OSV_PYTHON_BUILDER_ID" --cpython-origins "$asset/cpython-install-inventory.json"
    python3 scripts/python_science_closure.py seal "$asset/rootfs" --output "$asset/runtime-inventory.json"
    PYTHONHOME="$asset/rootfs/opt/python" LD_LIBRARY_PATH="$asset/rootfs/opt/python/lib" \
        "$asset/rootfs/opt/python/bin/python3.12" -B scripts/prepare-python-science-bytecode.py \
        --source "$asset/rootfs" --asset "$asset" --in-place
    python3 scripts/python_science_closure.py verify "$asset/rootfs" --output "$asset/runtime-inventory.json"
    # Reference execution on Linux verifies the compiled versions and closure;
    # this is a build check, never OSv acceptance.
    PYTHONHOME="$asset/rootfs/opt/python" LD_LIBRARY_PATH="$asset/rootfs/opt/python/lib" \
        OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 \
        "$asset/rootfs/opt/python/bin/python3.12" -B -c \
        'import sys, numpy, pandas, _ctypes, _ssl, _hashlib, _bz2, _lzma, _sqlite3; assert sys.version_info[:3] == (3,12,16); assert numpy.__version__ == "2.5.4"; assert pandas.__version__ == "3.1.0"; print("LINUX_BUILD_REFERENCE_ONLY",sys.version,numpy.__version__,pandas.__version__)'
    exit 0
fi
if [[ "$#" != 0 ]]; then
    echo 'usage: build-osv-python-science.sh' >&2
    exit 2
fi
builder_id=$(docker image inspect "$image" --format '{{.Id}}')
docker run --rm --network none -e "OSV_PYTHON_BUILDER_ID=$builder_id" -e "OSV_NATIVE_JOBS=$jobs" \
    -e "OSV_PYTHON_ASSET_RELATIVE=$asset_relative" -e "OSV_PYTHON_INFERENCE_SDK=$inference_sdk" -e SOURCE_DATE_EPOCH=0 \
    -v "$workspace:/work" -w /work "$image" bash scripts/build-osv-python-science.sh --inside-runtime-build
docker run --rm --network none -v "$workspace:/work" \
    -v "$asset/rootfs/opt/python:/opt/python:ro" -w /work "$image" \
    python3 scripts/reference-python-science.py --entry "/work/$work_relative/module-entry" \
    --module "/work/$asset_relative/rootfs/python3.12.so"
docker run --rm --network none -v "$workspace:/work" \
    -v "$asset/rootfs/opt/python:/opt/python:ro" -w /work "$image" \
    env PYTHONHOME=/opt/python LD_LIBRARY_PATH=/opt/python/lib OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 \
    /opt/python/bin/python3.12 -B scripts/reference-python-science-bytecode.py \
    --scratch "/work/$work_relative" --rootfs "/work/$asset_relative/rootfs"

bash scripts/build-osv-native-kernel.sh
docker run --rm --network none -e "OSV_PYTHON_ASSET_RELATIVE=$asset_relative" -e OSV_JOB_AGENT_DIAGNOSTIC_IMAGE=0 \
    -v "$workspace:/work" -w /work/osv-upstream \
    "$image" ./scripts/build "-j$jobs" fs=rofs image=python-science fs_size_mb=384 \
    conf_dot_file=/work/osv-native/conf/agent-sandbox.config \
    bootfs_manifest=../osv-native/conf/agent-sandbox-bootfs.manifest
release="$workspace/osv-upstream/build/release.x64"
qemu-img convert -f qcow2 -O raw "$release/usr.img" "$asset/rootfs.raw"
test "$(stat -c %s "$asset/rootfs.raw")" -eq 402653184
python3 scripts/python_science_sbom.py --rootfs "$asset/rootfs" --inventory "$asset/runtime-inventory.json" \
    --image "$asset/rootfs.raw" --output "$asset/runtime-sbom-input.json"
mkdir -p "$asset/modules"
cp "$release/loader-stripped.elf" "$asset/kernel.elf"
cp "$workspace/osv-upstream/apps/job-agent/osv-job-agent.so" "$asset/modules/osv-job-agent.so"
cp "$asset/rootfs/python3.12.so" "$asset/modules/python3.12.so"
python3 - "$asset" "$builder_id" <<'PY'
import hashlib,json
from pathlib import Path
import subprocess,sys
asset=Path(sys.argv[1])
def sha(path):
    with path.open('rb') as source:return hashlib.file_digest(source,'sha256').hexdigest()
record={'protocol':'osv-python-science-image/v1','builder_image_id':sys.argv[2],
        'osv_upstream_commit':subprocess.check_output(['git','-C','osv-upstream','rev-parse','HEAD'],text=True).strip(),
        'inputs_sha256':{name:sha(Path(name)) for name in ['scripts/build-osv-python-science.sh','scripts/python_science_sbom.py','scripts/rofs_inventory.py']},
        'files_sha256':{name:sha(asset/name) for name in ['kernel.elf','rootfs.raw','runtime-inventory.json','runtime-sbom-input.json','modules/osv-job-agent.so','modules/python3.12.so']},
        'runtime_build_provenance_sha256':sha(asset/'rootfs/build-provenance.json'),
        'performance_acceptance':False,'real_KVM_acceptance':False,'minimal_64MiB_acceptance':False}
if (asset/'guest-inference.json').exists():record['guest_inference_sha256']=sha(asset/'guest-inference.json')
(asset/'image-build-provenance.json').write_text(json.dumps(record,indent=2)+'\n')
PY
inference_files=()
if [[ "$inference_sdk" == 1 ]]; then inference_files+=(guest-inference.json); fi
(
    cd "$asset"
    sha256sum kernel.elf rootfs.raw runtime-inventory.json runtime-sbom-input.json cpython-install-inventory.json pre-bytecode-inventory.json \
        modules/osv-job-agent.so modules/python3.12.so image-build-provenance.json "${inference_files[@]}" > SHA256SUMS
    sha256sum -c SHA256SUMS --quiet
)
echo "OSv Python science compatibility candidate: $asset"
