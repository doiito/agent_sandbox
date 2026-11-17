# Offline GNU Bash runtime

`source-lock.json` pins GNU Bash 5.3 and the upstream archive digest. The complete
source is stored under `source/`, and the release carries its source archive and
license. `artifacts/linux-{amd64,arm64}` contains the actual statically linked
shell, configuration and build provenance. No shared library, package manager or
download is required on the target host.

Build on this project host:

```sh
BASH_BUILD_DIR=/tmp/fresh-bash-amd64 scripts/build-static-bash.sh amd64
docker build -f deploy/bash-musl-builder.Dockerfile -t osv-sandbox-bash-musl-builder:ubuntu22.04 build/validation/bash-bootstrap
```

For ARM64, run the same script with `arm64` inside that local image, mount the
project at its existing absolute path and a fresh build directory, and set
`OSV_MUSL_CLANG=clang-14`. The C wrapper uses the project musl headers/CRT/libc and
the architecture's stored C `libgcc` libraries. Their hashes are recorded in the
build provenance; the ARM compiler package version is separately retained in the
toolchain directory. Build tools may be installed on the build machine; offline
rebuilding from source was not requested.

The shell preserves Bash language features, arrays and process substitution.
This non-PTY runtime omits readline and translated diagnostics. It uses musl's
C allocator; it does not claim Bash uses mimalloc. The Rust guest/executor still
use the separately locked mimalloc build. Performance claims require actual
workload measurements.

Run `python3 scripts/check-static-bash.py --architecture amd64` (or `arm64`) before
packing. The rootfs and release scripts compare `/bin/bash` to this selected
binary, and the SBOM records the actual Bash binary and source identity.
