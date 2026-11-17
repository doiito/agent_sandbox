FROM osv-sandbox-native-builder:ubuntu22.04

# Compiler only: binaries statically link Rust's musl libc and mimalloc.
# Ubuntu's Clang build includes the AArch64 backend as well as x86_64.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    clang-14 && rm -rf /var/lib/apt/lists/*
