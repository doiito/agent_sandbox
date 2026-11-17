FROM osv-sandbox-musl-c-builder:ubuntu22.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    lld-14 llvm-14 && rm -rf /var/lib/apt/lists/*
ENV PATH=/usr/lib/llvm-14/bin:$PATH
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ripgrep && rm -rf /var/lib/apt/lists/*
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    gcc-aarch64-linux-gnu && rm -rf /var/lib/apt/lists/*
