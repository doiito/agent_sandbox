ARG BASE_IMAGE=debian@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
FROM ${BASE_IMAGE}

# Build tools only; the signed guest receives the explicitly resolved runtime
# closure, never this image or a dependency on Docker/apt at installation.
RUN dpkg --add-architecture arm64 \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       build-essential gcc-aarch64-linux-gnu g++-aarch64-linux-gnu \
       libc6-dev-arm64-cross pkg-config ca-certificates xz-utils \
       libssl-dev libssl-dev:arm64 libffi-dev libffi-dev:arm64 \
       zlib1g-dev zlib1g-dev:arm64 libbz2-dev libbz2-dev:arm64 \
       liblzma-dev liblzma-dev:arm64 libsqlite3-dev libsqlite3-dev:arm64 \
       libreadline-dev libreadline-dev:arm64 libgdbm-dev libgdbm-dev:arm64 \
       uuid-dev uuid-dev:arm64 libstdc++6:arm64 python3 \
    && rm -rf /var/lib/apt/lists/*
ENV SOURCE_DATE_EPOCH=0
WORKDIR /work
