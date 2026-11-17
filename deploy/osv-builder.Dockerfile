FROM ubuntu:22.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential \
        git \
        make \
        python3 \
        qemu-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work/osv-upstream
