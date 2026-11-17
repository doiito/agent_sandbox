FROM osv-sandbox-builder:ubuntu22.04
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       bison flex gawk genromfs rsync ccache libboost-all-dev libssl-dev \
       libncurses-dev libyaml-cpp-dev libedit-dev python3-pyelftools python3-requests \
       python3-pyparsing \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work/osv-upstream
