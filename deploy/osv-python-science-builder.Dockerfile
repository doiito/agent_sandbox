FROM osv-sandbox-native-builder:ubuntu22.04

# Build dependencies only. The final ROFS carries its own resolved runtime libs.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    libbz2-dev libffi-dev libgdbm-dev liblzma-dev libreadline-dev libsqlite3-dev uuid-dev \
    && rm -rf /var/lib/apt/lists/*
