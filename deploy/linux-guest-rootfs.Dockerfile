ARG TARGETARCH
# Legacy image recipe. Signed proxy-v3 releases use
# scripts/build-firecracker-linux-rootfs.sh, including the static TLS client.
FROM --platform=linux/${TARGETARCH} debian:12-slim AS builder
ARG TARGETARCH

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       busybox-static e2fsprogs ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /rootfs/bin /rootfs/sbin /rootfs/usr/bin /rootfs/usr/local/bin \
        /rootfs/etc /rootfs/proc /rootfs/sys /rootfs/dev /rootfs/run \
        /rootfs/tmp /rootfs/workspace /rootfs/input /out \
    && cp /bin/busybox /rootfs/bin/busybox \
    && for applet in sh ash echo printf true false sleep cat ls id uname env pwd \
         mkdir touch rm cp mv dd head tail yes wc grep sed awk find xargs sync poweroff wget nc chmod; do \
         ln -s busybox "/rootfs/bin/$applet"; \
       done \
    && chmod 1777 /rootfs/tmp \
    && chmod 0755 /rootfs/workspace

COPY linux-guest/rootfs/etc/passwd /rootfs/etc/passwd
COPY linux-guest/rootfs/etc/group /rootfs/etc/group
COPY linux-guest/agent-init /rootfs/sbin/agent-init
COPY linux-guest/osv-workload-supervisor /rootfs/sbin/osv-workload-supervisor
COPY assets/trust/mozilla-2026-10-20/cacert.pem /rootfs/etc/ssl/certs/ca-certificates.crt

RUN chmod 0755 /rootfs/sbin/agent-init /rootfs/sbin/osv-workload-supervisor \
    && truncate -s 64M /out/linux-agent-rootfs.ext4 \
    && mkfs.ext4 -q -F -O '^has_journal' -L agent-rootfs -d /rootfs /out/linux-agent-rootfs.ext4 \
    && e2fsck -fn /out/linux-agent-rootfs.ext4

FROM scratch
COPY --from=builder /out/linux-agent-rootfs.ext4 /
