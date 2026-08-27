FROM debian:12-slim AS builder

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       busybox-static e2fsprogs ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /rootfs/bin /rootfs/sbin /rootfs/usr/bin /rootfs/usr/local/bin \
        /rootfs/etc /rootfs/proc /rootfs/sys /rootfs/dev /rootfs/run \
        /rootfs/tmp /rootfs/workspace /rootfs/input /out \
    && cp /bin/busybox /rootfs/bin/busybox \
    && for applet in sh ash echo printf true false sleep cat ls id uname env pwd \
         mkdir touch rm cp mv dd head tail yes wc grep sed awk find xargs sync poweroff; do \
         ln -s busybox "/rootfs/bin/$applet"; \
       done \
    && chmod 1777 /rootfs/tmp \
    && chmod 0755 /rootfs/workspace

COPY linux-guest/rootfs/etc/passwd /rootfs/etc/passwd
COPY linux-guest/rootfs/etc/group /rootfs/etc/group
COPY linux-guest/target/x86_64-unknown-linux-musl/release/agent-init /rootfs/sbin/agent-init

RUN chmod 0755 /rootfs/sbin/agent-init \
    && truncate -s 64M /out/linux-agent-rootfs.ext4 \
    && mkfs.ext4 -q -F -O '^has_journal' -L agent-rootfs -d /rootfs /out/linux-agent-rootfs.ext4 \
    && e2fsck -fn /out/linux-agent-rootfs.ext4

FROM scratch
COPY --from=builder /out/linux-agent-rootfs.ext4 /
