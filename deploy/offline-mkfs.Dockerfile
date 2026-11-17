FROM debian:bookworm-slim AS builder
ARG DEBIAN_ARCH
RUN test "$DEBIAN_ARCH" = amd64 -o "$DEBIAN_ARCH" = arm64 \
    && dpkg --add-architecture "$DEBIAN_ARCH" \
    && apt-get update \
    && mkdir -p /packages /rootfs /out/bin /out/lib \
    && cd /packages \
    && apt-get download "e2fsprogs:$DEBIAN_ARCH" "libext2fs2:$DEBIAN_ARCH" \
       "libcom-err2:$DEBIAN_ARCH" "libblkid1:$DEBIAN_ARCH" \
       "libuuid1:$DEBIAN_ARCH" "libc6:$DEBIAN_ARCH" \
    && for package in *.deb; do dpkg-deb -x "$package" /rootfs; done \
    && cp -L /rootfs/sbin/mkfs.ext4 /out/bin/mkfs.ext4 \
    && if [ "$DEBIAN_ARCH" = arm64 ]; then loader=ld-linux-aarch64.so.1; else loader=ld-linux-x86-64.so.2; fi \
    && for library in "$loader" libext2fs.so.2 libcom_err.so.2 libblkid.so.1 \
       libuuid.so.1 libe2p.so.2 libc.so.6; do \
         source=$(find /rootfs/lib /rootfs/usr/lib -name "$library" -print -quit); \
         test -n "$source" && cp -L "$source" "/out/lib/$library"; \
       done \
    && chmod 0555 /out/bin/mkfs.ext4 /out/lib/*

FROM scratch
COPY --from=builder /out /
