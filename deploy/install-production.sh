#!/usr/bin/env bash
set -euo pipefail

workspace_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [[ ${EUID} -ne 0 ]]; then
    echo "install-production.sh must run as root" >&2
    exit 1
fi
for binary in osv-sandbox-launcher osv-sandboxd; do
    if [[ ! -x "$workspace_dir/build/$binary" ]]; then
        echo "missing build/$binary; run the documented Go builds first" >&2
        exit 1
    fi
done
if ! getent passwd osv-sandbox >/dev/null; then
    useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin osv-sandbox
fi
api_uid=$(id -u osv-sandbox)
api_gid=$(id -g osv-sandbox)
install -d -m 0750 -o root -g osv-sandbox /etc/osv-sandbox
install -d -m 0750 -o root -g root /var/lib/osv-sandbox/artifacts
install -d -m 0700 -o root -g root /var/lib/osv-sandbox/run /var/log/osv-sandbox
install -d -m 0755 -o root -g root /usr/local/libexec /usr/local/bin
install -m 0755 "$workspace_dir/build/osv-sandbox-launcher" /usr/local/libexec/osv-sandbox-launcher
install -m 0755 "$workspace_dir/build/osv-sandboxd" /usr/local/bin/osv-sandboxd
install -m 0644 "$workspace_dir/deploy/systemd/osv-sandbox-launcher.service" /etc/systemd/system/osv-sandbox-launcher.service
install -m 0644 "$workspace_dir/deploy/systemd/osv-sandboxd-production.service" /etc/systemd/system/osv-sandboxd.service
install -d -m 0755 /usr/lib/tmpfiles.d
install -m 0644 "$workspace_dir/deploy/tmpfiles/osv-sandbox.conf" /usr/lib/tmpfiles.d/osv-sandbox.conf
install -d -m 0755 /usr/share/doc/osv-sandbox
install -m 0644 "$workspace_dir/docs/PRODUCTION.zh-CN.md" /usr/share/doc/osv-sandbox/PRODUCTION.zh-CN.md
printf 'SANDBOX_API_UID=%s\nSANDBOX_API_GID=%s\n' "$api_uid" "$api_gid" > /etc/osv-sandbox/launcher.env
chmod 0640 /etc/osv-sandbox/launcher.env
systemd-tmpfiles --create /usr/lib/tmpfiles.d/osv-sandbox.conf
systemctl daemon-reload
echo "Installed production binaries and units; provision signed artifacts, auth policy and mTLS files before enabling services."
