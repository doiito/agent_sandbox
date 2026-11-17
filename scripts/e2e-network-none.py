#!/usr/bin/env python3
"""Real installed release/KVM proof of the current network=none boundary."""

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import ssl
import subprocess
import sys
import time
from urllib import error, request


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def tasks(path):
    return sorted(item.name for item in path.glob('job-*'))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--host-ip', required=True)
    parser.add_argument('--neighbor-ip', required=True)
    parser.add_argument('--in-netns', action='store_true')
    args = parser.parse_args()
    root = args.root.resolve()
    require(root.name.startswith('osv-offline-validation-20261030-') and
            root.parent == Path('/var/lib'), 'requires isolated validation fixture')
    host_ip = str(ipaddress.IPv4Address(args.host_ip))
    neighbor_ip = str(ipaddress.IPv4Address(args.neighbor_ip))
    require(host_ip != neighbor_ip and host_ip != '169.254.169.254',
            'isolation targets must differ')
    if not args.in_netns:
        unit = root.name + '-api.service'
        shown = subprocess.run(['systemctl', 'show', '-p', 'MainPID', '--value', unit],
                               check=True, capture_output=True, text=True)
        pid = int(shown.stdout.strip())
        require(pid > 1, 'API fixture is not active')
        subprocess.run(['nsenter', '-t', str(pid), '-n', sys.executable, __file__,
                        '--root', str(root), '--package', str(args.package),
                        '--host-ip', host_ip, '--neighbor-ip', neighbor_ip,
                        '--in-netns'], check=True)
        return

    releases = [path for path in (root / 'releases').iterdir() if path.is_dir()]
    require(len(releases) == 1, 'fixture must have exactly one installed release')
    sdk_dir = releases[0] / 'sdk/python'
    sys.path.insert(0, str(sdk_dir))
    import osv_sandbox_client as sdk  # pylint: disable=import-outside-toplevel
    require(Path(sdk.__file__).resolve() == (sdk_dir / 'osv_sandbox_client.py').resolve(),
            'client was not imported from installed release')
    config = json.loads((root / 'config.production.json').read_text())
    require(config['run_root'] == str(root / 'run'), 'fixture run root mismatch')
    cgroup = Path('/sys/fs/cgroup') / root.name
    require(not tasks(root / 'run') and not tasks(cgroup), 'fixture has prior tasks')
    port = config['listen'].rsplit(':', 1)[1]
    url = 'https://localhost:' + port
    token = (root / 'secrets/token').read_text()
    ca_file, cert_file, key_file = (root / 'tls/ca.crt', root / 'tls/client.crt',
                                    root / 'tls/client.key')
    client = sdk.Client(url, token=token, ca_file=str(ca_file),
                        cert_file=str(cert_file), key_file=str(key_file),
                        request_timeout_seconds=50)
    caps = client.capabilities()
    require(caps['backend'] == 'firecracker-linux' and
            caps['artifact_authenticated'] is True and
            caps['features']['network_egress'] is False,
            'network-none capability contract missing')
    doctor = client.doctor()
    require(doctor['ready'] is False, 'fixture unexpectedly production ready')

    script = ("set -eu; "
              "/bin/busybox nc --help 2>&1 | /bin/busybox grep -q 'Usage: nc'; "
              "printf 'ifaces:'; /bin/busybox ls /sys/class/net; "
              "echo 'route4:'; /bin/busybox ip -4 route show; "
              "echo 'route6:'; /bin/busybox ip -6 route show; ")
    for label, address in [('metadata', '169.254.169.254'),
                           ('host', host_ip), ('neighbor', neighbor_ip)]:
        script += (f'if /bin/busybox timeout 3 /bin/busybox nc -w 2 {address} 80 '
                   f'</dev/null >/dev/null 2>&1; then echo {label}:reachable; '
                   f'else echo {label}:blocked; fi; ')
    result = client.run(sdk.JobRequest('/bin/sh', args=('-c', script), timeout_ms=20000))
    require(result.succeeded and result.guest_result is not None,
            'network probe guest did not succeed')
    lines = result.guest_result.get('stdout', '').splitlines()
    require(set(lines) == {'ifaces:lo', 'route4:', 'route6:',
                           'metadata:blocked', 'host:blocked', 'neighbor:blocked'},
            'guest interfaces/routes/connectivity mismatch: ' + repr(lines))
    require(not tasks(root / 'run') and not tasks(cgroup),
            'network probe left a task resource')

    tls = ssl.create_default_context(cafile=str(ca_file))
    tls.minimum_version = ssl.TLSVersion.TLSv1_3
    tls.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
    opener = request.build_opener(request.ProxyHandler({}), request.HTTPSHandler(context=tls))
    rejected = {}
    for network in ('proxy', 'all'):
        body = {'entrypoint': '/bin/sh', 'args': ['-c', 'echo must-not-run'],
                'network': network, 'backend': caps['backend'],
                'artifact_manifest_sha256': caps['artifact_manifest_sha256']}
        req = request.Request(url + '/v2/jobs', data=json.dumps(body).encode(),
                              headers={'Authorization': 'Bearer ' + token,
                                       'Content-Type': 'application/json'},
                              method='POST')
        try:
            with opener.open(req, timeout=10):
                raise RuntimeError('unsupported network mode was accepted')
        except error.HTTPError as response:
            data = json.load(response)
            require(response.code == 400 and data.get('code') == 'invalid_request',
                    'network rejection status/code mismatch')
            rejected[network] = {'status': response.code, 'code': data['code']}
        require(not tasks(root / 'run') and not tasks(cgroup),
                'rejected network mode created a task resource')

    def digest(path):
        with path.open('rb') as stream:
            return hashlib.file_digest(stream, 'sha256').hexdigest()

    report = {'suite': 'network-none-kvm/v1',
              'generated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
              'package_sha256': digest(args.package),
              'test_script_sha256': digest(Path(__file__)),
              'installed_sdk_sha256': digest(sdk_dir / 'osv_sandbox_client.py'),
              'backend': caps['backend'], 'manifest_sha256': caps['artifact_manifest_sha256'],
              'network_egress_advertised': caps['features']['network_egress'],
              'doctor_ready': doctor['ready'],
              'targets': {'metadata': '169.254.169.254', 'host': host_ip,
                          'neighbor': neighbor_ip},
              'job': {'id': result.id, 'state': result.state,
                      'protocol_ok': result.protocol_ok, 'guest_lines': lines},
              'rejected_modes': rejected, 'remaining_workdirs': tasks(root / 'run'),
              'remaining_cgroups': tasks(cgroup), 'passed': True}
    (root / 'results/network-none.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': True, 'guest_lines': lines,
                      'rejected_modes': rejected}), flush=True)


if __name__ == '__main__':
    main()
