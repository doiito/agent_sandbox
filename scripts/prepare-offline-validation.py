#!/usr/bin/env python3
"""Install a signed release in an isolated root-owned systemd fixture."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import grp
import pwd
import secrets
import shutil
import socket
import subprocess


def run(*args):
    subprocess.run([str(arg) for arg in args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def cpu_period_settings(period):
    if period is None:
        return {}
    if type(period) is not int or not 1000 <= period <= 1000000:
        raise ValueError('validation CPU period must be within [1000, 1000000] us')
    # Both fields must change together; period alone would change CPU share.
    return {'cpu_period_us': period, 'cpu_quota_per_vcpu_us': period}


def health_interval_settings(interval, warm_pool):
    if interval is None:
        return {}
    if not warm_pool or type(interval) is not int or not 100 <= interval <= 30000:
        raise ValueError('validation health interval requires warm pool and [100, 30000] ms')
    return {'health_interval_ms': interval}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--upload', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--isolate-network', action='store_true')
    parser.add_argument('--tenant-pair', action='store_true')
    parser.add_argument('--warm-pool', action='store_true')
    parser.add_argument('--egress-probe', action='store_true')
    parser.add_argument('--guest-proxy',action='store_true')
    parser.add_argument('--inference-probe', action='store_true', help='use actual v7 templates with private persistent inference state')
    parser.add_argument('--session-list-probe',action='store_true')
    parser.add_argument('--template-catalog-probe',action='store_true')
    parser.add_argument('--osv-default',action='store_true')
    parser.add_argument('--oci-import-probe', action='store_true', help='use installed CLI imports for both catalog templates and mask the original source in both services')
    parser.add_argument('--linux-code-probe', action='store_true',
                        help='use the installed v5 code image as the isolated fixture default')
    parser.add_argument('--linux-code-selected', action='store_true',
                        help='with --linux-code-probe, retain shell default and select the additional code template')
    parser.add_argument('--quota-probe', action='store_true')
    parser.add_argument('--port-preview', action='store_true', help='enable separate local preview TLS and loopback port policy for code-VM acceptance')
    parser.add_argument('--io-read-bps', type=int)
    parser.add_argument('--io-write-bps', type=int)
    parser.add_argument('--capacity-memory-mib', type=int)
    parser.add_argument('--cpu-period-us', type=int,
                        help='set equal period/quota, retaining one CPU per vCPU in this fixture')
    parser.add_argument('--health-interval-ms', type=int, help='override health interval before starting this diagnostic fixture')
    parser.add_argument('--cold-start-measurement', action='store_true',
                        help='reserve a different warm profile from the fixed performance workload')
    parser.add_argument('--allocator-reference', type=Path,
                        help='select an explicitly diagnostic, signed same-source allocator reference')
    args = parser.parse_args()
    if args.allocator_reference and (not args.warm_pool or not args.tenant_pair or not args.isolate_network or
            args.linux_code_probe or args.template_catalog_probe or args.cold_start_measurement or args.egress_probe or
            args.session_list_probe or args.quota_probe or args.cpu_period_us is not None or args.health_interval_ms is not None):
        parser.error('--allocator-reference requires the ordinary isolated Linux shell warm fixture')
    if args.cold_start_measurement and (not args.warm_pool or args.linux_code_probe or args.template_catalog_probe != args.osv_default):
        parser.error('--cold-start-measurement requires the shell or default OSv science pool')
    if args.template_catalog_probe and (not args.tenant_pair or args.session_list_probe or args.quota_probe):raise SystemExit('--template-catalog-probe requires the ordinary isolated tenant pair')
    if args.osv_default and not args.template_catalog_probe:raise SystemExit('--osv-default requires --template-catalog-probe')
    if args.oci_import_probe and not args.template_catalog_probe:
        raise SystemExit('--oci-import-probe requires the ordinary two-template catalog probe')
    if args.linux_code_selected and not args.linux_code_probe:
        raise SystemExit('--linux-code-selected requires --linux-code-probe')
    if args.linux_code_probe and (not args.tenant_pair or args.template_catalog_probe or args.osv_default or args.session_list_probe or args.quota_probe):
        raise SystemExit('--linux-code-probe requires the ordinary tenant pair without other catalog/lifecycle/quota probes')
    if args.guest_proxy and not args.egress_probe:raise SystemExit('--guest-proxy requires --egress-probe')
    if args.inference_probe and not (args.guest_proxy and (args.linux_code_probe or args.template_catalog_probe)):
        raise SystemExit('--inference-probe requires guest proxy and an explicit code or science template probe')
    cpu_settings = cpu_period_settings(args.cpu_period_us)
    health_settings = health_interval_settings(args.health_interval_ms, args.warm_pool)
    if args.port_preview and not (args.linux_code_probe and args.tenant_pair and args.isolate_network):
        raise SystemExit('--port-preview requires isolated network, tenant pair and linux-code-probe')
    if args.capacity_memory_mib is not None and not 1 <= args.capacity_memory_mib <= 1048576:
        raise SystemExit('validation capacity memory must be within [1, 1048576] MiB')
    if args.session_list_probe and (not args.tenant_pair or args.warm_pool or args.quota_probe):raise SystemExit("--session-list-probe requires the isolated tenant pair without warm/quota probes")
    if args.warm_pool and (not args.tenant_pair or args.capacity_memory_mib is not None):
        raise SystemExit('--warm-pool requires --tenant-pair and its default shared budget')
    if args.quota_probe and not args.tenant_pair:
        raise SystemExit('--quota-probe requires --tenant-pair')
    if args.egress_probe and (not args.tenant_pair or not args.isolate_network):raise SystemExit('--egress-probe requires isolated network and tenant pair')
    upload, root = args.upload.resolve(), args.root
    if args.io_read_bps is not None and not 0 < args.io_read_bps <= 104857600:
        raise SystemExit('validation IO read limit must be within (0, 100 MiB/s]')
    if args.io_write_bps is not None and not 0 < args.io_write_bps <= 52428800:
        raise SystemExit('validation IO write limit must be within (0, 50 MiB/s]')
    if os.geteuid() != 0 or root.exists() or not root.is_absolute():
        raise SystemExit('requires root and a new absolute fixture root')
    # Public traversal and group-readable TLS must survive a private job umask.
    # Private directories and credentials below still use explicit modes.
    os.umask(0o022)
    api = pwd.getpwnam('osv-sandbox')
    root.mkdir(mode=0o755)
    for name, mode in [('run', 0o700), ('audit', 0o700), ('socket', 0o711),
                       ('results', 0o700), ('secrets', 0o700), ('tls', 0o750)]:
        (root / name).mkdir(mode=mode)
    os.chown(root / 'tls', 0, api.pw_gid)
    package = args.package.resolve()
    if package.parent != upload:
        raise RuntimeError('validation package must be in the isolated upload directory')
    verifier = upload / 'osv-offline-release-linux-amd64'
    public_key = upload / 'TEST-ONLY-release.public.pem'
    completed = subprocess.run([str(verifier), 'install', '-archive', str(package),
                                '-public-key', str(public_key), '-root', str(root / 'releases')],
                               check=True, text=True, capture_output=True)
    release = Path(completed.stdout.strip())
    if not release.is_dir() or release.parent != root / 'releases':
        raise RuntimeError('installer did not return an isolated release directory')
    artifact_public = root / 'artifact.public'
    shutil.copyfile(upload / 'TEST-ONLY-artifact.public', artifact_public)
    artifact_public.chmod(0o644)

    tls = root / 'tls'
    run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=OSv offline validation CA', '-keyout', tls / 'ca.key', '-out', tls / 'ca.crt')
    identities = [('server', 'localhost', 'serverAuth'), ('client', 'validation-client', 'clientAuth')]
    if args.port_preview:
        identities.append(('preview', '*.preview.test', 'serverAuth'))
    for name, cn, purpose in identities:
        run('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=' + cn,
            '-keyout', tls / (name + '.key'), '-out', tls / (name + '.csr'))
        extension = tls / (name + '.ext')
        extension.write_text('extendedKeyUsage=' + purpose + '\n' +
                             ('subjectAltName=DNS:localhost,IP:127.0.0.1\n' if name == 'server' else
                              ('subjectAltName=DNS:*.preview.test\n' if name == 'preview' else '')))
        run('openssl', 'x509', '-req', '-days', '1', '-in', tls / (name + '.csr'),
            '-CA', tls / 'ca.crt', '-CAkey', tls / 'ca.key', '-CAcreateserial',
            '-extfile', extension, '-out', tls / (name + '.crt'))
        (tls / (name + '.key')).chmod(0o640 if name in ('server', 'preview') else 0o600)
        if name in ('server', 'preview'):
            os.chown(tls / (name + '.key'), 0, api.pw_gid)
    (tls / 'ca.key').unlink()

    token = secrets.token_hex(32)
    (root / 'secrets/token').write_text(token)
    (root / 'secrets/token').chmod(0o600)
    tenants = [{
        'id': 'validation-a' if args.tenant_pair else 'validation',
        'token_sha256': hashlib.sha256(token.encode()).hexdigest(),
        'allowed_entrypoints': ['/bin/sh','/bin/bash'], 'requests_per_second': 100,
        'burst': 100, 'max_concurrent': 1}]
    if args.tenant_pair:
        second_token = secrets.token_hex(32)
        (root / 'secrets/token-b').write_text(second_token)
        (root / 'secrets/token-b').chmod(0o600)
        tenants.append({'id': 'validation-b',
                        'token_sha256': hashlib.sha256(second_token.encode()).hexdigest(),
                        'allowed_entrypoints': ['/bin/sh','/bin/bash'], 'requests_per_second': 100,
                        'burst': 100, 'max_concurrent': 1})
    if args.quota_probe:
        tenants[0]['requests_per_second'] = 0.001
        tenants[0]['burst'] = 3
    if args.session_list_probe:tenants[0]['max_concurrent']=3
    if args.linux_code_probe:
        template = release / 'templates/linux-code'
        if not (template / 'template.json').is_file():raise SystemExit('code probe requires installed Linux code template')
        tenants[0]['allowed_entrypoints'] += ['/opt/python/bin/python3.12', '/opt/node/bin/node']
        tenants[1]['allowed_entrypoints'].append('/opt/python/bin/python3.12')
        tenants[1]['allowed_templates'] = [{'backend': 'firecracker-linux',
            'artifact_manifest_sha256': hashlib.sha256((template / 'artifacts/manifest.json').read_bytes()).hexdigest()}]
    if args.template_catalog_probe:
        template = release / 'templates/python-science'
        if not (template / 'template.json').is_file():raise SystemExit('catalog probe requires the packaged OSv science template')
        for tenant in tenants:
            tenant['allowed_entrypoints'].append('/python3.12.so')
            tenant['max_concurrent'] = 2
        tenants[1]['allowed_templates'] = [{'backend':'firecracker-osv','artifact_manifest_sha256':hashlib.sha256((template/'artifacts/manifest.json').read_bytes()).hexdigest()}]
    if args.egress_probe:
        tenants[0]['egress']={'allowed_origins':['https://localhost:44443','https://127.0.0.1:44443','https://localhost:44444'],'allowed_cidrs':['127.0.0.1/32','::1/128'],'max_concurrent':1,'max_request_bytes':4096,'max_response_bytes':4096,'timeout_ms':2000,'max_redirects':2}
        if args.guest_proxy:
            tenants[0]['egress']['allowed_origins'].append('http://localhost:44445')
            # Cancellation checks must complete well before this network deadline.
            tenants[0]['egress']['timeout_ms']=10000
    if args.port_preview:
        for tenant in tenants:
            tenant['ports'] = {'allowed_ports': [{'from': 8080, 'to': 8081}], 'max_concurrent': 8, 'preview': True}
    if args.inference_probe:
        state = root / 'egress-state'
        state.mkdir(mode=0o700)
        os.chown(state, api.pw_uid, api.pw_gid)
        credential = state / 'provider-credential'
        credential.write_text(secrets.token_hex(32))
        credential.chmod(0o600)
        os.chown(credential, api.pw_uid, api.pw_gid)
        tenants[0]['egress'].update(max_request_bytes=256 << 10, max_response_bytes=512 << 10)
        tenants[0]['inference'] = {
            'endpoints': [{'name': 'model', 'url': 'https://localhost:44443/infer',
                           'credential': {'file': str(credential), 'header': 'Authorization', 'prefix': 'Bearer '},
                           'price': {'request_units': '9007199254740993', 'input_byte_units': '2', 'output_byte_units': '3'}}],
            'max_invocations': 32, 'budget_units': '1000000000000000000'}
    policy = {'protocol': 'osv-sandbox-auth/v1', 'tenants': tenants}
    (root / 'auth.json').write_text(json.dumps(policy))
    (root / 'auth.json').chmod(0o640)
    os.chown(root / 'auth.json', 0, api.pw_gid)

    config = json.loads((release / 'config/config.production.json.template').read_text())
    if not args.linux_code_probe:
        # These historical regression fixtures select the original shell/science
        # catalog; code default/selection has its own independently named fixture.
        config['templates'] = [item for item in config.get('templates', []) if item['id'] != 'linux-code']
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    config.update(listen=f'127.0.0.1:{port}', artifact_root=str(release / 'artifacts'),
                  run_root=str(root / 'run'), launcher_socket=str(root / 'socket/launcher.sock'),
                  auth_policy_path=str(root / 'auth.json'), audit_log_path=str(root / 'audit/audit.jsonl'))
    if args.port_preview:
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            preview_port = probe.getsockname()[1]
        config['preview'] = {'listen': f'127.0.0.1:{preview_port}',
            'origin_base': f'https://preview.test:{preview_port}', 'api_origin': f'https://localhost:{port}',
            'cert_file': str(tls / 'preview.crt'), 'key_file': str(tls / 'preview.key')}
    config['hypervisor_path'] = str(release / 'bin/firecracker')
    config['jailer'].update(path=str(release / 'bin/jailer'), uid=230000, gid=230000,
                            identity_pool_size=4 if args.session_list_probe else (3 if args.warm_pool else (2 if args.tenant_pair else 1)),
                            parent_cgroup=root.name)
    if args.io_read_bps is not None:
        config['jailer']['io_read_bps'] = args.io_read_bps
    if args.io_write_bps is not None:
        config['jailer']['io_write_bps'] = args.io_write_bps
    config['jailer'].update(cpu_settings)
    for offset in range(config['jailer']['identity_pool_size']):
        for lookup, value in ((pwd.getpwuid, 230000 + offset), (grp.getgrgid, 230000 + offset)):
            try:
                lookup(value)
            except KeyError:
                pass
            else:
                raise RuntimeError(f'validation jail identity already assigned: {value}')
    config['linux_guest'].update(scratch_mib=32,
                                 mkfs_path=str(release / 'bin/mkfs.ext4'),
                                 mkfs_loader_path=str(release / 'lib/ld-linux-x86-64.so.2'),
                                 mkfs_library_path=str(release / 'lib'))
    config['artifact_manifest']['public_key_path'] = str(artifact_public)
    for template in config.get('templates', []):
        directory = release / 'templates' / template['id']
        if not (directory / 'template.json').is_file():raise SystemExit('catalog template payload is missing')
        template['artifact_root'] = str(directory / 'artifacts')
        template['artifact_manifest']['public_key_path'] = str(artifact_public)
    config['tls'] = {'cert_file': str(tls / 'server.crt'),
                     'key_file': str(tls / 'server.key'),
                     'client_ca_file': str(tls / 'ca.crt')}
    if args.session_list_probe:config['session_max_lifetime_ms']=60000
    config['limits']['max_concurrent'] = 4 if args.session_list_probe else (2 if args.tenant_pair else 1)
    instances = 3 if args.warm_pool else config['limits']['max_concurrent']
    config['vm_capacity'] = {
        'max_instances': instances,
        'reserved_memory_mib': args.capacity_memory_mib or instances * (
            config['limits']['max_memory_mib'] + config['jailer']['memory_overhead_mib']),
        'reserved_vcpus': instances * config['limits']['max_vcpus'],
        'reserved_pids': instances * config['jailer']['pids_max'],
    }
    if args.warm_pool:
        config['warm_pool'] = {
            'enabled': True, 'on_miss': 'cold', 'max_booting': 2,
            'refill_per_second': 4, 'refill_burst': 2,
            'max_idle_age_ms': 120000, 'health_interval_ms': 1000,
            'check_timeout_ms': 1000, 'boot_timeout_ms': 10000,
            'checkout_timeout_ms': 10000, 'startup_timeout_ms': 30000,
            'min_available_memory_mib': 128,
            'profiles': [
                {'name': 'small', 'memory_mib': 128, 'vcpus': 1, 'min_ready': 1, 'max_ready': 2},
                {'name': 'large', 'memory_mib': 256, 'vcpus': 1, 'min_ready': 1, 'max_ready': 1},
            ],
        }
        config['warm_pool'].update(health_settings)
        if args.template_catalog_probe:
            config['warm_pool']['profiles'] = [{'name':'small','memory_mib':128,'vcpus':1,'min_ready':1,'max_ready':1}]
            for template in config['templates']:
                template['warm_profiles'] = [{'name':'science','memory_mib':512,'vcpus':1,'min_ready':1,'max_ready':1}]
    config['allowed_entrypoints'] = ['/bin/sh','/bin/bash']
    if args.linux_code_probe and args.linux_code_selected and args.warm_pool:
        code = next(item for item in config['templates'] if item['id'] == 'linux-code')
        config['warm_pool']['profiles'] = [{'name': 'shell', 'memory_mib': 128, 'vcpus': 1, 'min_ready': 1, 'max_ready': 1}]
        code['warm_profiles'] = [{'name': 'code', 'memory_mib': 1024, 'vcpus': 1, 'min_ready': 1, 'max_ready': 1}]
        config['warm_pool'].update(boot_timeout_ms=30000, startup_timeout_ms=60000, checkout_timeout_ms=30000)
    if args.linux_code_probe and not args.linux_code_selected:
        code = next(item for item in config['templates'] if item['id'] == 'linux-code')
        shell = {'id': 'shell', **{key: config[key] for key in ['backend', 'artifact_root', 'kernel', 'image',
                 'artifact_manifest', 'allowed_entrypoints', 'linux_guest', 'defaults']}}
        if args.warm_pool:
            shell['warm_profiles'] = [{'name': 'shell', 'memory_mib': 128, 'vcpus': 1, 'min_ready': 1, 'max_ready': 1}]
            config['warm_pool']['profiles'] = [{'name': 'code', 'memory_mib': 1024, 'vcpus': 1, 'min_ready': 1, 'max_ready': 1}]
            config['warm_pool'].update(boot_timeout_ms=30000, startup_timeout_ms=60000, checkout_timeout_ms=30000)
        for key in ['backend', 'artifact_root', 'kernel', 'image', 'artifact_manifest', 'allowed_entrypoints', 'defaults']:
            config[key] = code[key]
        config['template_id'] = 'linux-code'
        config['templates'] = [shell]
    if args.osv_default:
        science = next(item for item in config['templates'] if item['id']=='python-science')
        linux = {'id':'linux',**{key:config[key] for key in ['backend','artifact_root','kernel','image','artifact_manifest','allowed_entrypoints','linux_guest','defaults']}}
        if args.warm_pool:
            linux['warm_profiles'] = config['warm_pool']['profiles']
            config['warm_pool']['profiles'] = science['warm_profiles']
        for key in ['backend','artifact_root','kernel','image','artifact_manifest','allowed_entrypoints','defaults']:
            config[key] = science[key]
        config.pop('linux_guest',None)
        config['template_id'] = 'python-science'
        config['templates'] = [linux]
    if args.cold_start_measurement:
        measured_profile, replacement_memory = ('science', 640) if args.osv_default else ('small', 192)
        profile, = (p for p in config['warm_pool']['profiles'] if p['name'] == measured_profile)
        profile['memory_mib'] = replacement_memory
    if args.egress_probe:config['egress_socket']=str(root/'egress-runtime/e.sock')
    imported_sources = []
    if args.oci_import_probe:
        from oci_template_fixture import prepare as prepare_imports
        config, imported = prepare_imports(release, root, config, artifact_public)
        imported_sources = [row['source'] for row in imported['profiles']]
    if args.allocator_reference:
        from allocator_comparison_fixture import prepare as prepare_reference
        prepare_reference(args.allocator_reference, root, config)
    config_path = root / 'config.production.json'
    config_path.write_text(json.dumps(config, indent=2) + '\n')
    config_path.chmod(0o640)
    os.chown(config_path, 0, api.pw_gid)
    (root / 'launcher.env').write_text(f'SANDBOX_API_UID={api.pw_uid}\nSANDBOX_API_GID={api.pw_gid}\n')
    (root / 'launcher.env').chmod(0o640)

    units = [root.name + '-launcher.service', root.name + '-api.service']
    for source, name in [('osv-sandbox-launcher.service', units[0]),
                         ('osv-sandboxd.service', units[1])]:
        content = (release / 'systemd' / source).read_text()
        for old, new in [('/opt/osv-sandbox/current', str(release)),
                         ('/etc/osv-sandbox', str(root)),
                         ('/var/lib/osv-sandbox/run', str(root / 'run')),
                         ('/var/log/osv-sandbox', str(root / 'audit')),
                         ('/run/osv-sandbox', str(root / 'socket')),
                         ('osv-sandbox-launcher.service', units[0]),
                         ('osv-sandboxd.service', units[1])]:
            content = content.replace(old, new)
        content = '\n'.join(line for line in content.splitlines()
                            if not line.startswith(('RuntimeDirectory=', 'StateDirectory=',
                                                    'LogsDirectory=', 'WantedBy='))) + '\n'
        content = content.replace('Restart=on-failure', 'Restart=no')
        content = content.replace('[Service]', '[Service]\nRuntimeMaxSec=1800')
        if imported_sources:
            if any(any(ch.isspace() for ch in path) or '%' in path for path in imported_sources):
                raise ValueError('validation InaccessiblePaths requires simple absolute source paths')
            content = content.replace('[Service]', '[Service]\nInaccessiblePaths=' + ' '.join(imported_sources))
        if args.isolate_network:
            content = content.replace('[Service]', '[Service]\nPrivateNetwork=yes')
        target = Path('/run/systemd/system') / name
        if target.exists():
            raise RuntimeError(f'unit already exists: {target}')
        target.write_text(content)
    shutil.copyfile(upload / 'e2e-api.py', root / 'e2e-api.py')
    if args.egress_probe:
        subprocess.run(['python3',str(upload/'prepare-egress-fixture.py'),'--root',str(root),'--upload',str(upload),'--release',str(release)]+(['--guest-proxy'] if args.guest_proxy else [])+(['--inference'] if args.inference_probe else []),check=True)
    run('systemctl', 'daemon-reload')
    subprocess.run(['systemctl', 'start', units[1]], check=True)
    with package.open('rb') as stream:
        package_sha256 = hashlib.file_digest(stream, 'sha256').hexdigest()
    print(json.dumps({'root': str(root), 'release': str(release), 'units': units,
                      'package_sha256': package_sha256, 'port': port,
                      'isolated_network': args.isolate_network}))


if __name__ == '__main__':
    main()
