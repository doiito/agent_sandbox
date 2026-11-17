#!/usr/bin/env python3
"""Run one isolated Firecracker vsock transport fixture on the validation host."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import errno
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import struct
import subprocess
import threading
import time

ROOT = Path('/var/lib/osv-native-vsock-validation-20261029')
JAIL_ID = 'osv-vsock-20261029'
UID = GID = 220200


def sha(path):
    with path.open('rb') as stream:
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def receive_exact(peer, size):
    data = bytearray()
    while len(data) < size:
        block = peer.recv(size - len(data))
        if not block:
            raise RuntimeError(f'vsock EOF after {len(data)}/{size} bytes')
        data.extend(block)
    return bytes(data)


def receive_line(peer):
    data = bytearray()
    while len(data) < 100:
        byte = receive_exact(peer, 1)
        data.extend(byte)
        if byte == b'\n':
            return bytes(data)
    raise RuntimeError('oversized vsock negotiation reply')


def guest_connection(path, port=5000):
    peer = socket.socket(socket.AF_UNIX)
    peer.settimeout(35)
    peer.connect(str(path))
    peer.sendall(f'CONNECT {port}\n'.encode())
    reply = receive_line(peer)
    if not reply.startswith(b'OK '):
        peer.close()
        raise RuntimeError(f'CONNECT {port} failed: {reply!r}')
    return peer


def run(upload):
    if os.geteuid() != 0 or ROOT.exists():
        raise RuntimeError('run as root with a fresh, isolated fixture path')
    try:
        pwd.getpwuid(UID)
    except KeyError:
        pass
    else:
        raise RuntimeError('reserved fixture UID is already allocated')
    kernel = upload / 'loader-stripped.elf'
    image = upload / 'osv-native-vsock.raw'
    if not kernel.is_file() or not image.is_file() or image.stat().st_size != 64 * 1024 * 1024:
        raise RuntimeError('missing or unexpected validation artifacts')
    result = {'kernel_sha256': sha(kernel), 'image_sha256': sha(image), 'checks': []}
    jailroot = ROOT / 'jailer' / 'firecracker' / JAIL_ID / 'root'
    jailroot.mkdir(parents=True, mode=0o755)
    os.chown(jailroot, UID, GID)
    for source, target in [(kernel, jailroot / 'kernel'), (image, jailroot / 'rootfs')]:
        shutil.copyfile(source, target)
        target.chmod(0o444)
    config = {
        'boot-source': {'kernel_image_path': '/kernel',
                        'boot_args': '--nopci --console=serial --rootfs=rofs /vsock-test.so'},
        'drives': [{'drive_id': 'rootfs', 'path_on_host': '/rootfs',
                    'is_root_device': True, 'is_read_only': True}],
        'machine-config': {'vcpu_count': 1, 'mem_size_mib': 128,
                           'smt': False, 'track_dirty_pages': False},
        'vsock': {'guest_cid': 3, 'uds_path': '/agent.vsock'},
    }
    (jailroot / 'config.json').write_text(json.dumps(config))
    (jailroot / 'config.json').chmod(0o444)
    backing = jailroot / 'agent.vsock'
    host_listener = socket.socket(socket.AF_UNIX)
    host_listener.settimeout(45)
    host_listener.bind(str(backing) + '_6000')
    os.chmod(str(backing) + '_6000', 0o666)
    host_listener.listen(1)
    parallel_listener = socket.socket(socket.AF_UNIX)
    parallel_listener.settimeout(45)
    parallel_listener.bind(str(backing) + '_6001')
    os.chmod(str(backing) + '_6001', 0o666)
    parallel_listener.listen(8)
    proc = None
    serial = []
    ready = threading.Event()
    done = threading.Event()
    host_eof = threading.Event()
    host_accepted = threading.Event()
    host_error = []

    def read_serial():
        for line in proc.stdout:
            serial.append(line)
            if 'VSOCK_READY' in line:
                ready.set()
            if 'VSOCK_DONE' in line:
                done.set()
            if 'VSOCK_HOST_EOF_OK' in line:
                host_eof.set()

    def host_peer():
        try:
            peer, _ = host_listener.accept()
            host_accepted.set()
            with peer:
                peer.settimeout(35)
                if receive_exact(peer, 5) != b'guest':
                    raise RuntimeError('guest-initiated payload mismatch')
                peer.sendall(b'host')
        except Exception as exc:
            host_error.append(str(exc))

    parallel_gate = threading.Barrier(8)

    def parallel_host_peer():
        peer, _ = parallel_listener.accept()
        with peer:
            peer.settimeout(35)
            index = receive_exact(peer, 1)[0]
            if index >= 8:
                raise RuntimeError(f'parallel flow index out of range: {index}')
            parallel_gate.wait(timeout=20)
            peer.sendall(b'G')
            for chunk in range(16):
                expected = bytes((index * 17 + chunk * 13 + offset) & 0xff
                                 for offset in range(4096))
                if receive_exact(peer, 4096) != expected:
                    raise RuntimeError(f'parallel flow data mismatch: {index}, {chunk}')
            peer.sendall(bytes([index]))
            return index

    try:
        args = ['/usr/local/bin/jailer', '--id', JAIL_ID,
                '--exec-file', '/usr/local/bin/firecracker',
                '--uid', str(UID), '--gid', str(GID),
                '--chroot-base-dir', str(ROOT / 'jailer'),
                '--cgroup-version', '2',
                '--parent-cgroup', 'osv-native-validation-20261029',
                '--cgroup', 'memory.max=268435456',
                '--cgroup', 'memory.swap.max=0',
                '--cgroup', 'memory.oom.group=1',
                '--cgroup', 'cpu.max=100000 100000',
                '--cgroup', 'pids.max=64',
                '--resource-limit', 'no-file=1024',
                '--resource-limit', 'fsize=268435456',
                '--', '--no-api', '--config-file', '/config.json']
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
        threading.Thread(target=read_serial, daemon=True).start()
        threading.Thread(target=host_peer, daemon=True).start()
        if not ready.wait(35):
            raise RuntimeError(f'guest did not become ready; exit={proc.poll()}')
        status = Path(f'/proc/{proc.pid}/status').read_text()
        cgroup = Path(f'/proc/{proc.pid}/cgroup').read_text().strip()
        result['process'] = {'pid': proc.pid, 'uid': next(x for x in status.splitlines() if x.startswith('Uid:')),
                             'seccomp': next(x for x in status.splitlines() if x.startswith('Seccomp:')),
                             'cap_eff': next(x for x in status.splitlines() if x.startswith('CapEff:')),
                             'cgroup': cgroup}
        if not result['process']['uid'].split()[1:] == [str(UID)] * 4:
            raise RuntimeError('jailer UID mismatch')
        if result['process']['seccomp'].split()[1] != '2' or \
           int(result['process']['cap_eff'].split()[1], 16) != 0:
            raise RuntimeError('jailer sandbox controls missing')
        group = Path('/sys/fs/cgroup') / cgroup.split('::', 1)[1].lstrip('/')
        limits = {name: (group / name).read_text().strip()
                  for name in ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')}
        if limits != {'memory.max': '268435456', 'memory.swap.max': '0',
                      'cpu.max': '100000 100000', 'pids.max': '64'}:
            raise RuntimeError(f'jailer cgroup limits mismatch: {limits}')
        result['process']['limits'] = limits
        result['checks'].append('nonroot-jailer-seccomp-capabilities')

        with socket.socket(socket.AF_UNIX) as missing:
            missing.settimeout(5)
            missing.connect(str(backing))
            missing.sendall(b'CONNECT 5001\n')
            if missing.recv(1) != b'':
                raise RuntimeError('closed guest port did not reject connection')
        result['checks'].append('closed-port-rejection')

        for size in (0, 17, 262144, 1048576):
            payload = bytes((i * 37 + 19) & 0xff for i in range(size))
            with guest_connection(backing) as peer:
                peer.sendall(b'\x01' + struct.pack('<I', size) + payload)
                returned = struct.unpack('<I', receive_exact(peer, 4))[0]
                echoed = receive_exact(peer, returned)
                if returned != size or echoed != payload:
                    raise RuntimeError(f'echo mismatch at {size} bytes')
            result['checks'].append(f'echo-{size}')
        gate = threading.Barrier(8)
        def simultaneous_echo(index):
            gate.wait(timeout=10)
            payload = bytes([index]) * 4096
            with guest_connection(backing) as peer:
                peer.sendall(b'\x01' + struct.pack('<I', len(payload)) + payload)
                size = struct.unpack('<I', receive_exact(peer, 4))[0]
                if size != len(payload) or receive_exact(peer, size) != payload:
                    raise RuntimeError(f'concurrent echo mismatch: {index}')
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(simultaneous_echo, range(8)))
        result['checks'].append('eight-concurrent-connections')
        with guest_connection(backing) as peer:
            peer.sendall(b'\x02')
            if receive_exact(peer, 4) != b'half' or peer.recv(1) != b'':
                raise RuntimeError('half-close mismatch')
            peer.shutdown(socket.SHUT_WR)
        result['checks'].append('half-close')
        with guest_connection(backing) as peer:
            peer.sendall(b'\x06Z')
            peer.shutdown(socket.SHUT_WR)
            if peer.recv(1) != b'' or not host_eof.wait(5):
                raise RuntimeError('host-to-guest EOF not observed')
        result['checks'].append('host-to-guest-eof')
        with guest_connection(backing) as peer:
            peer.sendall(b'\x03')
            if receive_exact(peer, 9) != b'connected':
                raise RuntimeError('guest-initiated exchange mismatch')
        if host_error:
            raise RuntimeError(f'host listener failed: {host_error}')
        result['checks'].append('guest-initiated-connect')
        with ThreadPoolExecutor(max_workers=8) as pool:
            flows = [pool.submit(parallel_host_peer) for _ in range(8)]
            with guest_connection(backing) as peer:
                peer.sendall(b'\x07')
                if receive_exact(peer, 11) != b'parallel-ok':
                    raise RuntimeError('guest parallel completion missing')
            if sorted(flow.result(timeout=5) for flow in flows) != list(range(8)):
                raise RuntimeError('guest parallel flow identities mismatch')
        result['checks'].append('guest-eight-parallel-flows')
        for argument, expected in [(b'native-task', 7), (b'rejected', 64)]:
            with guest_connection(backing) as peer:
                peer.sendall(b'\x08' + bytes([len(argument)]) + argument)
                returned = struct.unpack('<i', receive_exact(peer, 4))[0]
                if returned != expected:
                    raise RuntimeError(f'OSv in-image module exit mismatch: {returned} != {expected}')
            result['checks'].append(f'in-image-module-exit-{expected}')
        for operation, expected, name in [(9, -errno.ENOENT, 'missing-module-rejected'),
                                          (10, -errno.EINVAL, 'module-traversal-rejected')]:
            with guest_connection(backing) as peer:
                peer.sendall(bytes([operation]))
                returned = struct.unpack('<i', receive_exact(peer, 4))[0]
                if returned != expected:
                    raise RuntimeError(f'{name}: {returned} != {expected}')
            result['checks'].append(name)
        with guest_connection(backing) as peer:
            argument = b'native-task'
            peer.sendall(b'\x08' + bytes([len(argument)]) + argument)
            if struct.unpack('<i', receive_exact(peer, 4))[0] != 7:
                raise RuntimeError('module runner did not recover after bad paths')
        result['checks'].append('module-runner-recovered')
        with guest_connection(backing) as peer:
            peer.sendall(b'\x04')
            refusal = struct.unpack('<i', receive_exact(peer, 4))[0]
            if refusal != -errno.ECONNREFUSED:
                raise RuntimeError(f'connect refusal returned {refusal}')
        result['checks'].append('connect-refusal')
        with guest_connection(backing) as peer:
            peer.sendall(b'\x05')
            timeout = struct.unpack('<i', receive_exact(peer, 4))[0]
            if timeout != -errno.ETIMEDOUT:
                raise RuntimeError(f'receive timeout returned {timeout}')
        result['checks'].append('receive-timeout')
        with guest_connection(backing) as peer:
            peer.sendall(b'\x63')
            if receive_exact(peer, 4) != b'done':
                raise RuntimeError('final acknowledgement missing')
            peer.sendall(b'\xa5')
        if not done.wait(10):
            raise RuntimeError('guest did not complete final acknowledgement')
        result['checks'].append('guest-completion')
        result['ok'] = True
    except Exception as exc:
        result['ok'] = False
        result['error'] = str(exc)
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        host_listener.close()
        parallel_listener.close()
        result['serial_tail'] = ''.join(serial)[-12000:]
        if result.get('ok') and 'OSV_NATIVE_MODULE_RAN' not in result['serial_tail']:
            result['ok'] = False
            result['error'] = 'in-image module execution marker missing'
        result['host_accepted'] = host_accepted.is_set()
        result['host_error'] = host_error
        shutil.rmtree(ROOT)
        cgroup_parent = Path('/sys/fs/cgroup/osv-native-validation-20261029')
        cgroup_leaf = cgroup_parent / JAIL_ID
        for group in (cgroup_leaf, cgroup_parent):
            if group.exists():
                if (group / 'cgroup.procs').read_text().strip():
                    result['ok'] = False
                    result['cleanup_error'] = f'live fixture cgroup: {group}'
                    break
                try:
                    group.rmdir()
                except OSError as exc:
                    result['ok'] = False
                    result['cleanup_error'] = str(exc)
                    break
        result['cleanup'] = {'fixture_root_absent': not ROOT.exists(),
                             'cgroup_absent': not cgroup_parent.exists()}
        (upload / 'e2e-result.json').write_text(json.dumps(result, indent=2) + '\n')
        (upload / 'e2e-result.json').chmod(0o644)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('upload_dir', type=Path)
    outcome = run(parser.parse_args().upload_dir.resolve())
    print(json.dumps({'ok': outcome['ok'], 'checks': outcome['checks'],
                      'error': outcome.get('error'), 'process': outcome.get('process')}))
    raise SystemExit(0 if outcome['ok'] else 1)
