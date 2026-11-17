#!/usr/bin/env python3
"""Isolated true-KVM smoke test for the OSv one-job-per-VM wire protocol."""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import threading
import time

ROOT = Path('/var/lib/osv-job-validation-20261029')
UID = GID = 220210


def exact(peer, size):
    data = bytearray()
    while len(data) < size:
        block = peer.recv(size - len(data))
        if not block:
            raise RuntimeError(f'premature EOF: {len(data)}/{size}')
        data.extend(block)
    return bytes(data)


def environment_payload(entries):
    return (struct.pack('<H', len(entries)) +
            b''.join(struct.pack('<HH', len(name), len(value)) + name + value
                     for name, value in entries))


def run_case(upload, number, argument, expected_exit, invalid_kind=None, *,
             root=None, uid=None, binaries=None, timeout_ms=30000,
             stdout_marker=None, stderr_marker=None, forbidden_stdout=None,
             ack_mode='normal', socket_timeout=35, stop_timeout=15,
             entrypoint='/task-probe.so', module_arguments=None, memory_mib=128,
             boot_options=(), report_capture_bytes=128, max_capture=4096, observe_io=False):
    root = ROOT if root is None else root
    uid = UID if uid is None else uid
    if ack_mode not in ('normal', 'omit', 'disconnect'):
        raise ValueError('unknown ACK mode')
    if not 1024 <= max_capture <= 1 << 20:
        raise ValueError('invalid diagnostic capture budget')
    if boot_options not in ((), ('--disable_rofs_cache',), ('--sandbox-small-pages',),
            ('--disable_rofs_cache', '--sandbox-small-pages')) or memory_mib not in (64, 128, 256, 512):
        raise ValueError('unsupported diagnostic profile')
    ident = f'osv-job-{number}'
    jailroot = root / 'jailer' / 'firecracker' / ident / 'root'
    jailroot.mkdir(parents=True)
    os.chown(jailroot, uid, uid)
    for source, name in [('loader-stripped.elf', 'kernel'), ('osv-native-agent.raw', 'rootfs')]:
        target = jailroot / name
        shutil.copyfile(upload / source, target)
        target.chmod(0o444)
    config = {
        'boot-source': {'kernel_image_path': '/kernel',
                        'boot_args': ' '.join(('--nopci', '--console=serial', '--rootfs=rofs', *boot_options, '/osv-job-agent.so'))},
        'drives': [{'drive_id': 'rootfs', 'path_on_host': '/rootfs',
                    'is_root_device': True, 'is_read_only': True}],
        'vsock': {'guest_cid': 100 + number, 'uds_path': '/agent.vsock'},
        'machine-config': {'vcpu_count': 1, 'mem_size_mib': memory_mib,
                           'smt': False, 'track_dirty_pages': False},
    }
    (jailroot / 'config.json').write_text(json.dumps(config))
    (jailroot / 'config.json').chmod(0o444)
    jailer = '/usr/local/bin/jailer' if binaries is None else str(binaries/'jailer')
    firecracker = '/usr/local/bin/firecracker' if binaries is None else str(binaries/'firecracker')
    args = [jailer, '--id', ident,
            '--exec-file', firecracker,
            '--uid', str(uid), '--gid', str(uid),
            '--chroot-base-dir', str(root / 'jailer'),
            '--cgroup-version', '2', '--parent-cgroup', root.name,
            '--cgroup', 'memory.max=' + str((memory_mib + 128) * 1048576), '--cgroup', 'memory.swap.max=0',
            '--cgroup', 'memory.oom.group=1', '--cgroup', 'cpu.max=100000 100000',
            '--cgroup', 'pids.max=64', '--resource-limit', 'no-file=1024',
            '--resource-limit', 'fsize=268435456', '--', '--no-api',
            '--config-file', '/config.json']
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, bufsize=1)
    serial = []
    ready = threading.Event()

    def read_serial():
        for line in process.stdout:
            serial.append(line)
            if 'OSV_JOB_READY' in line:
                ready.set()

    threading.Thread(target=read_serial, daemon=True).start()
    result = {'argument': argument, 'expected_exit': expected_exit,
              'invalid_kind': invalid_kind, 'memory_mib': memory_mib, 'boot_options': list(boot_options)}
    try:
        if not ready.wait(40):
            raise RuntimeError(f'guest not ready; exit={process.poll()}')
        status = Path(f'/proc/{process.pid}/status').read_text()
        if next(x for x in status.splitlines() if x.startswith('Uid:')).split()[1:] != [str(uid)] * 4:
            raise RuntimeError('jailer UID mismatch')
        if next(x for x in status.splitlines() if x.startswith('Seccomp:')).split()[1] != '2':
            raise RuntimeError('jailer seccomp missing')
        if next(x for x in status.splitlines() if x.startswith('CapEff:')).split()[1] != '0000000000000000':
            raise RuntimeError('jailer retained effective capabilities')
        cgroup = Path('/sys/fs/cgroup')/root.name/ident
        limits = {name: (cgroup/name).read_text().strip() for name in
                  ('memory.max', 'memory.swap.max', 'cpu.max', 'pids.max')}
        if limits != {'memory.max': str((memory_mib+128)*1048576), 'memory.swap.max': '0',
                      'cpu.max': '100000 100000', 'pids.max': '64'}:
            raise RuntimeError('diagnostic VMM resource limits mismatch')
        result['resource_limits'] = limits
        job_id = f'{number:024x}'.encode()
        nonce = bytes(range(16))
        path = entrypoint.encode()
        arguments = [argument] if module_arguments is None else list(module_arguments)
        if argument == 'native-many-args':
            arguments.extend(f'arg-{index:02d}' for index in range(1, 64))
        stdin_payload = {
            'native-stdin-empty': b'',
            'native-stdin-binary': b'A\x00B\xff\n',
            'native-env-stdin': b'A\x00B\xff\n',
            'native-stdin-ignore': bytes(index % 251 for index in range(16384)),
            'native-stdin-max': bytes(index % 251 for index in range(16384)),
        }.get(argument)
        flags = (1 if argument in ('native-env', 'native-env-stdin') else 0) | (2 if stdin_payload is not None else 0)
        body = (b'OSJ1' + bytes([1, flags, 0, 0]) + job_id + nonce +
                struct.pack('<IIHH', timeout_ms, max_capture, len(path), len(arguments)) + path +
                b''.join(struct.pack('<H', len(arg.encode())) + arg.encode()
                         for arg in arguments))
        if argument in ('native-env', 'native-env-stdin'):
            body += environment_payload([
                (b'SANDBOX_EMPTY', b''), (b'SANDBOX_TEST_MARKER', b'native-env-ok')])
        if stdin_payload is not None:
            body += struct.pack('<H', len(stdin_payload)) + stdin_payload
        backing = jailroot / 'agent.vsock'
        with socket.socket(socket.AF_UNIX) as peer:
            peer.settimeout(socket_timeout)
            directory = os.open(backing.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                peer.connect('/proc/self/fd/' + str(directory) + '/' + backing.name)
            finally:
                os.close(directory)
            peer.sendall(b'CONNECT 5000\n')
            reply = bytearray()
            while not reply.endswith(b'\n') and len(reply) < 128:
                reply.extend(exact(peer, 1))
            if not reply.startswith(b'OK '):
                raise RuntimeError(f'vsock connect failed: {reply!r}')
            if invalid_kind == 'oversized-length':
                peer.sendall(struct.pack('<I', 65537))
            else:
                if invalid_kind:
                    body = bytearray(body)
                    if invalid_kind == 'bad-type': body[4] = 9
                    elif invalid_kind == 'bad-magic': body[:4] = b'OSX1'
                    elif invalid_kind == 'bad-flags': body[5] = 1
                    elif invalid_kind == 'unknown-flag': body[5] = 4
                    elif invalid_kind == 'reserved-byte': body[6] = 1
                    elif invalid_kind == 'uppercase-id': body[8] = ord('A')
                    elif invalid_kind == 'zero-timeout': body[48:52] = b'\x00' * 4
                    elif invalid_kind == 'oversized-capture': body[52:56] = struct.pack('<I', 1048577)
                    elif invalid_kind == 'too-many-args': body[58:60] = struct.pack('<H', 65)
                    elif invalid_kind == 'nul-path': body[60] = 0
                    elif invalid_kind == 'nul-arg': body[60 + len(path) + 2] = 0
                    elif invalid_kind == 'trailing-byte': body.append(0)
                    elif invalid_kind.startswith('bad-env-'):
                        body[5] = 1
                        if invalid_kind == 'bad-env-count':
                            body.extend(struct.pack('<H', 33))
                        else:
                            entries = [(b'GOOD', b'value')]
                            if invalid_kind == 'bad-env-name': entries = [(b'1BAD', b'value')]
                            elif invalid_kind == 'bad-env-reserved': entries = [(b'LD_PRELOAD', b'value')]
                            elif invalid_kind == 'bad-env-value-nul': entries = [(b'GOOD', b'bad\x00value')]
                            elif invalid_kind == 'bad-env-order': entries = [(b'Z_KEY', b'1'), (b'A_KEY', b'2')]
                            elif invalid_kind == 'bad-env-duplicate': entries = [(b'GOOD', b'1'), (b'GOOD', b'2')]
                            elif invalid_kind == 'bad-env-total':
                                entries = [(f'KEY_{i:02d}'.encode(), b'v' * 1024) for i in range(9)]
                            elif invalid_kind != 'bad-env-trailing':
                                raise RuntimeError(f'unknown invalid kind: {invalid_kind}')
                            body.extend(environment_payload(entries))
                            if invalid_kind == 'bad-env-trailing': body.append(0)
                    elif invalid_kind.startswith('bad-stdin-'):
                        body[5] = 2
                        if invalid_kind == 'bad-stdin-missing-length':
                            pass
                        elif invalid_kind == 'bad-stdin-truncated':
                            body.extend(struct.pack('<H', 5) + b'abc')
                        elif invalid_kind == 'bad-stdin-over-limit':
                            body.extend(struct.pack('<H', 16385) + b'x' * 16385)
                        elif invalid_kind == 'bad-stdin-trailing':
                            body.extend(struct.pack('<H', 1) + b'xy')
                        else:
                            raise RuntimeError(f'unknown invalid kind: {invalid_kind}')
                    else: raise RuntimeError(f'unknown invalid kind: {invalid_kind}')
                if observe_io:
                    io_before = {key: int(value) for key, value in (line.split(':', 1) for line in
                        Path(f'/proc/{process.pid}/io').read_text().splitlines())}
                task_started = time.monotonic()
                peer.sendall(struct.pack('<I', len(body)) + body)
            if invalid_kind:
                if peer.recv(1) != b'':
                    raise RuntimeError('malformed guest request produced a result')
                result['rejected_without_result'] = True
            else:
                length = struct.unpack('<I', exact(peer, 4))[0]
                if length < 64 or length > 64+max_capture:
                    raise RuntimeError(f'invalid result length {length}')
                response = exact(peer, length)
                if observe_io:
                    io_after = {key: int(value) for key, value in (line.split(':', 1) for line in
                        Path(f'/proc/{process.pid}/io').read_text().splitlines())}
                    result['host_process_io_delta'] = {key: io_after[key]-value for key, value in io_before.items()}
                if (response[:5] != b'OSJ1\x02' or response[5] & ~3 or
                        response[6:8] != b'\x00\x00' or
                        response[8:32] != job_id or response[32:48] != nonce):
                    raise RuntimeError('result identity or header mismatch')
                status_code, exit_code, stdout_len, stderr_len = struct.unpack('<iiII', response[48:64])
                expected_codes = (expected_exit,) if isinstance(expected_exit, int) else expected_exit
                if 64 + stdout_len + stderr_len != length:
                    raise RuntimeError('invalid module result capture lengths')
                if status_code != 0 or exit_code not in expected_codes:
                    # Preserve a bounded, identity-checked failure without
                    # treating an unexpected exit as a successful test.
                    result['unexpected_guest_result'] = {
                        'runner_status': status_code, 'exit_code': exit_code,
                        'stdout_len': stdout_len, 'stderr_len': stderr_len,
                        'stdout': response[64:64 + stdout_len][:report_capture_bytes].decode(errors='replace'),
                        'stderr': response[64 + stdout_len:][:report_capture_bytes].decode(errors='replace'),
                        'flags': response[5], 'frame_identity_checked': True}
                    raise RuntimeError(f'invalid module result: status={status_code} exit={exit_code}')
                stdout = response[64:64 + stdout_len]
                stderr = response[64 + stdout_len:]
                if expected_exit == 7 and b'OSV_NATIVE_MODULE_RAN' not in stdout:
                    raise RuntimeError(f'module stdout missing: {stdout!r}')
                if argument == 'native-success' and b'OSV_NATIVE_MODULE_OK' not in stdout:
                    raise RuntimeError(f'success stdout missing: {stdout!r}')
                if argument == 'native-stderr' and b'OSV_NATIVE_STDERR' not in stderr:
                    raise RuntimeError(f'stderr missing: {stderr!r}')
                if argument == 'native-flood' and (stdout_len != 4096 or response[5] != 1):
                    raise RuntimeError(f'flood truncation failed: bytes={stdout_len} flags={response[5]}')
                if argument == 'native-many-args' and b'OSV_NATIVE_64_ARGS_OK' not in stdout:
                    raise RuntimeError(f'64-argument boundary failed: {stdout!r}')
                if argument == 'native-env' and b'OSV_NATIVE_ENV_OK' not in stdout:
                    raise RuntimeError(f'environment was not passed to module: {stdout!r}')
                if argument == 'native-stdin-empty' and b'OSV_NATIVE_STDIN_EMPTY_OK' not in stdout:
                    raise RuntimeError('empty stdin was not delivered')
                if argument in ('native-stdin-binary', 'native-env-stdin') and b'OSV_NATIVE_STDIN_BINARY_OK' not in stdout:
                    raise RuntimeError('binary stdin was not delivered')
                if argument == 'native-stdin-max' and b'OSV_NATIVE_STDIN_MAX_OK' not in stdout:
                    raise RuntimeError('16 KiB stdin was not delivered')
                if argument == 'native-stdin-ignore' and b'OSV_NATIVE_STDIN_IGNORE_OK' not in stdout:
                    raise RuntimeError('non-reading module stalled on stdin')
                if stdout_marker is not None:
                    markers = (stdout_marker,) if isinstance(stdout_marker, bytes) else stdout_marker
                    if not all(marker in stdout for marker in markers):
                        raise RuntimeError('expected exit stdout missing')
                if stderr_marker is not None and stderr_marker not in stderr:
                    raise RuntimeError('expected exit stderr missing')
                if forbidden_stdout is not None and forbidden_stdout in stdout:
                    raise RuntimeError('immediate exit unexpectedly flushed user stdio')
                if ack_mode == 'normal':
                    peer.sendall(b'\xa5')
                elif ack_mode == 'disconnect':
                    peer.shutdown(socket.SHUT_RDWR)
                    peer.close()
                if ack_mode != 'disconnect' and peer.recv(1) != b'':
                    raise RuntimeError('guest produced a second result or failed to close result stream')
                result.update({'runner_status': status_code, 'exit_code': exit_code,
                               'task_wire_duration_ms': round((time.monotonic()-task_started)*1000, 3),
                               'stdout': stdout[:report_capture_bytes].decode(errors='replace'),
                               'stdout_len': stdout_len, 'stderr': stderr[:report_capture_bytes].decode(errors='replace'),
                               'stderr_len': stderr_len,
                               'flags': response[5], 'ack_mode': ack_mode})
        result['vmm_exit'] = process.wait(timeout=stop_timeout)
        stopped = ''.join(serial)
        if result['vmm_exit'] not in (0, 1) or (result['vmm_exit'] == 1 and
                'RunWithoutApiError(Shutdown(GenericError))' not in stopped):
            raise RuntimeError('VMM did not follow its expected shutdown path')
        if any(marker in stopped for marker in ('Aborted', 'Assertion failed', 'Page fault', 'Backtrace:')):
            raise RuntimeError('guest faulted during completion')
        result['ok'] = True
    except Exception as error:
        result['ok'] = False
        result['error'] = str(error)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        result['serial_tail'] = ''.join(serial)[-6000:]
    return result


def protocol_cases():
    cases = [('native-task', 7, None), ('rejected', 64, None),
                 ('native-success', 0, None), ('native-stderr', 0, None),
                 ('native-flood', 0, None), ('native-many-args', 0, None),
                 ('native-env', 0, None), ('native-stdin-empty', 0, None),
                 ('native-stdin-binary', 0, None), ('native-stdin-max', 0, None),
                 ('native-stdin-ignore', 0, None), ('native-env-stdin', 0, None)]
    cases.extend((name, None, name) for name in
                     ('bad-type', 'oversized-length', 'bad-magic', 'bad-flags',
                      'unknown-flag',
                      'reserved-byte', 'uppercase-id', 'zero-timeout',
                      'oversized-capture', 'too-many-args', 'nul-path',
                      'nul-arg', 'trailing-byte', 'bad-env-count',
                      'bad-env-name', 'bad-env-reserved', 'bad-env-value-nul',
                      'bad-env-order', 'bad-env-duplicate', 'bad-env-total',
                      'bad-env-trailing', 'bad-stdin-missing-length',
                      'bad-stdin-truncated', 'bad-stdin-over-limit',
                      'bad-stdin-trailing'))
    return cases


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--upload', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or ROOT.exists():
        raise SystemExit('requires root and an unused isolated fixture directory')
    result = {'cases': []}
    cases = protocol_cases()
    try:
        for number, (argument, expected, invalid) in enumerate(cases, 1):
            result['cases'].append(run_case(args.upload, number, argument, expected, invalid))
            if not result['cases'][-1]['ok']:
                break
        result['ok'] = len(result['cases']) == len(cases) and all(case['ok'] for case in result['cases'])
    finally:
        shutil.rmtree(ROOT)
        parent = Path('/sys/fs/cgroup/osv-job-validation-20261029')
        for leaf in ([parent / f'osv-job-{number}' for number in range(1, len(cases) + 1)] + [parent]):
            if leaf.exists() and not (leaf / 'cgroup.procs').read_text().strip():
                leaf.rmdir()
        result['cleanup'] = {'fixture_absent': not ROOT.exists(), 'cgroup_absent': not parent.exists()}
        (args.upload / 'job-agent-result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    if not result['ok']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
