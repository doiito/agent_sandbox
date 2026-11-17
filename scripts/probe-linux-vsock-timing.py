#!/usr/bin/env python3
"""Bounded, serialized pristine ping diagnostics; never API startup evidence."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import socket
import time

from startup_benchmark import atomic_report, owned_leases, percentiles, require, sha, validation_lock

FIELDS = ('unix_connect_us', 'connect_handshake_us', 'request_write_us', 'result_read_us', 'total_us')


def diagnostic_deadline(origin, config):
    start = origin.get('prepare_started_monotonic_ns')
    require(type(start) is int and start > 0 and start <= time.monotonic_ns(), 'invalid prepare origin')
    require(config['warm_pool']['health_interval_ms'] == 30000, 'diagnostic health interval is not 30s')
    return start + 25_000_000_000


def remaining(deadline):
    value = (deadline - time.monotonic_ns()) / 1e9
    require(value > 0, 'pre-health diagnostic deadline exhausted')
    return min(value, 1.0)


def validate_reply(line, job_id):
    prefix = b'FC_AGENT_RESULT '
    require(line.startswith(prefix) and line.endswith(b'\n') and len(line) < 16384, 'invalid bounded ping envelope')
    value = json.loads(line[len(prefix):])
    require(isinstance(value, dict) and value.get('protocol') == 'fc-agent/v3' and
            value.get('job_id') == job_id and value.get('ok') is True and
            type(value.get('exit_code')) is int and value['exit_code'] == 0 and
            value.get('guest_state') == 'pristine' and type(value.get('pristine_revision')) is int and value['pristine_revision'] == 2 and
            value.get('binding') is None and type(value.get('remaining_lifetime_ms')) is int and
            0 < value['remaining_lifetime_ms'] <= 600000, 'ping did not prove bound pristine readiness')


def ping(socket_path, port, job_id, deadline):
    require(type(port) is int and 0 < port <= 0xffffffff and re.fullmatch('[0-9a-f]{24}', job_id), 'invalid ping address/ID')
    payload = json.dumps({'protocol': 'fc-agent/v3', 'job_id': job_id, 'operation': 'ping'}, separators=(',', ':')).encode()+b'\n'
    directory = os.open(socket_path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        short_path = '/proc/self/fd/'+str(directory)+'/'+socket_path.name
        with socket.socket(socket.AF_UNIX) as conn:
            conn.settimeout(remaining(deadline))
            start = time.monotonic_ns()
            conn.connect(short_path)
            connected = time.monotonic_ns()
            with conn.makefile('rb') as reader:
                conn.settimeout(remaining(deadline))
                conn.sendall(('CONNECT '+str(port)+'\n').encode())
                conn.settimeout(remaining(deadline))
                ack = reader.readline(128)
                require(re.fullmatch(b'OK [0-9]+\n', ack) is not None and 0 < int(ack[3:]) <= 0xffffffff, 'invalid vsock CONNECT acknowledgement')
                handshake = time.monotonic_ns()
                conn.settimeout(remaining(deadline))
                conn.sendall(payload)
                sent = time.monotonic_ns()
                conn.settimeout(remaining(deadline))
                line = reader.readline(16384)
                received = time.monotonic_ns()
                remaining(deadline)
                validate_reply(line, job_id)
        points = (start, connected, handshake, sent, received)
        values = [(points[i+1]-points[i])//1000 for i in range(4)]
        total = (received-start)//1000
        # Keep the partition exact after conversion; residual goes to result read.
        values[-1] += total-sum(values)
        return {**dict(zip(FIELDS[:-1], values)), 'total_us': total}
    finally:
        os.close(directory)


def same_ready(config, expected):
    current = owned_leases(config)
    for vm_id, lease in expected.items():
        observed = current.get(vm_id, {})
        require(observed.get('phase') == 'ready' and all(observed.get(key) == lease[key]
                for key in ('pid', 'start_time_ticks', 'instance_id', 'vm_id', 'pool_key', 'uid')),
                'diagnostic VM generation or ready ownership changed')
    return current


def measure(root, config, package, origin):
    deadline = diagnostic_deadline(origin, config)
    output = root/'results/vsock-timing'
    output.mkdir(mode=0o700)
    report = {'suite': 'linux-pristine-vsock-timing/v1', 'diagnostic': True,
        'release_eligible': False, 'performance_gate_evidence': False,
        'measurement': 'direct pristine ping transport; excludes launcher admission/claim/prepare/durability',
        'test_sha256': sha(__file__), 'support_sha256': sha(Path(__file__).with_name('startup_benchmark.py')),
        'configuration_sha256': sha(root/'config.production.json'), 'candidate_sha256': sha(package),
        'origin': origin, 'deadline_monotonic_ns': deadline, 'attempts': [], 'passed': False}
    audit_path = Path(config['audit_log_path'])
    audit_before = audit_path.read_bytes()
    try:
        remaining(deadline)
        while True:
            ready = {key:row for key,row in owned_leases(config).items() if row.get('phase') == 'ready'}
            if len(ready) == 2:
                break
            remaining(deadline)
            time.sleep(.02)
        report['preboot_observations'] = ready
        with (output/'samples.jsonl').open('x') as raw:
            os.chmod(output/'samples.jsonl', 0o600)
            for vm_id, lease in sorted(ready.items()):
                for index in range(-5, 128):
                    row = {'vm_id': vm_id, 'job_id': secrets.token_hex(12), 'index': index,
                           'warmup': index < 0, 'success': False}
                    try:
                        remaining(deadline)
                        before = same_ready(config, ready)[vm_id]['cpu_snapshot']
                        uds = Path(config['run_root'])/lease['instance_id']/'jailer/firecracker'/lease['instance_id']/'root/agent.vsock'
                        row['timing'] = ping(uds, config['linux_guest']['vsock_port'], row['job_id'], deadline)
                        after = same_ready(config, ready)[vm_id]['cpu_snapshot']
                        require(before['limit'] == after['limit'], 'CPU policy changed during ping')
                        row['cpu_before'], row['cpu_after'] = before, after
                        row['cpu_delta'] = {key:after['stat'][key]-before['stat'][key]
                                            for key in ('usage_usec','nr_periods','nr_throttled','throttled_usec')}
                        require(all(value >= 0 for value in row['cpu_delta'].values()), 'CPU counters reversed')
                        remaining(deadline)
                        row['success'] = True
                    except Exception as error:
                        row['error'] = type(error).__name__+': '+str(error)[:512]
                    report['attempts'].append(row)
                    raw.write(json.dumps(row)+'\n');raw.flush()
                    if not row['success']:
                        raise ValueError('ping attempt failed; no retry')
                    time.sleep(.02)
            raw.flush();os.fsync(raw.fileno())
        remaining(deadline)
        same_ready(config, ready)
        report['pings_finished_monotonic_ns'] = time.monotonic_ns()
        require(report['pings_finished_monotonic_ns'] < deadline, 'pings exceeded serialized diagnostic window')
        audit_after = audit_path.read_bytes()
        require(audit_after.startswith(audit_before), 'audit prefix changed during probe')
        events = [json.loads(line) for line in audit_after.splitlines() if line]
        require(not any(event.get('event') in ('run.admitted','pool.claimed') for event in events), 'foreground work overlaps direct probe')
        require(len(report['attempts']) == 266 and all(row['success'] for row in report['attempts']), 'incomplete ping batch')
        report['passed'] = True
    except Exception as error:
        report['error'] = type(error).__name__+': '+str(error)[:512]
    finally:
        rows = [row for row in report['attempts'] if not row['warmup'] and row['success']]
        report['successes'] = len(rows)
        report['failures'] = sum(not row['success'] for row in report['attempts'])
        report['percentiles_ms'] = {key:percentiles([row['timing'][key]/1000 for row in rows]) for key in FIELDS}
        report['raw_samples_sha256'] = sha(output/'samples.jsonl') if (output/'samples.jsonl').exists() else None
        atomic_report(output/'report.json', report)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--lock-fd', type=int, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    require(os.geteuid() == 0 and root.parent == Path('/var/lib') and
            re.fullmatch('osv-offline-validation-20261030-[a-z0-9]+', root.name), 'requires owned diagnostic fixture')
    config = json.loads((root/'config.production.json').read_text())
    require(config['backend'] == 'firecracker-linux' and config['warm_pool']['enabled'] and
            config['run_root'] == str(root/'run') and config['jailer']['parent_cgroup'] == root.name,
            'diagnostic fixture ownership mismatch')
    origin = json.loads((root/'results/vsock-origin.json').read_text())
    with validation_lock(args.lock_fd):
        report = measure(root, config, args.package, origin)
    print(json.dumps({key:report[key] for key in ('passed','successes','failures','percentiles_ms')}), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
