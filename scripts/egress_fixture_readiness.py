"""Read-only current-generation readiness for disposable inference fixtures."""
import http.client
import json
from pathlib import Path
import pwd
import re
import socket
import struct
import subprocess
import time

MAX_REPLY = 1 << 20


class NotReady(Exception):
    pass


def unix_json(path, method, route, body, token, pid, uid, timeout, expected_status=200, extra_headers=None):
    connection = http.client.HTTPConnection('egress.invalid', timeout=timeout)
    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        stream.settimeout(timeout)
        stream.connect(str(path))
        peer, owner, _ = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if peer != pid or owner != uid:
            raise NotReady('socket belongs to another generation')
        connection.sock = stream
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        if extra_headers:
            headers.update(extra_headers)
        connection.request(method, route, body=body, headers=headers)
        response = connection.getresponse()
        data = response.read(MAX_REPLY + 1)
        if response.status != expected_status or len(data) > MAX_REPLY:
            raise NotReady('endpoint did not acknowledge readiness')
        value = json.loads(data)
        if not isinstance(value, dict):
            raise NotReady('invalid readiness envelope')
        return value
    finally:
        connection.close()
        stream.close()


def wait_for_generation(directory, token, tenant, task, price, uid, generation, timeout=10):
    """The two endpoint responses must belong to one still-current process."""
    if not 0 < timeout <= 10:
        raise ValueError('readiness has an independent bounded ten-second budget')
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            before = generation()
            pid, invocation = before['pid'], before['invocation_id']
            if pid <= 1 or not re.fullmatch('[0-9a-f]{32}', invocation):
                raise NotReady('service has no current generation')
            limit = min(0.25, max(0.001, deadline - time.monotonic()))
            state = unix_json(Path(directory) / 'e.sock', 'GET', '/v1/inference/state', None,
                              token, pid, uid, limit)
            if state.get('protocol') != 'osv-sandbox-inference-state/v1' or state.get('billing') is not True:
                raise NotReady('billing not available')
            digest = state.get('policy_sha256', '')
            endpoints = (state.get('policy') or {}).get('endpoints', [])
            if not re.fullmatch('[0-9a-f]{64}', digest) or not any(
                    item.get('name') == 'model' and item.get('price', {}).get('request_units') == price
                    for item in endpoints):
                raise NotReady('expected policy not loaded')
            request = json.dumps({'protocol': 'osv-sandbox-inference-root/v1',
                                  'binding': {'tenant': tenant, 'task_id': task}}).encode()
            limit = min(0.25, max(0.001, deadline - time.monotonic()))
            inspected = unix_json(Path(directory) / 'inference.sock', 'POST', '/v1/inference/root/inspect',
                                  request, None, pid, uid, limit)
            if inspected.get('protocol') != 'osv-sandbox-inference-root/v1' or (inspected.get('bill') or {}).get('task_id') != task:
                raise NotReady('existing task not available on control endpoint')
            if generation() != before:
                raise NotReady('generation changed during observation')
            return {'pid': pid, 'invocation_id': invocation, 'policy_sha256': digest,
                    'task_id': task, 'read_only': True}
        except (OSError, ValueError, TypeError, KeyError, AttributeError, http.client.HTTPException, NotReady,
                subprocess.SubprocessError):
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(0.025, remaining))
    raise TimeoutError('egress current-generation endpoints did not become ready')


def verify_root_policy_rejection(directory, binding, old_policy, current, uid):
    """Authenticate the outer grant refusal without starting an inner request."""
    if not re.fullmatch('[0-9a-f]{64}', old_policy) or old_policy == current['policy_sha256']:
        raise ValueError('policy probe requires two distinct observed policies')
    if not all(re.fullmatch('[0-9a-f]{24}', binding[name]) for name in ('task_id', 'vm_id', 'lease_id')):
        raise ValueError('policy probe requires an actual bound task bill')
    headers = {'Connection': 'upgrade', 'Upgrade': 'osv-guest-proxy/1',
               'X-OSV-Tenant': binding['tenant'], 'X-OSV-Task': binding['task_id'],
               'X-OSV-VM': binding['vm_id'], 'X-OSV-Lease': binding['lease_id'],
               'X-OSV-Inference': 'remote-infer-v1', 'X-OSV-Inference-Policy': old_policy}
    value = unix_json(Path(directory) / 'e.sock', 'POST', '/v1/guest-proxy', b'', None,
                      current['pid'], uid, 1, expected_status=503, extra_headers=headers)
    if set(value) != {'code', 'error'} or value.get('code') != 'inference_policy_unavailable' or not isinstance(value.get('error'), str):
        raise NotReady('outer grant did not receive the specified policy refusal')
    return {'pid': current['pid'], 'task_id': binding['task_id'], 'status': 503,
            'code': 'inference_policy_unavailable', 'inner_request_sent': False}


def verify_fixture_policy_rejection(root, binding, old_policy, current):
    return verify_root_policy_rejection(Path(root) / 'egress-runtime', binding, old_policy, current,
                                        pwd.getpwnam('osv-sandbox').pw_uid)


def wait_fixture_egress(root, task, price):
    root = Path(root)
    policy = json.loads((root / 'auth.json').read_text())
    tenant = policy['tenants'][0]['id']
    token = (root / 'secrets/token').read_text().strip()

    def generation():
        result = subprocess.run(['systemctl', 'show', root.name + '-egress.service',
                                 '--property=MainPID,InvocationID,ActiveState'],
                                capture_output=True, text=True, check=True, timeout=1)
        values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        if values.get('ActiveState') != 'active':
            raise NotReady('egress unit is not active')
        return {'pid': int(values['MainPID']), 'invocation_id': values['InvocationID']}

    return wait_for_generation(root / 'egress-runtime', token, tenant, task, str(price),
                               pwd.getpwnam('osv-sandbox').pw_uid, generation)
