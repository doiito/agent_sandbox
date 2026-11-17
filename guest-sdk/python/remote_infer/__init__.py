"""Controlled inference from Linux and OSv guests; import performs no I/O."""
from ._contract import (APIError, ConfigurationError, InferenceError, InferenceResult,
                       ProtocolError, SandboxError, TransportError, UnsupportedCapability,
                       _INFERENCE_ENDPOINT, _inference_bill, _inference_id, _inference_json,
                       _inference_policy_document, _inference_receipt)
from . import _transport

_task_id = None


def _bill(bound):
    global _task_id
    value = _transport.exchange('GET', '/v1/bill', None, bound)
    task = value.get('task_id') if isinstance(value, dict) else None
    result = _inference_bill(value, task if _task_id is None else _task_id)
    _task_id = result['task_id']
    return result


def bill(*, request_timeout=35.0):
    """Read the current root-bound task bill, including uncertain invocations."""
    return _bill(_transport.deadline(request_timeout))


def policy(*, request_timeout=35.0):
    """Read authorized aliases, limits and integer prices without credentials."""
    return _inference_policy_document(_transport.exchange('GET', '/v1/policy', None, _transport.deadline(request_timeout)))


def invoke(endpoint, payload, *, invocation_id=None, timeout_ms=0, request_timeout=35.0):
    """Submit once. On failure, query bill() using the retained invocation ID."""
    if invocation_id is None:
        import secrets
        invocation_id = secrets.token_hex(12)
    identity = _inference_id(invocation_id)
    attempted = False
    try:
        bound = _transport.deadline(request_timeout)
        if (not isinstance(endpoint, str) or not _INFERENCE_ENDPOINT.fullmatch(endpoint) or
                type(timeout_ms) is not int or not 0 <= timeout_ms <= 30000):
            raise ConfigurationError('invalid inference alias or timeout')
        snapshot, size = _inference_json(payload, 256 << 10)
        task = _bill(bound)['task_id']
        current = _inference_policy_document(_transport.exchange('GET', '/v1/policy', None, bound))
        if endpoint not in {item['name'] for item in current['endpoints']}:
            raise UnsupportedCapability('inference alias is not authorized')
        if size > current['max_request_bytes'] or timeout_ms > current['timeout_ms']:
            raise ConfigurationError('inference payload or timeout exceeds tenant policy')
        _transport.remaining(bound)
        attempted = True
        value = _transport.exchange('POST', '/v1/invoke', {'id': identity, 'endpoint': endpoint, 'payload': snapshot, 'timeout_ms': timeout_ms}, bound)
        if (not isinstance(value, dict) or set(value) != {'protocol', 'task_id', 'invocation', 'data'} or
                value['protocol'] != 'osv-sandbox-inference-invoke/v1' or value['task_id'] != task):
            raise ProtocolError('invalid inference result binding')
        _inference_receipt(value['invocation'])
        if value['invocation']['id'] != identity or value['invocation']['endpoint'] != endpoint or value['invocation']['state'] != 'succeeded':
            raise ProtocolError('invalid inference result invocation')
        data, _ = _inference_json(value['data'], 4 << 20, ProtocolError)
        return InferenceResult(task, identity, value['invocation'], data)
    except (SandboxError, TypeError, ValueError, OverflowError) as cause:
        raise InferenceError(_task_id, identity, cause, attempted) from cause


class _ML:
    invoke = staticmethod(invoke)
    bill = staticmethod(bill)
    policy = staticmethod(policy)


ml = _ML()
