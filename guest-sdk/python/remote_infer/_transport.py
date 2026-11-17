"""One fixed, bounded guest route; no credentials, environment URLs or retries."""
import json
import math
import re
import time

from ._contract import APIError, ConfigurationError, ProtocolError, TransportError

MAX_BODY = (512 << 10) * 2 + (64 << 10)
MAX_HEADER = 16384
HOST = 'inference.osv.invalid'


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise TransportError('inference observation deadline elapsed')
    return value


def deadline(timeout):
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 300:
        raise ConfigurationError('request_timeout must be between 0 and 300 seconds')
    return time.monotonic() + timeout


def _osv_api():
    # OSv deliberately reports Linux in uname. Detect its exported ABI lazily,
    # not sys.platform/uname, and never import socket or ssl on this path.
    import ctypes
    library = ctypes.CDLL(None)
    try:
        library.osv_vsock_connect
    except AttributeError:
        return None
    signatures = {
        'osv_vsock_connect': ([ctypes.c_uint64, ctypes.c_uint32, ctypes.c_uint32], ctypes.c_int),
        'osv_vsock_send': ([ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32], ctypes.c_int64),
        'osv_vsock_recv': ([ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32], ctypes.c_int64),
        'osv_vsock_close': ([ctypes.c_int], ctypes.c_int),
    }
    try:
        for name, (arguments, result) in signatures.items():
            function = getattr(library, name)
            function.argtypes, function.restype = arguments, result
    except AttributeError:
        raise TransportError('incomplete OSv vsock ABI') from None
    return library


class _VSock:
    def __init__(self, api, bound):
        self.api, self.handle = api, None
        handle = api.osv_vsock_connect(2, 5001, self._milliseconds(bound))
        if handle < 0:
            raise TransportError('OSv vsock connect errno ' + str(-handle))
        self.handle = handle

    @staticmethod
    def _milliseconds(bound):
        return min(300000, max(1, math.ceil(remaining(bound) * 1000)))

    def write(self, data, bound):
        import ctypes
        buffer = ctypes.create_string_buffer(data)
        offset = 0
        while offset < len(data):
            count = self.api.osv_vsock_send(self.handle, ctypes.byref(buffer, offset), len(data) - offset, self._milliseconds(bound))
            if count == -4:  # Interrupted before transferring bytes.
                continue
            if not 0 < count <= len(data) - offset:
                raise TransportError('OSv vsock send failed')
            offset += count

    def read(self, maximum, bound):
        import ctypes
        buffer = ctypes.create_string_buffer(maximum)
        while True:
            count = self.api.osv_vsock_recv(self.handle, buffer, maximum, self._milliseconds(bound))
            if count != -4:
                break
        if not 0 <= count <= maximum:
            raise TransportError('OSv vsock receive failed')
        return buffer.raw[:count]

    def close(self):
        if self.handle is not None:
            handle, self.handle = self.handle, None
            self.api.osv_vsock_close(handle)


class _Loopback:
    def __init__(self, bound):
        import socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.socket.settimeout(remaining(bound))
            self.socket.connect(('127.0.0.1', 3128))
        except BaseException:
            self.socket.close()
            raise

    def write(self, data, bound):
        self.socket.settimeout(remaining(bound))
        self.socket.sendall(data)

    def read(self, maximum, bound):
        self.socket.settimeout(remaining(bound))
        return self.socket.recv(maximum)

    def close(self):
        self.socket.close()


def _connect(bound):
    api = _osv_api()
    return _VSock(api, bound) if api is not None else _Loopback(bound)


def _json(data):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ProtocolError('duplicate inference JSON field')
            result[key] = value
        return result
    def invalid(_):
        raise ProtocolError('non-finite inference JSON')
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=pairs, parse_constant=invalid)
    except (UnicodeError, ValueError, RecursionError):
        raise ProtocolError('invalid inference JSON') from None


def _response(connection, bound):
    data = bytearray()
    while b'\r\n\r\n' not in data:
        chunk = connection.read(4096, bound)
        if not chunk:
            raise ProtocolError('incomplete inference response headers')
        data.extend(chunk)
        if len(data) > MAX_HEADER and b'\r\n\r\n' not in data:
            raise ProtocolError('inference response headers exceed limit')
    position = data.index(b'\r\n\r\n') + 4
    if position > MAX_HEADER:
        raise ProtocolError('inference response headers exceed limit')
    try:
        lines = bytes(data[:position - 4]).decode('ascii').split('\r\n')
    except UnicodeError:
        raise ProtocolError('invalid inference response headers') from None
    match = re.fullmatch(r'HTTP/1\.[01] ([1-5][0-9]{2})(?: [\x20-\x7e]*)?', lines[0])
    if match is None:
        raise ProtocolError('invalid inference HTTP status')
    headers = {}
    for line in lines[1:]:
        name, separator, value = line.partition(':')
        if not separator or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) or name.lower() in headers or any(ord(c) < 32 and c != '\t' or ord(c) > 126 for c in value):
            raise ProtocolError('invalid inference response framing')
        headers[name.lower()] = value.strip(' \t')
    length = headers.get('content-length', '')
    if ('transfer-encoding' in headers or headers.get('content-encoding', 'identity') != 'identity' or
            not re.fullmatch(r'0|[1-9][0-9]{0,7}', length) or int(length) > MAX_BODY or
            headers.get('content-type', '').split(';')[0].strip().lower() != 'application/json'):
        raise ProtocolError('invalid inference response framing')
    length = int(length)
    body = data[position:]
    while len(body) < length:
        chunk = connection.read(min(16384, length - len(body)), bound)
        if not chunk:
            raise ProtocolError('incomplete inference response body')
        body.extend(chunk)
    if len(body) != length:
        raise ProtocolError('unexpected trailing inference bytes')
    value, status = _json(body), int(match[1])
    if status != 200:
        error = value.get('error') if isinstance(value, dict) else None
        if (not isinstance(error, dict) or value.get('protocol') != 'osv-sandbox-inference-error/v1' or
                not isinstance(error.get('code'), str) or not re.fullmatch(r'[a-z0-9_]{1,64}', error['code'])):
            raise ProtocolError('invalid inference error response')
        raise APIError(status, error['code'], 'guest inference request rejected')
    return value


def exchange(method, path, value, bound):
    assert (method, path) in {('GET', '/v1/policy'), ('GET', '/v1/bill'), ('POST', '/v1/invoke')}
    body = b'' if value is None else json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode('utf-8')
    if len(body) > (256 << 10) + 8192:
        raise ConfigurationError('encoded inference request exceeds limit')
    headers = (f'{method} http://{HOST}{path} HTTP/1.1\r\nHost: {HOST}\r\n'
               f'Content-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode('ascii')
    connection = None
    try:
        remaining(bound)
        connection = _connect(bound)
        connection.write(headers + body, bound)
        # No write half-close: peer EOF cancels an admitted model invocation.
        return _response(connection, bound)
    except OSError:
        raise TransportError('guest inference transport failed') from None
    finally:
        if connection is not None:
            connection.close()
