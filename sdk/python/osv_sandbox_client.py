"""Synchronous, standard-library-only client for the OSv Sandbox REST API.

Python 3.10+. The default run path binds a job to the authenticated, signed
template advertised by the server. No implicit v1 fallback is performed.
"""

from __future__ import annotations

import base64
import codecs
import time
import threading
import binascii
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
import math
import posixpath
import re
import secrets
import inspect
import http.client
import socket
import ssl
import struct
import unicodedata
from typing import Any
from urllib import error, parse, request


_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SESSION_ID = re.compile(r"^[0-9a-f]{24}$")
_MAX_REQUEST_BYTES = 1 << 20
_MAX_RESPONSE_BYTES = 4 << 20
_MAX_ERROR_BYTES = 64 << 10
_SESSION_FILE_LIMIT = 512 << 10
_SESSION_FILE_LIST_LIMIT = 256
_SESSION_FILE_LIST_NAME_BYTES_LIMIT = 64 << 10


class SandboxError(Exception):
    """Base class for client-side sandbox errors."""


class ConfigurationError(SandboxError):
    """Invalid client or job configuration."""


class TransportError(SandboxError):
    """The authenticated HTTPS exchange did not complete."""


class TimeoutException(TransportError):
    """The command observation deadline elapsed; the process may still run."""


class ProtocolError(SandboxError):
    """The server response is malformed or exceeds the client limit."""


class UnsupportedCapability(SandboxError):
    """The server does not advertise the requested operation."""


class APIError(SandboxError):
    """The server rejected a request with a non-success HTTP status."""

    def __init__(self, status: int, code: str, message: str):
        self.status = status
        self.code = code
        self.message = message
        super().__init__(f"HTTP {status} {code}: {message}")


class TemplateMismatch(APIError):
    """The selected signed template changed before admission."""


_PORT_MAX_BYTES = 64 << 20
_PORT_FRAME_BYTES = 16384
_PORT_FAILED = {"connection_refused", "timeout", "idle_timeout", "connection_lost",
                "byte_limit", "protocol_error", "io_error"}


def _preview_timestamp(text: Any) -> int:
    match = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)", text) if isinstance(text, str) else None
    if match is None:
        raise ValueError()
    zone = match[3]
    if zone != "Z" and (int(zone[1:3]) > 23 or int(zone[4:]) > 59):
        raise ValueError()
    value = datetime.fromisoformat(match[1] + zone.replace("Z", "+00:00"))
    delta = value - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1000000000 + int((match[2] or "").ljust(9, "0"))


def _port_info(value: Any, connection_id: str, port: int, maximum: int) -> dict[str, Any]:
    if (not isinstance(value, dict) or set(value) != {"id", "port", "status", "sent_bytes", "received_bytes", "error"} or
            value["id"] != connection_id or type(value["port"]) is not int or value["port"] != port or
            any(type(value[key]) is not int or not 0 <= value[key] <= maximum for key in ("sent_bytes", "received_bytes"))):
        raise ProtocolError("invalid port connection binding or counts")
    status, error_code = value["status"], value["error"]
    if not ((status in ("opening", "open", "cancelling", "completed") and error_code is None) or
            (status == "cancelled" and error_code in ("cancelled", "service_closed")) or
            (status == "failed" and isinstance(error_code, str) and error_code in _PORT_FAILED)):
        raise ProtocolError("invalid port connection state")
    return value


@dataclass(frozen=True)
class PortFrame:
    """One bounded frame. eof ends application data; finished proves a terminal result."""

    kind: str
    data: bytes = b""
    info: dict[str, Any] | None = None


class SessionPorts:
    def __init__(self, session: Session):
        self._session = session

    def preview(self, port: int, preview_id: str) -> PreviewGrant:
        """Reference an existing grant without creating or renewing it."""
        if (type(port) is not int or not 1 <= port <= 65535 or
                not isinstance(preview_id, str) or not _SESSION_ID.fullmatch(preview_id)):
            raise ConfigurationError("port and preview_id must be valid")
        return PreviewGrant(self._session, port, preview_id)

    def create_preview(self, port: int, *, preview_id: str | None = None,
                       ttl_ms: int = 300000, request_timeout: float | None = None) -> PreviewGrant:
        """Create once. An uncertain exception retains its preview handle."""
        handle = self.preview(port, secrets.token_hex(12) if preview_id is None else preview_id)
        if type(ttl_ms) is not int or not 1000 <= ttl_ms <= 300000:
            raise ConfigurationError("preview ttl_ms must be 1000..300000")
        request_timeout = _code_timeout(request_timeout)
        try:
            report = self._session.capabilities(request_timeout=request_timeout)
            if (report.get("backend") != "firecracker-linux" or
                    report.get("artifact_manifest_protocol") not in ("osv-sandbox-artifacts/v6", "osv-sandbox-artifacts/v7", "osv-sandbox-artifacts/v8") or
                    not isinstance(report.get("features"), dict) or report["features"].get("port_preview") is not True or
                    report["features"].get("port_forward") is not True):
                raise UnsupportedCapability("selected session has no authenticated preview")
            value = self._session._client._exchange("POST",
                f"/v2/sessions/{self._session.id}/ports/{port}/previews/{handle.id}",
                {"ttl_ms": ttl_ms}, accepted=(201,), timeout_seconds=request_timeout)
            handle._created = handle._validate(value, creating=True)
            return handle
        except Exception as exc:
            exc.preview = handle
            raise

    def connection(self, port: int, connection_id: str) -> PortConnection:
        """Reference a known ID without opening TCP. Allows cancel-before-open."""
        if (type(port) is not int or not 1 <= port <= 65535 or
                not isinstance(connection_id, str) or not _SESSION_ID.fullmatch(connection_id)):
            raise ConfigurationError("port and connection_id must be valid")
        return PortConnection(self._session, port, connection_id)

    def open(self, port: int, *, connection_id: str | None = None,
             max_bytes: int = _PORT_MAX_BYTES, timeout_ms: int = 300000,
             idle_timeout_ms: int = 300000, request_timeout: float | None = None) -> PortConnection:
        handle = self.connection(port, secrets.token_hex(12) if connection_id is None else connection_id)
        for value, maximum in ((max_bytes, _PORT_MAX_BYTES), (timeout_ms, 300000), (idle_timeout_ms, 300000)):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ConfigurationError("port limits must be positive and within advertised maxima")
        _code_timeout(request_timeout)
        try:
            report = self._session.capabilities(request_timeout=request_timeout)
            if (report.get("backend") != "firecracker-linux" or
                    report.get("artifact_manifest_protocol") not in ("osv-sandbox-artifacts/v6", "osv-sandbox-artifacts/v7", "osv-sandbox-artifacts/v8") or
                    not isinstance(report.get("features"), dict) or report["features"].get("port_forward") is not True):
                raise UnsupportedCapability("selected session has no native port tunnel")
            handle._open({"max_bytes": max_bytes, "timeout_ms": timeout_ms,
                          "idle_timeout_ms": idle_timeout_ms}, request_timeout)
            return handle
        except Exception as exc:
            exc.connection = handle
            raise


class PreviewGrant:
    """Session-owned browser authorization. No automatic retry, renewal or revoke.

    bootstrap_url is returned only by create; info never recovers its secret.
    revoke confirms authorization revocation, not physical guest cleanup.
    """

    def __init__(self, session: Session, port: int, preview_id: str):
        self._session, self._port, self._id = session, port, preview_id
        self._created = None
        self._path = f"/v2/sessions/{session.id}/previews/{preview_id}"

    def __repr__(self) -> str:
        return f"PreviewGrant(id={self.id!r}, port={self.port})"

    @property
    def id(self) -> str:
        return self._id

    @property
    def port(self) -> int:
        return self._port

    @property
    def created(self) -> dict[str, Any] | None:
        return dict(self._created) if self._created is not None else None

    @property
    def bootstrap_url(self) -> str | None:
        return self._created["bootstrap_url"] if self._created is not None else None

    def _validate(self, value: Any, *, creating: bool = False) -> dict[str, Any]:
        keys = {"protocol", "id", "session_id", "port", "origin", "created_at", "expires_at", "status"}
        if creating:
            keys.add("bootstrap_url")
        if (not isinstance(value, dict) or set(value) != keys or
                value.get("protocol") != "osv-sandbox-preview/v1" or value.get("id") != self.id or
                value.get("session_id") != self._session.id or type(value.get("port")) is not int or value["port"] != self.port or
                value.get("status") not in ("active", "revoked", "expired", "session_closed", "server_closed")):
            raise ProtocolError("invalid preview identity or state")
        try:
            origin = value["origin"]
            if not isinstance(origin, str) or not re.fullmatch(
                    r"https://[0-9a-f]{24}\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?::[1-9][0-9]{0,4})?", origin):
                raise ValueError()
            url = parse.urlsplit(origin)
            if url.port is not None and url.port > 65535:
                raise ValueError()
            dates = [_preview_timestamp(value[key]) for key in ("created_at", "expires_at")]
            if not 0 < dates[1] - dates[0] <= 300000000000:
                raise ValueError()
            if creating and (value["status"] != "active" or not isinstance(value["bootstrap_url"], str) or
                    not re.fullmatch(re.escape(origin) + r"/\.osv/authorize\?token=[0-9a-f]{64}", value["bootstrap_url"])):
                raise ValueError()
            if self._created is not None and any(value[key] != self._created[key] for key in
                    ("origin", "created_at", "expires_at")):
                raise ValueError()
        except (ValueError, TypeError, OverflowError):
            raise ProtocolError("invalid preview origin, lifetime or bootstrap URL") from None
        return dict(value)

    def info(self, *, request_timeout: float | None = None) -> dict[str, Any]:
        request_timeout = _code_timeout(request_timeout)
        return self._validate(self._session._client._exchange("GET", self._path, timeout_seconds=request_timeout))

    def revoke(self, *, request_timeout: float | None = None) -> dict[str, Any]:
        request_timeout = _code_timeout(request_timeout)
        value = self._validate(self._session._client._exchange("DELETE", self._path, timeout_seconds=request_timeout))
        if value["status"] == "active":
            raise ProtocolError("preview revocation response is still active")
        return value


class PortConnection:
    """Full duplex native tunnel, with one reader and one writer and no output queue.

    write accepts one 1..16384-byte block. Read until a finished frame, including
    after eof. close only closes local transport; use info/cancel to confirm the
    guest's result. A failed/uncertain write is never retried automatically.
    """

    def __init__(self, session: Session, port: int, connection_id: str):
        self._session, self._port, self._id = session, port, connection_id
        self._path = f"/v2/sessions/{session.id}/ports/{port}/connections/{connection_id}"
        self._read_lock, self._write_lock, self._state_lock = threading.Lock(), threading.Lock(), threading.Lock()
        self._http = self._response = self._socket = self._timer = None
        self._closed, self._expired, self._finished = False, False, False
        self._write_eof, self._read_eof = False, False
        self._written, self._received, self._maximum = 0, 0, _PORT_MAX_BYTES

    @property
    def id(self) -> str:
        return self._id

    @property
    def port(self) -> int:
        return self._port

    def _open(self, limits: dict[str, int], request_timeout: float | None) -> None:
        client = self._session._client
        self._maximum = limits["max_bytes"]
        deadline = time.monotonic() + limits["timeout_ms"] / 1000
        timeout = min(client._timeout, request_timeout or client._timeout, limits["timeout_ms"] / 1000)
        connection = http.client.HTTPSConnection(client._host, client._port, context=client._tls_context, timeout=timeout)
        self._http = connection
        self._timer = threading.Timer(limits["timeout_ms"] / 1000, self._expire)
        self._timer.daemon = True
        self._timer.start()
        handshake_timer = threading.Timer(timeout, self._expire)
        handshake_timer.daemon = True
        handshake_timer.start()
        try:
            connection.connect()
            self._socket = connection.sock
            self._check_stream()
            body = json.dumps(limits, separators=(",", ":")).encode("ascii")
            connection.request("POST", self._path, body, {"Authorization": "Bearer " + client._token,
                "Content-Type": "application/json", "Content-Length": str(len(body)),
                "Connection": "Upgrade", "Upgrade": "osv-port/1"})
            response = self._response = connection.getresponse()
            if response.status != 101:
                data = response.read(_MAX_ERROR_BYTES + 1)
                if len(data) > _MAX_ERROR_BYTES:
                    raise ProtocolError("port error response exceeds limit")
                if 300 <= response.status < 400:
                    raise ProtocolError("server redirected a port request")
                try:
                    code = json.loads(data).get("code", "api_error")
                except (ValueError, AttributeError):
                    code = "api_error"
                if not isinstance(code, str) or not re.fullmatch(r"[a-z0-9_]{1,64}", code):
                    code = "api_error"
                raise APIError(response.status, code, "port open rejected")
            expected = {"Upgrade": "osv-port/1", "X-OSV-Session-ID": self._session.id,
                        "X-OSV-Connection-ID": self.id, "X-OSV-Port": str(self.port)}
            if (any(len(response.headers.get_all(key, [])) != 1 or response.getheader(key) != value for key, value in expected.items()) or
                    "upgrade" not in [item.strip().lower() for item in response.getheader("Connection", "").split(",")] or
                    response.version != 11 or connection.sock is None):
                raise ProtocolError("invalid port upgrade binding")
            self._socket = connection.sock
            self._socket.settimeout(None)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutException("port connection deadline elapsed")
            self._check_stream()
        except (OSError, http.client.HTTPException):
            self.close()
            connection.close()
            if self._expired:
                raise TimeoutException("port open deadline elapsed; query known ID") from None
            raise TransportError("port open transport failed") from None
        except Exception:
            self.close()
            connection.close()
            raise
        finally:
            handshake_timer.cancel()

    def _expire(self) -> None:
        with self._state_lock:
            if self._closed:
                return
            self._expired = True
        self.close()

    def close(self) -> None:
        """Close local transport. This does not assert confirmed guest cleanup."""
        with self._state_lock:
            if self._closed:
                return
            self._closed = True
        if self._timer is not None:
            self._timer.cancel()
        sock = self._socket or (self._http.sock if self._http is not None else None)
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if self._response is not None:
            self._response.close()
        if self._http is not None:
            self._http.close()

    def _check_stream(self) -> None:
        if self._expired:
            raise TimeoutException("port connection deadline elapsed; query known ID")
        if self._closed or self._socket is None:
            raise TransportError("port transport is closed; query known ID")

    def _transport_failure(self) -> None:
        self.close()
        self._check_stream()

    def write(self, data: bytes) -> None:
        if not isinstance(data, bytes) or not 1 <= len(data) <= _PORT_FRAME_BYTES:
            raise ConfigurationError("port DATA must be 1..16384 bytes")
        self._send(1, data)

    def close_write(self) -> None:
        self._send(2, b"")

    def _send(self, kind: int, data: bytes) -> None:
        if not self._write_lock.acquire(blocking=False):
            raise ConfigurationError("port write already in progress")
        try:
            self._check_stream()
            with self._state_lock:
                if self._write_eof or len(data) > self._maximum - self._written:
                    raise ConfigurationError("port write is closed or exceeds byte limit")
                self._written += len(data)
                self._write_eof = kind == 2
            try:
                self._socket.sendall(struct.pack(">BI", kind, len(data)) + data)
            except OSError:
                self._transport_failure()
        finally:
            self._write_lock.release()

    def read_frame(self) -> PortFrame:
        if not self._read_lock.acquire(blocking=False):
            raise ConfigurationError("port read already in progress")
        try:
            self._check_stream()
            def exact(size: int) -> bytes:
                data = bytearray()
                while len(data) < size:
                    chunk = self._response.fp.read(size - len(data))
                    if not chunk:
                        self._transport_failure()
                    data.extend(chunk)
                return bytes(data)
            try:
                kind, size = struct.unpack(">BI", exact(5))
                if kind == 1 and not self._read_eof and 1 <= size <= min(_PORT_FRAME_BYTES, self._maximum - self._received):
                    data = exact(size)
                    self._received += size
                    return PortFrame("data", data)
                if kind == 2 and size == 0 and not self._read_eof:
                    self._read_eof = True
                    return PortFrame("eof")
                if kind == 4 and 1 <= size <= 4096:
                    payload = exact(size)
                    try:
                        info = _port_info(json.loads(payload.decode("utf-8")), self.id, self.port, self._maximum)
                    except (ValueError, TypeError):
                        raise ProtocolError("invalid port terminal JSON") from None
                    with self._state_lock:
                        valid = (info["status"] in ("completed", "cancelled", "failed") and
                                 info["received_bytes"] == self._received and info["sent_bytes"] <= self._written and
                                 (info["status"] != "completed" or self._read_eof and self._write_eof and info["sent_bytes"] == self._written))
                    if not valid:
                        raise ProtocolError("invalid port terminal proof")
                    self._finished = True
                    self.close()
                    return PortFrame("finished", info=info)
                raise ProtocolError("invalid port frame")
            except (OSError, ValueError, http.client.HTTPException):
                self._transport_failure()
            except ProtocolError:
                self.close()
                raise
        finally:
            self._read_lock.release()

    def _control(self, method: str, request_timeout: float | None) -> dict[str, Any]:
        value = self._session._client._exchange(method, self._path, accepted=(202,) if method == "DELETE" else (200,),
                                                timeout_seconds=_code_timeout(request_timeout))
        if value.get("session_id") != self._session.id:
            raise ProtocolError("port control session mismatch")
        return _port_info(value.get("connection"), self.id, self.port, self._maximum)

    def info(self, *, request_timeout: float | None = None) -> dict[str, Any]:
        return self._control("GET", request_timeout)

    def cancel(self, *, request_timeout: float | None = None) -> dict[str, Any]:
        return self._control("DELETE", request_timeout)

    def __enter__(self) -> PortConnection:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req: request.Request, fp: Any, code: int,
                         msg: str, headers: Any, newurl: str) -> None:
        return None


@dataclass(frozen=True)
class InputFile:
    path: str
    data: bytes
    mode: int = 0o444

    def payload(self) -> dict[str, Any]:
        if (not isinstance(self.path, str) or not self.path or
                self.path.startswith("/") or "\\" in self.path or
                any(ord(char) < 32 or ord(char) == 127 for char in self.path) or
                posixpath.normpath(self.path) != self.path or
                self.path in (".", "..") or self.path.startswith("../")):
            raise ConfigurationError("input file path must be a clean relative path")
        if not isinstance(self.data, bytes):
            raise ConfigurationError("input file data must be bytes")
        if type(self.mode) is not int or self.mode not in (0, 0o444):
            raise ConfigurationError("input file mode must be 0 or 0444")
        return {"path": self.path,
                "data": base64.b64encode(self.data).decode("ascii"),
                "mode": self.mode}


def _input_payload(items: tuple[InputFile, ...] | list[InputFile]) -> list[dict[str, Any]]:
    if not isinstance(items, (tuple, list)) or len(items) > 64:
        raise ConfigurationError("input_files exceed 64 files")
    if any(not isinstance(item, InputFile) for item in items):
        raise ConfigurationError("input_files must contain InputFile values")
    if any(not isinstance(item.data, bytes) for item in items):
        raise ConfigurationError("input file data must be bytes")
    if sum(len(item.data) for item in items) > 512 * 1024:
        raise ConfigurationError("input_files exceed 512 KiB")
    paths: set[str] = set()
    result = []
    for item in items:
        encoded = item.payload()
        if item.path in paths:
            raise ConfigurationError("duplicate input file path")
        paths.add(item.path)
        result.append(encoded)
    return result


@dataclass(frozen=True)
class JobRequest:
    entrypoint: str
    args: tuple[str, ...] = ()
    memory_mib: int | None = None
    vcpus: int | None = None
    timeout_ms: int | None = None
    network: str = "none"
    input_files: tuple[InputFile, ...] = ()
    environment: dict[str, str] | None = None
    stdin: bytes | None = None
    cwd: str | None = None

    def payload(self) -> dict[str, Any]:
        if not isinstance(self.entrypoint, str) or not self.entrypoint:
            raise ConfigurationError("entrypoint is required")
        if self.network not in ("none", "proxy"):
            raise UnsupportedCapability("network must be none or proxy")
        if not isinstance(self.args, (tuple, list)) or len(self.args) > 64 or any(
                not isinstance(arg, str) for arg in self.args):
            raise ConfigurationError("args must contain at most 64 strings")
        if sum(len(arg.encode("utf-8")) for arg in self.args) > 32 * 1024:
            raise ConfigurationError("argument bytes exceed 32 KiB")
        files = _input_payload(self.input_files)
        payload: dict[str, Any] = {"entrypoint": self.entrypoint,
                                   "args": list(self.args), "network": self.network}
        for key, value in (("memory_mib", self.memory_mib), ("vcpus", self.vcpus),
                           ("timeout_ms", self.timeout_ms)):
            if value is not None:
                if type(value) is not int or value <= 0:
                    raise ConfigurationError(f"{key} must be a positive integer")
                payload[key] = value
        if files:
            payload["input_files"] = files
        if self.environment is not None:
            if not isinstance(self.environment, dict) or len(self.environment) > 32:
                raise ConfigurationError("environment exceeds 32 entries")
            total = 0
            for name, value in self.environment.items():
                if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) or
                        len(name) > 64 or
                        not isinstance(value, str) or "\x00" in value):
                    raise ConfigurationError("invalid environment name or value")
                try:
                    encoded = value.encode("utf-8")
                except UnicodeError:
                    raise ConfigurationError("invalid environment value") from None
                if len(encoded) > 1024:
                    raise ConfigurationError("environment value exceeds 1024 bytes")
                total += len(name) + len(encoded)
            if total > 8192:
                raise ConfigurationError("environment exceeds 8192 bytes")
            if self.environment:
                payload["environment"] = self.environment
        if self.cwd is not None:
            try:
                valid_cwd = (isinstance(self.cwd, str) and self.cwd.startswith("/") and
                             len(self.cwd.encode("utf-8")) <= 1024 and
                             not any(unicodedata.category(ch) == "Cc" for ch in self.cwd))
            except UnicodeError:
                valid_cwd = False
            if not valid_cwd:
                raise ConfigurationError("cwd must be a guest absolute path")
            payload["cwd"] = self.cwd
        if self.stdin is not None:
            if not isinstance(self.stdin, bytes) or len(self.stdin) > 16384:
                raise ConfigurationError("stdin must be at most 16 KiB of bytes")
            payload["stdin"] = base64.b64encode(self.stdin).decode("ascii")
        return payload


@dataclass(frozen=True)
class TemplateSelector:
    backend: str
    artifact_manifest_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.backend, str) or not self.backend:
            raise ConfigurationError("template backend is required")
        if (not isinstance(self.artifact_manifest_sha256, str) or
                not _DIGEST.fullmatch(self.artifact_manifest_sha256)):
            raise ConfigurationError("template digest must be lowercase SHA-256")


@dataclass(frozen=True)
class JobResult:
    id: str
    state: str
    backend: str
    exit_code: int
    timed_out: bool
    duration_ms: int
    output: str
    output_truncated: bool
    protocol_ok: bool
    guest_result: dict[str, Any] | None
    startup_mode: str | None = None
    template_id: str | None = None
    artifact_manifest_sha256: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.state == "succeeded" and self.protocol_ok

    @classmethod
    def from_payload(cls, value: dict[str, Any]) -> JobResult:
        expected = {"id": str, "state": str, "backend": str, "exit_code": int,
                    "timed_out": bool, "duration_ms": int, "output": str,
                    "output_truncated": bool, "protocol_ok": bool}
        for key, kind in expected.items():
            if key not in value or type(value[key]) is not kind:
                raise ProtocolError(f"job result has invalid {key}")
        guest = value.get("guest_result")
        if guest is not None and not isinstance(guest, dict):
            raise ProtocolError("job result has invalid guest_result")
        if "startup_mode" in value and value["startup_mode"] not in ("warm", "cold"):
            raise ProtocolError("job result has invalid startup_mode")
        digest = value.get("artifact_manifest_sha256")
        template_id = value.get("template_id")
        if digest is not None and (not isinstance(digest, str) or not _DIGEST.fullmatch(digest)):
            raise ProtocolError("job result has invalid template digest")
        if template_id is not None and (not isinstance(template_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", template_id)):
            raise ProtocolError("job result has invalid template id")
        return cls(**{key: value[key] for key in expected}, guest_result=guest, startup_mode=value.get("startup_mode"),
                   template_id=template_id, artifact_manifest_sha256=digest)


@dataclass(frozen=True)
class SessionRequest:
    memory_mib: int | None = None
    vcpus: int | None = None
    ttl_ms: int | None = None
    network: str = "none"
    input_files: tuple[InputFile, ...] = ()

    def payload(self) -> dict[str, Any]:
        if self.network not in ("none", "proxy"):
            raise UnsupportedCapability("network must be none or proxy")
        result: dict[str, Any] = {"network": self.network}
        for key, value in (("memory_mib", self.memory_mib), ("vcpus", self.vcpus)):
            if value is not None:
                if type(value) is not int or value <= 0:
                    raise ConfigurationError(f"{key} must be a positive integer")
                result[key] = value
        if self.ttl_ms is not None:
            if type(self.ttl_ms) is not int or not 1000 <= self.ttl_ms <= 300000:
                raise ConfigurationError("ttl_ms must be in [1000,300000]")
            result["ttl_ms"] = self.ttl_ms
        files = _input_payload(self.input_files)
        if files:
            result["input_files"] = files
        return result


@dataclass(frozen=True)
class SessionCommand:
    entrypoint: str
    args: tuple[str, ...] = ()
    timeout_ms: int | None = None
    environment: dict[str,str] | None = None
    cwd: str | None = None
    interactive_stdin: bool = False

    def payload(self) -> dict[str, Any]:
        if not isinstance(self.entrypoint, str) or not self.entrypoint:
            raise ConfigurationError("entrypoint is required")
        if not isinstance(self.args, (tuple, list)) or len(self.args) > 64 or any(
                not isinstance(arg, str) for arg in self.args):
            raise ConfigurationError("args must contain at most 64 strings")
        if sum(len(arg.encode("utf-8")) for arg in self.args) > 32 * 1024:
            raise ConfigurationError("argument bytes exceed 32 KiB")
        if type(self.interactive_stdin) is not bool:raise ConfigurationError("interactive_stdin must be boolean")
        result: dict[str, Any] = {"entrypoint": self.entrypoint, "args": list(self.args)}
        if self.interactive_stdin:result["interactive_stdin"]=True
        if self.timeout_ms is not None:
            if type(self.timeout_ms) is not int or self.timeout_ms <= 0:
                raise ConfigurationError("timeout_ms must be a positive integer")
            result["timeout_ms"] = self.timeout_ms
        env=self.environment
        if env is not None:
            if not isinstance(env,dict) or len(env)>32:
                raise ConfigurationError("environment exceeds 32 entries")
            total=0
            for name,value in env.items():
                if (not isinstance(name,str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}",name) or
                        not isinstance(value,str) or "\0" in value or len(value.encode("utf-8"))>1024):
                    raise ConfigurationError("invalid environment name or value")
                total+=len(name)+len(value.encode("utf-8"))
            if total>8192:raise ConfigurationError("environment exceeds 8 KiB")
            if env:result["environment"]=dict(env)
        if self.cwd is not None:
            if (not isinstance(self.cwd,str) or not self.cwd.startswith("/") or len(self.cwd.encode("utf-8"))>1024 or
                    any(unicodedata.category(ch)=="Cc" for ch in self.cwd)):
                raise ConfigurationError("cwd must be a guest absolute path")
            result["cwd"]=self.cwd
        return result


@dataclass(frozen=True)
class SessionInfo:
    id: str
    state: str
    backend: str
    artifact_manifest_sha256: str
    created_at: str
    expires_at: str
    max_expires_at: str | None = None
    memory_mib: int | None = None
    vcpus: int | None = None
    guest_protocol: str | None = None
    network: str = "none"
    startup_mode: str | None = None

    @classmethod
    def from_payload(cls, value: dict[str, Any]) -> SessionInfo:
        if value.get("network", "none") not in ("none", "proxy") or value.get("startup_mode") not in (None, "cold", "warm"):
            raise ProtocolError("invalid session network or startup mode")
        for key in ("id", "state", "backend", "artifact_manifest_sha256",
                    "created_at", "expires_at"):
            if not isinstance(value.get(key), str) or not value[key]:
                raise ProtocolError(f"session info has invalid {key}")
        if (not _SESSION_ID.fullmatch(value["id"]) or value["state"] != "running" or
                value["backend"] != "firecracker-linux" or
                not _DIGEST.fullmatch(value["artifact_manifest_sha256"])):
            raise ProtocolError("session info has invalid identity or template")
        for key in ("memory_mib","vcpus"):
            if key in value and (type(value[key]) is not int or value[key]<=0):raise ProtocolError("invalid session resource metadata")
        if "guest_protocol" in value and value["guest_protocol"] not in ("fc-agent/v2","fc-agent/v3"):raise ProtocolError("invalid session guest protocol")
        if "max_expires_at" in value and not isinstance(value["max_expires_at"],str):raise ProtocolError("invalid session lifetime bound")
        return cls(**{key: value[key] for key in cls.__dataclass_fields__ if key in value})


@dataclass(frozen=True)
class ArtifactInfo:
    """An immutable tar cached by this session; delete explicitly after use."""
    id: str
    session_id: str
    path: str
    source_kind: str
    format: str
    size: int
    sha256: str
    entries: int
    files: int
    payload_bytes: int

    @classmethod
    def from_payload(cls, value: Any, session_id: str) -> ArtifactInfo:
        if not isinstance(value, dict):
            raise ProtocolError("invalid artifact metadata")
        try:
            Session._check_file_path(value.get("path"), allow_root=True)
        except ConfigurationError:
            raise ProtocolError("invalid artifact source path") from None
        if (not isinstance(value.get("id"), str) or not _SESSION_ID.fullmatch(value["id"]) or
                value.get("session_id") != session_id or value.get("format") != "tar" or
                value.get("source_kind") not in ("file", "directory") or
                value["path"] == "/workspace" and value["source_kind"] != "directory" or
                type(value.get("size")) is not int or not 2048 <= value["size"] <= 32 << 20 or value["size"] % 512 or
                not isinstance(value.get("sha256"), str) or not _DIGEST.fullmatch(value["sha256"]) or
                any(type(value.get(key)) is not int for key in ("entries", "files", "payload_bytes")) or
                not 0 <= value["files"] <= value["entries"] <= 1024 or
                not 0 <= value["payload_bytes"] <= value["size"] or
                value["files"] == 0 and value["payload_bytes"] != 0 or
                value["source_kind"] == "file" and (value["files"] != 1 or value["entries"] != 1)):
            raise ProtocolError("invalid artifact metadata binding or limits")
        return cls(**{name: value[name] for name in cls.__dataclass_fields__})


def _artifact_chunk(value: Any, session_id: str, artifact_id: str, offset: int, length: int) -> dict[str, Any]:
    if (not isinstance(value, dict) or value.get("id") != artifact_id or value.get("session_id") != session_id or
            type(value.get("offset")) is not int or value["offset"] != offset or
            type(value.get("total_size")) is not int or not 2048 <= value["total_size"] <= 32 << 20 or value["total_size"] % 512 or
            offset > value["total_size"] or type(value.get("eof")) is not bool or
            any(not isinstance(value.get(key), str) or not _DIGEST.fullmatch(value[key]) for key in ("data_sha256", "archive_sha256")) or
            not isinstance(value.get("data_base64"), str) or len(value["data_base64"]) > 699052):
        raise ProtocolError("invalid artifact chunk binding or limits")
    try:
        data = base64.b64decode(value["data_base64"], validate=True)
    except (ValueError, binascii.Error):
        raise ProtocolError("invalid artifact chunk encoding") from None
    if (base64.b64encode(data).decode("ascii") != value["data_base64"] or
            len(data) != min(length, value["total_size"]-offset) or
            value["eof"] != (offset+len(data) == value["total_size"]) or
            hashlib.sha256(data).hexdigest() != value["data_sha256"]):
        raise ProtocolError("artifact chunk integrity check failed")
    return dict(value)


class Session:
    """Handle for a live session; every operation is independently authenticated."""

    def __init__(self, client: Client, info: SessionInfo):
        self._client = client
        self.id = info.id
        self.created = info
        self.code = CodeContexts(self)
        self.ports = SessionPorts(self)
        self.ml = SessionML(self)

    def capabilities(self, *, request_timeout: float | None = None) -> dict[str, Any]:
        """Capabilities of this already admitted VM, independent of new admission."""
        report = self._client._exchange("GET", "/v2/sessions/" + self.id + "/capabilities",
                                       timeout_seconds=_code_timeout(request_timeout))
        _capability_report(report, TemplateSelector(self.created.backend, self.created.artifact_manifest_sha256))
        if report.get("session_id") != self.id or report.get("artifact_authenticated") is not True:
            raise ProtocolError("session capabilities have invalid owner or authentication")
        return report

    def start_file_watch(self, path: str, *, recursive: bool = False,
                         include_entry: bool = False, timeout_ms: int = 0) -> FileWatchHandle:
        self._check_file_path(path, allow_root=True)
        if type(recursive) is not bool or type(include_entry) is not bool:
            raise ConfigurationError("watch recursive and include_entry must be bool")
        if type(timeout_ms) is not int or not 0 <= timeout_ms <= 600000:
            raise ConfigurationError("watch timeout_ms must be in [0,600000]")
        payload = {"path": path, "recursive": recursive, "include_entry": include_entry,
                   "timeout_ms": timeout_ms}
        info = self._client._exchange("POST", "/v2/sessions/" + self.id + "/watches",
                                      payload, accepted=(201,))
        handle = FileWatchHandle(self, info)
        if any(info[key] != payload[key] for key in ("path", "recursive", "include_entry")):
            raise ProtocolError("watch creation options differ from request")
        return handle

    def list_file_watches(self) -> list[dict[str, Any]]:
        value = self._client._exchange("GET", "/v2/sessions/" + self.id + "/watches")
        infos = value.get("watches")
        if value.get("session_id") != self.id or not isinstance(infos, list) or len(infos) > 16:
            raise ProtocolError("invalid watch list")
        for info in infos:
            _watch_info(info, self.id)
        return infos

    def set_timeout(self,ttl_ms:int)->SessionInfo:
        if type(ttl_ms) is not int or not 1000<=ttl_ms<=300000:raise ConfigurationError("ttl_ms must be in [1000,300000]")
        info=SessionInfo.from_payload(self._client._exchange("POST","/v2/sessions/"+self.id+"/timeout",{"ttl_ms":ttl_ms}))
        if info.id!=self.id:raise ProtocolError("timeout response session mismatch")
        return info

    def start_command(self, command: SessionCommand) -> CommandHandle:
        if not isinstance(command, SessionCommand):
            raise ConfigurationError("start_command requires a SessionCommand")
        info = self._client._exchange("POST", "/v2/sessions/" + self.id + "/commands/start",
                                      command.payload(), accepted=(202,))
        return CommandHandle(self, info)

    def list_commands(self) -> list[dict[str, Any]]:
        value = self._client._exchange("GET", "/v2/sessions/" + self.id + "/commands")
        if value.get("session_id") != self.id or not isinstance(value.get("commands"), list) or len(value["commands"]) > 32:
            raise ProtocolError("command list has invalid session binding")
        for info in value["commands"]:
            _command_info(info, self.id)
        return value["commands"]

    def connect_command(self, command_id: str) -> CommandHandle:
        if not isinstance(command_id, str) or not _SESSION_ID.fullmatch(command_id):
            raise ConfigurationError("command ID must be 24 lowercase hex digits")
        value = self._client._exchange("GET", "/v2/sessions/" + self.id + "/commands/" + command_id)
        handle = CommandHandle(self, value.get("info"))
        if handle.id != command_id:
            raise ProtocolError("command query returned another ID")
        return handle

    def info(self) -> SessionInfo:
        value = SessionInfo.from_payload(self._client._exchange(
            "GET", "/v2/sessions/" + self.id))
        if value.id != self.id:
            raise ProtocolError("session query returned a different ID")
        return value

    def run(self, command: SessionCommand) -> JobResult:
        if not isinstance(command, SessionCommand):
            raise ConfigurationError("session run requires a SessionCommand")
        value = self._client._exchange("POST", "/v2/sessions/" + self.id + "/commands",
                                       command.payload())
        if value.get("session_id") != self.id or not isinstance(value.get("result"), dict):
            raise ProtocolError("session command result has invalid binding")
        return JobResult.from_payload(value["result"])

    def close(self) -> None:
        self._client._exchange("DELETE", "/v2/sessions/" + self.id, accepted=(204,))

    @staticmethod
    def _check_file_path(path: str, allow_root: bool = False) -> None:
        if allow_root and path == "/workspace":
            return
        try:
            valid_length = isinstance(path, str) and len(path.encode("utf-8")) <= len("/workspace/") + 1024
            components = path[len("/workspace/"):].split("/") if isinstance(path, str) else []
            valid_components = all(part and part not in (".", "..") and
                                   len(part.encode("utf-8")) <= 255 for part in components)
        except UnicodeError:
            raise ConfigurationError("file path must be valid UTF-8") from None
        if (not valid_length or not path.startswith("/workspace/") or
                "\\" in path or posixpath.normpath(path) != path or
                any(unicodedata.category(ch) == "Cc" for ch in path) or
                not valid_components):
            raise ConfigurationError("file path must be a clean /workspace path")

    def _file(self, action: str, path: str, data: bytes | None = None,
              metadata: dict[str, str] | None = None) -> tuple[int, bytes | None]:
        self._check_file_path(path)
        payload: dict[str, Any] = {"action": action, "path": path}
        if action == "write":
            if not isinstance(data, bytes) or len(data) > _SESSION_FILE_LIMIT:
                raise ConfigurationError("file data must be bytes at most 512 KiB")
            payload["data_base64"] = base64.b64encode(data).decode("ascii")
            if metadata is not None:
                _check_e2b_metadata(metadata)
                payload["metadata"] = metadata
        elif metadata is not None:
            raise ConfigurationError("metadata is only valid for file writes")
        value = self._client._exchange("POST", "/v2/sessions/" + self.id + "/files", payload)
        if (value.get("session_id") != self.id or value.get("action") != action or
                value.get("path") != path or type(value.get("size")) is not int or
                not 0 <= value["size"] <= _SESSION_FILE_LIMIT or
                "kind" in value or "entries" in value or "created" in value):
            raise ProtocolError("session file result has invalid binding")
        if action == "write":
            if value["size"] != len(data) or "data_base64" in value:
                raise ProtocolError("session file write result is invalid")
            return value["size"], None
        encoded = value.get("data_base64")
        if not isinstance(encoded, str):
            raise ProtocolError("session file read has no data")
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise ProtocolError("session file read has invalid base64") from None
        if (base64.b64encode(decoded).decode("ascii") != encoded or
                len(decoded) != value["size"]):
            raise ProtocolError("session file read has invalid size")
        return value["size"], decoded

    def read_file(self, path: str) -> bytes:
        """Read at most 512 KiB from the current session's /workspace."""
        _, data = self._file("read", path)
        if data is None:
            raise ProtocolError("session file read has no data")
        return data

    def create_artifact(self, path: str = "/workspace", *, request_timeout: float | None = None) -> ArtifactInfo:
        """Create one bounded immutable tar. Never retries a mutating request."""
        self._check_file_path(path, allow_root=True)
        value = self._client._exchange("POST", "/v2/sessions/"+self.id+"/artifacts", {"path": path},
                                       accepted=(201,), timeout_seconds=35.0 if request_timeout is None else _code_timeout(request_timeout))
        info = ArtifactInfo.from_payload(value, self.id)
        if info.path != path:
            raise ProtocolError("artifact response source differs from request")
        return info

    def read_artifact(self, artifact_id: str, offset: int = 0, length: int = 512 << 10,
                      *, request_timeout: float | None = None) -> dict[str, Any]:
        """Read and verify a bounded block; cancellation leaves the VM alive."""
        if not isinstance(artifact_id, str) or not _SESSION_ID.fullmatch(artifact_id):
            raise ConfigurationError("artifact ID must be 24 lowercase hex digits")
        if type(offset) is not int or not 0 <= offset <= 32 << 20 or type(length) is not int or not 1 <= length <= 512 << 10:
            raise ConfigurationError("invalid artifact byte range")
        value = self._client._exchange("POST", "/v2/sessions/"+self.id+"/artifacts/"+artifact_id+"/read",
                                       {"offset": offset, "length": length}, timeout_seconds=_code_timeout(request_timeout))
        return _artifact_chunk(value, self.id, artifact_id, offset, length)

    def download_artifact(self, info: ArtifactInfo, *, request_timeout: float | None = None) -> bytes:
        """Verify block and complete archive digests. Does not extract or delete."""
        if not isinstance(info, ArtifactInfo):
            raise ConfigurationError("download_artifact requires created ArtifactInfo")
        info = ArtifactInfo.from_payload(vars(info), self.id)
        _code_timeout(request_timeout)
        content = bytearray(info.size)
        offset = 0
        while offset < info.size:
            chunk = self.read_artifact(info.id, offset, min(512 << 10, info.size-offset), request_timeout=request_timeout)
            if chunk["total_size"] != info.size or chunk["archive_sha256"] != info.sha256:
                raise ProtocolError("artifact changed between create and download")
            data = base64.b64decode(chunk["data_base64"], validate=True)
            content[offset:offset+len(data)] = data
            offset += len(data)
        if hashlib.sha256(content).hexdigest() != info.sha256:
            raise ProtocolError("complete artifact integrity check failed")
        return bytes(content)

    def delete_artifact(self, artifact_id: str, *, request_timeout: float | None = None) -> None:
        if not isinstance(artifact_id, str) or not _SESSION_ID.fullmatch(artifact_id):
            raise ConfigurationError("artifact ID must be 24 lowercase hex digits")
        self._client._exchange("DELETE", "/v2/sessions/"+self.id+"/artifacts/"+artifact_id,
                               accepted=(204,), timeout_seconds=_code_timeout(request_timeout))

    def write_file(self, path: str, data: bytes,
                   *, metadata: dict[str, str] | None = None) -> int:
        """Atomically write one bounded file and return its byte count."""
        size, _ = self._file("write", path, data, metadata)
        return size

    def _file_metadata(self, action: str, path: str, destination: str | None = None) -> dict[str, Any]:
        self._check_file_path(path, allow_root=action in ("list", "stat", "info"))
        payload = {"action": action, "path": path}
        if destination is not None:
            self._check_file_path(destination)
            payload["destination"] = destination
        value = self._client._exchange("POST", "/v2/sessions/" + self.id + "/files",
                                       payload)
        if (value.get("session_id") != self.id or value.get("action") != action or
                value.get("path") != path or type(value.get("size")) is not int or
                value["size"] < 0 or "data_base64" in value or
                value.get("destination") != destination):
            raise ProtocolError("session file metadata result has invalid binding")
        return value

    def list_files(self, path: str = "/workspace") -> list[str]:
        """List at most 256 direct UTF-8 names in a workspace directory."""
        value = self._file_metadata("list", path)
        entries = value.get("entries")
        if (not isinstance(entries, list) or len(entries) > _SESSION_FILE_LIST_LIMIT or
                value["size"] != len(entries) or "kind" in value or "created" in value):
            raise ProtocolError("session file list is invalid")
        total = 0
        previous = ""
        for name in entries:
            if not isinstance(name, str):
                raise ProtocolError("session file list has invalid name")
            try:
                name_size = len(name.encode("utf-8"))
            except UnicodeError:
                raise ProtocolError("session file list has invalid UTF-8") from None
            if (not name or name in (".", "..") or "/" in name or "\\" in name or
                    name_size > 255 or any(unicodedata.category(ch) == "Cc" for ch in name) or
                    (previous and previous >= name)):
                raise ProtocolError("session file list has invalid name")
            total += name_size
            if total > _SESSION_FILE_LIST_NAME_BYTES_LIMIT:
                raise ProtocolError("session file list exceeds 64 KiB")
            previous = name
        return entries

    def stat_file(self, path: str) -> dict[str, int | str]:
        """Return kind and size for a regular file or directory."""
        value = self._file_metadata("stat", path)
        kind = value.get("kind")
        size = value["size"]
        if ("entries" in value or "created" in value or
                not ((kind == "file" and size <= 1 << 40) or
                     (kind == "directory" and size == 0))):
            raise ProtocolError("session file stat is invalid")
        return {"kind": kind, "size": size}

    def delete_file(self, path: str) -> None:
        """Delete one regular file without following links."""
        value = self._file_metadata("delete", path)
        if value["size"] != 0 or "kind" in value or "entries" in value or "created" in value:
            raise ProtocolError("session file delete result is invalid")

    def make_dir(self, path: str) -> bool:
        """Create at most 16 confined directory components; return whether final was new."""
        self._check_file_path(path)
        if len(path.removeprefix("/workspace/").split("/")) > 16:
            raise ConfigurationError("directory depth exceeds 16 components")
        value = self._file_metadata("mkdir", path)
        if (value["size"] != 0 or "kind" in value or "entries" in value or
                type(value.get("created")) is not bool):
            raise ProtocolError("session directory result is invalid")
        return value["created"]

    def rename_file(self, path: str, destination: str) -> dict[str, Any]:
        """Move a workspace entry and return its destination metadata."""
        self._check_file_path(destination)
        value = self._file_metadata("rename", path, destination)
        info = value.get("info")
        E2BEntryInfo.from_payload(info, destination)
        if (value.get("kind") != info["type"] or "entries" in value or "created" in value or
                value["size"] != (info["size"] if info["type"] == "file" else 0)):
            raise ProtocolError("rename result has invalid metadata")
        return info

    def remove_path(self, path: str) -> None:
        """Recursively remove a workspace entry, leaving symlink targets untouched."""
        value = self._file_metadata("remove", path)
        if value["size"] != 0 or any(key in value for key in ("kind", "entries", "created", "info", "entry_infos")):
            raise ProtocolError("recursive remove result is invalid")


def _command_info(value: Any, session_id: str) -> dict[str, Any]:
    if (not isinstance(value, dict) or value.get("session_id") != session_id or
            not isinstance(value.get("id"), str) or not _SESSION_ID.fullmatch(value["id"]) or
            value.get("state") not in ("running", "succeeded", "guest_error", "timed_out", "cancelled", "failed")):
        raise ProtocolError("command metadata has invalid binding or state")
    if "pid" in value and (type(value["pid"]) is not int or not 1<value["pid"]<=1<<30):
        raise ProtocolError("invalid guest command PID")
    return value


@dataclass(frozen=True)
class CommandEvent:
    sequence: int
    stream: str | None = None
    data: bytes = b""
    result: JobResult | None = None


class CommandHandle:
    """A session-owned background command; observing it never re-executes it."""

    def __init__(self, session: Session, info: dict[str, Any]):
        self._session = session
        self.created = _command_info(info, session.id)
        self.id = info["id"]
        self._path = "/v2/sessions/" + session.id + "/commands/" + self.id

    def _input_receipt(self, value, sequence=None):
        if (not isinstance(value,dict) or value.get("session_id")!=self._session.id or value.get("command_id")!=self.id or
                type(value.get("sequence")) is not int or not 1<=value["sequence"]<=256 or
                sequence is not None and value["sequence"]!=sequence or value.get("state") not in ("pending","delivered","closed","failed") or
                type(value.get("written_bytes")) is not int or not 0<=value["written_bytes"]<=16384 or type(value.get("closed")) is not bool or
                value.get("state")=="failed" and value.get("error_code") not in ("stdin_closed","stdin_io","command_exited")):
            raise ProtocolError("invalid stdin receipt binding or result")
        return value

    def submit_stdin(self, data: bytes = b"", *, close: bool = False, request_timeout=None):
        if request_timeout is not None and (type(request_timeout) not in (int,float) or not math.isfinite(request_timeout) or request_timeout<=0):raise ConfigurationError("stdin request timeout must be positive seconds")
        if not isinstance(data,bytes) or len(data)>16384 or type(close) is not bool or close and data:
            raise ConfigurationError("stdin requires at most 16 KiB of bytes, or an empty close")
        value=self._session._client._exchange("POST",self._path+"/stdin",{"data_base64":base64.b64encode(data).decode("ascii"),"close":close},accepted=(202,),timeout_seconds=request_timeout)
        return self._input_receipt(value)

    def poll_stdin(self, sequence: int, request_timeout=None):
        if request_timeout is not None and (type(request_timeout) not in (int,float) or not math.isfinite(request_timeout) or request_timeout<=0):raise ConfigurationError("stdin request timeout must be positive seconds")
        if type(sequence) is not int or not 1<=sequence<=256:raise ConfigurationError("invalid stdin sequence")
        return self._input_receipt(self._session._client._exchange("GET",self._path+"/stdin/"+str(sequence),timeout_seconds=request_timeout),sequence)

    def _send_input(self,data,close,request_timeout):
        duration=self._session._client._timeout if request_timeout is None else request_timeout
        if type(duration) not in (int,float) or not math.isfinite(duration) or duration<=0:raise ConfigurationError("stdin request timeout must be positive seconds")
        deadline=time.monotonic()+duration
        try:value=self.submit_stdin(data,close=close,request_timeout=duration)
        except TransportError as error:
            if time.monotonic()>=deadline:raise TimeoutException("stdin submission timed out; delivery outcome uncertain; input was not retried") from error
            raise
        sequence=value["sequence"]
        while value["state"]=="pending":
            if time.monotonic()>=deadline:raise TimeoutException("stdin delivery observation timed out; query sequence "+str(sequence)+"; input was not retried")
            time.sleep(min(0.01,max(0,deadline-time.monotonic())))
            remaining=deadline-time.monotonic()
            if remaining<=0:raise TimeoutException("stdin delivery observation timed out; query sequence "+str(sequence)+"; input was not retried")
            try:value=self.poll_stdin(sequence,request_timeout=remaining)
            except TransportError as error:
                if time.monotonic()>=deadline:raise TimeoutException("stdin delivery observation timed out; query sequence "+str(sequence)+"; input was not retried") from error
                raise
        if value["state"]=="failed":raise APIError(409,value["error_code"],"command stdin delivery failed")
        if value["written_bytes"]!=len(data) or value["closed"]!=close:raise ProtocolError("stdin confirmation differs from submitted input")

    def send_stdin(self,data: bytes,request_timeout=None):
        self._send_input(data,False,request_timeout)

    def close_stdin(self,request_timeout=None):
        self._send_input(b"",True,request_timeout)

    def poll(self, after: int = 0) -> dict[str, Any]:
        if type(after) is not int or not 0 <= after <= 256:
            raise ConfigurationError("command cursor must be in [0,256]")
        value = self._session._client._exchange("GET", self._path + "?after=" + str(after))
        if _command_info(value.get("info"), self._session.id)["id"] != self.id:
            raise ProtocolError("command result has invalid command ID")
        return value

    def kill(self) -> bool:
        value = self._session._client._exchange("DELETE", self._path)
        if type(value.get("killed")) is not bool:
            raise ProtocolError("command kill returned invalid result")
        return value["killed"]

    def events(self, after: int = 0, *, timeout_ms: int | None = None):
        if type(after) is not int or not 0 <= after <= 256:
            raise ConfigurationError("command cursor must be in [0,256]")
        query="?after="+str(after)
        if timeout_ms is not None:
            if type(timeout_ms) is not int or not 0 <= timeout_ms <= 86400000:
                raise ConfigurationError("invalid command observation timeout")
            query+="&timeout_ms="+str(timeout_ms)
        sequence = after
        total = 0
        for kind, value in self._session._client._events(self._path + "/events" + query):
            if kind == "output":
                if (not isinstance(value, dict) or value.get("session_id") != self._session.id or
                        value.get("command_id") != self.id or type(value.get("sequence")) is not int or
                        value["sequence"] != sequence + 1 or value["sequence"] > 256 or
                        value.get("stream") not in ("stdout", "stderr")):
                    raise ProtocolError("invalid command output event binding or sequence")
                try:
                    data = base64.b64decode(value["data_base64"], validate=True)
                except (KeyError, ValueError, TypeError, binascii.Error):
                    raise ProtocolError("invalid command output bytes") from None
                total += len(data)
                if not 0 < len(data) <= 4096 or total > 65536 or base64.b64encode(data).decode("ascii") != value["data_base64"]:
                    raise ProtocolError("command output exceeds its budget or is noncanonical")
                sequence += 1
                yield CommandEvent(sequence, value["stream"], data)
            elif kind == "timeout":
                if (value.get("session_id")!=self._session.id or value.get("command_id")!=self.id or value.get("next_sequence")!=sequence):
                    raise ProtocolError("invalid command timeout binding")
                raise TimeoutException("command observation timed out; process was not cancelled")
            elif kind == "result":
                if (_command_info(value.get("info"), self._session.id)["id"] != self.id or
                        value.get("complete") is not True or value.get("next_sequence") != sequence):
                    raise ProtocolError("invalid command terminal binding or cursor")
                result = value.get("result")
                if not isinstance(result, dict) or result.get("session_id") != self._session.id:
                    raise TransportError("command did not return a confirmed result")
                parsed = JobResult.from_payload(result.get("result", {}))
                if parsed.id != self.id or not parsed.protocol_ok:
                    raise ProtocolError("command terminal result has invalid identity")
                yield CommandEvent(sequence, result=parsed)
                return
            else:
                raise ProtocolError("unsupported command stream event")
        raise TransportError("command event stream ended without a terminal result")

    def wait(self) -> JobResult:
        for event in self.events():
            if event.result is not None:
                return event.result
        raise TransportError("command has no terminal result")


@dataclass(frozen=True)
class NetworkFetchResult:
    request_id: str
    url: str
    status: int
    headers: dict[str, list[str]]
    body: bytes
    redirects: int
    duration_ms: int
    request_bytes: int
    response_bytes: int

    @classmethod
    def from_payload(cls, value: dict[str, Any]) -> NetworkFetchResult:
        if (value.get("protocol") != "osv-sandbox-network-fetch/v1" or
                not isinstance(value.get("request_id"), str) or not _SESSION_ID.fullmatch(value["request_id"]) or
                not isinstance(value.get("url"), str) or not isinstance(value.get("headers"), dict) or
                type(value.get("status")) is not int or not 100 <= value["status"] <= 599 or
                any(not isinstance(k, str) or not isinstance(v, list) or any(not isinstance(x, str) for x in v)
                    for k, v in value["headers"].items())):
            raise ProtocolError("invalid network fetch identity/status/headers")
        for key in ("body_bytes", "redirects", "duration_ms", "request_bytes", "response_bytes"):
            if type(value.get(key)) is not int or value[key] < 0:
                raise ProtocolError("invalid network fetch counters")
        encoded = value.get("body_base64")
        if not isinstance(encoded, str) or len(encoded) > 699052:
            raise ProtocolError("invalid network fetch body")
        try:
            body = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise ProtocolError("invalid network fetch base64") from None
        if (base64.b64encode(body).decode("ascii") != encoded or len(body) != value["body_bytes"] or
                len(body) > 524288 or value["redirects"] > 5 or not len(body) <= value["response_bytes"] <= 524288 or
                value["request_bytes"] > 6 * 262144):
            raise ProtocolError("inconsistent network fetch bounds")
        return cls(value["request_id"], value["url"], value["status"], value["headers"], body,
                   value["redirects"], value["duration_ms"], value["request_bytes"], value["response_bytes"])


class Client:
    """Authenticated client for one sandbox API endpoint."""

    def __init__(self, base_url: str, *, token: str, cert_file: str,
                 key_file: str, ca_file: str | None = None,
                 request_timeout_seconds: float = 360.0):
        try:
            parsed = parse.urlsplit(base_url)
            host = parsed.hostname
            port = parsed.port
        except (TypeError, ValueError):
            raise ConfigurationError("base_url must be an HTTPS origin") from None
        if (parsed.scheme != "https" or not parsed.netloc or
                not host or (port is not None and port < 1) or
                parsed.username is not None or parsed.password is not None or
                parsed.path not in ("", "/") or parsed.query or parsed.fragment):
            raise ConfigurationError("base_url must be an HTTPS origin")
        if (not isinstance(token, str) or not token or
                any(ord(char) < 33 or ord(char) > 126 for char in token)):
            raise ConfigurationError("a non-empty bearer token is required")
        if not cert_file or not key_file:
            raise ConfigurationError("client certificate and key are required")
        if (type(request_timeout_seconds) not in (int, float) or
                not math.isfinite(request_timeout_seconds) or request_timeout_seconds <= 0):
            raise ConfigurationError("request timeout must be positive")
        try:
            context = ssl.create_default_context(cafile=ca_file)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        except (OSError, ssl.SSLError) as exc:
            raise ConfigurationError(f"cannot load TLS credentials ({type(exc).__name__})") from None
        self._origin = base_url.rstrip("/")
        self._token = token
        self._timeout = float(request_timeout_seconds)
        context.set_alpn_protocols(["http/1.1"])
        self._tls_context = context
        self._host, self._port = host, port or 443
        # Ignore ambient proxy variables so bearer and mTLS stay on this origin.
        self._opener = request.build_opener(request.ProxyHandler({}), _NoRedirect(),
                                            request.HTTPSHandler(context=context))

    def get_inference_bill(self, task_id: str, *, request_timeout: float | None = None) -> dict[str, Any]:
        """Read persistent history, including after the session or permission ends."""
        _inference_id(task_id, "task")
        value = self._exchange("GET", "/v2/ml/bills/" + task_id,
                               timeout_seconds=_code_timeout(request_timeout))
        return _inference_bill(value, task_id)

    def capabilities(self, *, template: TemplateSelector | None = None,
                     request_timeout_seconds: float | None = None) -> dict[str, Any]:
        path = "/v1/capabilities"
        if template is not None:
            if not isinstance(template, TemplateSelector):
                raise ConfigurationError("template must be a TemplateSelector")
            path += "?" + parse.urlencode({"backend": template.backend,
                                          "artifact_manifest_sha256": template.artifact_manifest_sha256})
        if request_timeout_seconds is not None:
            _code_timeout(request_timeout_seconds)
        report = self._exchange("GET", path, **({"timeout_seconds": request_timeout_seconds} if request_timeout_seconds is not None else {}))
        _capability_report(report, template)
        return report

    def templates(self) -> dict[str, Any]:
        """Discover signed, tenant-visible templates; availability can change."""
        value = self._exchange("GET", "/v2/templates")
        entries = value.get("templates")
        default = value.get("default_template_id")
        if (value.get("protocol") != "osv-sandbox-template-catalog/v1" or
                not isinstance(entries, list) or len(entries) > 16 or not isinstance(default, str)):
            raise ProtocolError("invalid template catalog")
        seen = set()
        selectors = set()
        for entry in entries:
            if (not isinstance(entry, dict) or not isinstance(entry.get("id"), str) or
                    not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", entry["id"]) or
                    entry["id"] in seen or type(entry.get("available")) is not bool or
                    not isinstance(entry.get("capabilities"), dict)):
                raise ProtocolError("invalid or duplicate template entry")
            cap = entry["capabilities"]
            key = (cap.get("backend"), cap.get("artifact_manifest_sha256"))
            if (cap.get("protocol") != "osv-sandbox-capabilities/v1" or
                    cap.get("artifact_authenticated") is not True or not isinstance(key[0], str) or
                    not isinstance(key[1], str) or not _DIGEST.fullmatch(key[1]) or key in selectors or
                    not isinstance(cap.get("methods"), list) or not isinstance(cap.get("allowed_entrypoints"), list)):
                raise ProtocolError("invalid authenticated template capability")
            seen.add(entry["id"])
            selectors.add(key)
        if default and default not in seen:
            raise ProtocolError("template default is not visible in catalog")
        return value

    def doctor(self) -> dict[str, Any]:
        report = self._exchange("GET", "/v1/doctor", accepted=(200, 503))
        if type(report.get("ready")) is not bool or not isinstance(report.get("checks"), list):
            raise ProtocolError("incomplete doctor response")
        return report

    def fetch_network(self, url: str, *, method: str = "GET", body: bytes | None = None,
                      headers: dict[str, str] | None = None, follow_redirects: bool = False,
                      timeout_ms: int | None = None) -> NetworkFetchResult:
        """Use the configured tenant egress service; never opens this URL locally."""
        if (not isinstance(url, str) or not url or len(url.encode("utf-8")) > 8192 or
                method not in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS") or
                body is not None and not isinstance(body, bytes) or type(follow_redirects) is not bool or
                headers is not None and (not isinstance(headers, dict) or len(headers) > 32 or
                    any(not isinstance(k, str) or not isinstance(v, str) for k, v in headers.items())) or
                timeout_ms is not None and (type(timeout_ms) is not int or not 100 <= timeout_ms <= 30000)):
            raise ConfigurationError("invalid network fetch options")
        report = self.capabilities()
        policy = report.get("network_fetch_policy")
        features = report.get("features")
        if (not isinstance(features, dict) or features.get("network_fetch") is not True or
                "POST /v2/net/fetch" not in report["methods"] or not isinstance(policy, dict)):
            raise UnsupportedCapability("tenant network fetch is unavailable")
        if (type(policy.get("max_request_bytes")) is not int or not 1 <= policy["max_request_bytes"] <= 262144 or
                type(policy.get("timeout_ms")) is not int or not 100 <= policy["timeout_ms"] <= 30000):
            raise ProtocolError("invalid tenant network fetch limits")
        data = body or b""
        if len(data) > min(262144, policy.get("max_request_bytes", 0)) or timeout_ms is not None and timeout_ms > policy.get("timeout_ms", 0):
            raise ConfigurationError("network fetch exceeds tenant limits")
        payload = {"url": url, "method": method, "headers": headers or {},
                   "body_base64": base64.b64encode(data).decode("ascii"), "follow_redirects": follow_redirects}
        if timeout_ms is not None:
            payload["timeout_ms"] = timeout_ms
        return NetworkFetchResult.from_payload(self._exchange("POST", "/v2/net/fetch", payload))

    def run(self, job: JobRequest, *, template: TemplateSelector | None = None) -> JobResult:
        if not isinstance(job, JobRequest):
            raise ConfigurationError("run requires a JobRequest")
        payload = job.payload()
        if template is not None and not isinstance(template, TemplateSelector):
            raise ConfigurationError("template must be a TemplateSelector")
        proxy_report = self.capabilities(template=template) if job.network == "proxy" else None
        if proxy_report is not None and (not isinstance(proxy_report.get("features"), dict) or proxy_report["features"].get("network_egress") is not True):
            raise UnsupportedCapability("tenant guest proxy is unavailable")
        if template is None:
            report = proxy_report or self.capabilities()
            if "POST /v2/jobs" not in report["methods"] or report.get("artifact_authenticated") is not True:
                raise UnsupportedCapability("server does not advertise signed v2 jobs")
            entries = report["allowed_entrypoints"]
            if job.entrypoint not in entries:
                raise UnsupportedCapability("entrypoint is not available to this tenant")
            features = report.get("features")
            if job.input_files and (not isinstance(features, dict) or
                                    features.get("input_files") is not True):
                raise UnsupportedCapability("input files are not available on this backend")
            if job.environment and (not isinstance(features, dict) or
                                    features.get("environment") is not True):
                raise UnsupportedCapability("environment is not available on this backend")
            if job.cwd is not None and (not isinstance(features, dict) or features.get("working_directory") is not True):
                raise UnsupportedCapability("working directory is not available on this backend")
            if job.stdin is not None and (not isinstance(features, dict) or
                                          features.get("stdin") is not True):
                raise UnsupportedCapability("stdin is not available on this backend")
            template = TemplateSelector(report["backend"],
                                        report.get("artifact_manifest_sha256", ""))
        elif not isinstance(template, TemplateSelector):
            raise ConfigurationError("template must be a TemplateSelector")
        if proxy_report is not None and (template.backend != proxy_report["backend"] or
                template.artifact_manifest_sha256 != proxy_report.get("artifact_manifest_sha256")):
            raise UnsupportedCapability("guest proxy requires the advertised signed template")
        if template.backend == "firecracker-osv" and job.environment and any(
                name.startswith(("LD_", "OSV_")) for name in job.environment):
            raise ConfigurationError("reserved OSv environment variable")
        if job.cwd is not None and template.backend != "firecracker-linux":
            raise UnsupportedCapability("working directory requires firecracker-linux")
        payload["backend"] = template.backend
        payload["artifact_manifest_sha256"] = template.artifact_manifest_sha256
        value = JobResult.from_payload(self._exchange("POST", "/v2/jobs", payload))
        if value.artifact_manifest_sha256 is not None and (value.backend != template.backend or
                value.artifact_manifest_sha256 != template.artifact_manifest_sha256):
            raise ProtocolError("job returned a different signed template")
        return value

    def run_legacy(self, job: JobRequest) -> JobResult:
        """Explicitly use v1 without signed-template selection guarantees."""
        if not isinstance(job, JobRequest):
            raise ConfigurationError("run_legacy requires a JobRequest")
        payload = job.payload()
        if job.network == "proxy":
            report = self.capabilities()
            if not isinstance(report.get("features"), dict) or report["features"].get("network_egress") is not True:
                raise UnsupportedCapability("tenant guest proxy is unavailable")
        return JobResult.from_payload(self._exchange("POST", "/v1/jobs", payload))

    def create_session(self, session: SessionRequest = SessionRequest(), *,
                       template: TemplateSelector | None = None) -> Session:
        if not isinstance(session, SessionRequest):
            raise ConfigurationError("create_session requires a SessionRequest")
        payload = session.payload()
        if template is not None and not isinstance(template, TemplateSelector):
            raise ConfigurationError("template must be a TemplateSelector")
        proxy_report = self.capabilities(template=template) if session.network == "proxy" else None
        if proxy_report is not None and (not isinstance(proxy_report.get("features"), dict) or proxy_report["features"].get("network_egress") is not True):
            raise UnsupportedCapability("tenant guest proxy is unavailable")
        if template is None:
            report = proxy_report or self.capabilities()
            features = report.get("features")
            if ("POST /v2/sessions" not in report["methods"] or
                    not isinstance(features, dict) or features.get("sessions") is not True or
                    report.get("artifact_authenticated") is not True or
                    report["backend"] != "firecracker-linux" or
                    not report["allowed_entrypoints"]):
                raise UnsupportedCapability("server does not advertise signed Linux sessions")
            if session.input_files and features.get("input_files") is not True:
                raise UnsupportedCapability("input files are not available on this backend")
            template = TemplateSelector(report["backend"],
                                        report.get("artifact_manifest_sha256", ""))
        elif not isinstance(template, TemplateSelector):
            raise ConfigurationError("template must be a TemplateSelector")
        if proxy_report is not None and (template.backend != proxy_report["backend"] or
                template.artifact_manifest_sha256 != proxy_report.get("artifact_manifest_sha256")):
            raise UnsupportedCapability("guest proxy requires the advertised signed template")
        if template.backend != "firecracker-linux":
            raise UnsupportedCapability("sessions require firecracker-linux")
        payload["backend"] = template.backend
        payload["artifact_manifest_sha256"] = template.artifact_manifest_sha256
        info = SessionInfo.from_payload(self._exchange("POST", "/v2/sessions", payload,
                                                       accepted=(201,)))
        if info.artifact_manifest_sha256 != template.artifact_manifest_sha256:
            raise ProtocolError("session create returned a different template")
        return Session(self, info)

    def list_sessions(self,*,limit:int=20,cursor:str|None=None,order:str="desc"):
        if type(limit) is not int or not 1<=limit<=100 or order not in ("asc","desc"):raise ConfigurationError("invalid session pagination limit/order")
        if cursor is not None and (not isinstance(cursor,str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}",cursor)):raise ConfigurationError("invalid session cursor")
        query={"limit":str(limit),"order":order}
        if cursor is not None:query["cursor"]=cursor
        value=self._exchange("GET","/v2/sessions?"+parse.urlencode(query))
        if not isinstance(value.get("sessions"),list) or len(value["sessions"])>limit:raise ProtocolError("invalid session list")
        rows=[SessionInfo.from_payload(row) for row in value["sessions"]]
        if len({row.id for row in rows})!=len(rows):raise ProtocolError("duplicate session in page")
        token=value.get("next_cursor")
        if token is not None and (not isinstance(token,str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}",token)):raise ProtocolError("invalid next cursor")
        return {"sessions":rows,"next_cursor":token}

    def connect_session(self, session_id: str) -> Session:
        if not isinstance(session_id, str) or not _SESSION_ID.fullmatch(session_id):
            raise ConfigurationError("session ID must be 24 lowercase hex digits")
        info = SessionInfo.from_payload(self._exchange("GET", "/v2/sessions/" + session_id))
        if info.id != session_id:
            raise ProtocolError("session query returned a different ID")
        return Session(self, info)

    def _events(self, path: str):
        req = request.Request(self._origin + path, headers={"Authorization": "Bearer " + self._token,
                                                          "Accept": "text/event-stream"})
        try:
            response = self._opener.open(req, timeout=self._timeout)
        except error.HTTPError as exc:
            data = exc.read(_MAX_ERROR_BYTES + 1)
            if len(data) > _MAX_ERROR_BYTES:
                raise ProtocolError("oversized stream error") from None
            try:
                value = json.loads(data)
            except (UnicodeError, json.JSONDecodeError):
                raise ProtocolError("invalid stream error") from None
            if 300 <= exc.code < 400:
                raise ProtocolError("server redirected command events") from None
            raise APIError(exc.code, str(value.get("code", "http_error")),
                           str(value.get("error", "stream rejected")).replace(self._token, "[redacted]")[:4096]) from None
        except (error.URLError, OSError, TimeoutError) as exc:
            raise TransportError("command event connection failed (" + type(exc).__name__ + ")") from None
        try:
            with response:
                if response.headers.get("Content-Type", "").split(";", 1)[0] != "text/event-stream":
                    raise ProtocolError("command events are not an SSE stream")
                kind = None
                payload = None
                size = 0
                while True:
                    line = response.readline(_MAX_RESPONSE_BYTES + 1)
                    if not line:
                        return
                    size += len(line)
                    if len(line) > _MAX_RESPONSE_BYTES or size > _MAX_RESPONSE_BYTES:
                        raise ProtocolError("command event stream exceeds 4 MiB")
                    if line in (b"\n", b"\r\n"):
                        if kind is not None and payload is not None:
                            try:
                                value = json.loads(payload.decode("utf-8"))
                            except (UnicodeError, json.JSONDecodeError):
                                raise ProtocolError("invalid command event JSON") from None
                            yield kind, value
                        kind = payload = None
                    elif line.startswith(b"event: "):
                        kind = line[7:].strip().decode("ascii")
                    elif line.startswith(b"data: "):
                        if payload is not None:
                            raise ProtocolError("duplicate command event data")
                        payload = line[6:].rstrip(b"\r\n")
        except (OSError, TimeoutError) as exc:
            raise TransportError("command event transport failed (" + type(exc).__name__ + ")") from None

    def _exchange(self, method: str, path: str, payload: dict[str, Any] | None = None,
                  accepted: tuple[int, ...] = (200,), timeout_seconds: float | None = None) -> dict[str, Any]:
        body = None
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":"),
                              ensure_ascii=False).encode("utf-8")
            if len(body) > _MAX_REQUEST_BYTES:
                raise ConfigurationError("JSON request exceeds 1 MiB")
        headers = {"Authorization": "Bearer " + self._token,
                   "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        req = request.Request(self._origin + path, data=body,
                              headers=headers, method=method)
        try:
            with self._opener.open(req, timeout=self._timeout if timeout_seconds is None else min(self._timeout,timeout_seconds)) as response:
                status = response.status
                data = response.read(_MAX_RESPONSE_BYTES + 1)
        except error.HTTPError as exc:
            status = exc.code
            if 300 <= status < 400:
                raise ProtocolError("server redirected an API request") from None
            data = exc.read(_MAX_ERROR_BYTES + 1)
            if len(data) > _MAX_ERROR_BYTES:
                raise ProtocolError("error response exceeds 64 KiB") from None
        except (error.URLError, OSError, TimeoutError) as exc:
            raise TransportError(f"HTTPS exchange failed ({type(exc).__name__})") from None
        if len(data) > _MAX_RESPONSE_BYTES:
            raise ProtocolError("response exceeds 4 MiB")
        if status == 204 and 204 in accepted:
            if data:
                raise ProtocolError("delete response must be empty")
            return {}
        try:
            value = json.loads(data.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            raise ProtocolError("server returned invalid JSON") from None
        if not isinstance(value, dict):
            raise ProtocolError("server returned a non-object JSON response")
        if status not in accepted:
            code = value.get("code")
            message = value.get("error")
            if not isinstance(code, str) or not code:
                code = f"http_{status}"
            if not isinstance(message, str):
                message = "request rejected"
            message = message.replace(self._token, "[redacted]")[:4096]
            kind = TemplateMismatch if status == 409 and code == "template_mismatch" else APIError
            raise kind(status, code, message)
        return value


_INFERENCE_ENDPOINT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_INFERENCE_U64 = (1 << 64) - 1


def _inference_id(value: Any, label: str = "invocation") -> str:
    if not isinstance(value, str) or not _SESSION_ID.fullmatch(value):
        raise ConfigurationError(label + " ID must be 24 lowercase hex digits")
    return value


class InferenceError(SandboxError):
    """A known invocation failed. Query its bill; never blindly repeat the POST."""

    def __init__(self, task_id: str, invocation_id: str, cause: Exception, attempted: bool):
        self.task_id, self.invocation_id, self.cause = task_id, invocation_id, cause
        self.delivery_unknown = attempted
        self.status = cause.status if isinstance(cause, APIError) else None
        self.code = cause.code if isinstance(cause, APIError) and re.fullmatch(r"[a-z0-9_]{1,64}", cause.code) else type(cause).__name__
        super().__init__(f"inference {self.code}; task={task_id} invocation={invocation_id}")


def _inference_units(value: Any) -> int:
    if (not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]{0,19}", value) or
            int(value) > _INFERENCE_U64):
        raise ProtocolError("invalid inference integer units")
    return int(value)


def _inference_price(value: Any, input_bytes: int, output_bytes: int) -> int:
    keys = ("request_units", "input_byte_units", "output_byte_units")
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ProtocolError("invalid inference price")
    price = [_inference_units(value[key]) for key in keys]
    total = price[0] + price[1] * input_bytes + price[2] * output_bytes
    if total > _INFERENCE_U64:
        raise ProtocolError("inference price overflow")
    return total


def _inference_json(value: Any, limit: int, problem=ConfigurationError) -> tuple[Any, int]:
    """Snapshot plain JSON before I/O, rejecting implicit/lossy conversions."""
    ancestors = set()
    def check(item, depth):
        kind = type(item)
        if depth > 64:
            raise ValueError()
        if item is None or kind is bool:
            return
        if kind in (int, float):
            if not math.isfinite(item) or (kind is int or item.is_integer()) and abs(item) > (1 << 53) - 1:
                raise ValueError()
            return
        if kind is str:
            item.encode("utf-8")
            return
        if kind not in (list, dict) or id(item) in ancestors:
            raise ValueError()
        ancestors.add(id(item))
        try:
            if kind is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise ValueError()
                    check(key, depth + 1)
                    check(child, depth + 1)
            else:
                for child in item:
                    check(child, depth + 1)
        finally:
            ancestors.remove(id(item))
    try:
        check(value, 0)
        data = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
        if len(data) > limit:
            raise ValueError()
        return json.loads(data), len(data)
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise problem("inference data must be bounded plain JSON with finite, exact numbers") from None


def _inference_integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ProtocolError("invalid inference byte/count limit")
    return value


def _inference_receipt(value: Any, closed: bool = False) -> tuple[int, int]:
    required = {"id", "endpoint", "state", "epoch", "price", "input_bytes", "max_output_bytes", "output_bytes",
                "dispatched", "http_status", "reserved_units", "settled_units", "started_at", "duration_ms"}
    if (not isinstance(value, dict) or not required <= set(value) or set(value) - required - {"code", "finished_at"} or
            any(not isinstance(value.get(key), str) or not _SESSION_ID.fullmatch(value[key]) for key in ("id", "epoch")) or
            not isinstance(value["endpoint"], str) or not _INFERENCE_ENDPOINT.fullmatch(value["endpoint"]) or
            type(value["dispatched"]) is not bool):
        raise ProtocolError("invalid inference receipt binding")
    inp = _inference_integer(value["input_bytes"], 0, 256 << 10)
    maximum = _inference_integer(value["max_output_bytes"], 1, 512 << 10)
    output = _inference_integer(value["output_bytes"], 0, maximum + 1)
    status = _inference_integer(value["http_status"], 0, 599)
    _inference_integer(value["duration_ms"], 0, 300000)
    code = value.get("code", "")
    if status != 0 and status < 100 or not isinstance(code, str) or code and not re.fullmatch(r"[a-z0-9_]{1,64}", code):
        raise ProtocolError("invalid inference response status/code")
    try:
        start = _preview_timestamp(value["started_at"])
        finish = _preview_timestamp(value["finished_at"]) if "finished_at" in value else None
        if start == -62135596800 * 1000000000 or finish is not None and finish < start:
            raise ValueError()
    except (TypeError, ValueError, OverflowError):
        raise ProtocolError("invalid inference receipt timestamps") from None
    reserved, settled = _inference_units(value["reserved_units"]), _inference_units(value["settled_units"])
    if reserved != _inference_price(value["price"], inp, maximum) or settled > reserved:
        raise ProtocolError("invalid inference reservation")
    state, dispatched = value["state"], value["dispatched"]
    if state == "reserved":
        if closed or finish is not None or settled or dispatched or status or output or code:
            raise ProtocolError("invalid pending inference")
        return 0, reserved
    if state == "uncertain":
        if finish is None or settled or not code:
            raise ProtocolError("invalid uncertain inference")
        return 0, reserved
    if state not in ("succeeded", "failed") or finish is None:
        raise ProtocolError("invalid inference state")
    expected = _inference_price(value["price"], inp, min(output, maximum)) if dispatched else 0
    if ((not dispatched and (output or status)) or expected != settled or
            state == "succeeded" and (not dispatched or output > maximum or not 200 <= status <= 299 or code) or state == "failed" and not code):
        raise ProtocolError("invalid settled inference")
    return settled, 0


def _inference_bill(value: Any, task_id: str) -> dict[str, Any]:
    required = {"protocol", "tenant", "task_id", "vm_id", "lease_id", "closed", "unit", "max_invocations",
                "settled_units", "held_units", "invocations"}
    if (not isinstance(value, dict) or not required <= set(value) or set(value) - required - {"budget_units"} or
            value["protocol"] != "osv-sandbox-inference-bill/v1" or value["unit"] != "microcredits" or
            value["task_id"] != task_id or any(not isinstance(value[key], str) or not _SESSION_ID.fullmatch(value[key]) for key in ("task_id", "vm_id", "lease_id")) or
            not isinstance(value["tenant"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value["tenant"]) or
            type(value["closed"]) is not bool or not isinstance(value["invocations"], list)):
        raise ProtocolError("invalid inference bill binding")
    maximum = _inference_integer(value["max_invocations"], 1, 256)
    if len(value["invocations"]) > maximum:
        raise ProtocolError("inference bill exceeds invocation limit")
    settled, held, ids = 0, 0, set()
    for entry in value["invocations"]:
        charged, pending = _inference_receipt(entry, value["closed"])
        if entry["id"] in ids:
            raise ProtocolError("duplicate invocation in bill")
        ids.add(entry["id"])
        settled, held = settled + charged, held + pending
    if (settled != _inference_units(value["settled_units"]) or held != _inference_units(value["held_units"]) or
            settled + held > _INFERENCE_U64 or "budget_units" in value and settled + held > _inference_units(value["budget_units"])):
        raise ProtocolError("invalid inference bill totals/budget")
    return value


def _inference_policy(report: dict[str, Any]) -> dict[str, Any]:
    features, policy = report.get("features", {}), report.get("remote_inference_policy")
    if ((report.get("artifact_manifest_protocol") != "osv-sandbox-artifacts/v7" and not (report.get("backend") == "firecracker-linux" and report.get("artifact_manifest_protocol") == "osv-sandbox-artifacts/v8")) or
            report.get("backend") not in ("firecracker-linux", "firecracker-osv") or
            not isinstance(features, dict) or any(features.get(k) is not True for k in ("sessions", "remote_inference", "network_egress")) or
            "POST /v2/sessions/{id}/ml/invocations" not in report.get("methods", [])):
        raise UnsupportedCapability("selected session has no remote inference")
    return _inference_policy_document(policy)


def _inference_policy_document(policy: Any) -> dict[str, Any]:
    required = {"protocol", "endpoints", "max_request_bytes", "max_response_bytes", "timeout_ms", "max_invocations"}
    if (not isinstance(policy, dict) or not required <= set(policy) or set(policy) - required - {"budget_units"} or
            policy["protocol"] != "osv-sandbox-inference-capabilities/v1" or not isinstance(policy["endpoints"], list) or
            not 1 <= len(policy["endpoints"]) <= 32):
        raise ProtocolError("invalid inference policy")
    for key, low, high in (("max_request_bytes", 1, 256 << 10), ("max_response_bytes", 1, 512 << 10),
                           ("timeout_ms", 100, 30000), ("max_invocations", 1, 256)):
        _inference_integer(policy[key], low, high)
    if "budget_units" in policy:
        _inference_units(policy["budget_units"])
    names = set()
    for endpoint in policy["endpoints"]:
        if (not isinstance(endpoint, dict) or set(endpoint) != {"name", "price"} or
                not isinstance(endpoint["name"], str) or not _INFERENCE_ENDPOINT.fullmatch(endpoint["name"]) or endpoint["name"] in names):
            raise ProtocolError("invalid inference endpoint policy")
        names.add(endpoint["name"])
        _inference_price(endpoint["price"], policy["max_request_bytes"], policy["max_response_bytes"])
    return policy


@dataclass(frozen=True)
class InferenceResult:
    task_id: str
    invocation_id: str
    invocation: dict[str, Any]
    data: Any


class SessionML:
    """Controlled inference via this owner's API; no model credentials in SDK."""
    def __init__(self, session: Session):
        self._session = session

    def bill(self, *, request_timeout: float | None = None) -> dict[str, Any]:
        return self._session._client.get_inference_bill(self._session.id, request_timeout=request_timeout)

    def invoke(self, endpoint: str, payload: Any, *, invocation_id: str | None = None,
               timeout_ms: int = 0, request_timeout: float | None = None) -> InferenceResult:
        identity = _inference_id(secrets.token_hex(12) if invocation_id is None else invocation_id)
        attempted = False
        try:
            timeout = 35.0 if request_timeout is None else _code_timeout(request_timeout)
            deadline = time.monotonic() + timeout
            if not isinstance(endpoint, str) or not _INFERENCE_ENDPOINT.fullmatch(endpoint) or type(timeout_ms) is not int or not 0 <= timeout_ms <= 30000:
                raise ConfigurationError("invalid inference endpoint alias or timeout")
            snapshot, size = _inference_json(payload, 256 << 10)
            if self._session.created.network != "proxy":
                raise UnsupportedCapability("inference requires a proxy-network session")
            policy = _inference_policy(self._session.capabilities(request_timeout=min(timeout, 10)))
            if endpoint not in {entry["name"] for entry in policy["endpoints"]}:
                raise UnsupportedCapability("inference endpoint alias is not authorized")
            if size > policy["max_request_bytes"] or timeout_ms > policy["timeout_ms"]:
                raise ConfigurationError("inference payload or timeout exceeds tenant policy")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TransportError("inference request deadline elapsed before submission")
            attempted = True
            value = self._session._client._exchange("POST", "/v2/sessions/" + self._session.id + "/ml/invocations",
                    {"id": identity, "endpoint": endpoint, "payload": snapshot, "timeout_ms": timeout_ms}, timeout_seconds=remaining)
            if (not isinstance(value, dict) or set(value) != {"protocol", "task_id", "invocation", "data"} or
                    value["protocol"] != "osv-sandbox-inference-invoke/v1" or value["task_id"] != self._session.id):
                raise ProtocolError("invalid inference result task/protocol")
            _inference_receipt(value["invocation"])
            if value["invocation"]["id"] != identity or value["invocation"]["endpoint"] != endpoint or value["invocation"]["state"] != "succeeded":
                raise ProtocolError("invalid inference result invocation")
            data, _ = _inference_json(value["data"], _MAX_RESPONSE_BYTES, ProtocolError)
            return InferenceResult(self._session.id, identity, value["invocation"], data)
        except (SandboxError, TypeError, ValueError, OverflowError) as exc:
            raise InferenceError(self._session.id, identity, exc, attempted) from exc


@dataclass(frozen=True)
class E2BWriteInfo:
    name: str
    path: str
    type: str = "file"
    metadata: dict[str, str] | None = None


@dataclass(frozen=True)
class E2BEntryInfo:
    name: str
    path: str
    type: str | None
    size: int
    mode: int
    permissions: str
    owner: str
    group: str
    modified_time: datetime
    symlink_target: str | None = None
    metadata: dict[str, str] | None = None

    @classmethod
    def from_payload(cls, value: Any, path: str) -> "E2BEntryInfo":
        if not isinstance(value, dict):
            raise ProtocolError("file info is not an object")
        if (value.get("path") != path or value.get("name") != posixpath.basename(path) or
                value.get("type") not in ("file", "directory", "symlink", "other") or
                type(value.get("size")) is not int or not 0 <= value["size"] <= 1 << 40 or
                type(value.get("mode")) is not int or not 0 <= value["mode"] <= 0o177777 or
                not isinstance(value.get("permissions"), str) or len(value["permissions"]) != 9 or
                not isinstance(value.get("owner"), str) or not value["owner"] or
                not isinstance(value.get("group"), str) or not value["group"] or
                type(value.get("modified_time_ms")) is not int or
                not 0 <= value["modified_time_ms"] <= 4_102_444_800_000):
            raise ProtocolError("file info has invalid fields or binding")
        expected_type = {"file": 0o100000, "directory": 0o040000,
                         "symlink": 0o120000}.get(value["type"])
        if ((expected_type is not None and value["mode"] & 0o170000 != expected_type) or
                (expected_type is None and value["mode"] & 0o170000 in
                 (0o100000, 0o040000, 0o120000))):
            raise ProtocolError("file info type differs from mode")
        target = value.get("symlink_target")
        try:
            target_bytes = len(target.encode("utf-8")) if isinstance(target, str) else 0
        except UnicodeError:
            raise ProtocolError("file info has invalid symlink target") from None
        if ((value["type"] == "symlink" and
             (not isinstance(target, str) or not target or target_bytes > 4096 or
              "\x00" in target or value["size"] != target_bytes)) or
                (value["type"] != "symlink" and target is not None)):
            raise ProtocolError("file info has invalid symlink target")
        metadata = value.get("metadata")
        if metadata is not None:
            if value["type"] == "symlink":
                raise ProtocolError("symlink metadata is not supported")
            try:
                _check_e2b_metadata(metadata)
            except ConfigurationError:
                raise ProtocolError("file info metadata is invalid") from None
        return cls(name=value["name"], path=path,
                   type={"directory": "dir", "file": "file", "symlink": "symlink"}.get(value["type"]),
                   size=value["size"], mode=value["mode"],
                   permissions=value["permissions"], owner=value["owner"],
                   group=value["group"],
                   modified_time=datetime.fromtimestamp(value["modified_time_ms"] / 1000,
                                                        tz=timezone.utc),
                   symlink_target=target, metadata=metadata or None)


def _check_e2b_metadata(metadata: dict[str, str]) -> None:
    if not isinstance(metadata, dict) or len(metadata) > 16:
        raise ConfigurationError("E2B metadata exceeds 16 entries")
    total = 0
    for key, value in metadata.items():
        if (not isinstance(key, str) or len(key) > 246 or
                not re.fullmatch(r"[A-Za-z0-9!#$%&'*+\-.^_`|~]+", key) or
                not isinstance(value, str) or any(not 0x20 <= ord(ch) <= 0x7e for ch in value)):
            raise ConfigurationError("E2B metadata requires token keys and printable ASCII values")
        total += len(key) + len(value)
    if total > 16 * 1024:
        raise ConfigurationError("E2B metadata exceeds 16 KiB")


def _watch_info(info: Any, session_id: str) -> dict[str, Any]:
    if (not isinstance(info, dict) or info.get("session_id") != session_id or
            not isinstance(info.get("id"), str) or not _SESSION_ID.fullmatch(info["id"]) or
            info.get("state") not in ("starting", "watching", "closed", "failed") or
            type(info.get("recursive")) is not bool or type(info.get("include_entry")) is not bool):
        raise ProtocolError("invalid watch info or owner")
    try:
        Session._check_file_path(info.get("path"), allow_root=True)
    except ConfigurationError:
        raise ProtocolError("invalid watch directory") from None
    if "error_code" in info and (not isinstance(info["error_code"], str) or len(info["error_code"]) > 64):
        raise ProtocolError("invalid watch terminal code")
    return info


_CODE_LANGUAGES = ("python", "javascript", "typescript")
_CODE_TERMINAL = ("completed", "cancelled", "timed_out", "failed")


def _capability_report(report, template=None):
    if report.get("protocol") != "osv-sandbox-capabilities/v1":
        raise ProtocolError("unsupported capabilities protocol")
    if (not isinstance(report.get("methods"), list) or any(not isinstance(item, str) for item in report["methods"]) or
            not isinstance(report.get("allowed_entrypoints"), list) or any(not isinstance(item, str) for item in report["allowed_entrypoints"]) or
            not isinstance(report.get("backend"), str)):
        raise ProtocolError("incomplete capabilities response")
    if template is not None and (report["backend"] != template.backend or report.get("artifact_manifest_sha256") != template.artifact_manifest_sha256):
        raise ProtocolError("selected capabilities returned a different template")


def _code_id(value: Any) -> str:
    if not isinstance(value, str) or not _SESSION_ID.fullmatch(value):
        raise ConfigurationError("code ID must be 24 lowercase hex digits")
    return value


def _code_timeout(value: float | None) -> float:
    if value is None:
        return 10.0
    if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
        raise ConfigurationError("code request timeout must be positive seconds")
    return float(value)


@dataclass(frozen=True)
class CodeContext:
    """An owner-bound snapshot; restart returns a new generation snapshot."""

    session_id: str
    id: str
    generation: int
    language: str
    cwd: str
    state: str
    pid: int | None
    failure: str | None
    discarded_late_events: int
    discarded_late_bytes: int

    @classmethod
    def from_payload(cls, value: Any, session_id: str) -> CodeContext:
        if (not isinstance(value, dict) or not set(cls.__dataclass_fields__).issubset(value) or value.get("session_id") != session_id or
                not isinstance(value.get("id"), str) or not _SESSION_ID.fullmatch(value["id"]) or
                type(value.get("generation")) is not int or not 1 <= value["generation"] < 1 << 53 or
                value.get("language") not in _CODE_LANGUAGES or
                value.get("state") not in ("starting", "idle", "running", "interrupting", "stopping", "failed") or
                value.get("pid") is not None and (type(value["pid"]) is not int or not 2 <= value["pid"] < 1 << 31) or
                value.get("failure") is not None and (not isinstance(value["failure"], str) or len(value["failure"]) > 4096)):
            raise ProtocolError("invalid code context or owner")
        try:
            Session._check_file_path(value.get("cwd"), allow_root=True)
        except ConfigurationError:
            raise ProtocolError("invalid code working directory") from None
        for name, limit in (("discarded_late_events", 1024), ("discarded_late_bytes", 256 << 10)):
            if type(value.get(name)) is not int or not 0 <= value[name] <= limit:
                raise ProtocolError("invalid late output accounting")
        return cls(**{key: value[key] for key in cls.__dataclass_fields__})


class CodeContexts:
    """Native asynchronous code control for one authenticated session."""

    def __init__(self, session: Session):
        self._session = session
        self._path = "/v2/sessions/" + session.id
        self._capabilities = None
        self._capability_lock = threading.Lock()

    def _check(self, language: str | None = None, request_timeout: float | None = None) -> None:
        _code_timeout(request_timeout)
        if language is not None and language not in _CODE_LANGUAGES:
            raise UnsupportedCapability("only python/javascript/typescript code is available")
        with self._capability_lock:
            if self._capabilities is None:
                report = self._session.capabilities(request_timeout=request_timeout)
                if (report.get("artifact_authenticated") is not True or report.get("backend") != "firecracker-linux" or
                        not isinstance(report.get("features"), dict) or report["features"].get("code_contexts") is not True or
                        report.get("artifact_manifest_protocol") not in ("osv-sandbox-artifacts/v5", "osv-sandbox-artifacts/v6", "osv-sandbox-artifacts/v7", "osv-sandbox-artifacts/v8") or
                        not isinstance(report.get("code_runtime"), dict) or
                        report["code_runtime"].get("kernel_protocol") != "osv-code-kernel/v2" or
                        not isinstance(report.get("code_languages"), list) or
                        any(item not in _CODE_LANGUAGES for item in report["code_languages"])):
                    raise UnsupportedCapability("selected signed template has no code contexts")
                self._capabilities = report
        if language is not None and language not in self._capabilities["code_languages"]:
            raise UnsupportedCapability("code interpreter is not authorized on the selected template")

    def _rpc(self, method: str, path: str, payload: dict[str, Any] | None = None,
             status: int = 200, request_timeout: float | None = None) -> dict[str, Any]:
        return self._session._client._exchange(method, self._path + path, payload,
                                               accepted=(status,), timeout_seconds=_code_timeout(request_timeout))

    def _context(self, context: CodeContext) -> CodeContext:
        if not isinstance(context, CodeContext) or context.session_id != self._session.id:
            raise ConfigurationError("context belongs to another session")
        return CodeContext.from_payload(vars(context), self._session.id)

    def get(self, context_id: str, *, request_timeout: float | None = None) -> CodeContext:
        _code_id(context_id)
        self._check(request_timeout=request_timeout)
        value = CodeContext.from_payload(self._rpc("GET", "/contexts/" + context_id,
                                                   request_timeout=request_timeout), self._session.id)
        if value.id != context_id:
            raise ProtocolError("code context ID changed")
        return value

    def default(self, language: str = "python", *, request_timeout: float | None = None) -> CodeContext:
        self._check(language, request_timeout)
        value = CodeContext.from_payload(self._rpc("POST", "/contexts/default", {"language": language},
                                                   request_timeout=request_timeout), self._session.id)
        if value.language != language:
            raise ProtocolError("default context language changed")
        return value

    def create(self, language: str = "python", cwd: str = "/workspace", *,
               context_id: str | None = None, request_timeout: float | None = None) -> CodeContext:
        context_id = secrets.token_hex(12) if context_id is None else _code_id(context_id)
        Session._check_file_path(cwd, allow_root=True)
        self._check(language, request_timeout)
        try:
            value = CodeContext.from_payload(self._rpc("POST", "/contexts", {
                "context_id": context_id, "language": language, "cwd": cwd}, 201, request_timeout), self._session.id)
            if (value.id, value.language, value.cwd) != (context_id, language, cwd):
                raise ProtocolError("created context binding changed")
        except BaseException as exc:
            exc.context_id = context_id
            exc.session_id = self._session.id
            raise
        return value

    def list(self, *, request_timeout: float | None = None) -> list[CodeContext]:
        self._check(request_timeout=request_timeout)
        value = self._rpc("GET", "/contexts", request_timeout=request_timeout)
        if value.get("session_id") != self._session.id or not isinstance(value.get("contexts"), list) or len(value["contexts"]) > 4:
            raise ProtocolError("invalid code context list")
        contexts = [CodeContext.from_payload(row, self._session.id) for row in value["contexts"]]
        if len({row.id for row in contexts}) != len(contexts):
            raise ProtocolError("duplicate code contexts")
        return contexts

    def restart(self, context: CodeContext, *, request_timeout: float | None = None) -> CodeContext:
        context = self._context(context)
        self._check(context.language, request_timeout)
        value = CodeContext.from_payload(self._rpc("POST", "/contexts/" + context.id + "/restart",
            {"generation": context.generation}, 202, request_timeout), self._session.id)
        if value.id != context.id or value.language != context.language or value.generation not in (context.generation, context.generation + 1):
            raise ProtocolError("restart changed context identity")
        return value

    def remove(self, context: CodeContext, *, request_timeout: float | None = None) -> None:
        context = self._context(context)
        self._check(request_timeout=request_timeout)
        value = self._rpc("DELETE", "/contexts/" + context.id + "?generation=" + str(context.generation),
                          status=202, request_timeout=request_timeout)
        if value.get("session_id") != context.session_id or value.get("context_id") != context.id or value.get("removed") is not True:
            raise ProtocolError("invalid code removal acknowledgment")

    def connect_execution(self, context: CodeContext, execution_id: str) -> CodeExecution:
        return CodeExecution(self, self._context(context), _code_id(execution_id))

    def execute(self, context: CodeContext, code: str, *, execution_id: str | None = None,
                environment: dict[str, str] | None = None, timeout_ms: int = 60000,
                request_timeout: float | None = None) -> CodeExecution:
        context = self._context(context)
        _code_timeout(request_timeout)
        env = _code_input(code, environment, timeout_ms)
        self._check(context.language, request_timeout)
        handle = self.connect_execution(context, secrets.token_hex(12) if execution_id is None else execution_id)
        try:
            value = self._rpc("POST", "/code-executions", {"context_id": context.id, "generation": context.generation,
                "execution_id": handle.id, "code": code, "environment": env, "timeout_ms": timeout_ms}, 202, request_timeout)
            if value.get("session_id") != context.session_id or value.get("execution_id") != handle.id or value.get("accepted") is not True:
                raise ProtocolError("invalid code submission acknowledgment")
        except BaseException as exc:
            exc.execution = handle
            raise
        return handle


class CodeExecution:
    """Known-ID journal. Losing an observation never resubmits or cancels code."""

    def __init__(self, controller: CodeContexts, context: CodeContext, execution_id: str):
        self._controller = controller
        self._context = controller._context(context)
        self._id = _code_id(execution_id)
        self._path = "/code-executions/" + execution_id

    @property
    def context(self) -> CodeContext:
        return self._context

    @property
    def id(self) -> str:
        return self._id

    def poll(self, after: int = 0, *, request_timeout: float | None = None) -> dict[str, Any]:
        if type(after) is not int or not 0 <= after <= 256:
            raise ConfigurationError("code cursor must be in [0,256]")
        page = self._controller._rpc("GET", self._path + "?after=" + str(after), request_timeout=request_timeout)
        c = self.context
        if (page.get("session_id"), page.get("id"), page.get("context_id"), page.get("generation"), page.get("language")) != (c.session_id, self.id, c.id, c.generation, c.language):
            raise ProtocolError("code execution binding changed")
        events = page.get("events")
        if (type(page.get("generation")) is not int or page.get("status") not in ("running",) + _CODE_TERMINAL or
                not isinstance(events, list) or len(events) > 64 or type(page.get("events_evicted")) is not bool or
                type(page.get("last_sequence")) is not int or not 1 <= page["last_sequence"] <= 256 or
                type(page.get("next_sequence")) is not int or page["next_sequence"] != after + len(events) or
                not after <= page["next_sequence"] <= page["last_sequence"] or
                page.get("failure") is not None and (not isinstance(page["failure"], str) or len(page["failure"]) > 4096)):
            raise ProtocolError("invalid code event page")
        if page["events_evicted"]:
            if events or page["status"] == "running" or after >= page["last_sequence"]:
                raise ProtocolError("invalid evicted code page")
            return page
        if not events and after < page["last_sequence"]:
            raise ProtocolError("code event page omitted output")
        preempted = page["status"] == "cancelled" and page.get("failure") == "cancelled_before_submit"
        if preempted and page["last_sequence"] != 1:
            raise ProtocolError("invalid cancellation placeholder")
        size = 0
        for sequence, row in enumerate(events, after + 1):
            if not isinstance(row, dict) or type(row.get("sequence")) is not int or row["sequence"] != sequence:
                raise ProtocolError("code events are not contiguous")
            event = row.get("event")
            if not isinstance(event, dict):
                raise ProtocolError("invalid code event")
            kind = event.get("type")
            fields = {"started": {"type"}, "stdout": {"type", "data"}, "stderr": {"type", "data"},
                      "result": {"type", "data", "is_main_result"}, "error": {"type", "name", "value", "traceback"},
                      "finished": {"type", "status", "context_usable"}}
            if not isinstance(kind, str) or set(event) != fields.get(kind) or (not preempted and (kind == "started") != (sequence == 1)) or preempted and kind != "finished":
                raise ProtocolError("invalid code event kind or starting sequence")
            if kind in ("stdout", "stderr"):
                try:
                    data = base64.b64decode(event["data"], validate=True)
                    if base64.b64encode(data).decode() != event["data"]:
                        raise ValueError()
                except (ValueError, TypeError, binascii.Error):
                    raise ProtocolError("invalid code output encoding") from None
                size += len(data)
            elif kind == "result":
                data = event["data"]
                if (type(event["is_main_result"]) is not bool or not isinstance(data, dict) or not 1 <= len(data) <= 16 or
                        any(not isinstance(mime, str) or "/" not in mime or len(mime) > 128 or mime != "application/json" and not isinstance(value, str) for mime, value in data.items())):
                    raise ProtocolError("invalid code rich result")
                count = len(json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode())
                if count > 32768:
                    raise ProtocolError("code rich result exceeds byte budget")
                size += count
            elif kind == "error":
                for name, limit in (("name", 512), ("value", 16384), ("traceback", 32768)):
                    if not isinstance(event[name], str) or len(event[name].encode()) > limit or name == "name" and not event[name]:
                        raise ProtocolError("invalid code error")
                    size += len(event[name].encode())
            elif kind == "finished":
                if sequence != page["last_sequence"] or event["status"] != page["status"] or event["status"] not in _CODE_TERMINAL or type(event["context_usable"]) is not bool:
                    raise ProtocolError("invalid code terminal event")
        if size > 65536 or page["status"] in _CODE_TERMINAL and events and page["next_sequence"] == page["last_sequence"] and events[-1]["event"]["type"] != "finished":
            raise ProtocolError("code output budget or terminal event violated")
        return page

    def cancel(self, *, request_timeout: float | None = None) -> None:
        value = self._controller._rpc("DELETE", self._path + "?" + parse.urlencode({"context_id": self.context.id,
            "generation": self.context.generation}), status=202, request_timeout=request_timeout)
        if value.get("session_id") != self.context.session_id or value.get("execution_id") != self.id or value.get("accepted") is not True:
            raise ProtocolError("invalid code cancellation acknowledgment")


class FileWatchHandle:
    """Bounded event journal. Polling with a later cursor acknowledges older events."""

    def __init__(self, session: Session, info: dict[str, Any]):
        _watch_info(info, session.id)
        self._session = session
        self.created = dict(info)
        self.id = info["id"]
        self._path = "/v2/sessions/" + session.id + "/watches/" + self.id

    def poll(self, after: int = 0) -> dict[str, Any]:
        if type(after) is not int or not 0 <= after <= 2147483647:
            raise ConfigurationError("watch cursor must be in [0,2147483647]")
        page = self._session._client._exchange("GET", self._path + "?after=" + str(after))
        info = _watch_info(page.get("info"), self._session.id)
        if (any(info[key] != self.created[key] for key in ("id", "path", "recursive", "include_entry")) or
                not isinstance(page.get("events"), list) or len(page["events"]) > 64 or
                type(page.get("next_sequence")) is not int or page["next_sequence"] != after + len(page["events"]) or
                page["next_sequence"] > 2147483647 or type(page.get("complete")) is not bool or
                page["complete"] and info["state"] in ("starting", "watching")):
            raise ProtocolError("invalid watch page")
        for n, event in enumerate(page["events"], after + 1):
            if (not isinstance(event, dict) or type(event.get("sequence")) is not int or event["sequence"] != n or
                    event.get("type") not in ("create", "write", "chmod", "rename", "remove") or
                    not isinstance(event.get("name"), str)):
                raise ProtocolError("invalid watch event")
            name = event["name"]
            full = info["path"] if name == "." else info["path"] + "/" + name
            if name == "." and event["type"] != "chmod" or name != "." and (name.startswith("/") or not info["recursive"] and "/" in name):
                raise ProtocolError("invalid relative watch name")
            try:
                Session._check_file_path(full, allow_root=True)
            except ConfigurationError:
                raise ProtocolError("invalid watch event path") from None
            if event.get("entry") is not None:
                if not info["include_entry"] or event["type"] in ("remove", "rename"):
                    raise ProtocolError("unexpected watch entry")
                E2BEntryInfo.from_payload(event["entry"], full)
        return page

    def stop(self) -> bool:
        result = self._session._client._exchange("DELETE", self._path)
        if type(result.get("stopped")) is not bool:
            raise ProtocolError("invalid watch stop response")
        return result["stopped"]


class FilesystemEventType(Enum):
    CHMOD = "chmod"
    CREATE = "create"
    REMOVE = "remove"
    RENAME = "rename"
    WRITE = "write"


@dataclass(frozen=True)
class FilesystemEvent:
    name: str
    type: FilesystemEventType
    entry: E2BEntryInfo | None = None


class WatchHandle:
    def __init__(self, native: FileWatchHandle):
        self._native = native
        self._cursor = 0
        self._closed = False
        self._failure: SandboxError | None = None
        self._lock = threading.Lock()

    def stop(self, request_timeout: float | None = None) -> None:
        if request_timeout is not None:
            raise UnsupportedCapability("per-call watch request timeout is not supported")
        with self._lock:
            self._native.stop()
            self._closed = True

    def get_new_events(self, request_timeout: float | None = None) -> list[FilesystemEvent]:
        if request_timeout is not None:
            raise UnsupportedCapability("per-call watch request timeout is not supported")
        with self._lock:
            if self._failure is not None:
                raise self._failure
            if self._closed:
                raise SandboxError("The watcher is already stopped")
            events = []
            # Drain at most the bounded host queue; a busy writer cannot make
            # one synchronous call run indefinitely.
            for _ in range(4):
                page = self._native.poll(self._cursor)
                for event in page["events"]:
                    name = event["name"]
                    full = self._native.created["path"] if name == "." else self._native.created["path"] + "/" + name
                    entry = E2BEntryInfo.from_payload(event["entry"], full) if event.get("entry") is not None else None
                    events.append(FilesystemEvent(name, FilesystemEventType(event["type"]), entry))
                self._cursor = page["next_sequence"]
                if page["complete"]:
                    self._closed = True
                    if page["info"]["state"] == "failed":
                        self._failure = SandboxError("directory watch failed: " + page["info"].get("error_code", "unknown"))
                        if not events:
                            raise self._failure
                    break
                if len(page["events"]) < 64:
                    break
            return events


class _E2BFilesystem:
    """Bounded E2B 2.51.0 file methods backed by one native session."""

    def __init__(self, session: Session):
        self._session = session

    def read(self, path: str, format: str = "text", *, user: str | None = None,
             request_timeout: float | None = None, gzip: bool = False,
             stream_idle_timeout: float | None = None) -> str | bytearray:
        if user is not None or request_timeout is not None or gzip or stream_idle_timeout is not None:
            raise UnsupportedCapability("E2B file read options are not supported")
        if format not in ("text", "bytes"):
            raise UnsupportedCapability("E2B file stream format is not supported")
        data = self._session.read_file(path)
        if format == "bytes":
            return bytearray(data)
        try:
            return data.decode("utf-8")
        except UnicodeError:
            raise ProtocolError("file is not valid UTF-8 text; use format='bytes'") from None

    def exists(self, path: str, *, user: str | None = None,
               request_timeout: float | None = None) -> bool:
        if user is not None or request_timeout is not None:
            raise UnsupportedCapability("E2B file exists options are not supported")
        try:
            self._session.stat_file(path)
        except APIError as exc:
            if exc.status == 404 and exc.code == "file_not_found":
                return False
            raise
        return True

    def write(self, path: str, data: str | bytes, *, user: str | None = None,
              request_timeout: float | None = None, gzip: bool = False,
              use_octet_stream: bool | None = None,
              metadata: dict[str, str] | None = None) -> E2BWriteInfo:
        return self.write_files([{"path": path, "data": data}], user=user,
                                request_timeout=request_timeout, gzip=gzip,
                                use_octet_stream=use_octet_stream, metadata=metadata)[0]

    def write_files(self, files: list[dict[str, Any]], *, user: str | None = None,
                    request_timeout: float | None = None, gzip: bool = False,
                    use_octet_stream: bool | None = None,
                    metadata: dict[str, str] | None = None) -> list[E2BWriteInfo]:
        if user is not None or request_timeout is not None or gzip or use_octet_stream is not None:
            raise UnsupportedCapability("E2B write options are not supported")
        if metadata is not None:
            _check_e2b_metadata(metadata)
        if not isinstance(files, list) or len(files) > 16:
            raise ConfigurationError("E2B batch requires at most 16 files")
        prepared: list[tuple[str, bytes]] = []
        total = 0
        for entry in files:
            if not isinstance(entry, dict) or set(entry) != {"path", "data"}:
                raise ConfigurationError("E2B write entry requires path and data")
            path, data = entry["path"], entry["data"]
            self._session._check_file_path(path)
            parent = posixpath.dirname(path)
            if parent != "/workspace" and len(parent.removeprefix("/workspace/").split("/")) > 16:
                raise ConfigurationError("directory depth exceeds 16 components")
            if isinstance(data, str):
                encoded = data.encode("utf-8")
            elif isinstance(data, bytes):
                encoded = data
            else:
                raise UnsupportedCapability("E2B streamed file input is not supported")
            total += len(encoded)
            if total > _SESSION_FILE_LIMIT:
                raise ConfigurationError("E2B batch bytes exceed 512 KiB")
            prepared.append((path, encoded))
        results = []
        for path, encoded in prepared:
            parent = posixpath.dirname(path)
            if parent != "/workspace":
                self._session.make_dir(parent)
            self._session.write_file(path, encoded, metadata=metadata)
            results.append(E2BWriteInfo(name=posixpath.basename(path), path=path,
                                        metadata=metadata or None))
        return results

    def list(self, path: str, depth: int = 1, *, user: str | None = None,
             request_timeout: float | None = None) -> list[E2BEntryInfo]:
        if depth != 1 or user is not None or request_timeout is not None:
            raise UnsupportedCapability("E2B list supports only default one-level directory options")
        value = self._session._file_metadata("list", path)
        names = value.get("entries")
        infos = value.get("entry_infos")
        if infos is None:
            raise UnsupportedCapability("signed guest does not provide complete file info")
        if (not isinstance(names, list) or len(names) > _SESSION_FILE_LIST_LIMIT or
                value["size"] != len(names) or not isinstance(infos, list) or
                len(infos) != len(names) or "info" in value):
            raise ProtocolError("file info list has invalid shape")
        total_names = 0
        previous_name = ""
        for name in names:
            if (not isinstance(name, str) or not name or name in (".", "..") or
                    "/" in name or "\\" in name or
                    any(unicodedata.category(ch) == "Cc" for ch in name) or
                    (previous_name and name <= previous_name)):
                raise ProtocolError("file info list has invalid name")
            try:
                name_size = len(name.encode("utf-8"))
            except UnicodeError:
                raise ProtocolError("file info list has invalid UTF-8") from None
            total_names += name_size
            if name_size > 255 or total_names > _SESSION_FILE_LIST_NAME_BYTES_LIMIT:
                raise ProtocolError("file info list exceeds name budget")
            previous_name = name
        result = []
        for expected_name, info in zip(names, infos):
            name = info.get("name") if isinstance(info, dict) else None
            if name != expected_name:
                raise ProtocolError("file info list has an unbound entry")
            result.append(E2BEntryInfo.from_payload(info, path.rstrip("/") + "/" + name))
        return result

    def get_info(self, path: str, *, user: str | None = None,
                 request_timeout: float | None = None) -> E2BEntryInfo:
        if user is not None or request_timeout is not None:
            raise UnsupportedCapability("E2B get_info options are not supported")
        value = self._session._file_metadata("info", path)
        info = value.get("info")
        if info is None:
            raise UnsupportedCapability("signed guest does not provide complete file info")
        result = E2BEntryInfo.from_payload(info, path)
        expected = {"directory": "dir", "file": "file", "symlink": "symlink", "other": None}.get(value.get("kind"), False)
        if expected is False or result.type != expected:
            raise ProtocolError("file info type differs from stat")
        if result.type == "file" and result.size != value["size"]:
            raise ProtocolError("file info size differs from stat")
        return result

    def make_dir(self, path: str, *, user: str | None = None,
                 request_timeout: float | None = None) -> bool:
        if user is not None or request_timeout is not None:
            raise UnsupportedCapability("E2B directory options are not supported")
        if path == "/workspace":
            return False
        return self._session.make_dir(path)

    def rename(self, old_path: str, new_path: str, *, user: str | None = None,
               request_timeout: float | None = None) -> E2BEntryInfo:
        if user is not None or request_timeout is not None:
            raise UnsupportedCapability("E2B rename options are not supported")
        return E2BEntryInfo.from_payload(self._session.rename_file(old_path, new_path), new_path)

    def remove(self, path: str, *, user: str | None = None,
               request_timeout: float | None = None) -> None:
        if user is not None or request_timeout is not None:
            raise UnsupportedCapability("E2B remove options are not supported")
        self._session.remove_path(path)

    def watch_dir(self, path: str, *, user: str | None = None,
                  request_timeout: float | None = None, recursive: bool = False,
                  include_entry: bool = False, allow_network_mounts: bool = False) -> WatchHandle:
        if user is not None or request_timeout is not None or allow_network_mounts:
            raise UnsupportedCapability("watch custom users, per-call timeouts and network mounts are not supported")
        return WatchHandle(self._session.start_file_watch(path, recursive=recursive,
                                                         include_entry=include_entry))


@dataclass(frozen=True)
class E2BCommandResult:
    stdout: str
    stderr: str
    exit_code: int
    error: str | None = None


class CommandExitException(SandboxError):
    def __init__(self, result: E2BCommandResult):
        super().__init__(result.error or f"command exited with code {result.exit_code}")
        self.stdout, self.stderr, self.exit_code, self.error = result.stdout, result.stderr, result.exit_code, result.error


@dataclass(frozen=True)
class E2BProcessInfo:
    pid: int
    cmd: str
    args: list[str]
    envs: dict[str,str]
    cwd: str | None = None
    tag: str | None = None


def _observation_timeout(timeout):
    if timeout is None:return 0
    if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<=timeout<=86400:
        raise ConfigurationError("command timeout must be seconds in [0,86400]")
    return math.ceil(timeout*1000)


class E2BCommandHandle:
    def __init__(self, native, pid, deadline):
        self._native=native
        self.pid=pid
        self._deadline=deadline
        self._result=None
        self._exception=None
        self._stream=None
        self._disconnected=False
        self._stdout=[]
        self._stderr=[]

    def disconnect(self):
        self._disconnected=True
        if self._stream is not None:
            try:self._stream.close()
            except ValueError:pass  # The active wait loop closes it after a callback returns.

    def kill(self):return self._native.kill()

    def send_stdin(self,data,request_timeout=None):
        self._native.send_stdin(data.encode("utf-8") if isinstance(data,str) else data,request_timeout)
    def close_stdin(self,request_timeout=None):self._native.close_stdin(request_timeout)

    def wait(self,on_pty=None,on_stdout=None,on_stderr=None):
        if on_pty is not None:raise UnsupportedCapability("PTY output is not available")
        for callback in (on_stdout,on_stderr):
            if callback is not None and not callable(callback):raise ConfigurationError("output callback must be callable")
        if self._exception is not None:raise self._exception
        if self._result is not None:
            if self._result.exit_code!=0:raise CommandExitException(self._result)
            return self._result
        try:
            if self._disconnected:raise TransportError("command observer disconnected; use commands.connect")
            remaining=0 if self._deadline is None else math.ceil((self._deadline-time.monotonic())*1000)
            if self._deadline is not None and remaining<=0:raise TimeoutException("command observation timed out; process may still run")
            self._stream=self._native.events(timeout_ms=remaining)
            decoders={name:codecs.getincrementaldecoder("utf-8")(errors="replace") for name in ("stdout","stderr")}
            buffers={"stdout":self._stdout,"stderr":self._stderr}
            callbacks={"stdout":on_stdout,"stderr":on_stderr}
            for event in self._stream:
                if self._disconnected:break
                if event.stream is not None:
                    text=decoders[event.stream].decode(event.data)
                    if text:
                        buffers[event.stream].append(text)
                        if callbacks[event.stream] is not None:callbacks[event.stream](text)
                elif event.result is not None:
                    for name,decoder in decoders.items():
                        text=decoder.decode(b"",final=True)
                        if text:
                            buffers[name].append(text)
                            if callbacks[name] is not None:callbacks[name](text)
                    guest=event.result.guest_result or {}
                    self._result=E2BCommandResult("".join(self._stdout),"".join(self._stderr),event.result.exit_code,guest.get("error"))
            if self._result is None:raise TransportError("command ended without a result")
        except Exception as exc:
            self._exception=exc
            raise
        finally:
            if self._stream is not None:self._stream.close()
        if self._result.exit_code!=0:raise CommandExitException(self._result)
        return self._result


class _E2BCommands:
    def __init__(self,session):self._session=session

    def list(self,request_timeout=None):
        return [E2BProcessInfo(info["pid"],info["entrypoint"],list(info.get("args",[])),dict(info.get("environment") or {}),info.get("cwd") or None)
                for info in self._session.list_commands() if info["state"]=="running" and info.get("pid",0)>1]

    def _find(self,pid,live=False):
        if type(pid) is not int or not 1<pid<=1<<30:raise ConfigurationError("invalid guest command PID")
        for info in reversed(self._session.list_commands()):
            if info.get("pid")==pid and (not live or info["state"]=="running"):return info
        return None

    def kill(self,pid,request_timeout=None):
        info=self._find(pid,True)
        if info is None:return False
        return CommandHandle(self._session,info).kill()

    def connect(self,pid,timeout=60,request_timeout=None):
        duration=_observation_timeout(timeout)
        info=self._find(pid)
        if info is None:raise APIError(404,"command_not_found","command not found")
        return E2BCommandHandle(CommandHandle(self._session,info),pid,None if duration==0 else time.monotonic()+duration/1000)

    def run(self,cmd,background=None,envs=None,user=None,cwd=None,on_stdout=None,on_stderr=None,stdin=None,timeout=60,request_timeout=None):
        if user is not None:raise UnsupportedCapability("custom users are not available yet")
        if stdin is not None and type(stdin) is not bool:raise ConfigurationError("stdin must be boolean")
        if background is not None and type(background) is not bool:raise ConfigurationError("background must be a boolean")
        if background and (on_stdout is not None or on_stderr is not None):raise UnsupportedCapability("Python background callbacks belong on handle.wait")
        if not isinstance(cmd,str) or not cmd or len(cmd.encode("utf-8"))>4096 or "\0" in cmd:raise ConfigurationError("command must be nonempty and at most 4096 bytes")
        for callback in (on_stdout,on_stderr):
            if callback is not None and not callable(callback):raise ConfigurationError("output callback must be callable")
        duration=_observation_timeout(timeout)
        deadline=None if duration==0 else time.monotonic()+duration/1000
        caps=self._session._client.capabilities(template=TemplateSelector(self._session.created.backend,self._session.created.artifact_manifest_sha256))
        if stdin and not caps.get("features",{}).get("interactive_stdin"):raise UnsupportedCapability("interactive stdin is not available on this template")
        if "/bin/bash" not in caps["allowed_entrypoints"]:raise UnsupportedCapability("template has no authorized Bash entrypoint")
        native=self._session.start_command(SessionCommand("/bin/bash",("-l","-c",cmd),timeout_ms=caps["limits"]["max_timeout_ms"],environment=envs,cwd=cwd,interactive_stdin=bool(stdin)))
        while True:
            page=native.poll();info=page["info"]
            if type(info.get("pid")) is int and info["pid"]>1:break
            if page.get("complete"):raise TransportError("command failed before a guest PID was created")
            if deadline is not None and time.monotonic()>=deadline:raise TimeoutException("command start observation timed out")
            time.sleep(0.01)
        handle=E2BCommandHandle(native,info["pid"],deadline)
        return handle if background else handle.wait(on_stdout=on_stdout,on_stderr=on_stderr)

    def send_stdin(self,pid,data,request_timeout=None):
        info=self._find(pid,True)
        if info is None:raise APIError(404,"command_not_found","command not found")
        CommandHandle(self._session,info).send_stdin(data.encode("utf-8") if isinstance(data,str) else data,request_timeout)
    def close_stdin(self,pid,request_timeout=None):
        info=self._find(pid,True)
        if info is None:raise APIError(404,"command_not_found","command not found")
        CommandHandle(self._session,info).close_stdin(request_timeout)


@dataclass(frozen=True)
class E2BSandboxInfo:
    sandbox_id:str
    template_id:str
    metadata:dict[str,str]
    started_at:datetime
    end_at:datetime
    state:str
    cpu_count:int
    memory_mb:int
    envd_version:str
    max_end_at:datetime
    name:str|None=None
    sandbox_domain:str|None=None
    allow_internet_access:bool=False
    network:None=None
    lifecycle:dict[str,Any]|None=None
    volume_mounts:list[dict[str,str]]=field(default_factory=list)

def _e2b_sandbox_info(info):
    if info.memory_mib is None or info.vcpus is None or info.guest_protocol is None or info.max_expires_at is None:raise ProtocolError("template omitted real sandbox metadata")
    try:
        dates=[datetime.fromisoformat(value.replace("Z","+00:00")) for value in (info.created_at,info.expires_at,info.max_expires_at)]
        if any(value.tzinfo is None for value in dates) or dates[0]>dates[1] or dates[1]>dates[2]:raise ValueError()
    except (ValueError,TypeError):raise ProtocolError("invalid session lifecycle dates") from None
    return E2BSandboxInfo(info.id,info.backend,{},dates[0],dates[1],info.state,info.vcpus,info.memory_mib,info.guest_protocol,dates[2],lifecycle={"on_timeout":"kill","auto_resume":False})

class E2BSandboxPaginator:
    def __init__(self,client,limit,cursor,order):
        self._client=client;self._limit=20 if limit is None else limit;self.next_token=cursor;self._order=order or "desc";self._has_next=True;self._lock=threading.Lock()
        if type(self._limit) is not int or not 1<=self._limit<=100 or self._order not in ("asc","desc"):raise ConfigurationError("invalid session pagination limit/order")
        if cursor is not None and (not isinstance(cursor,str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}",cursor)):raise ConfigurationError("invalid session cursor")
    @property
    def has_next(self):return self._has_next
    def next_items(self,**options):
        if options:raise UnsupportedCapability("custom paginator request options are not available")
        if not self._lock.acquire(blocking=False):raise ConfigurationError("pagination request already active")
        try:
            if not self._has_next:raise SandboxError("No more items to fetch")
            page=self._client.list_sessions(limit=self._limit,cursor=self.next_token,order=self._order)
            items=[_e2b_sandbox_info(row) for row in page["sessions"]]
            self.next_token=page["next_cursor"];self._has_next=self.next_token is not None
            return items
        finally:self._lock.release()


class CodeCleanupError(TransportError):
    """Execution termination could not be confirmed; owner close was requested."""

    def __init__(self, execution, original_error, cleanup_error):
        self.execution = execution
        self.original_error = original_error
        self.cleanup_error = cleanup_error
        self.owner_close_requested = True
        super().__init__("code termination could not be confirmed; owner close requested")


class CodeExecutionFailed(SandboxError):
    def __init__(self, execution, status, failure=None):
        self.execution = execution
        self.status = status
        self.failure = failure
        super().__init__(f"code execution {status}: {failure or 'no runtime detail'}")


@dataclass(frozen=True, init=False)
class Context:
    id: str
    language: str
    cwd: str
    _session_id: str | None = field(default=None, repr=False, compare=False)

    def __init__(self, context_id: str, language: str, cwd: str, *, session_id: str | None = None):
        _code_id(context_id)
        object.__setattr__(self, "id", context_id)
        object.__setattr__(self, "language", language)
        object.__setattr__(self, "cwd", cwd)
        object.__setattr__(self, "_session_id", session_id)

    @classmethod
    def from_native(cls, value: CodeContext) -> Context:
        return cls(value.id, value.language, value.cwd, session_id=value.session_id)


@dataclass(frozen=True)
class OutputMessage:
    line: str
    timestamp: int
    error: bool = False

    def __str__(self):
        return self.line


@dataclass(frozen=True)
class ExecutionError:
    name: str
    value: str
    traceback: str

    def to_json(self):
        return json.dumps(vars(self), ensure_ascii=False)


_RESULT_MIME = {"text/plain": "text", "text/html": "html", "text/markdown": "markdown",
                "image/svg+xml": "svg", "image/png": "png", "image/jpeg": "jpeg",
                "application/pdf": "pdf", "text/latex": "latex", "application/json": "json",
                "application/javascript": "javascript"}


class Result:
    def __init__(self, data: dict[str, Any], is_main_result: bool):
        self.mime_data = dict(data)
        self.raw = {_RESULT_MIME.get(mime, mime): value for mime, value in data.items()}
        self.is_main_result = is_main_result
        self.extra = {mime: value for mime, value in data.items() if mime not in _RESULT_MIME}
        for mime, name in _RESULT_MIME.items():
            setattr(self, name, data.get(mime))
        self.data = self.chart = None

    def __getitem__(self, key):
        return getattr(self, key)

    def __repr__(self):
        return f"Result({self.text})" if self.text is not None else "Result(Formats: " + ", ".join(self.formats()) + ")"

    def _repr_html_(self): return self.html
    def _repr_markdown_(self): return self.markdown
    def _repr_svg_(self): return self.svg
    def _repr_png_(self): return self.png
    def _repr_jpeg_(self): return self.jpeg
    def _repr_pdf_(self): return self.pdf
    def _repr_latex_(self): return self.latex
    def _repr_json_(self): return self.json
    def _repr_javascript_(self): return self.javascript

    def formats(self):
        return [name for name in _RESULT_MIME.values() if getattr(self, name) is not None] + list(self.extra)

    def _payload(self):
        return {**{name: getattr(self, name) for name in _RESULT_MIME.values() if getattr(self, name) is not None},
                "is_main_result": self.is_main_result, "extra": self.extra}


@dataclass
class Logs:
    stdout: list[str] = field(default_factory=list)
    stderr: list[str] = field(default_factory=list)

    def to_json(self):
        return json.dumps({"stdout": list(self.stdout), "stderr": list(self.stderr)}, ensure_ascii=False)


@dataclass
class Execution:
    results: list[Result] = field(default_factory=list)
    logs: Logs = field(default_factory=Logs)
    error: ExecutionError | None = None
    execution_count: int | None = None
    execution_id: str | None = None

    @property
    def text(self):
        return next((result.text for result in self.results if result.is_main_result), None)

    def to_json(self):
        return json.dumps({"results": [result._payload() for result in self.results], "logs": self.logs.to_json(),
                           "error": self.error.to_json() if self.error else None}, ensure_ascii=False)


def _code_duration(timeout):
    if timeout is None:
        return 60000
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout < 0 or timeout > 300:
        raise ConfigurationError("code timeout must be in [0,300] seconds")
    return math.ceil(timeout * 1000)


def _code_input(code, environment, timeout_ms):
    if not isinstance(code, str) or "\0" in code or type(timeout_ms) is not int or not 0 <= timeout_ms <= 300000:
        raise ConfigurationError("invalid code or execution timeout")
    env = {} if environment is None else dict(environment) if isinstance(environment, dict) else None
    if env is None or len(env) > 64 or any(not isinstance(key, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", key) or
            not isinstance(value, str) or "\0" in value for key, value in env.items()):
        raise ConfigurationError("invalid code environment")
    try:
        if len(code.encode("utf-8")) > 65536 or sum(len(key.encode()) + len(value.encode()) for key, value in env.items()) > 16384 or any(len(value.encode()) > 8192 for value in env.values()):
            raise ConfigurationError("code or environment exceeds byte budget")
        if len(json.dumps({"code": code, "env": env}, ensure_ascii=False, separators=(",", ":")).encode()) > 96 * 1024:
            raise ConfigurationError("encoded code exceeds kernel frame budget")
    except UnicodeError:
        raise ConfigurationError("code and environment must be UTF-8") from None
    return env


def _code_remaining(deadline, request_timeout):
    duration = _code_timeout(request_timeout)
    if deadline is not None:
        duration = min(duration, deadline - time.monotonic())
        if duration <= 0:
            raise TimeoutException("code execution observation timed out")
    return duration


def _code_rpc_observe(action, deadline):
    try:
        return action()
    except TransportError as error:
        # Classify at the RPC boundary, before cleanup can consume the budget.
        if (deadline is not None and time.monotonic() >= deadline and
                not isinstance(error, (TimeoutException, CodeCleanupError))):
            raise TimeoutException("code execution observation timed out") from error
        raise


def _code_context_ref(controller, value):
    if isinstance(value, CodeContext):
        owner, context_id = value.session_id, value.id
    elif isinstance(value, Context):
        owner, context_id = value._session_id, value.id
    elif isinstance(value, str):
        owner, context_id = None, value
    else:
        raise ConfigurationError("context must be a Context or context ID")
    if owner is not None and owner != controller._session.id:
        raise ConfigurationError("context belongs to another session")
    return _code_id(context_id)


def _code_ready(controller, current, *, request_timeout=None, expected_generation=None, missing_id=None):
    deadline = time.monotonic() + 40
    context_id = missing_id or current.id
    while True:
        if current is not None:
            if expected_generation is not None and current.generation > expected_generation:
                raise APIError(409, "stale_context", "context restarted concurrently")
            if current.state == "failed":
                raise CodeExecutionFailed(None, "context_failed", current.failure)
            if current.state == "idle" and (expected_generation is None or current.generation == expected_generation):
                return current
            if current.state in ("running", "interrupting"):
                raise APIError(409, "context_busy", "context is executing another cell")
        duration = _code_remaining(deadline, request_timeout)
        time.sleep(min(0.02, duration))
        try:
            current = controller.get(context_id, request_timeout=_code_remaining(deadline, request_timeout))
        except APIError as error:
            if missing_id is None or error.status != 404 or error.code != "code_not_found":
                raise


def _code_stop_confirm(execution):
    deadline, cursor, next_cancel = time.monotonic() + 8, 0, 0.0
    last_error = TransportError("no terminal journal confirmation")
    while time.monotonic() < deadline:
        if time.monotonic() >= next_cancel:
            try:
                execution.cancel(request_timeout=min(2, max(0.001, deadline - time.monotonic())))
            except Exception as error:
                last_error = error
            next_cancel = time.monotonic() + 0.25
        try:
            page = execution.poll(cursor, request_timeout=min(2, max(0.001, deadline - time.monotonic())))
            if page["status"] in _CODE_TERMINAL and (page["events_evicted"] or page["next_sequence"] == page["last_sequence"]):
                return
            cursor = page["next_sequence"]
        except ProtocolError:
            raise
        except Exception as error:
            last_error = error
        time.sleep(min(0.02, max(0, deadline - time.monotonic())))
    raise last_error


class _CodeStopGuard:
    def __init__(self, execution, deadline):
        self.execution = execution
        self.deadline = deadline
        self._lock = threading.Lock()
        self._active = True
        self._error = None
        self._timer = None
        if deadline is not None:
            self._timer = threading.Timer(max(0, deadline - time.monotonic()), self._expire)
            self._timer.daemon = True

    def start(self):
        if self._timer is not None:
            self._timer.start()

    def _expire(self):
        with self._lock:
            if self._active:
                self._stop()

    def _stop(self):
        self._active = False
        try:
            _code_stop_confirm(self.execution)
        except Exception as error:
            self._error = error
            controller = self.execution._controller
            try:
                controller._session._client._exchange("DELETE", controller._path, accepted=(204,), timeout_seconds=6)
            except Exception:
                pass

    def finish(self, original=None):
        if self._timer is not None:
            self._timer.cancel()
        with self._lock:
            if original is not None and self._active:
                self._stop()
            self._active = False
            if self._error is not None:
                raise CodeCleanupError(self.execution, original, self._error) from original


def _e2b_run_code(controller, code, *, language=None, context=None, on_stdout=None, on_stderr=None,
                  on_result=None, on_error=None, envs=None, timeout=None, request_timeout=None):
    if language is not None and context is not None:
        raise ConfigurationError("provide language or context, not both")
    if context is not None and not isinstance(context, (Context, CodeContext)):
        raise ConfigurationError("run_code context must be a Context")
    for callback in (on_stdout, on_stderr, on_result, on_error):
        if callback is not None and (not callable(callback) or inspect.iscoroutinefunction(callback)):
            raise ConfigurationError("Python code callbacks must be synchronous callables")
    duration = _code_duration(timeout)
    envs = _code_input(code, envs, duration)
    _code_timeout(request_timeout)
    if context is None:
        current = controller.default("python" if language is None else language, request_timeout=request_timeout)
    else:
        current = controller.get(_code_context_ref(controller, context), request_timeout=request_timeout)
    current = _code_ready(controller, current, request_timeout=request_timeout, expected_generation=current.generation)
    deadline = None if duration == 0 else time.monotonic() + duration / 1000
    execution_id = secrets.token_hex(12)
    handle = controller.connect_execution(current, execution_id)
    guard = _CodeStopGuard(handle, deadline)
    result, cursor, attempted = Execution(execution_id=execution_id), 0, False
    decoders = {stream: codecs.getincrementaldecoder("utf-8")("replace") for stream in ("stdout", "stderr")}
    callbacks = {"stdout": on_stdout, "stderr": on_stderr}
    def check_deadline():
        _code_remaining(deadline, request_timeout)
    def output(stream, text):
        if text:
            getattr(result.logs, stream).append(text)
            if callbacks[stream]:
                returned = callbacks[stream](OutputMessage(text, time.time_ns(), stream == "stderr"))
                if inspect.isawaitable(returned):
                    if inspect.iscoroutine(returned): returned.close()
                    raise ConfigurationError("Python code callbacks must not return awaitables")
                check_deadline()
    try:
        try:
            # The guard also operates while the submit RPC or a callback blocks.
            submit_timeout = _code_remaining(deadline, request_timeout)
            guard.start()
            attempted = True
            _code_rpc_observe(lambda: controller.execute(current, code, execution_id=execution_id,
                              environment=envs, timeout_ms=duration, request_timeout=submit_timeout), deadline)
        except APIError as error:
            if error.status in (400, 403, 404, 409, 429, 501):
                guard.finish()
                raise
            raise
        except ConfigurationError:
            guard.finish()
            raise
        while True:
            page = _code_rpc_observe(lambda: handle.poll(cursor,
                                     request_timeout=_code_remaining(deadline, request_timeout)), deadline)
            if page["events_evicted"]:
                raise ProtocolError("code output was evicted before delivery")
            for row in page["events"]:
                check_deadline()
                event = row["event"]
                kind = event["type"]
                if kind in decoders:
                    output(kind, decoders[kind].decode(base64.b64decode(event["data"])))
                elif kind == "result":
                    item = Result(event["data"], event["is_main_result"])
                    result.results.append(item)
                    if on_result:
                        returned = on_result(item)
                        if inspect.isawaitable(returned):
                            if inspect.iscoroutine(returned): returned.close()
                            raise ConfigurationError("Python code callbacks must not return awaitables")
                        check_deadline()
                elif kind == "error":
                    result.error = ExecutionError(event["name"], event["value"], event["traceback"])
                    if on_error:
                        returned = on_error(result.error)
                        if inspect.isawaitable(returned):
                            if inspect.iscoroutine(returned): returned.close()
                            raise ConfigurationError("Python code callbacks must not return awaitables")
                        check_deadline()
            cursor = page["next_sequence"]
            if page["status"] in _CODE_TERMINAL and cursor == page["last_sequence"]:
                for stream in decoders:
                    output(stream, decoders[stream].decode(b"", final=True))
                check_deadline()
                if page["status"] == "timed_out":
                    raise TimeoutException("guest code execution timed out")
                if page["status"] != "completed":
                    raise CodeExecutionFailed(handle, page["status"], page["failure"])
                guard.finish()
                return result
            time.sleep(min(0.02, _code_remaining(deadline, request_timeout)))
    except BaseException as error:
        if not hasattr(error, "execution"):
            error.execution = handle
        guard.finish(error if attempted else None)
        raise


def _e2b_create_context(controller, cwd=None, language=None, request_timeout=None):
    context_id = secrets.token_hex(12)
    current = None
    try:
        try:
            current = controller.create("python" if language is None else language,
                                        "/workspace" if cwd is None else cwd, context_id=context_id,
                                        request_timeout=request_timeout)
        except (TransportError, ProtocolError, APIError) as error:
            if not hasattr(error, "context_id") or isinstance(error, APIError) and error.status < 500:
                raise
        ready = _code_ready(controller, current, request_timeout=request_timeout,
                            expected_generation=1, missing_id=context_id if current is None else None)
        return Context.from_native(ready)
    except BaseException as error:
        error.context_id, error.session_id = context_id, controller._session.id
        raise


def _e2b_context_mutation(controller, context, restart):
    context_id = _code_context_ref(controller, context)
    current = controller.get(context_id)
    try:
        if restart:
            starting = controller.restart(current)
            _code_ready(controller, starting, expected_generation=current.generation + 1)
        else:
            controller.remove(current)
            deadline = time.monotonic() + 40
            while True:
                try:
                    observed = controller.get(context_id, request_timeout=_code_remaining(deadline, None))
                except APIError as error:
                    if error.status == 404 and error.code == "code_not_found":
                        return
                    raise
                if observed.generation != current.generation:
                    raise APIError(409, "stale_context", "context restarted concurrently")
                time.sleep(min(0.02, _code_remaining(deadline, None)))
    except BaseException as error:
        error.context_id, error.session_id = context_id, controller._session.id
        raise


class Sandbox:
    """Explicit E2B 2.51.0 facade; requires a configured native Client."""

    def __init__(self, session: Session):
        self._session = session
        self.sandbox_id = session.id
        self.files = _E2BFilesystem(session)
        self.commands = _E2BCommands(session)

    @classmethod
    def create(cls, template: str | None = None, timeout: int | None = None, *,
               client: Client, **opts: Any) -> Sandbox:
        if not isinstance(client, Client):
            raise ConfigurationError("E2B facade requires a native Client")
        if template != "firecracker-linux" or opts:
            raise UnsupportedCapability("E2B facade requires the signed firecracker-linux template without extra options")
        if timeout is not None and (type(timeout) is not int or not 1 <= timeout <= 300):
            raise ConfigurationError("timeout must be 1-300 seconds")
        request = SessionRequest(ttl_ms=timeout * 1000 if timeout is not None else None)
        return cls(client.create_session(request))

    @classmethod
    def connect(cls, sandbox_id: str, *, client: Client, timeout: int | None = None,
                on_resume: str = "restore", **opts: Any) -> Sandbox:
        if not isinstance(client, Client):
            raise ConfigurationError("E2B facade requires a native Client")
        if timeout is not None or on_resume != "restore" or opts:
            raise UnsupportedCapability("paused resume and live timeout update are not available")
        return cls(client.connect_session(sandbox_id))

    def is_running(self, request_timeout: float | None = None) -> bool:
        if request_timeout is not None:
            raise UnsupportedCapability("per-call E2B request timeout is not available")
        try:
            self._session.info()
        except APIError as exc:
            if exc.status == 404 and exc.code == "not_found":
                return False
            raise
        return True

    def kill(self) -> bool:
        try:
            self._session.close()
        except APIError as exc:
            if exc.status == 404 and exc.code == "not_found":
                return False
            raise
        return True

    @classmethod
    def list(cls,query=None,limit=None,next_token=None,order=None,*,client:Client,**options):
        if not isinstance(client,Client):raise ConfigurationError("E2B facade requires a native Client")
        if options or query not in (None,{}, {"state":["running"]}):raise UnsupportedCapability("custom session query options are not available")
        return E2BSandboxPaginator(client,limit,next_token,order)

    def get_info(self,**options):
        if options:raise UnsupportedCapability("custom info request options are not available")
        return _e2b_sandbox_info(self._session.info())

    def set_timeout(self,timeout:int,**options):
        if options:raise UnsupportedCapability("custom timeout request options are not available")
        if type(timeout) is not int or not 1<=timeout<=300:raise ConfigurationError("timeout must be in [1,300] seconds")
        self._session.set_timeout(timeout*1000)

    def pause(self, *_args: Any, **_kwargs: Any) -> None:
        raise UnsupportedCapability("E2B pause is not available")

    def fork(self, *_args: Any, **_kwargs: Any) -> None:
        raise UnsupportedCapability("E2B stateful fork is not available")

    def get_host(self, *_args: Any, **_kwargs: Any) -> None:
        raise UnsupportedCapability("E2B port tunnels are not available")

    def upload_url(self, *_args: Any, **_kwargs: Any) -> None:
        raise UnsupportedCapability("E2B upload URLs are not available")

    def download_url(self, *_args: Any, **_kwargs: Any) -> None:
        raise UnsupportedCapability("E2B download URLs are not available")

    def run_code(self, code: str, language=None, context=None, on_stdout=None, on_stderr=None,
                 on_result=None, on_error=None, envs=None, timeout=None, request_timeout=None) -> Execution:
        return _e2b_run_code(self._session.code, code, language=language, context=context,
            on_stdout=on_stdout, on_stderr=on_stderr, on_result=on_result, on_error=on_error,
            envs=envs, timeout=timeout, request_timeout=request_timeout)

    def create_code_context(self, cwd=None, language=None, request_timeout=None) -> Context:
        return _e2b_create_context(self._session.code, cwd, language, request_timeout)

    def list_code_contexts(self) -> list[Context]:
        return [Context.from_native(row) for row in self._session.code.list()]

    def restart_code_context(self, context) -> None:
        _e2b_context_mutation(self._session.code, context, True)

    def remove_code_context(self, context) -> None:
        _e2b_context_mutation(self._session.code, context, False)


__all__ = ["Context", "Execution", "ExecutionError", "OutputMessage", "Result", "Logs", "CodeCleanupError", "CodeExecutionFailed", "CodeContext", "CodeContexts", "CodeExecution", "E2BSandboxInfo", "E2BSandboxPaginator", "APIError", "Client", "ConfigurationError", "E2BEntryInfo", "E2BWriteInfo", "InputFile", "JobRequest",
           "JobResult", "ProtocolError", "Sandbox", "SandboxError", "Session", "SessionCommand",
           "SessionInfo", "SessionRequest", "TemplateMismatch", "TemplateSelector",
           "TransportError", "UnsupportedCapability"]
