"""Native port framing, half-close and uncertain outcome semantics."""
import io
import json
import socket
import struct
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from osv_sandbox_client import (ConfigurationError, PortConnection, ProtocolError,
                                SessionPorts, TimeoutException, TransportError,
                                UnsupportedCapability)

SID, CID = "a" * 24, "b" * 24


def info(**changes):
    return dict(id=CID, port=8080, status="cancelled", sent_bytes=0,
                received_bytes=0, error="cancelled", **changes)


def frame(kind, data=b""):
    return struct.pack(">BI", kind, len(data)) + data


class PortTests(unittest.TestCase):
    def handle(self, payload=b"", changes=None):
        calls = []
        def exchange(method, path, **options):
            calls.append((method, path, options))
            return {"session_id": SID, "connection": changes or info()}
        session = SimpleNamespace(id=SID, _client=SimpleNamespace(_exchange=exchange))
        handle = SessionPorts(session).connection(8080, CID)
        handle._socket = SimpleNamespace(sendall=lambda data: calls.append(data), shutdown=lambda how: None)
        handle._response = SimpleNamespace(fp=io.BytesIO(payload), close=lambda: None)
        self.addCleanup(handle.close)
        return handle, calls

    def test_binary_eof_finished_and_exact_delivery_counts(self):
        terminal = dict(info(), status="completed", error=None, sent_bytes=2, received_bytes=2)
        handle, calls = self.handle(frame(1, b"\0\xff") + frame(2) + frame(4, json.dumps(terminal).encode()))
        handle.write(b"\xff\0")
        handle.close_write()
        self.assertEqual(calls, [frame(1, b"\xff\0"), frame(2)])
        self.assertEqual(handle.read_frame().data, b"\0\xff")
        self.assertEqual(handle.read_frame().kind, "eof")
        self.assertEqual(handle.read_frame().info, terminal)
        self.assertEqual(handle.info()["status"], "cancelled")

    def test_server_eof_does_not_close_client_write_direction(self):
        handle, calls = self.handle(frame(2))
        self.assertEqual(handle.read_frame().kind, "eof")
        handle.write(b"after peer EOF")
        handle.close_write()
        self.assertEqual(calls[-2:], [frame(1, b"after peer EOF"), frame(2)])
        with self.assertRaises(TransportError):
            handle.read_frame()

    def test_invalid_frame_headers_are_rejected_before_body_allocation(self):
        for kind, size in [(0, 0), (1, 0), (1, 16385), (2, 1), (3, 0), (4, 0), (4, 4097), (255, 0xffffffff)]:
            with self.subTest(kind=kind, size=size):
                handle, _ = self.handle(struct.pack(">BI", kind, size))
                with self.assertRaises(ProtocolError):
                    handle.read_frame()
                self.assertTrue(handle._closed)

    def test_invalid_proofs_and_post_eof_data_never_become_success(self):
        for changes in [dict(id="c"*24), dict(port=8081), dict(status="open", error=None),
                        dict(status="completed", error=None), dict(received_bytes=1), dict(sent_bytes=1),
                        dict(status="failed", error="arbitrary"), dict(sent_bytes=True), dict(extra=1)]:
            with self.subTest(changes=changes):
                terminal = dict(info(), **changes)
                handle, _ = self.handle(frame(4, json.dumps(terminal).encode()))
                with self.assertRaises(ProtocolError):
                    handle.read_frame()
        for payload in [frame(2) + frame(2), frame(2) + frame(1, b"x")]:
            handle, _ = self.handle(payload)
            handle.read_frame()
            with self.assertRaises(ProtocolError):
                handle.read_frame()
        for payload in [b"[]", b"null", b"{", b"\xff"]:
            handle, _ = self.handle(frame(4, payload))
            with self.assertRaises(ProtocolError):
                handle.read_frame()

    def test_truncated_header_body_and_missing_finished_preserve_query(self):
        for payload in [b"", b"\x01", struct.pack(">BI", 1, 4) + b"xx", frame(4, b"{")[:5]]:
            with self.subTest(payload=payload):
                handle, calls = self.handle(payload)
                with self.assertRaises(TransportError):
                    handle.read_frame()
                self.assertEqual(handle.cancel()["status"], "cancelled")
                self.assertEqual([call[0] for call in calls if isinstance(call, tuple)], ["DELETE"])

    def test_control_never_waits_for_data_locks_or_new_capabilities(self):
        handle, calls = self.handle()
        handle._read_lock.acquire(); handle._write_lock.acquire()
        self.addCleanup(handle._read_lock.release); self.addCleanup(handle._write_lock.release)
        self.assertEqual(handle.info()["id"], CID)
        self.assertEqual(handle.cancel()["id"], CID)
        self.assertEqual([call[0] for call in calls], ["GET", "DELETE"])
        with self.assertRaises(ConfigurationError): handle.read_frame()
        with self.assertRaises(ConfigurationError): handle.write(b"x")

    def test_local_input_limits_half_close_and_identity_are_explicit(self):
        handle, calls = self.handle()
        for data in [b"", b"x"*16385, "text"]:
            with self.assertRaises(ConfigurationError): handle.write(data)
        self.assertEqual(calls, [])
        handle._maximum = 1
        handle.write(b"x")
        with self.assertRaises(ConfigurationError): handle.write(b"x")
        handle.close_write()
        with self.assertRaises(ConfigurationError): handle.close_write()
        with self.assertRaises(AttributeError): handle.id = "c"*24

    def test_partial_write_is_not_replayed_and_retains_control(self):
        handle, calls = self.handle()
        def failed(data):
            calls.append(data[:2])
            raise OSError("partial write")
        handle._socket.sendall = failed
        with self.assertRaises(TransportError): handle.write(b"once")
        self.assertEqual(calls, [frame(1, b"once")[:2]])
        self.assertEqual(handle.info()["id"], CID)

    def test_absolute_timeout_wakes_blocked_reader_without_peer_traffic(self):
        local, peer = socket.socketpair()
        handle, _ = self.handle()
        handle._socket = local
        reader = local.makefile("rb")
        handle._response = SimpleNamespace(fp=reader, close=reader.close)
        self.addCleanup(peer.close); self.addCleanup(local.close)
        handle._timer = threading.Timer(0.03, handle._expire)
        handle._timer.daemon = True; handle._timer.start()
        started = time.monotonic()
        with self.assertRaises(TimeoutException): handle.read_frame()
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual(handle.info()["id"], CID)

    def test_unknown_open_reply_keeps_generated_handle_and_never_retries(self):
        session = SimpleNamespace(id=SID, capabilities=lambda **kw: {
            "backend": "firecracker-linux", "artifact_manifest_protocol": "osv-sandbox-artifacts/v6",
            "features": {"port_forward": True}})
        ports = SessionPorts(session)
        with patch.object(PortConnection, "_open", side_effect=TransportError("ACK lost")) as opened:
            with self.assertRaises(TransportError) as caught: ports.open(8080)
            self.assertRegex(caught.exception.connection.id, r"^[a-f0-9]{24}$")
            self.assertEqual(opened.call_count, 1)
        session.capabilities = lambda **kw: {"backend": "firecracker-linux", "artifact_manifest_protocol": "osv-sandbox-artifacts/v5", "features": {"port_forward": True}}
        with patch.object(PortConnection, "_open") as opened:
            with self.assertRaises(UnsupportedCapability): ports.open(8080)
            opened.assert_not_called()

    def test_invalid_ids_and_limits_do_not_open(self):
        ports = SessionPorts(SimpleNamespace(id=SID))
        for port, cid in [(0, CID), (65536, CID), (True, CID), (8080, "A"*24), (8080, "../")]:
            with self.assertRaises(ConfigurationError): ports.connection(port, cid)
        for limits in [dict(max_bytes=0), dict(max_bytes=True), dict(timeout_ms=300001), dict(idle_timeout_ms=-1)]:
            with self.assertRaises(ConfigurationError): ports.open(8080, **limits)

    def test_v8_signed_port_profile_opens_with_existing_binary_protocol(self):
        session = SimpleNamespace(id=SID, capabilities=lambda **_: {
            "backend":"firecracker-linux", "artifact_manifest_protocol":"osv-sandbox-artifacts/v8",
            "features":{"port_forward":True}})
        with patch.object(PortConnection, "_open") as opened:
            handle = SessionPorts(session).open(8080, connection_id=CID)
            self.assertEqual(handle.id, CID)
            opened.assert_called_once()


if __name__ == "__main__":
    unittest.main()
