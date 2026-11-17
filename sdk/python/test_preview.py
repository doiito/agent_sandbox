"""Preview creation uncertainty, binding validation and cleanup without admission."""
import unittest
from types import SimpleNamespace

from osv_sandbox_client import (APIError, ConfigurationError, ProtocolError, SessionPorts,
                                TransportError, UnsupportedCapability)

SID, PID = "a" * 24, "b" * 24
ORIGIN = "https://" + "c" * 24 + ".preview.test:9444"


def metadata(creating=False, **changes):
    value = dict(protocol="osv-sandbox-preview/v1", id=PID, session_id=SID, port=8080,
                 origin=ORIGIN, created_at="2026-11-07T00:00:00.123456789Z",
                 expires_at="2026-11-07T00:01:00.123456789Z", status="active")
    if creating:
        value["bootstrap_url"] = ORIGIN + "/.osv/authorize?token=" + "d" * 64
    return value | changes


class PreviewTests(unittest.TestCase):
    def ports(self, *, response=None, failing=False):
        calls = []
        def exchange(method, path, *args, **kwargs):
            calls.append((method, path, args, kwargs))
            if failing and method == "POST":
                raise TransportError("response lost")
            return response if response is not None else metadata(method == "POST", status="revoked" if method == "DELETE" else "active")
        session = SimpleNamespace(id=SID, _client=SimpleNamespace(_exchange=exchange),
            capabilities=lambda **kwargs: dict(backend="firecracker-linux", artifact_manifest_protocol="osv-sandbox-artifacts/v6",
                features=dict(port_forward=True, port_preview=True)))
        return SessionPorts(session), calls

    def test_create_once_and_secret_free_independent_cleanup(self):
        ports, calls = self.ports()
        handle = ports.create_preview(8080, preview_id=PID, ttl_ms=60000, request_timeout=2)
        self.assertEqual(handle.bootstrap_url, metadata(True)["bootstrap_url"])
        self.assertNotIn("token", repr(handle))
        copy = handle.created
        copy["origin"] = "changed"
        self.assertEqual(handle.created["origin"], ORIGIN)
        ports._session.capabilities = lambda **kwargs: self.fail("cleanup must not discover new admission")
        self.assertNotIn("bootstrap_url", handle.info())
        self.assertEqual(ports.preview(8080, PID).revoke()["status"], "revoked")
        self.assertEqual([v[0] for v in calls], ["POST", "GET", "DELETE"])
        self.assertEqual(calls[0][2], ({"ttl_ms": 60000},))
        self.assertEqual(calls[0][3]["accepted"], (201,))
        with self.assertRaises(AttributeError): handle.id = "e" * 24

    def test_uncertain_create_retains_id_without_replay_or_revoke(self):
        ports, calls = self.ports(failing=True)
        with self.assertRaises(TransportError) as caught:
            ports.create_preview(8080, preview_id=PID)
        handle = caught.exception.preview
        self.assertEqual(handle.id, PID)
        self.assertIsNone(handle.bootstrap_url)
        self.assertEqual([v[0] for v in calls], ["POST"])
        self.assertEqual(handle.info()["status"], "active")
        self.assertNotIn("bootstrap_url", handle.info())
        handle.revoke()

    def test_invalid_local_inputs_do_not_send_requests(self):
        ports, calls = self.ports()
        for port in (True, 0, 65536, "8080"):
            with self.assertRaises(ConfigurationError): ports.create_preview(port)
        for ttl in (True, 999, 300001, 1000.5):
            with self.assertRaises(ConfigurationError): ports.create_preview(8080, ttl_ms=ttl)
        with self.assertRaises(ConfigurationError): ports.preview(8080, "../bad")
        with self.assertRaises(ConfigurationError): ports.create_preview(8080, request_timeout=0)
        self.assertEqual(calls, [])

    def test_disabled_old_and_wrong_backend_capabilities_reject_before_post(self):
        for cap in ({}, dict(backend="firecracker-linux", artifact_manifest_protocol="osv-sandbox-artifacts/v5", features=dict(port_forward=True, port_preview=True)),
                    dict(backend="osv", artifact_manifest_protocol="osv-sandbox-artifacts/v6", features=dict(port_forward=True, port_preview=True))):
            ports, calls = self.ports()
            ports._session.capabilities = lambda **kwargs: cap
            with self.assertRaises(UnsupportedCapability): ports.create_preview(8080, preview_id=PID)
            self.assertEqual(calls, [])

    def test_malformed_proofs_never_expose_a_successful_create(self):
        for change in (dict(id="e"*24), dict(session_id="f"*24), dict(port=True), dict(port=8081), dict(extra="bad"),
                       dict(protocol="other"), dict(status="unknown"), dict(origin="https://user@evil.test"),
                       dict(origin=ORIGIN+"/"), dict(origin=ORIGIN+"?x=1"), dict(created_at="2026-02-30T00:00:00Z"),
                       dict(expires_at="2026-11-07T00:00:00.123456789Z"), dict(expires_at="2026-11-07T00:10:00Z"),
                       dict(bootstrap_url="https://evil.test/.osv/authorize?token="+"d"*64),
                       dict(bootstrap_url=metadata(True)["bootstrap_url"]+"&extra=1")):
            with self.subTest(change=list(change)):
                ports, calls = self.ports(response=metadata(True, **change))
                with self.assertRaises(ProtocolError) as caught: ports.create_preview(8080, preview_id=PID)
                self.assertEqual(caught.exception.preview.id, PID)
                self.assertEqual(len(calls), 1)
        ports, _ = self.ports(response=metadata(True, expires_at="2026-11-07T00:00:00.123456790Z"))
        self.assertIsNotNone(ports.create_preview(8080, preview_id=PID).bootstrap_url)

    def test_control_secret_state_and_create_binding_cannot_change(self):
        for response in (metadata(True), metadata(extra="bad"), metadata(port=8081)):
            ports, _ = self.ports(response=response)
            with self.assertRaises(ProtocolError): ports.preview(8080, PID).info()
        ports, _ = self.ports(response=metadata())
        with self.assertRaises(ProtocolError): ports.preview(8080, PID).revoke()
        ports, _ = self.ports()
        handle = ports.create_preview(8080, preview_id=PID)
        ports._session._client._exchange = lambda *args, **kwargs: metadata(origin=ORIGIN.replace("c"*24, "e"*24))
        with self.assertRaises(ProtocolError): handle.info()


if __name__ == "__main__": unittest.main()
