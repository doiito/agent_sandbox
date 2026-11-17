"""Native code handles: immutable bindings, uncertainty, paging and admission."""
import base64
from dataclasses import FrozenInstanceError
import json
import unittest
from unittest.mock import patch

from osv_sandbox_client import (CodeContext, ConfigurationError, ProtocolError,
                                Session, SessionInfo, TransportError, UnsupportedCapability)
from test_client import DIGEST, SESSION_ID, FakeOpener, Reply, capabilities, make_client, session_info

CID, EID = "c" * 24, "e" * 24

def code_caps():
    value = capabilities()
    value.update(session_id=SESSION_ID, artifact_manifest_protocol="osv-sandbox-artifacts/v5",
                 code_runtime={"kernel_protocol": "osv-code-kernel/v2"},
                 code_languages=["python", "javascript", "typescript"])
    value["features"]["code_contexts"] = True
    return value

def context(**changes):
    value = dict(session_id=SESSION_ID, id=CID, generation=1, language="python", cwd="/workspace",
                 state="idle", pid=42, failure=None, discarded_late_events=0, discarded_late_bytes=0)
    value.update(changes)
    return value

def page(events=None, **changes):
    value = dict(session_id=SESSION_ID, id=EID, context_id=CID, generation=1, language="python",
                 status="completed", events=events if events is not None else [
                     {"sequence": 1, "event": {"type": "started"}},
                     {"sequence": 2, "event": {"type": "finished", "status": "completed", "context_usable": True}}],
                 next_sequence=2, last_sequence=2, events_evicted=False, failure=None)
    value.update(changes)
    return value

def session(replies):
    opener = FakeOpener(replies)
    client = make_client(opener)
    return Session(client, SessionInfo.from_payload(session_info())), opener


class NativeCodeTests(unittest.TestCase):
    def test_composed_v6_retains_code_capability_and_runtime_validation(self):
        for protocol in ("osv-sandbox-artifacts/v6", "osv-sandbox-artifacts/v7", "osv-sandbox-artifacts/v8"):
            cap = dict(code_caps(), artifact_manifest_protocol=protocol)
            native, _ = session([Reply(200, cap), Reply(200, context())])
            self.assertEqual(native.code.default().id, CID)
        cap = dict(cap, code_runtime={"kernel_protocol": "unknown"})
        native, _ = session([Reply(200, cap)])
        with self.assertRaises(UnsupportedCapability): native.code.default()

    def test_bound_capabilities_reject_wrong_owner_template_and_authentication(self):
        for changes in [{"session_id":"d"*24},{"backend":"firecracker-osv"},
                        {"artifact_manifest_sha256":"b"*64},{"artifact_authenticated":False}]:
            native, opener = session([Reply(200,dict(code_caps(),**changes))])
            with self.assertRaises(ProtocolError): native.code.default()
            self.assertEqual(len(opener.requests),1)

    def test_code_discovery_uses_owner_endpoint_after_new_template_admission_expires(self):
        native, _ = session([])
        calls=[]
        def exchange(method,path,payload=None,**options):
            calls.append(path)
            if path.startswith('/v1/capabilities'): raise AssertionError('new admission queried')
            if path.endswith('/capabilities'): return code_caps()
            return context()
        with patch.object(native._client,'_exchange',side_effect=exchange):
            self.assertEqual(native.capabilities()['session_id'],SESSION_ID)
            self.assertEqual(native.code.default().id,CID)
        self.assertTrue(all(path.startswith('/v2/sessions/'+SESSION_ID) for path in calls))

    def test_context_lifecycle_uses_snapshot_generation_and_real_transition(self):
        native, opener = session([Reply(200, code_caps()), Reply(201, context(state="starting", pid=None)),
            Reply(200, context()), Reply(200, {"session_id": SESSION_ID, "contexts": [context()]}),
            Reply(202, context(state="stopping")), Reply(202, {"session_id": SESSION_ID, "context_id": CID, "removed": True})])
        created = native.code.create(context_id=CID, request_timeout=2)
        self.assertEqual(created.state, "starting")
        with self.assertRaises(FrozenInstanceError):
            created.generation = 9
        current = native.code.get(CID)
        self.assertEqual(native.code.list(), [current])
        self.assertEqual(native.code.restart(current).state, "stopping")
        native.code.remove(current)
        self.assertEqual(opener.requests[1][1], 2)
        self.assertEqual(opener.requests[0][1], 2)
        self.assertEqual(json.loads(opener.requests[-2][0].data), {"generation": 1})
        self.assertTrue(opener.requests[-1][0].full_url.endswith(CID + "?generation=1"))
        self.assertTrue(opener.requests[0][0].full_url.endswith('/v2/sessions/' + SESSION_ID + '/capabilities'))

    def test_default_and_execute_preserve_known_id_empty_source_and_zero_timeout(self):
        ack = {"session_id": SESSION_ID, "execution_id": EID, "accepted": True}
        native, opener = session([Reply(200, code_caps()), Reply(200, context()), Reply(202, ack)])
        current = native.code.default()
        handle = native.code.execute(current, "", execution_id=EID, timeout_ms=0, environment={"VALUE": "中文"})
        self.assertEqual(handle.id, EID)
        self.assertEqual(handle.context, current)
        payload = json.loads(opener.requests[-1][0].data)
        self.assertEqual(payload["timeout_ms"], 0)
        self.assertEqual(payload["code"], "")
        self.assertEqual(payload["environment"], {"VALUE": "中文"})

    def test_transport_loss_exposes_handle_without_replay_or_implicit_cancel(self):
        native, _ = session([])
        calls = []
        def exchange(method, path, payload=None, **options):
            calls.append((method, path, payload))
            if path.endswith("/capabilities"):
                return code_caps()
            if method == "POST":
                raise TransportError("lost acknowledgment")
            if method == "DELETE":
                return {"session_id": SESSION_ID, "execution_id": EID, "accepted": True}
            return page()
        with patch.object(native._client, "_exchange", side_effect=exchange):
            with self.assertRaises(TransportError) as caught:
                native.code.execute(CodeContext.from_payload(context(), SESSION_ID), "side_effect()", execution_id=EID)
            handle = caught.exception.execution
            self.assertEqual(len([call for call in calls if call[0] == "POST"]), 1)
            self.assertEqual(len(calls), 2)
            self.assertEqual(handle.poll()["status"], "completed")
            handle.cancel()
            self.assertEqual(len([call for call in calls if call[0] == "POST"]), 1)

    def test_lost_context_creation_reply_retains_generated_identity(self):
        native, _ = session([])
        calls = []
        def exchange(method, path, payload=None, **options):
            calls.append((method, path, payload))
            if path.endswith("/capabilities"):
                return code_caps()
            if method == "POST":
                raise TransportError("lost create reply")
            return context(id=calls[1][2]["context_id"])
        with patch.object(native._client, "_exchange", side_effect=exchange):
            with self.assertRaises(TransportError) as caught:
                native.code.create()
            self.assertEqual(caught.exception.session_id, SESSION_ID)
            self.assertEqual(caught.exception.context_id, calls[1][2]["context_id"])
            self.assertEqual(native.code.get(caught.exception.context_id).id, caught.exception.context_id)
            self.assertEqual(len(calls), 3)
            self.assertEqual(len([call for call in calls if call[0] == "POST"]), 1)

    def test_completed_execution_still_pages_all_output_and_preserves_json_integer(self):
        first = page([{ "sequence": 1, "event": {"type": "started"}},
                      { "sequence": 2, "event": {"type": "result", "data": {"application/json": {"integer": 9007199254740993}}, "is_main_result": False}}], last_sequence=3)
        last = page([{ "sequence": 3, "event": {"type": "finished", "status": "completed", "context_usable": False}}], last_sequence=3, next_sequence=3)
        native, _ = session([Reply(200, first), Reply(200, last)])
        handle = native.code.connect_execution(CodeContext.from_payload(context(), SESSION_ID), EID)
        initial = handle.poll()
        self.assertLess(initial["next_sequence"], initial["last_sequence"])
        self.assertEqual(initial["events"][1]["event"]["data"]["application/json"]["integer"], 9007199254740993)
        self.assertFalse(handle.poll(2)["events"][0]["event"]["context_usable"])

    def test_cancel_before_submit_has_no_fake_started_and_eviction_is_explicit(self):
        placeholder = page([{ "sequence": 1, "event": {"type": "finished", "status": "cancelled", "context_usable": True}}],
                           status="cancelled", failure="cancelled_before_submit", last_sequence=1, next_sequence=1)
        evicted = page([], next_sequence=0, events_evicted=True)
        native, _ = session([Reply(200, placeholder), Reply(200, evicted)])
        handle = native.code.connect_execution(CodeContext.from_payload(context(), SESSION_ID), EID)
        self.assertEqual(handle.poll()["events"][0]["event"]["type"], "finished")
        self.assertTrue(handle.poll()["events_evicted"])

    def test_binary_stdio_and_empty_error_fields_remain_data(self):
        events = [{"sequence": 1, "event": {"type": "started"}},
                  {"sequence": 2, "event": {"type": "stdout", "data": base64.b64encode(b"\x00\xff").decode()}},
                  {"sequence": 3, "event": {"type": "error", "name": "Error", "value": "", "traceback": ""}},
                  {"sequence": 4, "event": {"type": "finished", "status": "completed", "context_usable": True}}]
        native, _ = session([Reply(200, page(events, next_sequence=4, last_sequence=4))])
        result = native.code.connect_execution(CodeContext.from_payload(context(), SESSION_ID), EID).poll()
        self.assertEqual(base64.b64decode(result["events"][1]["event"]["data"]), b"\x00\xff")
        self.assertEqual(result["events"][2]["event"]["value"], "")

    def test_forged_pages_reject_owner_identity_sequence_and_terminal_changes(self):
        edits = [lambda p: p.update(session_id="a" * 24), lambda p: p.update(context_id="d" * 24),
                 lambda p: p.update(generation=2), lambda p: p.update(language="javascript"),
                 lambda p: p.update(id="f" * 24), lambda p: p.update(next_sequence=1),
                 lambda p: p["events"][0].update(sequence=2),
                 lambda p: p["events"][-1]["event"].update(status="failed"),
                 lambda p: p["events"][-1]["event"].update(context_usable=None),
                 lambda p: p["events"][0]["event"].update(type=[]),
                 lambda p: p.update(events=[], next_sequence=0),
                 lambda p: p.update(events_evicted=True), lambda p: p.update(generation=True)]
        for edit in edits:
            value = page()
            edit(value)
            native, _ = session([Reply(200, value)])
            with self.assertRaises(ProtocolError):
                native.code.connect_execution(CodeContext.from_payload(context(), SESSION_ID), EID).poll()

    def test_context_binding_missing_fields_and_duplicate_list_are_rejected(self):
        for change in ({"session_id": "a" * 24}, {"generation": True}, {"pid": 1}, {"cwd": "/tmp"}):
            with self.assertRaises(ProtocolError):
                CodeContext.from_payload(context(**change), SESSION_ID)
        incomplete = context()
        del incomplete["pid"]
        with self.assertRaises(ProtocolError):
            CodeContext.from_payload(incomplete, SESSION_ID)
        native, _ = session([Reply(200, code_caps()), Reply(200, {"session_id": SESSION_ID, "contexts": [context(), context()]})])
        with self.assertRaises(ProtocolError):
            native.code.list()
        with self.assertRaises(ConfigurationError):
            native.code.connect_execution(CodeContext.from_payload(context(session_id="d" * 24), "d" * 24), EID)

    def test_unsupported_template_and_language_do_not_admit_code(self):
        for report in [dict(capabilities(), session_id=SESSION_ID), dict(code_caps(), artifact_manifest_protocol="osv-sandbox-artifacts/v4"),
                       dict(code_caps(), code_languages=["javascript"])]:
            native, opener = session([Reply(200, report)])
            with self.assertRaises(UnsupportedCapability):
                native.code.default()
            self.assertEqual(len(opener.requests), 1)

    def test_invalid_admission_inputs_never_reach_transport(self):
        native, opener = session([])
        current = CodeContext.from_payload(context(), SESSION_ID)
        for source, options in [("x" * 65537, {}), ("\ud800", {}), ("x\0", {}), ("", {"timeout_ms": True}),
                                ("", {"timeout_ms": -1}), ("", {"environment": {"BAD=KEY": "x"}}),
                                ("", {"environment": {"X": "x" * 8193}}), ("", {"request_timeout": 0})]:
            with self.assertRaises(ConfigurationError):
                native.code.execute(current, source, **options)
        self.assertEqual(opener.requests, [])

    def test_context_and_mutation_acknowledgments_cannot_change_known_binding(self):
        current = CodeContext.from_payload(context(), SESSION_ID)
        cases = [(lambda c: c.create(context_id=CID), context(id="d" * 24)),
                 (lambda c: c.default(), context(language="javascript")),
                 (lambda c: c.get(CID), context(id="d" * 24)),
                 (lambda c: c.restart(current), context(generation=7)),
                 (lambda c: c.remove(current), {"session_id": SESSION_ID, "context_id": "d" * 24, "removed": True}),
                 (lambda c: c.execute(current, "", execution_id=EID), {"session_id": SESSION_ID, "execution_id": "d" * 24, "accepted": True})]
        for call, reply in cases:
            native, _ = session([])
            def exchange(method, path, payload=None, **options):
                return code_caps() if path.endswith("/capabilities") else reply
            with patch.object(native._client, "_exchange", side_effect=exchange):
                with self.assertRaises(ProtocolError):
                    call(native.code)
        native, _ = session([Reply(202, {"session_id": "d" * 24, "execution_id": EID, "accepted": True})])
        with self.assertRaises(ProtocolError):
            native.code.connect_execution(current, EID).cancel()


if __name__ == "__main__":
    unittest.main()
