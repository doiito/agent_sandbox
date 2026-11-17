import copy
import unittest
from osv_sandbox_client import (Session, SessionInfo, Sandbox, SandboxError,
                                ConfigurationError, ProtocolError, UnsupportedCapability,
                                FilesystemEventType)
from test_client import SESSION_ID, Reply, FakeOpener, make_client, session_info

WATCH_ID = "c" * 24


def watch_info():
    return dict(id=WATCH_ID, session_id=SESSION_ID, path="/workspace", recursive=False,
                include_entry=False, state="watching")


def page(events=(), after=0):
    return dict(info=watch_info(), events=list(events), next_sequence=after + len(events), complete=False)


def session(replies):
    opener = FakeOpener(replies)
    return Session(make_client(opener), SessionInfo.from_payload(session_info())), opener


class WatchTests(unittest.TestCase):
    def test_native_watch_binds_request_pages_and_idempotent_stop(self):
        event = dict(sequence=1, name="new", type="create")
        value, opener = session([Reply(201, watch_info()), Reply(200, page([event])),
                                 Reply(200, {"session_id": SESSION_ID, "watches": [watch_info()]}),
                                 Reply(200, {"stopped": True}), Reply(200, {"stopped": False})])
        handle = value.start_file_watch("/workspace")
        self.assertEqual(handle.poll()["events"], [event])
        self.assertEqual(value.list_file_watches()[0]["id"], handle.id)
        self.assertTrue(handle.stop())
        self.assertFalse(handle.stop())
        self.assertTrue(opener.requests[1][0].full_url.endswith(WATCH_ID + "?after=0"))

    def test_e2b_poll_returns_incremental_events_and_stopped_handle_fails(self):
        event = dict(sequence=1, name="new", type="create")
        value, opener = session([Reply(201, watch_info()), Reply(200, page([event])),
                                 Reply(200, page(after=1)), Reply(200, {"stopped": True})])
        handle = Sandbox(value).files.watch_dir("/workspace")
        events = handle.get_new_events()
        self.assertEqual((events[0].name, events[0].type), ("new", FilesystemEventType.CREATE))
        self.assertEqual(handle.get_new_events(), [])
        self.assertTrue(opener.requests[2][0].full_url.endswith("?after=1"))
        handle.stop()
        with self.assertRaises(SandboxError): handle.get_new_events()

    def test_explicit_overflow_keeps_valid_events_then_reports_failure(self):
        ended = page([dict(sequence=1, name="new", type="write")])
        ended["complete"] = True
        ended["info"].update(state="failed", error_code="overflow")
        value, _ = session([Reply(201, watch_info()), Reply(200, ended)])
        handle = Sandbox(value).files.watch_dir("/workspace")
        self.assertEqual(len(handle.get_new_events()), 1)
        with self.assertRaisesRegex(SandboxError, "overflow"): handle.get_new_events()

    def test_bad_binding_sequence_path_metadata_and_page_are_rejected(self):
        original = page([dict(sequence=1, name="new", type="create")])
        for bad in ("session", "id", "directory", "sequence", "traversal", "nested", "entry", "complete"):
            with self.subTest(bad=bad):
                invalid = copy.deepcopy(original)
                if bad == "session": invalid["info"]["session_id"] = "d" * 24
                elif bad == "id": invalid["info"]["id"] = "d" * 24
                elif bad == "directory": invalid["info"]["path"] = "/workspace/other"
                elif bad == "sequence": invalid["events"][0]["sequence"] = 2
                elif bad == "traversal": invalid["events"][0]["name"] = "../other"
                elif bad == "nested": invalid["events"][0]["name"] = "nested/other"
                elif bad == "entry": invalid["events"][0]["entry"] = {}
                else: invalid["complete"] = True
                value, _ = session([Reply(201, watch_info()), Reply(200, invalid)])
                with self.assertRaises(ProtocolError): value.start_file_watch("/workspace").poll()

    def test_unsupported_and_invalid_options_do_not_create_watch(self):
        value, opener = session([])
        for options in ({"user": "root"}, {"request_timeout": 1}, {"allow_network_mounts": True}):
            with self.assertRaises(UnsupportedCapability): Sandbox(value).files.watch_dir("/workspace", **options)
        for options in ({"timeout_ms": -1}, {"timeout_ms": True}, {"recursive": 1}, {"include_entry": 1}):
            with self.assertRaises(ConfigurationError): value.start_file_watch("/workspace", **options)
        with self.assertRaises(ConfigurationError): value.start_file_watch("/tmp")
        self.assertEqual(opener.requests, [])
