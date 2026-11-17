import base64
import copy
import hashlib
import io
import tarfile
import unittest

from osv_sandbox_client import (ArtifactInfo, Session, SessionInfo, ConfigurationError,
                                ProtocolError, TransportError)
from test_client import SESSION_ID, Reply, FakeOpener, make_client, session_info

AID = "c" * 24


def fixture():
    payload = bytes([0, 255, 128, 13, 10]) * 150001
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        member = tarfile.TarInfo("报告.bin")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    data = stream.getvalue()
    info = dict(id=AID, session_id=SESSION_ID, path="/workspace", source_kind="directory", format="tar",
                size=len(data), sha256=hashlib.sha256(data).hexdigest(), entries=1, files=1, payload_bytes=len(payload))
    return info, data, payload


def chunk(info, data, offset=0, length=512 << 10):
    block = data[offset:offset+length]
    return dict(id=AID, session_id=SESSION_ID, offset=offset, total_size=len(data),
                data_base64=base64.b64encode(block).decode("ascii"), data_sha256=hashlib.sha256(block).hexdigest(),
                archive_sha256=info["sha256"], eof=offset+len(block) == len(data))


def session(replies):
    opener = FakeOpener(replies)
    return Session(make_client(opener), SessionInfo.from_payload(session_info())), opener


class ArtifactTests(unittest.TestCase):
    def test_create_download_binary_tar_in_multiple_chunks_and_explicit_delete(self):
        info, data, payload = fixture()
        replies = [Reply(201, info)] + [Reply(200, chunk(info, data, offset)) for offset in range(0, len(data), 512 << 10)] + [Reply(204, None)]
        value, opener = session(replies)
        created = value.create_artifact("/workspace")
        self.assertIsInstance(created, ArtifactInfo)
        downloaded = value.download_artifact(created)
        self.assertEqual(downloaded, data)
        with tarfile.open(fileobj=io.BytesIO(downloaded)) as archive:
            self.assertEqual(archive.extractfile("报告.bin").read(), payload)
        value.delete_artifact(created.id)
        self.assertEqual([request.method for request, _ in opener.requests], ["POST", "POST", "POST", "DELETE"])
        self.assertTrue(opener.requests[1][0].full_url.endswith(AID + "/read"))

    def test_download_rejects_changed_archive_and_checks_complete_digest(self):
        info, data, _ = fixture()
        for complete in (False, True):
            metadata = copy.deepcopy(info)
            if complete:
                metadata["sha256"] = "d" * 64
            blocks = [chunk(metadata, data, offset) for offset in range(0, len(data), 512 << 10)]
            if not complete:
                blocks[0]["archive_sha256"] = "e" * 64
            value, _ = session([Reply(200, row) for row in blocks])
            with self.subTest(complete=complete), self.assertRaises(ProtocolError):
                value.download_artifact(ArtifactInfo.from_payload(metadata, SESSION_ID))

    def test_read_rejects_forged_binding_offsets_sizes_eof_and_bytes(self):
        info, data, _ = fixture()
        good = chunk(info, data, length=512)
        changes = [{"id": "d" * 24}, {"session_id": "e" * 24}, {"offset": 1}, {"offset": True},
                   {"total_size": len(data)+1}, {"total_size": 33 << 20}, {"eof": True},
                   {"data_sha256": "0" * 64}, {"data_base64": "AA/="}, {"data_base64": ""}]
        for patch in changes:
            value, _ = session([Reply(200, dict(good, **patch))])
            with self.subTest(patch=patch), self.assertRaises(ProtocolError):
                value.read_artifact(AID, 0, 512)

    def test_empty_eof_and_maximum_block_are_valid(self):
        info, data, _ = fixture()
        value, _ = session([Reply(200, chunk(info, data)), Reply(200, chunk(info, data, len(data), 1))])
        self.assertEqual(len(base64.b64decode(value.read_artifact(AID, 0)["data_base64"])), 512 << 10)
        self.assertTrue(value.read_artifact(AID, len(data), 1)["eof"])

    def test_metadata_path_counts_and_resource_limits_are_checked(self):
        info, _, _ = fixture()
        for patch in ({"session_id": "d" * 24}, {"path": "/etc/passwd"}, {"size": 33 << 20}, {"files": 2},
                      {"source_kind": "symlink"}, {"format": "zip"}, {"entries": True}, {"sha256": "BAD"}):
            with self.subTest(patch=patch), self.assertRaises(ProtocolError):
                ArtifactInfo.from_payload(dict(info, **patch), SESSION_ID)
        value, _ = session([Reply(201, dict(info, path="/workspace/other"))])
        with self.assertRaises(ProtocolError):
            value.create_artifact("/workspace")

    def test_invalid_arguments_are_local_and_create_is_never_retried(self):
        value, opener = session([])
        for path in ("/etc/passwd", "/workspace/../etc", "/workspace/\ud800"):
            with self.assertRaises(ConfigurationError):
                value.create_artifact(path)
        for offset, length in ((-1, 1), (True, 1), (0, 0), (0, 524289), (33554433, 1)):
            with self.assertRaises(ConfigurationError):
                value.read_artifact(AID, offset, length)
        self.assertEqual(len(opener.requests), 0)
        value._client._exchange = lambda *args, **kwargs: (_ for _ in ()).throw(TransportError("lost response"))
        with self.assertRaises(TransportError):
            value.create_artifact("/workspace")


if __name__ == "__main__":
    unittest.main()
