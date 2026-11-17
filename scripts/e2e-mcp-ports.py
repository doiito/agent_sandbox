#!/usr/bin/env python3
"""MCP process -> mTLS API -> real launcher; fixture guest is scripted."""
import base64
import json
from pathlib import Path
import runpy
import sys
import time

MCP = runpy.run_path(str(Path(__file__).with_name("e2e-mcp.py")))["MCP"]
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdk/python"))
from osv_sandbox_client import Client, Session, SessionInfo


def main():
    config = json.loads(Path(sys.argv[1]).read_text())
    api = Client(config["url"], token="token-a", cert_file=config["cert"], key_file=config["key"], ca_file=config["ca"])
    session = Session(api, SessionInfo.from_payload(config["session"]))
    data = bytes(range(256)) * 128
    for legacy in (False, True):
        child = MCP(config["binary"], config["mcp_config"], legacy)
        identity = lambda number: f"{number + (16 if legacy else 0):024x}"
        args = lambda number: dict(session_id=session.id, connection_id=identity(number), port=8080)
        def call(op, number, expected_error=False, **options):
            return child.call("sandbox.ports." + op, expected_error=expected_error, **args(number), **options)
        def wait_terminal(number):
            deadline = time.monotonic() + 3
            while True:
                state = session.ports.connection(8080, identity(number)).info()
                if state["status"] in ("cancelled", "failed", "completed"): return state
                assert time.monotonic() < deadline
                time.sleep(.01)
        def assert_work_slot_full(number):
            probe_id = child.request("tools/call", {"name":"sandbox.ports.write", "arguments":args(number) | {"data_base64":""}})
            reply = child.messages.get(timeout=3)
            assert reply and reply["id"] == probe_id and reply.get("error", {}).get("code") == -33000, reply
        try:
            for number in (1, 2):
                assert call("open", number, timeout_ms=4000)["transport_open"]
                if number == 2: assert call("read", number)["kind"] == "eof"
                received = bytearray()
                for offset in range(0, len(data), 16384):
                    block = data[offset:offset+16384]
                    assert call("write", number, data_base64=base64.b64encode(block).decode())["written_bytes"] == len(block)
                    if number == 1:
                        while len(received) < offset + len(block):
                            packet = call("read", number)
                            assert packet["kind"] == "data"
                            received.extend(base64.b64decode(packet["data_base64"], validate=True))
                assert call("close_write", number)["write_closed"]
                if number == 1: assert call("read", number)["kind"] == "eof"
                finished = call("read", number)
                assert finished["kind"] == "finished" and finished["connection"]["status"] == "completed"
                assert received == (data if number == 1 else b"")
                assert call("info", number)["connection"]["sent_bytes"] == len(data)
                print("PASS MCP binary duplex" if number == 1 else "PASS MCP peer EOF first", flush=True)
            call("open", 3)
            call("close_write", 3)
            lost = call("read", 3, expected_error=True)
            assert lost["outcome_uncertain"] and lost["connection_id"] == identity(3)
            assert wait_terminal(3)["status"] == "cancelled"
            print("PASS MCP unconfirmed disconnect preserves ID", flush=True)
            call("open", 4)
            read_id = child.request("tools/call", {"name":"sandbox.ports.read", "arguments":args(4)})
            assert_work_slot_full(4)
            started = time.monotonic()
            cancel_id = child.request("tools/call", {"name":"sandbox.ports.cancel", "arguments":args(4)})
            replies = {}
            for _ in range(2):
                reply = child.messages.get(timeout=3)
                assert reply and "error" not in reply, reply
                replies[reply["id"]] = reply["result"]
            assert set(replies) == {read_id, cancel_id} and time.monotonic() - started < 1
            assert replies[read_id]["isError"] and not replies[cancel_id]["isError"]
            assert wait_terminal(4)["status"] == "cancelled"
            print("PASS MCP reserved cancel lane with all work slots occupied", flush=True)
            call("open", 5, timeout_ms=80)
            assert call("read", 5, expected_error=True)["outcome_uncertain"]
            assert call("cancel", 5)["connection"]["id"] == identity(5)
            print("PASS MCP absolute deadline and independent cleanup", flush=True)
            assert call("cancel", 6)["connection"]["status"] == "cancelled"
            rejected = call("open", 6, expected_error=True)
            assert rejected["error"]["status"] == 409 and rejected["connection_id"] == identity(6)
            print("PASS MCP cancel-before-open", flush=True)
            call("open", 8)
            read_id = child.request("tools/call", {"name":"sandbox.ports.read", "arguments":args(8)})
            assert_work_slot_full(8)
            child.send({"jsonrpc":"2.0", "method":"notifications/cancelled", "params":{"requestId":read_id}})
            assert wait_terminal(8)["status"] == "cancelled"
            assert call("info", 8)["connection"]["status"] == "cancelled"
            print("PASS MCP cancelled RPC closes uncertain transport without replay", flush=True)
            call("open", 10)
            time.sleep(.1)
            started = time.monotonic()
            assert call("cancel", 10)["connection"]["status"] == "cancelled"
            assert time.monotonic() - started < 1
            print("PASS MCP reverse backpressure independent cancel", flush=True)
            open_id = child.request("tools/call", {"name":"sandbox.ports.open", "arguments":args(11)})
            marker = Path(config["pending_marker"])
            deadline = time.monotonic() + 2
            while not marker.exists() or marker.read_text() != identity(11):
                assert time.monotonic() < deadline, "MCP did not reach the pending guest handshake"
                time.sleep(.005)
            child.send({"jsonrpc":"2.0", "method":"notifications/cancelled", "params":{"requestId":open_id}})
            assert wait_terminal(11)["status"] == "cancelled"
            print("PASS MCP pending open cancellation preserves ID", flush=True)
            call("open", 7)
            child.stop()
            assert wait_terminal(7)["status"] == "cancelled"
            print("PASS MCP process EOF reclaims idle transport", flush=True)
        finally:
            if child.process.poll() is None:
                child.process.kill(); child.process.wait(timeout=5)


if __name__ == "__main__": main()
