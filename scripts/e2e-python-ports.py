#!/usr/bin/env python3
"""Real TLS/API/launcher fixture; caller supplies only local test credentials."""
import json
from pathlib import Path
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdk/python"))
from osv_sandbox_client import Client, Session, SessionInfo, TransportError, TimeoutException, APIError


def main():
    config = json.loads(Path(sys.argv[1]).read_text())
    client = Client(config["url"], token="token-a", cert_file=config["cert"], key_file=config["key"],
                    ca_file=config["ca"], request_timeout_seconds=4)
    session = Session(client, SessionInfo.from_payload(config["session"]))
    ports = session.ports
    identity = lambda number: f"{number:024x}"
    data = bytes(range(256)) * 800
    for number in (1, 2):
        handle = ports.open(8080, connection_id=identity(number), timeout_ms=4000)
        errors = []
        if number == 2:
            assert handle.read_frame().kind == "eof"
        def write():
            try:
                for offset in range(0, len(data), 16384): handle.write(data[offset:offset+16384])
                handle.close_write()
            except Exception as exc: errors.append(exc)
        worker = threading.Thread(target=write, daemon=True); worker.start()
        received = bytearray(); eof = number == 2
        while True:
            frame = handle.read_frame()
            if frame.kind == "data": received.extend(frame.data)
            elif frame.kind == "eof": eof = True
            else:
                assert frame.info["status"] == "completed" and frame.info["sent_bytes"] == len(data)
                break
        worker.join(2)
        assert not worker.is_alive() and not errors and eof
        assert received == (data if number == 1 else b"")
        assert handle.info()["status"] == "completed"
        print("PASS binary duplex" if number == 1 else "PASS peer half-close first", flush=True)
    handle = ports.open(8080, connection_id=identity(3), timeout_ms=3000)
    handle.close_write()
    try: handle.read_frame()
    except TransportError: pass
    else: raise AssertionError("missing FINISHED was accepted")
    assert handle.info()["status"] in ("cancelled", "cancelling")
    print("PASS unconfirmed disconnect and known-ID query", flush=True)
    handle = ports.open(8080, connection_id=identity(4), timeout_ms=3000)
    started = time.monotonic()
    assert handle.cancel()["status"] in ("cancelled", "cancelling")
    assert time.monotonic() - started < 1
    handle.close()
    print("PASS independent cancel", flush=True)
    handle = ports.open(8080, connection_id=identity(5), timeout_ms=80)
    started = time.monotonic()
    try: handle.read_frame()
    except TransportError: pass
    else: raise AssertionError("silent connection did not expire")
    assert time.monotonic() - started < 1
    assert handle.cancel()["id"] == identity(5)
    print("PASS absolute timeout and cleanup", flush=True)
    handle = ports.connection(8080, identity(6))
    assert handle.cancel()["status"] == "cancelled"
    try: ports.open(8080, connection_id=identity(6))
    except APIError as exc:
        assert exc.status == 409 and exc.connection.id == identity(6)
    else: raise AssertionError("cancel-before-open replayed")
    print("PASS cancel-before-open blocks late dial", flush=True)
    handle = ports.open(8080, connection_id=identity(10), timeout_ms=3000)
    time.sleep(.1)
    started = time.monotonic()
    assert handle.cancel()["status"] in ("cancelled", "cancelling")
    assert time.monotonic() - started < 1
    handle.close()
    print("PASS reverse backpressure leaves cancellation available", flush=True)
    try: ports.open(8080, connection_id=identity(11), timeout_ms=3000, request_timeout=.08)
    except TimeoutException as exc: assert exc.connection.id == identity(11)
    else: raise AssertionError("pending open did not reach its handshake deadline")
    assert ports.connection(8080, identity(11)).cancel()["status"] in ("cancelled", "cancelling")
    print("PASS pending handshake timeout preserves ID", flush=True)


if __name__ == "__main__": main()
