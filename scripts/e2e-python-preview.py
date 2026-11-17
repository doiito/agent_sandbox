#!/usr/bin/env python3
"""Preview SDK lifecycle against the real local mTLS/API/launcher fixture."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdk/python"))
from osv_sandbox_client import APIError, Client, Session, SessionInfo

config = json.loads(Path(sys.argv[1]).read_text())
client = Client(config["url"], token="token-a", cert_file=config["cert"], key_file=config["key"], ca_file=config["ca"])
session = Session(client, SessionInfo.from_payload(config["session"]))
port, identity = config["port"], "b" * 24
if sys.argv[2] == "create":
    grant = session.ports.create_preview(port, preview_id=identity, ttl_ms=20000)
    assert grant.bootstrap_url and grant.id == identity
    assert "bootstrap_url" not in grant.info()
    try:
        session.ports.create_preview(port, preview_id=identity)
    except APIError as error:
        assert error.status == 409 and error.preview.id == identity
    else:
        raise AssertionError("preview ID reused")
    Path(config["result"]).write_text(json.dumps(grant.created))
    print("PASS create once and duplicate rejection", flush=True)
else:
    # New process, no local create result; policy now denies new previews.
    grant = session.ports.preview(port, identity)
    info = grant.info()
    assert info["status"] == "active" and "bootstrap_url" not in info and grant.bootstrap_url is None
    assert grant.revoke()["status"] == "revoked"
    assert grant.info()["status"] == "revoked"
    print("PASS new-process query and revoke after policy denial", flush=True)
