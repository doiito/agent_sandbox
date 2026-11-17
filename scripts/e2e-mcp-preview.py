#!/usr/bin/env python3
"""Separate MCP processes must retain an API-session-owned preview grant."""
import json
from pathlib import Path
import runpy
import sys

MCP = runpy.run_path(str(Path(__file__).with_name("e2e-mcp.py")))["MCP"]
config = json.loads(Path(sys.argv[1]).read_text())
child = MCP(config["binary"], config["mcp_config"], config["legacy"])
args = dict(session_id=config["session"]["id"], preview_id="b" * 24, port=config["port"])
try:
    if sys.argv[2] == "create":
        grant = child.call("sandbox.preview.create", **args, ttl_ms=20000)
        assert grant["id"] == args["preview_id"] and grant["bootstrap_url"]
        assert "bootstrap_url" not in child.call("sandbox.preview.info", **args)
        failed = child.call("sandbox.preview.create", expected_error=True, **args)
        assert failed["preview_id"] == args["preview_id"]
        Path(config["result"]).write_text(json.dumps(grant))
        print("PASS create once and duplicate rejection", flush=True)
    else:
        info = child.call("sandbox.preview.info", **args)
        assert info["status"] == "active" and "bootstrap_url" not in info
        assert child.call("sandbox.preview.revoke", **args)["status"] == "revoked"
        assert child.call("sandbox.preview.info", **args)["status"] == "revoked"
        print("PASS new-process query and revoke after policy denial", flush=True)
finally:
    child.stop()
