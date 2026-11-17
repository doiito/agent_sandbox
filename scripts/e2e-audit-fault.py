#!/usr/bin/env python3
"""ENOSPC acceptance on an isolated, tiny tmpfs audit fixture only.

This deliberately fills the fixture audit mount, tests the running task's
completion and subsequent admission, then removes its own filler. It never
fills a host filesystem or accepts a general production directory.
"""
import argparse
import errno
import json
import os
from pathlib import Path
import re
import ssl
import threading
import time
import urllib.error
import urllib.request


def require(value, message):
    if not value:
        raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.fixture_root.resolve()
    require(os.geteuid() == 0, "root fixture operator required")
    require(root.parent == Path("/var/lib") and re.fullmatch(r"osv-validation-[a-z0-9-]+", root.name), "not an isolated validation fixture")
    info = root.stat()
    require(info.st_uid == 0 and info.st_mode & 0o022 == 0, "untrusted fixture directory")
    config = json.loads((root / "config.production.json").read_text())
    require(config.get("production") is True and config["limits"]["max_concurrent"] == 1, "single-slot production fixture required")
    require(config["run_root"] == str(root / "run") and config["audit_log_path"] == str(root / "audit/audit.jsonl"), "fixture paths escaped")
    require(config["jailer"]["parent_cgroup"] == root.name, "cgroup is not isolated")
    mount = root / "audit"
    entries = [line.split() for line in Path("/proc/self/mountinfo").read_text().splitlines()]
    require(any(fields[4] == str(mount) and fields[fields.index("-")+1] == "tmpfs" for fields in entries), "audit must be an exact tmpfs mount")
    fs = os.statvfs(mount)
    require(0 < fs.f_blocks * fs.f_frsize <= 1024 * 1024, "refusing to fill a large filesystem")
    context = ssl.create_default_context(cafile=root / "tls/ca.crt")
    context.load_cert_chain(root / "tls/client.crt", root / "tls/client.key")
    token = (root / "secrets/token").read_text()
    url = "https://" + config["listen"]
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))

    def request(path, body=None):
        req = urllib.request.Request(url+path, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": "Bearer "+token, "Content-Type": "application/json"})
        try:
            with opener.open(req, timeout=15) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, json.load(error)

    cases = []
    outcome = {}
    filler = mount / "validation-filler"
    thread = None
    try:
        def hold():
            try:
                outcome["response"] = request("/v1/jobs", {"entrypoint":"/bin/sh", "args":["-c","sleep 3"], "timeout_ms":10000})
            except Exception as error:
                outcome["error"] = type(error).__name__
        thread = threading.Thread(target=hold)
        thread.start()
        deadline = time.monotonic()+4
        active = False
        while time.monotonic() < deadline:
            for leasepath in (root / "run").glob("job-*/lease.json"):
                try:
                    lease = json.loads(leasepath.read_text())
                    active = (Path("/proc") / str(lease["pid"]) / "comm").read_text().strip() == "firecracker"
                except (OSError, ValueError, KeyError):
                    continue
            if active:
                break
            time.sleep(0.01)
        require(active, "no live VMM admitted before fault")
        # Fill the audit file's last allocated block first; otherwise a small
        # completion record could fit in its existing slack despite ENOSPC.
        audit_path = root / "audit/audit.jsonl"
        gap = (-audit_path.stat().st_size) % fs.f_frsize
        padding = b'{"event":"fixture.padding","padding":""}\n'
        if gap:
            if gap < len(padding):
                gap += fs.f_frsize
            padding = b'{"event":"fixture.padding","padding":"'+b' '*(gap-len(padding))+b'"}\n'
            with audit_path.open("ab", buffering=0) as file:
                file.write(padding)
                os.fsync(file.fileno())
        require(audit_path.stat().st_size % fs.f_frsize == 0, "audit tail not aligned for deterministic fault")
        full = False
        with filler.open("xb", buffering=0) as file:
            for _ in range(512):
                try:
                    file.write(bytes(4096))
                except OSError as error:
                    require(error.errno == errno.ENOSPC, "fault did not produce ENOSPC")
                    full = True
                    break
        require(full, "bounded filler did not exhaust fixture tmpfs")
        thread.join(timeout=12)
        require(not thread.is_alive() and "response" in outcome, "active task did not return after audit fault")
        status, body = outcome["response"]
        require(status == 503 and "audit" in body.get("error", ""), "non-durable completion was acknowledged")
        cases.append({"name":"completion-enospc", "passed":True})
        filler.unlink()
        status, body = request("/v1/jobs", {"entrypoint":"/bin/sh", "args":["-c","printf must-not-run"]})
        require(status == 503 and "audit" in body.get("error", ""), "admission recovered without restart after record loss")
        cases.append({"name":"admission-latches-after-space-restored", "passed":True})
        status, doctor = request("/v1/doctor")
        require(status == 503 and any(c["name"] == "audit" and c["ok"] is False for c in doctor["checks"]), "audit readiness remained healthy")
        cases.append({"name":"audit-readiness-fails", "passed":True})
        require(not list((root/"run").glob("job-*")), "fault left job directory")
        require(not list((Path("/sys/fs/cgroup")/root.name).glob("job-*")), "fault left job cgroup")
        cases.append({"name":"fault-job-cleanup", "passed":True})
    except Exception as error:
        cases.append({"name":"audit-fault", "passed":False, "error":str(error) if isinstance(error, AssertionError) else type(error).__name__})
    finally:
        filler.unlink(missing_ok=True)
        if thread is not None:
            thread.join(timeout=15)
    report = {"suite":"audit-enospc-e2e/v1", "cases":cases, "passed":all(c["passed"] for c in cases), "production_validated":False}
    args.output.write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps(report))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
