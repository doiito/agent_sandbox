#!/usr/bin/env python3
"""Real API/launcher/KVM acceptance; never substitutes a helper backend.

Token is read only from OSV_SANDBOX_TOKEN. The report excludes raw responses,
secrets and URL/host identity. Host process/cgroup inspection is a separate gate.
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--backend", choices=["firecracker-linux", "firecracker", "qemu"], required=True)
    parser.add_argument("--ca")
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--output", required=True)
    parser.add_argument("--diagnostic-allow-unready", action="store_true")
    parser.add_argument("--expect-guest-proxy", action="store_true")
    args = parser.parse_args()
    token = os.environ.get("OSV_SANDBOX_TOKEN", "")
    require(bool(token), "OSV_SANDBOX_TOKEN is required")
    parsed = urllib.parse.urlsplit(args.url)
    require(parsed.scheme in ("https", "http") and parsed.hostname and not parsed.username and not parsed.password, "invalid API URL")
    require(args.diagnostic_allow_unready or parsed.scheme == "https", "production acceptance requires HTTPS")
    tls = None
    if parsed.scheme == "https":
        require(all((args.ca, args.cert, args.key)), "HTTPS tests require CA, client cert and key")
        tls = ssl.create_default_context(cafile=args.ca)
        tls.minimum_version = ssl.TLSVersion.TLSv1_3
        tls.load_cert_chain(args.cert, args.key)
    # Ignore proxy environment variables for a controlled local test endpoint.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=tls))
    results = []
    production_ready = False
    endpoint_verified = False
    selected_digest = ""
    selected_guest_protocol = "fc-agent/v1"

    def request(path, body=None, bearer=token, raw=None):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        headers = {"Authorization": "Bearer " + bearer, "Content-Type": "application/json"}
        req = urllib.request.Request(args.url.rstrip("/") + path, data=data, headers=headers)
        try:
            with opener.open(req, timeout=20) as response:
                return response.status, json.loads(response.read(20 << 20))
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read(1 << 20))

    def case(name, action):
        started = time.monotonic()
        try:
            action()
            results.append({"name": name, "passed": True, "duration_ms": round((time.monotonic()-started)*1000)})
        except Exception as error:
            # Assertion text is authored here, never include server responses.
            message = str(error) if isinstance(error, AssertionError) else type(error).__name__
            results.append({"name": name, "passed": False, "error": message})
        print(f"{'PASS' if results[-1]['passed'] else 'FAIL'} {name}", flush=True)

    def doctor():
        nonlocal production_ready
        status, report = request("/v1/doctor")
        require(status in (200, 503) and isinstance(report.get("checks"), list), "doctor response invalid")
        production_ready = status == 200 and report.get("ready") is True
        required_checks = {"artifacts", "hypervisor", "kvm", "jailer"}
        passed = {c["name"] for c in report["checks"] if c.get("ok") is True}
        require(required_checks <= passed, "KVM/artifacts/jailer checks failed")
        if not args.diagnostic_allow_unready:
            require(production_ready, "production doctor is not ready")
            require({"mtls", "tenant-auth", "production-policy"} <= passed, "production security checks missing")

    def job(script, state="succeeded", extra=None, timeout_ms=5000):
        payload = {"entrypoint": "/bin/sh", "args": ["-c", script], "timeout_ms": timeout_ms}
        payload.update(extra or {})
        status, result = request("/v1/jobs", payload)
        require(status == 200, "job HTTP status mismatch")
        require(result.get("backend") == args.backend and result.get("state") == state, "job backend/state mismatch")
        if state != "timed_out":
            require(result.get("protocol_ok") is True, "guest result missing")
            guest = result.get("guest_result", {})
            require(guest.get("protocol") == selected_guest_protocol and guest.get("job_id") == result.get("id"), "guest protocol/job ID mismatch")
            return guest
        require(result.get("timed_out") is True, "timeout not reported")
        return result

    def health():
        nonlocal endpoint_verified
        status, body = request("/healthz")
        require(status == 200 and body.get("status") == "ok", "authenticated transport health failed")
        endpoint_verified = True
    case("authenticated-transport", health)
    case("doctor", doctor)
    def capabilities():
        nonlocal selected_digest, selected_guest_protocol
        status, report = request("/v1/capabilities")
        require(status == 200 and report.get("protocol") == "osv-sandbox-capabilities/v1", "capability protocol invalid")
        require(report.get("backend") == args.backend, "capability backend mismatch")
        features = report.get("features", {})
        require(features.get("network_egress") is args.expect_guest_proxy and features.get("snapshots") is False,
                "guest proxy capability differs from explicit fixture expectation")
        if args.backend == "firecracker-linux":
            require(report.get("stage") == "production" and report.get("workload") == "linux-process",
                    "Linux production capability profile invalid")
            require(report.get("artifact_authenticated") is True and
                    len(report.get("artifact_manifest_sha256", "")) == 64,
                    "signed Linux template identity missing")
            require(features.get("input_files") is True and
                    report.get("allowed_entrypoints") == ["/bin/sh", "/bin/bash"],
                    "Linux input or tenant entrypoint capability invalid")
            require("POST /v2/jobs" in report.get("methods", []), "signed template v2 method missing")
            selected_guest_protocol = "fc-agent/v3" if features.get("warm_pool") is True else "fc-agent/v1"
            require(report.get("guest_result_protocol") == selected_guest_protocol, "guest protocol capability mismatch")
            selected_digest = report["artifact_manifest_sha256"]
    case("capability-contract", capabilities)
    if tls:
        def reject_tls_client(context):
            require(endpoint_verified, "positive TLS baseline missing")
            isolated = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
            try:
                with isolated.open(args.url.rstrip("/")+"/healthz", timeout=5) as response:
                    response.read()
            except (urllib.error.URLError, ssl.SSLError) as error:
                reason = error.reason if isinstance(error, urllib.error.URLError) else error
                require(isinstance(reason, ssl.SSLError) and not isinstance(reason, ssl.SSLCertVerificationError), "failure did not prove server rejected TLS policy")
                return
            raise AssertionError("forbidden TLS client connected")
        without_cert = ssl.create_default_context(cafile=args.ca)
        without_cert.minimum_version = ssl.TLSVersion.TLSv1_3
        case("mtls-client-required", lambda: reject_tls_client(without_cert))
        tls12 = ssl.create_default_context(cafile=args.ca)
        tls12.maximum_version = ssl.TLSVersion.TLSv1_2
        tls12.load_cert_chain(args.cert, args.key)
        case("tls12-rejected", lambda: reject_tls_client(tls12))
    case("invalid-bearer", lambda: require(request("/v1/doctor", bearer="invalid-e2e-token")[0] == 401, "bad token was accepted"))
    case("capability-auth-rejection", lambda: require(request("/v1/capabilities", bearer="invalid-e2e-token")[0] == 401, "bad token queried capabilities"))
    if args.backend == "firecracker-linux":
        def v2_selection(payload, expected_status, expected_code):
            status, response = request("/v2/jobs", payload)
            require(status == expected_status and response.get("code") == expected_code,
                    "v2 template selection error contract mismatch")
        selected = {"entrypoint": "/bin/sh", "args": ["-c", "printf v2-selected"],
                    "backend": "firecracker-linux", "artifact_manifest_sha256": selected_digest}
        case("v2-requires-template-selection", lambda: v2_selection({"entrypoint": "/bin/sh"}, 400, "invalid_request"))
        case("v2-rejects-backend-switch", lambda: v2_selection(dict(selected, backend="firecracker-osv"), 409, "template_mismatch"))
        case("v2-rejects-stale-template", lambda: v2_selection(dict(selected, artifact_manifest_sha256="0" * 64), 409, "template_mismatch"))
        def v2_selected_job():
            status, response = request("/v2/jobs", selected)
            guest = response.get("guest_result") or {}
            require(status == 200 and response.get("state") == "succeeded" and
                    response.get("backend") == "firecracker-linux" and
                    guest.get("stdout") == "v2-selected" and
                    guest.get("job_id") == response.get("id"), "selected v2 job did not execute")
        case("v2-executes-selected-template", v2_selected_job)
    case("strict-json", lambda: require(request("/v1/jobs", raw=b'{"entrypoint":"/bin/sh","unknown":true}')[0] == 400, "unknown JSON field accepted"))
    case("trailing-json", lambda: require(request("/v1/jobs", raw=b'{} {}')[0] == 400, "trailing JSON accepted"))
    if args.backend == "firecracker-linux":
        def streams():
            guest = job("printf e2e-stdout; printf e2e-stderr >&2")
            require(guest.get("stdout") == "e2e-stdout" and guest.get("stderr") == "e2e-stderr", "stdout/stderr mismatch")
        case("stdout-stderr", streams)
        def exit_code():
            require(job("exit 7", "guest_error").get("exit_code") == 7, "guest exit code lost")
        case("guest-exit-code", exit_code)
        def background_cleanup():
            guest = job("sleep 20 & printf main-completed")
            require(guest.get("stdout") == "main-completed", "background pipe lost main output")
            require(guest.get("duration_ms", 10000) < 1500, "background pipe delayed task completion")
        case("background-pipe-cleanup", background_cleanup)
        def escaped_session_cleanup():
            guest = job("/bin/busybox setsid /bin/sh -c 'echo ready > /workspace/escaped-ready; sleep 20' & while test ! -e /workspace/escaped-ready; do sleep 0.01; done; printf main-completed")
            require(guest.get("stdout") == "main-completed", "setsid descendant retained output pipe")
            require(guest.get("duration_ms", 10000) < 1500, "setsid descendant delayed completion")
        case("escaped-session-cleanup", escaped_session_cleanup)
        case("identity-and-hardening", lambda: job('test "$(id -u)" = 10000 && grep -q "NoNewPrivs:.*1" /proc/self/status && ! touch /forbidden-e2e && echo hardened'))
        case("no-nic", lambda: require(job("ls /sys/class/net").get("stdout", "").split() in ([], ["lo"]), "unexpected network interface"))
        def input_readonly():
            files = [{"path": "nested/input.txt", "data": base64.b64encode(b"e2e-input").decode(), "mode": 292}]
            guest = job("cat /input/nested/input.txt; test ! -w /input/nested/input.txt", extra={"input_files": files})
            require(guest.get("stdout") == "e2e-input", "input bytes changed")
        case("readonly-input", input_readonly)
        case("workspace-first", lambda: job("echo private > /workspace/previous-task"))
        case("workspace-fresh", lambda: job("test ! -e /workspace/previous-task"))
        def output_limit():
            guest = job("head -c 400000 /dev/zero")
            require(guest.get("output_truncated") is True, "output flood was not truncated")
            require(len(guest.get("stdout", "")) + len(guest.get("stderr", "")) <= 180000, "guest output exceeded production budget")
        case("output-flood", output_limit)
        case("timeout", lambda: job("sleep 10", "timed_out", timeout_ms=1000))
        case("network-policy-deny", lambda: require(request("/v1/jobs", {"entrypoint": "/bin/sh", "network": "all"})[0] == 400 and
             (args.expect_guest_proxy or request("/v1/jobs", {"entrypoint": "/bin/sh", "network": "proxy"})[0] == 400), "unsupported network enabled"))
        case("input-traversal-deny", lambda: require(request("/v1/jobs", {"entrypoint": "/bin/sh", "input_files": [{"path": "../escape", "data": ""}]})[0] == 400, "input traversal accepted"))
        case("tenant-entrypoint-deny", lambda: require(request("/v1/jobs", {"entrypoint": "/bin/id"})[0] == 403, "tenant entrypoint policy bypassed"))
        def disconnect():
            cls = http.client.HTTPSConnection if tls else http.client.HTTPConnection
            options = {"context": tls} if tls else {}
            conn = cls(parsed.hostname, parsed.port, timeout=10, **options)
            conn.request("POST", parsed.path.rstrip("/") + "/v1/jobs", json.dumps({"entrypoint":"/bin/sh", "args":["-c","sleep 20"], "timeout_ms":20000}), {"Authorization":"Bearer "+token,"Content-Type":"application/json"})
            time.sleep(1.5)
            conn.close()
            # Host-side inspection must additionally prove the running VMM was killed.
            time.sleep(0.3)
            job("printf after-cancel")
        case("client-disconnect-followup", disconnect)
    else:
        def osv_job():
            status, result = request("/v1/jobs", {"entrypoint":"/agent", "args":["isolation-probe"]})
            require(status == 200 and result.get("state") == "succeeded" and result.get("protocol_ok") is True, "OSv isolation job failed")
            require(result.get("backend") == args.backend, "OSv backend mismatch")
            guest = result.get("guest_result", {})
            require(guest.get("job_id") == result.get("id") and guest.get("protocol") == "osv-agent/v1", "OSv job binding invalid")
            data = guest.get("data", {})
            require(all(data.get(field) is True for field in ("root_write_blocked","metadata_connect_blocked","loopback_connect_blocked")), "OSv isolation probe did not prove all boundaries")
        case("osv-isolation", osv_job)
    report = {"suite":"sandbox-api-e2e/v1", "generated_at":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()), "backend":args.backend, "diagnostic":args.diagnostic_allow_unready, "production_ready":production_ready, "production_validated":False, "test_script_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "cases":results, "passed":all(c["passed"] for c in results), "host_inspection_required":True}
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2)+"\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
