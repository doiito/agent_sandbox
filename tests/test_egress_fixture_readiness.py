"""Real Unix peers expose stale sockets and missing restart readiness."""
import http.server
import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import socketserver
import tempfile
import threading
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'scripts/egress_fixture_readiness.py'
OUTER_ERROR = json.loads((SOURCE.parent.parent / 'tests/fixtures/egress-outer-policy-rejection.json').read_text())
spec = importlib.util.spec_from_file_location('readiness', SOURCE)
readiness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(readiness)
TASK = 'a' * 24


def serve(directory, ready, stop, price, control, accepted, release, refusal):
    if release is not None:
        release.wait(5)
    directory = Path(directory)

    class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True

        def get_request(self):
            request = super().get_request()
            accepted.set()
            return request

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            assert self.path == '/v1/inference/state'
            self.reply({'protocol': 'osv-sandbox-inference-state/v1', 'billing': True,
                        'policy_sha256': 'b' * 64,
                        'policy': {'endpoints': [{'name': 'model', 'price': {'request_units': price}}]}})

        def do_POST(self):
            if self.path == '/v1/guest-proxy':
                assert self.headers.get('Upgrade') == 'osv-guest-proxy/1'
                assert self.headers.get('Content-Length') == '0'
                assert self.headers.get('X-OSV-Inference-Policy') == 'a' * 64
                self.reply(OUTER_ERROR, refusal)
                return
            assert self.path == '/v1/inference/root/inspect'
            body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            assert body['binding']['task_id'] == TASK and 'invocation' not in body
            self.reply({'protocol': 'osv-sandbox-inference-root/v1', 'bill': {'task_id': TASK}})

        def reply(self, body, status=200):
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    servers = []
    for name in ['e.sock'] + (['inference.sock'] if control else []):
        path = directory / name
        path.unlink(missing_ok=True)
        server = Server(str(path), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
    ready.set()
    stop.wait(10)
    for server in servers:
        server.shutdown()
        server.server_close()


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='osv-egress-readiness-')
        self.root = Path(self.temp.name)
        self.children = []

    def tearDown(self):
        for process, stop in self.children:
            stop.set()
        for process, _ in self.children:
            process.join(3)
            if process.is_alive():
                process.kill()
                process.join(3)
            self.assertEqual(process.exitcode, 0)
        self.temp.cleanup()

    def service(self, price='1', control=True, release=None, refusal=503):
        ready, stop, accepted = [multiprocessing.Event() for _ in range(3)]
        process = multiprocessing.Process(target=serve, args=(self.root, ready, stop, price, control, accepted, release, refusal))
        process.start()
        self.children.append((process, stop))
        if release is None:
            self.assertTrue(ready.wait(3))
        return process, ready, accepted

    def wait(self, pid, price='1', generation=None, timeout=0.15):
        return readiness.wait_for_generation(self.root, 'test-only', 'tenant', TASK, price, os.geteuid(),
                                             generation or (lambda: {'pid': pid, 'invocation_id': 'c' * 32}), timeout)

    def test_current_peer_both_channels_and_policy_are_required(self):
        process, _, _ = self.service()
        result = self.wait(process.pid, timeout=2)
        self.assertEqual(result['pid'], process.pid)
        self.assertEqual(result['task_id'], TASK)
        self.assertTrue(result['read_only'])

    def test_existing_socket_from_old_pid_cannot_satisfy_readiness(self):
        process, _, _ = self.service()
        with self.assertRaises(TimeoutError):
            self.wait(os.getpid())
        self.assertTrue(process.is_alive())

    def test_current_pid_with_old_policy_is_rejected(self):
        process, _, _ = self.service(price='9007199254740993')
        with self.assertRaises(TimeoutError):
            self.wait(process.pid)

    def test_missing_control_endpoint_is_rejected(self):
        process, _, _ = self.service(control=False)
        with self.assertRaises(TimeoutError):
            self.wait(process.pid)

    def test_generation_change_during_probes_is_rejected(self):
        process, _, _ = self.service()
        calls = []

        # Keep changing the generation after each pair of replies.
        def changing():
            calls.append(None)
            return {'pid': process.pid, 'invocation_id': ('c' if len(calls) % 2 else 'd') * 32}

        with self.assertRaises(TimeoutError):
            self.wait(process.pid, generation=changing)

    def test_delayed_new_process_replaces_stale_sockets(self):
        old, _, accepted = self.service()
        release = multiprocessing.Event()
        new, ready, _ = self.service(release=release)
        result, errors = [], []

        def observe():
            try:
                result.append(self.wait(new.pid, timeout=3))
            except BaseException as error:
                errors.append(error)

        observer = threading.Thread(target=observe)
        observer.start()
        self.assertTrue(accepted.wait(2))
        self.assertFalse(result)
        release.set()
        self.assertTrue(ready.wait(3))
        observer.join(4)
        self.assertFalse(observer.is_alive())
        self.assertFalse(errors)
        self.assertEqual(result[0]['pid'], new.pid)
        self.assertNotEqual(old.pid, new.pid)

    def test_outer_refusal_is_verified_before_any_inner_request(self):
        process, _, _ = self.service()
        current = self.wait(process.pid, timeout=2)
        binding = {'tenant': 'tenant', 'task_id': TASK, 'vm_id': 'd' * 24, 'lease_id': 'e' * 24}
        result = readiness.verify_root_policy_rejection(self.root, binding, 'a' * 64, current, os.geteuid())
        self.assertEqual(result['status'], 503)
        self.assertFalse(result['inner_request_sent'])

    def test_success_cannot_be_mistaken_for_policy_refusal(self):
        process, _, _ = self.service(refusal=200)
        current = self.wait(process.pid, timeout=2)
        binding = {'tenant': 'tenant', 'task_id': TASK, 'vm_id': 'd' * 24, 'lease_id': 'e' * 24}
        with self.assertRaises(readiness.NotReady):
            readiness.verify_root_policy_rejection(self.root, binding, 'a' * 64, current, os.geteuid())


if __name__ == '__main__':
    unittest.main()
