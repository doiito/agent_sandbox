#!/usr/bin/env python3
"""Installed Python SDK -> authenticated API -> actual code vsock in a KVM VM."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import sys
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--package', type=Path, required=True)
    p.add_argument('--expected-mode', choices=['cold', 'warm'], required=True)
    p.add_argument('--in-netns', action='store_true')
    args = p.parse_args()
    root = args.root.resolve()
    if not args.in_netns:
        pid = subprocess.check_output(['systemctl', 'show', '-p', 'MainPID', '--value', root.name + '-api.service'], text=True).strip()
        assert int(pid) > 1
        raise SystemExit(subprocess.run(['nsenter', '-t', pid, '-n', sys.executable, __file__, '--root', str(root),
            '--package', str(args.package), '--expected-mode', args.expected_mode, '--in-netns']).returncode)
    release = next((root / 'releases').iterdir())
    sys.path.insert(0, str(release / 'sdk/python'))
    import osv_sandbox_client as sdk
    config = json.loads((root / 'config.production.json').read_text())
    options = dict(ca_file=str(root / 'tls/ca.crt'), cert_file=str(root / 'tls/client.crt'),
                   key_file=str(root / 'tls/client.key'), request_timeout_seconds=60)
    url = 'https://localhost:' + config['listen'].rsplit(':', 1)[1]
    a = sdk.Client(url, token=(root / 'secrets/token').read_text(), **options)
    b = sdk.Client(url, token=(root / 'secrets/token-b').read_text(), **options)
    cases, boxes = [], []

    def check(name, condition):
        assert condition, name
        cases.append(name)
        print('PASS python-code-' + name, flush=True)

    def wait(action, seconds=45):
        end = time.monotonic() + seconds
        while True:
            value = action()
            if value:
                return value
            assert time.monotonic() < end, 'code state observation timed out'
            time.sleep(.025)

    def create():
        if args.expected_mode == 'warm':
            wait(lambda: any(row['name'] == 'code' and row['ready'] >= 1 for row in a.doctor()['warm_pool']['profiles']))
        box = sdk.Sandbox.create('firecracker-linux', timeout=180, client=a)
        boxes.append(box)
        check('startup-' + str(len(boxes)), box._session.created.startup_mode == args.expected_mode)
        return box

    def ready(controller, context):
        return wait(lambda: (value if (value := controller.get(context.id)).state == 'idle' else None))

    def journal(handle):
        events, cursor = [], 0
        end = time.monotonic() + 20
        while True:
            page = handle.poll(cursor)
            events.extend(row['event'] for row in page['events'])
            cursor = page['next_sequence']
            if page['status'] != 'running' and cursor == page['last_sequence']:
                return page, events
            assert time.monotonic() < end, 'execution did not finish'
            time.sleep(.02)

    report = {'suite': 'python-code-real-kvm/v1', 'passed': False, 'mode': args.expected_mode,
              'cases': cases, 'actual_code_vsock': True, 'performance_gate_evidence': False,
              'candidate_sha256': hashlib.file_digest(args.package.open('rb'), 'sha256').hexdigest()}
    try:
        cap = a.capabilities()
        signed_protocol = json.loads((Path(config['artifact_root']) / 'manifest.json').read_text())['protocol']
        check('signed-profile', cap['artifact_manifest_protocol'] == signed_protocol and
              signed_protocol in ('osv-sandbox-artifacts/v5', 'osv-sandbox-artifacts/v6', 'osv-sandbox-artifacts/v7', 'osv-sandbox-artifacts/v8') and
              cap['features']['code_contexts'] and cap['code_languages'] == ['python', 'javascript', 'typescript'])
        box = create()
        sid = box.sandbox_id
        report['sandbox_id'] = sid
        control = box._session.code
        default = ready(control, control.default())
        check('real-prewarmed-python', default.pid is not None and default.generation == 1)
        check('owner-capabilities', box._session.capabilities()['session_id'] == sid)
        foreign = sdk.Session(b, box._session.created)
        try:
            sdk.Sandbox(foreign).list_code_contexts()
        except sdk.APIError as error:
            check('foreign-session-hidden', error.status == 404)
        else:
            raise AssertionError('foreign owner queried code')
        out, err = [], []
        result = box.run_code("import sys\nvalue=41\nprint('中文')\nprint('stderr',file=sys.stderr)\nvalue+1",
                              on_stdout=out.append, on_stderr=err.append)
        check('persistent-streaming-results', result.text == '42' and '中文' in ''.join(result.logs.stdout)
              and 'stderr' in ''.join(result.logs.stderr) and out and err and result.error is None)
        check('persistent-default', box.run_code('value+2').text == '43')
        rich = box.run_code("class Rich:\n def _repr_mimebundle_(self): return {'application/json': {'zero':0,'flag':False,'big':9007199254740993}, 'text/html':'<b>rich</b>'}\nRich()")
        check('mime-zero-false-precision', rich.results[-1].json == {'zero': 0, 'flag': False, 'big': 9007199254740993}
              and rich.results[-1].html == '<b>rich</b>')
        bad = box.run_code("raise ValueError('expected-user-error')")
        check('user-error-as-data', bad.error.name == 'ValueError' and 'expected-user-error' in bad.error.value)
        check('usable-after-user-error', box.run_code('value+3').text == '44')
        science = box.run_code('import numpy as np, pandas as pd\nint(pd.Series(np.array([20,22])).sum())')
        check('offline-numpy-pandas', science.text == '42')
        context = box.create_code_context(language='python')
        check('create-context-ready', control.get(context.id).state == 'idle')
        check('context-isolation', box.run_code("'value' in globals()", context=context).text == 'False')
        box.run_code('isolated=71', context=context)
        box.restart_code_context(context)
        check('restart-next-generation', control.get(context.id).generation == 2 and
              box.run_code("'isolated' in globals()", context=context).text == 'False')
        check('list-contexts', context.id in {item.id for item in box.list_code_contexts()})
        box.remove_code_context(context)
        try:
            box.run_code('1', context=context)
        except sdk.APIError as error:
            check('removed-context-observed', error.status == 404 and error.code == 'code_not_found')
        else:
            raise AssertionError('removed context executed')
        for action in [box.restart_code_context, box.remove_code_context]:
            try:
                action(context)
            except sdk.APIError as error:
                check('removed-context-' + action.__name__, error.status == 404 and error.code == 'code_not_found')
            else:
                raise AssertionError('removed context mutation accepted')
        try:
            box.create_code_context(cwd='/etc')
        except sdk.ConfigurationError:
            cases.append('invalid-create-cwd')
        else:
            raise AssertionError('invalid code cwd accepted')
        check('javascript-runtime', box.run_code('globalThis.jsValue=40; jsValue+3', language='javascript').text == '43')
        check('typescript-runtime', box.run_code('const answer: number = 44; answer', language='typescript').text == '44')
        try:
            box.run_code('1', language='ruby')
        except sdk.UnsupportedCapability:
            cases.append('unsupported-language-explicit')
        else:
            raise AssertionError('unsupported language accepted')
        native = ready(control, control.create())
        with ThreadPoolExecutor(max_workers=1) as executor:
            running = executor.submit(box._session.run, sdk.SessionCommand('/bin/sh', ('-c', 'sleep 2; echo shell-ok'), timeout_ms=5000))
            time.sleep(.1)
            page, events = journal(control.execute(native, '6*7'))
            check('code-and-owner-info-during-shell', page['status'] == 'completed' and box._session.info().id == sid and not running.done())
            check('shell-still-completes', running.result().succeeded)
        eid = secrets.token_hex(12)
        placeholder = control.connect_execution(native, eid)
        placeholder.cancel()
        page, events = journal(placeholder)
        check('cancel-before-submit-terminal', page['failure'] == 'cancelled_before_submit' and len(events) == 1)
        try:
            control.execute(native, "open('/workspace/should-not-exist','w').write('bad')", execution_id=eid)
        except sdk.APIError as error:
            check('cancelled-id-never-replayed', error.status == 409 and not box.files.exists('/workspace/should-not-exist'))
        else:
            raise AssertionError('cancel placeholder replayed')
        handle = control.execute(native, "import time\nwhile True: time.sleep(.01)", timeout_ms=0)
        check('explicit-cancel-running', handle.poll()['status'] == 'running')
        handle.cancel()
        page, events = journal(handle)
        check('explicit-cancel-confirmed', page['status'] == 'cancelled' and events[-1]['type'] == 'finished')
        control.remove(control.get(native.id))
        # Blocking facade must request and confirm VM-side cancellation before returning.
        try:
            box.run_code('while True: pass', timeout=.3)
        except sdk.TimeoutException:
            cases.append('e2b-timeout-confirmed')
        else:
            raise AssertionError('E2B timeout did not terminate observation')
        check('owner-survives-confirmed-timeout', box.is_running())
        box.kill()
        fresh = create()
        check('fresh-vm-does-not-reuse-state', fresh.run_code("'value' in globals()").text == 'False' and
              len(fresh.list_code_contexts()) == 1)
        fresh.kill()
        check('active-capacity-returned', a.doctor()['vm_capacity']['active'] == 0)
        report['passed'] = True
        directory = root / 'results/e2b-2.51.0'
        directory.mkdir(exist_ok=True)
        for operation in ['code.run_code', 'code.create_context', 'code.list_contexts', 'code.restart_context', 'code.remove_context']:
            evidence = {'suite': 'e2b-compat-case/v1', 'operation': operation, 'language': 'python',
                'upstream_commit': 'ccaf9fc0ffe6ac39c7ec786af7608ab1de19467b', 'candidate_sha256': report['candidate_sha256'],
                'environment': 'real-kvm', 'adapter': 'sdk/python.Sandbox', 'official_sdk_unmodified': False,
                'sandbox_id': sid, 'cases': [{'name': 'success', 'passed': True, 'detail': 'actual interpreter/context lifecycle, journals and installed code vsock'},
                    {'name': 'failure', 'passed': True, 'detail': 'user error, removed context, tenant ownership, cancelled ID and confirmed timeout'}], 'passed': True}
            (directory / ('python-' + operation + '.json')).write_text(json.dumps(evidence, indent=2) + '\n')
    finally:
        for box in boxes:
            try:
                box.kill()
            except sdk.APIError as error:
                if error.status != 404:
                    raise
        (root / 'results' / ('python-code-' + args.expected_mode + '.json')).write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
