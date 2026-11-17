#!/usr/bin/env python3
"""Real API/launcher/KVM acceptance for the standard-library Python SDK."""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

import osv_sandbox_client as sdk_module
from osv_sandbox_client import (APIError, Client, ConfigurationError, InputFile, JobRequest,
                                Sandbox, Session, SessionCommand, SessionRequest, TemplateMismatch,
                                CommandExitException, TimeoutException, TransportError,
                                TemplateSelector, UnsupportedCapability)

E2B_COMMIT = 'ccaf9fc0ffe6ac39c7ec786af7608ab1de19467b'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def job_dirs(root):
    return sorted(path.name for path in root.glob('job-*'))


def exercise_background_commands(client, tenant_b):
    session = client.create_session(SessionRequest(ttl_ms=90000))
    cases = []
    def check(name, value):
        require(value, name)
        cases.append(name)
    try:
        capabilities = client.capabilities()
        check('capability', capabilities['features'].get('background_commands') is True and
              capabilities['features'].get('streaming_output') is True)
        session.write_file('/workspace/persistent', b'preserved')
        command = session.start_command(SessionCommand('/bin/sh', ('-c',
            "sleep 30 & echo $! > /workspace/background-pid; printf once >> /workspace/exec-count; "
            "printf '\\000\\377first'; printf error >&2; sleep 30"), timeout_ms=20000))
        stream = command.events()
        first = next(stream)
        check('live-output-before-exit', first.result is None and command.poll()['info']['state'] == 'running')
        stream.close()
        check('observer-disconnect-preserves-command', session.connect_command(command.id).poll()['info']['state'] == 'running')
        check('list-and-connect', any(row['id'] == command.id for row in session.list_commands()))
        try:
            session.start_command(SessionCommand('/bin/sh', ('-c', 'printf forbidden-parallel')))
        except APIError as busy:
            check('one-running-command-limit', busy.status == 429)
        else:
            raise RuntimeError('parallel background command bypassed execution reservation')
        check('cancel-accepted', command.kill())
        check('repeat-cancel-false', not command.kill())
        check('cancel-confirmed', command.wait().state == 'cancelled')
        replay = list(command.events())
        stdout = b''.join(event.data for event in replay if event.stream == 'stdout')
        stderr = b''.join(event.data for event in replay if event.stream == 'stderr')
        check('binary-output-and-stderr', stdout == b'\x00\xfffirst' and stderr == b'error')
        resumed = list(command.events(after=first.sequence))
        check('cursor-resume', all(event.sequence > first.sequence for event in resumed if event.result is None) and
              resumed[-1].result.state == 'cancelled')
        follow = session.run(SessionCommand('/bin/sh', ('-c',
            'if kill -0 $(cat /workspace/background-pid) 2>/dev/null; then exit 9; fi; printf continued')))
        check('descendants-reaped-and-session-reused', follow.succeeded and follow.guest_result['stdout'] == 'continued')
        check('workspace-retained', session.read_file('/workspace/persistent') == b'preserved')
        failure = session.start_command(SessionCommand('/bin/sh', ('-c', 'printf out; printf err >&2; exit 7')))
        final = failure.wait()
        check('nonzero-terminal', final.state == 'guest_error' and final.exit_code == 7 and
              final.guest_result['stdout'] == 'out' and final.guest_result['stderr'] == 'err')
        timed = session.start_command(SessionCommand('/bin/sh', ('-c', 'sleep 30'), timeout_ms=200)).wait()
        check('guest-timeout', timed.state == 'timed_out' and timed.timed_out)
        flood = session.start_command(SessionCommand('/bin/sh', ('-c', '/bin/busybox yes x | /bin/busybox head -c 200000')))
        flooded = list(flood.events())
        check('bounded-flood', flooded[-1].result.succeeded and flooded[-1].result.output_truncated and
              len(flooded) <= 257 and sum(len(event.data) for event in flooded) <= capabilities['limits']['command_output_bytes'])
        path = '/v2/sessions/' + session.id + '/commands'
        for method, suffix in (('GET', ''), ('GET', '/' + command.id), ('GET', '/' + command.id + '/events'), ('DELETE', '/' + command.id)):
            try:
                tenant_b._exchange(method, path + suffix)
            except APIError as denied:
                check('cross-tenant-' + method + suffix, denied.status == 404)
            else:
                raise RuntimeError('other tenant accessed background command')
        for _ in range(33):
            require(session.start_command(SessionCommand('/bin/sh', ('-c', ':'))).wait().succeeded,
                    'command history sequence failed')
        check('bounded-command-history', len(session.list_commands()) == 32)
        try:
            session.connect_command(command.id)
        except APIError as evicted:
            check('old-handle-evicted', evicted.status == 404 and evicted.code == 'command_not_found')
        else:
            raise RuntimeError('old command was not evicted')
        check('observation-does-not-reexecute', session.read_file('/workspace/exec-count') == b'once')
        session.start_command(SessionCommand('/bin/sh', ('-c', 'sleep 30')))
    finally:
        session.close()
    return {'passed': True, 'cases': cases, 'case_count': len(cases), 'active-command-closed-with-session': True}


def exercise_e2b_commands(facade, native, tenant_b):
    cases = []
    def check(name, value):
        require(value, name)
        cases.append(name)
    def failed(handle, code):
        try:
            handle.wait()
        except CommandExitException as error:
            check('exit-exception-' + str(code), error.exit_code == code)
            return error
        raise RuntimeError('nonzero command did not raise')
    check('command-directory', facade.files.make_dir('/workspace/command-work'))
    out, err = [], []
    value = facade.commands.run(
        'a=(one two); read -r p < <(printf process); [[ $p == process ]] || exit 8; printf "%s|%s|%s" "${a[1]^^}" "$SDK_KEY" "$PWD"; '
        'printf once >> /workspace/command-count; printf warning >&2',
        envs={'SDK_KEY': '环境'}, cwd='/workspace/command-work',
        on_stdout=out.append, on_stderr=err.append)
    check('bash-env-cwd-callbacks', value.exit_code == 0 and
          value.stdout == 'TWO|环境|/workspace/command-work' and value.stderr == 'warning' and
          ''.join(out) == value.stdout and ''.join(err) == value.stderr)
    value = facade.commands.run('printf "%s|%s" "${SDK_KEY-unset}" "$PWD"')
    check('env-cwd-do-not-leak', value.stdout == 'unset|/workspace')
    handle = facade.commands.run('printf out; printf err >&2; exit 7', background=True)
    error = failed(handle, 7)
    check('nonzero-fields', error.stdout == 'out' and error.stderr == 'err' and hasattr(error, 'error'))
    failed(handle, 7)
    handle = facade.commands.run('printf cached', background=True)
    callbacks = []
    first = handle.wait(on_stdout=callbacks.append)
    check('cached-wait', handle.wait(on_stdout=callbacks.append) is first and
          ''.join(callbacks) == 'cached' and native.read_file('/workspace/command-count') == b'once')
    live = facade.commands.run('printf "%s" "$$"; sleep 30', background=True,
                              envs={'SDK_KEY': 'live'}, cwd='/workspace/command-work', timeout=0)
    for _ in range(200):
        page = live._native.poll()
        if page['events']:
            break
        time.sleep(0.01)
    else:
        raise RuntimeError('background Bash did not emit PID')
    rows = facade.commands.list()
    check('list-real-running-pid', len(rows) == 1 and rows[0].pid == live.pid and
          rows[0].cmd == '/bin/bash' and rows[0].args[:2] == ['-l', '-c'] and
          rows[0].envs == {'SDK_KEY': 'live'} and rows[0].cwd == '/workspace/command-work')
    live.disconnect()
    check('disconnect-preserves-process', [row.pid for row in facade.commands.list()] == [live.pid])
    attached = facade.commands.connect(live.pid, timeout=0)
    check('kill-live-pid', facade.commands.kill(live.pid))
    killed = failed(attached, 137)
    check('started-pid-matches-bash', killed.stdout == str(live.pid))
    check('repeat-kill-false', not facade.commands.kill(live.pid))
    check('completed-not-listed', facade.commands.list() == [])
    try:
        facade.commands.connect(1000000000)
    except APIError as error:
        check('unknown-connect-404', error.status == 404)
    else:
        raise RuntimeError('unknown guest PID connected')
    timed = facade.commands.run('printf before; sleep 30', background=True, timeout=1)
    try:
        timed.wait()
    except TimeoutException:
        check('observation-timeout-preserves-process', [row.pid for row in facade.commands.list()] == [timed.pid])
    else:
        raise RuntimeError('observation timeout missing')
    resumed = facade.commands.connect(timed.pid, timeout=0)
    check('kill-after-observation-timeout', resumed.kill())
    check('reconnect-replays-output', failed(resumed, 137).stdout == 'before')
    denied = Sandbox(Session(tenant_b, native.created))
    for name, action in [('list', denied.commands.list),
                         ('connect', lambda: denied.commands.connect(timed.pid)),
                         ('kill', lambda: denied.commands.kill(timed.pid))]:
        try:
            action()
        except APIError as error:
            check('cross-tenant-' + name, error.status == 404)
        else:
            raise RuntimeError('other tenant accessed E2B command')
    inaccessible = native.run(SessionCommand('/bin/bash', ('-c', 'printf forbidden'), cwd='/proc/1/fd'))
    check('cwd-after-permission-drop', not inaccessible.succeeded)
    check('session-reused', facade.commands.run('printf continued').stdout == 'continued')
    return {'passed': True, 'cases': cases, 'case_count': len(cases)}


def exercise_interactive_stdin(facade, native, tenant_b):
    cases=[]
    def check(name,value):
        require(value,name);cases.append(name)
    def rejected(action,status,code=None):
        try:action()
        except APIError as error:
            check('rejected-'+str(status)+(('-'+code) if code else ''),error.status==status and (code is None or error.code==code))
        else:raise RuntimeError('invalid stdin operation succeeded')
    def wait_output(command,text):
        for _ in range(300):
            page=command.poll()
            if text in b''.join(base64.b64decode(row['data_base64']) for row in page['events'] if row['stream']=='stdout'):return
            time.sleep(0.01)
        raise RuntimeError('stdin process did not reach readiness marker')
    handle=facade.commands.run('cat > /workspace/stdin-bytes; cat /workspace/stdin-bytes; printf eof >&2',background=True,stdin=True,timeout=0)
    facade.commands.send_stdin(handle.pid,'首行\n')
    handle.disconnect()
    attached=facade.commands.connect(handle.pid,timeout=0)
    attached.send_stdin(b'\x00\xfftail')
    facade.commands.close_stdin(handle.pid)
    final=attached.wait()
    expected='首行\n'.encode()+b'\x00\xfftail'
    check('binary-and-text-through-pid-and-handle',native.read_file('/workspace/stdin-bytes')==expected)
    check('eof-and-output-after-reconnect',final.exit_code==0 and final.stdout==expected.decode('utf-8',errors='replace') and final.stderr=='eof')
    rejected(lambda:facade.commands.send_stdin(1000000000,'missing'),404)
    rejected(lambda:facade.commands.close_stdin(1000000000),404)
    held=facade.commands.run('cat > /workspace/empty-stdin; printf eof; sleep 30',background=True,stdin=True,timeout=0)
    held.close_stdin();wait_output(held._native,b'eof')
    check('empty-eof-delivered',held._native.poll()['info']['stdin_closed'] is True)
    check('repeat-close-live-input',held.close_stdin() is None)
    rejected(lambda:facade.commands.send_stdin(held.pid,'after-eof'),409,'stdin_closed')
    held.kill()
    try:held.wait()
    except CommandExitException as error:check('eof-process-cancelled',error.exit_code==137)
    check('empty-stdin-was-empty',native.read_file('/workspace/empty-stdin')==b'')
    disabled=facade.commands.run('sleep 30',background=True,timeout=0)
    rejected(lambda:disabled.send_stdin('disabled'),409,'stdin_unavailable')
    rejected(lambda:disabled.close_stdin(),409,'stdin_unavailable')
    disabled.kill()
    try:disabled.wait()
    except CommandExitException as error:check('disabled-process-cancelled',error.exit_code==137)
    broken=facade.commands.run('exec 0<&-; printf closed; sleep 30',background=True,stdin=True,timeout=0)
    wait_output(broken._native,b'closed')
    rejected(lambda:broken.send_stdin('unused'),409,'stdin_closed')
    broken.kill()
    try:broken.wait()
    except CommandExitException as error:check('early-close-cancelled',error.exit_code==137)
    blocked=native.start_command(SessionCommand('/bin/bash',('-c','printf ready; sleep 30'),timeout_ms=20000,interactive_stdin=True))
    wait_output(blocked,b'ready')
    stalled=None
    for sequence in range(1,17):
        try:blocked.send_stdin(b'x'*16384,request_timeout=0.3)
        except TimeoutException:stalled=sequence;break
    check('bounded-backpressure-observation-timeout',stalled is not None)
    check('pending-input-queryable',blocked.poll_stdin(stalled)['state']=='pending')
    rejected(lambda:blocked.submit_stdin(b'extra'),429,'busy')
    denied=Sandbox(Session(tenant_b,native.created))
    rejected(lambda:denied.commands.send_stdin(42,'foreign'),404)
    rejected(lambda:denied.commands.close_stdin(42),404)
    for method,suffix,payload in [('POST','',{'data_base64':'eA==','close':False}),('GET','/'+str(stalled),None)]:
        rejected(lambda method=method,suffix=suffix,payload=payload:tenant_b._exchange(method,blocked._path+'/stdin'+suffix,payload),404)
    started=time.monotonic();check('backpressure-cancel-accepted',blocked.kill())
    check('backpressure-cancel-confirmed',blocked.wait().state=='cancelled' and time.monotonic()-started<3)
    pending=blocked.poll_stdin(stalled)
    check('unfinished-input-not-delivered',pending['state']=='failed' and pending['error_code']=='command_exited')
    quota=native.start_command(SessionCommand('/bin/bash',('-c','/bin/busybox wc -c > /workspace/stdin-count'),timeout_ms=20000,interactive_stdin=True))
    for _ in range(64):quota.send_stdin(b'q'*16384)
    rejected(lambda:quota.submit_stdin(b'extra'),413,'stdin_limit')
    rejected(lambda:client_raw_oversize(native._client,quota._path),413,'stdin_limit')
    quota.close_stdin()
    check('full-input-byte-budget-and-eof',quota.wait().succeeded and native.read_file('/workspace/stdin-count').strip()==b'1048576')
    check('session-reused-after-input',facade.commands.run('printf reused').stdout=='reused')
    return {'passed':True,'cases':cases,'case_count':len(cases)}


def client_raw_oversize(client,path):
    return client._exchange('POST',path+'/stdin',{'data_base64':base64.b64encode(b'x'*16385).decode(),'close':False},accepted=(202,))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--in-netns', action='store_true')
    parser.add_argument('--expect-doctor-ready', action='store_true')
    args = parser.parse_args()
    root = args.root.resolve()
    require(root.is_dir() and root.name.startswith('osv-offline-validation-20261030-'),
            'requires isolated validation fixture')
    if not args.in_netns:
        unit = root.name + '-api.service'
        pid = int(subprocess.run(['systemctl', 'show', '-p', 'MainPID', '--value', unit],
                                 check=True, capture_output=True, text=True).stdout.strip())
        require(pid > 1, 'API fixture unit is inactive')
        subprocess.run(['nsenter', '-t', str(pid), '-n', sys.executable, __file__,
                        '--root', str(root), '--package', str(args.package), '--in-netns',
                        *(['--expect-doctor-ready'] if args.expect_doctor_ready else [])],
                       check=True)
        return
    require(not job_dirs(root / 'run'), 'fixture has an existing task')
    releases = [path for path in (root / 'releases').iterdir() if path.is_dir()]
    require(len(releases) == 1, 'fixture must contain exactly one installed release')
    installed_sdk = releases[0] / 'sdk/python/osv_sandbox_client.py'
    require(installed_sdk.is_file() and
            Path(sdk_module.__file__).resolve() == installed_sdk.resolve(),
            'SDK was not imported from the installed release')
    config = json.loads((root / 'config.production.json').read_text())
    require(config['run_root'] == str(root / 'run'), 'fixture run root mismatch')
    port = config['listen'].rsplit(':', 1)[1]
    token = (root / 'secrets/token').read_text()
    client = Client('https://localhost:' + port, token=token,
                    ca_file=str(root / 'tls/ca.crt'),
                    cert_file=str(root / 'tls/client.crt'),
                    key_file=str(root / 'tls/client.key'),
                    request_timeout_seconds=65)
    report = client.capabilities()
    require(report['backend'] == 'firecracker-linux' and
            report['artifact_authenticated'] is True and
            'POST /v2/jobs' in report['methods'] and
            '/bin/sh' in report['allowed_entrypoints'],
            'signed v2 capability missing')
    doctor = client.doctor()
    require(doctor['ready'] is args.expect_doctor_ready,
            'fixture doctor readiness differs from the explicit expectation')

    job = JobRequest('/bin/sh', args=('-c', 'cat /input/prompt.txt'),
                     timeout_ms=30000,
                     input_files=(InputFile('prompt.txt', b'sdk-e2e'),))
    result = client.run(job)
    require(result.succeeded and result.guest_result is not None and
            result.guest_result.get('stdout') == 'sdk-e2e' and
            result.guest_result.get('job_id') == result.id,
            'SDK v2 job did not return bound guest result')
    require(not job_dirs(root / 'run'), 'successful SDK job left a workdir')

    wrong_digest = '0' * 64 if report['artifact_manifest_sha256'] != '0' * 64 else '1' * 64
    try:
        client.run(JobRequest('/bin/sh', args=('-c', 'printf should-not-run')),
                   template=TemplateSelector(report['backend'], wrong_digest))
    except TemplateMismatch as mismatch:
        require(mismatch.status == 409 and mismatch.code == 'template_mismatch',
                'stale template returned wrong status or code')
    else:
        raise RuntimeError('stale template was accepted')
    require(not job_dirs(root / 'run'), 'template mismatch created a task workdir')

    denied = Client('https://localhost:' + port, token='invalid-test-token',
                    ca_file=str(root / 'tls/ca.crt'),
                    cert_file=str(root / 'tls/client.crt'),
                    key_file=str(root / 'tls/client.key'))
    try:
        denied.capabilities()
    except APIError as unauthorized:
        require(unauthorized.status == 401, 'bad token returned wrong status')
    else:
        raise RuntimeError('bad token was accepted')
    require(not job_dirs(root / 'run'), 'authentication failure created a task workdir')

    require(report.get('features', {}).get('sessions') is True and
            'POST /v2/sessions' in report['methods'], 'session capability missing')
    session = client.create_session(SessionRequest(ttl_ms=30000))
    session_id = session.id
    try:
        first = session.run(SessionCommand('/bin/sh', ('-c',
            'printf python-session > /workspace/sdk-marker')))
        require(first.succeeded, 'first session command failed')
        require(client.connect_session(session_id).info().id == session_id,
                'session reconnect returned wrong ID')
        second = client.connect_session(session_id).run(SessionCommand('/bin/sh',
            ('-c', 'cat /workspace/sdk-marker')))
        require(second.succeeded and second.guest_result.get('stdout') == 'python-session',
                'session workspace did not persist')
        require(report.get('features', {}).get('session_files') is True and
                'POST /v2/sessions/{id}/files' in report['methods'],
                'session file capability missing')
        binary = bytes(range(256)) * 2048
        require(session.write_file('/workspace/sdk-bytes', binary) == len(binary),
                'SDK file write returned wrong size')
        require(client.connect_session(session_id).read_file('/workspace/sdk-bytes') == binary,
                'SDK file read changed binary bytes')
        counted = session.run(SessionCommand('/bin/sh', ('-c',
            '/bin/busybox wc -c /workspace/sdk-bytes')))
        require(counted.succeeded and str(len(binary)) in counted.guest_result.get('stdout', ''),
                'command did not observe SDK file write')
        require({'sdk-bytes', 'sdk-marker'}.issubset(set(session.list_files())),
                'SDK directory list omitted session files')
        require(session.stat_file('/workspace/sdk-bytes') ==
                {'kind': 'file', 'size': len(binary)}, 'SDK file stat mismatched')
        require(session.stat_file('/workspace') == {'kind': 'directory', 'size': 0},
                'SDK root directory stat mismatched')
        require(session.write_file('/workspace/delete-me', b'gone') == 4,
                'cannot stage delete target')
        session.delete_file('/workspace/delete-me')
        try:
            session.read_file('/workspace/delete-me')
        except APIError as removed:
            require(removed.status == 404, 'deleted file remained readable')
        else:
            raise RuntimeError('deleted file remained readable')
        try:
            session.write_file('/workspace/too-large', binary + b'x')
        except ConfigurationError:
            pass
        else:
            raise RuntimeError('SDK accepted oversized file')
        try:
            client._exchange('POST', '/v2/sessions/' + session_id + '/files',
                             {'action': 'write', 'path': '/workspace/too-large',
                              'data_base64': base64.b64encode(binary + b'x').decode('ascii')})
        except APIError as oversized:
            require(oversized.status == 413 and oversized.code == 'file_too_large',
                    'API accepted oversized file')
        else:
            raise RuntimeError('API accepted oversized file')
        try:
            session.read_file('/workspace/missing')
        except APIError as missing:
            require(missing.status == 404 and missing.code == 'file_not_found',
                    'missing file returned wrong error')
        else:
            raise RuntimeError('missing file was readable')
        linked = session.run(SessionCommand('/bin/sh', ('-c',
            '/bin/busybox ln -s /etc/passwd /workspace/sdk-link')))
        require(linked.succeeded, 'cannot prepare symlink escape probe')
        for action in ('read', 'write'):
            try:
                if action == 'read':
                    session.read_file('/workspace/sdk-link')
                else:
                    session.write_file('/workspace/sdk-link', b'blocked')
            except APIError as denied_file:
                require(denied_file.status == 403 and denied_file.code == 'file_denied',
                        'symlink file operation was not denied')
            else:
                raise RuntimeError('symlink file operation succeeded')
        for action in ('stat', 'delete'):
            try:
                if action == 'stat':
                    session.stat_file('/workspace/sdk-link')
                else:
                    session.delete_file('/workspace/sdk-link')
            except APIError as denied_file:
                require(denied_file.status == 403 and denied_file.code == 'file_denied',
                        'symlink metadata operation was not denied')
            else:
                raise RuntimeError('symlink metadata operation succeeded')
        try:
            session.read_file('/workspace/../etc/passwd')
        except ConfigurationError:
            pass
        else:
            raise RuntimeError('SDK accepted traversal path')
        try:
            client._exchange('POST', '/v2/sessions/' + session_id + '/files',
                             {'action': 'read', 'path': '/workspace/../etc/passwd'})
        except APIError as invalid_file:
            require(invalid_file.status == 400 and invalid_file.code == 'invalid_path',
                    'API accepted traversal path')
        else:
            raise RuntimeError('API accepted traversal path')
        tenant_b = Client('https://localhost:' + port,
                          token=(root / 'secrets/token-b').read_text(),
                          ca_file=str(root / 'tls/ca.crt'),
                          cert_file=str(root / 'tls/client.crt'),
                          key_file=str(root / 'tls/client.key'))
        try:
            tenant_b.connect_session(session_id)
        except APIError as denied_session:
            require(denied_session.status == 404, 'cross-tenant session status is not 404')
        else:
            raise RuntimeError('other tenant connected to session')
        try:
            tenant_b._exchange('POST', '/v2/sessions/' + session_id + '/files',
                               {'action': 'read', 'path': '/workspace/sdk-bytes'})
        except APIError as denied_file:
            require(denied_file.status == 404, 'other tenant accessed session file')
        else:
            raise RuntimeError('other tenant accessed session file')
    finally:
        session.close()
    try:
        client.connect_session(session_id)
    except APIError as closed:
        require(closed.status == 404, 'closed session status is not 404')
    else:
        raise RuntimeError('closed session remains connectable')
    require(not job_dirs(root / 'run'), 'SDK session left a workdir')
    cgroup_root = Path('/sys/fs/cgroup') / root.name
    require(not job_dirs(cgroup_root), 'SDK test left a task cgroup')

    background = exercise_background_commands(client, tenant_b)
    require(not job_dirs(root / "run") and not job_dirs(cgroup_root), "background command left VM resources")

    facade = Sandbox.create('firecracker-linux', client=client, timeout=90)
    facade_id = facade.sandbox_id
    ended = False
    try:
        require(facade.is_running(), 'E2B facade did not observe a live session')
        require(Sandbox.connect(facade_id, client=client).sandbox_id == facade_id,
                'E2B facade running reconnect changed identity')
        native = client.connect_session(facade_id)
        require(native.write_file('/workspace/e2b-text', b'hello-e2b') == 9,
                'E2B facade state setup failed')
        require(facade.files.read('/workspace/e2b-text') == 'hello-e2b',
                'E2B text read failed')
        require(facade.files.read('/workspace/e2b-text', format='bytes') == bytearray(b'hello-e2b'),
                'E2B byte read failed')
        require(facade.files.exists('/workspace/e2b-text'), 'E2B exists lost a real file')
        require(not facade.files.exists('/workspace/missing'), 'E2B exists invented a file')
        linked = native.run(SessionCommand('/bin/sh', ('-c',
            '/bin/busybox ln -s /etc/passwd /workspace/e2b-link')))
        require(linked.succeeded, 'cannot stage E2B link denial')
        tagged = facade.files.write('/workspace/e2b-meta', 'tagged',
                                    metadata={'label': 'proof'})
        require(tagged.metadata == {'label': 'proof'} and
                native.read_file('/workspace/e2b-meta') == b'tagged',
                'E2B metadata write did not persist content and result')
        try:
            facade.files.write('/workspace/e2b-meta', 'bad', metadata={'bad key': 'x'})
        except ConfigurationError:
            require(native.read_file('/workspace/e2b-meta') == b'tagged',
                    'invalid metadata write changed existing file')
        else:
            raise RuntimeError('E2B write accepted invalid metadata key')
        listed_info = facade.files.list('/workspace')
        text_info = next((item for item in listed_info if item.name == 'e2b-text'), None)
        link_info = next((item for item in listed_info if item.name == 'e2b-link'), None)
        meta_info = next((item for item in listed_info if item.name == 'e2b-meta'), None)
        require(text_info is not None and text_info.path == '/workspace/e2b-text' and
                text_info.type == 'file' and text_info.size == 9 and
                len(text_info.permissions) == 9 and text_info.owner and text_info.group and
                isinstance(text_info.modified_time, datetime) and
                text_info.modified_time.tzinfo == timezone.utc and
                link_info is not None and link_info.type == 'symlink' and
                link_info.symlink_target == '/etc/passwd' and
                meta_info is not None and meta_info.metadata == {'label': 'proof'},
                'E2B list lost file, symlink or xattr information')
        direct_info = facade.files.get_info('/workspace/e2b-text')
        require(direct_info == text_info and
                facade.files.get_info('/workspace/e2b-link') == link_info and
                facade.files.get_info('/workspace/e2b-meta') == meta_info and
                facade.files.get_info('/workspace').type == 'dir',
                'E2B get_info differs from list or lost directory type')
        try:
            facade.files.list('/workspace/e2b-link')
        except APIError as denied_list:
            require(denied_list.status == 403 and denied_list.code == 'file_denied',
                    'E2B list hid symlink denial')
        else:
            raise RuntimeError('E2B list followed symlink')
        try:
            facade.files.get_info('/workspace/missing')
        except APIError as missing_info:
            require(missing_info.status == 404 and missing_info.code == 'file_not_found',
                    'E2B get_info hid missing path')
        else:
            raise RuntimeError('E2B get_info invented missing path')
        require(facade.files.make_dir('/workspace/e2b-deep/a'), 'E2B mkdir did not create nested path')
        require(not facade.files.make_dir('/workspace/e2b-deep/a'),
                'E2B mkdir reported existing directory newly created')
        single = facade.files.write('/workspace/e2b-deep/new/single', 'hello')
        require(single.name == 'single' and single.path == '/workspace/e2b-deep/new/single' and
                single.type == 'file' and native.read_file(single.path) == b'hello',
                'E2B write did not create parent or return bound WriteInfo')
        batch = facade.files.write_files([
            {'path': '/workspace/e2b-deep/batch/one', 'data': '1'},
            {'path': '/workspace/e2b-deep/batch/two', 'data': b'2'}])
        require([item.name for item in batch] == ['one', 'two'] and
                native.read_file(batch[0].path) == b'1' and
                native.read_file(batch[1].path) == b'2',
                'E2B batch write lost file or result order')
        try:
            facade.files.make_dir('/workspace/e2b-link/sub')
        except APIError as denied_mkdir:
            require(denied_mkdir.status == 403 and denied_mkdir.code == 'file_denied',
                    'E2B mkdir hid symlink denial')
        else:
            raise RuntimeError('E2B mkdir followed symlink')
        try:
            facade.files.write('/workspace/e2b-link/escape', 'bad')
        except APIError as denied_write:
            require(denied_write.status == 403 and denied_write.code == 'file_denied',
                    'E2B write hid symlink denial')
        else:
            raise RuntimeError('E2B write followed symlink')
        try:
            facade.files.write_files([
                {'path': '/workspace/e2b-deep/partial', 'data': 'safe'},
                {'path': '/workspace/e2b-link/escape', 'data': 'bad'}])
        except APIError as denied_batch:
            require(denied_batch.status == 403 and denied_batch.code == 'file_denied' and
                    native.read_file('/workspace/e2b-deep/partial') == b'safe',
                    'E2B batch partial success or denial semantics changed')
        else:
            raise RuntimeError('E2B batch crossed symlink')
        try:
            facade.files.exists('/workspace/e2b-link')
        except APIError as denied_exists:
            require(denied_exists.status == 403 and denied_exists.code == 'file_denied',
                    'E2B exists hid permission failure')
        else:
            raise RuntimeError('E2B exists followed a symlink')
        try:
            facade.files.read('/workspace/missing')
        except APIError as missing_read:
            require(missing_read.status == 404 and missing_read.code == 'file_not_found',
                    'E2B read failure lost missing status')
        else:
            raise RuntimeError('E2B read invented missing file')
        renamed = facade.files.rename('/workspace/e2b-meta', '/workspace/e2b-deep/tagged')
        require(renamed.name == 'tagged' and renamed.path == '/workspace/e2b-deep/tagged' and
                renamed.metadata == {'label': 'proof'} and renamed.type == 'file' and
                native.read_file(renamed.path) == b'tagged' and
                not facade.files.exists('/workspace/e2b-meta'),
                'E2B rename lost bytes, metadata or source removal')
        try:
            facade.files.rename('/workspace/e2b-deep', '/workspace/e2b-deep/a/invalid')
        except APIError as conflict:
            require(conflict.status == 409 and conflict.code == 'file_conflict',
                    'invalid directory move returned wrong error')
        else:
            raise RuntimeError('directory moved inside itself')
        moved = facade.files.rename('/workspace/e2b-deep', '/workspace/e2b-moved')
        require(moved.type == 'dir' and moved.path == '/workspace/e2b-moved' and
                facade.files.read('/workspace/e2b-moved/new/single') == 'hello',
                'E2B directory rename lost nested files')
        link = facade.files.rename('/workspace/e2b-link', '/workspace/e2b-moved/external')
        require(link.type == 'symlink' and link.symlink_target == '/etc/passwd',
                'E2B rename did not move symlink itself')
        require(facade.files.remove('/workspace/e2b-moved') is None and
                not facade.files.exists('/workspace/e2b-moved') and
                facade.files.read('/workspace/e2b-text') == 'hello-e2b',
                'E2B recursive remove failed or removed unrelated file')
        sentinel = native.run(SessionCommand('/bin/sh', ('-c', '/bin/busybox test -s /etc/passwd')))
        require(sentinel.succeeded, 'recursive remove followed the external symlink')
        for action in ('rename', 'remove'):
            try:
                if action == 'rename':
                    facade.files.rename('/workspace/missing', '/workspace/no-source')
                else:
                    facade.files.remove('/workspace/e2b-moved')
            except APIError as missing_mutation:
                require(missing_mutation.status == 404 and missing_mutation.code == 'file_not_found',
                        action + ' lost missing path status')
            else:
                raise RuntimeError(action + ' accepted missing path')
        try:
            Sandbox.create('base', client=client)
        except UnsupportedCapability:
            pass
        else:
            raise RuntimeError('E2B facade accepted an unsupported template')
        e2b_commands = exercise_e2b_commands(facade, native, tenant_b)
        interactive_stdin = exercise_interactive_stdin(facade,native,tenant_b)
        require(facade.kill(), 'E2B facade kill did not terminate a live session')
        ended = True
        require(not facade.is_running(), 'E2B facade reported killed session running')
        require(not facade.kill(), 'E2B facade killed the same session twice')
    finally:
        if not ended:
            facade.kill()
    require(not job_dirs(root / 'run') and not job_dirs(cgroup_root),
            'E2B facade left a workdir or cgroup')

    with args.package.open('rb') as stream:
        package_sha = hashlib.file_digest(stream, 'sha256').hexdigest()
    with installed_sdk.open('rb') as stream:
        sdk_sha = hashlib.file_digest(stream, 'sha256').hexdigest()
    e2b_cases = {
        'commands.send_stdin': ('PID/handle text and binary input matched persisted bytes; reconnect retained input',
                                'disabled/closed stdin, missing PID, cross tenant and size quota rejected'),
        'commands.close_stdin': ('empty and populated stdin EOF confirmed; buffered bytes retained',
                                 'disabled/missing/foreign process rejected; writing after EOF failed'),
        'commands.run': ('real Bash arrays, env/cwd and callbacks matched result',
                         'exit 7 raised typed exception with stdout/stderr'),
        'commands.list': ('only actual running guest PID and process metadata returned',
                          'foreign tenant list returned 404'),
        'commands.connect': ('disconnected and timed-out observers reattached to running PID',
                             'unknown and foreign PID returned 404'),
        'commands.kill': ('SIGKILL confirmed by exit 137; session reused',
                          'repeat kill false and foreign tenant returned 404'),
        'command_handle.wait': ('cached result and UTF-8 callbacks; one execution',
                               'exit error and observation timeout typed distinctly'),
        'sandbox.create': ('signed firecracker-linux session retained one ID',
                           'unsupported base template rejected'),
        'sandbox.is_running': ('live session reported true',
                               'terminated session reported false'),
        'sandbox.kill': ('live session terminated and resources cleared',
                         'repeat kill reported false'),
        'files.read': ('UTF-8 text and bytearray matched native file bytes',
                       'missing file returned 404 file_not_found'),
        'files.exists': ('existing file true and missing file false',
                         'symlink returned 403 file_denied'),
        'files.make_dir': ('nested directory created then existing returned false',
                           'symlink parent returned 403 file_denied'),
        'files.write': ('text write auto-created parent and returned bound WriteInfo',
                         'symlink parent returned 403 file_denied'),
        'files.write_files': ('ordered two-file batch created parents and retained bytes',
                               'second denied write left earlier success without escape'),
        'files.list': ('directory returned file, symlink and xattr metadata',
                       'symlink directory returned 403 file_denied'),
        'files.get_info': ('file, symlink and xattr info matched list',
                           'missing path returned 404 file_not_found'),
        'files.rename': ('file, directory and symlink moved; bytes and xattr metadata retained',
                         'missing source returned 404; self-descendant directory returned 409'),
        'files.remove': ('nested directory tree removed without following external link',
                         'repeat remove returned 404 file_not_found'),
    }
    evidence_dir = root / 'results/e2b-2.51.0'
    evidence_dir.mkdir(parents=True, exist_ok=True)
    for operation, (success, failure) in e2b_cases.items():
        report_case = {'suite': 'e2b-compat-case/v1', 'operation': operation,
                       'language': 'python', 'upstream_commit': E2B_COMMIT,
                       'candidate_sha256': package_sha, 'environment': 'real-kvm',
                       'adapter': 'osv_sandbox_client.Sandbox',
                       'official_sdk_unmodified': False, 'sandbox_id': facade_id,
                       'cases': [{'name': 'success', 'passed': True, 'detail': success},
                                 {'name': 'failure', 'passed': True, 'detail': failure}],
                       'passed': True}
        (evidence_dir / ('python-' + operation + '.json')).write_text(
            json.dumps(report_case, indent=2) + '\n')
    evidence = {'suite': 'python-sdk-kvm/v8',
                'generated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'package_sha256': package_sha,
                'installed_sdk_sha256': sdk_sha,
                'background_commands': background,
                'e2b_commands': e2b_commands,
                'interactive_stdin':interactive_stdin,
                'backend': report['backend'],
                'manifest_sha256': report['artifact_manifest_sha256'],
                'doctor_ready': doctor['ready'],
                'doctor_expected_ready': args.expect_doctor_ready,
                'job': {'id': result.id, 'state': result.state,
                        'protocol_ok': result.protocol_ok,
                        'stdout': result.guest_result['stdout']},
                'stale_template_status': 409,
                'bad_token_status': 401,
                'session': {'id': session_id, 'workspace_stdout': second.guest_result['stdout'],
                            'cross_tenant_status': 404, 'closed_status': 404},
                'file': {'bytes': len(binary), 'binary_roundtrip': True,
                         'command_observed': True, 'missing_status': 404,
                         'oversized_status': 413,
                         'list_contains_files': True, 'stat_file_size': len(binary),
                         'stat_root_kind': 'directory', 'delete_then_missing_status': 404,
                         'symlink_stat_status': 403, 'symlink_delete_status': 403,
                         'symlink_read_status': 403, 'symlink_write_status': 403,
                         'traversal_status': 400, 'cross_tenant_status': 404},
                'remaining_workdirs': job_dirs(root / 'run'),
                'remaining_cgroups': job_dirs(cgroup_root),
                'passed': True}
    (root / 'results/python-sdk.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print(json.dumps({'passed': True, 'job_state': result.state,
                      'stale_template_status': 409, 'bad_token_status': 401}), flush=True)


if __name__ == '__main__':
    main()
