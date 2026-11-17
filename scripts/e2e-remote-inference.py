#!/usr/bin/env python3
"""Actual signed guest SDK -> root vsock -> non-root egress -> TLS model/bill."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import time

from egress_fixture_readiness import wait_fixture_egress, verify_fixture_policy_rejection


GUEST_PYTHON = '''import json,sys,time
import remote_infer as r
import sandbox
base=int(sys.argv[1]); identity=lambda n:format(base+n,'024x')
checks=[]
def check(name,value):
 assert value,name
 checks.append(name)
p=r.policy(); b=r.bill()
check('policy-redacted','credential' not in json.dumps(p) and 'url' not in json.dumps(p))
x=sandbox.ml.invoke('model',{},invocation_id=identity(1))
check('root-task-exact-money',x.task_id==b['task_id'] and x.data=={'answer':'ok'} and int(x.invocation['settled_units'])>2**53)
try:r.invoke('model',{},invocation_id=identity(1))
except r.InferenceError as e:check('replay-denied',e.code=='inference_replay' and e.invocation_id==identity(1))
else:raise AssertionError('replay accepted')
try:r.invoke('other',{},invocation_id=identity(9))
except r.InferenceError as e:check('unknown-alias-local',not e.delivery_unknown)
else:raise AssertionError('unknown alias accepted')
x=r.invoke('model',{'mode':'unicode'},invocation_id=identity(2))
check('bounded-large-UTF8',len(x.data['text'])==140000 and x.invocation['output_bytes']<=512<<10)
try:r.invoke('model',{'mode':'pending'},invocation_id=identity(3),request_timeout=.6)
except r.InferenceError as e:check('timeout-known-ID',e.invocation_id==identity(3) and e.delivery_unknown)
else:raise AssertionError('pending succeeded')
end=time.monotonic()+5
while True:
 b=r.bill(); entry=next(x for x in b['invocations'] if x['id']==identity(3))
 if entry['state']=='uncertain':break
 assert time.monotonic()<end
 time.sleep(.025)
check('unknown-keeps-budget',entry['settled_units']=='0' and int(entry['reserved_units'])>0)
print(json.dumps({'passed':True,'cases':checks,'task_id':b['task_id']}))
'''

GUEST_NODE = '''const r=require('/opt/osv/remote-infer.cjs');
(async()=>{const base=Number(process.argv[2]), id=n=>(base+n).toString(16).padStart(24,'0'), checks=[];
const check=(name,value)=>{if(!value)throw Error(name);checks.push(name);};
const p=await r.policy(), b=await r.bill();
check('policy-redacted',!JSON.stringify(p).includes('credential')&&!JSON.stringify(p).includes('url'));
const x=await r.ml.invoke('model',{}, {invocationId:id(1)});
check('root-task-exact-money',x.taskId===b.task_id&&x.data.answer==='ok'&&BigInt(x.invocation.settled_units)>2n**53n);
try{await r.invoke('model',{}, {invocationId:id(1)});throw Error('replay accepted');}catch(e){check('replay-denied',e.code==='inference_replay'&&e.invocationId===id(1));}
try{await r.invoke('other',{}, {invocationId:id(9)});throw Error('alias accepted');}catch(e){check('unknown-alias-local',e instanceof r.InferenceError&&!e.deliveryUnknown);}
const large=await r.invoke('model',{mode:'unicode'},{invocationId:id(2)});
check('bounded-large-UTF8',large.data.text.length===140000&&large.invocation.output_bytes<=512*1024);
try{await r.invoke('model',{mode:'pending'},{invocationId:id(3),requestTimeoutMs:600});throw Error('pending succeeded');}catch(e){check('timeout-known-ID',e.invocationId===id(3)&&e.deliveryUnknown);}
let bill,entry;const end=Date.now()+5000;
for(;;){bill=await r.bill();entry=bill.invocations.find(x=>x.id===id(3));if(entry.state==='uncertain')break;if(Date.now()>end)throw Error('drain');await new Promise(x=>setTimeout(x,25));}
check('unknown-keeps-budget',entry.settled_units==='0'&&BigInt(entry.reserved_units)>0n);
console.log(JSON.stringify({passed:true,cases:checks,task_id:bill.task_id}));
})().catch(e=>{console.error(e);process.exitCode=1;});
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--expected-mode', choices=['cold', 'warm'], required=True)
    parser.add_argument('--backend', choices=['linux', 'osv'], required=True)
    parser.add_argument('--in-netns', action='store_true')
    args = parser.parse_args()
    root = args.root.resolve()
    if not args.in_netns:
        pid = subprocess.check_output(['systemctl', 'show', '-p', 'MainPID', '--value', root.name + '-api.service'], text=True).strip()
        assert int(pid) > 1
        raise SystemExit(subprocess.run(['nsenter', '-t', pid, '-n', sys.executable, __file__,
            '--root', str(root), '--package', str(args.package), '--expected-mode', args.expected_mode,
            '--backend', args.backend, '--in-netns']).returncode)
    release = next((root / 'releases').iterdir())
    sys.path.insert(0, str(release / 'sdk/python'))
    import osv_sandbox_client as sdk
    config = json.loads((root / 'config.production.json').read_text())
    url = 'https://localhost:' + config['listen'].rsplit(':', 1)[1]
    options = dict(ca_file=str(root / 'tls/ca.crt'), cert_file=str(root / 'tls/client.crt'),
                   key_file=str(root / 'tls/client.key'), request_timeout_seconds=65)
    a, b = [sdk.Client(url, token=(root / 'secrets' / token).read_text(), **options) for token in ['token', 'token-b']]
    backend = 'firecracker-' + args.backend
    report = {'suite': 'signed-guest-inference-real-KVM/v1', 'passed': False,
              'backend': backend, 'mode': args.expected_mode, 'cases': [], 'tasks': [],
              'candidate_sha256': hashlib.file_digest(args.package.open('rb'), 'sha256').hexdigest(),
              'actual_guest_vsock': True, 'performance_gate_evidence': False}
    sessions, children, private = [], [], []
    def check(name, condition):
        assert condition, name
        report['cases'].append(name)
        print('PASS inference-' + name, flush=True)
    def wait(action, seconds=45):
        deadline = time.monotonic() + seconds
        while True:
            value = action()
            if value:
                return value
            assert time.monotonic() < deadline, 'inference observation timed out'
            time.sleep(.025)
    def warm_ready():
        if args.expected_mode == 'warm':
            wait(lambda: any(row.get('backend') == backend and
                             row.get('artifact_manifest_sha256') == cap['artifact_manifest_sha256'] and
                             row['name'] == ('code' if args.backend == 'linux' else 'science') and row['ready'] >= 1
                             for row in a.doctor()['warm_pool']['profiles']))
    def output(value):
        assert value.succeeded and not value.output_truncated, (value.state, value.guest_result, value.output)
        text = value.guest_result.get('stdout', '')
        rows = [json.loads(line) for line in text.splitlines() if line.startswith('{')]
        assert len(rows) == 1, text
        return rows[0]
    def model_events():
        path = root / 'results/upstream-events.jsonl'
        return [json.loads(line) for line in path.read_text().splitlines()
                if json.loads(line).get('event') == 'model-request'] if path.exists() else []
    def bill_closed(task):
        return wait(lambda: value if (value := a.get_inference_bill(task))['closed'] else None, 10)
    def guest(session, entry, path, source, base):
        session.write_file(path, source.encode())
        value = output(session.run(sdk.SessionCommand(entry, (path, str(base)), timeout_ms=15000)))
        check('actual-guest-' + str(base), value['passed'] and value['task_id'] == session.id and len(value['cases']) == 7)
        report.setdefault('guest_cases', {})[str(base)] = value['cases']
    def vm_observation(bill):
        observations = []
        for path in (root / 'run').glob('job-*/lease.json'):
            lease = json.loads(path.read_text())
            intent = path.parent / 'inference.binding.json'
            if not intent.is_file():
                continue
            bound = json.loads(intent.read_text())
            if bound.get('binding') != {key: bill[key] for key in ('tenant', 'task_id', 'vm_id', 'lease_id')}:
                continue
            assert bound['protocol'] == 'osv-sandbox-inference-intent/v1'
            assert path.parent.name.startswith('job-' + bill['vm_id'] + '-')
            proc = Path('/proc') / str(lease['pid'])
            if (proc / 'comm').read_text().strip() != 'firecracker':
                continue
            status = (proc / 'status').read_text().splitlines()
            uid = int(next(line for line in status if line.startswith('Uid:')).split()[2])
            ticks = int((proc / 'stat').read_text().rsplit(')', 1)[1].split()[19])
            fc_paths = list(path.parent.rglob('config.json'))
            assert len(fc_paths) == 1
            fc = json.loads(fc_paths[0].read_text())
            assert uid > 0 and ticks == lease['start_time_ticks'] and not fc.get('network-interfaces')
            observations.append({'pid': lease['pid'], 'uid': uid, 'vm_id': bill['vm_id'],
                                 'task_id': bill['task_id'], 'no_NIC': True, 'start_time_ticks': ticks})
        assert len(observations) == 1, observations
        report.setdefault('observed_actual_VMs', []).extend(observations)
    try:
        cap = a.capabilities()
        check('signed-v7-and-authorized-inference', cap['backend'] == backend and
              cap['artifact_manifest_protocol'] in (['osv-sandbox-artifacts/v7', 'osv-sandbox-artifacts/v8'] if args.backend == 'linux' else ['osv-sandbox-artifacts/v7']) and cap['features']['remote_inference'])
        check('policy-has-no-provider-secrets', 'credential' not in json.dumps(cap['remote_inference_policy']) and
              'url' not in json.dumps(cap['remote_inference_policy']))
        pid = subprocess.check_output(['systemctl', 'show', '-p', 'MainPID', '--value', root.name + '-egress.service'], text=True).strip()
        uid = int(next(line for line in (Path('/proc') / pid / 'status').read_text().splitlines() if line.startswith('Uid:')).split()[2])
        check('actual-production-egress-non-root', uid > 0)
        check('isolated-network-has-no-routes', not subprocess.check_output(['ip', 'route', 'show'], text=True).strip())
        before = len(model_events())
        if args.backend == 'linux':
            warm_ready()
            session = a.create_session(sdk.SessionRequest(memory_mib=1024, ttl_ms=180000, network='proxy'))
            sessions.append(session)
            check('actual-' + args.expected_mode + '-session', session.created.startup_mode == args.expected_mode)
            initial = session.ml.bill()
            check('new-root-grant-is-empty', not initial['invocations'] and initial['task_id'] == session.id)
            vm_observation(initial)
            if args.expected_mode == 'warm':
                check('warm-physical-VM-is-not-logical-task', initial['vm_id'] != session.id)
            guest(session, '/opt/python/bin/python3.12', '/workspace/inference.py', GUEST_PYTHON, 0)
            guest(session, '/opt/node/bin/node', '/workspace/inference.cjs', GUEST_NODE, 100)
            value = session.ml.invoke('model', {}, invocation_id=f'{301:024x}')
            check('installed-host-Python-to-actual-owner', value.task_id == session.id and value.data == {'answer': 'ok'})
            node_config = root / 'secrets/node-inference.json'
            node_config.write_text(json.dumps({'release': str(release), 'root': str(root), 'url': url, 'session_id': session.id}))
            node_config.chmod(0o600)
            result = subprocess.run(['node', str(Path(__file__).with_name('e2e-inference-node.mjs')), str(node_config)],
                                    check=True, capture_output=True, text=True, timeout=25)
            node_result = json.loads(result.stdout)
            check('installed-host-Node-to-actual-owner', node_result['passed'] and len(node_result['cases']) == 4)
            report['host_node_cases'] = node_result['cases']
            mcp_path = root / 'secrets/inference-mcp.json'
            mcp_path.write_text(json.dumps({'api_url': url, 'ca_file': options['ca_file'], 'cert_file': options['cert_file'],
                'key_file': options['key_file'], 'token_file': str(root / 'secrets/token'), 'max_in_flight': 4}))
            mcp_path.chmod(0o600)
            MCP = runpy.run_path(str(Path(__file__).with_name('e2e-mcp.py')))['MCP']
            mcp = MCP(release / 'bin/osv-sandbox-mcp', mcp_path); children.append(mcp)
            value = mcp.call('sandbox.ml.invoke', session_id=session.id, invocation_id=f'{401:024x}', endpoint='model', payload={})
            check('installed-MCP-to-actual-owner', value['task_id'] == session.id and value['data'] == {'answer': 'ok'})
            denied = mcp.call('sandbox.ml.invoke', expected_error=True, session_id=session.id, invocation_id=f'{401:024x}', endpoint='model', payload={})
            check('MCP-known-ID-not-replayed', denied['error']['code'] == 'inference_replay')
            check('MCP-reads-real-task-bill', len(mcp.call('sandbox.ml.bill', task_id=session.id)['invocations']) == 10)
            try:
                b.get_inference_bill(session.id)
            except sdk.APIError as error:
                check('other-tenant-history-hidden', error.status == 404)
            else:
                raise AssertionError('foreign bill visible')
            check('exact-ten-model-POSTs-no-replay', len(model_events()) - before == 10)
            original_policy = (root / 'auth.json').read_bytes()
            original_price = json.loads(original_policy)['tenants'][0]['inference']['endpoints'][0]['price']['request_units']
            original_generation = wait_fixture_egress(root, session.id, original_price)
            original_bill = a.get_inference_bill(session.id)
            changed = json.loads(original_policy)
            changed['tenants'][0]['inference']['endpoints'][0]['price']['request_units'] = '1'
            try:
                (root / 'auth.json').write_text(json.dumps(changed))
                subprocess.run(['systemctl', 'restart', root.name + '-egress.service'], check=True)
                current = wait_fixture_egress(root, session.id, '1')
                report.setdefault('egress_restarts', []).append(current)
                report['root_policy_refusal'] = verify_fixture_policy_rejection(root, original_bill,
                    original_generation['policy_sha256'], current)
                rejected = "import remote_infer as r,json\ntry:r.invoke('model',{},invocation_id='0000000000000000000001f5')\nexcept r.InferenceError as e:print(json.dumps({'denied':True,'known_id':e.invocation_id,'code':e.code,'delivery_unknown':e.delivery_unknown}))\nelse:raise AssertionError('changed policy accepted')"
                session.write_file('/workspace/changed.py', rejected.encode())
                value = output(session.run(sdk.SessionCommand('/opt/python/bin/python3.12', ('/workspace/changed.py',), timeout_ms=10000)))
                report['old_policy_guest_error'] = value
                check('old-root-policy-grant-denied-in-actual-guest', value['denied'] and
                      value['known_id'] == f'{501:024x}' and len(model_events()) - before == 10)
            finally:
                (root / 'auth.json').write_bytes(original_policy)
                subprocess.run(['systemctl', 'restart', root.name + '-egress.service'], check=True)
                price = json.loads(original_policy)['tenants'][0]['inference']['endpoints'][0]['price']['request_units']
                report.setdefault('egress_restarts', []).append(wait_fixture_egress(root, session.id, price))
            session.close()
            closed = bill_closed(session.id)
            check('real-session-close-keeps-known-uncertain-bills', len(closed['invocations']) == 10 and
                  sum(row['state'] == 'uncertain' for row in closed['invocations']) == 3 and int(closed['held_units']) > 0)
            report['tasks'].append(closed)
            warm_ready()
            none = a.create_session(sdk.SessionRequest(memory_mib=1024, ttl_ms=30000))
            sessions.append(none)
            script = "import remote_infer as r,json\ntry:r.bill(request_timeout=.3)\nexcept r.SandboxError:print(json.dumps({'denied':True}))\nelse:raise AssertionError('none network connected')"
            none.write_file('/workspace/none.py', script.encode())
            denied = output(none.run(sdk.SessionCommand('/opt/python/bin/python3.12', ('/workspace/none.py',), timeout_ms=5000)))
            check('next-VM-none-network-has-no-old-grant', denied['denied'] and len(model_events()) - before == 10)
            none.close()
        else:
            for number in (1, 2):
                warm_ready()
                identity = ",invocation_id='" + f'{number:024x}' + "'" if number == 1 else ''
                code = ("import remote_infer as r,json; x=r.invoke('model',{}" + identity +
                        "); print(json.dumps({'task':x.task_id,'id':x.invocation_id,'data':x.data,'bill':r.bill()}))")
                value = a.run(sdk.JobRequest('/python3.12.so', ('-c', code), memory_mib=512, timeout_ms=15000, network='proxy'))
                result = output(value)
                report.setdefault('osv_job_observations', []).append({'number': number,
                    'api_job_id': value.id, 'api_startup_mode': value.startup_mode,
                    'expected_startup_mode': args.expected_mode, 'guest': result})
                check('actual-OSv-C-ABI-' + str(number), result['data'] == {'answer': 'ok'} and result['task'] == value.id
                      and value.startup_mode == args.expected_mode and len(result['bill']['invocations']) == 1)
                check('OSv-known-or-generated-ID-' + str(number), result['bill']['invocations'][0]['id'] == result['id'] and
                      len(result['id']) == 24 and all(c in '0123456789abcdef' for c in result['id']))
                closed = bill_closed(value.id)
                check('OSv-task-closed-' + str(number), len(closed['invocations']) == 1 and int(closed['settled_units']) > 2**53)
                report['tasks'].append(closed)
                if args.expected_mode == 'warm':
                    check('OSv-warm-owner-' + str(number), closed['vm_id'] != value.id)
            check('OSv-fresh-owner-not-previous-task', report['tasks'][0]['vm_id'] != report['tasks'][1]['vm_id'])
            check('exact-two-OSv-TLS-POSTs', len(model_events()) - before == 2)
        check('all-model-credentials-were-private-egress-injected', all(row['authorized'] for row in model_events()))
        task = report['tasks'][0]['task_id']
        archive = root / 'results' / ('closed-' + task + '.json')
        binary = release / 'bin/osv-sandbox-egress'
        commands = [
            [str(binary), '-config', str(root / 'egress.production.json'), 'bill-export', '-tenant', 'validation-a', '-task', task, '-output', str(archive)],
            [str(binary), 'bill-verify', '-archive', str(archive)],
            [str(binary), '-config', str(root / 'egress.production.json'), 'bill-retire', '-archive', str(archive)],
        ]
        for command in commands:
            subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
        check('installed-offline-bill-export-verify-retire', archive.is_file() and archive.stat().st_mode & 0o077 == 0)
        try:
            a.get_inference_bill(task)
        except sdk.APIError as error:
            check('retired-history-not-returned', error.status == 404)
        else:
            raise AssertionError('retired bill remained live')
        report['model_POSTs'] = len(model_events()) - before
        report['passed'] = True
    finally:
        for child in children:
            child.stop()
        for session in sessions:
            try:
                session.close()
            except sdk.SandboxError:
                pass
        (root / 'results' / ('inference-' + args.backend + '-' + args.expected_mode + '.json')).write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
