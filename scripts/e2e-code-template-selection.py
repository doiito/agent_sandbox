#!/usr/bin/env python3
"""Use installed Python/Node/MCP code APIs while the default remains shell-only."""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
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
    MCP = runpy.run_path(str(Path(__file__).with_name('e2e-mcp.py')))['MCP']
    config = json.loads((root / 'config.production.json').read_text())
    url = 'https://localhost:' + config['listen'].rsplit(':', 1)[1]
    client = sdk.Client(url, token=(root / 'secrets/token').read_text(), ca_file=str(root / 'tls/ca.crt'),
        cert_file=str(root / 'tls/client.crt'), key_file=str(root / 'tls/client.key'), request_timeout_seconds=60)
    cases = []

    def check(name, value):
        assert value, name
        cases.append(name)

    def wait(action):
        end = time.monotonic() + 45
        while True:
            value = action()
            if value:
                return value
            assert time.monotonic() < end, 'selected template did not become ready'
            time.sleep(.025)

    entry = next(row for row in client.templates()['templates'] if row['id'] == 'linux-code' and row['available'])
    cap = entry['capabilities']
    digest = cap['artifact_manifest_sha256']
    selector = sdk.TemplateSelector(cap['backend'], digest)
    default = client.capabilities()
    check('default-shell-remains-without-code', not default['features'].get('code_contexts', False) and
          default['artifact_manifest_sha256'] != digest)
    check('explicit-signed-code-capability', client.capabilities(template=selector)['features']['code_contexts'])
    if args.expected_mode == 'warm':
        wait(lambda: any(row.get('artifact_manifest_sha256') == digest and row['ready'] >= 1
                         for row in client.doctor()['warm_pool']['profiles']))
    session = client.create_session(sdk.SessionRequest(ttl_ms=180000), template=selector)
    box = sdk.Sandbox(session)
    child = None
    report = {'suite': 'code-template-selection-real-kvm/v1', 'passed': False, 'cases': cases,
        'mode': args.expected_mode, 'candidate_sha256': hashlib.file_digest(args.package.open('rb'), 'sha256').hexdigest(),
        'selected_digest': digest, 'sandbox_id': session.id, 'performance_gate_evidence': False}
    try:
        check('python-selected-template-and-startup', session.created.backend == cap['backend'] and
              session.created.artifact_manifest_sha256 == digest and session.created.startup_mode == args.expected_mode)
        value = box.run_code("from pathlib import Path\nPath('selected.txt').write_text('shared')\nselected=41\nselected+1")
        check('python-selected-execution-and-prewarmed-cwd', value.text == '42' and box.files.read('/workspace/selected.txt') == 'shared')
        path = root / 'selected-mcp.json'
        path.write_text(json.dumps({'api_url': url, 'ca_file': str(root / 'tls/ca.crt'),
            'cert_file': str(root / 'tls/client.crt'), 'key_file': str(root / 'tls/client.key'),
            'token_file': str(root / 'secrets/token')}))
        path.chmod(0o600)
        child = MCP(release / 'bin/osv-sandbox-mcp', path)
        global_cap = child.call('sandbox.capabilities')
        owner = child.call('sandbox.capabilities', session_id=session.id)
        check('mcp-owner-profile-independent-of-default', not global_cap['features'].get('code_contexts', False) and
              owner['session_id'] == session.id and owner['artifact_manifest_sha256'] == digest and owner['features']['code_contexts'])
        tools = child.receive(child.request('tools/list', {}))['tools']
        check('mcp-catalog-advertises-selected-code-tools', 'sandbox.code.execute' in {row['name'] for row in tools})
        contexts = child.call('sandbox.code.context.list', session_id=session.id)['contexts']
        check('mcp-sees-selected-owner-context', len(contexts) == 1 and contexts[0]['language'] == 'python')
        # An ordinary default-shell session must not inherit the selected VM's feature.
        try:
            unexpected = sdk.Sandbox.create('firecracker-linux', client=client, timeout=30)
        except sdk.APIError as error:
            check('active-tenant-quota-still-global', error.status == 429)
        else:
            unexpected.kill()
            raise AssertionError('selected template bypassed active tenant quota')
        child.stop()
        child = None
        box.kill()
        script = r'''
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
const [root,release,mode]=process.argv.slice(1);
const {Client,Sandbox}=await import(pathToFileURL(release+'/sdk/node/index.js').href);
const config=JSON.parse(readFileSync(root+'/config.production.json','utf8'));
const client=new Client('https://localhost:'+config.listen.split(':').at(-1),{
 token:readFileSync(root+'/secrets/token','utf8'),caFile:root+'/tls/ca.crt',certFile:root+'/tls/client.crt',keyFile:root+'/tls/client.key'});
const entry=(await client.templates()).templates.find(row=>row.id==='linux-code'&&row.available);
assert.ok(entry);const cap=entry.capabilities;
assert.equal((await client.capabilities()).features.code_contexts,false);
if(mode==='warm'){
 const end=Date.now()+45000;
 while(!(await client.doctor()).warm_pool.profiles.some(row=>row.artifact_manifest_sha256===cap.artifact_manifest_sha256&&row.ready>=1)){
  assert.ok(Date.now()<end);await new Promise(resolve=>setTimeout(resolve,25));
 }
}
const session=await client.createSession({ttlMs:180000},{template:{backend:cap.backend,artifactManifestSha256:cap.artifact_manifest_sha256}});
const box=new Sandbox(session);
try{
 assert.equal(session.created.backend,cap.backend);assert.equal(session.created.artifactManifestSha256,cap.artifact_manifest_sha256);
 assert.equal(session.created.startupMode,mode);
 const value=await box.runCode('const selected: number=42; selected',{language:'typescript'});assert.equal(value.text,'42');
 const context=await box.createCodeContext({language:'python'});
 assert.equal((await box.runCode('40+2',{context})).text,'42');
 await box.restartCodeContext(context);await box.removeCodeContext(context);
 console.log(JSON.stringify({passed:true,sandbox_id:box.sandboxId,artifact_manifest_sha256:cap.artifact_manifest_sha256}));
}finally{await box.kill();}
'''
        result = subprocess.run(['node', '--input-type=module', '-e', script, str(root), str(release), args.expected_mode],
                                capture_output=True, text=True, check=True, timeout=120)
        node = json.loads(result.stdout)
        check('node-selected-template-lifecycle', node['passed'] and node['artifact_manifest_sha256'] == digest)
        check('active-capacity-returned', client.doctor()['vm_capacity']['active'] == 0)
        report.update(passed=True, node=node)
    finally:
        if child:
            child.stop()
        box.kill()
        (root / 'results' / ('code-template-selection-' + args.expected_mode + '.json')).write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
