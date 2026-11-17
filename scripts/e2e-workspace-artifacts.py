#!/usr/bin/env python3
"""Installed archive APIs over actual KVM: Python, Node, MCP and native gRPC."""
import argparse
import base64
import hashlib
import io
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tarfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--expected-mode', choices=['cold', 'warm'], required=True)
    parser.add_argument('--grpc-probe', type=Path, required=True)
    parser.add_argument('--in-netns', action='store_true')
    args = parser.parse_args()
    root = args.root.resolve()
    if not args.in_netns:
        pid = subprocess.check_output(['systemctl', 'show', '-p', 'MainPID', '--value', root.name+'-api.service'], text=True).strip()
        assert int(pid)>1
        raise SystemExit(subprocess.run(['nsenter', '-t', pid, '-n', sys.executable, __file__,
            '--root', str(root), '--package', str(args.package), '--expected-mode', args.expected_mode,
            '--grpc-probe', str(args.grpc_probe), '--in-netns']).returncode)
    release = next((root/'releases').iterdir())
    sys.path.insert(0, str(release/'sdk/python'))
    import osv_sandbox_client as sdk
    config = json.loads((root/'config.production.json').read_text())
    url = 'https://localhost:'+config['listen'].rsplit(':',1)[1]
    options = dict(ca_file=str(root/'tls/ca.crt'), cert_file=str(root/'tls/client.crt'),
                   key_file=str(root/'tls/client.key'), request_timeout_seconds=40)
    owner = sdk.Client(url, token=(root/'secrets/token').read_text(), **options)
    other = sdk.Client(url, token=(root/'secrets/token-b').read_text(), **options)
    cases, sessions, children = [], [], []
    report = dict(suite='workspace-artifacts-real-kvm/v1', passed=False, mode=args.expected_mode,
                  cases=cases, session_ids=[], actual_artifact_vsock=True, performance_gate_evidence=False,
                  candidate_sha256=hashlib.file_digest(args.package.open('rb'), 'sha256').hexdigest(),
                  installed_python_sdk_sha256=hashlib.sha256(Path(sdk.__file__).read_bytes()).hexdigest())

    def check(name, value):
        assert value, name
        cases.append(name)
        print('PASS artifact-'+name, flush=True)

    def wait(action, seconds=20):
        deadline=time.monotonic()+seconds
        while True:
            value=action()
            if value:return value
            assert time.monotonic()<deadline, 'artifact state observation timed out'
            time.sleep(.05)

    def create(ttl=180000):
        if args.expected_mode=='warm':
            wait(lambda: any(p['ready']>=1 for p in owner.doctor()['warm_pool']['profiles']))
        session=owner.create_session(sdk.SessionRequest(ttl_ms=ttl))
        sessions.append(session);report['session_ids'].append(session.id)
        check('actual-startup-'+str(len(sessions)), session.created.startup_mode==args.expected_mode)
        return session

    def command(session, code):
        value=session.run(sdk.SessionCommand('/bin/bash', ('-c',code), timeout_ms=10000))
        assert value.succeeded, 'fixture command failed'

    def rejected(name, action, status, code=None):
        try:action()
        except sdk.APIError as error:check(name, error.status==status and (code is None or error.code==code))
        else:raise AssertionError(name+' unexpectedly accepted')

    try:
        cap=owner.capabilities()
        check('signed-v8-and-bounds', cap['artifact_manifest_protocol']=='osv-sandbox-artifacts/v8' and
              cap['features']['session_artifacts'] and cap['limits']['session_artifact_count']==2 and
              cap['limits']['session_artifact_max_bytes']==32<<20 and cap['limits']['session_artifact_read_bytes']==512<<10)
        session=create();sid=session.id
        command(session, 'mkdir -p /workspace/export/empty; dd if=/dev/zero of=/workspace/export/large.bin bs=1024 count=700 2>/dev/null; printf executable > /workspace/export/run; chmod 751 /workspace/export/run')
        binary=bytes(range(256))*16
        session.write_file('/workspace/export/中文.bin', binary)
        info=session.create_artifact('/workspace/export')
        data=session.download_artifact(info)
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
            members=archive.getmembers();names=[m.name for m in members]
            check('manifest-first-and-sorted-tree', names==['.osv-artifact-manifest.json','empty','large.bin','run','中文.bin'])
            manifest=json.load(archive.extractfile(members[0]))
            check('manifest-binds-source', manifest['schema']=='osv-workspace-artifact/v1' and
                  manifest['source_path']=='/workspace/export' and manifest['source_kind']=='directory')
            check('binary-unicode-and-large-multiple-chunks', archive.extractfile('中文.bin').read()==binary and
                  archive.extractfile('large.bin').read()==bytes(700*1024) and len(data)>512<<10)
            check('safe-normalized-metadata', all(m.uid==0 and m.gid==0 and m.mtime==0 and
                  (m.isdir() or m.isfile()) and m.mode==(0o755 if m.isdir() or m.name=='run' else 0o644) for m in members))
            entries={e['path']:e for e in manifest['entries']}
            check('manifest-digests-and-counts', info.entries==4 and info.files==3 and
                  info.payload_bytes==700*1024+len(binary)+10 and
                  entries['中文.bin']['sha256']==hashlib.sha256(binary).hexdigest())
        second=session.create_artifact('/workspace/export')
        check('deterministic-tar-new-identity', second.id!=info.id and second.sha256==info.sha256 and session.download_artifact(second)==data)
        rejected('third-cache-quota', lambda:session.create_artifact('/workspace/export'),429,'artifact_limit')
        chunk=session.read_artifact(info.id,info.size,1)
        check('empty-eof-at-size', chunk['eof'] and chunk['data_base64']=='')
        rejected('range-past-end',lambda:session.read_artifact(info.id,info.size+1,1),416,'artifact_range')
        denied=sdk.Session(other,session.created)
        rejected('foreign-create-hidden',lambda:denied.create_artifact('/workspace/export'),404)
        rejected('foreign-read-hidden',lambda:denied.read_artifact(info.id),404)
        rejected('foreign-delete-hidden',lambda:denied.delete_artifact(info.id),404)
        command(session,'printf changed > /workspace/export/run')
        check('cached-bytes-immutable-after-source-mutation', session.download_artifact(info)==data)
        session.delete_artifact(info.id);session.delete_artifact(second.id)
        rejected('deleted-artifact-invisible',lambda:session.read_artifact(info.id),404,'artifact_not_found')
        single=session.create_artifact('/workspace/export/中文.bin')
        with tarfile.open(fileobj=io.BytesIO(session.download_artifact(single)),mode='r:') as archive:
            check('single-file-selection',single.source_kind=='file' and single.files==1 and
                  archive.getnames()==['.osv-artifact-manifest.json','中文.bin'] and archive.extractfile('中文.bin').read()==binary)
        session.delete_artifact(single.id)
        command(session,'mkdir -p /workspace/blank')
        empty=session.create_artifact('/workspace/blank')
        check('empty-directory-valid-tar', empty.entries==0 and empty.payload_bytes==0 and len(session.download_artifact(empty))>=2048)
        session.delete_artifact(empty.id)
        rejected('missing-source',lambda:session.create_artifact('/workspace/missing'),404,'file_not_found')
        command(session,'/bin/busybox ln -s /etc/passwd /workspace/link')
        rejected('symlink-refused',lambda:session.create_artifact('/workspace/link'),403,'file_denied')
        command(session,'/bin/busybox rm /workspace/link; /bin/busybox ln /workspace/export/run /workspace/hard')
        rejected('hardlink-refused',lambda:session.create_artifact('/workspace/hard'),403,'file_denied')
        command(session,'/bin/busybox rm /workspace/hard; /bin/busybox mkfifo /workspace/fifo')
        rejected('fifo-refused-without-blocking',lambda:session.create_artifact('/workspace/fifo'),403,'file_denied')
        command(session,'/bin/busybox rm /workspace/fifo; mkdir -p /workspace/reserved; printf conflict > /workspace/reserved/.osv-artifact-manifest.json')
        rejected('reserved-manifest-refused',lambda:session.create_artifact('/workspace/reserved'),400,'invalid_path')
        command(session,'dd if=/dev/zero of=/workspace/too-large bs=1048576 count=32 2>/dev/null')
        rejected('tar-overhead-included-in-budget',lambda:session.create_artifact('/workspace/too-large'),413,'artifact_too_large')
        command(session,'rm /workspace/too-large; rm -r /workspace/reserved')
        check('owner-survives-refused-exports',session.info().id==sid)

        node_config=root/'artifact-node.json'
        node_config.write_text(json.dumps(dict(root=str(root),release=str(release),url=url,session_id=sid)))
        node_config.chmod(0o600)
        run=subprocess.run(['node',str(Path(__file__).with_name('e2e-node-artifacts.mjs')),str(node_config)],capture_output=True,text=True,timeout=90,check=True)
        node=json.loads(run.stdout);check('installed-node-sdk',node['passed'] and node['session_id']==sid)
        report['node']=node

        MCP=runpy.run_path(str(Path(__file__).with_name('e2e-mcp.py')))['MCP']
        for legacy in (False,True):
            label='legacy' if legacy else 'modern'
            path=root/('artifact-mcp-'+label+'.json')
            path.write_text(json.dumps(dict(api_url=url,ca_file=options['ca_file'],cert_file=options['cert_file'],
                key_file=options['key_file'],token_file=str(root/'secrets/token'),max_in_flight=4)))
            path.chmod(0o600)
            child=MCP(release/'bin/osv-sandbox-mcp',path,legacy);children.append(child)
            names={row['name'] for row in child.receive(child.request('tools/list',{}))['tools']}
            check('mcp-'+label+'-catalog',{'sandbox.fs.artifact.'+op for op in ('create','read','delete')}<=names)
            value=child.call('sandbox.fs.artifact.create',session_id=sid,path='/workspace/export')
            meta=sdk.ArtifactInfo.from_payload(value,sid)
            part=child.call('sandbox.fs.artifact.read',session_id=sid,artifact_id=meta.id,offset=0,length=512<<10)
            sdk._artifact_chunk(part,sid,meta.id,0,512<<10)
            check('mcp-'+label+'-max-binary-chunk',len(base64.b64decode(part['data_base64']))==512<<10)
            child.call('sandbox.fs.artifact.delete',session_id=sid,artifact_id=meta.id)
            child.call('sandbox.fs.artifact.read',expected_error=True,session_id=sid,artifact_id=meta.id,offset=0,length=1)
            cases.append('mcp-'+label+'-deleted-error')
            child.stop();children.remove(child)

        subprocess.run([str(args.grpc_probe),'-root',str(root),'-session',sid,'-output',str(root/'results/grpc-artifacts.json')],check=True,timeout=90)
        grpc=json.loads((root/'results/grpc-artifacts.json').read_text())
        check('three-native-grpc-rpcs',grpc['passed'] and grpc['session_id']==sid)
        report['grpc']=grpc
        ttl_artifact=session.create_artifact('/workspace/export')
        session.close()
        rejected('closed-session-artifact-invisible',lambda:session.read_artifact(ttl_artifact.id),404)
        renewed=create(ttl=2000)
        renewed_artifact=renewed.create_artifact('/workspace')
        wait(lambda:owner.doctor()['vm_capacity']['active']==0,seconds=10)
        rejected('expired-session-artifact-invisible',lambda:renewed.read_artifact(renewed_artifact.id),404)
        report['passed']=True
    except Exception as error:
        report['failure']=str(error)
        raise
    finally:
        for child in children:child.stop()
        for session in sessions:
            try:session.close()
            except sdk.APIError as error:
                if error.status!=404:raise
        (root/'results'/('workspace-artifacts-'+args.expected_mode+'.json')).write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':
    main()
