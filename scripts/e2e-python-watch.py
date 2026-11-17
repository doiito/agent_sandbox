#!/usr/bin/env python3
"""Installed SDK directory watching against actual cold/prepared Linux VMs."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import osv_sandbox_client as sdk

p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--package',type=Path,required=True);p.add_argument('--expected-mode',choices=['cold','warm'],required=True);p.add_argument('--in-netns',action='store_true');args=p.parse_args();root=args.root
if not args.in_netns:
    pid=subprocess.check_output(['systemctl','show','-p','MainPID','--value',root.name+'-api.service'],text=True).strip();assert int(pid)>1
    raise SystemExit(subprocess.run(['nsenter','-t',pid,'-n',sys.executable,__file__,'--root',str(root),'--package',str(args.package),'--expected-mode',args.expected_mode,'--in-netns']).returncode)
config=json.loads((root/'config.production.json').read_text());url='https://localhost:'+config['listen'].rsplit(':',1)[1]
options=dict(ca_file=str(root/'tls/ca.crt'),cert_file=str(root/'tls/client.crt'),key_file=str(root/'tls/client.key'),request_timeout_seconds=35)
a=sdk.Client(url,token=(root/'secrets/token').read_text(),**options);b=sdk.Client(url,token=(root/'secrets/token-b').read_text(),**options)
cases=[];boxes=[];watches=[]
def check(name,value):
    assert value,name;cases.append(name)
def wait(action):
    deadline=time.monotonic()+5
    while True:
        value=action()
        if value:return value
        assert time.monotonic()<deadline,'watch condition timed out';time.sleep(.025)
def create(timeout=30):
    deadline=time.monotonic()+20
    while True:
        try:box=sdk.Sandbox.create('firecracker-linux',client=a,timeout=timeout);boxes.append(box);return box
        except sdk.APIError as error:
            if error.status!=429 or time.monotonic()>deadline:raise
            time.sleep(.05)
def command(box,code):return box._session.run(sdk.SessionCommand('/bin/bash',('-c',code),timeout_ms=5000))
def rejected(name,action,status,code=None):
    try:action()
    except sdk.APIError as error:check(name,error.status==status and (code is None or error.code==code))
    else:raise AssertionError(name+' accepted')
def watch(box,path='/workspace',**options):
    handle=box.files.watch_dir(path,**options);watches.append(handle);return handle

try:
    cap=a.capabilities();check('signed-feature-and-resource-limits',cap['artifact_manifest_protocol']=='osv-sandbox-artifacts/v4' and cap['features']['file_watch'] and cap['features']['recursive_file_watch'] and cap['features']['file_watch_entry'] and cap['limits']['file_watch_active']==4 and cap['limits']['file_watch_events']==256)
    box=create();check('actual-startup-mode',box._session.created.startup_mode==args.expected_mode)
    handle=watch(box,include_entry=True)
    check('actual-transient-file-command',command(box,'printf short > /workspace/transient; chmod 600 /workspace/transient; mv /workspace/transient /workspace/moved; rm /workspace/moved; printf stable > /workspace/stable').succeeded)
    events=[]
    def lifecycle():
        events.extend(handle.get_new_events())
        return {'create','write','chmod','rename','remove'} <= {event.type.value for event in events}
    wait(lifecycle);check('real-five-event-types-and-transient-remove',any(e.name=='moved' and e.type==sdk.FilesystemEventType.REMOVE for e in events))
    check('relative-events-and-entry-binding',all(not e.name.startswith('/') for e in events) and any(e.entry is not None and e.entry.path=='/workspace/stable' for e in events))
    check('incremental-empty-read',handle.get_new_events()==[])
    with ThreadPoolExecutor(max_workers=1) as executor:
        running=executor.submit(command,box,'sleep .2; printf live > /workspace/concurrent; sleep 1')
        concurrent=[]
        def during_run():
            concurrent.extend(handle.get_new_events())
            return any(e.name=='concurrent' for e in concurrent)
        wait(during_run)
        check('watch-and-session-info-during-synchronous-run',not running.done() and box._session.info().id==box.sandbox_id)
        check('synchronous-command-completes-once',running.result().succeeded)
    denied=sdk.Session(b,box._session.created)
    rejected('tenant-start-hidden',lambda:denied.start_file_watch('/workspace'),404)
    foreign=sdk.FileWatchHandle(denied,handle._native.created)
    rejected('tenant-poll-hidden',foreign.poll,404);rejected('tenant-stop-hidden',foreign.stop,404)
    handle.stop()
    try:handle.get_new_events()
    except sdk.SandboxError:cases.append('stopped-python-handle-error')
    else:raise AssertionError('stopped handle accepted')
    command(box,'mkdir -p /workspace/tree/sub')
    recursive=watch(box,'/workspace/tree',recursive=True)
    command(box,'printf recursive > /workspace/tree/sub/a')
    seen=[]
    wait(lambda:seen.extend(recursive.get_new_events()) or any(e.name=='sub/a' for e in seen));cases.append('recursive-existing-directory')
    command(box,'mv /workspace/tree/sub /workspace/tree/renamed')
    wait(lambda:any(e.type==sdk.FilesystemEventType.RENAME for e in recursive.get_new_events()))
    command(box,'printf updated >> /workspace/tree/renamed/a')
    wait(lambda:any(e.name=='renamed/a' and e.type==sdk.FilesystemEventType.WRITE for e in recursive.get_new_events()));cases.append('recursive-move-updates-prefix')
    recursive.stop()
    active=[box._session.start_file_watch('/workspace') for _ in range(4)]
    rejected('fifth-watch-quota',lambda:box._session.start_file_watch('/workspace'),429,'busy')
    check('watch-list-active-limit',sum(item['state']=='watching' for item in box._session.list_file_watches())==4)
    check('stop-releases-slot',active.pop().stop())
    active.append(box._session.start_file_watch('/workspace'))
    for item in active:item.stop()
    overflow=watch(box)
    check('overflow-writer-completes',command(box,'for ((i=0;i<400;i++)); do : > /workspace/overflow-$i; done').succeeded)
    seen=[]
    def failed():
        try:seen.extend(overflow.get_new_events())
        except sdk.SandboxError as error:return 'overflow' in str(error)
        return False
    wait(failed);check('bounded-queue-overflow-is-explicit',box.is_running())
    box.kill()
    renewed=create(timeout=2);live=watch(renewed);renewed.set_timeout(6)
    check('watch-survives-soft-lease-renewal',command(renewed,'sleep 2.1; printf renewed > /workspace/renewed').succeeded)
    wait(lambda:any(e.name=='renewed' for e in live.get_new_events()));cases.append('renewed-watch-retains-events')
    renewed.set_timeout(1)
    wait(lambda:not renewed.is_running());cases.append('session-ttl-closes-active-watch')
    rejected('expired-watch-has-no-owner',live._native.poll,404)
finally:
    for box in boxes:
        try:box.kill()
        except sdk.APIError as error:
            if error.status!=404:raise
cleanup_started=time.monotonic()
check('active-capacity-returned',wait(lambda:a.doctor()['vm_capacity']['active']==0))
cleanup_wait_ms=round((time.monotonic()-cleanup_started)*1000,3)
with args.package.open('rb') as stream:candidate=hashlib.file_digest(stream,'sha256').hexdigest()
evidence=root/'results/e2b-2.51.0';evidence.mkdir(exist_ok=True)
e2b=dict(suite='e2b-compat-case/v1',operation='files.watch_dir',language='python',upstream_commit='ccaf9fc0ffe6ac39c7ec786af7608ab1de19467b',candidate_sha256=candidate,environment='real-kvm',adapter='osv_sandbox_client.Sandbox',official_sdk_unmodified=False,sandbox_id=box.sandbox_id,cases=[dict(name='success',passed=True,detail='real inotify transient, five types, recursion, concurrent synchronous command, renewable lease'),dict(name='failure',passed=True,detail='tenant isolation, quota, explicit overflow, stopped handle, TTL cleanup')],passed=True)
(evidence/'python-files.watch_dir.json').write_text(json.dumps(e2b,indent=2)+'\n')
report=dict(suite='python-directory-watch-kvm/v1',passed=True,candidate_sha256=candidate,installed_sdk_sha256=hashlib.sha256(Path(sdk.__file__).read_bytes()).hexdigest(),expected_mode=args.expected_mode,cases=cases,case_count=len(cases),cleanup_wait_ms=cleanup_wait_ms,cleanup_bound_ms=5000,performance_gate_evidence=False)
(root/'results/python-watch.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(dict(passed=True,cases=len(cases))),flush=True)
