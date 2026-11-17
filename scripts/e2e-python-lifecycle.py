#!/usr/bin/env python3
"""Installed Python SDK lifecycle behavior in one isolated, real-KVM fixture."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import osv_sandbox_client as sdk

p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--package',type=Path,required=True);p.add_argument('--in-netns',action='store_true');args=p.parse_args()
root=args.root
if not args.in_netns:
    pid=subprocess.check_output(['systemctl','show','-p','MainPID','--value',root.name+'-api.service'],text=True).strip()
    assert int(pid)>1
    raise SystemExit(subprocess.run(['nsenter','-t',pid,'-n',sys.executable,__file__,'--root',str(root),'--package',str(args.package),'--in-netns']).returncode)
config=json.loads((root/'config.production.json').read_text());url='https://localhost:'+config['listen'].rsplit(':',1)[1]
options={'ca_file':str(root/'tls/ca.crt'),'cert_file':str(root/'tls/client.crt'),'key_file':str(root/'tls/client.key'),'request_timeout_seconds':65}
a=sdk.Client(url,token=(root/'secrets/token').read_text(),**options);b=sdk.Client(url,token=(root/'secrets/token-b').read_text(),**options)
cases=[];sandboxes=[];renewal_id=None

def check(name,value):
    assert value,name;cases.append(name)
def rejected(name,action,status,code=None):
    try:action()
    except sdk.APIError as error:check(name,error.status==status and (code is None or error.code==code))
    else:raise AssertionError(name+' accepted')
def create(client=a,timeout=30,retry=False):
    deadline=time.monotonic()+20
    while True:
        try:box=sdk.Sandbox.create('firecracker-linux',client=client,timeout=timeout);sandboxes.append(box);return box
        except sdk.APIError as error:
            if not retry or error.status!=429 or time.monotonic()>deadline:raise
            time.sleep(0.05)
def empty(client):
    page=sdk.Sandbox.list(client=client);return page.next_items()==[] and not page.has_next
try:
    caps=a.capabilities();check('capabilities',caps['features']['session_listing'] and caps['features']['session_timeout_update'] and caps['limits']['session_max_lifetime_ms']==60000)
    first,second,foreign=create(),create(),create(b)
    first.files.write('/workspace/metadata-marker','kept')
    info=first.get_info()
    check('bound-real-metadata',info.sandbox_id==first.sandbox_id and info.template_id=='firecracker-linux' and info.cpu_count==config['defaults']['vcpus'] and info.memory_mb==config['defaults']['memory_mib'] and info.envd_version=='fc-agent/v2' and info.metadata=={} and info.state=='running')
    check('metadata-dates-and-hard-limit',info.started_at<=info.end_at<=info.max_end_at and 59<=(info.max_end_at-info.started_at).total_seconds()<=60)
    check('get-info-preserves-workspace',first.files.read('/workspace/metadata-marker')=='kept')
    page=sdk.Sandbox.list(client=a,limit=1,order='asc');items=page.next_items();cursor=page.next_token
    check('first-page',len(items)==1 and items[0].sandbox_id==first.sandbox_id and page.has_next and cursor)
    late=create()
    items=page.next_items();check('stable-page-excludes-new-create',len(items)==1 and items[0].sandbox_id==second.sandbox_id and not page.has_next)
    try:page.next_items()
    except sdk.SandboxError:cases.append('exhausted-page-error')
    else:raise AssertionError('exhausted paginator fetched again')
    rejected('foreign-cursor-404',lambda:sdk.Sandbox.list(client=b,limit=1,order='asc',next_token=cursor).next_items(),404)
    bp=sdk.Sandbox.list(client=b).next_items();check('tenant-list-isolation',[row.sandbox_id for row in bp]==[foreign.sandbox_id])
    reverse=sdk.Sandbox.list(client=a,limit=3,order='desc').next_items();check('global-descending-order',[row.sandbox_id for row in reverse]==[late.sandbox_id,second.sandbox_id,first.sandbox_id])
    changing=sdk.Sandbox.list(client=a,limit=1,order='asc');changing.next_items();second.kill();remaining=changing.next_items()
    check('deleted-item-skipped',len(remaining)==1 and remaining[0].sandbox_id==late.sandbox_id and not changing.has_next)
    denied=sdk.Sandbox(sdk.Session(b,first._session.created))
    rejected('foreign-info-404',denied.get_info,404)
    rejected('foreign-timeout-404',lambda:denied.set_timeout(5),404)
    rejected('hard-lifetime-rejected',lambda:first.set_timeout(300),400,'timeout_exceeds_lifetime')
    check('rejected-timeout-keeps-deadline',first.get_info().end_at==info.end_at)
    for box in (first,second,late,foreign):box.kill()
    check('empty-authorized-list',empty(a) and empty(b))
    box=create(timeout=2);renewal_id=box.sandbox_id
    box.files.write('/workspace/renew-marker','survived')
    original=box.get_info()
    task=box.commands.run('printf once >> /workspace/run-count; sleep 3; cat /workspace/renew-marker',background=True,timeout=0)
    box.set_timeout(6);updated=box.get_info()
    check('renewed-remaining-ttl',updated.end_at>original.end_at and updated.max_end_at==original.max_end_at)
    check('real-command-crosses-original-expiry',task.wait().stdout=='survived' and box.files.read('/workspace/run-count')=='once')
    check('renewal-retains-identity',box.get_info().sandbox_id==renewal_id and box.is_running())
    active=box.commands.run('cat',background=True,stdin=True,timeout=0)
    box.set_timeout(1)
    deadline=time.monotonic()+4
    while box.is_running():
        assert time.monotonic()<deadline,'shortened TTL did not expire';time.sleep(0.05)
    cases.append('shortened-ttl-expires-active-command')
    rejected('expired-info-404',box.get_info,404)
    rejected('expired-timeout-does-not-resurrect',lambda:box.set_timeout(5),404)
    deadline=time.monotonic()+4
    while a.doctor()['vm_capacity']['active']!=0:
        assert time.monotonic()<deadline;time.sleep(0.05)
    check('expiry-releases-vm-resources',empty(a))
    replacements=[create(timeout=30,retry=True) for _ in range(3)]
    check('all-tenant-slots-reusable',all(item.is_running() for item in replacements))
finally:
    for box in sandboxes:
        try:box.kill()
        except sdk.APIError as error:
            if error.status!=404:raise
check('no-workdir-residual',not list((root/'run').glob('job-*')))
check('no-cgroup-residual',not list((Path('/sys/fs/cgroup')/root.name).glob('job-*')))
with args.package.open('rb') as stream:candidate=hashlib.file_digest(stream,'sha256').hexdigest()
evidence=root/'results/e2b-2.51.0';evidence.mkdir(exist_ok=True)
operations={
 'sandbox.list':('tenant-bound ascending/descending stable pages; new/deleted sessions handled','foreign cursor 404 and exhausted page error'),
 'sandbox.get_info':('same sandbox/template, actual CPU/memory/protocol and lifecycle dates','foreign and expired sandbox 404'),
 'sandbox.set_timeout':('actual command survived original TTL; shortened TTL killed active VM and quota recovered','hard-lifetime limit and foreign/expired updates rejected without resurrection')}
for operation,(success,failure) in operations.items():
    report={'suite':'e2b-compat-case/v1','operation':operation,'language':'python','upstream_commit':'ccaf9fc0ffe6ac39c7ec786af7608ab1de19467b','candidate_sha256':candidate,'environment':'real-kvm','adapter':'osv_sandbox_client.Sandbox','official_sdk_unmodified':False,'sandbox_id':renewal_id,'cases':[{'name':'success','passed':True,'detail':success},{'name':'failure','passed':True,'detail':failure}],'passed':True}
    (evidence/('python-'+operation+'.json')).write_text(json.dumps(report,indent=2)+'\n')
report={'suite':'python-lifecycle-kvm/v1','passed':True,'candidate_sha256':candidate,'installed_sdk_sha256':hashlib.sha256(Path(sdk.__file__).read_bytes()).hexdigest(),'cases':cases,'case_count':len(cases),'renewal_session_id':renewal_id,'remaining_jobs':[],'remaining_cgroups':[],'performance_gate_evidence':False}
(root/'results/python-lifecycle.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':True,'cases':len(cases)}),flush=True)
