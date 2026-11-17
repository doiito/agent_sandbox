#!/usr/bin/env python3
"""Optional actual egress service and TLS upstream for isolated KVM tests."""
import argparse
import json
import os
from pathlib import Path
import pwd
import subprocess
import time

p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--upload',type=Path,required=True);p.add_argument('--release',type=Path,required=True);p.add_argument('--guest-proxy',action='store_true');p.add_argument('--inference',action='store_true');args=p.parse_args();root=args.root;api=pwd.getpwnam('osv-sandbox')
assert os.geteuid()==0 and root.name.startswith('osv-offline-validation-20261030-') and root.is_dir()
for name in ['egress-runtime','egress-audit']:
 path=root/name;path.mkdir(mode=0o700);os.chown(path,api.pw_uid,api.pw_gid)
config={'production':True,'socket_path':str(root/'egress-runtime/e.sock'),'auth_policy_path':str(root/'auth.json'),'audit_log_path':str(root/'egress-audit/network.jsonl'),'ca_file':str(root/'tls/ca.crt'),'max_concurrent':2}
if args.guest_proxy:config['guest_proxy']=True
if args.inference:
 assert args.guest_proxy and (root/'egress-state/provider-credential').is_file()
 config['inference']={'ledger_directory':str(root/'egress-state/ledger'),'max_tasks':128}
path=root/'egress.production.json';path.write_text(json.dumps(config));path.chmod(0o640);os.chown(path,0,api.pw_gid)
upstream=root.name+'-upstream.service';egress=root.name+'-egress.service'
upstream_unit=f'''[Unit]
Description=Disposable TLS upstream for {root.name}
[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 {args.upload}/egress-fixture-upstream.py --root {root}
PrivateNetwork=yes
RuntimeMaxSec=1800
KillMode=control-group
TimeoutStopSec=10
StandardOutput=append:{root}/results/upstream-service.log
StandardError=append:{root}/results/upstream-service.log
'''
Path('/run/systemd/system',upstream).write_text(upstream_unit)
content=(args.release/'systemd/osv-sandbox-egress.service').read_text()
for old,new in [('/opt/osv-sandbox/current',str(args.release)),('/etc/osv-sandbox',str(root)),('/run/osv-sandbox-egress',str(root/'egress-runtime')),('/var/log/osv-sandbox-egress',str(root/'egress-audit')),('/var/lib/osv-sandbox-egress',str(root/'egress-state'))]:content=content.replace(old,new)
if not (root/'egress-state').exists():
 (root/'egress-state').mkdir(mode=0o700);os.chown(root/'egress-state',api.pw_uid,api.pw_gid)
content='\n'.join(line for line in content.splitlines() if not line.startswith(('RuntimeDirectory=','RuntimeDirectoryMode=','StateDirectory=','StateDirectoryMode=','LogsDirectory=','LogsDirectoryMode=','WantedBy=')))+'\n'
content=content.replace('After=network-online.target',f'After={upstream}\nRequires={upstream}\nJoinsNamespaceOf={upstream}')
content=content.replace('[Service]',f'[Service]\nPrivateNetwork=yes\nRuntimeMaxSec=1800\nStandardOutput=append:{root}/results/egress-service.log\nStandardError=append:{root}/results/egress-service.log').replace('Restart=on-failure','Restart=no')
Path('/run/systemd/system',egress).write_text(content)
subprocess.run(['systemctl','daemon-reload'],check=True)
subprocess.run(['systemctl','start',upstream],check=True)
deadline=time.monotonic()+10
while not (root/'upstream-ready.json').exists():assert time.monotonic()<deadline,'upstream failed readiness';time.sleep(.05)
subprocess.run(['systemctl','start',egress],check=True)
while not (root/'egress-runtime/e.sock').exists():assert time.monotonic()<deadline,'egress failed readiness';time.sleep(.05)
print(json.dumps({'egress_service':egress,'upstream_service':upstream,'only_test_network_namespace':True}))
