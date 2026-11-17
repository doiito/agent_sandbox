#!/usr/bin/env python3
"""Account for idle pool owners separately from active job cleanup."""
import argparse,importlib.util,json,sys,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--expected-mode',choices=('cold','warm'),required=True);args=p.parse_args();root=args.root
release=next((root/'releases').iterdir());sys.path.insert(0,str(release/'sdk/python'))
from osv_sandbox_client import Client
config=json.loads((root/'config.production.json').read_text());client=Client('https://localhost:'+config['listen'].rsplit(':',1)[1],token=(root/'secrets/token').read_text(),ca_file=str(root/'tls/ca.crt'),cert_file=str(root/'tls/client.crt'),key_file=str(root/'tls/client.key'),request_timeout_seconds=5)
spec=importlib.util.spec_from_file_location('pool_inspection',Path(__file__).with_name('e2e-warm-pool.py'));pool=importlib.util.module_from_spec(spec);spec.loader.exec_module(pool)
deadline=time.monotonic()+20
while True:
 status=client.doctor();capacity=status['vm_capacity'];directories=list((root/'run').glob('job-*'));groups=list((Path('/sys/fs/cgroup')/root.name).glob('job-*'))
 names={path.name for path in directories};group_names={path.name for path in groups};snapshot=None
 if capacity['active']==0:
  if args.expected_mode=='cold' and capacity['instances']==0 and not names and not group_names:
   snapshot={'passed':True,'active_jobs':0,'idle_pool_vms':0,'pool_owned_workdirs':[],'pool_owned_cgroups':[],'remaining_active_workdirs':[],'remaining_active_cgroups':[]}
  elif args.expected_mode=='warm':
   state=status['warm_pool'];profiles=state['profiles'];ready={row['key']:row['ready'] for row in profiles}
   if state['healthy'] and not state['degraded'] and state['checking']==0 and state['retiring']==0 and state['foreground']==0 and all(row['booting']==0 for row in profiles):
    # Existing pool inspector verifies PID start ticks, unique non-root jail UID,
    # actual cgroup membership and bounded physical count for each live owner.
    rows=list(pool.leases(root).values());counts={key:sum(row['pool_key']==key for row in rows) for key in ready}
    if len(rows)==len(names)==capacity['instances']==sum(ready.values()) and names==group_names and counts==ready and all(row['phase']=='ready' and not row.get('tenant') and not row.get('request_id') and row['pool_key'] in ready for row in rows):
     for row in rows:pool.pristine_pings(root,row,config['linux_guest']['vsock_port'],1)
     snapshot={'passed':True,'active_jobs':0,'idle_pool_vms':len(rows),'pool_owned_workdirs':sorted(names),'pool_owned_cgroups':sorted(group_names),'remaining_active_workdirs':[],'remaining_active_cgroups':[],'owners':[{key:row[key] for key in ('vm_id','pid','start_time_ticks','pool_key','phase')} for row in rows],'profile_ready_counts':ready,'guest_pristine_proven':True}
 if snapshot is not None:print(json.dumps(snapshot));break
 assert time.monotonic()<deadline,'job cleanup/pool ownership did not settle: '+json.dumps({'capacity':capacity,'directories':sorted(names),'cgroups':sorted(group_names)})
 time.sleep(0.05)
