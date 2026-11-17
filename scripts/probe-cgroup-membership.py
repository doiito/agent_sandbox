#!/usr/bin/env python3
"""Bounded kernel-interface diagnostic, with no application/performance gate claim."""
import argparse
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import time

from startup_benchmark import atomic_report, percentiles, require, sha, start_ticks, validation_lock

SAMPLES, MAX_SECONDS = 1024, 45
CHILD = ('import sys,time;sys.stdin.buffer.read(1);'
         'data=bytearray(int(sys.argv[1]));print("ready",flush=True);time.sleep(120)')


def validate_root(root):
    require(root.parent == Path('/var/lib') and re.fullmatch(
        r'osv-offline-validation-20261030-cgprobe[a-z0-9]+',root.name), 'invalid isolated diagnostic root')
    require(not root.exists() and not root.is_symlink(), 'diagnostic root already exists')
    parent=Path('/sys/fs/cgroup')/root.name
    require(not parent.exists() and not parent.is_symlink(), 'diagnostic cgroup already exists')
    return parent


def validate_membership(kind, data, pid):
    require(kind == b'domain\n', 'requires exact domain leaf')
    require(type(pid) is int and pid > 1 and 0 < len(data) <= 16384 and data.endswith(b'\n'),
            'invalid bounded member list')
    values=data.splitlines()
    require(values and all(re.fullmatch(rb'[1-9][0-9]{0,9}',value) and int(value)==pid for value in values),
            'missing or foreign member PID')


def deadline_check(deadline):
    require(time.monotonic() < deadline, 'diagnostic time limit reached')


def ready_line(process):
    require(select.select([process.stdout],[],[],3)[0], 'child startup timed out')
    return process.stdout.readline(4096)


def stop_owned(process, *, group=True):
    if process is None:return
    if process.poll() is None:
        try:
            if group:os.killpg(process.pid,signal.SIGTERM)
            else:process.terminate()
        except ProcessLookupError:pass
        try:process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            if group:os.killpg(process.pid,signal.SIGKILL)
            else:process.kill()
            process.wait(timeout=2)
    else:process.wait(timeout=1)
    for stream in (process.stdin,process.stdout):
        if stream is not None and not stream.closed:stream.close()


def limits(leaf):
    (leaf/'memory.max').write_text(str(128<<20))
    (leaf/'memory.swap.max').write_text('0')
    (leaf/'pids.max').write_text('16')
    (leaf/'cpu.max').write_text('100000 100000')


def start_owned(leaf, allocation, *, new_session=True):
    process=subprocess.Popen([sys.executable,'-c',CHILD,str(allocation)],stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=new_session)
    try:
        generation=start_ticks(process.pid)
        (leaf/'cgroup.procs').write_text(str(process.pid))
        require(start_ticks(process.pid)==generation, 'child generation changed during migration')
        process.stdin.write(b'1');process.stdin.flush()
        require(ready_line(process)==b'ready\n', 'child startup failed')
        return process,generation
    except BaseException:
        stop_owned(process,group=new_session);raise


def churn(parent):
    # Worker argument is only accepted for a root-owned, already-created probe.
    require(os.geteuid()==0 and parent.parent==Path('/sys/fs/cgroup') and
            re.fullmatch(r'osv-offline-validation-20261030-cgprobe[a-z0-9]+',parent.name) and
            parent.is_dir(), 'invalid churn parent')
    started=time.monotonic()
    deadline=started+10
    count,child=0,None
    leaf=parent/'churn'
    try:
        while count<64 and time.monotonic()<deadline and not select.select([sys.stdin],[],[],0)[0]:
            begin=time.monotonic()
            leaf.mkdir();limits(leaf)
            child,_=start_owned(leaf,32<<20,new_session=False)
            stop_owned(child,group=False);child=None
            require(not (leaf/'cgroup.procs').read_text().strip(), 'churn leaf not empty')
            leaf.rmdir();count+=1
            if count==1:print(json.dumps({'ready':True}),flush=True)
            time.sleep(max(0,.1-(time.monotonic()-begin)))
        reason='cycle_limit' if count>=64 else 'time_limit' if time.monotonic()>=deadline else 'stop_requested'
        return {'passed':reason=='stop_requested','cycles':count,'stop_reason':reason,
                'max_cycles_per_second':10,'elapsed_seconds':time.monotonic()-started}
    finally:
        stop_owned(child,group=False)
        if leaf.exists():
            require(not (leaf/'cgroup.procs').read_text().strip(), 'churn cleanup has unknown PID')
            leaf.rmdir()


def pair(leaf,pid,generation,stage,index,deadline):
    row={'stage':stage,'index':index,'pid':pid,'start_time_ticks':generation,
         'wall_start_ns':time.time_ns(),'monotonic_start_ns':time.monotonic_ns(),
         'order':['proc','members'] if index%2==0 else ['members','proc'],'success':False,'timing_us':{}}
    try:
        deadline_check(deadline)
        require(start_ticks(pid)==generation, 'target generation changed before pair')
        for mode in row['order']:
            begin=time.monotonic_ns()
            if mode=='proc':
                data=Path('/proc',str(pid),'cgroup').read_bytes()
                end=time.monotonic_ns()
                require(data==('0::/'+str(leaf.relative_to('/sys/fs/cgroup'))+'\n').encode(),
                        'proc cgroup ownership mismatch')
            else:
                kind=(leaf/'cgroup.type').read_bytes();data=(leaf/'cgroup.procs').read_bytes()
                end=time.monotonic_ns()
                validate_membership(kind,data,pid)
            row['timing_us'][mode]=(end-begin)/1000
        require(start_ticks(pid)==generation, 'target generation changed after pair')
        deadline_check(deadline)
        row['success']=True
    except Exception as error:row['error']=type(error).__name__+': '+str(error)[:512]
    row['wall_end_ns']=time.time_ns();row['monotonic_end_ns']=time.monotonic_ns()
    return row


def measure(root, lock_fd):
    parent=validate_root(root)
    require(os.geteuid()==0, 'requires root')
    enabled=(Path('/sys/fs/cgroup')/'cgroup.subtree_control').read_text().split()
    require({'cpu','memory','pids','io'}<=set(enabled), 'root controllers not already enabled')
    root.mkdir(mode=0o700);output=root/'results';output.mkdir(mode=0o700)
    report={'suite':'cgroup-membership-interface-diagnostic/v1','diagnostic':True,
        'performance_gate_evidence':False,'production_validated':False,'passed':False,
        'test_sha256':sha(__file__),'support_sha256':sha(Path(__file__).with_name('startup_benchmark.py')),
        'kernel':os.uname().release,'root_subtree_control_before':enabled,'samples_per_stage':SAMPLES,
        'stages':{},'churn':{},'errors':[]}
    target,worker=None,None
    deadline=time.monotonic()+MAX_SECONDS
    leaf=parent/'target'
    try:
        parent.mkdir();(parent/'cgroup.subtree_control').write_text('+cpu +memory +pids +io')
        leaf.mkdir();limits(leaf);target,generation=start_owned(leaf,0)
        report['target']={'pid':target.pid,'start_time_ticks':generation,'cgroup':str(leaf)}
        with (output/'samples.jsonl').open('x') as raw:
            for stage in ('A1','B1','B2','A2'):
                if stage.startswith('B'):
                    worker=subprocess.Popen([sys.executable,__file__,'--churn-parent',str(parent),'--lock-fd',str(lock_fd)],
                        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True,
                        pass_fds=(lock_fd,))
                    require(json.loads(ready_line(worker))=={'ready':True}, 'churn did not start')
                rows=[]
                for index in range(SAMPLES):
                    if worker is not None and worker.poll() is not None:
                        report['churn'][stage]=json.loads(worker.stdout.read(4096))
                        raise ValueError('churn stopped during measurement')
                    row=pair(leaf,target.pid,generation,stage,index,deadline)
                    raw.write(json.dumps(row)+'\n');raw.flush();rows.append(row)
                    require(row['success'], 'interface pair failed; no retry')
                    time.sleep(.002)
                if worker is not None:
                    worker.stdin.close();worker.wait(timeout=5)
                    result=json.loads(worker.stdout.read(4096))
                    require(worker.returncode==0 and result['passed'] and result['cycles']>0, 'churn failed')
                    report['churn'][stage]=result
                    stop_owned(worker);worker=None
                report['stages'][stage]={'samples':len(rows),'percentiles_ms':{
                    mode:percentiles([r['timing_us'][mode]/1000 for r in rows]) for mode in ('proc','members')},
                    'over_10ms':{mode:sum(r['timing_us'][mode]>10000 for r in rows) for mode in ('proc','members')}}
                print(json.dumps({'stage':stage,**report['stages'][stage]}),flush=True)
            raw.flush();os.fsync(raw.fileno())
        require((Path('/sys/fs/cgroup')/'cgroup.subtree_control').read_text().split()==enabled,
                'root controller baseline changed')
        report['passed']=True
    except Exception as error:
        report['errors'].append(type(error).__name__+': '+str(error)[:512])
    finally:
        for process in (worker,target):
            try:stop_owned(process)
            except Exception as error:report['errors'].append('process cleanup: '+str(error)[:512])
        try:
            if parent.exists():
                for node in parent.iterdir():
                    if node.is_dir():
                        require(node.name in ('churn','target') and not (node/'cgroup.procs').read_text().strip(),
                                'unknown or populated diagnostic leaf')
                        node.rmdir()
                parent.rmdir()
        except Exception as error:report['errors'].append('cgroup cleanup: '+str(error)[:512])
        report['cleanup']={'cgroup_parent_absent':not parent.exists(),
            'target_exited':target is None or target.poll() is not None,
            'worker_exited':worker is None or worker.poll() is not None}
        report['passed']=report['passed'] and not report['errors'] and all(report['cleanup'].values())
        report['raw_samples_sha256']=sha(output/'samples.jsonl') if (output/'samples.jsonl').exists() else None
        atomic_report(output/'report.json',report)
    return report


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--root',type=Path)
    parser.add_argument('--churn-parent',type=Path)
    parser.add_argument('--lock-fd',type=int)
    args=parser.parse_args()
    require((args.root is None)!=(args.churn_parent is None), 'provide exactly one diagnostic role')
    def interrupted(signum,frame):raise InterruptedError('diagnostic interrupted by signal '+str(signum))
    signal.signal(signal.SIGTERM,interrupted)
    if args.churn_parent is not None:
        require(args.lock_fd is not None, 'churn requires inherited validation lock')
        try:
            with validation_lock(args.lock_fd):result=churn(args.churn_parent)
        except Exception as error:result={'passed':False,'error':type(error).__name__+': '+str(error)[:512]}
    else:
        require(args.lock_fd is None, 'outer role must acquire its own lock')
        with validation_lock() as lock:result=measure(args.root,lock.fileno())
    print(json.dumps(result if args.churn_parent is not None else {
        k:result[k] for k in ('passed','errors','cleanup')}),flush=True)
    return 0 if result['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
