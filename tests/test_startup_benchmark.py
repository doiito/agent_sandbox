import copy
import errno
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('startup_benchmark', Path(__file__).resolve().parents[1]/'scripts/startup_benchmark.py')
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)
prepare_spec = importlib.util.spec_from_file_location('prepare_offline', Path(__file__).resolve().parents[1]/'scripts/prepare-offline-validation.py')
prepare = importlib.util.module_from_spec(prepare_spec)
prepare_spec.loader.exec_module(prepare)


class MeasurementTests(unittest.TestCase):
    def test_nearest_rank_percentiles_include_slow_successes(self):
        values = list(range(1, 1001))
        self.assertEqual(benchmark.percentiles(values), {'p50':500, 'p95':950, 'p99':990, 'max':1000})
        self.assertEqual(benchmark.percentiles([7]), dict.fromkeys(('p50','p95','p99','max'),7))
        self.assertEqual(benchmark.percentiles([]), dict.fromkeys(('p50','p95','p99','max')))
        for bad in ([True], [-1], [float('nan')], [float('inf')]):
            with self.assertRaises(ValueError):
                benchmark.percentiles(bad)

    def fixture(self):
        job, vm = '1'*24, '2'*24
        value = {'id':job,'backend':'firecracker-linux','state':'succeeded','exit_code':0,'protocol_ok':True,
            'startup_mode':'warm','startup_duration_us':6500,
            'guest_result':{'ok':True,'job_id':job,'exit_code':0,'stdout':'WARM_BENCH_OK'}}
        before = {vm:{'phase':'ready','pool_key':'a'*64,'pid':123,'start_time_ticks':4}}
        events = [{'event':'pool.claimed','job_id':job,'vm_id':vm,'profile_sha256':'a'*64,'startup_mode':'warm'}]
        return value,before,events

    @patch.object(benchmark, 'process_matches', return_value=False)
    def test_claim_requires_unused_observed_instance_and_bound_output(self, unused):
        value,before,events = self.fixture()
        used = set()
        result = benchmark.validate_job(value,'firecracker-linux','WARM_BENCH_OK',before,events,used)
        self.assertEqual(result['warm_start_ms'],6.5)
        self.assertEqual(used,{'2'*24})
        with self.assertRaises(ValueError):
            benchmark.validate_job(value,'firecracker-linux','WARM_BENCH_OK',before,events,used)
        for changes in ({'startup_mode':'cold'},{'startup_duration_us':True},{'startup_duration_us':0},
                        {'state':'guest_error'},{'protocol_ok':False},{'guest_result':dict(value['guest_result'],job_id='3'*24)}):
            bad = copy.deepcopy(value);bad.update(changes)
            with self.assertRaises(ValueError):
                benchmark.validate_job(bad,'firecracker-linux','WARM_BENCH_OK',before,events,set())
        for invalid_events in ([],events+events,[dict(events[0],vm_id='4'*24)], [dict(events[0],profile_sha256='b'*64)]):
            with self.assertRaises(ValueError):
                benchmark.validate_job(value,'firecracker-linux','WARM_BENCH_OK',before,invalid_events,set())

    @patch.object(benchmark, 'process_matches', return_value=True)
    def test_live_used_vm_is_failure(self, unused):
        value,before,events = self.fixture()
        with self.assertRaisesRegex(ValueError,'still live'):
            benchmark.validate_job(value,'firecracker-linux','WARM_BENCH_OK',before,events,set())

    def test_cold_requires_separate_boot_measurement_and_same_job_creation(self):
        value, _, (claim,) = self.fixture()
        value.update(startup_mode='cold', vm_boot_duration_us=5000)
        claim['startup_mode'] = 'cold'
        created = dict(claim, event='pool.created', code='profile_mismatch')
        result = benchmark.validate_job(value, 'firecracker-linux', 'WARM_BENCH_OK', {}, [created, claim], set(), mode='cold')
        self.assertEqual(result['cold_boot_ms'], 5)
        self.assertEqual(result['cold_admission_ms'], 6.5)
        for events in ([claim], [claim, created], [created, created, claim], [dict(created, code='empty'), claim],
                       [dict(created, vm_id='3'*24), claim]):
            with self.assertRaises(ValueError):
                benchmark.validate_job(value, 'firecracker-linux', 'WARM_BENCH_OK', {}, events, set(), mode='cold')
        for before, bad in (({}, dict(value, vm_boot_duration_us=None)), ({claim['vm_id']: {}}, value)):
            with self.assertRaises(ValueError):
                benchmark.validate_job(bad, 'firecracker-linux', 'WARM_BENCH_OK', before, [created, claim], set(), mode='cold')

    def test_pre_request_snapshot_skips_only_confirmed_retired_generation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            name, vm = 'job-' + '1'*24, '2'*24
            job = root / name
            job.mkdir()
            lease = {'pid': 123, 'start_time_ticks': 4, 'phase': 'ready', 'instance_id': name,
                     'vm_id': vm, 'pool_key': 'a'*64}
            (job / 'lease.json').write_text(json.dumps(lease))
            config = {'run_root': str(root), 'jailer': {'uid': 230000, 'identity_pool_size': 3,
                      'parent_cgroup': 'fixture'}, 'vm_capacity': {'max_instances': 3}}
            original_read = Path.read_text

            def read(path, *args, **kwargs):
                if str(path).startswith('/proc/123/'):
                    return {'status': 'Uid:\t230000 230000 230000 230000\nGid:\t230000 230000 230000 230000\n'
                                      'Seccomp:\t2\nCapEff:\t0000000000000000\nTracerPid:\t0\n'
                                      'Cpus_allowed_list:\t0-47\nMems_allowed_list:\t0-1\n',
                            'comm': 'firecracker\n', 'cgroup': '0::/fixture/' + name + '\n'}[path.name]
                return original_read(path, *args, **kwargs)

            for retired in (True, False):
                def exiting_read(path, *args, **kwargs):
                    if path.name == 'cgroup' and str(path).startswith('/proc/123/'):
                        return '0::/\n'
                    return read(path, *args, **kwargs)

                with patch.object(Path, 'read_text', exiting_read), patch.object(benchmark, 'process_matches', side_effect=[True, False]), \
                     patch.object(benchmark, 'process_retired', return_value=retired), patch.object(benchmark, 'live_cpu_snapshot') as cpu:
                    if retired:
                        self.assertEqual(benchmark.owned_leases(config), {})
                    else:
                        with self.assertRaisesRegex(ValueError, 'without confirmed retirement'):
                            benchmark.owned_leases(config)
                    cpu.assert_not_called()

    def test_audit_partial_tail_retains_complete_claim(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'audit.jsonl';path.write_text('{}\n')
            reader=benchmark.AuditTail(path)
            with path.open('ab') as writer:writer.write(b'{"event":"pool.');writer.flush()
            self.assertEqual(reader.read(),[])
            with path.open('ab') as writer:writer.write(b'claimed"}\n');writer.flush()
            self.assertEqual(reader.read(),[{'event':'pool.claimed'}])
            reader.close()

    def test_phase_partition_and_cold_boot_are_separate(self):
        timing={'schema':'osv-startup-timing/v1', 'total_us':21,
                **dict(zip(benchmark.PHASE_FIELDS,range(7)))}
        value={'startup_duration_us':21,'startup_mode':'warm','startup_timing':timing}
        self.assertEqual(benchmark.validate_startup_measurements(value,required=True),timing)
        current=dict(timing,schema='osv-startup-timing/v2')
        self.assertEqual(benchmark.validate_startup_measurements(dict(value,startup_timing=current),required=True),current)
        for bad in (dict(timing,total_us=20),dict(timing,readiness_us=True),dict(timing,audit_us=-1),
                    dict(timing,finalize_us=7),dict(timing,schema='other')):
            with self.assertRaises(ValueError):
                benchmark.validate_startup_measurements(dict(value,startup_timing=bad))
        with self.assertRaises(ValueError):
            benchmark.validate_startup_measurements({'startup_duration_us':21},required=True)
        for mode,boot in [('warm',1),('cold',0),('cold',True),('cold',22)]:
            with self.assertRaises(ValueError):
                benchmark.validate_startup_measurements(dict(value,startup_mode=mode,vm_boot_duration_us=boot))
        benchmark.validate_startup_measurements(dict(value,startup_mode='cold',vm_boot_duration_us=15),required=True)

    def test_cpu_period_override_preserves_one_cpu_share(self):
        self.assertEqual(prepare.cpu_period_settings(None),{})
        for value in (1000,10000,100000,1000000):
            settings=prepare.cpu_period_settings(value)
            self.assertEqual(settings,{'cpu_period_us':value,'cpu_quota_per_vcpu_us':value})
        for value in (999,1000001,True,1.5):
            with self.assertRaises(ValueError):prepare.cpu_period_settings(value)

    def test_cpu_statistics_and_sampled_window_are_honest(self):
        text='usage_usec 10\nnr_periods 2\nnr_throttled 1\nthrottled_usec 5\n'
        stats=benchmark.parse_cpu_stat(text)
        for bad in (text+'usage_usec 11\n',text.replace(' 10',' -1'),text.replace(' 10',' 1.2'),'usage_usec 1\n'):
            with self.assertRaises(ValueError):benchmark.parse_cpu_stat(bad)
        before={'started_monotonic_ns':10,'monotonic_ns':20,'limit':'10000 10000','stat':stats}
        after={'started_monotonic_ns':21,'monotonic_ns':30,'limit':'10000 10000',
               'stat':dict(stats,usage_usec=15,nr_throttled=2,throttled_usec=9)}
        self.assertEqual(benchmark.cpu_window(None,[after]),{'coverage':'missing-before'})
        self.assertEqual(benchmark.cpu_window(before,[]),{'coverage':'missing-live-after'})
        # A read that started before the baseline is not fresh even if it ended later.
        overlap=dict(after,started_monotonic_ns=19)
        self.assertEqual(benchmark.cpu_window(before,[overlap]),{'coverage':'missing-live-after'})
        self.assertEqual(benchmark.cpu_window(before,[after])['delta'],
                         {'usage_usec':5,'nr_periods':0,'nr_throttled':1,'throttled_usec':4})
        for bad in (dict(after,limit='100000 100000'),dict(after,stat=dict(stats,usage_usec=9))):
            with self.assertRaises(ValueError):benchmark.cpu_window(before,[bad])

    def test_cpu_sample_cache_is_bounded_and_returns_copies(self):
        history=benchmark.CPUHistory(max_vms=2,max_samples=3)
        for index in range(8):history.add('a',{'monotonic_ns':index,'stat':{'usage_usec':index}})
        self.assertEqual([x['monotonic_ns'] for x in history.get('a')],[5,6,7])
        copy=history.get('a');copy[0]['stat']['usage_usec']=999
        self.assertEqual(history.get('a')[0]['stat']['usage_usec'],5)
        history.add('b',{'stat':{}});history.add('c',{'stat':{}})
        self.assertEqual(history.get('a'),[])
        self.assertEqual(len(history.samples),2)

    def test_offline_cpu_read_requires_proven_retired_process(self):
        lease={'pid':123,'start_time_ticks':4}
        for retired in (False,True):
            with patch.object(benchmark,'process_retired',return_value=retired), \
                 patch.object(benchmark,'cpu_snapshot',side_effect=OSError(errno.ENODEV,'No such device')):
                if retired:
                    self.assertIsNone(benchmark.live_cpu_snapshot(Path('/unused'),lease))
                else:
                    with self.assertRaises(OSError):benchmark.live_cpu_snapshot(Path('/unused'),lease)
        with patch.object(benchmark,'process_retired',return_value=True), \
             patch.object(benchmark,'cpu_snapshot',side_effect=OSError(errno.EIO,'I/O error')):
            with self.assertRaises(OSError):benchmark.live_cpu_snapshot(Path('/unused'),lease)
        with patch.object(Path,'read_text',side_effect=PermissionError(errno.EACCES,'denied')):
            with self.assertRaises(PermissionError):benchmark.process_retired(lease)
        with patch.object(Path,'read_text',side_effect=FileNotFoundError()):
            self.assertTrue(benchmark.process_retired(lease))
        for state,ticks,retired in [('S',4,False),('Z',4,True),('X',4,True),('S',5,True)]:
            stat='123 (name with spaces) '+state+' '+' '.join(['0']*18+[str(ticks)])
            with patch.object(Path,'read_text',return_value=stat):
                self.assertEqual(benchmark.process_retired(lease),retired)

    def test_observation_error_preserves_errno_stage_and_vm(self):
        error=OSError(errno.EIO,'read failed','/sys/fs/cgroup/test/cpu.stat')
        result=benchmark.observation_error(error,'cpu-read',Path('/sys/fs/cgroup/test'),'a'*24)
        self.assertEqual(result['type'],'OSError');self.assertEqual(result['errno'],errno.EIO)
        self.assertEqual(result['stage'],'cpu-read');self.assertEqual(result['vm_id'],'a'*24)
        self.assertIn('cpu.stat',result['message']);self.assertGreater(result['utc_ns'],0)

    def test_observer_counts_retired_skip_and_preserves_unexpected_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);job=root/('job-'+'a'*24);job.mkdir()
            (job/'lease.json').write_text(json.dumps({'vm_id':'b'*24,'pid':os.getpid(),'start_time_ticks':1,'phase':'ready'}))
            config={'run_root':str(root),'jailer':{'parent_cgroup':'test'}}
            for effect in (None,OSError(errno.EIO,'I/O error')):
                observer=benchmark.RSSObserver(config)
                with patch.object(observer.stop,'wait',side_effect=[False,True]), \
                     patch.object(benchmark,'process_matches',return_value=True), \
                     patch.object(benchmark,'live_cpu_snapshot',side_effect=effect if effect else None,return_value=None):
                    observer.observe()
                self.assertEqual(observer.retired_cpu_reads,0 if effect else 1)
                self.assertEqual(observer.cpu.get('b'*24),[])
                if effect:
                    self.assertEqual(len(observer.errors),1)
                    self.assertEqual(observer.errors[0]['errno'],errno.EIO)
                    self.assertEqual(observer.errors[0]['stage'],'cpu-read')
                    self.assertEqual(observer.errors[0]['vm_id'],'b'*24)
                else:
                    self.assertEqual(observer.errors,[])

    def test_missing_controller_counters_require_retired_generation_and_booting_is_not_sampled(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'cpu.max').write_text('100000 100000\n');(root/'cpu.stat').write_text('')
            for retired in (False,True):
                with patch.object(benchmark,'process_retired',return_value=retired):
                    if retired:self.assertIsNone(benchmark.live_cpu_snapshot(root,{}))
                    else:
                        with self.assertRaises(benchmark.CPUControllerUnavailable):benchmark.live_cpu_snapshot(root,{})
            (root/'cpu.stat').write_text('usage_usec -1\n')
            with patch.object(benchmark,'process_retired',return_value=True):
                with self.assertRaises(ValueError):benchmark.live_cpu_snapshot(root,{})
            job=root/'job-booting';job.mkdir()
            (job/'lease.json').write_text(json.dumps({'vm_id':'b'*24,'pid':os.getpid(),'start_time_ticks':1,'phase':'booting'}))
            observer=benchmark.RSSObserver({'run_root':str(root),'jailer':{'parent_cgroup':'test'}})
            with patch.object(observer.stop,'wait',side_effect=[False,True]), \
                 patch.object(benchmark,'process_matches',return_value=True),patch.object(benchmark,'live_cpu_snapshot') as snapshot:
                observer.observe()
            snapshot.assert_not_called();self.assertEqual(observer.errors,[]);self.assertGreater(observer.peak,0)

    def test_inherited_validation_lock_preserves_parent_and_rejects_wrong_fd(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'validation.lock'
            with path.open('a') as parent:
                fcntl.flock(parent,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with benchmark.validation_lock(parent.fileno(),path):
                    with path.open('a') as competing:
                        with self.assertRaises(BlockingIOError):fcntl.flock(competing,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with path.open('a') as competing:
                    with self.assertRaises(BlockingIOError):fcntl.flock(competing,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with benchmark.validation_lock(path=path):pass
            with (Path(temporary)/'other').open('a') as other:
                with self.assertRaisesRegex(ValueError,'wrong file'):benchmark.validation_lock(other.fileno(),path)

    def test_diagnostic_cannot_hide_failure_or_claim_minimum_samples(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for name in ('config.json','vmm','jailer','manifest.json','sbom.json','audit.jsonl',
                         'osv-sandboxd','osv-sandbox-launcher','kernel','image'):
                (root/name).write_text('{}\n')
            config={'run_root':str(root/'run'),'backend':'firecracker-linux','hypervisor_path':str(root/'vmm'),
                    'artifact_root':str(root),'audit_log_path':str(root/'audit.jsonl'),
                    'artifact_manifest':{'path':'manifest.json','sbom_path':'sbom.json'},
                    'kernel':{'path':'kernel'},'image':{'path':'image'},
                    'jailer':{'path':str(root/'jailer')}}
            calls=[]
            def request(path,body=None):
                calls.append(path)
                if path=='/v1/capabilities':
                    return 200,{'backend':'firecracker-linux','stage':'diagnostic','features':{'warm_pool':True},'artifact_manifest_sha256':'a'*64}
                if path=='/v1/doctor':
                    return 503,{'ready':False,'warm_pool':{'healthy':True,'memory_pressure':False,'foreground':0,
                        'profiles':[{'name':'small','key':'a'*64}]},'vm_capacity':{'active':0}}
                return 429,{'code':'busy'}
            before={'2'*24:{'phase':'ready','pool_key':'a'*64,
                            'cpu_snapshot':{'monotonic_ns':1,'limit':'100000 100000','stat':{}}}}
            with patch.object(benchmark,'owned_leases',return_value=before):
                report=benchmark.measure(request,config,root/'output',samples=1000,warmup=0,diagnostic=True)
            self.assertFalse(report['passed']);self.assertFalse(report['release_eligible'])
            self.assertFalse(report['minimum_samples_met']);self.assertEqual(report['failures'],1)
            self.assertEqual(report['rejections'],1);self.assertEqual(calls.count('/v2/jobs'),1)
            raw=[json.loads(line) for line in (root/'output/samples.jsonl').read_text().splitlines()]
            self.assertEqual(len(raw),1);self.assertEqual(raw[0]['http_status'],429)
            self.assertFalse(raw[0]['success'])
            # Without the diagnostic flag the same endpoint must reject before execution.
            calls.clear()
            report=benchmark.measure(request,config,root/'strict',samples=1000,warmup=0)
            self.assertFalse(report['passed']);self.assertIn('doctor is not ready',report['error'])
            self.assertNotIn('/v2/jobs',calls)
            calls.clear()
            with patch.object(benchmark,'owned_leases',return_value=before):
                report=benchmark.measure(request,config,root/'warmupfail',samples=1000,warmup=5,diagnostic=True)
            self.assertFalse(report['passed']);self.assertEqual(report['warmup_failures'],1)
            self.assertEqual(report['attempted'],0);self.assertEqual(calls.count('/v2/jobs'),1)
            # Failure in telemetry after a valid execution must not retain the
            # success flag from validate_job and falsely pass the batch.
            calls.clear()
            value,_,events=self.fixture()
            def successful_request(path,body=None):
                if path=='/v2/jobs':
                    calls.append(path)
                    return 200,value
                return request(path,body)
            with patch.object(benchmark,'owned_leases',return_value=before), \
                 patch.object(benchmark,'process_matches',return_value=False), \
                 patch.object(benchmark.AuditTail,'read',side_effect=[[],events]), \
                 patch.object(benchmark,'cpu_window',side_effect=ValueError('counter reversal')):
                report=benchmark.measure(successful_request,config,root/'telemetryfail',samples=1000,warmup=0,diagnostic=True)
            self.assertFalse(report['passed']);self.assertEqual(report['failures'],1)
            self.assertEqual(report['successes'],0);self.assertEqual(calls.count('/v2/jobs'),1)


if __name__=='__main__':
    unittest.main()
