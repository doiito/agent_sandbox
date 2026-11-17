import importlib.util
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
spec=importlib.util.spec_from_file_location('vsock_timing',Path(__file__).resolve().parents[1]/'scripts/probe-linux-vsock-timing.py')
probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)
prepare_spec=importlib.util.spec_from_file_location('prepare_probe',Path(__file__).resolve().parents[1]/'scripts/prepare-offline-validation.py')
prepare=importlib.util.module_from_spec(prepare_spec);prepare_spec.loader.exec_module(prepare)


class ProbeTests(unittest.TestCase):
    def reply(self,job='a'*24,**changes):
        value={'protocol':'fc-agent/v3','job_id':job,'ok':True,'exit_code':0,'guest_state':'pristine',
               'pristine_revision':2,'remaining_lifetime_ms':500000,'binding':None}
        value.update(changes)
        return b'FC_AGENT_RESULT '+json.dumps(value).encode()+b'\n'

    def test_bound_pristine_reply_and_negative_frames(self):
        probe.validate_reply(self.reply(),'a'*24)
        for change in ({'protocol':'fc-agent/v2'},{'job_id':'b'*24},{'ok':False},{'exit_code':False},
                       {'exit_code':1},{'guest_state':'prepared'},{'pristine_revision':1},{'pristine_revision':2.0},
                       {'remaining_lifetime_ms':True},{'remaining_lifetime_ms':0},{'remaining_lifetime_ms':600001},
                       {'binding':{'session_id':'b'*24}}):
            with self.assertRaises(ValueError):probe.validate_reply(self.reply(**change),'a'*24)
        for bad in (self.reply()[:-1],b'bad\n',b'FC_AGENT_RESULT []\n',b'FC_AGENT_RESULT '+b' '*16384+b'\n'):
            with self.assertRaises(ValueError):probe.validate_reply(bad,'a'*24)

    def test_health_override_and_pre_health_deadline(self):
        self.assertEqual(prepare.health_interval_settings(None,False),{})
        for value in (100,1000,30000):self.assertEqual(prepare.health_interval_settings(value,True),{'health_interval_ms':value})
        for value in (99,30001,True,1.5):
            with self.assertRaises(ValueError):prepare.health_interval_settings(value,True)
        with self.assertRaises(ValueError):prepare.health_interval_settings(30000,False)
        config={'warm_pool':{'health_interval_ms':30000}}
        with patch.object(probe.time,'monotonic_ns',return_value=100):
            self.assertEqual(probe.diagnostic_deadline({'prepare_started_monotonic_ns':10},config),25000000010)
            for value in (0,-1,True,101):
                with self.assertRaises(ValueError):probe.diagnostic_deadline({'prepare_started_monotonic_ns':value},config)
            with self.assertRaises(ValueError):probe.diagnostic_deadline({'prepare_started_monotonic_ns':10},{'warm_pool':{'health_interval_ms':1000}})
            with self.assertRaisesRegex(ValueError,'exhausted'):probe.remaining(100)
            self.assertEqual(probe.remaining(2000000100),1.0)

    def test_socket_partition_and_invalid_connect_have_no_retry(self):
        for ack in (b'OK 1025\n',b'OK 0\n',b'OK 4294967296\n',b'NOPE\n'):
            with tempfile.TemporaryDirectory() as temporary:
                path=Path(temporary)/'vsock'
                errors=[];connections=[]
                with socket.socket(socket.AF_UNIX) as server:
                    server.bind(str(path));server.listen(1);server.settimeout(2)
                    def serve():
                        try:
                            with server.accept()[0] as connection:
                                connections.append(1)
                                connection.settimeout(2)
                                with connection.makefile('rb') as reader:
                                    self.assertEqual(reader.readline(128),b'CONNECT 5000\n')
                                    connection.sendall(ack)
                                    if ack==b'OK 1025\n':
                                        value=json.loads(reader.readline(16384))
                                        self.assertEqual(value,{'protocol':'fc-agent/v3','job_id':'a'*24,'operation':'ping'})
                                        connection.sendall(self.reply())
                        except Exception as error:errors.append(error)
                    thread=threading.Thread(target=serve);thread.start()
                    try:
                        if ack==b'OK 1025\n':
                            result=probe.ping(path,5000,'a'*24,time.monotonic_ns()+1_000_000_000)
                            self.assertEqual(sum(result[key] for key in probe.FIELDS[:-1]),result['total_us'])
                            self.assertTrue(all(type(value) is int and value>=0 for value in result.values()))
                        else:
                            with self.assertRaisesRegex(ValueError,'acknowledgement'):
                                probe.ping(path,5000,'a'*24,time.monotonic_ns()+1_000_000_000)
                    finally:thread.join(3)
                    self.assertFalse(thread.is_alive());self.assertEqual(errors,[]);self.assertEqual(len(connections),1)

    def test_generation_change_or_missing_ready_is_fatal(self):
        lease={'phase':'ready','pid':123,'start_time_ticks':7,'instance_id':'job-a','vm_id':'a','pool_key':'b','uid':230000}
        for observed in ({},dict(lease,phase='active'),dict(lease,start_time_ticks=8),dict(lease,pid=124)):
            with patch.object(probe,'owned_leases',return_value={'a':observed}):
                with self.assertRaises(ValueError):probe.same_ready({}, {'a':lease})

    def test_expired_window_records_failure_without_contacting_guest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'results').mkdir()
            (root/'config.production.json').write_text('{}');(root/'package').write_text('test');(root/'audit').write_text('')
            config={'warm_pool':{'health_interval_ms':30000},'audit_log_path':str(root/'audit')}
            with patch.object(probe,'owned_leases') as observe:
                report=probe.measure(root,config,root/'package',{'prepare_started_monotonic_ns':time.monotonic_ns()-26_000_000_000})
            self.assertFalse(report['passed']);self.assertFalse(report['release_eligible'])
            self.assertIn('exhausted',report['error']);self.assertEqual(report['attempts'],[]);observe.assert_not_called()
            self.assertTrue((root/'results/vsock-timing/report.json').exists())

    def test_unknown_result_or_post_ping_observation_error_stops_and_is_retained(self):
        for post_ping in (False,True):
            with tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);(root/'results').mkdir()
                (root/'config.production.json').write_text('{}');(root/'package').write_text('test');(root/'audit').write_text('')
                config={'warm_pool':{'health_interval_ms':30000},'audit_log_path':str(root/'audit'),
                        'run_root':str(root/'run'),'linux_guest':{'vsock_port':5000}}
                lease={'instance_id':'job-a','phase':'ready','cpu_snapshot':{'limit':'100000 100000',
                    'stat':dict.fromkeys(('usage_usec','nr_periods','nr_throttled','throttled_usec'),0)}}
                ready={'a':lease,'b':dict(lease,instance_id='job-b')}
                with patch.object(probe,'owned_leases',return_value=ready), \
                     patch.object(probe,'same_ready',side_effect=[ready,OSError('CPU read failed')]), \
                     patch.object(probe,'ping',return_value=dict.fromkeys(probe.FIELDS,0),
                                  side_effect=None if post_ping else ValueError('unknown result')) as ping:
                    report=probe.measure(root,config,root/'package',{'prepare_started_monotonic_ns':time.monotonic_ns()})
                self.assertFalse(report['passed']);self.assertEqual(report['failures'],1)
                self.assertEqual(report['successes'],0);self.assertEqual(ping.call_count,1)
                self.assertEqual(len(report['attempts']),1);self.assertFalse(report['attempts'][0]['success'])
                rows=[json.loads(line) for line in (root/'results/vsock-timing/samples.jsonl').read_text().splitlines()]
                self.assertEqual(rows,report['attempts']);self.assertIn('error',rows[0])


if __name__=='__main__':unittest.main()
