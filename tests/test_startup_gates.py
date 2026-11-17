"""Policy checks use synthetic temporary evidence, never production gate data."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('startup_gate_policy',ROOT/'scripts/check-startup-gates.py')
gate=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class StartupGatePolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='osv-startup-gate-unit-')
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.contract=copy.deepcopy(json.loads((ROOT/'docs/contracts/warm-start-gates.json').read_text()))
        self.contract['evidence']=[]
        (self.root/'docs/contracts').mkdir(parents=True)
        (self.root/'results').mkdir()
        (self.root/'dist').mkdir()
        candidate=self.root/'dist/unit-fixture.tar'
        candidate.write_bytes(b'isolated unit fixture; not a real release')
        self.candidate_sha=hashlib.sha256(candidate.read_bytes()).hexdigest()

    def evidence(self,warm=None,*,count=1000,doctor=True,missing_case=False,cold=300):
        self.contract['evidence']=[]
        for backend,_ in self.contract['required_backend_arch']:
            for mode in ('warm','cold'):
                name=backend+'-'+mode
                metric='warm_start_ms' if mode=='warm' else 'cold_boot_ms'
                values=warm if mode=='warm' and warm is not None else [4.8 if mode=='warm' else cold]*count
                samples=[{'success':True,metric:value} for value in values]
                sample_path=self.root/'results'/(name+'-samples.json')
                sample_path.write_text(json.dumps(samples))
                cases={case:True for case in self.contract['required_cases']}
                if missing_case:cases.pop('exclusive_owner')
                report={'unit_fixture':True,'backend':backend,'arch':'amd64','startup_mode':mode,
                    'environment':'real-kvm','unqueued':True,'production_doctor_ready':doctor,
                    'candidate_archive':'dist/unit-fixture.tar','candidate_sha256':self.candidate_sha,
                    'host_baseline_sha256':'a'*64,'configuration_sha256':'b'*64,'test_sha256':'c'*64,
                    'cases':cases,'samples_path':str(sample_path.relative_to(self.root)),
                    'samples_sha256':hashlib.sha256(sample_path.read_bytes()).hexdigest(),
                    'peak_rss_bytes':1024,'reserved_memory_bytes':4096,'hit_rate':1.0,'refill_p95_ms':1,
                    'throughput_per_second':1,'failures':0,'timeouts':0,'rejections':0}
                path=self.root/'results'/(name+'-report.json')
                path.write_text(json.dumps(report))
                self.contract['evidence'].append({'path':str(path.relative_to(self.root)),
                    'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})

    def audit(self,candidate=None):
        (self.root/'docs/contracts/warm-start-gates.json').write_text(json.dumps(self.contract))
        argv=['gate','--require-target']
        if candidate is not None:argv+=['--candidate',str(candidate)]
        with patch.object(gate,'ROOT',self.root),patch.object(sys,'argv',argv):
            with contextlib.redirect_stdout(io.StringIO()):return gate.main()

    def test_user_revised_p99_fifteen_boundary(self):
        self.evidence(warm=[4.0]*980+[15.0]*20)
        self.assertEqual(self.audit(),0)
        self.evidence(warm=[4.0]*980+[15.001]*20)
        with self.assertRaisesRegex(ValueError,'percentile exceeded'):self.audit()

    def test_warm_four_point_eight_is_accepted(self):
        self.evidence()
        self.assertEqual(self.audit(),0)

    def test_exact_five_nine_fifteen_boundaries_are_accepted(self):
        self.evidence(warm=[5]*500+[9]*450+[15]*50)
        self.assertEqual(self.audit(),0)

    def test_values_between_old_and_new_tail_limits_are_accepted(self):
        self.evidence(warm=[4.8]*500+[8.5]*450+[14.9]*50)
        self.assertEqual(self.audit(),0)

    def test_warm_median_over_five_is_rejected(self):
        self.evidence(warm=[5.001]*1000)
        with self.assertRaisesRegex(ValueError,'percentile exceeded'):self.audit()

    def test_warm_p95_over_nine_is_rejected(self):
        self.evidence(warm=[4.8]*949+[9.001]*51)
        with self.assertRaisesRegex(ValueError,'percentile exceeded'):self.audit()

    def test_warm_p99_over_fifteen_is_rejected(self):
        self.evidence(warm=[4.8]*989+[15.001]*11)
        with self.assertRaisesRegex(ValueError,'percentile exceeded'):self.audit()

    def test_short_batches_are_still_rejected(self):
        self.evidence(count=999)
        with self.assertRaisesRegex(ValueError,'insufficient or failed samples'):self.audit()

    def test_unready_host_is_still_rejected(self):
        self.evidence(doctor=False)
        with self.assertRaisesRegex(ValueError,'diagnostic or queued evidence'):self.audit()

    def test_cold_median_limit_remains_four_hundred(self):
        self.evidence(cold=400.001)
        with self.assertRaisesRegex(ValueError,'percentile exceeded'):self.audit()

    def test_missing_isolation_case_is_still_rejected(self):
        self.evidence(missing_case=True)
        with self.assertRaisesRegex(ValueError,'startup safety case missing'):self.audit()

    def test_no_evidence_stays_unmet(self):
        self.assertEqual(self.audit(),1)

    def test_explicit_candidate_accepts_only_its_own_evidence(self):
        self.evidence()
        self.assertEqual(self.audit(self.root/'dist/unit-fixture.tar'),0)
        newer=self.root/'dist/new-candidate.tar';newer.write_bytes(b'changed runtime payload')
        with self.assertRaisesRegex(ValueError,'another candidate'):self.audit(newer)

    def test_historical_audit_rejects_mixed_candidate_routes(self):
        self.evidence()
        other=self.root/'dist/other.tar';other.write_bytes(b'another measured candidate')
        record=self.contract['evidence'][1];path=self.root/record['path'];report=json.loads(path.read_text())
        report.update(candidate_archive='dist/other.tar',candidate_sha256=hashlib.sha256(other.read_bytes()).hexdigest())
        path.write_text(json.dumps(report));record['sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError,'mix different candidates'):self.audit()


if __name__=='__main__':unittest.main()
