"""Payload/source binding tests. Real archive authentication is tested by the Go CLI."""
import copy
import datetime
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('candidate_gate',ROOT/'scripts/release_candidate_gate.py')
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)


class CandidateGateTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='osv-candidate-gate-');self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)
        for name in gate.SOURCE_ROOTS:
            path=self.root/name;path.mkdir(parents=True,exist_ok=True);(path/'source.txt').write_text(name)
        for name in gate.SOURCE_FILES:
            path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(name)
        (self.root/'go.mod').write_text('module fixture\n\ngo 1.24\n')
        (self.root/'docs/contracts').mkdir(parents=True)
        (self.root/'docs/contracts/warm-start-gates.json').write_text('{}')
        environment=patch.dict(os.environ,{},clear=False);environment.start();self.addCleanup(environment.stop)
        os.environ.pop('SOURCE_DATE_EPOCH',None)
        self.epoch=int(time.time())-60
        self.build=gate.build_identity(self.epoch,self.root)
        self.public=self.root/'candidate.public';self.public.write_text('unit verifier trust-anchor fixture')
        self.attestations={};self.payloads={}
        verification=patch.object(gate,'verify_archive',side_effect=self.verified_response)
        verification.start();self.addCleanup(verification.stop)
        self.startup=self.make_candidate('startup','amd64')

    def verified_response(self,path,public,arch,root):
        self.assertEqual(Path(public),self.public)
        value=copy.deepcopy(self.attestations[str(Path(path).resolve())])
        gate.require(value['manifest']['arch']==arch,'test verifier architecture mismatch')
        return value

    def make_candidate(self,name,arch,build=None,changes=None):
        build=copy.deepcopy(self.build if build is None else build)
        timestamp=datetime.datetime.fromtimestamp(build['epoch'],datetime.timezone.utc).isoformat().replace('+00:00','Z')
        payload={
            'docs/security-profile.json':json.dumps({'profile':'baseline','release_build':build}).encode(),
            'artifacts/manifest.json':json.dumps({'created_at':timestamp,'expires_at':'2099-01-01T00:00:00Z'}).encode(),
            'artifacts/manifest.json.sig':b'signature fixture',
            'sdk/node/index.js':b'one',
            'config/config.production.json.template':b'{}',
        }
        payload.update(changes or {})
        manifest={'format':1,'version':'same-version','commit':'a'*40,'arch':arch,'valid_until':'2099-01-01T00:00:00Z',
                  'files':[dict(path=k,size=len(v),mode=0o444,sha256=hashlib.sha256(v).hexdigest()) for k,v in sorted(payload.items())]}
        path=self.root/(name+'.tar')
        with tarfile.open(path,'w') as archive:
            for key,body in payload.items():
                member=tarfile.TarInfo(key);member.size=len(body);member.mode=0o444;archive.addfile(member,io.BytesIO(body))
        self.attestations[str(path.resolve())]=dict(manifest=manifest,archive_sha256=gate.file_hash(path),archive_bytes=path.stat().st_size)
        self.payloads[str(path)]=payload
        return path

    def plan(self,target=None,arch='amd64'):
        return gate.preflight(self.startup,target or self.startup,self.public,arch,self.root)

    def stage(self):
        stage=self.root/'stage'
        if stage.exists():shutil.rmtree(stage)
        stage.mkdir()
        for name,body in self.payloads[str(self.startup)].items():
            path=stage/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(body)
        return stage

    def test_same_payload_passes_and_canonical_readonly_modes_match(self):
        plan=self.plan();stage=self.stage()
        (stage/'sdk/node/index.js').chmod(0o444)
        self.assertEqual(gate.compare_stage(plan,stage,self.root),plan['target']['manifest'])

    def test_cross_architecture_same_source_is_linked_without_claiming_ARM_KVM(self):
        arm=self.make_candidate('arm','arm64')
        self.assertEqual(self.plan(arm,'arm64')['target']['manifest']['arch'],'arm64')

    def test_changed_runtime_byte_config_signature_and_metadata_are_rejected(self):
        plan=self.plan()
        for name in ('sdk/node/index.js','config/config.production.json.template','artifacts/manifest.json.sig','docs/security-profile.json'):
            with self.subTest(name=name):
                stage=self.stage();path=stage/name;body=path.read_bytes();path.write_bytes(bytes([body[0]^1])+body[1:])
                with self.assertRaisesRegex(ValueError,'payload differs'):gate.compare_stage(plan,stage,self.root)

    def test_extra_missing_linked_and_executable_mode_entries_are_rejected(self):
        plan=self.plan()
        for kind in ('extra','missing','link','mode'):
            with self.subTest(kind=kind):
                stage=self.stage();path=stage/'sdk/node/index.js'
                if kind=='extra':(stage/'extra').write_bytes(b'new')
                elif kind=='missing':path.unlink()
                elif kind=='link':path.unlink();path.symlink_to(self.public)
                else:path.chmod(0o755)
                with self.assertRaises(ValueError):gate.compare_stage(plan,stage,self.root)

    def test_source_changed_during_build_is_rejected(self):
        plan=self.plan();stage=self.stage();(self.root/'internal/source.txt').write_text('new runtime implementation')
        with self.assertRaisesRegex(ValueError,'current source or compiler differs'):gate.compare_stage(plan,stage,self.root)

    def test_reference_replacement_is_rejected(self):
        plan=self.plan();stage=self.stage()
        self.make_candidate('startup','amd64',changes={'sdk/node/index.js':b'two'})
        with self.assertRaisesRegex(ValueError,'reference candidate replaced'):gate.compare_stage(plan,stage,self.root)

    def test_key_or_policy_changes_are_rejected(self):
        plan=self.plan();stage=self.stage()
        self.public.write_text('changed key')
        with self.assertRaisesRegex(ValueError,'public key changed'):gate.compare_stage(plan,stage,self.root)
        self.public.write_text('unit verifier trust-anchor fixture')
        (self.root/'docs/contracts/warm-start-gates.json').write_text('{"new":"policy"}')
        with self.assertRaisesRegex(ValueError,'policy changed'):gate.compare_stage(plan,stage,self.root)

    def test_old_candidate_without_build_identity_is_rejected(self):
        old=self.make_candidate('old','amd64',changes={'docs/security-profile.json':b'{"profile":"baseline"}'})
        with self.assertRaisesRegex(ValueError,'missing.*build identity'):gate.inspect_candidate(old,self.public,'amd64',self.root)

    def test_cross_architecture_source_compiler_and_revision_mismatch_are_rejected(self):
        for field,value in (('source_inputs_sha256','b'*64),('go_version','go1.99.0')):
            with self.subTest(field=field):
                build=dict(self.build,**{field:value});arm=self.make_candidate('arm','arm64',build)
                with self.assertRaisesRegex(ValueError,'source or compiler identities'):self.plan(arm,'arm64')
        arm=self.make_candidate('arm','arm64')
        self.attestations[str(arm)]['manifest']['commit']='b'*40
        with self.assertRaisesRegex(ValueError,'versions or revisions'):self.plan(arm,'arm64')

    def test_explicit_epoch_change_is_rejected(self):
        os.environ['SOURCE_DATE_EPOCH']=str(self.epoch+1)
        with self.assertRaisesRegex(ValueError,'explicit build epoch differs'):self.plan()

    def test_expired_future_and_wrong_epoch_nested_artifacts_are_rejected(self):
        for created,expires in (('2000-01-01T00:00:00Z','2001-01-01T00:00:00Z'),('2098-01-01T00:00:00Z','2099-01-01T00:00:00Z'),('2000-01-01T00:00:00Z','2099-01-01T00:00:00Z')):
            path=self.make_candidate('old','amd64',changes={'artifacts/manifest.json':json.dumps(dict(created_at=created,expires_at=expires)).encode()})
            with self.assertRaises(ValueError):gate.inspect_candidate(path,self.public,'amd64',self.root)

    def test_metadata_is_rechecked_against_authenticated_file_hash(self):
        old=copy.deepcopy(self.attestations[str(self.startup)])
        self.make_candidate('startup','amd64',build=dict(self.build,source_inputs_sha256='b'*64))
        self.attestations[str(self.startup)]=old
        with self.assertRaisesRegex(ValueError,'metadata changed'):gate.inspect_candidate(self.startup,self.public,'amd64',self.root)

    def test_source_fingerprint_excludes_caches_but_includes_real_build_packages(self):
        before=gate.source_identity(self.root)
        cache=self.root/'scripts/__pycache__';cache.mkdir();(cache/'test.pyc').write_bytes(b'cache')
        (self.root/'README.md').write_text('status metadata only')
        self.assertEqual(gate.source_identity(self.root),before)
        package=self.root/'internal/build';package.mkdir();(package/'real.go').write_text('real source')
        self.assertNotEqual(gate.source_identity(self.root),before)

    def test_source_symlink_is_rejected(self):
        (self.root/'internal/alias.go').symlink_to(self.root/'cmd/source.txt')
        with self.assertRaisesRegex(ValueError,'linked build input'):gate.source_identity(self.root)


if __name__=='__main__':unittest.main()
