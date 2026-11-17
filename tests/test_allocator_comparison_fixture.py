import base64
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import allocator_comparison_fixture as fixture


class AllocatorReferenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source, self.install, self.validation = [self.root / name for name in ('source', 'install', 'validation')]
        for path in (self.source, self.install, self.validation / 'results'):
            path.mkdir(parents=True)
        for name, data in {'kernel': b'kernel', 'rootfs.ext4': b'rootfs', 'agent-init': b'agent',
                           'sbom.cdx.json': b'{}', 'artifact.public': base64.b64encode(b'k' * 32),
                           'manifest.json.sig': base64.b64encode(b's' * 64)}.items():
            (self.source / name).write_bytes(data)
        manifest = {'protocol': 'osv-sandbox-artifacts/v6', 'backend': 'firecracker-linux',
                    'agent_features': ['port-forward-v1'], 'kernel': {'path': 'kernel', 'sha256': fixture.sha(self.source / 'kernel')},
                    'image': {'path': 'rootfs.ext4', 'sha256': fixture.sha(self.source / 'rootfs.ext4'), 'format': 'raw'},
                    'kernel_size': 6, 'image_size': 6, 'sbom_size': 2,
                    'sbom_sha256': fixture.sha(self.source / 'sbom.cdx.json'),
                    'firecracker_sha256': 'a' * 64, 'jailer_sha256': 'b' * 64}
        (self.source / 'manifest.json').write_text(json.dumps(manifest))
        (self.install / 'manifest.json').write_text(json.dumps(manifest))
        (self.source / 'comparison-provenance.json').write_text(json.dumps({
            'allocator': 'system', 'agent_sha256': fixture.sha(self.source / 'agent-init')}))
        self.reference = {'protocol': 'osv-allocator-api-reference/v1', 'diagnostic': True, 'release_eligible': False,
                          'allocator': 'system', 'agent_sha256': fixture.sha(self.source / 'agent-init'),
                          'base_package_sha256': 'c' * 64}
        self.refresh()
        self.config = {'backend': 'firecracker-linux', 'artifact_root': str(self.install),
                       'artifact_manifest': {'path': 'manifest.json'}, 'kernel': manifest['kernel'], 'image': manifest['image']}

    def refresh(self):
        names = fixture.FILES | {'osv-workload-supervisor'} if self.reference['protocol'].endswith(('/v2','/v3')) else fixture.FILES
        self.reference['files'] = {name: fixture.sha(self.source / name) for name in names}
        (self.source / 'reference.json').write_text(json.dumps(self.reference))

    def reject(self):
        before = copy.deepcopy(self.config)
        with self.assertRaises(ValueError):
            fixture.prepare(self.source, self.validation, self.config)
        self.assertEqual(self.config, before)
        self.assertFalse((self.validation / 'allocator-reference').exists())

    def test_selects_bound_diagnostic_variant(self):
        receipt = fixture.prepare(self.source, self.validation, self.config)
        self.assertEqual(receipt['allocator'], 'system')
        self.assertIs(receipt['release_eligible'], False)
        self.assertEqual(Path(self.config['artifact_root']), self.validation / 'allocator-reference')
        for name, digest in self.reference['files'].items():
            path = Path(self.config['artifact_root']) / name
            self.assertEqual(fixture.sha(path), digest)
            self.assertEqual(path.stat().st_mode & 0o777, 0o444)

    def supervisor_reference(self, variant='standalone'):
        (self.source / 'osv-workload-supervisor').write_bytes(b'static system supervisor')
        self.reference.update(protocol='osv-allocator-api-reference/v2', allocator='mimalloc',
            comparison='workload-supervisor-layout', variant=variant, mimalloc_secure_level=4,
            supervisor_allocator='mimalloc' if variant == 'combined' else 'system',
            supervisor_path='/sbin/agent-init' if variant == 'combined' else '/sbin/osv-workload-supervisor',
            helper_sha256=fixture.sha(self.source / 'osv-workload-supervisor'))
        fields = ('allocator', 'agent_sha256', 'comparison', 'variant', 'mimalloc_secure_level',
                  'supervisor_allocator', 'supervisor_path', 'helper_sha256')
        (self.source / 'comparison-provenance.json').write_text(json.dumps({key: self.reference[key] for key in fields}))
        self.refresh()

    def test_selects_standalone_with_actual_pid1_allocator(self):
        self.supervisor_reference()
        receipt = fixture.prepare(self.source, self.validation, self.config)
        self.assertEqual(receipt['allocator'], 'mimalloc')
        self.assertEqual(receipt['supervisor_allocator'], 'system')
        self.assertEqual(receipt['variant'], 'standalone')
        helper = self.validation / 'allocator-reference/osv-workload-supervisor'
        self.assertEqual(fixture.sha(helper), self.reference['helper_sha256'])
        self.assertEqual(helper.stat().st_mode & 0o777, 0o444)

    def test_selects_combined_route_without_mislabeling_pid1(self):
        self.supervisor_reference('combined')
        receipt = fixture.prepare(self.source, self.validation, self.config)
        self.assertEqual(receipt['allocator'], 'mimalloc')
        self.assertEqual(receipt['supervisor_allocator'], 'mimalloc')
        self.assertEqual(receipt['supervisor_path'], '/sbin/agent-init')

    def test_rejects_supervisor_variant_and_path_mismatch(self):
        self.supervisor_reference()
        for key, value in (('variant', 'unknown'), ('supervisor_allocator', 'mimalloc'),
                           ('supervisor_path', '/sbin/agent-init'), ('mimalloc_secure_level', 0),
                           ('allocator', 'system')):
            with self.subTest(key=key):
                original = self.reference[key]
                self.reference[key] = value
                self.refresh()
                self.reject()
                self.reference[key] = original

    def test_rejects_changed_supervisor(self):
        self.supervisor_reference()
        (self.source / 'osv-workload-supervisor').write_bytes(b'tampered')
        self.reject()

    def test_rejects_missing_supervisor_inventory(self):
        self.supervisor_reference()
        del self.reference['files']['osv-workload-supervisor']
        (self.source / 'reference.json').write_text(json.dumps(self.reference))
        self.reject()

    def test_rejects_reinventoried_supervisor_provenance_mismatch(self):
        self.supervisor_reference()
        path = self.source / 'comparison-provenance.json'
        provenance = json.loads(path.read_text())
        provenance['supervisor_allocator'] = 'mimalloc'
        path.write_text(json.dumps(provenance))
        self.refresh()
        self.reject()

    def code_read_reference(self, variant='primed'):
        self.supervisor_reference()
        self.reference.update(protocol='osv-allocator-api-reference/v3', comparison='supervisor-code-preparation',
                              variant=variant, helper_code_primed=variant == 'primed')
        path = self.source / 'comparison-provenance.json'
        provenance = json.loads(path.read_text())
        provenance.update(comparison=self.reference['comparison'], variant=variant,
                          helper_code_primed=self.reference['helper_code_primed'])
        path.write_text(json.dumps(provenance))
        self.refresh()

    def test_code_read_variants_keep_same_allocator_and_path(self):
        self.code_read_reference()
        result = fixture.prepare(self.source, self.validation, self.config)
        self.assertTrue(result['helper_code_primed'])
        self.assertEqual(result['supervisor_allocator'], 'system')
        self.assertEqual(result['allocator'], 'mimalloc')

    def test_code_read_baseline_is_not_combined(self):
        self.code_read_reference('baseline')
        result = fixture.prepare(self.source, self.validation, self.config)
        self.assertIs(result['helper_code_primed'], False)
        self.assertEqual(result['supervisor_path'], '/sbin/osv-workload-supervisor')

    def test_rejects_wrong_code_read_state_or_old_layout(self):
        self.code_read_reference()
        for key,value in (('helper_code_primed',False),('helper_code_primed',1),('variant','standalone'),
                          ('supervisor_path','/sbin/agent-init'),('supervisor_allocator','mimalloc')):
            with self.subTest(key=key,value=value):
                original = self.reference[key]
                self.reference[key] = value
                self.refresh()
                self.reject()
                self.reference[key] = original

    def test_rejects_reinventoried_code_read_provenance(self):
        self.code_read_reference()
        path = self.source / 'comparison-provenance.json'
        provenance = json.loads(path.read_text())
        provenance['helper_code_primed'] = False
        path.write_text(json.dumps(provenance))
        self.refresh()
        self.reject()

    def test_rejects_changed_image_before_start(self):
        (self.source / 'rootfs.ext4').write_bytes(b'tamper')
        self.reject()

    def test_preserves_other_templates_public_key(self):
        shared = self.install / 'shared.public'
        shared.write_text('original template identity\n')
        self.config['artifact_manifest']['public_key_path'] = str(shared)
        self.config['templates'] = [{'id': 'other', 'artifact_manifest': {'public_key_path': str(shared)}}]
        original = copy.deepcopy(self.config['templates'])
        fixture.prepare(self.source, self.validation, self.config)
        self.assertEqual(shared.read_text(), 'original template identity\n')
        self.assertEqual(self.config['templates'], original)
        self.assertEqual(self.config['artifact_manifest']['public_key_path'],
                         str(self.validation / 'allocator-reference/artifact.public'))

    def test_rejects_other_kernel_or_features(self):
        original = json.loads((self.source / 'manifest.json').read_text())
        for key, value in [('kernel_size', 7), ('agent_features', []), ('firecracker_sha256', 'd' * 64)]:
            with self.subTest(key=key):
                changed = {**original, key: value}
                (self.source / 'manifest.json').write_text(json.dumps(changed))
                self.refresh()
                self.reject()

    def test_rejects_publishable_or_unknown_allocator(self):
        for key, value in [('release_eligible', True), ('diagnostic', False), ('allocator', 'unknown')]:
            with self.subTest(key=key):
                previous = self.reference[key]
                self.reference[key] = value
                self.refresh()
                self.reject()
                self.reference[key] = previous

    def test_rejects_manifest_payload_mismatch_even_when_reinventoried(self):
        (self.source / 'rootfs.ext4').write_bytes(b'tamper')
        self.refresh()
        self.reject()

    def test_cli_rejects_reference_without_isolation_and_mixed_runtime(self):
        script = Path(__file__).resolve().parents[1] / 'scripts/prepare-offline-validation.py'
        base = [sys.executable, str(script), '--upload', str(self.root), '--root', str(self.root / 'new'),
                '--package', str(self.root / 'package.tar'), '--allocator-reference', str(self.source)]
        for options in ([], ['--warm-pool', '--tenant-pair', '--isolate-network', '--linux-code-probe']):
            with self.subTest(options=options):
                result = subprocess.run(base + options, capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn('ordinary isolated Linux shell warm fixture', result.stderr)
                self.assertFalse((self.root / 'new').exists())


if __name__ == '__main__':
    unittest.main()
