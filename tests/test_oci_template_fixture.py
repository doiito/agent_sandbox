"""Confinement and service-view counterexamples for the OCI catalog fixture."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('oci_template_fixture', ROOT / 'scripts/oci_template_fixture.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class OCITemplateFixtureTests(unittest.TestCase):
    def setUp(self):
        base = ROOT / 'build/validation/oci-imported-fixture'
        base.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=str(base), prefix='unit-')
        self.root = Path(self.temporary.name)
        self.release = self.root / 'release'
        self.release.mkdir()
        self.config = {'limits': {'max_concurrent': 2}, 'policy_marker': 'preserve-existing-policy'}
        profiles = []
        for identity, backend in [('default', 'firecracker-linux'), ('science', 'firecracker-osv')]:
            directory = self.release / identity
            directory.mkdir()
            for name in ('kernel', 'image', 'sbom.cdx.json', 'manifest.json.sig'):
                (directory / name).write_text(identity + '-' + name)
            manifest = {'backend': backend, 'kernel': {'path': 'kernel', 'sha256': fixture.sha(directory / 'kernel')},
                        'image': {'path': 'image', 'sha256': fixture.sha(directory / 'image')}}
            (directory / 'manifest.json').write_text(json.dumps(manifest))
            profiles.append({'id': identity, 'backend': backend, 'artifact_root': str(directory),
                             'kernel': manifest['kernel'], 'image': manifest['image'],
                             'artifact_manifest': {'path': 'manifest.json', 'signature_path': 'manifest.json.sig', 'sbom_path': 'sbom.cdx.json'},
                             'allowed_entrypoints': ['/python3.12.so'] if backend.endswith('osv') else ['/bin/bash']})
        self.config.update({k: v for k, v in profiles[0].items() if k != 'id'})
        self.config['templates'] = [profiles[1]]

    def tearDown(self):
        self.temporary.cleanup()

    def test_catalog_identity_backend_and_trusted_OSv_allowlist_rejections(self):
        variants = []
        duplicate = copy.deepcopy(self.config)
        duplicate['templates'][0]['id'] = 'default'
        variants.append(duplicate)
        invalid = copy.deepcopy(self.config)
        invalid['templates'][0]['allowed_entrypoints'] = []
        variants.append(invalid)
        wrong_backend = copy.deepcopy(self.config)
        wrong_backend['templates'][0]['backend'] = 'firecracker-linux'
        variants.append(wrong_backend)
        escaped = copy.deepcopy(self.config)
        escaped['artifact_root'] = str(self.root)
        variants.append(escaped)
        wrong_image = copy.deepcopy(self.config)
        wrong_image['image']['sha256'] = '0' * 64
        variants.append(wrong_image)
        for config in variants:
            with self.subTest(config=config), self.assertRaises(ValueError):
                fixture.sources(self.release, config)

    def test_signed_paths_and_symlinks_cannot_escape_source(self):
        source = self.release / 'default'
        for name in ('../outside', '/outside', './kernel', 'a//b'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                fixture.regular_below(source, name)
        (source / 'link').symlink_to(source / 'kernel')
        with self.assertRaises(ValueError):
            fixture.regular_below(source, 'link')

    def test_OSv_default_keeps_original_identity_policy_and_bytes(self):
        linux = {k: v for k, v in self.config.items() if k != 'templates'}
        linux['id'] = 'linux'
        config = {**copy.deepcopy(self.config['templates'][0]), 'template_id': 'science', 'templates': [linux],
                  'limits': {'max_concurrent': 2}}
        before = copy.deepcopy(config)
        rows = fixture.sources(self.release, config)
        for row in rows:
            row['destination'] = str(self.root / 'imports' / row['id'])
        remapped = fixture.remap(config, rows)
        self.assertEqual(config, before)
        self.assertEqual(remapped['backend'], 'firecracker-osv')
        self.assertEqual(remapped['allowed_entrypoints'], ['/python3.12.so'])
        self.assertEqual(remapped['limits'], before['limits'])
        self.assertEqual(remapped['templates'][0]['kernel'], before['templates'][0]['kernel'])
        tampered = copy.deepcopy(config)
        tampered['templates'][0]['artifact_root'] = '/unexpected/source'
        with self.assertRaises(ValueError):
            fixture.remap(tampered, rows)

    def test_unmasked_namespace_never_counts_as_imported_service(self):
        rows = fixture.sources(self.release, self.config)
        for row in rows:
            row['destination'] = row['source']
        with self.assertRaisesRegex(ValueError, 'original packaged'):
            fixture.namespace_view(rows, Path('/'))

    def test_namespace_rejects_wrong_import_content_or_writable_files(self):
        rows = fixture.sources(self.release, self.config)
        view = self.root / 'view'
        for row in rows:
            row['destination'] = str(self.root / 'imported' / row['id'])
            target = view / row['destination'].lstrip('/')
            target.mkdir(parents=True)
            for name in row['files']:
                (target / name).write_bytes((Path(row['source']) / name).read_bytes())
                (target / name).chmod(0o444)
        self.assertEqual(len(fixture.namespace_view(rows, view)), 2)
        target = view / rows[0]['destination'].lstrip('/') / 'image'
        target.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'metadata differs'):
            fixture.namespace_view(rows, view)
        target.chmod(0o444)
        target = view / rows[0]['destination'].lstrip('/') / 'manifest.json'
        target.chmod(0o644)
        target.write_text('{}')
        target.chmod(0o444)
        with self.assertRaisesRegex(ValueError, 'signature manifest'):
            fixture.namespace_view(rows, view)

    def test_open_descriptor_blocks_layout_retirement(self):
        layout = self.root / 'layout'
        layout.mkdir()
        blob = layout / 'blob'
        blob.write_text('live-reference')
        with blob.open('rb'):
            check = fixture.reference_check(layout)
        self.assertFalse(check['passed'])
        self.assertTrue(any(row.get('pid') == str(os.getpid()) and row.get('path') == str(blob) for row in check['references']))

    def test_import_option_requires_catalog_before_fixture_creation(self):
        root = self.root / 'must-not-create'
        child = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/prepare-offline-validation.py'),
                                '--root', str(root), '--upload', str(self.root), '--package', str(self.root / 'absent.tar'),
                                '--oci-import-probe'], text=True, capture_output=True, timeout=10)
        self.assertNotEqual(child.returncode, 0)
        self.assertIn('--oci-import-probe requires', child.stderr)
        self.assertFalse(root.exists())


if __name__ == '__main__':
    unittest.main()
