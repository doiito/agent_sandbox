"""Origin checks reject mismatched runtime bytes and package declarations."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('runtime_provenance',ROOT/'scripts/python_science_provenance.py')
provenance=importlib.util.module_from_spec(spec)
spec.loader.exec_module(provenance)


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)

    def test_changed_library_is_rejected_before_package_lookup(self):
        runtime=self.root/'rootfs'
        (runtime/'usr/lib').mkdir(parents=True)
        (runtime/'usr/lib/libexample.so').write_bytes(b'changed runtime')
        installed=self.root/'installed.so'
        installed.write_bytes(b'original builder')
        with patch.object(provenance.closure,'system_libraries',return_value={'libexample.so':installed}),patch.object(provenance,'owner_of') as owner:
            with self.assertRaisesRegex(ValueError,'differs from builder'):
                provenance.collect_system(runtime,{'builder_image_id':'image','packages':[]},'image')
            owner.assert_not_called()

    def test_builder_identity_and_package_version_cannot_be_substituted(self):
        runtime=self.root/'rootfs'
        (runtime/'usr/lib').mkdir(parents=True)
        installed=self.root/'installed.so'
        installed.write_bytes(b'actual library')
        (runtime/'usr/lib/libexample.so').write_bytes(installed.read_bytes())
        build={'builder_image_id':'image','packages':['libexample:amd64=1.0']}
        with self.assertRaisesRegex(ValueError,'builder image'):
            provenance.collect_system(runtime,build,'other-image')
        with patch.object(provenance.closure,'system_libraries',return_value={'libexample.so':installed}),patch.object(provenance,'owner_of',return_value='libexample:amd64'),patch.object(provenance.subprocess,'check_output',return_value='libexample:amd64\t2.0\texample\t2.0\tamd64\n'):
            with self.assertRaisesRegex(ValueError,'package version differs'):
                provenance.collect_system(runtime,build,'image')

    def wheel(self,version='1.0',license=True):
        path=self.root/'example.whl'
        with zipfile.ZipFile(path,'w') as archive:
            archive.writestr('example/__init__.py',b'VALUE = 42\n')
            archive.writestr('example-1.0.dist-info/METADATA',f'Name: example\nVersion: {version}\n')
            if license:
                archive.writestr('example-1.0.dist-info/LICENSE',b'actual license text')
        runtime=self.root/'rootfs'
        site=runtime/'opt/python/lib/python3.12/site-packages'
        provenance.closure.install_wheel(path,site)
        lock={'files':[{'kind':'wheel','project':'example','version':'1.0','filename':path.name,
            'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}]}
        return runtime,lock

    def test_locked_wheel_metadata_files_and_license_are_bound(self):
        runtime,lock=self.wheel()
        with patch.object(provenance.closure.sources,'SOURCES',self.root):
            components,owners=provenance.collect_wheels(runtime,lock)
            self.assertEqual(components[0]['version'],'1.0')
            self.assertEqual(len(owners),3)
            self.assertEqual(len(components[0]['licenses']),1)
            source=runtime/'opt/python/lib/python3.12/site-packages/example/__init__.py'
            source.write_bytes(b'changed, same claimed package version')
            with self.assertRaisesRegex(ValueError,'differs from locked source'):
                provenance.collect_wheels(runtime,lock)

    def test_wrong_metadata_version_and_missing_license_rejected(self):
        runtime,lock=self.wheel(version='2.0')
        with patch.object(provenance.closure.sources,'SOURCES',self.root),self.assertRaisesRegex(ValueError,'metadata differs'):
            provenance.collect_wheels(runtime,lock)
        import shutil
        shutil.rmtree(runtime)
        runtime,lock=self.wheel(license=False)
        with patch.object(provenance.closure.sources,'SOURCES',self.root),self.assertRaisesRegex(ValueError,'license missing'):
            provenance.collect_wheels(runtime,lock)


if __name__=='__main__':
    unittest.main()
