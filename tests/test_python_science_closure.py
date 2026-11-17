"""Supply-chain rejection tests for the OSv runtime closure, without downloads."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('python_science_closure', ROOT / 'scripts/python_science_closure.py')
closure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(closure)


class ClosureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def wheel(self, names):
        wheel = self.root / 'input.whl'
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(wheel, 'w') as archive:
                for name in names:
                    archive.writestr(name, b'payload')
        return wheel

    def test_wheel_traversal_symlink_duplicates_and_data_rejected(self):
        cases = [['../escape'], ['/escape'], ['x/../escape'], ['x//escape'],
                 ['x\\escape'], ['x.py', 'x.py'], ['x.data/data/payload']]
        symlink = zipfile.ZipInfo('link')
        symlink.create_system = 3
        symlink.external_attr = 0o120777 << 16
        cases.append([symlink])
        for names in cases:
            with self.subTest(names=names), self.assertRaises(ValueError):
                closure.install_wheel(self.wheel(names), self.root / 'target')

    def test_wheel_retains_license_and_rejects_package_overlap(self):
        wheel = self.wheel(['demo/__init__.py', 'demo/tests/test_x.py', 'demo-1.dist-info/licenses/LICENSE'])
        target = self.root / 'target'
        closure.install_wheel(wheel, target)
        self.assertTrue((target / 'demo-1.dist-info/licenses/LICENSE').is_file())
        self.assertFalse((target / 'demo/tests').exists())
        with self.assertRaises(FileExistsError):
            closure.install_wheel(wheel, target)

    def test_locked_urls_and_hashes_rejected_without_network(self):
        lock = closure.sources.read_lock()
        candidate = self.root / 'lock.json'
        for field, value in [('url', 'https://attacker.invalid/numpy.whl'),
                             ('url', 'https://user@files.pythonhosted.org/numpy.whl'),
                             ('filename', '../escape'), ('sha256', '0' * 63), ('kind', 'script')]:
            with self.subTest(field=field, value=value):
                bad = json.loads(json.dumps(lock))
                bad['files'][1][field] = value
                candidate.write_text(json.dumps(bad))
                with patch.object(closure.sources, 'LOCK', candidate), self.assertRaises(ValueError):
                    closure.sources.read_lock()
        source = self.root / 'source'
        source.write_bytes(b'tampered')
        with self.assertRaises(ValueError):
            closure.sources.verify(source, '0' * 64)

    def compile_dependency(self, extra=()):
        self.rootfs = self.root / 'rootfs'
        self.rootfs.mkdir()
        source = self.root / 'dep.c'
        source.write_text('int closure_dependency(void) { return 7; }\n')
        library = self.root / 'libclosure_fixture.so'
        subprocess.run(['cc', '-fPIC', '-shared', '-Wl,-soname,libclosure_fixture.so',
                        '-o', str(library), str(source)], check=True)
        source.write_text('extern int closure_dependency(void); int main(void) { return closure_dependency(); }\n')
        subprocess.run(['cc', '-fPIC', '-shared', '-o', str(self.rootfs / 'main.so'), str(source),
                        '-L' + str(self.root), '-lclosure_fixture', *extra], check=True)
        return library

    def test_recursive_resolution_copies_dependency_and_closes_graph(self):
        library = self.compile_dependency()
        edges = closure.resolve_closure(self.rootfs, {'libclosure_fixture.so': library})
        self.assertEqual((self.rootfs / 'usr/lib/libclosure_fixture.so').read_bytes(), library.read_bytes())
        self.assertIn({'from': '/main.so', 'soname': 'libclosure_fixture.so',
                       'provider': '/usr/lib/libclosure_fixture.so'}, edges)
        # A second pass must resolve entirely from the packaged tree.
        self.assertEqual(closure.resolve_closure(self.rootfs, {}), edges)

    def test_unresolved_dependency_rejected(self):
        self.compile_dependency()
        with self.assertRaisesRegex(ValueError, 'unresolved dependency'):
            closure.resolve_closure(self.rootfs, {})

    def test_rpath_escape_rejected(self):
        library = self.compile_dependency(['-Wl,-rpath,$ORIGIN/../../outside'])
        with self.assertRaisesRegex(ValueError, 'escapes rootfs'):
            closure.resolve_closure(self.rootfs, {'libclosure_fixture.so': library})

    def test_inventory_detects_mutation_extra_file_and_symlink_escape(self):
        rootfs = self.root / 'rootfs'
        rootfs.mkdir()
        path = rootfs / 'payload'
        path.write_bytes(b'original')
        document = {'protocol': 'osv-python-science-runtime/v1', 'files': closure.inventory(rootfs),
                    'source_lock_sha256': closure.sources.digest(closure.sources.LOCK)}
        closure.verify(rootfs, document)
        path.write_bytes(b'modified')
        with self.assertRaisesRegex(ValueError, 'inventory mismatch'):
            closure.verify(rootfs, document)
        path.write_bytes(b'original')
        (rootfs / 'extra').write_bytes(b'extra')
        with self.assertRaisesRegex(ValueError, 'inventory mismatch'):
            closure.verify(rootfs, document)
        (rootfs / 'escape').symlink_to('/etc/passwd')
        with self.assertRaisesRegex(ValueError, 'symlink escapes'):
            closure.inventory(rootfs)

    def test_bytecode_requires_provenance_and_the_pinned_abi(self):
        rootfs=self.root/'rootfs'
        cache=rootfs/'opt/python/lib/python3.12/__pycache__/example.cpython-312.pyc'
        cache.parent.mkdir(parents=True)
        cache.write_bytes(b'unattributed cache')
        with self.assertRaisesRegex(ValueError,'unattributed bytecode'):
            closure.bytecode_policy(rootfs)
        record={'protocol':'osv-python-checked-bytecode/v1','optimization':0,'flags':3,
            'cache_tag':'cpython-312','python_version':[3,12,16],'magic':'a70d0d0a','files':[]}
        (rootfs/'bytecode-provenance.json').write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError,'unsupported bytecode policy'):
            closure.bytecode_policy(rootfs)
        record['magic']='cb0d0d0a'
        record['optimization']=2
        (rootfs/'bytecode-provenance.json').write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError,'unsupported bytecode policy'):
            closure.bytecode_policy(rootfs)

    def test_v2_cleanup_metadata_cannot_silently_change(self):
        rootfs=self.root/'rootfs'
        rootfs.mkdir()
        (rootfs/'file').write_bytes(b'actual runtime file')
        record={'protocol':'osv-python-science-runtime/v2','files':closure.inventory(rootfs),
            'source_lock_sha256':closure.sources.digest(closure.sources.LOCK),
            'initial_cleanup_excluded_directories':sorted(closure.EXCLUDED_PARTS),
            'final_excluded_directories':sorted(closure.EXCLUDED_PARTS),'bytecode_policy':None}
        closure.verify(rootfs,record)
        record['final_excluded_directories'].remove('__pycache__')
        with self.assertRaisesRegex(ValueError,'cleanup policy mismatch'):
            closure.verify(rootfs,record)


if __name__ == '__main__':
    unittest.main()
