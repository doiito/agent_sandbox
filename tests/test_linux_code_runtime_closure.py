import importlib.util
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('code_closure', ROOT/'scripts/linux_code_runtime_closure.py')
closure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(closure)


class RuntimeClosureTests(unittest.TestCase):
    def test_absolute_guest_symlink_never_uses_host_root(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            (root/'opt').mkdir(); (root/'usr/lib').mkdir(parents=True)
            (root/'usr/lib/inside').write_text('guest')
            (root/'opt/alias').symlink_to('/usr/lib/inside')
            self.assertEqual(closure.guest_resolve(root, '/opt/alias').read_text(), 'guest')
            (root/'opt/host').symlink_to('/etc/passwd')
            self.assertFalse(closure.guest_resolve(root, '/opt/host').exists())
            (root/'opt/escape').symlink_to('../../../etc/passwd')
            with self.assertRaisesRegex(ValueError, 'escapes'):
                closure.guest_resolve(root, '/opt/escape')
            (root/'opt/loop').symlink_to('loop')
            with self.assertRaisesRegex(ValueError, 'cycle'):
                closure.guest_resolve(root, '/opt/loop')

    def test_architecture_is_read_from_actual_elf_and_wrong_target_rejected(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work); path = root/'foreign'
            header = bytearray(64); header[:7] = b'\x7fELF\x02\x01\x01'
            struct.pack_into('<H', header, 18, 183); path.write_bytes(header)
            self.assertEqual(closure.elf_machine(path), 183)
            with self.assertRaisesRegex(ValueError, 'architecture'):
                closure.resolve(root, 'amd64')
            header[5] = 2; path.write_bytes(header)
            with self.assertRaisesRegex(ValueError, 'little-endian'):
                closure.elf_machine(path)

    @unittest.skipUnless(shutil.which('cc') and shutil.which('readelf'), 'native ELF tools required')
    def test_real_shared_library_closure_and_missing_version_fail_without_host_fallback(self):
        with tempfile.TemporaryDirectory() as work:
            base = Path(work); root = base/'guest'; root.mkdir(); lib = base/'libraries'; lib.mkdir()
            source = base/'value.c'; source.write_text('int value(void){return 42;}\n')
            version = base/'version.map'; version.write_text('CODE_1 { global: value; local: *; };\n')
            subprocess.run(['cc','-shared','-fPIC','-nostdlib',str(source),'-Wl,-soname,libcode.so.1',
                            '-Wl,--version-script='+str(version),'-o',str(lib/'libcode.so.1')],check=True)
            program = base/'entry.c'; program.write_text('extern int value(void); int entry(void){return value();}\n')
            subprocess.run(['cc','-shared','-fPIC','-nostdlib',str(program),'-L'+str(lib),'-l:libcode.so.1',
                            '-o',str(root/'entry.so')],check=True)
            with self.assertRaisesRegex(ValueError, 'unresolved'):
                closure.resolve(root,'amd64')
            report = closure.resolve(root,'amd64',[lib])
            self.assertEqual(report['elf_count'],2)
            self.assertEqual(report['edges'][0]['required_versions'],['CODE_1'])
            self.assertEqual(closure.resolve(root,'amd64')['elf_count'],2)
            version.write_text('CODE_2 { global: value; local: *; };\n')
            provider = root/'usr/lib/x86_64-linux-gnu/libcode.so.1'
            subprocess.run(['cc','-shared','-fPIC','-nostdlib',str(source),'-Wl,-soname,libcode.so.1',
                            '-Wl,--version-script='+str(version),'-o',str(provider)],check=True)
            with self.assertRaisesRegex(ValueError, 'lacks symbol versions'):
                closure.resolve(root,'amd64')


if __name__ == '__main__':
    unittest.main()
