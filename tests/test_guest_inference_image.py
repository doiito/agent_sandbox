"""Image-bound SDK files: real copy, tampering, missing paths and symlinks."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import guest_inference_image as sdk

class GuestInferenceImage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work=ROOT/'build/validation/guest-inference-image-unit'
        cls.work.mkdir(parents=True,exist_ok=True)

    def test_actual_files_metadata_and_source_hashes_for_supported_profiles(self):
        for backend,architecture,count in [('firecracker-linux','amd64',6),('firecracker-linux','arm64',6),('firecracker-osv','amd64',4)]:
            with self.subTest(backend=backend,architecture=architecture),tempfile.TemporaryDirectory(dir=self.work) as temporary:
                root=Path(temporary);profile=sdk.install(root,backend,architecture)
                self.assertEqual(len(profile['files_sha256']),count)
                self.assertEqual(json.loads((root/sdk.META.lstrip('/')).read_text()),profile)
                sdk.validate(root,profile,backend,architecture)
                for name,digest in profile['files_sha256'].items():self.assertEqual(sdk.sha(root/name.lstrip('/')),digest)
                with self.assertRaises(ValueError):sdk.install(root,backend,architecture)

    def test_tampered_missing_and_replaced_files_are_rejected(self):
        for mode in ['changed','missing','symlink','writable','metadata']:
            with self.subTest(mode=mode),tempfile.TemporaryDirectory(dir=self.work) as temporary:
                root=Path(temporary);profile=sdk.install(root,'firecracker-linux','amd64')
                name=next(iter(profile['files_sha256']));path=root/name.lstrip('/')
                if mode=='changed':path.write_text('print("wrong")')
                elif mode=='missing':path.unlink()
                elif mode=='symlink':path.unlink();path.symlink_to('/etc/passwd')
                elif mode=='writable':path.chmod(0o666)
                else:(root/sdk.META.lstrip('/')).write_text('{}')
                with self.assertRaises(ValueError):sdk.validate(root,profile,'firecracker-linux','amd64')

    def test_ancestor_symlink_is_rejected_before_writing_outside_tree(self):
        with tempfile.TemporaryDirectory(dir=self.work) as temporary:
            root=Path(temporary);outside=root/'outside';outside.mkdir();(root/'opt').symlink_to(outside,target_is_directory=True)
            with self.assertRaises(ValueError):sdk.install(root,'firecracker-linux','amd64')
            self.assertEqual(list(outside.iterdir()),[])

    def test_unsupported_osv_ARM_and_unknown_backend_have_no_profile(self):
        for backend,arch in [('firecracker-osv','arm64'),('qemu','amd64'),('firecracker-linux','riscv64')]:
            with self.subTest(backend=backend,architecture=arch),self.assertRaises(ValueError):sdk.profile_for(backend,arch)

    def test_fresh_SDK_directories_remain_traversable_under_private_builder_umask(self):
        with tempfile.TemporaryDirectory(dir=self.work) as temporary:
            root=Path(temporary);previous=os.umask(0o077)
            try:profile=sdk.install(root,'firecracker-linux','amd64')
            finally:os.umask(previous)
            for name in [*profile['files_sha256'],sdk.META]:
                parent=(root/name.lstrip('/')).parent
                while parent!=root:
                    self.assertEqual(parent.stat().st_mode&0o777,0o755)
                    parent=parent.parent

if __name__=='__main__':unittest.main()
