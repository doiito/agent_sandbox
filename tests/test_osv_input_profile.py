"""Signing must not advertise input files for old bytes or a missing mountpoint."""
import copy
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import osv_input_profile as profile


def disk(anchor):
    name='input' if anchor else 'other'
    entry=struct.pack('<QH',2,len(name))+name.encode()
    inodes=struct.pack('<4Q',0x4000,1,0,1)+struct.pack('<4Q',0x4000,2,1,0)
    data=bytearray(1536)
    data[:64]=struct.pack('<8Q',0xDEADBEAD,1,512,2,1,1,0,2)
    data[1024:1024+len(entry+inodes)]=entry+inodes
    return data


class InputProfileTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.asset=Path(self.directory.name)
        (self.asset/'modules').mkdir()
        self.compile('kernel.elf','int osv_sandbox_mount_inputs_v1(void) { return 0; }')
        self.compile('modules/osv-job-agent.so','extern int osv_sandbox_mount_inputs_v1(void);\n'
                     'const char *mode="--pristine-inputs-v1";\nint main(void) { return osv_sandbox_mount_inputs_v1(); }')
        (self.asset/'rootfs.raw').write_bytes(disk(True))

    def compile(self,name,source):
        subprocess.run(['gcc','-x','c','-fPIC','-shared','-nostdlib','-o',str(self.asset/name),'-'],
                       input=source.encode(),capture_output=True,check=True)

    def test_explicit_abi_agent_and_empty_mountpoint(self):
        value=profile.create(self.asset)
        self.assertEqual(profile.verify(self.asset,value),value)

    def test_artifact_change_invalidates_profile(self):
        value=profile.create(self.asset)
        with (self.asset/'rootfs.raw').open('ab') as stream:stream.write(b'changed')
        with self.assertRaisesRegex(ValueError,'bind actual artifacts'):profile.verify(self.asset,value)

    def test_old_agent_cannot_be_promoted_by_metadata(self):
        self.compile('modules/osv-job-agent.so','int main(void) { return 0; }')
        with self.assertRaisesRegex(ValueError,'agent does not use'):profile.create(self.asset)

    def test_old_kernel_cannot_be_promoted_by_metadata(self):
        self.compile('kernel.elf','int old_kernel(void) { return 0; }')
        with self.assertRaisesRegex(ValueError,'kernel ABI is missing'):profile.create(self.asset)

    def test_missing_mountpoint_cannot_be_promoted_by_metadata(self):
        (self.asset/'rootfs.raw').write_bytes(disk(False))
        with self.assertRaisesRegex(ValueError,'empty in-image directory'):profile.create(self.asset)

    def test_changed_limits_or_protocol_are_not_silently_signed(self):
        value=profile.create(self.asset)
        for field in ('limits','preparation','mountpoint','extra'):
            candidate=copy.deepcopy(value)
            if field=='limits':candidate[field]['files']=65
            else:candidate[field]='unknown'
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'unsupported readonly input profile'):
                profile.verify(self.asset,candidate)


if __name__=='__main__':unittest.main()
