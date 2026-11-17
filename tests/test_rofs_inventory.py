"""Malformed disk metadata must not become host paths or unbounded reads."""
import hashlib
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('rofs_inventory',ROOT/'scripts/rofs_inventory.py')
rofs=importlib.util.module_from_spec(spec)
spec.loader.exec_module(rofs)


def disk(name='payload',inode=2,file_block=1,count=5,partitioned=False):
    entry=struct.pack('<QH',inode,len(name.encode()))+name.encode()
    nodes=struct.pack('<4Q',0x4000,1,0,1)+struct.pack('<4Q',0x8000,2,file_block,count)
    table=entry+nodes
    result=bytearray(1536)
    result[:64]=struct.pack('<8Q',rofs.MAGIC,1,512,2,1,1,0,2)
    result[512:517]=b'hello'
    result[1024:1024+len(table)]=table
    if partitioned:
        prefix=bytearray(512)
        prefix[510:]=b'\x55\xaa'
        struct.pack_into('<B3sB3sII',prefix,446,0,b'\0'*3,0x83,b'\0'*3,1,3)
        result=prefix+result
    return result


class ROFSInventoryTests(unittest.TestCase):
    def inspect(self,data):
        with tempfile.TemporaryDirectory() as directory:
            image=Path(directory)/'image.raw'
            image.write_bytes(data)
            return rofs.inspect(image)

    def test_standalone_and_mbr_hash_exact_file_bytes(self):
        for partitioned in (False,True):
            with self.subTest(partitioned=partitioned):
                result=self.inspect(disk(partitioned=partitioned))
                self.assertEqual(result['partition_offset'],512 if partitioned else 0)
                self.assertEqual(result['files'],[{'path':'/payload','size':5,'sha256':hashlib.sha256(b'hello').hexdigest()}])

    def test_traversal_cycles_invalid_inode_and_metadata_overlap_fail(self):
        for data in (disk(name='..'),disk(name='a/b'),disk(inode=1),disk(inode=99),disk(file_block=2),disk(file_block=0),disk(count=99999)):
            with self.subTest(header=bytes(data[:64])),self.assertRaises(ValueError):
                self.inspect(data)

    def test_optional_directory_inventory_keeps_empty_mountpoints(self):
        data = disk(name='input',count=0)
        struct.pack_into('<4Q',data,1024+10+len('input')+32,0x4000|0o755,2,1,0)
        with tempfile.TemporaryDirectory() as directory:
            image=Path(directory)/'image.raw';image.write_bytes(data)
            result=rofs.inspect(image,include_directories=True)
            self.assertEqual(result['files'],[])
            self.assertEqual(result['directories'],[{'path':'/','mode':0x4000,'children':1},
                {'path':'/input','mode':0x4000|0o755,'children':0}])
            self.assertNotIn('directories',rofs.inspect(image))

    def test_unbounded_or_truncated_tables_and_invalid_partition_fail(self):
        too_many=disk()
        struct.pack_into('<Q',too_many,56,rofs.MAX_NODES+1)
        oversized=disk()
        struct.pack_into('<Q',oversized,32,rofs.MAX_TABLE_BYTES//512+1)
        partition=disk(partitioned=True)
        struct.pack_into('<I',partition,446+12,999999)
        for data in (b'',disk()[:1100],too_many,oversized,partition):
            with self.subTest(length=len(data)),self.assertRaises(ValueError):
                self.inspect(data)


if __name__=='__main__':
    unittest.main()
