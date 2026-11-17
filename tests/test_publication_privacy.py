import importlib.util
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
privacy=module('publication_privacy','scripts/check-publication-privacy.py')
licenses=module('reproducible_licenses','scripts/reproducible_license_archive.py')

class PublicationPrivacyTests(unittest.TestCase):
    def test_plain_and_nested_private_values_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'source.txt';source.write_text('fixture-private-operator')
            archive=root/'proof.tar.gz'
            with tarfile.open(archive,'w:gz') as t:t.add(source,arcname='nested.txt')
            for p in (source,archive):
                result=privacy.check_publication_paths([(p.name,p)],[('operator',b'fixture-private-operator')])
                self.assertFalse(result['passed'])
                self.assertTrue(any('operator' in row['labels'] for row in result['hits']))

    def test_public_metadata_and_contract_root_url_allowed(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/'public.txt';p.write_text('POST /v1/inference/root/bind\npublic key fingerprint')
            self.assertTrue(privacy.check_publication_paths([(p.name,p)],[('operator',b'fixture-private-operator')])['passed'])

    def test_linked_inputs_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/'source';p.write_text('public');link=Path(temp)/'link';link.symlink_to(p)
            self.assertFalse(privacy.check_publication_paths([(link.name,link)],[])['passed'])

    def test_license_archive_is_path_and_timestamp_independent(self):
        with tempfile.TemporaryDirectory() as temp,patch.dict(os.environ,{'SOURCE_DATE_EPOCH':'123456'}):
            root=Path(temp);p=root/'LICENSE';p.write_text('public license\n');first=root/'first.gz';second=root/'second.gz'
            licenses.write_license_archive(first,[(p,'licenses/LICENSE')]);os.utime(p,(999999,999999))
            licenses.write_license_archive(second,[(p,'licenses/LICENSE')]);self.assertEqual(first.read_bytes(),second.read_bytes())
            with tarfile.open(first,'r:gz') as t:
                m,=t.getmembers();self.assertEqual((m.uid,m.gid,m.uname,m.gname,m.mtime),(0,0,'','',123456))
                self.assertEqual(t.extractfile(m).read(),p.read_bytes())

if __name__=='__main__':unittest.main()
