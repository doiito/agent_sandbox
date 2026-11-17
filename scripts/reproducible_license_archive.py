"""Archive verified license files without operator identity or filesystem timestamps."""
import gzip
import os
from pathlib import Path
import tarfile

def write_license_archive(output, entries):
    epoch=int(os.environ.get('SOURCE_DATE_EPOCH','0'))
    with Path(output).open('wb') as raw:
        with gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=epoch) as compressed:
            with tarfile.open(fileobj=compressed,mode='w',format=tarfile.PAX_FORMAT) as archive:
                for source,name in entries:
                    source=Path(source)
                    if not source.is_file() or source.is_symlink():raise ValueError('license must be a regular file')
                    info=archive.gettarinfo(str(source),arcname=name)
                    info.uid=info.gid=0;info.uname=info.gname='';info.mtime=epoch;info.pax_headers={}
                    with source.open('rb') as stream:archive.addfile(info,stream)
