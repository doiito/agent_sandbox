#!/usr/bin/env python3
"""Generate pinned C headers for mimalloc; Rust supplies the static libc link."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
ASSET = ROOT / 'assets/allocators/mimalloc'


def sha(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def main():
    lock = json.loads((ASSET / 'source-lock.json').read_text())
    headers = lock['musl_headers']
    archive = ASSET / 'sources' / f'musl-{headers["version"]}.tar.gz'
    if sha(archive) != headers['sha256']:
        raise ValueError('musl header source differs from source lock')
    source = ASSET / f'musl-{headers["version"]}'
    marker = source / '.osv-source-sha256'
    if source.exists():
        if not marker.is_file() or marker.read_text().strip() != headers['sha256']:
            raise ValueError('existing header source has no matching preparation identity')
    else:
        staging = ASSET / 'musl-source-stage'
        staging.mkdir()
        with tarfile.open(archive) as package:
            for member in package.getmembers():
                path = PurePosixPath(member.name)
                if (path.is_absolute() or '..' in path.parts or path.parts[0] != source.name or
                        not (member.isfile() or member.isdir())):
                    raise ValueError('unsupported musl source archive entry')
            package.extractall(staging)
        (staging / source.name).rename(source)
        staging.rmdir()
        marker.write_text(headers['sha256'] + '\n')
    for arch in ('x86_64', 'aarch64'):
        output = ASSET / 'sysroots' / arch
        work = ROOT / 'build/musl-headers' / arch
        work.mkdir(parents=True, exist_ok=True)
        subprocess.run(['make', '-f', str(source / 'Makefile'), f'srcdir={source}', f'ARCH={arch}',
                        f'prefix={output}', 'install-headers'], cwd=work, check=True)
        files = {str(p.relative_to(output)): sha(p) for p in sorted((output / 'include').rglob('*')) if p.is_file()}
        report = {'protocol': 'osv-musl-c-headers/v1', 'architecture': arch,
                  'header_version': headers['version'], 'source_sha256': headers['sha256'],
                  'static_libc_provider': 'Rust target toolchain (not this header sysroot)',
                  'headers_sha256': files}
        (output / 'headers-manifest.json').write_text(json.dumps(report, indent=2) + '\n')
        shutil.copyfile(source / 'COPYRIGHT', output / 'COPYRIGHT')
        print(f'prepared {arch}: {len(files)} headers in {output}', flush=True)


if __name__ == '__main__':
    main()
