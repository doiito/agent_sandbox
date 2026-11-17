#!/usr/bin/env python3
"""Build the pinned Linux code runtimes; installation never downloads packages."""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import tarfile
import zipfile

from linux_code_runtime_closure import inventory, resolve, sha, TRIPLETS

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'assets/runtimes/linux-code'
LOCK = ASSETS / 'source-lock.json'
IMAGE = 'osv-sandbox-code-runtime-builder:bookworm-20261104'


def run(arguments, **kwargs):
    print('+ ' + ' '.join(map(str, arguments)), flush=True)
    return subprocess.run(list(map(str, arguments)), check=True, **kwargs)


def extract(archive, target):
    """One top-level directory, no devices/hardlinks or writes through links."""
    target.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as source:
        members = source.getmembers()
        top = None
        seen, links = set(), []
        for member in members:
            name = member.name.rstrip('/')
            parts = PurePosixPath(name).parts
            if (not parts or name.startswith('/') or '\\' in name or '\0' in name
                    or any(part in ('.', '..') for part in parts)):
                raise ValueError('invalid archive member: ' + name)
            top = top or parts[0]
            if parts[0] != top:
                raise ValueError('multiple archive top-level directories')
            if len(parts) == 1:
                if not member.isdir():
                    raise ValueError('archive root is not a directory')
                continue
            relative = '/'.join(parts[1:])
            if relative in seen:
                raise ValueError('duplicate archive member: ' + relative)
            seen.add(relative)
            output = target / relative
            if member.issym():
                links.append((output, member.linkname))
                continue
            if member.isdir():
                output.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                output.parent.mkdir(parents=True, exist_ok=True)
                with output.open('xb') as sink, source.extractfile(member) as entry:
                    shutil.copyfileobj(entry, sink)
                output.chmod(0o755 if member.mode & 0o111 else 0o644)
            else:
                raise ValueError('unsupported archive inode: ' + relative)
        # Apply links last, so no following member can write through one.
        for output, value in links:
            if (not value or value.startswith('/') or '\\' in value or '\0' in value
                    or not (output.parent / value).resolve().is_relative_to(target.resolve())):
                raise ValueError('archive link escapes its distribution')
            output.parent.mkdir(parents=True, exist_ok=True)
            output.symlink_to(value)


def wheel(archive, target, origins, origin):
    """Install locked wheel data without pip resolution or package scripts."""
    seen = set()
    with zipfile.ZipFile(archive) as source:
        for member in source.infolist():
            name = member.filename.rstrip('/')
            parts = PurePosixPath(name).parts
            if (not name or name.startswith('/') or '\\' in name or '\0' in name
                    or str(PurePosixPath(name)) != name or any(p in ('.', '..') for p in parts)
                    or name in seen or stat.S_ISLNK(member.external_attr >> 16)
                    or any(p.endswith('.data') for p in parts)):
                raise ValueError('unsupported wheel member: ' + name)
            seen.add(name)
            if {'test', 'tests', '__pycache__'}.intersection(parts) or name.endswith(('.pyc', '.pyo')):
                continue
            output = target / name
            if member.is_dir():
                output.mkdir(parents=True, exist_ok=True)
                continue
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open('xb') as sink, source.open(member) as entry:
                shutil.copyfileobj(entry, sink)
            output.chmod(0o755 if name.endswith('.so') else 0o644)
            origins[output] = origin


def inside(args, lock):
    arch = args.architecture
    target = ASSETS / ('linux-' + arch)
    if target.exists():
        raise ValueError('final runtime asset already exists; verify it instead of overwriting it')
    work = ROOT / 'build/linux-code-runtime' / arch
    rootfs = work / 'rootfs-stage'
    if rootfs.exists():
        raise ValueError('partial rootfs exists; inspect it before removing or resuming')
    source = ROOT / 'build/linux-code-runtime/source'
    inputs = [row for row in lock['files'] if arch in row['architectures']]
    for row in inputs:
        if sha(ROOT / row['path']) != row['sha256']:
            raise ValueError('runtime source hash mismatch: ' + row['path'])
    python_source = next(row for row in inputs if row['project'] == 'CPython')
    if not source.exists():
        extract(ROOT / python_source['path'], source)
    rootfs.mkdir(parents=True)
    obj = work / 'obj'
    obj.mkdir(parents=True, exist_ok=True)
    triplet = TRIPLETS[arch]
    cc = 'gcc' if arch == 'amd64' else 'aarch64-linux-gnu-gcc'
    env = dict(os.environ, SOURCE_DATE_EPOCH='0', PYTHONDONTWRITEBYTECODE='1', CFLAGS='-O3 -fno-semantic-interposition',
               LDFLAGS='-Wl,-rpath,/opt/python/lib -L/usr/lib/' + triplet,
               CPPFLAGS='-I/usr/include/' + triplet, CC=cc,
               PKG_CONFIG_LIBDIR='/usr/lib/' + triplet + '/pkgconfig:/usr/share/pkgconfig')
    configure = [source / 'configure', '--prefix=/opt/python', '--enable-shared',
                 '--with-ensurepip=no', '--with-system-ffi']
    if arch == 'arm64':
        native = ASSETS / 'linux-amd64/rootfs/opt/python'
        if not (native / 'bin/python3.12').is_file():
            raise ValueError('build and seal native Python before arm64 cross-compilation')
        wrapper = work / 'build-python'
        wrapper.write_text('#!/bin/sh\nexport PYTHONHOME=' + str(native) + '\n'
                           'export LD_LIBRARY_PATH=' + str(native / 'lib') + '\n'
                           'export PYTHONDONTWRITEBYTECODE=1\n'
                           'exec ' + str(native / 'bin/python3.12') + ' -B "$@"\n')
        wrapper.chmod(0o755)
        configure += ['--host=aarch64-linux-gnu', '--build=x86_64-linux-gnu',
                      '--with-build-python=' + str(wrapper)]
        env.update(AR='aarch64-linux-gnu-ar', READELF='aarch64-linux-gnu-readelf',
                   ac_cv_file__dev_ptmx='yes', ac_cv_file__dev_ptc='no',
                   ac_cv_buggy_getaddrinfo='no')
    run(configure, cwd=obj, env=env)
    run(['make', '-j' + str(args.jobs)], cwd=obj, env=env)
    run(['make', '-j' + str(args.jobs), 'install', 'DESTDIR=' + str(rootfs),
         'COMPILEALL_OPTS=-j' + str(args.jobs)], cwd=obj, env=env)
    python = rootfs / 'opt/python'
    shutil.copyfile(source / 'LICENSE', python / 'LICENSE')
    # Keep pip/ensurepip and all runtime stdlib; remove development/test material.
    for path in sorted(python.rglob('*'), reverse=True):
        if path.is_dir() and not path.is_symlink() and (
                path.name in {'test', 'tests', '__pycache__', 'idlelib', 'pkgconfig'}
                or path.name.startswith('config-') or path == python / 'include'):
            shutil.rmtree(path)
        elif path.is_file() and path.suffix in {'.a', '.pyc', '.pyo'}:
            path.unlink()
    origins = {path: {'project': 'CPython', 'source_sha256': python_source['sha256']}
               for path in python.rglob('*') if path.is_file() and not path.is_symlink()}
    site = python / 'lib/python3.12/site-packages'
    for row in inputs:
        if row['kind'] == 'wheel':
            wheel(ROOT / row['path'], site, origins,
                  {'project': row['project'], 'source_sha256': row['sha256']})
    for bundled in (python / 'lib/python3.12/ensurepip/_bundled').glob('pip-*.whl'):
        wheel(bundled, site, origins, {'project': 'pip', 'bundled_by': 'CPython',
                                     'source_sha256': python_source['sha256']})
    for project, directory in [('Node.js', 'node'), ('TypeScript', 'typescript')]:
        row = next(item for item in inputs if item['project'] == project)
        distribution = rootfs / 'opt' / directory
        extract(ROOT / row['path'], distribution)
        origins.update({path: {'project': project, 'source_sha256': row['sha256']}
                        for path in distribution.rglob('*') if path.is_file() and not path.is_symlink()})
    bindir = rootfs / 'usr/bin'
    bindir.mkdir(parents=True)
    for name, value in {'python3': '../../opt/python/bin/python3.12',
                        'node': '../../opt/node/bin/node',
                        'npm': '../../opt/node/lib/node_modules/npm/bin/npm-cli.js',
                        'npx': '../../opt/node/lib/node_modules/npm/bin/npx-cli.js',
                        'tsc': '../../opt/typescript/bin/tsc'}.items():
        (bindir / name).symlink_to(value)
    # CA bundle is data, rather than a runtime dependency on host certificates.
    cert = rootfs / 'etc/ssl/certs/ca-certificates.crt'
    cert.parent.mkdir(parents=True)
    shutil.copyfile('/etc/ssl/certs/ca-certificates.crt', cert)
    origins[cert] = {'project': 'ca-certificates', 'builder_file': '/etc/ssl/certs/ca-certificates.crt'}
    ssl = rootfs / 'usr/lib/ssl'
    ssl.mkdir(parents=True)
    (ssl / 'cert.pem').symlink_to('../../../etc/ssl/certs/ca-certificates.crt')
    (ssl / 'certs').symlink_to('../../../etc/ssl/certs')
    sources = [Path('/usr/lib/' + triplet), Path('/lib/' + triplet)]
    if arch == 'amd64':
        sources += [Path('/lib64')]
    else:
        sources += [Path('/usr/aarch64-linux-gnu/lib')]
    closure = resolve(rootfs, arch, sources)
    packages = subprocess.check_output(['dpkg-query', '-W', '-f', '${binary:Package}=${Version}\n'], text=True).splitlines()
    system_licenses = rootfs / 'usr/share/licenses/linux-code-runtime'
    system_licenses.mkdir(parents=True)
    owners = set()
    for name, provider in closure['copied_libraries'].items():
        original = provider['source']
        candidates = [original]
        if original.startswith('/usr/lib/'):
            candidates.append(original[4:])
        owned = None
        for candidate in candidates:
            query = subprocess.run(['dpkg-query', '-S', candidate], capture_output=True, text=True)
            if query.returncode == 0:
                owned = query.stdout.splitlines()[0].rsplit(': ', 1)[0]
                break
        if not owned:
            raise ValueError('no package provenance for runtime library: ' + original)
        owners.add(owned)
        origins[rootfs / name.lstrip('/')] = {'project': 'Debian runtime library',
                                             'package': owned, 'builder_file': original}
    for owner in sorted(owners | {'ca-certificates'}):
        name = owner.split(':')[0]
        copyright = Path('/usr/share/doc') / name / 'copyright'
        if not copyright.is_file():
            raise ValueError('missing runtime license: ' + owner)
        output = system_licenses / (owner.replace(':', '_') + '.copyright')
        shutil.copyfile(copyright, output)
        origins[output] = {'project': name, 'package': owner, 'builder_file': str(copyright)}
    files = inventory(rootfs)
    provenance = {}
    for name, metadata in files.items():
        if metadata['kind'] == 'file':
            origin = origins.get(rootfs / name.lstrip('/'))
            if not origin:
                raise ValueError('runtime file lacks origin: ' + name)
            provenance[name] = origin
    record = {'protocol': 'osv-linux-code-runtime/v1', 'architecture': arch,
              'builder_image_id': os.environ['OSV_CODE_RUNTIME_BUILDER_ID'],
              'source_lock_sha256': sha(LOCK), 'source_date_epoch': 0,
              'compiler': subprocess.check_output([cc, '--version'], text=True),
              'configure': list(map(str, configure)), 'build_environment': {
                  key: env[key] for key in ['CC', 'CFLAGS', 'CPPFLAGS', 'LDFLAGS', 'PKG_CONFIG_LIBDIR']},
              'build_packages': packages, 'runtime_packages': sorted(owners | {'ca-certificates'}),
              'inputs_sha256': {name: sha(ROOT / name) for name in [
                  'scripts/build-linux-code-runtime.py', 'scripts/linux_code_runtime_closure.py',
                  'deploy/linux-code-runtime-builder.Dockerfile']},
              'files': files, 'origins': provenance, 'closure': closure}
    # Freeze only after standalone closure verification succeeds without providers.
    standalone = resolve(rootfs, arch)
    if standalone['edges'] != closure['edges']:
        raise ValueError('copied closure differs from standalone resolution')
    work_record = work / 'runtime-inventory.json'
    work_record.write_text(json.dumps(record, indent=2) + '\n')
    target.mkdir()
    rootfs.rename(target / 'rootfs')
    work_record.rename(target / 'runtime-inventory.json')
    (target / 'SHA256SUMS').write_text(sha(target / 'runtime-inventory.json') + '  runtime-inventory.json\n')
    print(json.dumps({'asset': str(target), 'architecture': arch,
                      'files': len(files), 'elf_count': closure['elf_count']}), flush=True)


def verify(architecture):
    asset = ASSETS / ('linux-' + architecture)
    document = json.loads((asset / 'runtime-inventory.json').read_text())
    if (document['protocol'] != 'osv-linux-code-runtime/v1'
            or document['architecture'] != architecture or document['source_lock_sha256'] != sha(LOCK)
            or document['files'] != inventory(asset / 'rootfs')):
        raise ValueError('runtime inventory or source lock mismatch')
    if resolve(asset / 'rootfs', architecture)['edges'] != document['closure']['edges']:
        raise ValueError('standalone runtime closure mismatch')
    print('Verified sealed offline runtime: ' + architecture, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--architecture', choices=['amd64', 'arm64', 'all'], default='all')
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--image', default=IMAGE)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    if not 1 <= args.jobs <= 16:
        parser.error('jobs must be between 1 and 16')
    lock = json.loads(LOCK.read_text())
    if args.inside:
        if args.architecture == 'all':
            parser.error('inside build takes one architecture')
        inside(args, lock)
        return
    for arch in ['amd64', 'arm64'] if args.architecture == 'all' else [args.architecture]:
        if args.verify:
            verify(arch)
            continue
        builder = subprocess.check_output(['docker', 'image', 'inspect', args.image,
                                           '--format', '{{.Id}}'], text=True).strip()
        run(['docker', 'run', '--rm', '--network', 'none', '-v', str(ROOT) + ':/work', '-w', '/work',
             '-e', 'OSV_CODE_RUNTIME_BUILDER_ID=' + builder, args.image,
             'python3', 'scripts/build-linux-code-runtime.py', '--inside',
             '--architecture', arch, '--jobs', args.jobs])
        verify(arch)


if __name__ == '__main__':
    main()
