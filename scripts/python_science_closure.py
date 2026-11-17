#!/usr/bin/env python3
"""Prepare/verify a Python ROFS closure without running a dependency resolver."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import zipfile

from importlib.util import module_from_spec, spec_from_file_location

ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location('python_science_sources', ROOT / 'scripts/fetch-python-science.py')
sources = module_from_spec(spec)
spec.loader.exec_module(sources)

# Exact sonames supplied by the pinned OSv ELF loader with hide_symbols=1.
# libstdc++ and libgcc_s are deliberately resolved into the image.
PROVIDED = {'ld-linux-x86-64.so.2', 'libresolv.so.2', 'libc.so.6', 'libm.so.6',
            'libc.musl-x86_64.so.1', 'ld-musl-x86_64.so.1', 'libpthread.so.0',
            'libdl.so.2', 'librt.so.1', 'libaio.so.1', 'libxenstore.so.3.0',
            'libcrypt.so.1', 'libutil.so'}
EXCLUDED_PARTS = {'test', 'tests', '__pycache__', 'idlelib', 'ensurepip'}


def guest_path(value):
    path = PurePosixPath(value)
    if (not value.startswith('/') or value.startswith('//') or str(path) != value or
            any(part in ('.', '..') for part in value.split('/')[1:]) or '\\' in value or '\0' in value):
        raise ValueError(f'noncanonical guest path: {value}')
    return path


def install_wheel(wheel, target):
    """No wheel scripts or metadata commands are executed."""
    with zipfile.ZipFile(wheel) as archive:
        seen = set()
        for member in archive.infolist():
            name = member.filename.rstrip('/')
            path = PurePosixPath(name)
            mode = member.external_attr >> 16
            if (not name or path.is_absolute() or str(path) != name or
                    any(part in ('', '.', '..') for part in name.split('/')) or
                    '\\' in name or '\0' in name or name in seen or stat.S_ISLNK(mode) or
                    any(part.endswith('.data') for part in path.parts)):
                raise ValueError(f'unsupported or unsafe wheel member: {member.filename}')
            seen.add(name)
            if EXCLUDED_PARTS.intersection(path.parts) or name.endswith(('.pyc', '.pyo')):
                continue
            output = target / name
            if member.is_dir():
                output.mkdir(parents=True, exist_ok=True)
                continue
            output.parent.mkdir(parents=True, exist_ok=True)
            # No overlapping packages or pre-existing symlinks are accepted.
            with output.open('xb') as sink, archive.open(member) as source:
                shutil.copyfileobj(source, sink)
            output.chmod(0o755 if name.endswith('.so') else 0o644)


def dynamic(path):
    text = subprocess.check_output(['readelf', '-dW', str(path)], text=True)
    needed = re.findall(r'\(NEEDED\).*?\[([^\]]+)\]', text)
    search = re.findall(r'\((?:RPATH|RUNPATH)\).*?\[([^\]]*)\]', text)
    if any('/' in name or not re.fullmatch(r'[A-Za-z0-9_.+-]+', name) for name in needed):
        raise ValueError(f'unsupported ELF dependency in {path}')
    return needed, [part for value in search for part in value.split(':')]


def is_elf(path):
    if not path.is_file() or path.is_symlink():
        return False
    with path.open('rb') as source:
        return source.read(4) == b'\x7fELF'


def system_libraries():
    result = {}
    text = subprocess.check_output(['ldconfig', '-p'], text=True)
    for name, path in re.findall(r'^\s*(\S+) \([^\n]*x86-64[^\n]*\) => (\S+)$', text, re.MULTILINE):
        result.setdefault(name, Path(path).resolve(strict=True))
    return result


def resolve_closure(rootfs, system):
    rootfs = rootfs.resolve(strict=True)
    pending = sorted(path for path in rootfs.rglob('*') if is_elf(path))
    seen, edges = set(), []
    while pending:
        path = pending.pop()
        if path in seen:
            continue
        seen.add(path)
        needed, search = dynamic(path)
        for name in needed:
            if name in PROVIDED:
                edges.append({'from': '/' + str(path.relative_to(rootfs)), 'soname': name, 'provider': 'OSv'})
                continue
            candidates = []
            for directory in search:
                expanded = directory.replace('${ORIGIN}', str(path.parent)).replace('$ORIGIN', str(path.parent))
                if '$' in expanded or not expanded.startswith('/'):
                    raise ValueError(f'unsupported ELF search path {directory} in {path}')
                candidate = Path(expanded) if '$ORIGIN' in directory or '${ORIGIN}' in directory else rootfs / expanded.lstrip('/')
                candidate = (candidate / name).resolve()
                if not candidate.is_relative_to(rootfs):
                    raise ValueError(f'ELF search path escapes rootfs: {directory}')
                candidates.append(candidate)
            candidates.extend(rootfs / directory / name for directory in ('opt/python/lib', 'usr/lib', 'lib'))
            found = next((item for item in candidates if item.is_file()), None)
            if found is None:
                original = system.get(name)
                if original is None:
                    raise ValueError(f'unresolved dependency {name} in {path}')
                found = rootfs / 'usr/lib' / name
                found.parent.mkdir(parents=True, exist_ok=True)
                if found.exists() or found.is_symlink():
                    raise ValueError(f'conflicting runtime library: {name}')
                shutil.copyfile(original, found)
                found.chmod(0o755)
            if not is_elf(found):
                raise ValueError(f'dependency is not a regular ELF: {found}')
            pending.append(found)
            edges.append({'from': '/' + str(path.relative_to(rootfs)), 'soname': name,
                          'provider': '/' + str(found.relative_to(rootfs))})
    return sorted(edges, key=lambda item: (item['from'], item['soname']))


def inventory(rootfs):
    files = []
    for path in sorted(rootfs.rglob('*')):
        name = '/' + str(path.relative_to(rootfs))
        guest_path(name)
        if path.is_symlink():
            target = os.readlink(path)
            if not (path.parent / target).resolve().is_relative_to(rootfs.resolve()):
                raise ValueError(f'runtime symlink escapes rootfs: {name}')
            files.append({'path': name, 'symlink': target})
        elif path.is_file():
            files.append({'path': name, 'size': path.stat().st_size, 'sha256': sources.digest(path)})
        elif not path.is_dir():
            raise ValueError(f'unsupported runtime inode: {name}')
    return files


def verify(rootfs, document):
    if document.get('protocol') not in ('osv-python-science-runtime/v1', 'osv-python-science-runtime/v2'):
        raise ValueError('unsupported runtime inventory')
    # Inventory is stored inside the signed ROFS and alongside the build assets;
    # exclude only that self-reference when comparing the complete tree.
    actual = [item for item in inventory(rootfs) if item['path'] != '/runtime-inventory.json']
    if actual != document['files']:
        raise ValueError('runtime file inventory mismatch')
    if document['source_lock_sha256'] != sources.digest(sources.LOCK):
        raise ValueError('runtime source lock mismatch')
    if document['protocol'].endswith('/v2'):
        policy = bytecode_policy(rootfs)
        final = EXCLUDED_PARTS - ({'__pycache__'} if policy else set())
        if (document['initial_cleanup_excluded_directories'] != sorted(EXCLUDED_PARTS) or
                document['final_excluded_directories'] != sorted(final) or document['bytecode_policy'] != policy):
            raise ValueError('runtime bytecode or cleanup policy mismatch')


def bytecode_policy(rootfs):
    caches = {'/'+str(path.relative_to(rootfs)) for path in rootfs.rglob('*.pyc')}
    provenance = rootfs/'bytecode-provenance.json'
    if not provenance.exists():
        if caches:
            raise ValueError('unattributed bytecode cache')
        return None
    record = json.loads(provenance.read_text())
    if (record['protocol'] != 'osv-python-checked-bytecode/v1' or record['optimization'] != 0 or
            record['flags'] != 3 or record['cache_tag'] != 'cpython-312' or record['python_version'] != [3,12,16] or
            record['magic'] != 'cb0d0d0a'):
        raise ValueError('unsupported bytecode policy')
    seen = set()
    for row in record['files']:
        source_path, cache_path = guest_path(row['source']), guest_path(row['bytecode'])
        expected = source_path.parent/'__pycache__'/(source_path.stem+'.cpython-312.pyc')
        if cache_path != expected or str(cache_path) in seen:
            raise ValueError('noncanonical or duplicate bytecode')
        source = rootfs/str(source_path).lstrip('/')
        cache = rootfs/str(cache_path).lstrip('/')
        if (not str(source_path).startswith('/opt/python/lib/python3.12/') or
                source.is_symlink() or cache.is_symlink() or
                not source.resolve().is_relative_to(rootfs.resolve()) or not cache.resolve().is_relative_to(rootfs.resolve())):
            raise ValueError('escaping or unsupported bytecode path')
        data = cache.read_bytes()
        if (source.is_symlink() or cache.is_symlink() or sources.digest(source) != row['source_sha256'] or
                sources.digest(cache) != row['bytecode_sha256'] or len(data) != row['size'] or
                data[:4].hex() != record['magic'] or data[4:8] != b'\x03\x00\x00\x00' or data[8:16].hex() != row['source_hash']):
            raise ValueError('bytecode provenance mismatch')
        seen.add(str(cache_path))
    if seen != caches:
        raise ValueError('incomplete bytecode provenance')
    return {'optimization':0,'invalidation':'checked-hash','cache_tag':'cpython-312','files':len(seen),
        'provenance_sha256':sources.digest(provenance)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('wheels', 'resolve', 'seal', 'verify'))
    parser.add_argument('rootfs', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    lock = sources.read_lock()
    if args.action == 'wheels':
        target = args.rootfs / 'opt/python/lib/python3.12/site-packages'
        target.mkdir(parents=True, exist_ok=True)
        for item in lock['files']:
            if item['kind'] == 'wheel':
                wheel = sources.SOURCES / item['filename']
                sources.verify(wheel, item['sha256'])
                install_wheel(wheel, target)
        return
    if args.action == 'seal':
        if args.output is None or (args.rootfs / 'runtime-inventory.json').exists():
            raise ValueError('sealing requires a new inventory output')
        edges = resolve_closure(args.rootfs, system_libraries())
        policy = bytecode_policy(args.rootfs)
        document = {'protocol': 'osv-python-science-runtime/v2', 'architecture': 'x86_64',
                    'source_lock_sha256': sources.digest(sources.LOCK), 'sources': lock['files'],
                    'initial_cleanup_excluded_directories': sorted(EXCLUDED_PARTS),
                    'final_excluded_directories': sorted(EXCLUDED_PARTS - ({'__pycache__'} if policy else set())),
                    'bytecode_policy': policy,
                    'osv_provided_sonames': sorted(PROVIDED), 'dependencies': edges,
                    'files': inventory(args.rootfs)}
        encoded = json.dumps(document, indent=2) + '\n'
        args.output.write_text(encoded)
        (args.rootfs / 'runtime-inventory.json').write_text(encoded)
    elif args.action == 'resolve':
        edges = resolve_closure(args.rootfs,system_libraries())
        print(f'resolved {len(edges)} ELF dependency edges')
        return
    else:
        if args.output is None:
            raise ValueError('verification requires an inventory')
        document = json.loads(args.output.read_text())
        if (args.rootfs / 'runtime-inventory.json').read_bytes() != args.output.read_bytes():
            raise ValueError('embedded inventory differs from build inventory')
        verify(args.rootfs, document)
    print(f'{args.action}: {len(document["files"])} runtime files, {len(document["dependencies"])} ELF dependencies')


if __name__ == '__main__':
    main()
