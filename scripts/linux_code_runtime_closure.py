#!/usr/bin/env python3
"""Resolve/verify a guest ELF closure without executing target architecture code."""
import argparse
from collections import deque
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import stat
import struct
import subprocess

MACHINES = {'amd64': 62, 'arm64': 183}
TRIPLETS = {'amd64': 'x86_64-linux-gnu', 'arm64': 'aarch64-linux-gnu'}
SONAME = re.compile(r'^[A-Za-z0-9_.+-]+$')


def sha(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def guest_resolve(root, value):
    """Resolve absolute guest links inside root, rather than the build host."""
    if not isinstance(value, str) or not value.startswith('/') or '\\' in value or '\0' in value:
        raise ValueError('invalid guest absolute path')
    pending, resolved, links = deque(value.split('/')[1:]), [], 0
    while pending:
        part = pending.popleft()
        if part in ('', '.'):
            continue
        if part == '..':
            if not resolved:
                raise ValueError('guest path escapes root')
            resolved.pop()
            continue
        candidate = root.joinpath(*resolved, part)
        if candidate.is_symlink():
            links += 1
            if links > 32:
                raise ValueError('guest symlink cycle or excessive depth')
            target = os.readlink(candidate)
            if '\\' in target or '\0' in target:
                raise ValueError('invalid guest link target')
            if target.startswith('/'):
                resolved = []
            pending.extendleft(reversed(target.split('/')))
        else:
            resolved.append(part)
    return root.joinpath(*resolved)


def elf_machine(path):
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError('ELF is not a regular file')
    with path.open('rb') as source:
        header = source.read(64)
    if header[:4] != b'\x7fELF':
        return None
    if len(header) != 64 or header[4:7] != b'\x02\x01\x01':
        raise ValueError('runtime must be little-endian ELF64')
    return struct.unpack_from('<H', header, 18)[0]


def dynamic(path):
    text = subprocess.check_output(['readelf', '-dW', str(path)], text=True)
    needed = re.findall(r'\(NEEDED\).*?\[([^\]]+)\]', text)
    search = re.findall(r'\((?:RPATH|RUNPATH)\).*?\[([^\]]*)\]', text)
    if any(not SONAME.fullmatch(name) for name in needed):
        raise ValueError('invalid dependency soname: ' + str(path))
    program = subprocess.check_output(['readelf', '-lW', str(path)], text=True)
    interpreters = re.findall(r'Requesting program interpreter: ([^\]]+)', program)
    if len(interpreters) > 1:
        raise ValueError('ambiguous ELF interpreter')
    return needed, [value for item in search for value in item.split(':') if value], interpreters[0] if interpreters else None


def versions(path):
    text = subprocess.check_output(['readelf', '--version-info', '-W', str(path)], text=True)
    needs, definitions, section, owner = {}, set(), None, None
    for line in text.splitlines():
        if line.startswith('Version needs section'):
            section = 'needs'
        elif line.startswith('Version definition section'):
            section = 'definitions'
        elif line.startswith('Version symbols section'):
            section = None
        match = re.search(r'File: (\S+)', line)
        if section == 'needs' and match:
            owner = match.group(1)
        match = re.search(r'Name: (\S+)', line)
        if match and section == 'needs' and owner:
            needs.setdefault(owner, set()).add(match.group(1))
        elif match and section == 'definitions':
            definitions.add(match.group(1))
    return needs, definitions


def library_dirs(architecture):
    triplet = TRIPLETS[architecture]
    return ['/opt/python/lib', '/usr/lib/' + triplet, '/lib/' + triplet,
            '/usr/lib', '/lib', '/lib64', '/opt/node/lib']


def resolve(root, architecture, source_dirs=()):
    root = root.resolve(strict=True)
    expected = MACHINES[architecture]
    sources = [Path(path).resolve(strict=True) for path in source_dirs]
    edges, copied = [], {}
    pending = deque(path for path in root.rglob('*') if path.is_file() and not path.is_symlink()
                    and elf_machine(path) is not None)
    seen, metadata = set(), {}

    def elf(path):
        if elf_machine(path) != expected:
            raise ValueError('wrong runtime ELF architecture: ' + str(path))
        if path not in metadata:
            metadata[path] = versions(path)
        return path

    def copy(name, destination):
        if not sources:
            raise ValueError('unresolved offline dependency: ' + name)
        for directory in sources:
            candidate = directory / name
            if not candidate.is_file():
                continue
            original = candidate.resolve(strict=True)
            if elf_machine(original) != expected:
                continue
            if not any(original.is_relative_to(allowed) for allowed in sources):
                raise ValueError('target system library escapes explicit search roots')
            target = guest_resolve(root, destination)
            if target.exists() or target.is_symlink():
                raise ValueError('conflicting runtime dependency: ' + destination)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original, target)
            target.chmod(0o755)
            copied[destination] = {'source': str(original), 'sha256': sha(target)}
            pending.append(target)
            return elf(target)
        raise ValueError('no target-architecture provider: ' + name)

    while pending:
        path = pending.popleft()
        if path in seen:
            continue
        seen.add(elf(path))
        source_name = '/' + str(path.relative_to(root))
        needed, runpaths, interpreter = dynamic(path)
        if interpreter:
            provider = guest_resolve(root, interpreter)
            if not provider.is_file():
                provider = copy(PurePosixPath(interpreter).name, interpreter)
            pending.append(elf(provider))
            edges.append({'from': source_name, 'interpreter': interpreter,
                          'provider': '/' + str(provider.relative_to(root))})
        directories = []
        for value in runpaths:
            origin = posixpath.dirname(source_name)
            expanded = value.replace('${ORIGIN}', origin).replace('$ORIGIN', origin)
            if '$' in expanded or not expanded.startswith('/'):
                raise ValueError('unsupported runtime search path: ' + value)
            # Keep '..' for guest_resolve to reject paths above guest root.
            directories.append(expanded)
        directories += library_dirs(architecture)
        requirements, _ = metadata[path]
        for name in needed:
            provider = next((candidate for directory in directories
                             if (candidate := guest_resolve(root, directory + '/' + name)).is_file()), None)
            if provider is None:
                provider = copy(name, '/usr/lib/' + TRIPLETS[architecture] + '/' + name)
            elf(provider)
            missing = requirements.get(name, set()) - metadata[provider][1]
            if missing:
                raise ValueError('provider lacks symbol versions ' + repr(sorted(missing)) + ': ' + name)
            pending.append(provider)
            edges.append({'from': source_name, 'soname': name,
                          'provider': '/' + str(provider.relative_to(root)),
                          'required_versions': sorted(requirements.get(name, set()))})
    return {'architecture': architecture, 'elf_count': len(seen),
            'edges': sorted(edges, key=lambda item: (item['from'], item.get('soname', item.get('interpreter')))),
            'copied_libraries': copied}


def inventory(root):
    entries = {}
    for path in sorted(root.rglob('*')):
        name = '/' + str(path.relative_to(root))
        if path.is_symlink():
            target = guest_resolve(root, name)
            if not target.exists():
                raise ValueError('dangling runtime link: ' + name)
            entries[name] = {'kind': 'symlink', 'target': os.readlink(path)}
        elif path.is_file():
            entries[name] = {'kind': 'file', 'sha256': sha(path), 'size': path.stat().st_size,
                             'mode': stat.S_IMODE(path.stat().st_mode)}
        elif not path.is_dir():
            raise ValueError('unsupported runtime file type: ' + name)
    return entries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs', type=Path, required=True)
    parser.add_argument('--architecture', choices=MACHINES, required=True)
    parser.add_argument('--system-dir', type=Path, action='append', default=[])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = resolve(args.rootfs, args.architecture, args.system_dir)
    report['files'] = inventory(args.rootfs)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'architecture': args.architecture, 'elf_count': report['elf_count'],
                      'file_count': len(report['files'])}))


if __name__ == '__main__':
    main()
