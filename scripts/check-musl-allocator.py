#!/usr/bin/env python3
"""Check pinned allocator inputs and static guest build identity."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]
ASSET = ROOT / 'assets/allocators/mimalloc'


def sha(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def check_sources():
    lock_path = ASSET / 'source-lock.json'
    lock = json.loads(lock_path.read_text())
    if lock.get('protocol') != 'osv-musl-allocator-sources/v1':
        raise ValueError('unsupported allocator lock')
    config = tomllib.loads((ROOT / '.cargo/config.toml').read_text())
    if (lock['policy'].get('source_date_epoch') != 0 or
            config['env'].get('SOURCE_DATE_EPOCH') != {'value': '0', 'force': True}):
        raise ValueError('allocator compiler date must be reproducible')
    for field in ('rust_allocator', 'c_binding'):
        package = lock[field]
        archive = ASSET / 'crates' / f'{package["name"]}-{package["version"]}.crate'
        if archive.is_symlink() or sha(archive) != package['sha256']:
            raise ValueError('allocator archive differs from lock')
    for directory in ('runtime-allocator', 'guest', 'linux-guest'):
        cargo = tomllib.loads((ROOT / directory / 'Cargo.lock').read_text())
        packages = {item['name']: item for item in cargo['package']}
        for field in ('rust_allocator', 'c_binding'):
            expected = lock[field]
            actual = packages[expected['name']]
            if actual['version'] != expected['version'] or actual['checksum'] != expected['sha256']:
                raise ValueError(f'{directory} allocator package differs from lock')
        manifest = tomllib.loads((ROOT / directory / 'Cargo.toml').read_text())
        if manifest['profile']['release']['package']['libmimalloc-sys']['opt-level'] != lock['policy']['c_opt_level']:
            raise ValueError('allocator optimization differs from policy')
        if directory != 'runtime-allocator':
            if (set(manifest['features']['mimalloc']) != {
                    'osv-runtime-allocator/mimalloc', 'osv-runtime-allocator/secure'} or
                    'mimalloc' not in manifest['features']['default']):
                raise ValueError('published guest must force the hardened allocator feature')
    manifest = tomllib.loads((ROOT / 'runtime-allocator/Cargo.toml').read_text())
    dependency = manifest['target']['cfg(target_env = "musl")']['dependencies']['mimalloc']
    if (set(dependency['features']) != {'no_thp'} or dependency['default-features'] or
            set(manifest['features']['default']) != {'mimalloc', 'secure'} or
            set(manifest['features']['secure']) != {'mimalloc', 'mimalloc/secure'} or
            lock['policy']['secure'] != 4 or not lock['policy']['no_thp'] or lock['policy']['c_malloc_override']):
        raise ValueError('allocator feature/ownership policy mismatch')
    binding = lock['c_binding']
    header = ROOT / f'assets/build/cargo-vendor/{binding["name"]}-{binding["version"]}/c_src/mimalloc/v3/include/mimalloc.h'
    actual_version = int(re.search(r'^#define MI_MALLOC_VERSION\s+(\d+)', header.read_text(), re.MULTILINE)[1])
    if actual_version != binding['c_version']:
        raise ValueError('vendored C implementation version mismatch')
    headers = {}
    for arch in ('x86_64', 'aarch64'):
        sysroot = ASSET / 'sysroots' / arch
        identity = sysroot / 'headers-manifest.json'
        data = json.loads(identity.read_text())
        if (data['architecture'] != arch or data['source_sha256'] != lock['musl_headers']['sha256'] or
                data['header_version'] != lock['musl_headers']['version']):
            raise ValueError('C headers target/source mismatch')
        actual = {str(p.relative_to(sysroot)): sha(p) for p in sorted((sysroot / 'include').rglob('*')) if p.is_file()}
        if actual != data['headers_sha256']:
            raise ValueError('C header inventory mismatch')
        headers[arch] = sha(identity)
    return {'protocol': 'osv-musl-allocator-build-check/v1', 'source_lock_sha256': sha(lock_path),
            'allocator': 'mimalloc', 'c_version': actual_version, 'secure_level': 4,
            'header_manifest_sha256': headers, 'binary_sha256': {}, 'supervisor_binary_sha256': {},
            'functional_test_evidence': False}


def check_binary(path, architecture):
    machine = {'amd64': 'Advanced Micro Devices X86-64', 'arm64': 'AArch64'}[architecture]
    header = subprocess.check_output(['readelf', '-hW', str(path)], text=True)
    segments = subprocess.check_output(['readelf', '-lW', str(path)], text=True)
    dynamic = subprocess.check_output(['readelf', '-dW', str(path)], text=True)
    if not re.search(r'Machine:\s*' + re.escape(machine), header) or 'INTERP' in segments or '(NEEDED)' in dynamic:
        raise ValueError('guest must be a static ELF for the selected architecture')
    if b'mimalloc hardened guest secure=4 differs from source lock' not in path.read_bytes():
        raise ValueError('guest is missing the compiled hardened mimalloc initialization guard')
    return sha(path)


def check_supervisor(path, architecture, link_map):
    if not 0 < path.stat().st_size <= 4 * 1024 * 1024:
        raise ValueError('supervisor must fit the bounded guest code preparation budget')
    machine = {'amd64': 'Advanced Micro Devices X86-64', 'arm64': 'AArch64'}[architecture]
    header = subprocess.check_output(['readelf', '-hW', str(path)], text=True)
    segments = subprocess.check_output(['readelf', '-lW', str(path)], text=True)
    dynamic = subprocess.check_output(['readelf', '-dW', str(path)], text=True)
    if not re.search(r'Machine:\s*' + re.escape(machine), header) or 'INTERP' in segments or '(NEEDED)' in dynamic:
        raise ValueError('supervisor must be a static ELF for the selected architecture')
    mapping = link_map.read_text()
    if ('dispatch_helper' not in mapping or
            any(token in mapping for token in ('libmimalloc', 'libosv_runtime_allocator', 'mi_malloc',
                                               'mi_process_init', 'mi_process_done')) or
            b'mimalloc hardened guest secure=4 differs from source lock' in path.read_bytes()):
        raise ValueError('supervisor must use the shared dispatcher and System allocator')
    return sha(path)


def check_artifacts(directory, architecture, report):
    expected = {'agent-init', 'osv-agent-executor', 'allocator-policy.json', 'build-check.json',
                'build-provenance.json', 'compiler-transcript.txt', 'build-libraries/libmimalloc.a',
                'licenses/mimalloc-rust.txt', 'licenses/mimalloc-sys.txt', 'licenses/mimalloc-c.txt',
                'osv-workload-supervisor', 'supervisor-link-map.txt'}
    entries = {}
    for line in (directory / 'SHA256SUMS').read_text().splitlines():
        digest, name = line.split('  ', 1)
        if not re.fullmatch('[0-9a-f]{64}', digest) or name not in expected or name in entries:
            raise ValueError('invalid allocator artifact inventory')
        path = directory / name
        if path.is_symlink() or not path.is_file() or sha(path) != digest:
            raise ValueError('allocator artifact digest mismatch: ' + name)
        entries[name] = digest
    if set(entries) != expected or entries['allocator-policy.json'] != report['source_lock_sha256']:
        raise ValueError('allocator artifact inventory/policy mismatch')
    provenance = json.loads((directory / 'build-provenance.json').read_text())
    target = {'amd64': 'x86_64', 'arm64': 'aarch64'}[architecture] + '-unknown-linux-musl'
    if (provenance.get('protocol') != 'osv-musl-guest-build/v2' or provenance.get('target') != target or
            provenance.get('allocator') != 'mimalloc' or provenance.get('c_version') != 30302 or
            provenance.get('secure_level') != 4 or
            provenance.get('source_date_epoch') != 0 or
            provenance.get('c_preprocessor_date') != '"Jan  1 1970" "00:00:00"' or
            provenance.get('libmimalloc_archive_sha256') != entries['build-libraries/libmimalloc.a'] or
            provenance.get('compiler_transcript_sha256') != entries['compiler-transcript.txt']):
        raise ValueError('allocator build provenance mismatch')
    sources = provenance.get('source_sha256', {})
    required = {'runtime-allocator/src/lib.rs', 'guest/src/main.rs', 'linux-guest/src/main.rs',
                'linux-guest/src/network_proxy.rs',
                'linux-guest/src/workspace_mutations.rs', 'linux-guest/src/streaming.rs', 'linux-guest/src/command_stdin.rs', 'linux-guest/src/job_stdin.rs',
                'runtime-allocator/Cargo.lock', 'guest/Cargo.lock', 'linux-guest/Cargo.lock',
                'scripts/build-musl-guests.sh', 'scripts/check-musl-allocator.py',
                'linux-guest/src/workload.rs', 'linux-guest/src/bin/workload_supervisor.rs'}
    if not required.issubset(sources):
        raise ValueError('allocator source provenance incomplete')
    for name, digest in sources.items():
        path = ROOT / name
        if not path.resolve().is_relative_to(ROOT) or sha(path) != digest:
            raise ValueError('allocator source changed after build: ' + name)
    transcript = (directory / 'compiler-transcript.txt').read_text()
    commands = [line for line in transcript.splitlines() if '"-c"' in line and '"-DMI_SECURE=4"' in line]
    if not commands or any('"-O3"' not in line or '"-DMI_NO_THP=1"' not in line or
                           'MI_MALLOC_OVERRIDE' in line for line in commands):
        raise ValueError('allocator compiler flags do not prove hardened optimized static build')
    previous = json.loads((directory / 'build-check.json').read_text())
    if (previous.get('source_lock_sha256') != report['source_lock_sha256'] or
            previous.get('header_manifest_sha256') != report['header_manifest_sha256']):
        raise ValueError('allocator build check source/header mismatch')
    binaries = {Path(name).name: digest for name, digest in previous.get('binary_sha256', {}).items()}
    for name in ('agent-init', 'osv-agent-executor'):
        digest = check_binary(directory / name, architecture)
        if binaries.get(name) != digest:
            raise ValueError('allocator build check binary mismatch')
        report['binary_sha256'][str(directory / name)] = digest
        expected_component = {'allocator': 'mimalloc', 'c_version': 30302, 'secure_level': 4, 'sha256': digest}
        if provenance.get('components', {}).get(name) != expected_component:
            raise ValueError('published guest component allocator identity differs')
    helper = directory / 'osv-workload-supervisor'
    digest = check_supervisor(helper, architecture, directory / 'supervisor-link-map.txt')
    previous_helpers = {Path(name).name: value for name, value in previous.get('supervisor_binary_sha256', {}).items()}
    if (previous_helpers.get(helper.name) != digest or provenance.get('components', {}).get(helper.name) != {
            'allocator': 'system', 'sha256': digest, 'link_map_sha256': entries['supervisor-link-map.txt']}):
        raise ValueError('supervisor build provenance identity differs')
    report['supervisor_binary_sha256'][str(helper)] = digest
    report['artifacts_directory'] = str(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, action='append', default=[])
    parser.add_argument('--architecture', choices=('amd64', 'arm64'))
    parser.add_argument('--report', type=Path)
    parser.add_argument('--artifacts', type=Path, help='validate a complete guest build with provenance')
    parser.add_argument('--supervisor', type=Path, help='System allocator workload supervisor ELF')
    parser.add_argument('--supervisor-link-map', type=Path, help='actual supervisor linker map')
    args = parser.parse_args()
    if (args.binary or args.artifacts or args.supervisor) and not args.architecture:
        parser.error('--architecture is required with --binary/--artifacts')
    if bool(args.supervisor) != bool(args.supervisor_link_map):
        parser.error('--supervisor and --supervisor-link-map must be provided together')
    report = check_sources()
    if args.artifacts:
        check_artifacts(args.artifacts, args.architecture, report)
    for path in args.binary:
        report['binary_sha256'][str(path)] = check_binary(path, args.architecture)
    if args.supervisor:
        report['supervisor_binary_sha256'][str(args.supervisor)] = check_supervisor(
            args.supervisor, args.architecture, args.supervisor_link_map)
    report['architecture'] = args.architecture
    encoded = json.dumps(report, indent=2) + '\n'
    if args.report:
        args.report.write_text(encoded)
    print(encoded, end='')


if __name__ == '__main__':
    main()
