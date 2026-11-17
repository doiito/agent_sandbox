#!/usr/bin/env python3
"""Bind a formal rebuild to authenticated, measured candidate payload bytes."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOTS = ('cmd', 'internal', 'api', 'sdk', 'deploy', 'examples', 'scripts', 'vendor',
                'linux-guest/src', 'linux-guest/code-kernels', 'linux-guest/rootfs', 'osv-native')
SOURCE_FILES = ('go.mod', 'go.sum', 'linux-guest/Cargo.toml', 'linux-guest/Cargo.lock')
SKIP = {'.git', '__pycache__', '.pytest_cache', '.mypy_cache', 'node_modules'}
BUILD_PROTOCOL = 'osv-release-build-inputs/v1'
PLAN_PROTOCOL = 'osv-release-candidate-plan/v1'


def require(value, message):
    if not value:
        raise ValueError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode()


def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def fingerprint(path):
    item = Path(path).stat()
    require(stat.S_ISREG(item.st_mode), 'requires a regular file: '+str(path))
    return item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns


def source_identity(root):
    root = Path(root).resolve()
    paths = []
    for name in SOURCE_ROOTS:
        parent = root/name
        require(parent.is_dir() and not parent.is_symlink(), 'missing or linked source root: '+name)
        for directory, children, files in os.walk(parent, followlinks=False):
            children[:] = sorted(name for name in children if name not in SKIP)
            for name in children + sorted(files):
                path = Path(directory)/name
                require(not path.is_symlink(), 'linked build input: '+str(path.relative_to(root)))
                if path.is_dir() or path.suffix in ('.pyc', '.pyo'):
                    continue
                require(stat.S_ISREG(path.stat().st_mode), 'special build input: '+str(path))
                paths.append(path)
    for name in SOURCE_FILES:
        path = root/name
        require(path.is_file() and not path.is_symlink(), 'missing or linked source input: '+name)
        paths.append(path)
    require(len(paths) <= 100000, 'source input count exceeds bound')
    require(sum(p.stat().st_size for p in paths) <= 1 << 30, 'source bytes exceed bound')
    rows = {}
    for path in sorted(paths):
        before = fingerprint(path)
        rows[str(path.relative_to(root))] = file_hash(path)
        require(before == fingerprint(path), 'source input changed while hashing: '+str(path))
    return hashlib.sha256(canonical(rows)).hexdigest(), len(rows)


def epoch_seconds(value):
    require(re.fullmatch('[0-9]+', str(value)) is not None, 'invalid SOURCE_DATE_EPOCH')
    seconds = int(value)
    require(seconds <= 253402300799, 'SOURCE_DATE_EPOCH exceeds RFC3339 range')
    return seconds


def build_identity(epoch, root=ROOT, go_version=None):
    digest, count = source_identity(root)
    if go_version is None:
        environment = dict(os.environ, GOTOOLCHAIN='local')
        go_version = subprocess.check_output(['go', 'env', 'GOVERSION'], cwd=root,
                                             env=environment, text=True).strip()
    require(re.fullmatch(r'go[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[a-z0-9.]+)?', go_version) is not None,
            'invalid build Go version')
    return dict(protocol=BUILD_PROTOCOL, source_inputs_sha256=digest, source_files=count,
                go_version=go_version, epoch=epoch_seconds(epoch), cgo_enabled=False,
                go_flags_sha256=hashlib.sha256(os.environ.get('GOFLAGS', '').encode()).hexdigest(),
                go_experiment_sha256=hashlib.sha256(os.environ.get('GOEXPERIMENT', '').encode()).hexdigest())


def read_build(profile):
    value = profile.get('release_build')
    require(isinstance(value, dict) and value.get('protocol') == BUILD_PROTOCOL,
            'candidate is missing the current release build identity')
    require(re.fullmatch('[0-9a-f]{64}', value.get('source_inputs_sha256', '')) is not None,
            'invalid candidate source identity')
    require(type(value.get('source_files')) is int and 0 < value['source_files'] <= 100000,
            'invalid candidate source count')
    require(type(value.get('epoch')) is int and value['epoch'] == epoch_seconds(value['epoch']),
            'invalid candidate build epoch')
    require(value.get('cgo_enabled') is False, 'candidate host programs must use CGO_ENABLED=0')
    for name in ('go_flags_sha256', 'go_experiment_sha256'):
        require(re.fullmatch('[0-9a-f]{64}', value.get(name, '')) is not None, 'invalid build flag binding')
    return value


def verify_archive(path, public, arch, root=ROOT):
    """The existing Go verifier authenticates every payload and hashes the whole tar."""
    command = ['go', 'run', '-mod=vendor', './cmd/osv-offline-release', 'verify', '-json',
               '-archive', str(path), '-public-key', str(public), '-arch', arch]
    environment = dict(os.environ, GOTOOLCHAIN='local', CGO_ENABLED='0',
                       GOCACHE=os.environ.get('GOCACHE', '/tmp/osv-offline-release-go-cache'))
    result = subprocess.run(command, cwd=root, env=environment,
                            capture_output=True, text=True, check=False)
    require(result.returncode == 0, 'candidate verification failed: '+result.stderr[-2000:])
    require(len(result.stdout) <= 2 << 20, 'candidate verification output exceeds bound')
    value = json.loads(result.stdout)
    require(set(value) == {'manifest', 'archive_sha256', 'archive_bytes'}, 'invalid verifier response')
    require(value['manifest']['arch'] == arch and re.fullmatch('[0-9a-f]{64}', value['archive_sha256']) is not None,
            'invalid authenticated candidate identity')
    return value


def inspect_candidate(path, public, arch, root=ROOT):
    path = Path(path).resolve()
    before = fingerprint(path)
    value = verify_archive(path, public, arch, root)
    require(value['archive_bytes'] == before[2], 'candidate archive size changed')
    entries = {item['path']: item for item in value['manifest']['files']}
    require('docs/security-profile.json' in entries, 'candidate has no release security profile')
    with tarfile.open(path) as archive:
        def metadata(name):
            require(name in entries, 'unsigned candidate metadata: '+name)
            member = archive.getmember(name)
            require(member.isfile() and 0 <= member.size <= 65536, 'candidate metadata exceeds bound')
            with archive.extractfile(member) as stream:
                raw = stream.read(65537)
            require(len(raw) == entries[name]['size'] and hashlib.sha256(raw).hexdigest() == entries[name]['sha256'],
                    'candidate metadata changed after verification')
            return json.loads(raw)
        value['build'] = read_build(metadata('docs/security-profile.json'))
        for name in entries:
            if name == 'artifacts/manifest.json' or name.startswith('templates/') and name.endswith('/artifacts/manifest.json'):
                artifact = metadata(name)
                created = datetime.datetime.fromisoformat(artifact['created_at'].replace('Z', '+00:00'))
                expires = datetime.datetime.fromisoformat(artifact['expires_at'].replace('Z', '+00:00'))
                now = datetime.datetime.now(datetime.timezone.utc)
                require(created.tzinfo is not None and expires.tzinfo is not None and created <= now < expires,
                        'candidate artifact is not currently valid: '+name)
                require(created.timestamp() == value['build']['epoch'], 'candidate artifact does not use its declared build epoch')
    require(fingerprint(path) == before, 'candidate archive changed during verification')
    value['path'] = str(path)
    return value


def common_build(value):
    return {name: field for name, field in value.items() if name != 'epoch'}


def preflight(startup, candidate, public, arch, root=ROOT):
    require(arch in ('amd64', 'arm64'), 'unknown release architecture')
    public = Path(public).resolve()
    require(fingerprint(public)[2] <= 16384, 'candidate public key exceeds bound')
    public_digest = file_hash(public)
    startup = inspect_candidate(startup, public, 'amd64', root)
    target = startup if arch == 'amd64' and Path(candidate).resolve() == Path(startup['path']) else inspect_candidate(candidate, public, arch, root)
    if arch == 'amd64':
        require(startup['archive_sha256'] == target['archive_sha256'], 'x64 release and startup candidates differ')
    require(common_build(startup['build']) == common_build(target['build']), 'candidate architectures have different source or compiler identities')
    require(all(startup['manifest'][key] == target['manifest'][key] for key in ('version', 'commit')),
            'candidate architectures have different versions or revisions')
    current = build_identity(target['build']['epoch'], root)
    require(current == target['build'], 'current source or compiler differs from the validated candidate')
    supplied = os.environ.get('SOURCE_DATE_EPOCH')
    require(supplied is None or epoch_seconds(supplied) == target['build']['epoch'], 'explicit build epoch differs from candidate')
    return dict(protocol=PLAN_PROTOCOL, startup=startup, target=target, public_key=str(public),
                public_key_sha256=public_digest, policy_sha256=file_hash(Path(root)/'docs/contracts/warm-start-gates.json'))


def compare_stage(plan, stage, root=ROOT):
    require(plan.get('protocol') == PLAN_PROTOCOL, 'invalid release preflight plan')
    require(file_hash(plan['public_key']) == plan['public_key_sha256'], 'candidate public key changed')
    require(file_hash(Path(root)/'docs/contracts/warm-start-gates.json') == plan['policy_sha256'], 'startup policy changed while building')
    fresh = preflight(plan['startup']['path'], plan['target']['path'], plan['public_key'], plan['target']['manifest']['arch'], root)
    require(all(fresh[key]['archive_sha256'] == plan[key]['archive_sha256'] for key in ('startup', 'target')),
            'reference candidate replaced while building')
    stage = Path(stage)
    require(stage.is_dir() and not stage.is_symlink(), 'release stage must be a real directory')
    actual = {}
    for path in stage.rglob('*'):
        item = path.lstat()
        require(not path.is_symlink(), 'linked stage entry: '+str(path))
        if stat.S_ISDIR(item.st_mode):
            continue
        require(stat.S_ISREG(item.st_mode), 'special stage entry: '+str(path))
        before = fingerprint(path)
        name = str(path.relative_to(stage))
        actual[name] = dict(path=name, size=item.st_size, mode=0o555 if item.st_mode & 0o111 else 0o444, sha256=file_hash(path))
        require(fingerprint(path) == before, 'stage file changed while hashing: '+name)
    expected = {item['path']: item for item in fresh['target']['manifest']['files']}
    require(set(actual) == set(expected), 'stage file set differs from the validated candidate')
    for name in sorted(actual):
        require(actual[name] == expected[name], 'stage payload differs from the validated candidate: '+name)
    return fresh['target']['manifest']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest='action', required=True)
    info = actions.add_parser('build-info');info.add_argument('--epoch', required=True);info.add_argument('--output', type=Path, required=True)
    before = actions.add_parser('preflight')
    for name in ('startup', 'candidate', 'public-key', 'arch'):
        before.add_argument('--'+name, required=True)
    before.add_argument('--output', type=Path, required=True)
    compare = actions.add_parser('compare');compare.add_argument('--plan', type=Path, required=True);compare.add_argument('--stage', type=Path, required=True);compare.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.action == 'build-info':
        value = build_identity(args.epoch)
    elif args.action == 'preflight':
        value = preflight(args.startup, args.candidate, args.public_key, args.arch)
    else:
        value = compare_stage(json.loads(args.plan.read_text()), args.stage)
    with args.output.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2);stream.write('\n')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError, tarfile.TarError) as error:
        raise SystemExit('release candidate gate: '+str(error))
