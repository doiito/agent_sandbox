"""Prepare byte-verified OCI imports for the existing isolated catalog fixture."""
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def regular_below(root, relative):
    if (not isinstance(relative, str) or not relative or Path(relative).is_absolute()
            or Path(relative).as_posix() != relative or '..' in Path(relative).parts):
        raise ValueError('noncanonical artifact path')
    path = root / relative
    if path.resolve() != path or not path.is_relative_to(root) or not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError('artifact must be a regular file without symlink indirection')
    return path


def sources(release, config):
    rows = []
    selected = [(config.get('template_id', 'default'), config)]
    selected += [(row['id'], row) for row in config.get('templates', [])]
    for identity, value in selected:
        if not isinstance(identity, str) or not re.fullmatch('[a-z0-9][a-z0-9-]{0,62}', identity):
            raise ValueError('invalid catalog identity')
        source = Path(value['artifact_root'])
        if not source.is_absolute() or source.resolve() != source or not source.is_relative_to(release):
            raise ValueError('OCI fixture source must be inside the installed release')
        binding = value['artifact_manifest']
        if (binding['path'], binding['signature_path'], binding['sbom_path']) != ('manifest.json', 'manifest.json.sig', 'sbom.cdx.json'):
            raise ValueError('unsupported artifact metadata names')
        manifest = json.loads(regular_below(source, 'manifest.json').read_text())
        if value['backend'] != manifest['backend']:
            raise ValueError('configured and signed backends differ')
        for role in ('kernel', 'image'):
            if any(value[role][key] != manifest[role][key] for key in ('path', 'sha256')):
                raise ValueError('configured artifact differs from the signed source')
        names = ['manifest.json', 'manifest.json.sig', 'sbom.cdx.json', manifest['kernel']['path'], manifest['image']['path']]
        if len(set(names)) != 5:
            raise ValueError('artifact roles overlap')
        digests = {name: sha(regular_below(source, name)) for name in names}
        entries = value['allowed_entrypoints'] if value['backend'] == 'firecracker-osv' else []
        if value['backend'] == 'firecracker-osv' and (not entries or not all(isinstance(n, str) and n.startswith('/') for n in entries)):
            raise ValueError('OSv requires the existing trusted module allowlist')
        rows.append({'id': identity, 'backend': value['backend'], 'source': str(source),
                     'source_relative_to_release': str(source.relative_to(release)),
                     'files': digests, 'sizes': {name: (source / name).stat().st_size for name in names},
                     'kernel': manifest['kernel']['path'], 'image': manifest['image']['path'],
                     'entrypoints': list(entries)})
    if len(rows) != 2 or {r['backend'] for r in rows} != {'firecracker-linux', 'firecracker-osv'} or len({r['id'] for r in rows}) != 2:
        raise ValueError('OCI catalog probe requires exactly one Linux and one OSv template')
    return rows


def remap(config, rows):
    output = copy.deepcopy(config)
    items = [(output.get('template_id', 'default'), output)] + [(v['id'], v) for v in output.get('templates', [])]
    by_id = {row['id']: row for row in rows}
    if {identity for identity, _ in items} != set(by_id):
        raise ValueError('imported catalog identities do not match configuration')
    for identity, value in items:
        row = by_id[identity]
        if value['artifact_root'] != row['source'] or value['backend'] != row['backend']:
            raise ValueError('source catalog binding changed')
        value['artifact_root'] = row['destination']
    return output


def config_sha(config):
    return hashlib.sha256(json.dumps(config, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def namespace_view(rows, process_root):
    """Inspect the actual process mount view; original files must be inaccessible."""
    result = []
    for row in rows:
        original = Path(process_root) / row['source'].lstrip('/') / 'manifest.json'
        try:
            with original.open('rb') as stream:
                stream.read(1)
        except OSError as error:
            if error.errno not in (2, 13, 1):
                raise
            denied_errno = error.errno
        else:
            raise ValueError('service can still read the original packaged template')
        imported = Path(process_root) / row['destination'].lstrip('/')
        if sha(imported / 'manifest.json') != row['files']['manifest.json']:
            raise ValueError('service cannot read the expected imported signature manifest')
        for name, size in row['sizes'].items():
            path = imported / name
            info = path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_size != size or info.st_mode & 0o222:
                raise ValueError('service imported artifact metadata differs')
            with path.open('rb') as stream:
                stream.read(1)
        result.append({'id': row['id'], 'backend': row['backend'], 'original_source_blocked_errno': denied_errno,
                       'imported_manifest_sha256': row['files']['manifest.json'], 'imported_files_readable': len(row['sizes'])})
    return result


def reference_check(target):
    """Fail closed on inaccessible host processes; never read process arguments."""
    prefix = str(target)
    def matches(value):
        value = value.removesuffix(' (deleted)')
        return value == prefix or value.startswith(prefix + '/')
    hits, denied, inspected = [], 0, 0
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        inspected += 1
        try:
            for link in [proc / 'cwd', proc / 'exe', proc / 'root', *list((proc / 'fd').iterdir())]:
                try:
                    value = os.readlink(link)
                    if matches(value):
                        hits.append({'pid': proc.name, 'path': value})
                except (FileNotFoundError, ProcessLookupError):
                    pass
            for line in (proc / 'maps').read_text().splitlines():
                columns = line.split(None, 5)
                if len(columns) == 6 and matches(columns[5]):
                    hits.append({'pid': proc.name, 'path': columns[5]})
            try:
                if prefix in (proc / 'mountinfo').read_text():
                    hits.append({'pid': proc.name, 'mount_prefix': prefix})
            except OSError as error:
                state = (proc / 'stat').read_text().rsplit(')', 1)[1].split()[0]
                if error.errno != 22 or state not in ('Z', 'X'):
                    raise
        except PermissionError:
            denied += 1
        except (FileNotFoundError, ProcessLookupError):
            pass
    return {'passed': not hits and not denied, 'target': prefix, 'references': hits, 'denied': denied,
            'processes_inspected': inspected, 'process_arguments_read': False}


def prepare(release, root, config, public_key):
    """Run installed CLI, bind imports, retire private layouts; do not start services."""
    release, root, public_key = Path(release), Path(root), Path(public_key)
    report_path = root / 'results/oci-import-preparation.json'
    if report_path.exists():
        raise ValueError('OCI preparation already has a report; do not overwrite or replay')
    report = {'protocol': 'osv-oci-imported-catalog-preparation/v1', 'passed': False, 'profiles': [],
              'actual_KVM': False, 'full_original_goal_complete': False}
    began = time.monotonic()
    try:
        if release.resolve() != release or root.resolve() != root:
            raise ValueError('fixture paths must be absolute without symlink indirection')
        rows = sources(release, config)
        cli = regular_below(release, 'bin/osv-template-oci')
        firecracker, jailer = regular_below(release, 'bin/firecracker'), regular_below(release, 'bin/jailer')
        if not public_key.is_file() or public_key.resolve() != public_key:
            raise ValueError('missing external artifact public key')
        report.update(cli_sha256=sha(cli), public_key_sha256=sha(public_key))
        with (root / 'results/oci-import-preparation.lock').open('x') as lock:
            os.chmod(lock.name, 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            imports, cache = root / 'oci-imported', root / '.oci-layouts'
            imports.mkdir(mode=0o755)
            cache.mkdir(mode=0o700)
            for row in rows:
                layout, destination = cache / row['id'], imports / row['id']
                row['destination'] = str(destination)
                evidence = root / 'results/oci' / row['id']
                evidence.mkdir(mode=0o700, parents=True)
                params = ['-architecture', 'amd64', '-backend', row['backend'], '-public-key', str(public_key),
                          '-firecracker', str(firecracker), '-jailer', str(jailer)]
                for entry in row['entrypoints']:
                    params += ['-entrypoint', entry]
                commands = []
                def invoke(operation, source, target, extra=()):
                    argv = [str(cli), operation, '-source', str(source), '-destination', str(target), *params, *extra]
                    child = subprocess.run(argv, capture_output=True, text=True, timeout=180)
                    commands.append({'argv': argv, 'exit_code': child.returncode, 'stdout': child.stdout, 'stderr': child.stderr})
                    (evidence / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
                    if child.returncode:
                        raise ValueError('installed OCI CLI failed: ' + operation)
                    return json.loads(child.stdout)
                exported = invoke('export', row['source'], layout)
                digest = exported['digest']
                if not re.fullmatch('sha256:[0-9a-f]{64}', digest):
                    raise ValueError('CLI did not return an immutable OCI digest')
                envelope_path = layout / 'blobs/sha256' / digest[7:]
                envelope = json.loads(envelope_path.read_text())
                for name, data in [('index.json', (layout / 'index.json').read_bytes()),
                                   ('oci-layout', (layout / 'oci-layout').read_bytes()),
                                   ('oci-manifest.json', envelope_path.read_bytes()),
                                   ('config.json', (layout / 'blobs/sha256' / envelope['config']['digest'][7:]).read_bytes())]:
                    (evidence / name).write_bytes(data)
                imported = invoke('import', layout, destination, ['-digest', digest])
                if imported['digest'] != digest:
                    raise ValueError('import did not confirm the original OCI digest')
                for name, expected in row['files'].items():
                    path = regular_below(destination, name)
                    if sha(path) != expected or path.stat().st_mode & 0o222:
                        raise ValueError('imported bytes or read-only mode differ from the source')
                    if path.stat().st_size <= 1 << 20:
                        target = evidence / 'imported-metadata' / name
                        target.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(path, target)
                row.update(oci_manifest_digest=digest, passed=True)
                check = reference_check(layout)
                (evidence / 'layout-reference-check.json').write_text(json.dumps(check, indent=2) + '\n')
                if not check['passed']:
                    raise ValueError('completed layout still referenced or host inspection incomplete')
                shutil.rmtree(layout)
                row['temporary_layout_retired'] = True
                report['profiles'].append(row)
            check = reference_check(cache)
            report['cache_reference_check'] = check
            if not check['passed']:
                raise ValueError('layout workspace still referenced')
            shutil.rmtree(cache)
            output = remap(config, rows)
            report['source_configuration_sha256'] = config_sha(config)
            report['configuration_sha256'] = config_sha(output)
            report['passed'] = True
            return output, report
    except BaseException as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        report['duration_seconds'] = round(time.monotonic() - began, 3)
        report_path.write_text(json.dumps(report, indent=2) + '\n')
