#!/usr/bin/env python3
"""Audit the fixed E2B method denominator and two-language real-service evidence."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / 'docs/contracts/e2b-2.51.0-matrix.json'
EVIDENCE = ROOT / 'docs/contracts/e2b-2.51.0-evidence.json'
GROUP_COUNTS = {'lifecycle': 9, 'commands': 7, 'files': 10, 'code': 5, 'ports': 3}
FROZEN_IDS = set('''sandbox.create sandbox.connect sandbox.list sandbox.is_running
sandbox.get_info sandbox.set_timeout sandbox.kill sandbox.pause sandbox.fork
commands.run commands.list commands.connect commands.kill commands.send_stdin
commands.close_stdin command_handle.wait files.read files.write files.write_files
files.list files.exists files.get_info files.make_dir files.rename files.remove
files.watch_dir code.run_code code.create_context code.list_contexts
code.restart_context code.remove_context sandbox.get_host sandbox.upload_url
sandbox.download_url'''.split())
SOURCE_GROUPS = {
    'lifecycle': ('packages/python-sdk/e2b/sandbox_sync/main.py',
                  'packages/python-sdk/e2b/sandbox_sync/sandbox_api.py',
                  'packages/js-sdk/src/sandbox/index.ts',
                  'packages/js-sdk/src/sandbox/sandboxApi.ts'),
    'commands': ('packages/python-sdk/e2b/sandbox_sync/commands/command.py',
                 'packages/python-sdk/e2b/sandbox_sync/commands/command_handle.py',
                 'packages/js-sdk/src/sandbox/commands/index.ts',
                 'packages/js-sdk/src/sandbox/commands/commandHandle.ts'),
    'files': ('packages/python-sdk/e2b/sandbox_sync/filesystem/filesystem.py',
              'packages/js-sdk/src/sandbox/filesystem/index.ts'),
    'code': ('packages/code-interpreter-python/e2b_code_interpreter/code_interpreter_sync.py',
             'packages/code-interpreter-js/src/sandbox.ts'),
    'ports': ('packages/python-sdk/e2b/sandbox/main.py',
              'packages/js-sdk/src/sandbox/index.ts'),
}
MANIFEST_SOURCES = {
    'packages/python-sdk/pyproject.toml', 'packages/js-sdk/package.json',
    'packages/code-interpreter-python/pyproject.toml',
    'packages/code-interpreter-js/package.json',
}
DIGEST = re.compile(r'^[0-9a-f]{64}$')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load(path):
    return json.loads(path.read_text())


def audit_matrix(matrix):
    require(matrix.get('schema') == 'osv-e2b-compat-matrix/v1', 'matrix schema mismatch')
    upstream = matrix['upstream']
    commit = upstream['commit']
    require(re.fullmatch(r'[0-9a-f]{40}', commit) and
            upstream['tag'] == 'e2b@2.51.0', 'upstream pin mismatch')
    require(upstream['packages'] == {
        'python': 'e2b==2.51.0', 'typescript': 'e2b@2.51.0',
        'python_code_interpreter': 'e2b-code-interpreter==2.10.0',
        'typescript_code_interpreter': '@e2b/code-interpreter@2.8.0'},
        'upstream package versions drifted')
    sources = upstream['source_sha256']
    require(set(sources) == {path for paths in SOURCE_GROUPS.values() for path in paths} | MANIFEST_SOURCES
            and all(DIGEST.fullmatch(value) for value in sources.values()),
            'source inventory or digest mismatch')
    operations = matrix['operations']
    require(matrix['denominator'] == len(operations) == 34 and
            matrix['required_compatible'] == 28, 'locked denominator or threshold drifted')
    ids = set()
    counts = {group: 0 for group in GROUP_COUNTS}
    for row in operations:
        key = row['id']
        require(re.fullmatch(r'[a-z][a-z0-9_.]*', key) and key not in ids,
                'duplicate or malformed operation ID')
        ids.add(key)
        group = row['group']
        require(group in counts, f'unknown group: {group}')
        counts[group] += 1
        require(re.fullmatch(r'[A-Za-z][A-Za-z0-9_.]*', row['python']) and
                re.fullmatch(r'[A-Za-z][A-Za-z0-9_.]*', row['typescript']) and
                len(row['behavior']) >= 35,
                f'incomplete language mapping or behavior: {key}')
    require(counts == GROUP_COUNTS, f'group denominator drifted: {counts}')
    require(ids == FROZEN_IDS, 'fixed operation IDs drifted')
    return ids, counts


def verify_upstream(matrix):
    upstream = matrix['upstream']
    commit = upstream['commit']
    sources = {}
    for path, expected in upstream['source_sha256'].items():
        url = f'https://raw.githubusercontent.com/e2b-dev/E2B/{commit}/{path}'
        fetched = subprocess.run(['curl', '--fail', '--location', '--silent', '--show-error',
                                  '--max-time', '20', url], check=True,
                                 capture_output=True, timeout=25)
        data = fetched.stdout
        require(len(data) <= 2 << 20, f'upstream source exceeds limit: {path}')
        require(hashlib.sha256(data).hexdigest() == expected,
                f'upstream source hash mismatch: {path}')
        sources[path] = data.decode('utf-8')
    for path, version in [('packages/python-sdk/pyproject.toml', '2.51.0'),
                          ('packages/code-interpreter-python/pyproject.toml', '2.10.0')]:
        require(re.search(r'^version\s*=\s*"' + re.escape(version) + r'"\s*$',
                          sources[path], re.MULTILINE), f'upstream version mismatch: {path}')
    for path, version in [('packages/js-sdk/package.json', '2.51.0'),
                          ('packages/code-interpreter-js/package.json', '2.8.0')]:
        require(json.loads(sources[path])['version'] == version,
                f'upstream version mismatch: {path}')
    for row in matrix['operations']:
        candidates = SOURCE_GROUPS[row['group']]
        for field, suffix in (('python', '.py'), ('typescript', '.ts')):
            name = row[field].rsplit('.', 1)[-1]
            texts = [sources[path] for path in candidates if path.endswith(suffix)]
            pattern = (rf'\bdef\s+{re.escape(name)}\s*\(' if suffix == '.py'
                       else rf'\b{re.escape(name)}\s*\(')
            require(any(re.search(pattern, source) for source in texts),
                    f'upstream method missing: {row["id"]} {field}')
    return len(sources)


def verified_report(entry, language, operation, commit, candidate):
    record = entry[language]
    relative = record['path']
    require(relative.startswith('results/e2b-2.51.0/') and '..' not in Path(relative).parts,
            f'invalid {language} evidence path')
    path = ROOT / relative
    require(path.resolve().is_relative_to((ROOT / 'results/e2b-2.51.0').resolve()),
            f'{language} evidence escapes results directory')
    data = path.read_bytes()
    require(DIGEST.fullmatch(record['sha256']), f'invalid {language} report hash')
    require(hashlib.sha256(data).hexdigest() == record['sha256'],
            f'{language} evidence hash mismatch')
    report = json.loads(data)
    require(report.get('suite') == 'e2b-compat-case/v1' and
            report.get('operation') == operation and
            report.get('language') == language and
            report.get('upstream_commit') == commit and
            report.get('candidate_sha256') == candidate and
            report.get('environment') == 'real-kvm' and report.get('passed') is True,
            f'{language} report metadata mismatch')
    cases = report.get('cases')
    require(isinstance(cases, list) and len(cases) >= 2 and
            {case.get('name') for case in cases} >= {'success', 'failure'} and
            all(case.get('passed') is True for case in cases),
            f'{language} evidence lacks positive/negative cases')


def audit_evidence(evidence, matrix, ids):
    commit = matrix['upstream']['commit']
    require(evidence.get('schema') == 'osv-e2b-compat-evidence/v1' and
            evidence.get('upstream_commit') == commit, 'evidence pin mismatch')
    seen = set()
    counted = []
    for entry in evidence['records']:
        operation, candidate = entry['operation'], entry['candidate_sha256']
        require(operation in ids and operation not in seen and DIGEST.fullmatch(candidate),
                'unknown/duplicate operation or invalid candidate digest')
        seen.add(operation)
        archive_rel = entry['candidate_archive']
        require(archive_rel.startswith('dist/') and '..' not in Path(archive_rel).parts,
                'candidate archive must be in project dist')
        archive = ROOT / archive_rel
        require(archive.resolve().is_relative_to((ROOT / 'dist').resolve()) and
                hashlib.sha256(archive.read_bytes()).hexdigest() == candidate,
                'candidate archive digest mismatch')
        for language in ('python', 'typescript'):
            verified_report(entry, language, operation, commit, candidate)
        counted.append(operation)
    return sorted(counted)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--verify-upstream', action='store_true')
    parser.add_argument('--require-target', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    matrix = load(MATRIX)
    ids, counts = audit_matrix(matrix)
    verified_sources = verify_upstream(matrix) if args.verify_upstream else None
    counted = audit_evidence(load(EVIDENCE), matrix, ids)
    report = {'suite': 'e2b-compat-matrix-audit/v1',
              'upstream_commit': matrix['upstream']['commit'],
              'denominator': matrix['denominator'],
              'required_compatible': matrix['required_compatible'],
              'compatible': len(counted), 'compatible_ids': counted,
              'group_counts': counts, 'target_met': len(counted) >= matrix['required_compatible'],
              'upstream_sources_verified': verified_sources}
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    return 1 if args.require_target and not report['target_met'] else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (KeyError, TypeError, ValueError, OSError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as exc:
        print(f'E2B matrix invalid: {exc}', file=sys.stderr)
        sys.exit(2)
