#!/usr/bin/env python3
"""Audit startup targets against hashed raw real-KVM evidence; absent is unmet."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import stat

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {'warm': ('warm_start_ms', 5, 9, 15, True),
           'cold': ('cold_boot_ms', 400, 600, 1000, True),
           'snapshot': ('snapshot_start_ms', 100, 150, 250, False)}
CASES = set('''pristine_single_checkout tenant_state_isolation input_readonly
unique_identity exclusive_owner orphan_reconciliation ttl capacity_accounting pool_exhaustion profile_mismatch
dead_vm_checkout refill_failure artifact_expiry template_rotation checkout_cancel
api_crash launcher_crash shutdown_zero_residue'''.split())


def require(value, message):
    if not value:
        raise ValueError(message)


def verified_file(relative, digest, prefix):
    path = (ROOT / relative).resolve()
    require(path.is_relative_to((ROOT / prefix).resolve()) and
            re.fullmatch('[0-9a-f]{64}', digest) is not None, 'invalid evidence path/hash')
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == digest, 'evidence hash mismatch')
    return data


def archive_hash(path, cache):
    path = path.resolve()
    require(path.is_relative_to((ROOT/'dist').resolve()), 'candidate must be in dist')
    before = path.stat()
    require(stat.S_ISREG(before.st_mode), 'candidate must be a regular file')
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    key = (str(path), identity)
    if key not in cache:
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(1 << 20), b''):
                digest.update(block)
        after = path.stat()
        require(identity == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                'candidate changed while verifying')
        cache[key] = digest.hexdigest()
    return cache[key]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--require-target', action='store_true')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--candidate', type=Path, help='require evidence for this exact candidate archive')
    args = parser.parse_args()
    contract = json.loads((ROOT / 'docs/contracts/warm-start-gates.json').read_text())
    require(contract['schema'] == 'osv-startup-gates/v1' and
            contract['minimum_samples'] == 1000 and
            contract['required_backend_arch'] == [['firecracker-linux', 'amd64'], ['firecracker-osv', 'amd64']] and
            set(contract['required_cases']) == CASES, 'startup contract scope drift')
    for mode, (metric, p50, p95, p99, required) in TARGETS.items():
        require(contract['paths'][mode] == dict(metric=metric, p50_ms=p50, p95_ms=p95,
                                               p99_ms=p99, required=required), 'startup threshold drift')
    passed = set()
    archives = {}
    requested_candidate = archive_hash(args.candidate, archives) if args.candidate else None
    measured_candidate = None
    for record in contract['evidence']:
        report = json.loads(verified_file(record['path'], record['sha256'], 'results'))
        key = (report['backend'], report['arch'], report['startup_mode'])
        require(key not in passed and key[2] in TARGETS, 'duplicate/unknown startup evidence')
        require(report['environment'] == 'real-kvm' and report['unqueued'] is True and
                report['production_doctor_ready'] is True, 'diagnostic or queued evidence cannot pass startup gate')
        digest = report['candidate_sha256']
        require(re.fullmatch('[0-9a-f]{64}', digest) is not None, 'invalid candidate evidence hash')
        require(requested_candidate is None or digest == requested_candidate,
                'startup evidence belongs to another candidate')
        require(measured_candidate is None or digest == measured_candidate,
                'startup routes mix different candidates')
        measured_candidate = digest
        require(archive_hash(ROOT/report['candidate_archive'], archives) == digest, 'evidence hash mismatch')
        for field in ('host_baseline_sha256', 'configuration_sha256', 'test_sha256'):
            require(re.fullmatch('[0-9a-f]{64}', report[field]) is not None, 'missing evidence binding')
        require(all(report['cases'].get(case) is True for case in CASES), 'startup safety case missing/failed')
        samples = json.loads(verified_file(report['samples_path'], report['samples_sha256'], 'results'))
        metric, p50, p95, p99, _ = TARGETS[key[2]]
        require(len(samples) >= 1000 and all(row.get('success') is True for row in samples), 'insufficient or failed samples')
        values = sorted(row[metric] for row in samples)
        require(all(type(x) in (int, float) and math.isfinite(x) and x >= 0 for x in values), 'invalid timing sample')
        for percentile, limit in ((0.5, p50), (0.95, p95), (0.99, p99)):
            require(values[math.ceil(len(values) * percentile) - 1] <= limit, 'startup percentile exceeded')
        require(all(field in report for field in ('peak_rss_bytes', 'reserved_memory_bytes',
                    'hit_rate', 'refill_p95_ms', 'throughput_per_second', 'failures', 'timeouts', 'rejections')),
                'missing capacity/health measurements')
        require(report['failures'] == report['timeouts'] == 0, 'failed requests omitted from latency gate')
        passed.add(key)
    needed = {(backend, arch, mode) for backend, arch in contract['required_backend_arch']
              for mode, target in TARGETS.items() if target[-1]}
    report = {'suite': 'startup-gates-audit/v1', 'target_met': needed <= passed,
              'passed': sorted(passed), 'missing': sorted(needed - passed),
              'candidate_sha256': measured_candidate, 'requested_candidate_sha256': requested_candidate}
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    return 1 if args.require_target and not report['target_met'] else 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, TypeError, OSError) as exc:
        raise SystemExit(f'startup gate invalid: {exc}')
