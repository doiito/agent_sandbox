"""A clean checkout must not make test allowance a formal release bypass."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ReleaseSecurityGateTests(unittest.TestCase):
    def run_builder(self, test_mode, profile='extended', startup_target=False):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            git = work/'git'
            git.write_text('''#!/bin/sh
case "$*" in
  *"rev-parse --verify HEAD") echo 0123456789abcdef0123456789abcdef01234567 ;;
  *"status --porcelain --untracked-files=all") exit 0 ;;
  *) exit 99 ;;
esac
''')
            git.chmod(0o755)
            # The release-profile test must not depend on the repository's
            # current benchmark receipts or proceed to build real payloads.
            python = work/'python3'
            audit = json.dumps({'suite': 'startup-gates-audit/v1', 'target_met': startup_target})
            python.write_text('''#!/bin/sh
case "$*" in
  *"scripts/check-startup-gates.py --require-target --candidate "*)
    printf '%s\\n' 'AUDIT'
    exit GATE_STATUS ;;
  *) exit 77 ;;
esac
'''.replace('AUDIT', audit).replace('GATE_STATUS', '0' if startup_target else '1'))
            python.chmod(0o755)
            env = dict(os.environ, PATH=str(work)+os.pathsep+os.environ['PATH'],
                RELEASE_ARCH='amd64', RELEASE_VERSION='security-gate-test',
                RELEASE_VALID_UNTIL='2099-01-01T00:00:00Z', RELEASE_OUTPUT=str(work/'formal.tar'),
                RELEASE_PRIVATE_KEY=str(work/'unused-key'), ARTIFACT_PRIVATE_KEY=str(work/'unused-key'),
                RELEASE_STARTUP_CANDIDATE=str(work/'startup.tar'),
                RELEASE_VALIDATED_CANDIDATE=str(work/'target.tar'),
                RELEASE_CANDIDATE_PUBLIC_KEY=str(work/'candidate.public'),
                RELEASE_ALLOW_DIRTY_TEST='1' if test_mode else '0',RELEASE_SECURITY_PROFILE=profile)
            for name in ('RELEASE_SECURITY_SNAPSHOT', 'RELEASE_SECURITY_SNAPSHOT_SHA256'):
                env.pop(name, None)
            return subprocess.run(['bash', str(ROOT/'scripts/build-offline-release.sh')],
                env=env, cwd=ROOT, capture_output=True, text=True, timeout=10)

    def test_clean_checkout_requires_security_evidence_before_payload_build(self):
        result = self.run_builder(False)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('formal release requires RELEASE_SECURITY_SNAPSHOT', result.stderr)

    def test_clean_checkout_test_allowance_cannot_emit_formal_filename(self):
        result = self.run_builder(True)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('dirty test candidate output must end in .test-signed.tar', result.stderr)

    def test_baseline_does_not_require_extended_scan(self):
        for target in (False, True):
            with self.subTest(startup_target=target):
                result=self.run_builder(False,'baseline',startup_target=target)
                self.assertNotIn('formal release requires RELEASE_SECURITY_SNAPSHOT',result.stderr)
                self.assertEqual(result.returncode,77 if target else 1,result.stderr)
                self.assertEqual(json.loads(result.stdout),{'suite':'startup-gates-audit/v1','target_met':target})

    def test_unknown_security_profile_is_rejected(self):
        result=self.run_builder(False,'unknown')
        self.assertEqual(result.returncode,2)
        self.assertIn('RELEASE_SECURITY_PROFILE must be baseline or extended',result.stderr)


if __name__ == '__main__':
    unittest.main()
