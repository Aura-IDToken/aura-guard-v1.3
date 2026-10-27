"""Positive and negative controls for the bounded offline lockfile check."""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from check_known_rustsec_lock import scan_lock_bytes, version_tuple

SCRIPT = Path(__file__).with_name("check_known_rustsec_lock.py")


def lock(versions):
    text = "version = 4\n"
    for name, version in versions:
        text += f'\n[[package]]\nname = "{name}"\nversion = "{version}"\n'
    return text.encode()


class OfflineRustSecTests(unittest.TestCase):
    def test_upstream_baseline_is_blocked(self):
        report = scan_lock_bytes(lock([
            ("crypto-bigint", "0.5.5"), ("tokio", "1.52.3"),
            ("rustls-webpki", "0.103.13"), ("webpki-roots", "0.26.11"),
            ("webpki-roots", "1.0.7"),
        ]))
        self.assertEqual(report["status"], "BLOCKED_KNOWN_ADVISORIES")
        self.assertEqual(len(report["findings"]), 5)  # incl. re-export condition

    def test_patched_candidate_versions_pass_bounded_scope(self):
        report = scan_lock_bytes(lock([
            ("crypto-bigint", "0.7.7"), ("tokio", "1.54.1"),
            ("rustls-webpki", "0.103.16"), ("webpki-roots", "0.26.11"),
            ("webpki-roots", "1.0.10"),
        ]))
        self.assertEqual(report["status"], "PASS_FOUR_ADVISORIES_ONLY")
        self.assertEqual(report["findings"], [])

    def test_compat_root_without_patched_parent_is_rejected(self):
        report = scan_lock_bytes(lock([
            ("webpki-roots", "0.26.11"), ("webpki-roots", "1.0.7"),
        ]))
        self.assertEqual(report["status"], "BLOCKED_KNOWN_ADVISORIES")

    def test_malformed_or_prerelease_version_fails_closed(self):
        with self.assertRaises(ValueError):
            version_tuple("1.0.10-alpha")

    def test_wrong_pin_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "Cargo.lock"
            path.write_bytes(lock([("tokio", "1.54.1")]))
            process = subprocess.run(
                [sys.executable, str(SCRIPT), "--lockfile", str(path),
                 "--expected-sha256", "0" * 64],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(process.returncode, 0)
            self.assertIn('"status": "ERROR"', process.stdout)


if __name__ == "__main__":
    unittest.main()
