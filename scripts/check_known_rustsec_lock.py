#!/usr/bin/env python3
"""Bounded offline lockfile regression for 4 AURA RustSec findings.

Not a full advisory database scan, cargo-audit, or proof of zero vulnerabilities.
Requires Python 3.11+ stdlib only. No network or GitHub Actions required.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib

ADVISORIES = {
    "crypto-bigint": "RUSTSEC-2026-0387",
    "tokio": "RUSTSEC-2026-0386",
    "rustls-webpki": "RUSTSEC-2026-0382",
    "webpki-roots": "RUSTSEC-2026-0381",
}
VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


def version_tuple(text: str) -> tuple[int, int, int]:
    match = VERSION.fullmatch(text)
    if not match:
        raise ValueError(f"non-stable or malformed version needs manual review: {text!r}")
    return tuple(map(int, match.groups()))


def scan_lock_bytes(data: bytes) -> dict:
    parsed = tomllib.loads(data.decode("utf-8"))
    packages = parsed.get("package")
    if not isinstance(packages, list):
        raise ValueError("missing [[package]] entries in Cargo.lock")
    observed: dict[str, list[str]] = {name: [] for name in ADVISORIES}
    for pkg in packages:
        if not isinstance(pkg, dict):
            raise ValueError("invalid Cargo.lock package")
        name = pkg.get("name")
        if name in observed:
            version = pkg.get("version")
            if not isinstance(version, str):
                raise ValueError(f"{name}: missing version")
            observed[name].append(version)

    findings = []
    root_1x_fixed = any(version_tuple(v) >= (1, 0, 10)
                        for v in observed["webpki-roots"]
                        if version_tuple(v)[0] >= 1)
    for name, versions in observed.items():
        for version in versions:
            v = version_tuple(version)
            if name == "crypto-bigint":
                blocked = v < (0, 7, 6)
            elif name == "tokio":
                # Intentionally uses stricter Aura migration target 1.54.1.
                # This does not describe every RustSec-patched Tokio branch.
                blocked = v < (1, 54, 1)
            elif name == "rustls-webpki":
                blocked = v < (0, 103, 16)
            else:
                # webpki-roots 0.26.11 is a compatibility re-export,
                # independently safe only with a fixed 1.x dependency.
                blocked = not root_1x_fixed if v == (0, 26, 11) else v < (1, 0, 10)
            if blocked:
                findings.append({"package": name, "version": version,
                                 "advisory": ADVISORIES[name]})
    return {
        "status": "BLOCKED_KNOWN_ADVISORIES" if findings else "PASS_FOUR_ADVISORIES_ONLY",
        "scope": "four named advisories / Aura migration targets; not a complete RustSec scan",
        "versions": observed,
        "findings": sorted(findings, key=lambda x: (x["package"], x["version"])),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lockfile", type=Path, default=Path("Cargo.lock"))
    parser.add_argument("--expected-sha256", default=None)
    args = parser.parse_args()
    try:
        data = args.lockfile.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if args.expected_sha256 is not None and digest != args.expected_sha256.lower():
            raise ValueError("Cargo.lock raw SHA-256 does not match pinned input")
        result = scan_lock_bytes(data)
        result["cargo_lock_sha256"] = digest
    except (OSError, ValueError, UnicodeError, tomllib.TOMLDecodeError) as error:
        result = {"status": "ERROR", "reason": str(error)}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS_FOUR_ADVISORIES_ONLY" else 1


if __name__ == "__main__":
    sys.exit(main())
