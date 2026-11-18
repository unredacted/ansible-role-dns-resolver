"""Fail on vulnerabilities in crates that are compiled into a binary.

Usage: runtime-advisories.py <cargo-audit.json> <runtime-crates.txt> <label>

cargo-audit.json is the output of `cargo audit --json` on the lockfile.
runtime-crates.txt has one `name@version` per line: the crates reached from the
binary through normal (not build or dev) dependencies, from `cargo tree -e
normal`.

Vulnerabilities in runtime crates fail the check. Vulnerabilities in crates
that are only used at build time, and warnings (unsound, unmaintained,
yanked), are printed but do not fail it.
"""

import json
import sys


def main(audit_path, runtime_path, label):
    report = json.load(open(audit_path))
    runtime = {line.strip() for line in open(runtime_path) if line.strip()}

    failures = []
    build_only = []
    for vuln in report.get("vulnerabilities", {}).get("list", []):
        pkg = vuln["package"]
        key = f"{pkg['name']}@{pkg['version']}"
        entry = f"{vuln['advisory']['id']} {key}: {vuln['advisory']['title']}"
        (failures if key in runtime else build_only).append(entry)

    warnings = []
    for kind, items in (report.get("warnings") or {}).items():
        for item in items:
            pkg = item.get("package", {})
            advisory = item.get("advisory") or {}
            warnings.append(f"{kind} {advisory.get('id', '')} {pkg.get('name')}@{pkg.get('version')}")

    for title, items in (
        ("build-time only (not in the binary)", build_only),
        ("warnings", warnings),
        ("VULNERABLE RUNTIME CRATES", failures),
    ):
        if items:
            print(f"{label}: {title}:")
            for item in sorted(set(items)):
                print(f"  {item}")

    if failures:
        sys.exit(1)
    print(f"{label}: no known vulnerabilities in runtime crates")


if __name__ == "__main__":
    main(*sys.argv[1:4])
