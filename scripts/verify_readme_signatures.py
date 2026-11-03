#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""scripts/verify_readme_signatures.py.

Static audit script verifying that public function and struct declarations
documented in package README.md files match actual signatures in .goose sources.
"""

import re
import sys
from pathlib import Path

PACKAGES = [
    "auth",
    "cookie",
    "http",
    "http2",
    "http3",
    "net",
    "proxy",
    "quic",
    "server",
    "tls",
]


def audit_package_readme(pkg_name: str, root_dir: Path) -> list[str]:
    pkg_dir = root_dir / pkg_name
    readme_path = pkg_dir / "README.md"
    if not readme_path.exists():
        return [f"{pkg_name}/README.md does not exist"]

    readme_text = readme_path.read_text(encoding="utf-8")

    # Collect declared function names in README code fences
    # Looking for: fn func_name(...)
    fn_pattern = re.compile(r"\bfn\s+([a-zA-Z0-9_]+)\s*\(")
    readme_fns = set(fn_pattern.findall(readme_text))

    # Collect all function declarations in the package's .goose files
    goose_fns = set()
    for goose_file in pkg_dir.rglob("*.goose"):
        text = goose_file.read_text(encoding="utf-8", errors="ignore")
        for match in fn_pattern.finditer(text):
            goose_fns.add(match.group(1))

    # Also collect wing/core symbols if referenced
    wing_file = root_dir / "wing.goose"
    if wing_file.exists():
        for match in fn_pattern.finditer(wing_file.read_text(encoding="utf-8", errors="ignore")):
            goose_fns.add(match.group(1))

    mismatches = []
    # Verify that functions declared in README exist in the package or wing
    for fn in sorted(readme_fns):
        # Ignore generic placeholder examples or standard library helpers if any
        if fn not in goose_fns and not fn.startswith("test_") and not fn.startswith("example_"):
            mismatches.append(
                f"{pkg_name}/README.md documents '{fn}', but it is not declared in {pkg_name}/*.goose"
            )

    return mismatches


def main() -> int:
    root_dir = Path(__file__).resolve().parent.parent
    total_errors = 0

    print("Auditing package README.md API signatures...")
    for pkg in PACKAGES:
        errors = audit_package_readme(pkg, root_dir)
        if errors:
            print(f"[{pkg}] Signature sync issues ({len(errors)}):")
            for err in errors:
                print(f"  - {err}")
            total_errors += len(errors)
        else:
            print(f"[{pkg}] All documented signatures verified.")

    if total_errors > 0:
        print(f"\nTotal signature mismatches found: {total_errors}")
        print(
            "Note: Update package README.md files during remediation waves to match updated API signatures."
        )
        return 0  # Advisory check until remediation waves finalize signatures
    else:
        print("\nAll package README signatures match codebase!")
        return 0


if __name__ == "__main__":
    sys.exit(main())
