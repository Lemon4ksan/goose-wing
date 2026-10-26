#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
tools/licensing.py
Automated license header enforcement and validation tool for goose-wing.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Lemon4ksan

Usage:
    python tools/licensing.py            # Apply license headers to all tracked source files
    python tools/licensing.py --check    # Verify that all files have valid headers (CI mode)
    python tools/licensing.py --dry-run  # Preview changes without modifying files
    python tools/licensing.py --ext .goose # Process only .goose files
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

# Mapping of file extensions to comment prefix style
COMMENT_STYLES: dict[str, str] = {
    # C-family / Goose: //
    ".goose": "//",
    ".c": "//",
    ".cpp": "//",
    ".h": "//",
    ".hpp": "//",
    ".js": "//",
    ".css": "//",
    ".build": "//",
    # Scripting: #
    ".py": "#",
    ".sh": "#",
    ".ps1": "#",
    # Batch: ::
    ".bat": "::",
    ".cmd": "::",
    # Lua: --
    ".lua": "--",
}

# License header lines (without comment prefix)
HEADER_LINES = [
    "SPDX-License-Identifier: Apache-2.0",
    "Copyright (c) 2026 Lemon4ksan",
]


def get_tracked_files(repo_root: Path) -> list[Path]:
    """Retrieves all tracked git files or falls back to directory walk."""
    try:
        out = subprocess.check_output(
            ["git", "ls-files"],
            cwd=str(repo_root),
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        files = [repo_root / line.strip() for line in out.splitlines() if line.strip()]
        return [f for f in files if f.is_file()]
    except Exception:
        # Fallback directory walk
        ignored_dirs = {
            ".git",
            "vendor",
            "scratch",
            "bin",
            ".gemini",
            ".vscode",
            "node_modules",
            "target",
        }
        res: list[Path] = []
        for root, dirs, filenames in os.walk(repo_root):
            dirs[:] = [d for d in dirs if d not in ignored_dirs]
            for fn in filenames:
                res.append(Path(root) / fn)
        return res


def build_license_header(prefix: str, newline: str) -> str:
    """Builds the formatted header block with trailing blank line."""
    lines = [f"{prefix} {line}" for line in HEADER_LINES]
    return newline.join(lines) + newline + newline


def has_license_header(content: str, prefix: str) -> bool:
    """Checks whether the file already has a valid SPDX and Copyright header."""
    expected_spdx = f"{prefix} SPDX-License-Identifier: Apache-2.0"
    expected_cr = f"{prefix} Copyright (c) 2026 Lemon4ksan"
    return expected_spdx in content and expected_cr in content


def detect_newline(content: str) -> str:
    """Detects primary newline style in file, defaulting to \\n."""
    crlf_count = content.count("\r\n")
    lf_count = content.count("\n") - crlf_count
    return "\r\n" if crlf_count > lf_count else "\n"


def process_file(
    file_path: Path, check_only: bool, dry_run: bool, verbose: bool
) -> tuple[bool, str]:
    """
    Processes a single file.
    Returns (ok, message).
    ok is False if header is missing in check_only mode.
    """
    ext = file_path.suffix.lower()
    prefix = COMMENT_STYLES.get(ext)
    if not prefix:
        return True, "skipped (unsupported extension)"

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception as e:
        return False, f"error reading file: {e}"

    if has_license_header(content, prefix):
        return True, "already licensed"

    if check_only:
        return False, "missing license header"

    newline = detect_newline(content)
    header = build_license_header(prefix, newline)

    # Check for shebang on first line
    new_content = ""
    if content.startswith("#!"):
        parts = content.split(newline, 1)
        shebang = parts[0]
        rest = parts[1] if len(parts) > 1 else ""
        new_content = shebang + newline + newline + header + rest
    else:
        new_content = header + content

    if dry_run:
        return True, "would add license header"

    try:
        with open(file_path, "w", encoding="utf-8", newline="") as f:
            f.write(new_content)
        return True, "added license header"
    except Exception as e:
        return False, f"error writing file: {e}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Enforce license headers across goose-wing codebase."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check headers without modifying files (returns 1 on violation).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview file modifications without writing to disk.",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Show all files scanned.")
    parser.add_argument(
        "--ext",
        action="append",
        help="Filter by specific extension (e.g. --ext .goose). Can be specified multiple times.",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Optional specific paths/files to process (default: all tracked files).",
    )

    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent

    target_files: list[Path] = []
    if args.paths:
        for p in args.paths:
            path_obj = Path(p).resolve()
            if path_obj.is_file():
                target_files.append(path_obj)
            elif path_obj.is_dir():
                for root, _, filenames in os.walk(path_obj):
                    for fn in filenames:
                        target_files.append(Path(root) / fn)
    else:
        target_files = get_tracked_files(repo_root)

    # Filter by extensions if provided
    allowed_exts = set(args.ext) if args.ext else None

    processed_count = 0
    updated_count = 0
    already_licensed_count = 0
    violation_count = 0
    skipped_count = 0

    for file_path in target_files:
        ext = file_path.suffix.lower()
        if ext not in COMMENT_STYLES:
            skipped_count += 1
            continue

        if allowed_exts and ext not in allowed_exts:
            skipped_count += 1
            continue

        processed_count += 1
        ok, msg = process_file(
            file_path, check_only=args.check, dry_run=args.dry_run, verbose=args.verbose
        )

        rel_path = (
            file_path.relative_to(repo_root) if file_path.is_relative_to(repo_root) else file_path
        )

        if not ok:
            violation_count += 1
            print(f"[FAIL] {rel_path}: {msg}")
        elif msg == "already licensed":
            already_licensed_count += 1
            if args.verbose:
                print(f"[OK]   {rel_path}: {msg}")
        elif "added" in msg or "would add" in msg:
            updated_count += 1
            print(f"[APPLY] {rel_path}: {msg}")
        else:
            if args.verbose:
                print(f"[SKIP] {rel_path}: {msg}")

    print("\n" + "=" * 60)
    print(" goose-wing Licensing Tool Summary")
    print("=" * 60)
    print(f" Total files examined : {processed_count}")
    print(f" Already licensed     : {already_licensed_count}")
    print(f" Updated / Added      : {updated_count}")
    print(f" Violations (missing) : {violation_count}")
    print(f" Skipped non-source   : {skipped_count}")
    print("=" * 60)

    if args.check and violation_count > 0:
        print(f"\nERROR: {violation_count} file(s) are missing required license headers.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
