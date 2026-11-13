#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""Live Go <-> Wing TLS 1.3 + HTTP/2 + X.509 differential test harness."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def build_go_oracle(out_bin: Path) -> None:
    """Builds tests/fuzz/h2oracle offline using GOPROXY=off."""
    oracle_dir = REPO_ROOT / "tests" / "fuzz" / "h2oracle"
    env = os.environ.copy()
    env["GOPROXY"] = "off"
    res = subprocess.run(
        ["go", "build", "-o", str(out_bin), "."],
        cwd=oracle_dir,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        raise RuntimeError(
            f"go build h2oracle failed (exit {res.returncode}):\n{res.stderr}\n{res.stdout}"
        )


def build_wing_verdict(goose_bin: str, out_bin: Path) -> None:
    """Builds tests/fuzz/h2_tls_client_verdict.goose with stack headroom on Windows."""
    env = os.environ.copy()
    if sys.platform == "win32":
        stack_cc = REPO_ROOT / "tools" / "gcc_stack.bat"
        if stack_cc.exists():
            env["GOOSE_CC"] = str(stack_cc)
    src = REPO_ROOT / "tests" / "fuzz" / "h2_tls_client_verdict.goose"
    res = subprocess.run(
        [goose_bin, "build", "-O2", "-o", str(out_bin), str(src)],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        raise RuntimeError(
            f"goose build h2_tls_client_verdict failed (exit {res.returncode}):\n"
            f"{res.stderr}\n{res.stdout}"
        )


def encode_headers_hex(headers: dict[str, str] | None) -> str:
    """Encodes request headers map into lowercase hex of 'K: V\\n' lines, or '-'."""
    if not headers:
        return "-"
    lines = "".join(f"{k}: {v}\n" for k, v in sorted(headers.items()))
    return lines.encode("utf-8").hex()


def encode_body_hex(body: str) -> str:
    """Encodes request body string as lowercase hex, or '-' when empty."""
    if not body:
        return "-"
    return body.encode("utf-8").hex()


def format_cases_tsv(scenarios: list[dict]) -> str:
    """Formats manifest scenarios into TSV lines for h2_tls_client_verdict."""
    rows: list[str] = []
    for sc in scenarios:
        use_ca = "1" if sc.get("use_ca", False) else "0"
        hdr_hex = encode_headers_hex(sc.get("headers"))
        body_hex = encode_body_hex(sc.get("body", ""))
        check_hdr = sc.get("go_check_hdr") or {}
        hdr_csv = ",".join(sorted(check_hdr.keys())) if check_hdr else "-"
        rows.append(
            "\t".join(
                [
                    sc["name"],
                    use_ca,
                    sc["method"],
                    sc["url"],
                    hdr_hex,
                    body_hex,
                    hdr_csv,
                ]
            )
        )
    return "\n".join(rows) + "\n"


def parse_hdr_summary(raw: str) -> dict[str, str]:
    """Parses 'k=v;k2=v2' header summary field emitted by h2_tls_client_verdict."""
    if not raw or raw == "-":
        return {}
    out: dict[str, str] = {}
    for pair in raw.split(";"):
        if "=" not in pair:
            continue
        k, v = pair.split("=", 1)
        out[k.lower()] = v
    return out


def compare_verdicts(
    scenarios: list[dict],
    wing_stdout: str,
    verbose: bool,
) -> list[str]:
    """Compares Go oracle expectations against Wing stdout lines."""
    wing_map: dict[str, tuple[str, dict[str, str], str]] = {}
    for line in wing_stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        name = parts[0]
        verdict = parts[1]
        hdrs = parse_hdr_summary(parts[2] if len(parts) >= 3 else "-")
        detail = parts[3] if len(parts) >= 4 else ""
        wing_map[name] = (verdict, hdrs, detail)

    mismatches: list[str] = []
    for sc in scenarios:
        name = sc["name"]
        go_verdict = sc["go_verdict"]
        go_hdrs = {k.lower(): v for k, v in (sc.get("go_check_hdr") or {}).items()}
        if name not in wing_map:
            mismatches.append(f"{name}: missing Wing verdict (Go={go_verdict})")
            continue

        wing_verdict, wing_hdrs, detail = wing_map[name]
        hdr_ok = all(wing_hdrs.get(k) == v for k, v in go_hdrs.items())
        if wing_verdict != go_verdict or not hdr_ok:
            mismatches.append(
                f"{name}: mismatch\n"
                f"  Go  : {go_verdict} hdrs={go_hdrs}\n"
                f"  Wing: {wing_verdict} hdrs={wing_hdrs} detail={detail!r}"
            )
        elif verbose:
            suffix = f" ({detail})" if detail else ""
            print(f"[PASS] {name}: {wing_verdict}{suffix}")
    return mismatches


def run_differential(goose_bin: str, verbose: bool) -> int:
    """Builds and runs Go h2oracle against Wing h2_tls_client_verdict."""
    exe_suffix = ".exe" if sys.platform == "win32" else ""
    with tempfile.TemporaryDirectory(prefix="wing_h2_diff_") as tmp:
        tmp_dir = Path(tmp)
        oracle_bin = tmp_dir / f"h2oracle{exe_suffix}"
        wing_bin = tmp_dir / f"h2_tls_client_verdict{exe_suffix}"
        manifest_path = tmp_dir / "manifest.json"
        ca_path = tmp_dir / "ca.pem"
        cases_path = tmp_dir / "cases.tsv"

        print("Building Go h2oracle...")
        build_go_oracle(oracle_bin)
        print("Building Wing h2_tls_client_verdict...")
        build_wing_verdict(goose_bin, wing_bin)

        proc = subprocess.Popen(
            [str(oracle_bin), "-manifest", str(manifest_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            assert proc.stdout is not None
            ready = proc.stdout.readline().strip()
            if ready != "READY":
                stderr_out = proc.stderr.read() if proc.stderr else ""
                raise RuntimeError(f"h2oracle failed to become ready: {ready!r}\n{stderr_out}")

            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            ca_path.write_text(manifest["ca_pem"], encoding="utf-8")
            cases_path.write_text(format_cases_tsv(manifest["scenarios"]), encoding="utf-8")

            res = subprocess.run(
                [str(wing_bin), str(ca_path), str(cases_path)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if res.returncode != 0:
                raise RuntimeError(
                    f"h2_tls_client_verdict failed (exit {res.returncode}):\n"
                    f"{res.stderr}\n{res.stdout}"
                )
        finally:
            if proc.stdin:
                proc.stdin.close()
            proc.wait(timeout=10)
        oracle_stderr = proc.stderr.read() if proc.stderr else ""

        scenarios = manifest["scenarios"]
        mismatches = compare_verdicts(scenarios, res.stdout, verbose)
        if mismatches:
            if oracle_stderr.strip():
                print("ORACLE STDERR:\n" + oracle_stderr.strip())
            print("DIFFERENTIAL MISMATCHES:")
            for item in mismatches:
                print(item)
            return 1
        print(f"ALL {len(scenarios)} TLS 1.3 + HTTP/2 + X.509 DIFFERENTIAL SCENARIOS PASSED")
        return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Run live Go <-> Wing TLS 1.3 + HTTP/2 + X.509 differential tests."
    )
    ap.add_argument("-v", "--verbose", action="store_true", help="Print per-scenario verdicts")
    ap.add_argument("--goose", default=shutil.which("goose") or "goose", help="Path to goose CLI")
    args = ap.parse_args()
    return run_differential(args.goose, args.verbose)


if __name__ == "__main__":
    sys.exit(main())
