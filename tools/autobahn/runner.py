#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
Autobahn WebSocket Testsuite Runner for goose-wing.
Launches the native Goose WebSocket server, executes the Autobahn conformance
test cases using the native runner (kosoku / wstest), parses report artifacts,
and formats a complete RFC 6455 compliance report.
"""

import argparse
import io
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

# Ensure UTF-8 output on Windows consoles
if (
    isinstance(sys.stdout, io.TextIOWrapper)
    and sys.stdout.encoding
    and sys.stdout.encoding.lower() != "utf-8"
):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if (
    isinstance(sys.stderr, io.TextIOWrapper)
    and sys.stderr.encoding
    and sys.stderr.encoding.lower() != "utf-8"
):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
TOOLS_DIR = ROOT_DIR / "tools"
BIN_DIR = TOOLS_DIR / "bin"
SERVER_SRC = TOOLS_DIR / "autobahn" / "server.goose"
SERVER_EXE = BIN_DIR / ("autobahn_server.exe" if sys.platform == "win32" else "autobahn_server")
KOSOKU_EXE = BIN_DIR / ("kosoku.exe" if sys.platform == "win32" else "kosoku")
DEFAULT_OUT_DIR = ROOT_DIR / "reports" / "autobahn"


def ensure_server_binary(force_rebuild: bool = False) -> Path:
    """Ensures the native Goose Autobahn server is compiled and ready."""
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    if not force_rebuild and SERVER_EXE.is_file() and SERVER_EXE.stat().st_mtime >= SERVER_SRC.stat().st_mtime:
        return SERVER_EXE

    print(f"[*] Building native Autobahn WebSocket server: {SERVER_SRC} -> {SERVER_EXE}...")
    env = os.environ.copy()
    if sys.platform == "win32":
        gcc_wrapper = ROOT_DIR / "tools" / "gcc_noavx.cmd"
        if gcc_wrapper.is_file():
            env["GOOSE_CC"] = str(gcc_wrapper)
    cmd = ["goose", "build", str(SERVER_SRC), "-o", str(SERVER_EXE), "-O2"]
    res = subprocess.run(cmd, check=False, cwd=str(ROOT_DIR), capture_output=True, text=True, env=env)
    if res.returncode != 0:
        print("[!] Failed to build Autobahn server:", file=sys.stderr)
        if res.stdout:
            print(res.stdout, file=sys.stderr)
        if res.stderr:
            print(res.stderr, file=sys.stderr)
        sys.exit(1)

    print(f"[+] Successfully built {SERVER_EXE.name}")
    return SERVER_EXE


def find_test_runner(prefer_docker: bool = False) -> tuple[str, list[str]]:
    """
    Finds available test runner:
      1. If prefer_docker: Docker crossbario/autobahn-testsuite
      2. Local tools/bin/kosoku
      3. System kosoku
      4. System wstest (autobahntestsuite)
      5. Docker crossbario/autobahn-testsuite
    """
    which_docker = shutil.which("docker")
    if prefer_docker and which_docker:
        return "docker", [which_docker]

    if KOSOKU_EXE.is_file() and os.access(KOSOKU_EXE, os.X_OK):
        return "kosoku", [str(KOSOKU_EXE)]

    which_kosoku = shutil.which("kosoku")
    if which_kosoku:
        return "kosoku", [which_kosoku]

    which_wstest = shutil.which("wstest")
    if which_wstest:
        return "wstest", [which_wstest]

    if which_docker:
        return "docker", [which_docker]

    print(
        "[!] No Autobahn runner found! Looked for kosoku, wstest, or docker.",
        file=sys.stderr,
    )
    print("    Install kosoku via: pip install kosoku", file=sys.stderr)
    sys.exit(1)


class GooseAutobahnServer:
    """Coordinates lifecycle of the native Goose WebSocket server."""

    def __init__(self, binary_path: Path):
        self.binary_path = binary_path
        self.proc: subprocess.Popen | None = None
        self.port: int = 0

    def start(self, timeout: float = 5.0) -> int:
        self.proc = subprocess.Popen(
            [str(self.binary_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            cwd=str(ROOT_DIR),
        )
        assert self.proc and self.proc.stdout and self.proc.stderr

        t_start = time.time()
        while time.time() - t_start < timeout:
            line = self.proc.stdout.readline()
            if "READY_PORT:" in line:
                self.port = int(line.strip().split("READY_PORT:")[1])
                return self.port
            if self.proc.poll() is not None:
                err = self.proc.stderr.read()
                raise RuntimeError(
                    f"Server exited immediately with code {self.proc.returncode}: {err}"
                )
            time.sleep(0.02)

        self.stop()
        raise TimeoutError(f"Server did not print READY_PORT within {timeout}s")

    def stop(self):
        if not self.proc:
            return

        # Try clean HTTP shutdown trigger
        if self.port > 0:
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{self.port}/shutdown", timeout=0.5)
            except Exception:
                pass

        try:
            self.proc.terminate()
            self.proc.wait(timeout=1.0)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass
        self.proc = None


CATEGORY_NAMES = {
    "1": "Framing Basics (Echo / Sizes 0B..1MB)",
    "2": "Pings & Pongs (Heartbeats & Invariants)",
    "3": "Reserved Bits (RSV1..3 Zero Enforcement)",
    "4": "Opcodes (Control & Reserved Rejection)",
    "5": "Fragmentation (Interleaved Control Frames)",
    "6": "UTF-8 Validation (RFC 3629 Conformance)",
    "7": "Close Handshake (Codes, Reasons)",
    "9": "Limits & Performance (High Throughput)",
    "10": "Miscellaneous & Reporting",
    "12": "WebSocket Compression (RFC 7692 Deflate)",
    "13": "WebSocket Compression Context Takeover",
}


def print_summary_table(results_dir: Path) -> tuple[int, int, int]:
    """Parses index.json report and displays a formatted compliance breakdown."""
    index_file = results_dir / "index.json"
    if not index_file.is_file():
        print(f"[!] Report index not found at {index_file}")
        return 0, 0, 0

    with open(index_file, encoding="utf-8") as f:
        data = json.load(f)

    if not data:
        print("[!] Empty report data")
        return 0, 0, 0

    agent = next(iter(data.keys()))
    case_results = data[agent]

    categories: dict[str, list[tuple[str, dict]]] = {}
    for case_id, res in case_results.items():
        cat = case_id.split(".")[0]
        categories.setdefault(cat, []).append((case_id, res))

    print("\n" + "=" * 86)
    print(" Autobahn WebSocket Testsuite (RFC 6455) Compliance Report")
    print("=" * 86)
    print(
        f"{'Category':<8} | {'Description':<42} | {'Total':>5} | {'Passed':>6} | {'Status'}"
    )
    print("-" * 86)

    total_passed = 0
    total_non_strict = 0
    total_informational = 0
    total_unimplemented = 0
    total_failed = 0
    total_count = 0

    for cat_num in sorted(categories.keys(), key=lambda x: int(x)):
        items = categories[cat_num]
        desc = CATEGORY_NAMES.get(cat_num, "Extension / Miscellaneous")
        cat_total = len(items)
        cat_passed = 0
        cat_non_strict = 0
        cat_info = 0
        cat_unimpl = 0
        cat_failed = 0

        for _, res in items:
            b = res.get("behavior", "")
            bc = res.get("behaviorClose", "")
            if b == "OK" and bc in ("OK", "INFORMATIONAL"):
                cat_passed += 1
            elif b == "NON-STRICT" or bc == "NON-STRICT":
                cat_non_strict += 1
            elif b == "INFORMATIONAL" or bc == "INFORMATIONAL":
                cat_info += 1
            elif b == "UNIMPLEMENTED":
                cat_unimpl += 1
            else:
                cat_failed += 1

        total_count += cat_total
        total_passed += cat_passed
        total_non_strict += cat_non_strict
        total_informational += cat_info
        total_unimplemented += cat_unimpl
        total_failed += cat_failed

        ok_total = cat_passed + cat_non_strict + cat_info
        if cat_failed > 0:
            status = f"{cat_failed} FAILED"
        elif cat_unimpl == cat_total and cat_total > 0:
            status = f"{cat_unimpl} UNIMPL"
        elif cat_unimpl > 0:
            status = f"OK ({cat_unimpl} UNIMPL)"
        else:
            status = "100% OK"
        print(
            f"{cat_num:<8} | {desc:<42} | {cat_total:>5} | {ok_total:>6} | {status}"
        )

    print("=" * 86)
    print(
        f"TOTAL: {total_count} | PASSED: {total_passed} | "
        f"NON-STRICT: {total_non_strict} | INFO: {total_informational} | "
        f"UNIMPL: {total_unimplemented} | FAILED: {total_failed}"
    )

    implemented_total = total_count - total_unimplemented
    passed_total = total_passed + total_non_strict + total_informational
    if implemented_total > 0:
        compliance_pct = passed_total / implemented_total * 100
        print(
            f"Implemented Cases Compliance: {compliance_pct:.1f}% "
            f"({passed_total}/{implemented_total})"
        )
    else:
        print(
            f"Implemented Cases Compliance: N/A "
            f"(0 implemented, {total_unimplemented} UNIMPL)"
        )
    print(
        f"Detailed HTML Reports: file:///{(results_dir.resolve() / 'index.html').as_posix()}"
    )
    print("=" * 86 + "\n")

    return (
        total_count,
        total_passed + total_non_strict + total_informational,
        total_failed,
    )


def run_autobahn(
    cases: list[str] | None = None,
    exclude: list[str] | None = None,
    parallelism: int = 1,
    out_dir: Path = DEFAULT_OUT_DIR,
    force_rebuild: bool = False,
    prefer_docker: bool = False,
) -> int:
    """Executes the Autobahn test suite against the native server."""
    server_exe = ensure_server_binary(force_rebuild=force_rebuild)
    runner_type, runner_cmd = find_test_runner(prefer_docker=prefer_docker)

    out_dir.mkdir(parents=True, exist_ok=True)

    server = GooseAutobahnServer(server_exe)
    print(f"[*] Starting native Goose WebSocket server ({server_exe.name})...")
    port = server.start()
    print(f"[+] Server listening on 127.0.0.1:{port}")

    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"

    try:
        t0 = time.time()
        if runner_type == "kosoku":
            cmd = [
                runner_cmd[0],
                "-m",
                "fuzzingclient",
                "-p",
                str(parallelism),
                "-o",
                str(out_dir),
            ]
            if cases:
                for c in cases:
                    cmd.extend(["-i", c])

            if exclude:
                for x in exclude:
                    cmd.extend(["-x", x])

            cmd.append(f"127.0.0.1:{port}")

            print(f"[*] Running Autobahn via kosoku ({' '.join(cmd[1:])})...")
            proc = subprocess.run(cmd, check=False, env=env, capture_output=True, text=True)
            elapsed = time.time() - t0
            print(f"[+] Finished test execution in {elapsed:.2f}s")
            if proc.stdout:
                for line in proc.stdout.strip().splitlines()[-5:]:
                    print("   ", line)

        elif runner_type == "wstest":
            spec_file = out_dir / "fuzzingclient.json"
            spec = {
                "outdir": str(out_dir),
                "servers": [{"url": f"ws://127.0.0.1:{port}"}],
                "cases": cases or ["*"],
                "exclude-cases": exclude or [],
            }
            with open(spec_file, "w", encoding="utf-8") as f:
                json.dump(spec, f, indent=2)

            cmd = [runner_cmd[0], "-m", "fuzzingclient", "-s", str(spec_file)]
            print("[*] Running Autobahn via wstest...")
            proc = subprocess.run(cmd, check=False, env=env, capture_output=True, text=True)
            elapsed = time.time() - t0
            print(f"[+] Finished wstest execution in {elapsed:.2f}s")

        elif runner_type == "docker":
            spec_file = out_dir / "fuzzingclient.json"
            host_target = (
                "host.docker.internal" if sys.platform in ("win32", "darwin") else "172.17.0.1"
            )
            spec = {
                "outdir": "/reports",
                "servers": [{"url": f"ws://{host_target}:{port}"}],
                "cases": cases or ["*"],
                "exclude-cases": exclude or [],
            }
            with open(spec_file, "w", encoding="utf-8") as f:
                json.dump(spec, f, indent=2)

            spec_posix = str(spec_file.resolve()).replace("\\", "/")
            out_posix = str(out_dir.resolve()).replace("\\", "/")

            cmd = [
                runner_cmd[0],
                "run",
                "--rm",
                "--add-host=host.docker.internal:host-gateway",
                "-v",
                f"{spec_posix}:/config/fuzzingclient.json:ro",
                "-v",
                f"{out_posix}:/reports",
                "crossbario/autobahn-testsuite",
                "wstest",
                "-m",
                "fuzzingclient",
                "-s",
                "/config/fuzzingclient.json",
            ]
            print("[*] Running Autobahn via Docker (crossbario/autobahn-testsuite)...")
            proc = subprocess.run(cmd, check=False)
            elapsed = time.time() - t0
            print(f"[+] Finished Docker Autobahn execution in {elapsed:.2f}s")

        else:
            print(
                f"[!] Unknown runner type: {runner_type}",
                file=sys.stderr,
            )
            return 1

    finally:
        server.stop()
        print("[+] Server stopped cleanly.")

    # Parse and print summary
    _, _, failed = print_summary_table(out_dir)
    return 1 if failed > 0 else 0


def main():
    parser = argparse.ArgumentParser(
        description="Run Autobahn WebSocket Conformance Testsuite against goose-wing",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-i",
        "--include",
        action="append",
        dest="cases",
        help="Case or glob to include (e.g. 1.*, 6.4.1)",
    )
    parser.add_argument(
        "-x",
        "--exclude",
        action="append",
        dest="exclude",
        help="Case or glob to exclude",
    )
    parser.add_argument(
        "-p", "--parallelism", type=int, default=1, help="Max test cases in parallel"
    )
    parser.add_argument(
        "-o",
        "--outdir",
        type=Path,
        default=DEFAULT_OUT_DIR,
        help="Directory to store reports",
    )
    parser.add_argument(
        "--rebuild",
        action="store_true",
        help="Force rebuild of native goose server executable",
    )
    parser.add_argument(
        "--docker",
        action="store_true",
        help="Run Autobahn fuzzing client via official Docker image (crossbario/autobahn-testsuite)",
    )
    parser.add_argument(
        "--compose",
        action="store_true",
        help="Launch full Autobahn stack (native server + fuzzing client) via docker-compose",
    )

    args = parser.parse_args()

    if args.compose:
        compose_file = TOOLS_DIR / "autobahn" / "docker-compose.yml"
        cmd = [
            "docker",
            "compose",
            "-f",
            str(compose_file),
            "up",
            "--build",
            "--abort-on-container-exit",
            "--exit-code-from",
            "autobahn-fuzzer",
        ]
        print(f"[*] Running Autobahn via docker-compose ({compose_file.name})...")
        res = subprocess.run(cmd, check=False, cwd=str(ROOT_DIR))
        total, _, failed = print_summary_table(DEFAULT_OUT_DIR)
        sys.exit(0 if res.returncode == 0 and total > 0 and failed == 0 else 1)

    rc = run_autobahn(
        cases=args.cases,
        exclude=args.exclude,
        parallelism=args.parallelism,
        out_dir=args.outdir,
        force_rebuild=args.rebuild,
        prefer_docker=args.docker,
    )
    sys.exit(rc)


if __name__ == "__main__":
    main()
