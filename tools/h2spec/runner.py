#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
h2spec HTTP/2 Conformance Test Runner for goose-wing.
Compiles and starts the native Goose HTTP/2 server, executes h2spec (RFC 9113 / RFC 7540),
and formats test outcomes.
"""

import argparse
import io
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

# Ensure UTF-8 output on Windows consoles
if isinstance(sys.stdout, io.TextIOWrapper) and sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if isinstance(sys.stderr, io.TextIOWrapper) and sys.stderr.encoding and sys.stderr.encoding.lower() != "utf-8":
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
TOOLS_DIR = ROOT_DIR / "tools"
BIN_DIR = TOOLS_DIR / "bin"
SERVER_SRC = TOOLS_DIR / "h2spec" / "server.goose"
SERVER_EXE = BIN_DIR / ("h2spec_server.exe" if sys.platform == "win32" else "h2spec_server")
H2SPEC_EXE = BIN_DIR / ("h2spec.exe" if sys.platform == "win32" else "h2spec")


def ensure_server_binary(force_rebuild: bool = False) -> Path:
    """Ensures the native Goose HTTP/2 server is compiled and ready."""
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    if not force_rebuild and SERVER_EXE.is_file():
        return SERVER_EXE

    print(f"[*] Building native HTTP/2 h2spec server: {SERVER_SRC} -> {SERVER_EXE}...")
    cmd = ["goose", "build", str(SERVER_SRC), "-o", str(SERVER_EXE), "-O2"]
    res = subprocess.run(cmd, check=False, cwd=str(ROOT_DIR), capture_output=True, text=True)
    if res.returncode != 0:
        print("[!] Failed to build h2spec server:", file=sys.stderr)
        if res.stdout:
            print(res.stdout, file=sys.stderr)
        if res.stderr:
            print(res.stderr, file=sys.stderr)
        sys.exit(1)

    print(f"[+] Successfully built {SERVER_EXE.name}")
    return SERVER_EXE


def find_h2spec() -> Path:
    """Locates h2spec binary in tools/bin or system PATH."""
    if H2SPEC_EXE.is_file() and os.access(H2SPEC_EXE, os.X_OK):
        return H2SPEC_EXE

    found = shutil.which("h2spec.exe" if sys.platform == "win32" else "h2spec")
    if found:
        return Path(found)

    print(
        "[!] h2spec binary not found! Please build or place it in tools/bin/h2spec.exe",
        file=sys.stderr,
    )
    sys.exit(1)


class GooseH2Server:
    """Coordinates lifecycle of the native Goose HTTP/2 server."""

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


def run_h2spec(
    spec_section: str = "generic",
    strict: bool = False,
    timeout_sec: int = 2,
    verbose: bool = False,
    force_rebuild: bool = False,
) -> int:
    """Executes h2spec against the server and prints formatted results."""
    server_exe = ensure_server_binary(force_rebuild=force_rebuild)
    h2spec_bin = find_h2spec()

    server = GooseH2Server(server_exe)
    print(f"[*] Starting native Goose HTTP/2 server ({server_exe.name})...")
    port = server.start()
    print(f"[+] Server listening on 127.0.0.1:{port}")

    cmd = [
        str(h2spec_bin),
        "-h",
        "127.0.0.1",
        "-p",
        str(port),
        "-P",
        "/ping",
        "-o",
        str(timeout_sec),
    ]
    if strict:
        cmd.append("-S")
    if verbose:
        cmd.append("-v")

    if spec_section and spec_section != "all":
        cmd.append(spec_section)

    print(f"[*] Executing h2spec: {' '.join(cmd[1:])}")
    try:
        t0 = time.time()
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
        dur = time.time() - t0
        print(f"[+] Completed in {dur:.2f}s\n")

        print(proc.stdout)
        if proc.stderr:
            print("[!] Standard Error:\n", proc.stderr, file=sys.stderr)

        return proc.returncode

    finally:
        server.stop()
        print("[+] Server stopped cleanly.")


def main():
    parser = argparse.ArgumentParser(
        description="Run h2spec HTTP/2 Conformance Testing against goose-wing",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "spec",
        nargs="?",
        default="generic",
        help="Spec section to test: generic, http2/3.5, http2/4.1, hpack, or all",
    )
    parser.add_argument("-S", "--strict", action="store_true", help="Run in strict mode")
    parser.add_argument(
        "-o", "--timeout", type=int, default=2, help="Timeout in seconds for each test"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose test log")
    parser.add_argument("--rebuild", action="store_true", help="Force rebuild server binary")

    args = parser.parse_args()
    rc = run_h2spec(
        spec_section=args.spec,
        strict=args.strict,
        timeout_sec=args.timeout,
        verbose=args.verbose,
        force_rebuild=args.rebuild,
    )
    sys.exit(rc)


if __name__ == "__main__":
    main()
