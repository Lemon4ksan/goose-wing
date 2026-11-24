#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
quic-interop-runner (`marten-seemann/quic-interop-runner`) local & Docker
orchestrator for `goose-wing`.

Compiles `tools/quic_interop/endpoint.goose` and runs live loopback UDP
self-interop scenarios (`handshake`, `transfer`, `retry`, `keyupdate`,
`chacha20`, `http3`) with SHA-256 integrity and `SSLKEYLOGFILE` verification.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

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

SUITE_DIR = Path(__file__).resolve().parent
ROOT_DIR = SUITE_DIR.parent.parent
BIN_DIR = ROOT_DIR / "tools" / "bin"
ENDPOINT_SRC = SUITE_DIR / "endpoint.goose"
ENDPOINT_EXE = BIN_DIR / (
    "quic_interop_endpoint.exe" if sys.platform == "win32" else "quic_interop_endpoint"
)
EDGE_H3_SRC = SUITE_DIR / "edge_h3_server.goose"
EDGE_H3_EXE = BIN_DIR / (
    "edge_h3_server.exe" if sys.platform == "win32" else "edge_h3_server"
)
RUN_ENDPOINT_SH = SUITE_DIR / "run_endpoint.sh"
CURL_HTTP3_IMAGE = "ghcr.io/macbre/curl-http3:latest"

LOCAL_SCENARIOS: list[tuple[str, str, int]] = [
    ("handshake", "handshake.bin", 0),
    ("transfer", "payload_transfer.bin", 32768),
    ("retry", "payload_retry.bin", 16384),
    ("keyupdate", "payload_keyupdate.bin", 24576),
    ("chacha20", "payload_chacha20.bin", 20480),
    ("http3", "payload_http3.bin", 16384),
]

SUPPORTED_CONTRACT_TESTCASES = (
    "handshake",
    "transfer",
    "retry",
    "resumption",
    "keyupdate",
    "chacha20",
    "multiconnect",
    "zerortt",
    "http3",
)


def _build_goose_binary(
    src: Path, exe: Path, label: str, force_rebuild: bool = False
) -> Path:
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    if (
        not force_rebuild
        and exe.is_file()
        and exe.stat().st_mtime >= src.stat().st_mtime
    ):
        return exe

    print(f"[*] Building {label}: {src.name} -> {exe.name}...")
    env = os.environ.copy()
    opt_flag = "-O2"
    if sys.platform == "win32":
        opt_flag = "-O0"
        if "GOOSE_CC" not in env:
            stack_cc = ROOT_DIR / "tools" / "gcc_stack.bat"
            if stack_cc.is_file():
                env["GOOSE_CC"] = str(stack_cc)
    cmd = ["goose", "build", opt_flag, "-o", str(exe), str(src)]
    res = subprocess.run(
        cmd, check=False, cwd=str(ROOT_DIR), capture_output=True, text=True, env=env
    )
    if res.returncode != 0:
        print(f"[!] Failed to build {label}:\n{res.stdout}\n{res.stderr}", file=sys.stderr)
        sys.exit(1)
    print(f"[+] Built {exe.name}")
    return exe


def ensure_endpoint_binary(force_rebuild: bool = False) -> Path:
    return _build_goose_binary(
        ENDPOINT_SRC, ENDPOINT_EXE, "QUIC interop endpoint", force_rebuild
    )


def ensure_edge_h3_binary(force_rebuild: bool = False) -> Path:
    return _build_goose_binary(
        EDGE_H3_SRC, EDGE_H3_EXE, "H3EdgeSession server", force_rebuild
    )


class InteropEndpointServer:
    def __init__(
        self, exe: Path, www_dir: Path, testcase: str, keylog_path: Path
    ) -> None:
        self.exe = exe
        self.www_dir = www_dir
        self.testcase = testcase
        self.keylog_path = keylog_path
        self.proc: subprocess.Popen[str] | None = None
        self.port: int = 0

    def start(self, timeout: float = 5.0) -> int:
        self.proc = subprocess.Popen(
            [
                str(self.exe),
                "server",
                "0",
                str(self.www_dir),
                self.testcase,
                str(self.keylog_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            cwd=str(ROOT_DIR),
        )
        assert self.proc.stdout and self.proc.stderr
        t0 = time.time()
        while time.time() - t0 < timeout:
            line = self.proc.stdout.readline()
            if "READY_PORT:" in line:
                self.port = int(line.strip().split("READY_PORT:")[1])
                return self.port
            if self.proc.poll() is not None:
                err = self.proc.stderr.read()
                raise RuntimeError(
                    f"endpoint server exited ({self.proc.returncode}): {err}"
                )
            time.sleep(0.01)
        self.stop()
        raise TimeoutError(f"endpoint server did not print READY_PORT within {timeout}s")

    def stop(self) -> None:
        if not self.proc:
            return
        if self.port > 0:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(0.5)
                    s.sendto(b"SHUTDOWN", ("127.0.0.1", self.port))
                    s.recvfrom(64)
            except Exception:
                pass
        try:
            self.proc.terminate()
            self.proc.wait(timeout=1.5)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass
        self.proc = None


def _make_deterministic_payload(seed_tag: str, size: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < size:
        block = hashlib.sha256(f"{seed_tag}:{counter}".encode("ascii")).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:size])


def _verify_run_endpoint_contract() -> tuple[bool, str]:
    if not RUN_ENDPOINT_SH.is_file():
        return False, "run_endpoint.sh missing"
    text = RUN_ENDPOINT_SH.read_text(encoding="utf-8")
    missing = [tc for tc in SUPPORTED_CONTRACT_TESTCASES if tc not in text]
    has_127 = "exit 127" in text
    has_vars = all(
        v in text
        for v in ("ROLE", "TESTCASE", "SSLKEYLOGFILE", "/www", "/downloads", "USE_EDGE_H3")
    )
    if missing or not has_127 or not has_vars:
        return False, f"missing={missing} has_127={has_127} has_vars={has_vars}"
    return True, "9 testcases + ROLE/SSLKEYLOGFILE/USE_EDGE_H3/www/downloads + exit 127"


def run_local_interop(
    selected_testcase: str = "",
    rebuild: bool = False,
) -> int:
    exe = ensure_endpoint_binary(force_rebuild=rebuild)
    scenarios = [
        sc for sc in LOCAL_SCENARIOS if not selected_testcase or sc[0] == selected_testcase
    ]
    if not scenarios:
        print(f"[!] Unknown local testcase: {selected_testcase}", file=sys.stderr)
        return 127

    passed = 0
    failed = 0
    print("\nExecuting quic-interop-runner Local Loopback Self-Interop Suite...")

    ok_contract, detail_contract = _verify_run_endpoint_contract()
    if ok_contract:
        passed += 1
        print(f"  [PASS] [contract ] run_endpoint.sh       -> {detail_contract}")
    else:
        failed += 1
        print(f"  [FAIL] [contract ] run_endpoint.sh       -> {detail_contract}")

    with tempfile.TemporaryDirectory(prefix="wing_qir_") as tmp_root:
        root = Path(tmp_root)
        www_dir = root / "www"
        dl_dir = root / "downloads"
        www_dir.mkdir()
        dl_dir.mkdir()

        for testcase, fname, size in scenarios:
            exp_sha = ""
            if size > 0:
                payload = _make_deterministic_payload(testcase, size)
                (www_dir / fname).write_bytes(payload)
                exp_sha = hashlib.sha256(payload).hexdigest()
            else:
                exp_sha = hashlib.sha256(b"HANDSHAKE_OK").hexdigest()

            srv_keylog = root / f"{testcase}_srv.keylog"
            cli_keylog = root / f"{testcase}_cli.keylog"
            srv = InteropEndpointServer(exe, www_dir, testcase, srv_keylog)
            port = srv.start()
            try:
                res = subprocess.run(
                    [
                        str(exe),
                        "client",
                        "127.0.0.1",
                        str(port),
                        str(dl_dir),
                        testcase,
                        fname,
                        str(cli_keylog),
                    ],
                    cwd=str(ROOT_DIR),
                    capture_output=True,
                    text=True,
                    timeout=20.0,
                    check=False,
                )
            finally:
                srv.stop()

            out_line = (res.stdout or "").strip().splitlines()
            cols = out_line[-1].split("\t") if out_line else []
            ok_row = res.returncode == 0 and len(cols) >= 7 and cols[0] == "INTEROP_OK"
            got_sha = cols[4] if ok_row else ""
            got_bytes = int(cols[3]) if ok_row else 0
            flips = int(cols[5]) if ok_row else 0
            cipher = int(cols[6]) if ok_row else 0

            file_ok = True
            if size > 0:
                dl_file = dl_dir / fname
                file_ok = (
                    dl_file.is_file()
                    and hashlib.sha256(dl_file.read_bytes()).hexdigest() == exp_sha
                )
            keylog_ok = (
                cli_keylog.is_file()
                and "CLIENT_TRAFFIC_SECRET_0 " in cli_keylog.read_text(encoding="utf-8")
            )
            extra_ok = True
            if testcase == "keyupdate":
                extra_ok = flips >= 1
            elif testcase == "chacha20":
                extra_ok = cipher == 0x1303

            if ok_row and got_sha == exp_sha and file_ok and keylog_ok and extra_ok:
                passed += 1
                print(
                    f"  [PASS] [{testcase:9s}] {fname:21s} -> {got_bytes}B "
                    f"sha256={got_sha[:16]}... cipher=0x{cipher:04x} ku_flips={flips}"
                )
            else:
                failed += 1
                print(
                    f"  [FAIL] [{testcase:9s}] rc={res.returncode} out={res.stdout!r} "
                    f"err={res.stderr!r} sha_ok={got_sha == exp_sha} file_ok={file_ok} "
                    f"keylog_ok={keylog_ok} extra_ok={extra_ok}"
                )

    total = passed + failed
    print(f"\nquic-interop-runner Local Suite: {passed}/{total} passed, {failed} failed.")
    return 0 if failed == 0 and total > 0 else 1


class EdgeH3Server:
    def __init__(self, exe: Path, www_dir: Path) -> None:
        self.exe = exe
        self.www_dir = www_dir
        self.proc: subprocess.Popen[str] | None = None
        self.port: int = 0

    def start(self, timeout: float = 5.0) -> int:
        self.proc = subprocess.Popen(
            [str(self.exe), "server", "0", str(self.www_dir)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            cwd=str(ROOT_DIR),
        )
        assert self.proc.stdout and self.proc.stderr
        t0 = time.time()
        while time.time() - t0 < timeout:
            line = self.proc.stdout.readline()
            if "READY_PORT:" in line:
                self.port = int(line.strip().split("READY_PORT:")[1])
                return self.port
            if self.proc.poll() is not None:
                err = self.proc.stderr.read()
                raise RuntimeError(
                    f"edge_h3_server exited ({self.proc.returncode}): {err}"
                )
            time.sleep(0.01)
        self.stop()
        raise TimeoutError(f"edge_h3_server did not print READY_PORT within {timeout}s")

    def stop(self) -> None:
        if not self.proc:
            return
        try:
            self.proc.terminate()
            self.proc.wait(timeout=2.0)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass
        self.proc = None


def _docker_available() -> bool:
    try:
        res = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=8.0,
            check=False,
        )
        return res.returncode == 0
    except Exception:
        return False


def _docker_net_target(port: int) -> tuple[list[str], str, int]:
    if sys.platform.startswith("linux"):
        return ["--network", "host"], "127.0.0.1", port
    return [], "host.docker.internal", port


def _run_curl_http3_checks(host: str, port: int, net_args: list[str], exp_sha: str) -> tuple[int, int]:
    passed = 0
    failed = 0
    checks: list[tuple[str, list[str], str, bool]] = [
        ("GET /", ["-sk", "--http3-only", f"https://{host}:{port}/"], "Hello from goose-wing HTTP/3!", False),
        ("GET /ping", ["-sk", "--http3-only", f"https://{host}:{port}/ping"], "PONG_H3_EDGE", False),
        ("GET /api/info", ["-sk", "--http3-only", f"https://{host}:{port}/api/info"], '"session":"edge"', False),
        ("POST /echo", ["-sk", "--http3-only", "-d", "hello-h3-echo-body", f"https://{host}:{port}/echo"], "hello-h3-echo-body", False),
        ("HEAD /", ["-skI", "--http3-only", f"https://{host}:{port}/"], "200", False),
        ("GET /payload.bin", ["-sk", "--http3-only", f"https://{host}:{port}/payload.bin"], exp_sha, True),
    ]
    for label, curl_args, expected, check_sha in checks:
        cmd = ["docker", "run", "--rm", *net_args, CURL_HTTP3_IMAGE, "curl", *curl_args]
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=False,
                timeout=25.0,
                check=False,
            )
        except subprocess.TimeoutExpired:
            failed += 1
            print(f"  [FAIL] [curl-h3  ] {label:16s} timed out after 25s")
            continue
        body = res.stdout or b""
        if check_sha:
            got = hashlib.sha256(body).hexdigest()
            ok = res.returncode == 0 and got == expected
            detail = f"{len(body)}B sha256={got[:16]}..."
        else:
            text_out = body.decode("utf-8", errors="replace")
            ok = res.returncode == 0 and expected in text_out
            detail = text_out.strip().splitlines()[0] if text_out.strip() else f"rc={res.returncode}"
        if ok:
            passed += 1
            print(f"  [PASS] [curl-h3  ] {label:16s} -> {detail}")
        else:
            failed += 1
            err_s = (res.stderr or b"").decode("utf-8", errors="replace")[-240:]
            print(f"  [FAIL] [curl-h3  ] {label:16s} rc={res.returncode} detail={detail!r} err={err_s!r}")
    return passed, failed


def _run_external_h3_peers(
    host: str, port: int, net_args: list[str], tmp_root: Path
) -> tuple[int, int]:
    passed = 0
    failed = 0
    peer_specs: list[tuple[str, str, list[str], Path | None]] = [
        (
            "ngtcp2",
            "ghcr.io/ngtcp2/ngtcp2-interop:latest",
            [
                "--entrypoint",
                "/usr/local/bin/wsslclient",
                "-v",
                f"{tmp_root / 'dl_ngtcp2'}:/downloads",
                "ghcr.io/ngtcp2/ngtcp2-interop:latest",
                "--download=/downloads",
                "--exit-on-all-streams-close",
                host,
                str(port),
                f"https://{host}:{port}/ping",
            ],
            tmp_root / "dl_ngtcp2" / "ping",
        ),
        (
            "quiche",
            "cloudflare/quiche-qns:latest",
            [
                "--entrypoint",
                "/quiche/quiche-client",
                "cloudflare/quiche-qns:latest",
                "--no-verify",
                f"https://{host}:{port}/ping",
            ],
            None,
        ),
        (
            "quic-go",
            "martenseemann/quic-go-interop:latest",
            [
                "--entrypoint",
                "./client",
                "-e",
                "TESTCASE=http3",
                "-v",
                f"{tmp_root / 'dl_quicgo'}:/downloads",
                "-v",
                f"{tmp_root / 'logs_quicgo'}:/logs",
                "martenseemann/quic-go-interop:latest",
                f"https://{host}:{port}/ping",
            ],
            tmp_root / "dl_quicgo" / "ping",
        ),
        (
            "lsquic",
            "litespeedtech/lsquic-qir:latest",
            [
                "--entrypoint",
                "/usr/bin/http_client",
                "-v",
                f"{tmp_root / 'dl_lsquic'}:/downloads",
                "litespeedtech/lsquic-qir:latest",
                "-o",
                "version=h3",
                "-H",
                "localhost",
                "-s",
                f"{host}:{port}",
                "-p",
                "/ping",
                "-B",
                "-7",
                "/downloads",
            ],
            tmp_root / "dl_lsquic" / "ping",
        ),
    ]
    for peer_name, image, docker_args, check_file in peer_specs:
        if check_file is not None:
            check_file.parent.mkdir(parents=True, exist_ok=True)
        if peer_name == "quic-go":
            (tmp_root / "logs_quicgo").mkdir(parents=True, exist_ok=True)
        pull_chk = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            text=True,
            check=False,
        )
        if pull_chk.returncode != 0:
            pull_res = subprocess.run(
                ["docker", "pull", image],
                capture_output=True,
                text=True,
                timeout=90.0,
                check=False,
            )
            if pull_res.returncode != 0:
                failed += 1
                print(f"  [FAIL] [{peer_name:9s}] image pull failed for {image}")
                continue
        cmd = ["docker", "run", "--rm", *net_args, *docker_args]
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=25.0,
                check=False,
            )
        except subprocess.TimeoutExpired:
            failed += 1
            print(f"  [FAIL] [{peer_name:9s}] timed out after 25s")
            continue
        ok_body = False
        if check_file is not None:
            ok_body = check_file.is_file() and "PONG_H3_EDGE" in check_file.read_text(
                encoding="utf-8", errors="replace"
            )
        else:
            ok_body = "PONG_H3_EDGE" in (res.stdout or "")
        if res.returncode == 0 and ok_body:
            passed += 1
            print(f"  [PASS] [{peer_name:9s}] ALPN h3 GET /ping -> PONG_H3_EDGE")
        else:
            failed += 1
            print(
                f"  [FAIL] [{peer_name:9s}] rc={res.returncode} ok_body={ok_body} "
                f"err={(res.stderr or '')[-240:]!r}"
            )
    return passed, failed


def run_edge_h3_interop(rebuild: bool = False, with_peers: bool = False) -> int:
    exe = ensure_edge_h3_binary(force_rebuild=rebuild)
    passed = 0
    failed = 0
    print("\nExecuting Live H3EdgeSession (QuicServerEndpoint + HTTP/3) Interop Suite...")

    ok_contract, detail_contract = _verify_run_endpoint_contract()
    if ok_contract:
        passed += 1
        print(f"  [PASS] [contract ] run_endpoint.sh       -> {detail_contract}")
    else:
        failed += 1
        print(f"  [FAIL] [contract ] run_endpoint.sh       -> {detail_contract}")

    if not _docker_available():
        print("  [FAIL] [docker   ] Docker daemon unavailable for curl-http3/QNS peers")
        return 1

    with tempfile.TemporaryDirectory(prefix="wing_h3_edge_") as tmp_root_str:
        tmp_root = Path(tmp_root_str)
        www_dir = tmp_root / "www"
        www_dir.mkdir()
        payload = _make_deterministic_payload("edge_h3", 32768)
        (www_dir / "payload.bin").write_bytes(payload)
        exp_sha = hashlib.sha256(payload).hexdigest()

        srv = EdgeH3Server(exe, www_dir)
        port = srv.start()
        try:
            net_args, host, target_port = _docker_net_target(port)
            p1, f1 = _run_curl_http3_checks(host, target_port, net_args, exp_sha)
            passed += p1
            failed += f1
            if with_peers:
                p2, f2 = _run_external_h3_peers(host, target_port, net_args, tmp_root)
                passed += p2
                failed += f2
            # Exercise HTTP/3 /shutdown cleanly
            try:
                shut_res = subprocess.run(
                    [
                        "docker",
                        "run",
                        "--rm",
                        *net_args,
                        CURL_HTTP3_IMAGE,
                        "curl",
                        "-sk",
                        "--http3-only",
                        "-X",
                        "POST",
                        f"https://{host}:{target_port}/shutdown",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=15.0,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                shut_res = subprocess.CompletedProcess([], 124, "", "timeout")
            if shut_res.returncode == 0 and "BYE" in (shut_res.stdout or ""):
                passed += 1
                print("  [PASS] [curl-h3  ] POST /shutdown    -> BYE")
            else:
                failed += 1
                print(
                    f"  [FAIL] [curl-h3  ] POST /shutdown rc={shut_res.returncode} "
                    f"out={shut_res.stdout!r}"
                )
        finally:
            srv.stop()

    total = passed + failed
    print(f"\nH3EdgeSession Live Interop Suite: {passed}/{total} passed, {failed} failed.")
    return 0 if failed == 0 and total > 0 else 1


def main() -> None:
    parser = argparse.ArgumentParser(
        description="quic-interop-runner endpoint orchestrator for goose-wing"
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Run local loopback QUIC/H3 self-interop scenarios with SHA-256 verification",
    )
    parser.add_argument(
        "--edge-h3",
        action="store_true",
        help="Run live UDP QuicServerEndpoint + H3EdgeSession interop suite with curl --http3",
    )
    parser.add_argument(
        "--peers",
        action="store_true",
        help="Include external HTTP/3 peer containers (ngtcp2, quiche, quic-go, lsquic) with --edge-h3",
    )
    parser.add_argument("--testcase", default="", help="Run a single scenario by name")
    parser.add_argument(
        "--docker",
        action="store_true",
        help="Run via docker compose (tools/quic_interop/docker-compose.yml)",
    )
    parser.add_argument("--rebuild", action="store_true", help="Force rebuild endpoint binary")
    args = parser.parse_args()

    if args.edge_h3:
        sys.exit(run_edge_h3_interop(rebuild=args.rebuild, with_peers=args.peers))

    if args.docker:
        compose_file = SUITE_DIR / "docker-compose.yml"
        cmd = [
            "docker",
            "compose",
            "-f",
            str(compose_file),
            "up",
            "--build",
            "--abort-on-container-exit",
            "--exit-code-from",
            "wing-client",
        ]
        sys.exit(subprocess.run(cmd, check=False, cwd=str(ROOT_DIR)).returncode)

    sys.exit(run_local_interop(selected_testcase=args.testcase, rebuild=args.rebuild))


if __name__ == "__main__":
    main()
