#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""Live Go <-> Wing TLS 1.3 + HTTP/2 + X.509 differential and interactive test harness."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


class OneByteFragmentProxy:
    """TCP proxy that segments bidirectional stream data into 1-byte TCP writes."""

    def __init__(self, target_port: int) -> None:
        self.target_port = target_port
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind(("127.0.0.1", 0))
        self.server_sock.listen(8)
        self.port: int = self.server_sock.getsockname()[1]
        self.running = True
        self.thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.thread.start()

    def _forward_1byte(self, src: socket.socket, dst: socket.socket) -> None:
        try:
            while self.running:
                data = src.recv(4096)
                if not data:
                    break
                for i in range(len(data)):
                    dst.sendall(data[i : i + 1])
        except Exception:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except Exception:
                pass

    def _accept_loop(self) -> None:
        while self.running:
            try:
                client_sock, _ = self.server_sock.accept()
                client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                remote_sock.connect(("127.0.0.1", self.target_port))
                t1 = threading.Thread(
                    target=self._forward_1byte, args=(client_sock, remote_sock), daemon=True
                )
                t2 = threading.Thread(
                    target=self._forward_1byte, args=(remote_sock, client_sock), daemon=True
                )
                t1.start()
                t2.start()
            except Exception:
                break

    def close(self) -> None:
        self.running = False
        try:
            self.server_sock.close()
        except Exception:
            pass


def find_openssl(custom_bin: str | None = None) -> str | None:
    """Locates OpenSSL 3.x CLI binary."""
    if custom_bin:
        cand = Path(custom_bin)
        if cand.exists():
            return str(cand)
    git_cand = Path(r"C:\Program Files\Git\usr\bin\openssl.exe")
    if git_cand.exists():
        return str(git_cand)
    found = shutil.which("openssl")
    if found:
        return found
    return None


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


def build_wing_binary(goose_bin: str, src_rel: str, out_bin: Path) -> None:
    """Builds a .goose test binary with stack headroom on Windows (with .lit cache)."""
    src = REPO_ROOT / src_rel
    cache_dir = REPO_ROOT / ".lit" / "cache" / "h2_diff"
    cache_dir.mkdir(parents=True, exist_ok=True)
    cached = cache_dir / out_bin.name
    newest_dep_mtime = max(
        [src.stat().st_mtime]
        + [p.stat().st_mtime for p in (REPO_ROOT / "shim").glob("*.c")]
        + [p.stat().st_mtime for p in (REPO_ROOT / "tls").glob("*.goose")]
        + [p.stat().st_mtime for p in (REPO_ROOT / "server").glob("*.goose")]
    )
    if cached.exists() and cached.stat().st_mtime >= newest_dep_mtime:
        shutil.copy2(cached, out_bin)
        return

    env = os.environ.copy()
    if sys.platform == "win32":
        stack_cc = REPO_ROOT / "tools" / "gcc_stack.bat"
        if stack_cc.exists():
            env["GOOSE_CC"] = str(stack_cc)
    res = subprocess.run(
        [goose_bin, "build", "-O0", "-o", str(out_bin), str(src)],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        raise RuntimeError(
            f"goose build {src_rel} failed (exit {res.returncode}):\n"
            f"{res.stderr}\n{res.stdout}"
        )
    try:
        shutil.copy2(out_bin, cached)
    except Exception:
        pass


def start_wing_tls_server(wing_server_bin: Path, ca_out: Path) -> tuple[subprocess.Popen, int]:
    """Starts tests/fuzz/wing_tls_server, writes its PEM cert to `ca_out`, returns (proc, port)."""
    proc = subprocess.Popen(
        [str(wing_server_bin)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        cwd=REPO_ROOT,
    )
    assert proc.stdout is not None
    cert_hex = ""
    port = 0
    t_deadline = time.time() + 10.0
    while time.time() < t_deadline:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                break
            continue
        s = line.strip()
        if s.startswith("CERT_HEX:"):
            cert_hex = s.split(":", 1)[1].strip()
        elif s.startswith("READY_PORT:"):
            port = int(s.split(":", 1)[1].strip())
            break
    if not cert_hex or port <= 0:
        err = proc.stderr.read() if proc.stderr else ""
        proc.kill()
        raise RuntimeError(f"wing_tls_server failed to start (port={port}): {err}")
    ca_out.write_text(ssl.DER_cert_to_PEM_cert(bytes.fromhex(cert_hex)), encoding="utf-8")
    return proc, port


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


def verify_openssl_1byte_frag(
    wing_port: int,
    ca_path: Path,
    openssl_bin: str,
) -> tuple[bool, str]:
    """Tests Wing TLS 1.3 server handshake reassembly through a 1-byte TCP segmenting proxy."""
    proxy = OneByteFragmentProxy(wing_port)
    try:
        proc = subprocess.Popen(
            [
                openssl_bin,
                "s_client",
                "-connect",
                f"127.0.0.1:{proxy.port}",
                "-CAfile",
                str(ca_path),
                "-tls1_3",
                "-alpn",
                "http/1.1",
                "-servername",
                "localhost",
                "-quiet",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(0.5)
        proc.stdin.write(b"GET /h1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        proc.stdin.flush()
        out, err = proc.communicate(timeout=15)
        out_text = out.decode("latin1", errors="replace")
        err_text = err.decode("latin1", errors="replace")
        if "HTTP/1.1 200 OK" not in out_text or "hello-from-wing-TLS1.3" not in out_text:
            return False, f"missing 200 OK or body: out={out_text!r} err={err_text!r}"
        return True, "Wing server 1-byte proxy handshake + HTTP/1.1 200 OK"
    finally:
        proxy.close()


def verify_openssl_keyupdate(
    wing_port: int,
    ca_path: Path,
    openssl_bin: str,
) -> tuple[bool, str]:
    """Tests Wing TLS 1.3 post-handshake KeyUpdate and post-rotation app data over active wire."""
    proc = subprocess.Popen(
        [
            openssl_bin,
            "s_client",
            "-connect",
            f"127.0.0.1:{wing_port}",
            "-CAfile",
            str(ca_path),
            "-tls1_3",
            "-alpn",
            "http/1.1",
            "-servername",
            "localhost",
            "-msg",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    out_chunks: list[bytes] = []
    err_chunks: list[bytes] = []

    def _drain(stream, acc: list[bytes]) -> None:
        while True:
            chunk = stream.read(4096)
            if not chunk:
                break
            acc.append(chunk)

    t_out = threading.Thread(target=_drain, args=(proc.stdout, out_chunks), daemon=True)
    t_err = threading.Thread(target=_drain, args=(proc.stderr, err_chunks), daemon=True)
    t_out.start()
    t_err.start()

    assert proc.stdin is not None
    time.sleep(0.3)
    proc.stdin.write(b"K\n")
    proc.stdin.flush()
    time.sleep(0.4)
    proc.stdin.write(b"GET /h1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    proc.stdin.flush()
    time.sleep(0.8)
    try:
        proc.stdin.close()
    except Exception:
        pass
    proc.wait(timeout=15)
    t_out.join(timeout=2)
    t_err.join(timeout=2)

    combined = (b"".join(out_chunks) + b"".join(err_chunks)).decode("latin1", errors="replace")
    has_client_ku = ">>> TLS 1.3, Handshake [length 0005], KeyUpdate" in combined
    has_server_ku = "<<< TLS 1.3, Handshake [length 0005], KeyUpdate" in combined
    has_keyupdate_tag = "KEYUPDATE" in combined
    has_http_ok = "HTTP/1.1 200 OK" in combined and "hello-from-wing-TLS1.3" in combined
    if not (has_client_ku and has_server_ku and has_keyupdate_tag and has_http_ok):
        return (
            False,
            f"KeyUpdate failed: client={has_client_ku} server={has_server_ku} tag={has_keyupdate_tag} http={has_http_ok}\n{combined[-800:]}",
        )
    return True, "Wing server bidirectional KeyUpdate + post-rotation 200 OK"


def verify_openssl_resumption(
    wing_port: int,
    ca_path: Path,
    openssl_bin: str,
    tmp_dir: Path,
) -> tuple[bool, str]:
    """Tests Wing TLS 1.3 NewSessionTicket capture and 1-RTT session resumption."""
    sess_file = tmp_dir / "sess.pem"
    p1 = subprocess.Popen(
        [
            openssl_bin,
            "s_client",
            "-connect",
            f"127.0.0.1:{wing_port}",
            "-CAfile",
            str(ca_path),
            "-tls1_3",
            "-alpn",
            "http/1.1",
            "-servername",
            "localhost",
            "-sess_out",
            str(sess_file),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(0.3)
    p1.stdin.write(b"GET /h1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    p1.stdin.flush()
    time.sleep(0.3)
    out1, err1 = p1.communicate(timeout=15)
    combined1 = (out1 + err1).decode("latin1", errors="replace")
    if not sess_file.exists() or sess_file.stat().st_size == 0:
        return False, f"ticket file was not written: {combined1[:400]!r}"

    p2 = subprocess.Popen(
        [
            openssl_bin,
            "s_client",
            "-connect",
            f"127.0.0.1:{wing_port}",
            "-CAfile",
            str(ca_path),
            "-tls1_3",
            "-alpn",
            "http/1.1",
            "-servername",
            "localhost",
            "-sess_in",
            str(sess_file),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(0.3)
    p2.stdin.write(b"GET /h1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    p2.stdin.flush()
    time.sleep(0.3)
    out2, err2 = p2.communicate(timeout=15)
    combined2 = (out2 + err2).decode("latin1", errors="replace")
    if "Reused, TLSv1.3" not in combined2 or "hello-from-wing-TLS1.3" not in combined2:
        return False, f"resumption failed: output={combined2[:600]!r}"
    return True, "Wing server 1-RTT resumption (Reused, TLSv1.3 + 200 OK)"


def verify_openssl_psk_fallback(
    wing_port: int,
    ca_path: Path,
    openssl_bin: str,
) -> tuple[bool, str]:
    """Tests that unknown PSK identity triggers fallback to ECDHE and Wing cert auth."""
    proc = subprocess.Popen(
        [
            openssl_bin,
            "s_client",
            "-connect",
            f"127.0.0.1:{wing_port}",
            "-CAfile",
            str(ca_path),
            "-tls1_3",
            "-alpn",
            "http/1.1",
            "-servername",
            "localhost",
            "-psk_identity",
            "unknown_client_id",
            "-psk",
            "0102030405060708090a0b0c0d0e0f10",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(0.3)
    proc.stdin.write(b"GET /h1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    proc.stdin.flush()
    time.sleep(0.4)
    out, err = proc.communicate(timeout=15)
    combined = (out + err).decode("latin1", errors="replace")
    has_new_tls = "New, TLSv1.3" in combined
    has_cert_ok = "Verification: OK" in combined or "verify return:1" in combined
    has_http_ok = "HTTP/1.1 200 OK" in combined and "hello-from-wing-TLS1.3" in combined
    if not (has_new_tls and has_cert_ok and has_http_ok):
        return (
            False,
            f"PSK fallback failed: new={has_new_tls} cert={has_cert_ok} http={has_http_ok}\n{combined[-500:]}",
        )
    return True, "Wing server PSK fallback to ECDHE (New, TLSv1.3, Verification: OK)"


def run_differential(
    goose_bin: str,
    verbose: bool,
    openssl_bin: str | None = None,
    skip_openssl: bool = False,
) -> int:
    """Builds and runs Go h2oracle against Wing h2_tls_client_verdict and OpenSSL."""
    exe_suffix = ".exe" if sys.platform == "win32" else ""
    with tempfile.TemporaryDirectory(prefix="wing_h2_diff_", ignore_cleanup_errors=True) as tmp:
        tmp_dir = Path(tmp)
        oracle_bin = tmp_dir / f"h2oracle{exe_suffix}"
        wing_bin = tmp_dir / f"h2_tls_client_verdict{exe_suffix}"
        wing_srv_bin = tmp_dir / f"wing_tls_server{exe_suffix}"
        manifest_path = tmp_dir / "manifest.json"
        ca_path = tmp_dir / "ca.pem"
        wing_ca_path = tmp_dir / "wing_ca.pem"
        cases_path = tmp_dir / "cases.tsv"

        print("Building Go h2oracle...")
        build_go_oracle(oracle_bin)
        print("Building Wing h2_tls_client_verdict...")
        build_wing_binary(goose_bin, "tests/fuzz/h2_tls_client_verdict.goose", wing_bin)
        print("Building Wing wing_tls_server...")
        build_wing_binary(goose_bin, "tests/fuzz/wing_tls_server.goose", wing_srv_bin)

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

            # Setup 1-byte fragment proxy for Wing client
            h2_port = manifest["ports"]["h2"]
            wing_frag_proxy = OneByteFragmentProxy(h2_port)
            scenarios = list(manifest["scenarios"])
            scenarios.append(
                {
                    "name": "h2_1byte_frag",
                    "target": "h2",
                    "method": "GET",
                    "url": f"https://localhost:{wing_frag_proxy.port}/get",
                    "use_ca": True,
                    "go_verdict": (
                        "OK HTTP/2 200 16 1d5bac7589fa28b2c4c29b92cc3daa6a621cd1e6c8cc0b74a4518d32b9a3c98b"
                    ),
                    "go_check_hdr": {"content-type": "text/plain", "x-oracle-proto": "HTTP/2.0"},
                }
            )

            try:
                cases_path.write_text(format_cases_tsv(scenarios), encoding="utf-8")
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
                wing_frag_proxy.close()

            mismatches = compare_verdicts(scenarios, res.stdout, verbose)
            if mismatches:
                if proc.stdin:
                    try:
                        proc.stdin.close()
                    except Exception:
                        pass
                try:
                    proc.terminate()
                    _, oracle_stderr = proc.communicate(timeout=3)
                except Exception:
                    proc.kill()
                    _, oracle_stderr = proc.communicate(timeout=3)
                if oracle_stderr and oracle_stderr.strip():
                    print("ORACLE STDERR:\n" + oracle_stderr.strip())
                print("DIFFERENTIAL MISMATCHES:")
                for item in mismatches:
                    print(item)
                return 1

            # Run interactive live TLS 1.3 tests: OpenSSL <-> Wing TLS 1.3 Server
            resolved_openssl = find_openssl(openssl_bin) if not skip_openssl else None
            openssl_count = 0
            if resolved_openssl:
                print(
                    f"Running OpenSSL 3.x interactive TLS 1.3 tests against Wing server using {resolved_openssl}..."
                )
                wing_srv_proc, wing_port = start_wing_tls_server(wing_srv_bin, wing_ca_path)
                try:
                    openssl_tests = [
                        (
                            "openssl_wing_1byte_frag",
                            lambda: verify_openssl_1byte_frag(
                                wing_port, wing_ca_path, resolved_openssl
                            ),
                        ),
                        (
                            "openssl_wing_keyupdate",
                            lambda: verify_openssl_keyupdate(
                                wing_port, wing_ca_path, resolved_openssl
                            ),
                        ),
                        (
                            "openssl_wing_resumption",
                            lambda: verify_openssl_resumption(
                                wing_port, wing_ca_path, resolved_openssl, tmp_dir
                            ),
                        ),
                        (
                            "openssl_wing_psk_fallback",
                            lambda: verify_openssl_psk_fallback(
                                wing_port, wing_ca_path, resolved_openssl
                            ),
                        ),
                    ]
                    for test_name, test_fn in openssl_tests:
                        ok, detail = test_fn()
                        if not ok:
                            print(f"[FAIL] {test_name}: {detail}")
                            return 1
                        openssl_count += 1
                        if verbose:
                            print(f"[PASS] {test_name}: {detail}")
                finally:
                    try:
                        wing_srv_proc.terminate()
                        wing_srv_proc.wait(timeout=3)
                    except Exception:
                        wing_srv_proc.kill()
            elif not skip_openssl:
                print("Notice: OpenSSL not detected on PATH; skipping OpenSSL interactive tests.")

        finally:
            if proc.stdin:
                try:
                    proc.stdin.close()
                except Exception:
                    pass
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                pass
            time.sleep(0.2)

        total_passed = len(scenarios) + openssl_count
        openssl_str = f" + {openssl_count} OpenSSL interactive" if openssl_count > 0 else ""
        print(
            f"ALL {total_passed} TLS 1.3 + HTTP/2 + X.509 DIFFERENTIAL SCENARIOS PASSED "
            f"({len(scenarios)} Go/Wing{openssl_str})"
        )
        return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Run live Go <-> Wing TLS 1.3 + HTTP/2 + X.509 differential tests."
    )
    ap.add_argument("-v", "--verbose", action="store_true", help="Print per-scenario verdicts")
    ap.add_argument("--goose", default=shutil.which("goose") or "goose", help="Path to goose CLI")
    ap.add_argument("--openssl", default=None, help="Explicit path to OpenSSL CLI binary")
    ap.add_argument(
        "--skip-openssl", action="store_true", help="Skip OpenSSL interactive test suites"
    )
    args = ap.parse_args()
    return run_differential(args.goose, args.verbose, args.openssl, args.skip_openssl)


if __name__ == "__main__":
    sys.exit(main())
