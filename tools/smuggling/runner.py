#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
HTTP/1.1 Smuggling Differential Wall (`http-garden`-style) for goose-wing.
Compares full `wing` (`server::parse_http1_wire_request` + `server::HttpServer`),
modular `wing_h1` (`h1::parse_request_view` + `h1::decode_chunked_body`),
an independent Python RFC 9112 strict reference oracle, and (in `--docker` mode)
live `nginx` and `haproxy` frontends against adversarial HTTP/1.1 desync vectors.
"""

from __future__ import annotations

import argparse
import io
import os
import re
import socket
import subprocess
import sys
import tempfile
from dataclasses import dataclass
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

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
TOOLS_DIR = ROOT_DIR / "tools"
BIN_DIR = TOOLS_DIR / "bin"
WING_SRC = TOOLS_DIR / "smuggling" / "wing_harness.goose"
WING_H1_SRC = TOOLS_DIR / "smuggling" / "wing_h1_harness.goose"
WING_EXE = BIN_DIR / ("smuggling_wing.exe" if sys.platform == "win32" else "smuggling_wing")
WING_H1_EXE = BIN_DIR / (
    "smuggling_wing_h1.exe" if sys.platform == "win32" else "smuggling_wing_h1"
)


@dataclass(frozen=True)
class SmugglingVector:
    name: str
    category: str
    raw: bytes
    expect_accept: bool
    expected_body: bytes = b""
    expected_consumed: int = -1


def build_smuggling_corpus() -> list[SmugglingVector]:
    """Returns 34 HTTP/1.1 vectors: 5 RFC 9112 baselines and 29 adversarial desync attacks."""
    pipelined_valid = (
        b"POST /echo HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"5\r\nhello\r\n0\r\n\r\n"
        b"GET /second HTTP/1.1\r\nHost: example.com\r\n\r\n"
    )
    pipelined_first_len = len(
        b"POST /echo HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"5\r\nhello\r\n0\r\n\r\n"
    )
    return [
        # ---- Valid RFC 9112 Baselines (5) ----
        SmugglingVector(
            "baseline_get_http11",
            "baseline",
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            True,
            b"",
            37,
        ),
        SmugglingVector(
            "baseline_post_cl",
            "baseline",
            b"POST /echo HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello",
            True,
            b"hello",
            66,
        ),
        SmugglingVector(
            "baseline_post_chunked",
            "baseline",
            (
                b"POST /echo HTTP/1.1\r\nHost: example.com\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
            ),
            True,
            b"hello",
            85,
        ),
        SmugglingVector(
            "baseline_http10_no_host",
            "baseline",
            b"GET / HTTP/1.0\r\n\r\n",
            True,
            b"",
            18,
        ),
        SmugglingVector(
            "baseline_pipelined_chunked_boundary",
            "baseline",
            pipelined_valid,
            True,
            b"hello",
            pipelined_first_len,
        ),
        # ---- Adversarial Smuggling & Desync Corpus (29) ----
        SmugglingVector(
            "cl_te_conflict",
            "CL.TE",
            (
                b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"
            ),
            False,
        ),
        SmugglingVector(
            "te_cl_conflict",
            "TE.CL",
            (
                b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n"
                b"Content-Length: 4\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\n\r\n0\r\n\r\n"
            ),
            False,
        ),
        SmugglingVector(
            "te_obfuscated_xchunked",
            "TE.TE",
            b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: xchunked\r\n\r\n0\r\n\r\n",
            False,
        ),
        SmugglingVector(
            "te_space_before_colon",
            "TE.TE",
            b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\n",
            False,
        ),
        SmugglingVector(
            "te_tab_prefixed_name",
            "TE.TE",
            b"POST / HTTP/1.1\r\nHost: example.com\r\n\tTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            False,
        ),
        SmugglingVector(
            "te_space_prefixed_name",
            "TE.TE",
            b"POST / HTTP/1.1\r\nHost: example.com\r\n Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            False,
        ),
        SmugglingVector(
            "te_dual_chunked_identity",
            "TE.TE",
            (
                b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n"
                b"Transfer-Encoding: identity\r\n\r\n0\r\n\r\n"
            ),
            False,
        ),
        SmugglingVector(
            "te_dual_chunked_gzip",
            "TE.TE",
            (
                b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n"
                b"Transfer-Encoding: gzip\r\n\r\n0\r\n\r\n"
            ),
            False,
        ),
        SmugglingVector(
            "te_comma_nonfinal_chunked",
            "TE.TE",
            (
                b"POST / HTTP/1.1\r\nHost: example.com\r\n"
                b"Transfer-Encoding: chunked, identity\r\n\r\n0\r\n\r\n"
            ),
            False,
        ),
        SmugglingVector(
            "te_http10_forbidden",
            "TE.H10",
            b"POST / HTTP/1.0\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            False,
        ),
        SmugglingVector(
            "cl_duplicate_differing",
            "CL.CL",
            (
                b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n"
                b"Content-Length: 8\r\n\r\n12345678"
            ),
            False,
        ),
        SmugglingVector(
            "cl_comma_differing",
            "CL.CL",
            b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4, 8\r\n\r\n12345678",
            False,
        ),
        SmugglingVector(
            "cl_negative",
            "CL.Syntax",
            b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: -5\r\n\r\n",
            False,
        ),
        SmugglingVector(
            "cl_plus_prefix",
            "CL.Syntax",
            b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: +5\r\n\r\nhello",
            False,
        ),
        SmugglingVector(
            "cl_hex_value",
            "CL.Syntax",
            b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0x05\r\n\r\nhello",
            False,
        ),
        SmugglingVector(
            "cl_space_before_colon",
            "CL.Syntax",
            b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length : 5\r\n\r\nhello",
            False,
        ),
        SmugglingVector(
            "bare_lf_request_line",
            "LineEnding",
            b"GET / HTTP/1.1\nHost: example.com\r\n\r\n",
            False,
        ),
        SmugglingVector(
            "bare_lf_header_line",
            "LineEnding",
            b"GET / HTTP/1.1\r\nHost: example.com\nX-Smuggle: 1\r\n\r\n",
            False,
        ),
        SmugglingVector(
            "bare_cr_header_line",
            "LineEnding",
            b"GET / HTTP/1.1\r\nHost: example.com\rX-Smuggle: 1\r\n\r\n",
            False,
        ),
        SmugglingVector(
            "obs_fold_continuation",
            "ObsFold",
            b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Fold: a\r\n b\r\n\r\n",
            False,
        ),
        SmugglingVector(
            "invalid_http_version_09",
            "Version",
            b"GET / HTTP/0.9\r\nHost: example.com\r\n\r\n",
            False,
        ),
        SmugglingVector(
            "invalid_http_version_12",
            "Version",
            b"GET / HTTP/1.2\r\nHost: example.com\r\n\r\n",
            False,
        ),
        SmugglingVector(
            "missing_host_http11",
            "Host",
            b"GET / HTTP/1.1\r\nUser-Agent: smuggler\r\n\r\n",
            False,
        ),
        SmugglingVector(
            "duplicate_host_header",
            "Host",
            b"GET / HTTP/1.1\r\nHost: a.example.com\r\nHost: b.example.com\r\n\r\n",
            False,
        ),
        SmugglingVector(
            "nul_byte_in_header_value",
            "Injection",
            b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Evil: a\x00b\r\n\r\n",
            False,
        ),
        SmugglingVector(
            "nul_byte_in_target",
            "Injection",
            b"GET /a\x00b HTTP/1.1\r\nHost: example.com\r\n\r\n",
            False,
        ),
        SmugglingVector(
            "oversized_chunk_size_overflow",
            "Chunked",
            (
                b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"fffffffffffffffff;ext=" + (b"A" * 4096) + b"\r\n0\r\n\r\n"
            ),
            False,
        ),
        SmugglingVector(
            "chunked_trailing_garbage_no_crlf",
            "Chunked",
            (
                b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"5\r\nhello\r\n0\r\nGARBAGE_SMUGGLE"
            ),
            False,
        ),
        SmugglingVector(
            "pipelined_split_frame_smuggling",
            "Pipeline",
            (
                b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
                b"0\r\n\r\nGET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n"
            ),
            False,
        ),
    ]


TCHAR_RE = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


def python_rfc9112_oracle(raw: bytes) -> tuple[str, int, bytes]:
    """Independent strict RFC 9112 parser oracle returning (ACCEPT|REJECT, consumed, body)."""
    hdr_end = raw.find(b"\r\n\r\n")
    if hdr_end < 0 or hdr_end + 4 > 8192:
        return "REJECT", 0, b""
    head = raw[:hdr_end]
    # Reject bare CR or bare LF anywhere in head
    for idx, b in enumerate(head):
        if b == 0x0D and (idx + 1 >= len(head) or head[idx + 1] != 0x0A):
            return "REJECT", 0, b""
        if b == 0x0A and (idx == 0 or head[idx - 1] != 0x0D):
            return "REJECT", 0, b""

    lines = head.split(b"\r\n")
    req_parts = lines[0].split(b" ")
    if len(req_parts) != 3:
        return "REJECT", 0, b""
    method, target, version = req_parts
    if not TCHAR_RE.match(method):
        return "REJECT", 0, b""
    if not target or (target[0:1] != b"/" and not (target == b"*" and method == b"OPTIONS")):
        return "REJECT", 0, b""
    if any(b < 0x21 or b > 0x7E or b == ord("#") for b in target):
        return "REJECT", 0, b""
    if version not in (b"HTTP/1.1", b"HTTP/1.0"):
        return "REJECT", 0, b""

    has_host = False
    cl_val: int | None = None
    has_te = False
    for hline in lines[1:]:
        if not hline or hline[0:1] in (b" ", b"\t") or b":" not in hline:
            return "REJECT", 0, b""
        name, raw_val = hline.split(b":", 1)
        if not TCHAR_RE.match(name):
            return "REJECT", 0, b""
        val = raw_val.strip(b" \t")
        if any(not (b == 0x09 or 0x20 <= b <= 0x7E or b >= 0x80) for b in val):
            return "REJECT", 0, b""
        lname = name.lower()
        if lname == b"host":
            if has_host or not val:
                return "REJECT", 0, b""
            has_host = True
        elif lname == b"content-length":
            if has_te or not val or not all(0x30 <= b <= 0x39 for b in val):
                return "REJECT", 0, b""
            parsed_cl = int(val.decode("ascii"))
            if cl_val is not None and cl_val != parsed_cl:
                return "REJECT", 0, b""
            cl_val = parsed_cl
        elif lname == b"transfer-encoding":
            if cl_val is not None or version == b"HTTP/1.0" or val.lower() != b"chunked":
                return "REJECT", 0, b""
            has_te = True

    if version == b"HTTP/1.1" and not has_host:
        return "REJECT", 0, b""

    body_start = hdr_end + 4
    if has_te:
        cur = body_start
        out = bytearray()
        while cur < len(raw):
            crlf = raw.find(b"\r\n", cur)
            if crlf < 0:
                return "REJECT", 0, b""
            sz_tok = raw[cur:crlf].split(b";", 1)[0].strip(b" \t")
            if not sz_tok or not all(b in b"0123456789abcdefABCDEF" for b in sz_tok):
                return "REJECT", 0, b""
            sz = int(sz_tok.decode("ascii"), 16)
            if sz > 10 * 1024 * 1024:
                return "REJECT", 0, b""
            cur = crlf + 2
            if sz == 0:
                if cur + 2 > len(raw) or raw[cur : cur + 2] != b"\r\n":
                    return "REJECT", 0, b""
                return "ACCEPT", cur + 2, bytes(out)
            if cur + sz + 2 > len(raw) or raw[cur + sz : cur + sz + 2] != b"\r\n":
                return "REJECT", 0, b""
            out.extend(raw[cur : cur + sz])
            cur += sz + 2
        return "REJECT", 0, b""

    need = cl_val or 0
    if len(raw) < body_start + need:
        return "REJECT", 0, b""
    return "ACCEPT", body_start + need, raw[body_start : body_start + need]


def probe_tcp_frontend(addr: str, raw: bytes) -> str:
    """Sends a raw HTTP/1.1 byte stream to a live frontend (nginx/haproxy) and classifies response."""
    host, port_str = addr.rsplit(":", 1)
    port = int(port_str)
    try:
        with socket.create_connection((host, port), timeout=2.0) as s:
            s.settimeout(1.0)
            s.sendall(raw)
            try:
                resp = s.recv(512)
            except TimeoutError:
                return "TIMEOUT"
        if not resp:
            return "CLOSED"
        first_line = resp.split(b"\r\n", 1)[0]
        parts = first_line.split(b" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            code = int(parts[1])
            return f"HTTP_{code}"
        return "MALFORMED"
    except OSError:
        return "CONN_ERR"


def ensure_binary(src: Path, exe: Path, label: str, force_rebuild: bool = False) -> Path:
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    if not force_rebuild and exe.is_file() and exe.stat().st_mtime >= src.stat().st_mtime:
        return exe

    print(f"[*] Building {label}: {src.name} -> {exe.name}...")
    env = os.environ.copy()
    build_flags = ["-O2"]
    if sys.platform == "win32":
        build_flags = ["-O0"]
        if "GOOSE_CC" not in env:
            stack_cc = ROOT_DIR / "tools" / "gcc_stack.bat"
            if stack_cc.is_file():
                env["GOOSE_CC"] = str(stack_cc)
    cmd = ["goose", "build", *build_flags, "-o", str(exe), str(src)]
    res = subprocess.run(
        cmd, check=False, cwd=str(ROOT_DIR), capture_output=True, text=True, env=env
    )
    if res.returncode != 0:
        print(f"[!] Failed to build {label}:", file=sys.stderr)
        if res.stdout:
            print(res.stdout, file=sys.stderr)
        if res.stderr:
            print(res.stderr, file=sys.stderr)
        sys.exit(1)
    print(f"[+] Built {exe.name}")
    return exe


def run_goose_harness(exe: Path, tsv_path: Path) -> dict[str, list[str]]:
    res = subprocess.run(
        [str(exe), str(tsv_path)],
        cwd=str(ROOT_DIR),
        capture_output=True,
        text=True,
        timeout=30.0,
        check=False,
    )
    if res.returncode != 0:
        raise RuntimeError(f"{exe.name} failed (exit {res.returncode}): {res.stderr}\n{res.stdout}")
    out: dict[str, list[str]] = {}
    for line in res.stdout.splitlines():
        cols = line.strip().split("\t")
        if len(cols) >= 7:
            out[cols[0]] = cols
    return out


def run_differential_wall(
    rebuild: bool = False,
    nginx_addr: str = "",
    haproxy_addr: str = "",
) -> int:
    wing_exe = ensure_binary(WING_SRC, WING_EXE, "wing smuggling harness", rebuild)
    wing_h1_exe = ensure_binary(WING_H1_SRC, WING_H1_EXE, "wing_h1 smuggling harness", rebuild)
    corpus = build_smuggling_corpus()

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".tsv", encoding="utf-8", delete=False
    ) as tmp:
        tsv_path = Path(tmp.name)
        for vec in corpus:
            tmp.write(f"{vec.name}\t{vec.raw.hex()}\n")

    try:
        wing_res = run_goose_harness(wing_exe, tsv_path)
        h1_res = run_goose_harness(wing_h1_exe, tsv_path)
    finally:
        tsv_path.unlink(missing_ok=True)

    passed = 0
    failed = 0
    parity_mismatches = 0
    smuggling_accepts = 0

    print("\nExecuting HTTP/1.1 Smuggling Differential Wall (wing vs wing_h1 vs RFC 9112 oracle)...")
    for vec in corpus:
        w_cols = wing_res.get(vec.name)
        h_cols = h1_res.get(vec.name)
        py_verdict, py_consumed, py_body = python_rfc9112_oracle(vec.raw)

        if not w_cols or not h_cols:
            failed += 1
            print(f"  [FAIL] {vec.name}: missing harness output")
            continue

        w_accept = w_cols[1] == "ACCEPT"
        h_accept = h_cols[1] == "ACCEPT"
        py_accept = py_verdict == "ACCEPT"
        w_consumed = int(w_cols[2])
        h_consumed = int(h_cols[2])
        w_body_hex = w_cols[6]
        h_body_hex = h_cols[6]
        srv_status = int(w_cols[7]) if len(w_cols) > 7 else 0

        parity_ok = (w_accept == h_accept) and (
            not w_accept
            or (
                w_consumed == h_consumed
                and w_cols[3] == h_cols[3]
                and w_cols[4] == h_cols[4]
                and w_body_hex == h_body_hex
            )
        )
        if not parity_ok:
            parity_mismatches += 1

        if not vec.expect_accept and (w_accept or h_accept or (srv_status != 0 and srv_status < 400)):
            smuggling_accepts += 1

        expected_hex = vec.expected_body.hex() if vec.expected_body else "-"
        vec_ok = (
            parity_ok
            and (w_accept == vec.expect_accept)
            and (h_accept == vec.expect_accept)
            and (py_accept == vec.expect_accept)
        )
        if vec.expect_accept:
            vec_ok = (
                vec_ok
                and w_body_hex == expected_hex
                and h_body_hex == expected_hex
                and py_body == vec.expected_body
                and (vec.expected_consumed < 0 or w_consumed == vec.expected_consumed)
                and (vec.expected_consumed < 0 or py_consumed == vec.expected_consumed)
            )
        else:
            vec_ok = vec_ok and (srv_status == 0 or srv_status >= 400)

        ext_info = ""
        if nginx_addr:
            ext_info += f" nginx={probe_tcp_frontend(nginx_addr, vec.raw)}"
        if haproxy_addr:
            ext_info += f" haproxy={probe_tcp_frontend(haproxy_addr, vec.raw)}"

        if vec_ok:
            passed += 1
            tag = "ACCEPT" if w_accept else f"REJECT({srv_status})"
            print(f"  [PASS] [{vec.category:10s}] {vec.name:36s} -> {tag}{ext_info}")
        else:
            failed += 1
            print(
                f"  [FAIL] [{vec.category:10s}] {vec.name:36s} "
                f"wing={w_cols[1]}(c={w_consumed},st={srv_status}) "
                f"wing_h1={h_cols[1]}(c={h_consumed}) py={py_verdict}(c={py_consumed}){ext_info}"
            )

    total = passed + failed
    adv_count = sum(1 for v in corpus if not v.expect_accept)
    print(
        f"\nCompleted: {passed}/{total} passed ({adv_count} adversarial, "
        f"{total - adv_count} baseline), {smuggling_accepts} smuggling accepts, "
        f"{parity_mismatches} wing/wing_h1 parity mismatches."
    )
    return 0 if failed == 0 and total > 0 else 1


def main() -> None:
    parser = argparse.ArgumentParser(
        description="HTTP/1.1 Smuggling Differential Wall for goose-wing and wing_h1"
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Run local differential wall (wing + wing_h1 + Python RFC 9112 oracle)",
    )
    parser.add_argument(
        "--docker",
        action="store_true",
        help="Run multi-implementation differential wall with nginx + haproxy via docker compose",
    )
    parser.add_argument("--rebuild", action="store_true", help="Force rebuild Goose harnesses")
    parser.add_argument("--nginx-addr", default="", help="Live nginx host:port for differential probe")
    parser.add_argument(
        "--haproxy-addr", default="", help="Live haproxy host:port for differential probe"
    )
    args = parser.parse_args()

    if args.docker:
        compose_file = TOOLS_DIR / "smuggling" / "docker-compose.yml"
        cmd = [
            "docker",
            "compose",
            "-f",
            str(compose_file),
            "up",
            "--build",
            "--abort-on-container-exit",
            "--exit-code-from",
            "smuggling-runner",
        ]
        print(f"[*] Running HTTP/1.1 Smuggling Wall via docker compose ({compose_file.name})...")
        sys.exit(subprocess.run(cmd, check=False, cwd=str(ROOT_DIR)).returncode)

    sys.exit(
        run_differential_wall(
            rebuild=args.rebuild,
            nginx_addr=args.nginx_addr,
            haproxy_addr=args.haproxy_addr,
        )
    )


if __name__ == "__main__":
    main()
