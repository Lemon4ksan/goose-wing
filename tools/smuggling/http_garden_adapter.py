#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
HTTP Garden (`narfindustries/http-garden`) origin-echo and differential adapter
for `goose-wing` (`wing_harness` and `wing_h1_harness`).

Supports three modes:
  - `--self-test`: compiles both Goose harnesses, checks 34-vector parity across
    `wing` and `wing_h1`, and tests live TCP origin-echo HTTP responses.
  - `--mode serve`: runs an HTTP/1.1 TCP origin-echo server compatible with
    `narfindustries/http-garden` (`{method, uri, version, headers, body}`).
  - `--mode eval`: evaluates `--raw-b64` or JSONL stdin payloads and emits JSON.
"""

from __future__ import annotations

import argparse
import base64
import io
import json
import os
import socket
import socketserver
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any

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

_SMUGGLING_DIR = Path(__file__).resolve().parent
if str(_SMUGGLING_DIR) not in sys.path:
    sys.path.insert(0, str(_SMUGGLING_DIR))

from runner import (
    WING_EXE,
    WING_H1_EXE,
    WING_H1_SRC,
    WING_SRC,
    build_smuggling_corpus,
    ensure_binary,
    run_goose_harness,
)

ENGINE_SPECS = {
    "wing": (WING_SRC, WING_EXE, "wing smuggling harness"),
    "wing_h1": (WING_H1_SRC, WING_H1_EXE, "wing_h1 smuggling harness"),
}


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _decode_chunked_prefix(raw_body: bytes) -> bytes:
    """Decodes an already-validated chunked transfer body slice."""
    cur = 0
    out = bytearray()
    while cur < len(raw_body):
        crlf = raw_body.find(b"\r\n", cur)
        if crlf < 0:
            break
        size_tok = raw_body[cur:crlf].split(b";", 1)[0].strip(b" \t")
        size = int(size_tok.decode("ascii"), 16)
        cur = crlf + 2
        if size == 0:
            break
        out.extend(raw_body[cur : cur + size])
        cur += size + 2
    return bytes(out)


def _extract_accepted_request(
    raw: bytes,
    cols: list[str],
    engine: str,
) -> dict[str, Any]:
    """Builds an http-garden JSON record from an accepted Goose harness row."""
    consumed = int(cols[2])
    harness_method = cols[3].encode("latin-1")
    harness_uri = cols[4].encode("latin-1")
    body_len = int(cols[5])
    body_hex = cols[6]

    msg = raw[:consumed]
    hdr_end = msg.find(b"\r\n\r\n")
    head = msg[:hdr_end] if hdr_end >= 0 else msg
    lines = head.split(b"\r\n")
    req_parts = lines[0].split(b" ", 2) if lines else []
    version = req_parts[2] if len(req_parts) == 3 else b"HTTP/1.1"

    headers: list[tuple[bytes, bytes]] = []
    is_chunked = False
    for hline in lines[1:]:
        if b":" not in hline:
            continue
        k, v = hline.split(b":", 1)
        val_stripped = v.strip(b" \t")
        headers.append((k, val_stripped))
        if k.lower() == b"transfer-encoding" and b"chunked" in val_stripped.lower():
            is_chunked = True

    raw_body = msg[hdr_end + 4 :] if hdr_end >= 0 else b""
    if body_len == 0:
        body_bytes = b""
    elif is_chunked:
        body_bytes = _decode_chunked_prefix(raw_body)
    else:
        body_bytes = raw_body[:body_len]

    expected_preview = b"" if body_hex == "-" else bytes.fromhex(body_hex)
    if len(body_bytes) != body_len or body_bytes[: len(expected_preview)] != expected_preview:
        raise ValueError(
            f"{engine} body mismatch: len={len(body_bytes)} expected={body_len}"
        )

    return {
        "accepted": True,
        "engine": engine,
        "verdict": "ACCEPT",
        "consumed": consumed,
        "method": _b64(harness_method),
        "uri": _b64(harness_uri),
        "version": _b64(version),
        "headers": [[_b64(k), _b64(v)] for k, v in headers],
        "body": _b64(body_bytes),
    }


def _to_garden_origin_echo(record: dict[str, Any]) -> dict[str, Any]:
    """Returns the exact narfindustries/http-garden origin echo JSON schema."""
    return {
        "headers": record["headers"],
        "body": record["body"],
        "version": record["version"],
        "uri": record["uri"],
        "method": record["method"],
    }


def get_harness_exe(engine: str = "wing", rebuild: bool = False) -> Path:
    if engine not in ENGINE_SPECS:
        raise ValueError(f"Unsupported engine: {engine}")
    src, exe, label = ENGINE_SPECS[engine]
    return ensure_binary(src, exe, label, force_rebuild=rebuild)


def evaluate_raw_batch(
    items: list[tuple[str, bytes]],
    engine: str = "wing",
    rebuild: bool = False,
) -> dict[str, dict[str, Any]]:
    """Evaluates named raw HTTP/1.1 byte streams via a compiled Goose harness."""
    exe = get_harness_exe(engine=engine, rebuild=rebuild)
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".tsv", encoding="utf-8", delete=False
    ) as tmp:
        tsv_path = Path(tmp.name)
        for name, raw in items:
            tmp.write(f"{name}\t{raw.hex()}\n")
    try:
        rows = run_goose_harness(exe, tsv_path)
    finally:
        tsv_path.unlink(missing_ok=True)

    results: dict[str, dict[str, Any]] = {}
    for name, raw in items:
        cols = rows.get(name)
        if not cols:
            results[name] = {
                "accepted": False,
                "engine": engine,
                "verdict": "ERROR",
                "status": 500,
                "error": "missing_harness_row",
            }
            continue
        verdict = cols[1]
        srv_status = int(cols[7]) if len(cols) > 7 else 0
        if verdict != "ACCEPT":
            status = srv_status if srv_status >= 400 else 400
            if verdict == "REJECT_413":
                status = 413
            elif verdict == "REJECT_431":
                status = 431
            results[name] = {
                "accepted": False,
                "engine": engine,
                "verdict": verdict,
                "status": status,
                "error": f"rejected:{verdict}",
            }
            continue
        results[name] = _extract_accepted_request(raw, cols, engine)
    return results


def evaluate_raw_bytes(raw: bytes, engine: str = "wing", rebuild: bool = False) -> dict[str, Any]:
    """Evaluates a single raw HTTP/1.1 byte buffer."""
    return evaluate_raw_batch([("req", raw)], engine=engine, rebuild=rebuild)["req"]


def _format_http_json_response(status: int, reason: str, payload: dict[str, Any]) -> bytes:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    head = (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("ascii")
    return head + body


class _GardenTcpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(0.25)
        chunks = bytearray()
        while len(chunks) < 65536:
            try:
                part = self.request.recv(8192)
            except TimeoutError:
                break
            except OSError:
                break
            if not part:
                break
            chunks.extend(part)
            if len(part) < 8192 and b"\r\n\r\n" in chunks:
                break

        raw = bytes(chunks)
        engine: str = getattr(self.server, "garden_engine", "wing")
        if not raw:
            resp = _format_http_json_response(
                400, "Bad Request", {"error": "empty_request", "status": 400}
            )
            self.request.sendall(resp)
            return

        res = evaluate_raw_bytes(raw, engine=engine)
        if res["accepted"]:
            resp = _format_http_json_response(200, "OK", _to_garden_origin_echo(res))
        else:
            st = int(res.get("status", 400))
            resp = _format_http_json_response(
                st,
                "Bad Request",
                {"error": res["error"], "status": st, "verdict": res["verdict"]},
            )
        self.request.sendall(resp)


class HttpGardenOriginServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address: tuple[str, int], engine: str = "wing") -> None:
        self.garden_engine = engine
        super().__init__(server_address, _GardenTcpHandler)


def _probe_garden_tcp(port: int, raw: bytes) -> tuple[int, dict[str, Any]]:
    with socket.create_connection(("127.0.0.1", port), timeout=3.0) as sock:
        sock.sendall(raw)
        sock.shutdown(socket.SHUT_WR)
        buf = bytearray()
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            buf.extend(chunk)
    head, _, body = bytes(buf).partition(b"\r\n\r\n")
    status = int(head.split(b" ", 2)[1])
    return status, json.loads(body.decode("utf-8"))


def run_self_test(rebuild: bool = False) -> int:
    corpus = build_smuggling_corpus()
    items = [(v.name, v.raw) for v in corpus]
    wing_map = evaluate_raw_batch(items, engine="wing", rebuild=rebuild)
    h1_map = evaluate_raw_batch(items, engine="wing_h1", rebuild=rebuild)

    passed = 0
    failed = 0
    print("\nExecuting HTTP Garden Adapter Self-Test (wing vs wing_h1 + live TCP origin)...")
    for vec in corpus:
        w = wing_map[vec.name]
        h = h1_map[vec.name]
        w_ok = w["accepted"] == vec.expect_accept
        h_ok = h["accepted"] == vec.expect_accept
        if vec.expect_accept:
            w_echo = _to_garden_origin_echo(w) if w["accepted"] else {}
            h_echo = _to_garden_origin_echo(h) if h["accepted"] else {}
            body_match = (
                w["accepted"] and base64.b64decode(w["body"]) == vec.expected_body
            )
            consumed_ok = vec.expected_consumed < 0 or (
                w.get("consumed") == vec.expected_consumed
                and h.get("consumed") == vec.expected_consumed
            )
            ok = w_ok and h_ok and w_echo == h_echo and body_match and consumed_ok
        else:
            ok = w_ok and h_ok and w.get("status", 0) >= 400 and h.get("status", 0) >= 400
        if ok:
            passed += 1
            tag = "ACCEPT" if vec.expect_accept else f"REJECT({w.get('status')})"
            print(f"  [PASS] [batch:{vec.category:10s}] {vec.name:36s} -> {tag}")
        else:
            failed += 1
            print(f"  [FAIL] [batch:{vec.category:10s}] {vec.name:36s} w={w} h1={h}")

    # Live TCP origin-echo verification for both wing and wing_h1
    tcp_probes = [
        ("baseline_get_http11", True),
        ("baseline_post_cl", True),
        ("baseline_post_chunked", True),
        ("cl_te_conflict", False),
        ("te_cl_conflict", False),
        ("obs_fold_continuation", False),
    ]
    vec_by_name = {v.name: v for v in corpus}
    for engine in ("wing", "wing_h1"):
        srv = HttpGardenOriginServer(("127.0.0.1", 0), engine=engine)
        port = srv.server_address[1]
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        try:
            for name, expect_ok in tcp_probes:
                vec = vec_by_name[name]
                st, payload = _probe_garden_tcp(port, vec.raw)
                if expect_ok:
                    dec_body = base64.b64decode(payload.get("body", ""))
                    ok = (
                        st == 200
                        and set(payload.keys()) == {"method", "uri", "version", "headers", "body"}
                        and dec_body == vec.expected_body
                    )
                else:
                    ok = st >= 400 and "error" in payload
                if ok:
                    passed += 1
                    print(f"  [PASS] [tcp:{engine:7s}] {name:36s} -> HTTP {st}")
                else:
                    failed += 1
                    print(f"  [FAIL] [tcp:{engine:7s}] {name:36s} -> HTTP {st} {payload}")
        finally:
            srv.shutdown()
            srv.server_close()

    total = passed + failed
    print(f"\nHTTP Garden Adapter Self-Test: {passed}/{total} passed, {failed} failed.")
    return 0 if failed == 0 and total > 0 else 1


def run_eval_mode(engine: str, raw_b64: str, rebuild: bool = False) -> int:
    if raw_b64:
        raw = base64.b64decode(raw_b64)
        print(json.dumps(evaluate_raw_bytes(raw, engine=engine, rebuild=rebuild)))
        return 0

    for line in sys.stdin:
        text = line.strip()
        if not text:
            continue
        obj = json.loads(text)
        raw = base64.b64decode(obj["raw_b64"])
        eng = obj.get("engine", engine)
        print(json.dumps(evaluate_raw_bytes(raw, engine=eng, rebuild=rebuild)))
    return 0


def main() -> None:
    default_engine = os.environ.get("GARDEN_ENGINE", "wing")
    parser = argparse.ArgumentParser(
        description="narfindustries/http-garden origin-echo adapter for goose-wing"
    )
    parser.add_argument(
        "--mode",
        choices=("serve", "eval"),
        default="eval",
        help="Run TCP origin-echo server (`serve`) or JSON stdin/arg evaluator (`eval`)",
    )
    parser.add_argument(
        "--engine",
        choices=("wing", "wing_h1"),
        default=default_engine if default_engine in ENGINE_SPECS else "wing",
        help="Goose HTTP/1.1 parser harness to expose",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Bind host for --mode serve")
    parser.add_argument("--port", type=int, default=80, help="Bind port for --mode serve")
    parser.add_argument("--raw-b64", default="", help="Base64 raw HTTP request for --mode eval")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Verify wing vs wing_h1 parity and live TCP http-garden JSON origin echo",
    )
    parser.add_argument("--rebuild", action="store_true", help="Force rebuild Goose harnesses")
    args = parser.parse_args()

    if args.self_test:
        sys.exit(run_self_test(rebuild=args.rebuild))

    if args.mode == "serve":
        get_harness_exe(engine=args.engine, rebuild=args.rebuild)
        srv = HttpGardenOriginServer((args.host, args.port), engine=args.engine)
        print(
            f"[*] goose-wing HTTP Garden origin ({args.engine}) listening on "
            f"{args.host}:{srv.server_address[1]}",
            flush=True,
        )
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            srv.server_close()
        sys.exit(0)

    sys.exit(run_eval_mode(engine=args.engine, raw_b64=args.raw_b64, rebuild=args.rebuild))


if __name__ == "__main__":
    main()
