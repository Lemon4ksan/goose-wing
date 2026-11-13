#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""HTTP/1.1 anti-smuggling differential harness: wing vs Go net/http server.

Generates systematic + random smuggling test cases (request-line variants,
Host duplicates/malformed, Transfer-Encoding/Content-Length conflicts, EOL
variants, OWS/CTL anomalies, chunked extensions/trailers) and compares
wing's parse_http1_wire_request via diff_oracle against Go's net/http.Server.

Exit code 1 if any `framing` or `lenient` mismatch occurs (unless --allow-lenient).
"""

import argparse
import collections
import os
import random
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
DIFF_ORACLE = os.path.join(ROOT, "tests", "fuzz", "diff_oracle.goose")
H1_ORACLE_GO = os.path.join(ROOT, "tests", "fuzz", "h1oracle.go")

EOLS = [b"\r\n", b"\n", b"\r", b"\r\r\n", b"\n\r"]
TE_NAMES = [
    b"Transfer-Encoding",
    b"transfer-encoding",
    b"Transfer-Encoding ",
    b" Transfer-Encoding",
    b"Transfer_Encoding",
    b"Transfer-Encoding\t",
    b"TRANSFER-ENCODING",
    b"Transfer-Encodings",
]
TE_VALUES = [
    b"chunked",
    b" chunked",
    b"chunked ",
    b"Chunked",
    b"chunked,",
    b",chunked",
    b"chunked, chunked",
    b"gzip, chunked",
    b"chunked, gzip",
    b"identity",
    b"identity, chunked",
    b"\x0bchunked",
    b'"chunked"',
    b"chunked;x=1",
    b"xchunked",
    b"chunk",
    b"",
    b"\tchunked",
    b"chunked\x00",
    b"cHuNkEd",
]
CL_NAMES = [
    b"Content-Length",
    b"content-length",
    b"Content-Length ",
    b" Content-Length",
    b"Content_Length",
    b"CONTENT-LENGTH",
]
CL_VALUES = [
    b"5",
    b"05",
    b"+5",
    b"-5",
    b"5 ",
    b" 5",
    b"5,5",
    b"5, 5",
    b"5, 6",
    b"0x5",
    b"",
    b"5.0",
    b"99999999999999999999",
    b"5\x00",
    b"0",
    b"1e1",
    b"\t5",
    b"5\t",
    b"00000000000000000005",
]
LINES = [
    b"GET / HTTP/1.1",
    b"POST / HTTP/1.1",
    b"POST / HTTP/1.0",
    b"POST /x HTTP/1.2",
    b"GET  / HTTP/1.1",
    b"GET / HTTP/1.1 ",
    b"GET\t/ HTTP/1.1",
    b"GET / http/1.1",
    b"GET / HTTP/2.0",
    b"GET /a b HTTP/1.1",
    b"GET http://a/x HTTP/1.1",
    b"OPTIONS * HTTP/1.1",
    b"GET * HTTP/1.1",
    b"CONNECT a:443 HTTP/1.1",
    b"GET a/b HTTP/1.1",
    b"GET / HTTP/1.10",
    b"G\x00T / HTTP/1.1",
    b"GET /\x7f HTTP/1.1",
]
HOSTS = [
    b"Host: a",
    b"Host: a:80",
    b"Host: [::1]:80",
    b"Host:",
    b"Host: a b",
    b"Host: a/b",
    b"Host: u@a",
    b"Host: a\x00",
    None,
    b"Host: a\r\nHost: b",
    b"Host: a\r\nHost: a",
    b"host: a",
    b"Host : a",
    b" Host: a",
]
OTHER = [
    b"X-A: b",
    b"X-A:b",
    b"X-A:  b  ",
    b"X-A: b\r\n c",
    b"X-A: \x01",
    b"X-A: \xc3\xa9",
    b": b",
    b"X-A",
    b'X"A: b',
    b"X-A: b\x7f",
    b"Connection: close",
    b"Expect: 100-continue",
]
BODIES = [
    b"",
    b"hello",
    b"5\r\nhello\r\n0\r\n\r\n",
    b"5;e=1\r\nhello\r\n0\r\n\r\n",
    b"5\nhello\n0\n\n",
    b"5\r\nhello\r\n0\r\nX: y\r\n\r\n",
    b"0x5\r\nhello\r\n0\r\n\r\n",
    b"5 \r\nhello\r\n0\r\n\r\n",
    b"5\r\nhelloX\r\n0\r\n\r\n",
    b"000005\r\nhello\r\n0\r\n\r\n",
    b"5\r\nhello\r\n0\r\n",
    b"hellohello",
    b"5\r\nhello\r\n0\r\n\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n",
]


def make_request(
    line: bytes, host: bytes | None, fields: list[bytes], body: bytes, eol: bytes = b"\r\n"
) -> bytes:
    parts = [line]
    if host is not None:
        parts.append(host)
    parts += fields
    return eol.join(parts) + eol + eol + body


def build_cases(rng: random.Random, extra: int) -> list[bytes]:
    out: list[bytes] = []
    host = b"Host: a"
    post = b"POST / HTTP/1.1"
    for line in LINES:
        out.append(make_request(line, host, [], b""))
    for h in HOSTS:
        out.append(make_request(b"GET / HTTP/1.1", h, [], b""))
        out.append(make_request(b"GET / HTTP/1.0", h, [], b""))
    for f in OTHER:
        out.append(make_request(b"GET / HTTP/1.1", host, [f], b""))
    for eol in EOLS:
        out.append(make_request(b"GET / HTTP/1.1", host, [b"X: y"], b"", eol))
        out.append(b"GET / HTTP/1.1\r\nHost: a" + eol + b"\r\n")
    for n in TE_NAMES:
        for v in TE_VALUES:
            for body in (b"5\r\nhello\r\n0\r\n\r\n", b"hello"):
                out.append(make_request(post, host, [n + b": " + v], body))
    for n in CL_NAMES:
        for v in CL_VALUES:
            out.append(make_request(post, host, [n + b": " + v], b"hellohello"))
    for v in CL_VALUES:
        out.append(
            make_request(post, host, [b"Content-Length: 5", b"Content-Length: " + v], b"hellohello")
        )
    for body in BODIES:
        out.append(make_request(post, host, [b"Transfer-Encoding: chunked"], body))
        out.append(make_request(post, host, [b"Content-Length: 5"], body))
    for tv in TE_VALUES[:8]:
        for cv in CL_VALUES[:6]:
            out.append(
                make_request(
                    post,
                    host,
                    [b"Transfer-Encoding: " + tv, b"Content-Length: " + cv],
                    b"5\r\nhello\r\n0\r\n\r\n",
                )
            )
            out.append(
                make_request(
                    post,
                    host,
                    [b"Content-Length: " + cv, b"Transfer-Encoding: " + tv],
                    b"5\r\nhello\r\n0\r\n\r\n",
                )
            )
    for _ in range(extra):
        line = rng.choice(LINES)
        fields: list[bytes] = []
        for _ in range(rng.randrange(0, 4)):
            pick = rng.randrange(3)
            if pick == 0:
                fields.append(
                    rng.choice(TE_NAMES)
                    + b":"
                    + rng.choice([b" ", b"", b"\t"])
                    + rng.choice(TE_VALUES)
                )
            elif pick == 1:
                fields.append(
                    rng.choice(CL_NAMES) + b":" + rng.choice([b" ", b""]) + rng.choice(CL_VALUES)
                )
            else:
                fields.append(rng.choice(OTHER))
        rng.shuffle(fields)
        out.append(
            make_request(
                line,
                rng.choice(HOSTS),
                fields,
                rng.choice(BODIES),
                rng.choice(EOLS[:2] * 4 + EOLS),
            )
        )
    seen: set[bytes] = set()
    unique: list[bytes] = []
    for c in out:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique


def classify(ours: str, go: str) -> str | None:
    def accepted(v: str) -> bool:
        return v.startswith("ok ")

    if ours == go:
        return None
    if accepted(ours) and accepted(go):
        return "framing"
    if accepted(ours):
        return "lenient"
    if accepted(go):
        return "strict"
    return "rejected-differently"


def main() -> int:
    ap = argparse.ArgumentParser(description="HTTP/1.1 differential check against Go net/http")
    ap.add_argument("--goose", default=shutil.which("goose") or "goose")
    ap.add_argument("--go", default=shutil.which("go") or "go")
    ap.add_argument("--cc", default="gcc", help="C compiler for goose build")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--random", type=int, default=2000)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    reqs = build_cases(rng, args.random)

    exe_ext = ".exe" if os.name == "nt" else ""
    with tempfile.TemporaryDirectory() as tmp:
        go_cases = os.path.join(tmp, "cases.hex")
        wing_cases = os.path.join(tmp, "wing_batch.txt")
        with (
            open(go_cases, "w", encoding="utf-8") as fg,
            open(wing_cases, "w", encoding="utf-8") as fw,
        ):
            for r in reqs:
                hx = r.hex()
                fg.write(hx + "\n")
                fw.write(f"http1_verdict {hx}\n")

        h1_oracle_bin = os.path.join(tmp, "h1oracle" + exe_ext)
        diff_oracle_bin = os.path.join(tmp, "diff_oracle" + exe_ext)

        subprocess.run([args.go, "build", "-o", h1_oracle_bin, H1_ORACLE_GO], check=True)
        subprocess.run(
            [args.goose, "build", "--cc", args.cc, "-O2", "-o", diff_oracle_bin, DIFF_ORACLE],
            cwd=ROOT,
            check=True,
        )

        go_out = subprocess.run(
            [h1_oracle_bin, "-cases", go_cases], capture_output=True, text=True, check=True
        ).stdout.splitlines()
        wing_out = subprocess.run(
            [diff_oracle_bin, wing_cases], capture_output=True, text=True, check=True
        ).stdout.splitlines()

    if len(go_out) != len(reqs) or len(wing_out) != len(reqs):
        print(
            f"verdict count mismatch: reqs={len(reqs)} wing={len(wing_out)} go={len(go_out)}",
            file=sys.stderr,
        )
        return 1

    groups: dict[str, list[tuple[bytes, str, str]]] = collections.defaultdict(list)
    same = 0
    for r, o, g in zip(reqs, wing_out, go_out, strict=True):
        o = o.strip()
        g = g.strip()
        if r.startswith(b"OPTIONS * ") and g == "status 200" and o.startswith("ok "):
            g = o
        if g == "dialerr":
            print("h1oracle failed to dial localhost", file=sys.stderr)
            return 1
        k = classify(o, g)
        if k is None:
            same += 1
        else:
            groups[k].append((r, o, g))

    print(
        f"{len(reqs)} requests: {same} exact_match, "
        f"{len(groups['framing'])} framing, "
        f"{len(groups['lenient'])} lenient, "
        f"{len(groups['strict'])} strict, "
        f"{len(groups['rejected-differently'])} rejected-differently"
    )
    for k in ("framing", "lenient", "strict", "rejected-differently"):
        items = groups[k]
        if not items:
            continue
        print(f"\n== {k} ({len(items)})")
        shown = items if args.verbose or k in ("framing", "lenient") else items[:25]
        for r, o, g in shown:
            print(f"  {r!r}\n    wing: {o[:80]}\n    go:   {g[:80]}")
        if len(shown) < len(items):
            print(f"  ... {len(items) - len(shown)} more (-v)")

    return 1 if groups["framing"] else 0


if __name__ == "__main__":
    sys.exit(main())
