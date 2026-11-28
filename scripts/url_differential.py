#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""Differential oracle comparing wing core/url against Go net/url.

Usage:
    python scripts/url_differential.py [--random N] [--seed S] [-v]
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import random
import subprocess
import sys
import tempfile
import time
from collections import Counter

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_PORTS = {"http": b"80", "https": b"443", "ws": b"80", "wss": b"443", "ftp": b"21"}
SPECIAL_SCHEMES = {"http", "https", "ws", "wss", "ftp", "file"}


def hex_or_dash(data: bytes) -> str:
    return "-" if not data else data.hex()


def unhex(tok: str) -> bytes:
    if tok == "-":
        return b""
    return bytes.fromhex(tok)


def build_binaries(build_dir: str) -> tuple[str, str]:
    go_bin = os.path.join(build_dir, "urloracle.exe" if os.name == "nt" else "urloracle")
    wing_bin = os.path.join(build_dir, "url_verdict.exe" if os.name == "nt" else "url_verdict")

    res_go = subprocess.run(
        ["go", "build", "-o", go_bin, os.path.join(REPO_ROOT, "tests", "fuzz", "urloracle.go")],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if res_go.returncode != 0:
        raise RuntimeError(f"go build urloracle failed:\n{res_go.stderr}")

    goose_cmd = ["goose", "build"]
    if os.name == "nt":
        goose_cmd.extend(["--cc", "gcc"])
    goose_cmd.extend(
        ["-O2", os.path.join(REPO_ROOT, "tests", "fuzz", "url_verdict.goose"), "-o", wing_bin]
    )
    res_wing = subprocess.run(goose_cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    if res_wing.returncode != 0:
        raise RuntimeError(f"goose build url_verdict failed:\n{res_wing.stderr}\n{res_wing.stdout}")

    return go_bin, wing_bin


def curated_cases() -> list[tuple[str, bytes, bytes, str]]:
    """Returns list of (op, base_or_raw, ref_or_empty, label)."""
    cases: list[tuple[str, bytes, bytes, str]] = []
    parse_inputs = [
        ("http://example.com", "basic_http"),
        ("https://example.com:443/a/b?c=1#d", "default_https_port"),
        ("http://example.com:80/a/b", "default_http_port"),
        ("http://example.com:8080/a/b/../c/./d", "dot_segments"),
        ("HTTP://ExAmPlE.COM/Path", "upper_scheme_host"),
        ("http://user:pass@example.com:8443/x?y=1&z=2#frag", "userinfo_port"),
        ("http://[::1]:8080/ipv6", "ipv6_loopback"),
        ("http://[2001:db8::1]/", "ipv6_basic"),
        ("http://[2001:0db8:0000:0000:0000:ff00:0042:8329]/x", "ipv6_canonical"),
        ("https://evil.com\\@good.com/", "backslash_at_confusion"),
        ("https://good.com@evil.com/", "authority_at_confusion"),
        ("http://127.0.0.1/admin", "ipv4_loopback"),
        ("http://example.com:0/port0", "port_zero"),
        ("http://example.com:65535/portmax", "port_max"),
        ("http://example.com:65536/port_overflow", "port_overflow"),
        ("http://example.com:99999/", "port_huge"),
        ("http://example.com:-1/", "port_negative"),
        ("http://example.com:/empty_port", "empty_port"),
        ("http:///missing_host", "missing_host"),
        ("/relative/only", "relative_no_base"),
        ("//protocol-relative.example/a", "proto_relative_no_base"),
        ("javascript:alert(1)", "non_special_opaque"),
        ("data:text/plain;base64,SGVsbG8=", "data_scheme"),
        ("mailto:user@example.com", "mailto_scheme"),
        ("http://example.com/a?b=1#c#d", "double_hash"),
        ("http://example.com/a%2Fb/c%20d?k=v%26w#f%201", "percent_encoded"),
        ("http://example.com/\tpath\n", "ctl_tab_lf"),
        (" http://example.com/ ", "outer_spaces"),
        ("http://ex ample.com/", "space_in_host"),
        ("file:///etc/passwd", "file_empty_host"),
        ("file://localhost/etc/passwd", "file_localhost"),
        ("http://example.com/?", "empty_query_mark"),
        ("http://example.com/#", "empty_frag_mark"),
        ("", "empty_input"),
    ]
    for raw, label in parse_inputs:
        cases.append(("P", raw.encode("utf-8"), b"", label))

    base = b"http://a/b/c/d;p?q"
    rfc3986_rel = [
        ("g:h", "rfc3986_5_4_1_1"),
        ("g", "rfc3986_5_4_1_2"),
        ("./g", "rfc3986_5_4_1_3"),
        ("g/", "rfc3986_5_4_1_4"),
        ("/g", "rfc3986_5_4_1_5"),
        ("//g", "rfc3986_5_4_1_6"),
        ("?y", "rfc3986_5_4_1_7"),
        ("g?y", "rfc3986_5_4_1_8"),
        ("#s", "rfc3986_5_4_1_9"),
        ("g#s", "rfc3986_5_4_1_10"),
        ("g?y#s", "rfc3986_5_4_1_11"),
        (";x", "rfc3986_5_4_1_12"),
        ("g;x", "rfc3986_5_4_1_13"),
        ("g;x?y#s", "rfc3986_5_4_1_14"),
        ("", "rfc3986_5_4_1_15"),
        (".", "rfc3986_5_4_1_16"),
        ("./", "rfc3986_5_4_1_17"),
        ("..", "rfc3986_5_4_1_18"),
        ("../", "rfc3986_5_4_1_19"),
        ("../g", "rfc3986_5_4_1_20"),
        ("../..", "rfc3986_5_4_1_21"),
        ("../../", "rfc3986_5_4_1_22"),
        ("../../g", "rfc3986_5_4_1_23"),
        ("../../../g", "rfc3986_5_4_2_1"),
        ("../../../../g", "rfc3986_5_4_2_2"),
        ("/./g", "rfc3986_5_4_2_3"),
        ("/../g", "rfc3986_5_4_2_4"),
        ("g.", "rfc3986_5_4_2_5"),
        (".g", "rfc3986_5_4_2_6"),
        ("g..", "rfc3986_5_4_2_7"),
        ("..g", "rfc3986_5_4_2_8"),
        ("./../g", "rfc3986_5_4_2_9"),
        ("./g/.", "rfc3986_5_4_2_10"),
        ("g/./h", "rfc3986_5_4_2_11"),
        ("g/../h", "rfc3986_5_4_2_12"),
        ("g;x=1/./y", "rfc3986_5_4_2_13"),
        ("g;x=1/../y", "rfc3986_5_4_2_14"),
        ("g?y/./x", "rfc3986_5_4_2_15"),
        ("g?y/../x", "rfc3986_5_4_2_16"),
        ("g#s/./x", "rfc3986_5_4_2_17"),
        ("g#s/../x", "rfc3986_5_4_2_18"),
        ("http:g", "rfc3986_5_4_2_19_same_scheme_rel"),
        ("https://other.example/x", "resolve_abs_https"),
        ("//evil.com/p", "resolve_proto_rel"),
        ("\\\\evil.com\\p", "resolve_double_backslash"),
    ]
    for ref, label in rfc3986_rel:
        cases.append(("R", base, ref.encode("utf-8"), label))

    return cases


def random_cases(n: int, seed: int) -> list[tuple[str, bytes, bytes, str]]:
    rng = random.Random(seed)
    schemes = [b"http", b"https", b"ws", b"wss", b"ftp", b"HTTP", b"custom", b"file", b""]
    hosts = [
        b"example.com",
        b"ExAmPlE.Org",
        b"127.0.0.1",
        b"[::1]",
        b"[2001:db8::1]",
        b"sub.domain.test",
        b"localhost",
        b"",
    ]
    ports = [b"", b":80", b":443", b":8080", b":0", b":65535", b":70000", b":bad", b":"]
    auths = [b"", b"user@", b"user:pass@", b"u%3A1:p%402@", b"evil.com\\@", b"a:b:c@"]
    segs = [b"a", b"b", b".", b"..", b"%2e", b"%2e%2e", b"x y", b"c;p", b"index.html", b"\\k"]
    queries = [b"", b"?", b"?a=1", b"?a=1&b=two%20words", b"?q=a/b/../c", b"?x=\\"]
    frags = [b"", b"#", b"#top", b"#a/b/../c", b"#s%201"]

    def make_raw() -> bytes:
        sch = rng.choice(schemes)
        sep = b"://" if sch and rng.random() < 0.85 else (b":" if sch else b"")
        auth = rng.choice(auths)
        host = rng.choice(hosts)
        port = rng.choice(ports)
        pcount = rng.randint(0, 4)
        psep = rng.choice([b"/", b"\\", b""])
        path = b"/" + b"/".join(rng.choice(segs) for _ in range(pcount)) if pcount else psep
        url = sch + sep + auth + host + port + path + rng.choice(queries) + rng.choice(frags)
        if rng.random() < 0.12:
            ins = rng.choice([b"\x00", b"\t", b"\n", b"\r", b" ", b"\\", b"@", b"?"])
            pos = rng.randint(0, len(url))
            url = url[:pos] + ins + url[pos:]
        return url

    cases: list[tuple[str, bytes, bytes, str]] = []
    bases = [b"http://a.example/b/c/d?q=1#f", b"https://[::1]:8443/x/y/", b"http://user@h.test/p"]
    for i in range(n):
        if i % 3 == 0:
            base = rng.choice(bases)
            if rng.random() < 0.7:
                pcount = rng.randint(0, 4)
                ref = (
                    rng.choice([b"", b"/", b"./", b"../", b"//other.test/"])
                    + b"/".join(rng.choice(segs) for _ in range(pcount))
                    + rng.choice(queries)
                    + rng.choice(frags)
                )
            else:
                ref = make_raw()
            cases.append(("R", base, ref, f"rand_r_{i}"))
        else:
            cases.append(("P", make_raw(), b"", f"rand_p_{i}"))
    return cases


def parse_verdict(line: str) -> tuple[bool, dict[str, bytes]]:
    parts = line.rstrip("\r\n").split("\t")
    if not parts or parts[0] != "OK" or len(parts) < 10:
        return False, {}
    return True, {
        "scheme": unhex(parts[1]),
        "user": unhex(parts[2]),
        "pass": unhex(parts[3]),
        "host": unhex(parts[4]),
        "port": unhex(parts[5]),
        "path": unhex(parts[6]),
        "query": unhex(parts[7]),
        "frag": unhex(parts[8]),
        "href": unhex(parts[9]),
    }


def normalize_host_cmp(go_host: bytes, wg_host: bytes, scheme: str) -> bool:
    if go_host.lower() == wg_host.lower():
        return True
    if scheme == "file" and go_host.lower() == b"localhost" and wg_host == b"":
        return True
    gh = go_host.decode("latin1")
    wh = wg_host.decode("latin1")
    if wh.startswith("[") and wh.endswith("]"):
        wh = wh[1:-1]
    if gh.startswith("[") and gh.endswith("]"):
        gh = gh[1:-1]
    try:
        return ipaddress.IPv6Address(gh) == ipaddress.IPv6Address(wh)
    except ValueError:
        return False


def rfc3986_remove_dot_segments(path: bytes) -> bytes:
    """RFC 3986 Section 5.2.4 dot-segment normalization for standalone URL compare."""
    if not path:
        return path
    inp = path.decode("latin1")
    out: list[str] = []
    while inp:
        if inp.startswith("../"):
            inp = inp[3:]
        elif inp.startswith("./"):
            inp = inp[2:]
        elif inp.startswith("/./"):
            inp = "/" + inp[3:]
        elif inp == "/.":
            inp = "/"
        elif inp.startswith("/../"):
            inp = "/" + inp[4:]
            if out:
                out.pop()
        elif inp == "/..":
            inp = "/"
            if out:
                out.pop()
        elif inp in (".", ".."):
            inp = ""
        else:
            if inp.startswith("/"):
                idx = inp.find("/", 1)
                if idx == -1:
                    out.append(inp)
                    inp = ""
                else:
                    out.append(inp[:idx])
                    inp = inp[idx:]
            else:
                idx = inp.find("/")
                if idx == -1:
                    out.append(inp)
                    inp = ""
                else:
                    out.append(inp[:idx])
                    inp = inp[idx:]
    return "".join(out).encode("latin1")


def classify_case(
    op: str,
    inp_a: bytes,
    inp_b: bytes,
    go_line: str,
    wing_line: str,
) -> tuple[str, str]:
    go_ok, go = parse_verdict(go_line)
    wing_ok, wg = parse_verdict(wing_line)

    if not go_ok and not wing_ok:
        return "both_reject", ""
    if go_ok and not wing_ok:
        if op == "P" and b":" not in inp_a.split(b"/", 1)[0]:
            return "expected_spec_diff", "relative_without_base"
        return "wing_stricter", f"go_ok(scheme={go['scheme']!r},host={go['host']!r}) vs wing_err"
    if not go_ok and wing_ok:
        raw = inp_b if op == "R" else inp_a
        if any(b < 0x20 or b == 0x20 or b == 0x7F or b == ord("\\") for b in raw):
            return "expected_spec_diff", "whatwg_ws_ctl_or_backslash"
        return "go_stricter", f"go_err vs wing_ok(href={wg['href']!r})"

    wg_q = wg["query"][1:] if wg["query"].startswith(b"?") else wg["query"]
    wg_f = wg["frag"][1:] if wg["frag"].startswith(b"#") else wg["frag"]
    wg_scheme = wg["scheme"].lower()
    go_scheme = go["scheme"].lower()

    go_port = go["port"]
    wg_port = wg["port"]
    sch_str = wg_scheme.decode("latin1")
    if not wg_port and sch_str in DEFAULT_PORTS and go_port == DEFAULT_PORTS[sch_str]:
        wg_port = go_port

    go_path = go["path"]
    wg_path = wg["path"]
    if sch_str in SPECIAL_SCHEMES and go_path == b"" and wg_path == b"/":
        go_path = b"/"

    diffs: list[str] = []
    if go_scheme != wg_scheme:
        diffs.append(f"scheme:{go_scheme!r}!={wg_scheme!r}")
    if not normalize_host_cmp(go["host"], wg["host"], sch_str):
        diffs.append(f"host:{go['host']!r}!={wg['host']!r}")
    if go_port != wg_port:
        diffs.append(f"port:{go_port!r}!={wg_port!r}")
    if go_path != wg_path:
        diffs.append(f"path:{go_path!r}!={wg_path!r}")
    if go["query"] != wg_q:
        diffs.append(f"query:{go['query']!r}!={wg_q!r}")
    if go["frag"] != wg_f:
        diffs.append(f"frag:{go['frag']!r}!={wg_f!r}")
    if go["user"] != wg["user"] or go["pass"] != wg["pass"]:
        diffs.append(f"auth:({go['user']!r},{go['pass']!r})!=({wg['user']!r},{wg['pass']!r})")

    if not diffs:
        return "exact_match", ""

    raw = inp_b if op == "R" else inp_a
    # 1. Special scheme without // (Go parses RFC 3986 opaque; WHATWG parses authority)
    if (
        sch_str in SPECIAL_SCHEMES
        and (sch_str.encode("latin1") + b"://") not in raw.lower()
        and op == "P"
    ):
        return "expected_spec_diff", "special_scheme_without_slashes"
    # 2. Standalone parse dot-segment normalization or %2e (WHATWG collapses on Parse; Go leaves raw)
    if (
        sch_str in SPECIAL_SCHEMES
        and go_path.replace(b"%2e", b".").replace(b"%2E", b".") != wg_path
        and rfc3986_remove_dot_segments(go_path.replace(b"%2e", b".").replace(b"%2E", b"."))
        == wg_path
        and all(d.startswith("path:") for d in diffs)
    ):
        return "expected_spec_diff", "whatwg_dot_segment_normalization"
    # Same dot-segment + space-in-path normalization combined
    go_path_norm = rfc3986_remove_dot_segments(go_path.replace(b"%2e", b".").replace(b"%2E", b"."))
    if go_path_norm.replace(b"%20", b" ") == wg_path and all(d.startswith("path:") for d in diffs):
        return "expected_spec_diff", "path_dot_or_space_repr"
    # 3. Special scheme backslash -> slash in WHATWG
    if b"\\" in raw and sch_str in SPECIAL_SCHEMES:
        return "expected_spec_diff", "backslash_in_special_scheme"
    # 4. Same-scheme relative reference like "http:g" against http base
    if op == "R" and b":" in inp_b and b"://" not in inp_b:
        return "expected_spec_diff", "same_scheme_relative_ref"
    # 5. Trailing empty ? or # or unescaped # in fragment (Go %23 vs WHATWG #)
    if (b"?" in raw or b"#" in raw) and all(d.startswith(("query:", "frag:")) for d in diffs):
        if go["frag"].replace(b"%23", b"#") == wg_f and go["query"] == wg_q:
            return "expected_spec_diff", "fragment_hash_encoding"
        if (go["query"] == b"" and wg["query"] == b"?") or (
            go["frag"] == b"" and wg["frag"] == b"#"
        ):
            return "expected_spec_diff", "empty_query_or_hash_delimiter"
    # 5b. RFC 3986 §5.2.2 / WHATWG empty or '#' relative reference drops base fragment (Go keeps base #frag)
    if op == "R" and inp_b in (b"", b"#") and diffs == [f"frag:{go['frag']!r}!={wg_f!r}"] and wg_f == b"":
        return "expected_spec_diff", "rfc3986_empty_ref_drops_base_frag"
    # 6. Non-special opaque schemes
    if sch_str not in SPECIAL_SCHEMES and all(
        d.startswith(("path:", "host:", "auth:", "frag:")) for d in diffs
    ):
        return "expected_spec_diff", "non_special_opaque_scheme"
    # 7. Percent-encoded credentials/paths
    if b"%" in raw and all(d.startswith(("auth:", "path:", "host:")) for d in diffs):
        return "expected_spec_diff", "percent_encoding_repr"
    # 7a. WHATWG §4.3 embedded '@' in userinfo percent-encoded as '%40' (Go keeps raw '@')
    if (
        raw.count(b"@") >= 2
        and all(d.startswith("auth:") for d in diffs)
        and go["user"].replace(b"@", b"%40") == wg["user"]
        and go["pass"].replace(b"@", b"%40") == wg["pass"]
    ):
        return "expected_spec_diff", "whatwg_userinfo_at_escape"
    # 7b. WHATWG §3.5 decimal/partial IPv4 host normalization (e.g. '12' -> '0.0.0.12', '127.0.' -> '127.0.0.0')
    if sch_str in SPECIAL_SCHEMES and all(d.startswith("host:") for d in diffs):
        expected_ipv4 = _whatwg_expected_ipv4(go["host"])
        if expected_ipv4 is not None and expected_ipv4 == wg["host"]:
            return "expected_spec_diff", "whatwg_ipv4_host_normalization"
    # 8. Space / unescaped ASCII in path/query/frag
    if any(b < 0x21 or b >= 0x7F for b in raw) and all(
        d.startswith(("path:", "query:", "frag:", "auth:")) for d in diffs
    ):
        return "expected_spec_diff", "whatwg_percent_encode_or_trim"

    return "unexpected_mismatch", "; ".join(diffs)


def _whatwg_expected_ipv4(host_b: bytes) -> bytes | None:
    if not host_b:
        return None
    parts = host_b.split(b".")
    if parts[-1] == b"":
        if len(parts) == 1:
            return None
        parts.pop()
    if not parts or len(parts) > 4:
        return None
    nums: list[int] = []
    for p in parts:
        if not p:
            return None
        try:
            if p.startswith((b"0x", b"0X")):
                val = 0 if len(p) == 2 else int(p[2:], 16)
            elif len(p) >= 2 and p.startswith(b"0"):
                val = int(p, 8)
            else:
                val = int(p, 10)
        except ValueError:
            return None
        if val < 0:
            return None
        nums.append(val)
    if any(n > 255 for n in nums[:-1]) or nums[-1] >= 256 ** (5 - len(nums)):
        return None
    ipv4 = nums[-1]
    for i, n in enumerate(nums[:-1]):
        ipv4 += n * (256 ** (3 - i))
    return str(ipaddress.IPv4Address(ipv4)).encode("ascii")


def main() -> int:
    ap = argparse.ArgumentParser(description="URL differential harness (wing vs Go net/url)")
    ap.add_argument("--random", type=int, default=1000, help="Number of random URL cases")
    ap.add_argument("--seed", type=int, default=20261113, help="PRNG seed")
    ap.add_argument("-v", "--verbose", action="store_true", help="Print sample diffs")
    args = ap.parse_args()

    t0 = time.time()
    cases = curated_cases() + random_cases(args.random, args.seed)

    with tempfile.TemporaryDirectory(prefix="wing_url_diff_") as tmpdir:
        go_bin, wing_bin = build_binaries(tmpdir)
        batch_path = os.path.join(tmpdir, "batch.txt")
        with open(batch_path, "w", encoding="ascii", newline="\n") as f:
            for op, a, b, _ in cases:
                if op == "P":
                    f.write(f"P\t{hex_or_dash(a)}\n")
                else:
                    f.write(f"R\t{hex_or_dash(a)}\t{hex_or_dash(b)}\n")

        res_go = subprocess.run([go_bin, batch_path], capture_output=True, text=True)
        if res_go.returncode != 0:
            print(f"urloracle failed: {res_go.stderr}", file=sys.stderr)
            return 2
        res_wing = subprocess.run([wing_bin, batch_path], capture_output=True, text=True)
        if res_wing.returncode != 0:
            print(f"url_verdict failed: {res_wing.stderr}\n{res_wing.stdout}", file=sys.stderr)
            return 2

    go_lines = [ln for ln in res_go.stdout.splitlines() if ln.strip()]
    wing_lines = [ln for ln in res_wing.stdout.splitlines() if ln.strip()]
    if len(go_lines) != len(cases) or len(wing_lines) != len(cases):
        print(
            f"line count mismatch: cases={len(cases)} go={len(go_lines)} wing={len(wing_lines)}",
            file=sys.stderr,
        )
        return 2

    counts: Counter[str] = Counter()
    spec_reasons: Counter[str] = Counter()
    mismatches: list[tuple[str, str, bytes, bytes, str]] = []
    stricter_samples: list[tuple[str, str, bytes, bytes, str]] = []

    for (op, a, b, label), gl, wl in zip(cases, go_lines, wing_lines, strict=True):
        cat, detail = classify_case(op, a, b, gl, wl)
        counts[cat] += 1
        if cat == "expected_spec_diff":
            spec_reasons[detail] += 1
        elif cat == "unexpected_mismatch":
            mismatches.append((label, op, a, b, detail))
        elif cat in ("wing_stricter", "go_stricter") and len(stricter_samples) < 12:
            stricter_samples.append((f"{cat}:{label}", op, a, b, detail))

    dt = time.time() - t0
    print(
        f"URL differential ({len(cases)} cases, {dt:.2f}s): "
        f"exact_match={counts['exact_match']}, "
        f"both_reject={counts['both_reject']}, "
        f"expected_spec_diff={counts['expected_spec_diff']}, "
        f"wing_stricter={counts['wing_stricter']}, "
        f"go_stricter={counts['go_stricter']}, "
        f"unexpected_mismatch={counts['unexpected_mismatch']}"
    )
    if args.verbose and spec_reasons:
        print("  expected_spec_diff breakdown:", dict(spec_reasons))
    if args.verbose and stricter_samples:
        for lbl, op, a, b, detail in stricter_samples:
            print(f"  [stricter] {lbl} ({op} {a!r} {b!r}): {detail}")

    for lbl, op, a, b, detail in mismatches[:20]:
        print(f"MISMATCH [{lbl}] {op} {a!r} {b!r}: {detail}", file=sys.stderr)

    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
