#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
Browser Fingerprints (JA3/JA4/JA4H/Akamai H2 / JA4DB) and WPT Conformance Runner
for goose-wing (Cookies RFC 6265bis, Redirects RFC 9110/Fetch, CORS Fetch).
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import struct
import subprocess
import sys
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
SUITE_DIR = TOOLS_DIR / "fingerprint_wpt"
HARNESS_SRC = SUITE_DIR / "fp_wpt_harness.goose"
HARNESS_EXE = BIN_DIR / ("fp_wpt_harness.exe" if sys.platform == "win32" else "fp_wpt_harness")
JA4DB_REF_PATH = SUITE_DIR / "ja4db_reference.json"
H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
T0_US = 1767225600 * 1_000_000  # 2026-01-01T00:00:00Z in microseconds


def is_grease(val: int) -> bool:
    return (val & 0x0F0F) == 0x0A0A and ((val >> 8) == (val & 0xFF))


def ensure_harness_binary(force_rebuild: bool = False) -> Path:
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    if (
        not force_rebuild
        and HARNESS_EXE.is_file()
        and HARNESS_EXE.stat().st_mtime >= HARNESS_SRC.stat().st_mtime
    ):
        return HARNESS_EXE

    print(f"[*] Building fingerprint/WPT harness: {HARNESS_SRC.name} -> {HARNESS_EXE.name}...")
    env = os.environ.copy()
    build_flags = ["-O2"]
    if sys.platform == "win32":
        build_flags = ["-O0"]
        if "GOOSE_CC" not in env:
            stack_cc = ROOT_DIR / "tools" / "gcc_stack.bat"
            if stack_cc.is_file():
                env["GOOSE_CC"] = str(stack_cc)
    cmd = ["goose", "build", *build_flags, "-o", str(HARNESS_EXE), str(HARNESS_SRC)]
    res = subprocess.run(
        cmd, check=False, cwd=str(ROOT_DIR), capture_output=True, text=True, env=env
    )
    if res.returncode != 0:
        print("[!] Failed to build fp_wpt_harness:", file=sys.stderr)
        if res.stdout:
            print(res.stdout, file=sys.stderr)
        if res.stderr:
            print(res.stderr, file=sys.stderr)
        sys.exit(1)
    print(f"[+] Built {HARNESS_EXE.name}")
    return HARNESS_EXE


# ---- Independent Wire Parsers (ClientHello -> JA3/JA4, H2 -> Akamai) --------

@dataclass
class ParsedClientHello:
    legacy_version: int
    ciphers: list[int]
    extensions: list[int]
    supported_versions: list[int]
    groups: list[int]
    ec_point_formats: list[int]
    sig_algorithms: list[int]
    sni: str
    alpn: list[str]
    has_grease: bool


def parse_client_hello_wire(raw: bytes) -> ParsedClientHello:
    pos = 0
    legacy_ver = struct.unpack_from("!H", raw, pos)[0]
    pos += 2 + 32  # legacy_version + random
    sid_len = raw[pos]
    pos += 1 + sid_len
    cs_len = struct.unpack_from("!H", raw, pos)[0]
    pos += 2
    ciphers = list(struct.unpack_from(f"!{cs_len // 2}H", raw, pos))
    pos += cs_len
    comp_len = raw[pos]
    pos += 1 + comp_len
    ext_total = struct.unpack_from("!H", raw, pos)[0]
    pos += 2
    end = pos + ext_total

    exts: list[int] = []
    supp_vers: list[int] = []
    groups: list[int] = []
    ec_fmts: list[int] = []
    sig_algs: list[int] = []
    sni = ""
    alpn: list[str] = []

    while pos + 4 <= end:
        eid, elen = struct.unpack_from("!HH", raw, pos)
        pos += 4
        body = raw[pos : pos + elen]
        pos += elen
        exts.append(eid)
        if eid == 0x0000 and len(body) >= 5:
            hlen = struct.unpack_from("!H", body, 3)[0]
            sni = body[5 : 5 + hlen].decode("ascii", errors="replace")
        elif eid == 0x000A and len(body) >= 2:
            glen = struct.unpack_from("!H", body, 0)[0]
            groups = list(struct.unpack_from(f"!{glen // 2}H", body, 2))
        elif eid == 0x000B and len(body) >= 1:
            ec_fmts = list(body[1 : 1 + body[0]])
        elif eid == 0x000D and len(body) >= 2:
            slen = struct.unpack_from("!H", body, 0)[0]
            sig_algs = list(struct.unpack_from(f"!{slen // 2}H", body, 2))
        elif eid == 0x0010 and len(body) >= 3:
            p_end = 2 + struct.unpack_from("!H", body, 0)[0]
            p = 2
            while p < p_end:
                plen = body[p]
                alpn.append(body[p + 1 : p + 1 + plen].decode("ascii", errors="replace"))
                p += 1 + plen
        elif eid == 0x002B and len(body) >= 1:
            vlen = body[0]
            supp_vers = list(struct.unpack_from(f"!{vlen // 2}H", body, 1))

    has_grease = any(is_grease(x) for x in ciphers + exts + supp_vers + groups)
    return ParsedClientHello(
        legacy_version=legacy_ver, ciphers=ciphers, extensions=exts,
        supported_versions=supp_vers, groups=groups, ec_point_formats=ec_fmts,
        sig_algorithms=sig_algs, sni=sni, alpn=alpn, has_grease=has_grease,
    )


def compute_ja3_from_ch(ch: ParsedClientHello) -> tuple[str, str]:
    c_str = "-".join(str(c) for c in ch.ciphers if not is_grease(c))
    e_str = "-".join(str(e) for e in ch.extensions if not is_grease(e))
    g_str = "-".join(str(g) for g in ch.groups if not is_grease(g))
    f_str = "-".join(str(f) for f in ch.ec_point_formats)
    ja3_text = f"{ch.legacy_version},{c_str},{e_str},{g_str},{f_str}"
    return ja3_text, hashlib.md5(ja3_text.encode("ascii")).hexdigest()


def compute_ja4_from_ch(ch: ParsedClientHello, is_quic: bool = False) -> str:
    proto = "q" if is_quic else "t"
    ver_map = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3"}
    vers = [v for v in ch.supported_versions if not is_grease(v)]
    best_v = max(vers) if vers else ch.legacy_version
    ver_s = ver_map.get(best_v, "00")
    sni_s = "d" if ch.sni else "i"
    fc = [c for c in ch.ciphers if not is_grease(c)]
    fe = [e for e in ch.extensions if not is_grease(e)]
    alpn_s = f"{ch.alpn[0][0]}{ch.alpn[0][-1]}" if ch.alpn and ch.alpn[0] else "00"
    ja4_a = f"{proto}{ver_s}{sni_s}{min(len(fc), 99):02d}{min(len(fe), 99):02d}{alpn_s}"

    if fc:
        c_csv = ",".join(f"{c:04x}" for c in sorted(fc))
        ja4_b = hashlib.sha256(c_csv.encode("ascii")).hexdigest()[:12]
    else:
        ja4_b = "000000000000"

    ext_h = sorted(e for e in fe if e not in (0x0000, 0x0010))
    sigs = [s for s in ch.sig_algorithms if not is_grease(s)]
    if ext_h or sigs:
        parts = []
        if ext_h:
            parts.append(",".join(f"{e:04x}" for e in ext_h))
        if sigs:
            parts.append(",".join(f"{s:04x}" for s in sigs))
        ja4_c = hashlib.sha256("_".join(parts).encode("ascii")).hexdigest()[:12]
    else:
        ja4_c = "000000000000"
    return f"{ja4_a}_{ja4_b}_{ja4_c}"


def parse_akamai_from_h2_wire(raw: bytes, pseudo_csv: str) -> tuple[str, str]:
    buf = raw[len(H2_PREFACE) :] if raw.startswith(H2_PREFACE) else raw
    pos = 0
    settings: list[str] = []
    window_update = 0
    priorities: list[str] = []
    while pos + 9 <= len(buf):
        flen = (buf[pos] << 16) | (buf[pos + 1] << 8) | buf[pos + 2]
        ftype = buf[pos + 3]
        sid = struct.unpack_from("!I", buf, pos + 5)[0] & 0x7FFFFFFF
        pos += 9
        payload = buf[pos : pos + flen]
        pos += flen
        if ftype == 0x04 and sid == 0:  # SETTINGS
            for off in range(0, len(payload), 6):
                pid, pval = struct.unpack_from("!HI", payload, off)
                settings.append(f"{pid}:{pval}")
        elif ftype == 0x08 and sid == 0 and len(payload) == 4:  # WINDOW_UPDATE
            window_update = struct.unpack_from("!I", payload, 0)[0] & 0x7FFFFFFF
        elif ftype == 0x02 and len(payload) == 5:  # PRIORITY
            dep_raw = struct.unpack_from("!I", payload, 0)[0]
            excl = (dep_raw >> 31) & 1
            dep = dep_raw & 0x7FFFFFFF
            wt = payload[4] + 1
            priorities.append(f"{sid}:{excl}:{dep}:{wt}")
    prio_s = ",".join(priorities) if priorities else "0"
    ak_str = f"{';'.join(settings)}|{window_update}|{prio_s}|{pseudo_csv}"
    return ak_str, hashlib.md5(ak_str.encode("ascii")).hexdigest()


class HarnessClient:
    def __init__(self, exe: Path) -> None:
        self.proc = subprocess.Popen(
            [str(exe)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            cwd=str(ROOT_DIR),
        )

    def send_recv(self, line: str) -> list[str]:
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        resp = self.proc.stdout.readline()
        if not resp:
            err = self.proc.stderr.read() if self.proc.stderr else ""
            raise RuntimeError(f"fp_wpt_harness exited prematurely: {err}")
        return resp.strip().split("\t")

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.write("QUIT\n")
                self.proc.stdin.flush()
                self.proc.stdin.close()
        except Exception:
            pass
        self.proc.wait(timeout=5)


@dataclass
class SuiteStats:
    passed: int = 0
    failed: int = 0

    def record(self, area: str, cid: str, ok: bool, detail: str) -> None:
        if ok:
            self.passed += 1
            print(f"  [PASS] [{area:11s}] {cid} ({detail})")
        else:
            self.failed += 1
            print(f"  [FAIL] [{area:11s}] {cid}: {detail}")


def enc_hdrs(hdrs: dict[str, str] | None) -> str:
    if not hdrs:
        return "-"
    return "".join(f"{k}: {v}\n" for k, v in hdrs.items()).encode("utf-8").hex()


# ---- Browser Fingerprint Parity Suite (JA3 / JA4 / Akamai H2 / JA4DB) -------

def run_fingerprint_local(client: HarnessClient, stats: SuiteStats) -> None:
    ref_doc = json.loads(JA4DB_REF_PATH.read_text(encoding="utf-8"))
    profiles = ref_doc["profiles"]
    checked_native_ch = False

    for prof_name in ("Chrome", "Firefox", "Safari", "Wing"):
        ref = profiles[prof_name]
        cols = client.send_recv(f"PROFILE\t{prof_name}")
        if len(cols) < 11 or cols[0] != "PROFILE_OUT":
            stats.record("fingerprint", f"fp::{prof_name}", False, f"bad output: {cols}")
            continue
        wing_ja4 = cols[2]
        wing_ja4h = cols[3]
        wing_ak = cols[4]
        wing_ak_h = cols[5]
        pseudo_csv = cols[6]
        ch_raw = bytes.fromhex(cols[7])
        h2_raw = bytes.fromhex(cols[8])
        rt_ok = cols[9] == "1"
        native_ch_raw = bytes.fromhex(cols[10])

        ch = parse_client_hello_wire(ch_raw)
        py_ja3_text, py_ja3_hash = compute_ja3_from_ch(ch)
        py_ja4 = compute_ja4_from_ch(ch)
        py_ak, py_ak_h = parse_akamai_from_h2_wire(h2_raw, pseudo_csv)

        errs: list[str] = []
        if py_ja4 != wing_ja4:
            errs.append(f"wire JA4 {py_ja4} != wing {wing_ja4}")
        if py_ja4 != ref["ja4"]:
            errs.append(f"JA4 {py_ja4} != ja4db {ref['ja4']}")
        if wing_ja4h != ref["ja4h"]:
            errs.append(f"JA4H {wing_ja4h} != ref {ref['ja4h']}")
        if py_ja3_hash != ref["ja3_hash"]:
            errs.append(f"JA3 {py_ja3_hash} ({py_ja3_text}) != ref {ref['ja3_hash']}")
        if py_ak != wing_ak or py_ak != ref["akamai_h2"]:
            errs.append(f"Akamai {py_ak} != wing {wing_ak} / ref {ref['akamai_h2']}")
        if py_ak_h != wing_ak_h or py_ak_h != ref["akamai_h2_hash"]:
            errs.append(f"AkamaiHash {py_ak_h} != ref {ref['akamai_h2_hash']}")
        if ch.has_grease != bool(ref["grease_present"]):
            errs.append(f"GREASE={ch.has_grease} != ref {ref['grease_present']}")
        if not rt_ok:
            errs.append("H2 wire round-trip anomaly check failed")

        stats.record(
            "fingerprint", f"fp::{prof_name.lower()}-ja3-ja4-akamai-parity",
            not errs,
            f"ja4={py_ja4} ja3={py_ja3_hash[:10]}.. ak={py_ak_h[:10]}.." if not errs
            else "; ".join(errs),
        )

        if not checked_native_ch and prof_name == "Wing":
            checked_native_ch = True
            nch = parse_client_hello_wire(native_ch_raw)
            nja4 = compute_ja4_from_ch(nch)
            _, nja3 = compute_ja3_from_ch(nch)
            ok_native = (
                nja4.startswith("t13d")
                and nch.sni == "tls.peet.ws"
                and nch.alpn[:2] == ["h2", "http/1.1"]
                and len(nch.ciphers) >= 3
                and len(nch.sig_algorithms) >= 5
            )
            stats.record(
                "fingerprint", "fp::wing-native-tls13-clienthello",
                ok_native,
                f"ja4={nja4} ja3={nja3[:10]}.. alpn={','.join(nch.alpn)}",
            )


# ---- WPT Cookies Conformance Suite (RFC 6265bis) ----------------------------

def run_wpt_cookies(client: HarnessClient, stats: SuiteStats) -> None:
    def _reset() -> None:
        client.send_recv("COOKIE_RESET")

    def _set(
        cid: str, url: str, raw: str, now_us: int = T0_US, api: str = "HTTP", pk: str = "-"
    ) -> bool:
        cols = client.send_recv(
            f"COOKIE_SET\t{cid}\t{now_us}\t{url}\t{raw.encode('utf-8').hex()}\t{api}\t{pk}"
        )
        return len(cols) >= 3 and cols[2] == "1"

    def _get(
        cid: str, url: str, now_us: int = T0_US, api: str = "HTTP",
        pk: str = "-", acc: str = "SAME_SITE",
    ) -> str:
        cols = client.send_recv(f"COOKIE_GET\t{cid}\t{now_us}\t{url}\t{api}\t{pk}\t{acc}")
        return "" if len(cols) < 3 or cols[2] == "-" else cols[2]

    # 1. __Host- valid on HTTPS with Secure; Path=/ and no Domain
    _reset()
    ok1 = _set("c1", "https://app.example.com/", "__Host-sid=abc; Secure; Path=/")
    got1 = _get("c1", "https://app.example.com/home")
    stats.record("wpt-cookie", "cookie::host-prefix-valid", ok1 and got1 == "__Host-sid=abc", got1)

    # 2. __Host- rejected with Domain attribute
    _reset()
    ok2 = _set("c2", "https://app.example.com/", "__Host-bad=1; Secure; Path=/; Domain=example.com")
    stats.record("wpt-cookie", "cookie::host-prefix-reject-domain", not ok2, f"accepted={ok2}")

    # 3. __Host- rejected with non-root Path
    _reset()
    ok3 = _set("c3", "https://app.example.com/sub", "__Host-bad=1; Secure; Path=/sub")
    stats.record("wpt-cookie", "cookie::host-prefix-reject-path", not ok3, f"accepted={ok3}")

    # 4. __Host- rejected on insecure HTTP origin
    _reset()
    ok4 = _set("c4", "http://app.example.com/", "__Host-bad=1; Secure; Path=/")
    stats.record("wpt-cookie", "cookie::host-prefix-reject-http", not ok4, f"accepted={ok4}")

    # 5. __Secure- valid on HTTPS with Secure
    _reset()
    ok5 = _set("c5", "https://app.example.com/", "__Secure-tok=xyz; Secure; Path=/")
    got5 = _get("c5", "https://app.example.com/")
    stats.record("wpt-cookie", "cookie::secure-prefix-valid", ok5 and got5 == "__Secure-tok=xyz", got5)

    # 6. __Secure- rejected without Secure flag
    _reset()
    ok6 = _set("c6", "https://app.example.com/", "__Secure-bad=1; Path=/")
    stats.record("wpt-cookie", "cookie::secure-prefix-reject-nosecure", not ok6, f"accepted={ok6}")

    # 7. __Secure- rejected on HTTP origin
    _reset()
    ok7 = _set("c7", "http://app.example.com/", "__Secure-bad=1; Secure; Path=/")
    stats.record("wpt-cookie", "cookie::secure-prefix-reject-http", not ok7, f"accepted={ok7}")

    # 8. Host-only vs Domain scoping + public suffix rejection
    _reset()
    _set("c8a", "https://example.com/", "ho=1; Path=/")
    _set("c8b", "https://example.com/", "dom=2; Domain=example.com; Path=/")
    ok_psl = _set("c8c", "https://example.com/", "psl=3; Domain=com; Path=/")
    got_sub = _get("c8d", "https://sub.example.com/")
    stats.record(
        "wpt-cookie", "cookie::domain-vs-hostonly-and-psl",
        (not ok_psl) and got_sub == "dom=2",
        f"psl_accepted={ok_psl} sub={got_sub!r}",
    )
    # 9. Path prefix boundary (/app matches /app and /app/x, NOT /application)
    _reset()
    _set("c9", "https://example.com/app", "p=1; Path=/app")
    g_exact = _get("c9a", "https://example.com/app")
    g_child = _get("c9b", "https://example.com/app/items")
    g_sib = _get("c9c", "https://example.com/application")
    stats.record(
        "wpt-cookie", "cookie::path-boundary-matching",
        g_exact == "p=1" and g_child == "p=1" and g_sib == "",
        f"exact={g_exact!r} child={g_child!r} sib={g_sib!r}",
    )

    # 10. SameSite=Strict blocked on cross-site top-level GET
    _reset()
    _set("c10", "https://example.com/", "st=1; Path=/; SameSite=Strict")
    g_ss = _get("c10a", "https://example.com/", acc="SAME_SITE")
    g_cs = _get("c10b", "https://example.com/", acc="CROSS_TOP_GET")
    stats.record(
        "wpt-cookie", "cookie::samesite-strict",
        g_ss == "st=1" and g_cs == "",
        f"same_site={g_ss!r} cross_top_get={g_cs!r}",
    )

    # 11. SameSite=Lax allowed on cross-site top GET, blocked on cross-site POST & subresource
    _reset()
    _set("c11", "https://example.com/", "lx=1; Path=/; SameSite=Lax")
    g_lget = _get("c11a", "https://example.com/", acc="CROSS_TOP_GET")
    g_lpost = _get("c11b", "https://example.com/", acc="CROSS_TOP_POST")
    g_lsub = _get("c11c", "https://example.com/", acc="CROSS_SUB_GET")
    stats.record(
        "wpt-cookie", "cookie::samesite-lax-matrix",
        g_lget == "lx=1" and g_lpost == "" and g_lsub == "",
        f"top_get={g_lget!r} top_post={g_lpost!r} sub_get={g_lsub!r}",
    )

    # 12. SameSite=None requires Secure
    _reset()
    ok_ns = _set("c12a", "https://example.com/", "nn=bad; Path=/; SameSite=None")
    ok_sc = _set("c12b", "https://example.com/", "nn=ok; Path=/; SameSite=None; Secure")
    g_n = _get("c12c", "https://example.com/", acc="CROSS_SUB_GET")
    stats.record(
        "wpt-cookie", "cookie::samesite-none-requires-secure",
        (not ok_ns) and ok_sc and g_n == "nn=ok",
        f"no_sec={ok_ns} sec={ok_sc} cross_sub={g_n!r}",
    )

    # 13. Max-Age precedence over Expires and Max-Age=0 eviction
    _reset()
    _set(
        "c13a", "https://example.com/",
        "ttl=1; Path=/; Expires=Wed, 01 Jan 2020 00:00:00 GMT; Max-Age=60",
    )
    g_alive = _get("c13b", "https://example.com/", now_us=T0_US + 30_000_000)
    g_exp = _get("c13c", "https://example.com/", now_us=T0_US + 61_000_000)
    _reset()
    _set("c13d", "https://example.com/", "del=1; Path=/; Max-Age=300")
    _set("c13e", "https://example.com/", "del=; Path=/; Max-Age=0")
    g_del = _get("c13f", "https://example.com/")
    stats.record(
        "wpt-cookie", "cookie::max-age-precedence-and-eviction",
        g_alive == "ttl=1" and g_exp == "" and g_del == "",
        f"alive={g_alive!r} exp={g_exp!r} del={g_del!r}",
    )

    # 14. Max cookie size (4096 bytes accepted, 4097 bytes rejected per RFC 6265bis)
    _reset()
    ok_4096 = _set("c14a", "https://example.com/", "k=" + ("a" * 4095) + "; Path=/")
    ok_4097 = _set("c14b", "https://example.com/", "k=" + ("b" * 4096) + "; Path=/")
    stats.record(
        "wpt-cookie", "cookie::max-size-4096-boundary",
        ok_4096 and (not ok_4097),
        f"len4096={ok_4096} len4097={ok_4097}",
    )

    # 15. HttpOnly hidden from script API, visible on HTTP API
    _reset()
    _set("c15", "https://example.com/", "sec=1; Path=/; HttpOnly")
    g_http = _get("c15a", "https://example.com/", api="HTTP")
    g_js = _get("c15b", "https://example.com/", api="SCRIPT")
    stats.record(
        "wpt-cookie", "cookie::httponly-api-isolation",
        g_http == "sec=1" and g_js == "",
        f"http={g_http!r} script={g_js!r}",
    )


# ---- WPT Redirects Conformance Suite (RFC 9110 Section 15.4 / Fetch) --------

def run_wpt_redirects(client: HarnessClient, stats: SuiteStats) -> None:
    def _redir(
        cid: str, status: int, method: str, cur: str, loc: str,
        ref_pol: str = "strict-origin-when-cross-origin",
        cur_ref: str = "-",
        hdrs: dict[str, str] | None = None,
    ) -> dict[str, object]:
        cols = client.send_recv(
            f"REDIRECT\t{cid}\t{status}\t{method}\t{cur}\t{loc}\t{ref_pol}\t{cur_ref}\t{enc_hdrs(hdrs)}"
        )
        assert len(cols) >= 14 and cols[0] == "REDIRECT_OUT", f"bad redirect resp: {cols}"
        return {
            "err": cols[2], "method": cols[3],
            "clear_body": cols[4] == "true", "cross_origin": cols[5] == "true",
            "downgrade": cols[6] == "true", "url": cols[7],
            "has_auth": cols[8] == "true", "has_cookie": cols[9] == "true",
            "has_dpop": cols[10] == "true", "has_ct": cols[11] == "true",
            "origin": cols[12], "referer": cols[13],
        }

    base_hdrs = {
        "Authorization": "Bearer secret", "Cookie": "sid=1",
        "DPoP": "jwt.proof.sig", "Content-Type": "application/json",
        "Origin": "https://a.test",
    }

    # 1. 301 POST -> GET + clear_body + strip Content-Type
    r1 = _redir("r1", 301, "POST", "https://a.test/old", "/new", hdrs=base_hdrs)
    stats.record(
        "wpt-redir", "redirect::301-post-to-get-clear-body",
        r1["err"] == "None" and r1["method"] == "GET" and r1["clear_body"] and not r1["has_ct"],
        f"m={r1['method']} clear={r1['clear_body']} ct={r1['has_ct']}",
    )
    # 2. 302 POST -> GET + clear_body
    r2 = _redir("r2", 302, "POST", "https://a.test/old", "/new", hdrs=base_hdrs)
    stats.record(
        "wpt-redir", "redirect::302-post-to-get-clear-body",
        r2["err"] == "None" and r2["method"] == "GET" and r2["clear_body"],
        f"m={r2['method']} clear={r2['clear_body']}",
    )
    # 3. 303 PUT -> GET + clear_body
    r3 = _redir("r3", 303, "PUT", "https://a.test/item", "/status", hdrs=base_hdrs)
    stats.record(
        "wpt-redir", "redirect::303-put-to-get-clear-body",
        r3["err"] == "None" and r3["method"] == "GET" and r3["clear_body"],
        f"m={r3['method']} clear={r3['clear_body']}",
    )
    # 4. 307 POST preserves method, body, Content-Type
    r4 = _redir("r4", 307, "POST", "https://a.test/v1", "/v2", hdrs=base_hdrs)
    stats.record(
        "wpt-redir", "redirect::307-preserve-post-body",
        r4["err"] == "None" and r4["method"] == "POST" and not r4["clear_body"] and r4["has_ct"],
        f"m={r4['method']} clear={r4['clear_body']} ct={r4['has_ct']}",
    )
    # 5. 308 PUT preserves method & body
    r5 = _redir("r5", 308, "PUT", "https://a.test/v1", "/v2", hdrs=base_hdrs)
    stats.record(
        "wpt-redir", "redirect::308-preserve-put-body",
        r5["err"] == "None" and r5["method"] == "PUT" and not r5["clear_body"],
        f"m={r5['method']} clear={r5['clear_body']}",
    )
    # 6. Same-origin 307 keeps Authorization, strips Cookie for jar re-eval
    stats.record(
        "wpt-redir", "redirect::same-origin-keeps-auth-strips-cookie",
        (not r4["cross_origin"]) and r4["has_auth"] and (not r4["has_cookie"]),
        f"auth={r4['has_auth']} cookie={r4['has_cookie']}",
    )
    # 7. Cross-origin 307 strips Authorization, DPoP, Cookie
    r7 = _redir("r7", 307, "POST", "https://a.test/p", "https://b.test/p", hdrs=base_hdrs)
    stats.record(
        "wpt-redir", "redirect::cross-origin-strips-auth-dpop-cookie",
        r7["cross_origin"] and (not r7["has_auth"]) and (not r7["has_dpop"]) and (not r7["has_cookie"]),
        f"xorig={r7['cross_origin']} auth={r7['has_auth']} dpop={r7['has_dpop']}",
    )
    # 8. HTTPS -> HTTP scheme downgrade strips Authorization and Referer
    r8 = _redir("r8", 302, "GET", "https://a.test/s", "http://a.test/insec", hdrs=base_hdrs)
    stats.record(
        "wpt-redir", "redirect::scheme-downgrade-strips-auth-referer",
        r8["downgrade"] and (not r8["has_auth"]) and r8["referer"] == "-",
        f"down={r8['downgrade']} auth={r8['has_auth']} ref={r8['referer']!r}",
    )
    # 9. Cross-origin strict-origin-when-cross-origin trims Referer to origin only
    r9 = _redir("r9", 302, "GET", "https://a.test/secret/path?q=1", "https://b.test/dst")
    stats.record(
        "wpt-redir", "redirect::referrer-policy-cross-origin-trim",
        r9["cross_origin"] and r9["referer"] in ("https://a.test", "https://a.test/"),
        f"ref={r9['referer']!r}",
    )
    # 10. Forbidden scheme javascript: rejected
    r10 = _redir("r10", 302, "GET", "https://a.test/x", "javascript:alert(1)")
    stats.record(
        "wpt-redir", "redirect::forbidden-scheme-rejected",
        r10["err"] == "ForbiddenRedirectScheme",
        f"err={r10['err']}",
    )


# ---- WPT CORS Conformance Suite (WHATWG Fetch Sections 3.2 & 4.9) -----------

def run_wpt_cors(client: HarnessClient, stats: SuiteStats) -> None:
    def _srv(
        cid: str, creds: bool, origins: str, methods: str, headers: str,
        req_m: str, req_hdrs: dict[str, str],
    ) -> tuple[str, str, str, str]:
        cols = client.send_recv(
            f"CORS_SRV\t{cid}\t{1 if creds else 0}\t{origins}\t{methods}\t{headers}"
            f"\t{req_m}\t{enc_hdrs(req_hdrs)}"
        )
        assert len(cols) >= 6 and cols[0] == "CORS_SRV_OUT", f"bad cors_srv: {cols}"
        return cols[2], cols[3], cols[4], cols[5]

    def _cli(cid: str, req_orig: str, mode: str, resp_hdrs: dict[str, str]) -> bool:
        cols = client.send_recv(f"CORS_CLI\t{cid}\t{req_orig}\t{mode}\t{enc_hdrs(resp_hdrs)}")
        return len(cols) >= 3 and cols[2] == "1"

    # 1. Exact allowed origin -> AllowedActual + echoed ACAO + Vary: Origin
    res1, acao1, _, vary1 = _srv(
        "co1", False, "https://app.test", "-", "-", "GET", {"Origin": "https://app.test"}
    )
    stats.record(
        "wpt-cors", "cors::actual-exact-origin-and-vary",
        res1 == "AllowedActual" and acao1 == "https://app.test" and "Origin" in vary1,
        f"res={res1} acao={acao1} vary={vary1}",
    )
    # 2. Wildcard '*' origin without credentials -> AllowedActual + ACAO: *
    res2, acao2, _, _ = _srv(
        "co2", False, "*", "-", "-", "GET", {"Origin": "https://any.example"}
    )
    stats.record(
        "wpt-cors", "cors::actual-wildcard-no-creds",
        res2 == "AllowedActual" and acao2 == "*",
        f"res={res2} acao={acao2}",
    )
    # 3. Unlisted origin rejected
    res3, _, _, _ = _srv(
        "co3", False, "https://good.test", "-", "-", "GET", {"Origin": "https://evil.test"}
    )
    stats.record("wpt-cors", "cors::reject-unlisted-origin", res3 == "RejectedOrigin", f"res={res3}")

    # 4. Preflight OPTIONS allowed method + allowed headers
    res4, acao4, _, _ = _srv(
        "co4", False, "https://app.test", "GET, POST, PUT", "Content-Type, X-API-Key",
        "OPTIONS", {
            "Origin": "https://app.test",
            "Access-Control-Request-Method": "PUT",
            "Access-Control-Request-Headers": "Content-Type, X-API-Key",
        },
    )
    stats.record(
        "wpt-cors", "cors::preflight-allowed",
        res4 == "AllowedPreflight" and acao4 == "https://app.test",
        f"res={res4} acao={acao4}",
    )
    # 5. Preflight disallowed method rejected
    res5, _, _, _ = _srv(
        "co5", False, "https://app.test", "GET, POST", "Content-Type",
        "OPTIONS", {
            "Origin": "https://app.test",
            "Access-Control-Request-Method": "DELETE",
        },
    )
    stats.record(
        "wpt-cors", "cors::preflight-reject-method",
        res5 == "RejectedPreflightMethod", f"res={res5}",
    )
    # 6. Preflight disallowed private custom header rejected
    res6, _, _, _ = _srv(
        "co6", False, "https://app.test", "GET, POST", "Content-Type",
        "OPTIONS", {
            "Origin": "https://app.test",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-Private-Secret",
        },
    )
    stats.record(
        "wpt-cors", "cors::preflight-reject-private-header",
        res6 == "RejectedPreflightHeaders", f"res={res6}",
    )
    # 7. Preflight Authorization NOT covered by wildcard '*' (Fetch Section 3.2.3)
    res7, _, _, _ = _srv(
        "co7", False, "https://app.test", "GET, POST", "*",
        "OPTIONS", {
            "Origin": "https://app.test",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Authorization",
        },
    )
    stats.record(
        "wpt-cors", "cors::preflight-wildcard-blocks-authorization",
        res7 == "RejectedPreflightHeaders", f"res={res7}",
    )
    # 8. Credentials + wildcard '*' origin rejected as InvalidConfig (Fetch Section 3.2.2)
    res8, _, _, _ = _srv(
        "co8", True, "*", "-", "-", "GET", {"Origin": "https://app.test"}
    )
    stats.record(
        "wpt-cors", "cors::creds-with-wildcard-invalid-config",
        res8 == "InvalidConfig", f"res={res8}",
    )
    # 9. Credentials + exact origin emits ACAC: true, rejects 'null' origin
    res9a, _, acac9a, _ = _srv(
        "co9a", True, "https://app.test", "-", "-", "GET", {"Origin": "https://app.test"}
    )
    res9b, _, _, _ = _srv(
        "co9b", True, "https://app.test", "-", "-", "GET", {"Origin": "null"}
    )
    stats.record(
        "wpt-cors", "cors::creds-exact-ok-and-null-rejected",
        res9a == "AllowedActual" and acac9a == "true" and res9b == "RejectedOrigin",
        f"exact={res9a}/acac={acac9a} null={res9b}",
    )
    # 10. Client-side Fetch Section 4.9 check (creds reject '*', tainted expects 'null')
    ok_c_wild = _cli("cc1", "https://a.test", "CREDS", {
        "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true",
    })
    ok_c_exact = _cli("cc2", "https://a.test", "CREDS", {
        "Access-Control-Allow-Origin": "https://a.test", "Access-Control-Allow-Credentials": "true",
    })
    ok_c_taint = _cli("cc3", "https://a.test", "TAINTED", {"Access-Control-Allow-Origin": "null"})
    stats.record(
        "wpt-cors", "cors::client-verify-creds-and-tainted",
        (not ok_c_wild) and ok_c_exact and ok_c_taint,
        f"wild_creds={ok_c_wild} exact_creds={ok_c_exact} tainted_null={ok_c_taint}",
    )


# ---- Live Fingerprint Echo Probes (tls.peet.ws & tls.browserleaks.com) ------

LIVE_ENDPOINTS = (
    ("peet.ws", "https://tls.peet.ws/api/all"),
    ("browserleaks", "https://tls.browserleaks.com/json"),
)


def _extract_live_fp(payload: dict[str, object]) -> tuple[str, str, str]:
    tls_obj = payload.get("tls") if isinstance(payload.get("tls"), dict) else {}
    h2_obj = payload.get("http2") if isinstance(payload.get("http2"), dict) else {}
    ja3 = str(tls_obj.get("ja3_hash") or payload.get("ja3_hash") or "")
    ja4 = str(tls_obj.get("ja4") or payload.get("ja4") or "")
    ak = str(
        h2_obj.get("akamai_fingerprint")
        or payload.get("akamai_text")
        or payload.get("akamai_hash")
        or ""
    )
    return ja3, ja4, ak


def run_live_probes(client: HarnessClient, stats: SuiteStats, profile: str = "Wing") -> None:
    ref = json.loads(JA4DB_REF_PATH.read_text(encoding="utf-8"))["profiles"][profile]
    exp_ja4_prefix = str(ref["ja4"]).split("_")[0][:4]  # e.g. "t13d"
    for label, url in LIVE_ENDPOINTS:
        cols = client.send_recv(f"LIVE_FETCH\t{profile}\t{url}")
        if len(cols) < 6 or cols[0] != "LIVE_OUT" or cols[3] != "0":
            err_info = f"status={cols[2]} stage={cols[4]}" if len(cols) >= 5 else str(cols)
            stats.record("live-fp", f"live::{label}-{profile.lower()}", False, err_info)
            continue
        body_bytes = b"" if cols[5] == "-" else bytes.fromhex(cols[5])
        try:
            data = json.loads(body_bytes.decode("utf-8", errors="replace"))
        except Exception as exc:
            stats.record("live-fp", f"live::{label}-{profile.lower()}", False, f"bad json: {exc}")
            continue
        obs_ja3, obs_ja4, obs_ak = _extract_live_fp(data)
        ok_live = (
            bool(obs_ja3 or obs_ja4)
            and (not obs_ja4 or obs_ja4.startswith(exp_ja4_prefix))
        )
        stats.record(
            "live-fp", f"live::{label}-{profile.lower()}", ok_live,
            f"ja4={obs_ja4 or '-'} ja3={obs_ja3[:12] or '-'} ak={obs_ak[:24] or '-'}",
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Browser Fingerprints (JA3/JA4/Akamai H2) & WPT Conformance Suite for goose-wing"
    )
    parser.add_argument("--local", action="store_true", help="Run offline JA3/JA4/H2 + WPT suite")
    parser.add_argument(
        "--live", action="store_true",
        help="Probe https://tls.peet.ws/api/all and https://tls.browserleaks.com/json via Wing client",
    )
    parser.add_argument("--profile", default="Wing", help="Profile name for --live probes")
    parser.add_argument("--docker", action="store_true", help="Run local suite inside Docker")
    parser.add_argument("--rebuild", action="store_true", help="Force rebuild fp_wpt_harness")
    args = parser.parse_args()

    if args.docker:
        img = "goose-wing-fingerprint-wpt"
        b_cmd = [
            "docker", "build", "-f", str(SUITE_DIR / "Dockerfile"), "-t", img, str(ROOT_DIR)
        ]
        if subprocess.run(b_cmd, check=False).returncode != 0:
            sys.exit(1)
        sys.exit(subprocess.run(["docker", "run", "--rm", img, "--local"], check=False).returncode)

    exe = ensure_harness_binary(force_rebuild=args.rebuild)
    client = HarnessClient(exe)
    stats = SuiteStats()
    try:
        if args.local or not args.live:
            print("\nExecuting JA3 / JA4 / JA4H / Akamai H2 Fingerprint Parity Suite (5 vectors)...")
            run_fingerprint_local(client, stats)
            print("\nExecuting WPT Cookies RFC 6265bis Conformance Suite (15 vectors)...")
            run_wpt_cookies(client, stats)
            print("\nExecuting WPT Redirects RFC 9110 / Fetch Conformance Suite (10 vectors)...")
            run_wpt_redirects(client, stats)
            print("\nExecuting WPT CORS WHATWG Fetch Conformance Suite (10 vectors)...")
            run_wpt_cors(client, stats)
        if args.live:
            print(f"\nExecuting Live Fingerprint Echo Probes ({args.profile})...")
            run_live_probes(client, stats, profile=args.profile)
    finally:
        client.close()

    total = stats.passed + stats.failed
    print(f"\nCompleted: {stats.passed}/{total} passed, {stats.failed} failed.")
    sys.exit(0 if stats.failed == 0 and total > 0 else 1)


if __name__ == "__main__":
    main()
