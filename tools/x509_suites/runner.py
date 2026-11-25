#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
X.509 PKI Conformance Testbed for goose-wing covering:
  1. C2SP/x509-limbo (real limbo.json schema + 24 local torture vectors)
  2. Netflix/BetterTLS (intermediate & TrustAnchor NameConstraints + path building)
  3. NIST PKITS (RFC 5280 chain, CRL, OCSP stapling + --pkits-dir corpus support)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
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
SUITE_DIR = TOOLS_DIR / "x509_suites"
HARNESS_SRC = SUITE_DIR / "x509_harness.goose"
HARNESS_EXE = BIN_DIR / ("x509_harness.exe" if sys.platform == "win32" else "x509_harness")
LIMBO_RAW_URL = "https://raw.githubusercontent.com/C2SP/x509-limbo/main/limbo.json"
DEFAULT_NOW = 1767225600  # 2026-01-01T00:00:00Z


def find_openssl_bin() -> str | None:
    found = shutil.which("openssl")
    if found:
        return found
    for cand in (
        r"C:\Program Files\Git\usr\bin\openssl.exe",
        r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
        r"C:\Program Files (x86)\OpenSSL-Win32\bin\openssl.exe",
    ):
        if Path(cand).is_file():
            return cand
    return None


def ensure_harness_binary(force_rebuild: bool = False) -> Path:
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    latest_tls_mtime = max(
        (p.stat().st_mtime for p in (ROOT_DIR / "tls").glob("*.goose")),
        default=0.0,
    )
    if (
        not force_rebuild
        and HARNESS_EXE.is_file()
        and HARNESS_EXE.stat().st_mtime >= max(HARNESS_SRC.stat().st_mtime, latest_tls_mtime)
    ):
        return HARNESS_EXE

    print(f"[*] Building X.509 harness: {HARNESS_SRC.name} -> {HARNESS_EXE.name}...")
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
        print("[!] Failed to build x509_harness:", file=sys.stderr)
        if res.stdout:
            print(res.stdout, file=sys.stderr)
        if res.stderr:
            print(res.stderr, file=sys.stderr)
        sys.exit(1)
    print(f"[+] Built {HARNESS_EXE.name}")
    return HARNESS_EXE


def der_to_pem(der: bytes, label: str = "CERTIFICATE") -> str:
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


def pem_to_der(pem: str) -> bytes:
    body = []
    in_block = False
    for raw_line in pem.splitlines():
        line = raw_line.strip()
        if line.startswith("-----BEGIN "):
            in_block = True
            continue
        if line.startswith("-----END "):
            break
        if in_block and line:
            body.append(line)
    if not body:
        return b""
    return base64.b64decode("".join(body))


def parse_iso_time(val: str | None) -> int:
    if not val:
        return DEFAULT_NOW
    s = val.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return int(dt.timestamp())


# ---- ASN.1 DER Primitives ---------------------------------------------------

OID_EC_PUBKEY = "1.2.840.10045.2.1"
OID_SECP256R1 = "1.2.840.10045.3.1.7"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
OID_ECDSA_SHA384 = "1.2.840.10045.4.3.3"
OID_ECDSA_SHA1 = "1.2.840.10045.4.1"
OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_SHA256_RSA = "1.2.840.113549.1.1.11"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_CN = "2.5.4.3"
OID_ORG = "2.5.4.10"
OID_SKID = "2.5.29.14"
OID_KEY_USAGE = "2.5.29.15"
OID_SAN = "2.5.29.17"
OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_NAME_CONSTRAINTS = "2.5.29.30"
OID_AKID = "2.5.29.35"
OID_EKU = "2.5.29.37"
OID_EKU_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
OID_EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
OID_OCSP_BASIC = "1.3.6.1.5.5.7.48.1.1"


def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    enc = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(enc)]) + enc


def der_tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + der_len(len(body)) + body


def der_seq(body: bytes) -> bytes:
    return der_tlv(0x30, body)


def der_set(body: bytes) -> bytes:
    return der_tlv(0x31, body)


def der_bool(val: bool) -> bytes:
    return der_tlv(0x01, b"\xff" if val else b"\x00")


def der_null() -> bytes:
    return b"\x05\x00"


def der_int(val: int) -> bytes:
    if val == 0:
        return b"\x02\x01\x00"
    raw = val.to_bytes((val.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return der_tlv(0x02, raw)


def der_oid(dotted: str) -> bytes:
    parts = [int(x) for x in dotted.split(".")]
    out = bytearray([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        if p == 0:
            out.append(0)
            continue
        chunks = []
        v = p
        while v > 0:
            chunks.append(v & 0x7F)
            v >>= 7
        chunks.reverse()
        for i, c in enumerate(chunks):
            out.append(c | (0x80 if i < len(chunks) - 1 else 0))
    return der_tlv(0x06, bytes(out))


def der_bit_string(data: bytes, unused_bits: int = 0) -> bytes:
    return der_tlv(0x03, bytes([unused_bits]) + data)


def der_octet_string(data: bytes) -> bytes:
    return der_tlv(0x04, data)


def der_utf8(text: str) -> bytes:
    return der_tlv(0x0C, text.encode("utf-8"))


def der_ia5(text: str) -> bytes:
    return der_tlv(0x16, text.encode("ascii"))


def der_ctx(num: int, body: bytes, constructed: bool = True) -> bytes:
    tag = (0xA0 if constructed else 0x80) | num
    return der_tlv(tag, body)


def der_time(unix_sec: int) -> bytes:
    dt = datetime.fromtimestamp(unix_sec, tz=UTC)
    if 1950 <= dt.year <= 2049:
        return der_tlv(0x17, dt.strftime("%y%m%d%H%M%SZ").encode("ascii"))
    return der_tlv(0x18, dt.strftime("%Y%m%d%H%M%SZ").encode("ascii"))


def der_gentime(unix_sec: int) -> bytes:
    dt = datetime.fromtimestamp(unix_sec, tz=UTC)
    return der_tlv(0x18, dt.strftime("%Y%m%d%H%M%SZ").encode("ascii"))


# ---- Pure-Python NIST P-256 ECDSA -------------------------------------------

_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_A = _P256_P - 3
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)


def _p256_add(p1: tuple[int, int] | None, p2: tuple[int, int] | None) -> tuple[int, int] | None:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % _P256_P == 0:
            return None
        lam = (3 * x1 * x1 + _P256_A) * pow(2 * y1, -1, _P256_P) % _P256_P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _P256_P) % _P256_P
    x3 = (lam * lam - x1 - x2) % _P256_P
    y3 = (lam * (x1 - x3) - y1) % _P256_P
    return (x3, y3)


def _p256_mul(k: int, pt: tuple[int, int]) -> tuple[int, int]:
    res: tuple[int, int] | None = None
    addend: tuple[int, int] | None = pt
    v = k % _P256_N
    while v > 0:
        if v & 1:
            res = _p256_add(res, addend)
        addend = _p256_add(addend, addend)
        v >>= 1
    assert res is not None
    return res


class P256Key:
    def __init__(self, seed_label: str) -> None:
        h = int.from_bytes(hashlib.sha256(f"wing-x509-p256:{seed_label}".encode()).digest(), "big")
        self.d = 1 + (h % (_P256_N - 1))
        self.pub_pt = _p256_mul(self.d, _P256_G)
        self.pub_bytes = (
            b"\x04" + self.pub_pt[0].to_bytes(32, "big") + self.pub_pt[1].to_bytes(32, "big")
        )
        self.skid = hashlib.sha1(self.pub_bytes).digest()

    def spki_der(self) -> bytes:
        alg = der_seq(der_oid(OID_EC_PUBKEY) + der_oid(OID_SECP256R1))
        return der_seq(alg + der_bit_string(self.pub_bytes))

    def sign_der(self, data: bytes) -> bytes:
        z = int.from_bytes(hashlib.sha256(data).digest(), "big")
        priv_b = self.d.to_bytes(32, "big")
        ctr = 1
        while True:
            k_seed = hashlib.sha256(priv_b + data + ctr.to_bytes(4, "big")).digest()
            k = 1 + (int.from_bytes(k_seed, "big") % (_P256_N - 1))
            r = _p256_mul(k, _P256_G)[0] % _P256_N
            if r == 0:
                ctr += 1
                continue
            s = (pow(k, -1, _P256_N) * (z + r * self.d)) % _P256_N
            if s != 0:
                return der_seq(der_int(r) + der_int(s))
            ctr += 1


def make_rsa1024_spki_der() -> bytes:
    """Produces a 1024-bit RSA SPKI DER (via openssl if present, else deterministic synthetic)."""
    ossl = find_openssl_bin()
    if ossl:
        with tempfile.TemporaryDirectory() as td:
            key_p = Path(td) / "k1024.pem"
            pub_p = Path(td) / "p1024.der"
            r1 = subprocess.run(
                [ossl, "genrsa", "-out", str(key_p), "1024"],
                capture_output=True,
                check=False,
            )
            if r1.returncode == 0:
                r2 = subprocess.run(
                    [ossl, "rsa", "-in", str(key_p), "-pubout", "-outform", "DER", "-out", str(pub_p)],
                    capture_output=True,
                    check=False,
                )
                if r2.returncode == 0 and pub_p.is_file():
                    return pub_p.read_bytes()
    n_bytes = bytearray(128)
    n_bytes[0] = 0xB5
    for i in range(1, 127):
        n_bytes[i] = (i * 37 + 19) & 0xFF
    n_bytes[127] = 0xFB
    rsa_pub = der_seq(der_int(int.from_bytes(n_bytes, "big")) + der_int(65537))
    alg = der_seq(der_oid(OID_RSA_ENCRYPTION) + der_null())
    return der_seq(alg + der_bit_string(rsa_pub))


def make_openssl_rsa2048_chain(cn_leaf: str = "rsa.example.com") -> tuple[bytes, bytes] | None:
    """Generates a real RSA-2048 root + leaf DER pair via OpenSSL CLI when available."""
    ossl = find_openssl_bin()
    if not ossl:
        return None
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        ca_key, ca_crt, ca_der = p / "ca.key", p / "ca.pem", p / "ca.der"
        ee_key, ee_csr, ee_crt, ee_der = p / "ee.key", p / "ee.csr", p / "ee.pem", p / "ee.der"
        ext_cfg = p / "ee.ext"
        ext_cfg.write_text(
            f"basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\n"
            f"extendedKeyUsage=serverAuth\nsubjectAltName=DNS:{cn_leaf}\n",
            encoding="utf-8",
        )
        cmds = [
            [ossl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
             "-keyout", str(ca_key), "-out", str(ca_crt), "-days", "365",
             "-subj", "/CN=Wing OpenSSL RSA2048 Root",
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign"],
            [ossl, "req", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(ee_key), "-out", str(ee_csr),
             "-subj", f"/CN={cn_leaf}"],
            [ossl, "x509", "-req", "-in", str(ee_csr), "-CA", str(ca_crt), "-CAkey", str(ca_key),
             "-CAcreateserial", "-out", str(ee_crt), "-days", "365", "-sha256",
             "-extfile", str(ext_cfg)],
            [ossl, "x509", "-in", str(ca_crt), "-outform", "DER", "-out", str(ca_der)],
            [ossl, "x509", "-in", str(ee_crt), "-outform", "DER", "-out", str(ee_der)],
        ]
        for cmd in cmds:
            if subprocess.run(cmd, capture_output=True, check=False).returncode != 0:
                return None
        return ca_der.read_bytes(), ee_der.read_bytes()


# ---- X.509 v3 Certificate, CRL & OCSP Builders ------------------------------

def der_dn(cn: str, org: str = "Wing PKI Testbed") -> bytes:
    rdn_org = der_set(der_seq(der_oid(OID_ORG) + der_utf8(org)))
    rdn_cn = der_set(der_seq(der_oid(OID_CN) + der_utf8(cn)))
    return der_seq(rdn_org + rdn_cn)


def x509_ext(oid: str, value: bytes, critical: bool = False) -> bytes:
    parts = der_oid(oid)
    if critical:
        parts += der_bool(True)
    parts += der_octet_string(value)
    return der_seq(parts)


def ext_basic_constraints(is_ca: bool, path_len: int | None = None, critical: bool = True) -> bytes:
    body = b""
    if is_ca:
        body += der_bool(True)
    if path_len is not None:
        body += der_int(path_len)
    return x509_ext(OID_BASIC_CONSTRAINTS, der_seq(body), critical=critical)


def ext_key_usage(byte_val: int, unused_bits: int, critical: bool = True) -> bytes:
    return x509_ext(OID_KEY_USAGE, der_bit_string(bytes([byte_val]), unused_bits), critical=critical)


def ext_eku(oids: list[str], critical: bool = False) -> bytes:
    return x509_ext(OID_EKU, der_seq(b"".join(der_oid(o) for o in oids)), critical=critical)


def ext_san(dns_names: list[str] | None = None, ips: list[str] | None = None) -> bytes:
    items = bytearray()
    for d in dns_names or []:
        items += der_tlv(0x82, d.encode("ascii"))
    for ip_s in ips or []:
        items += der_tlv(0x87, ipaddress.ip_address(ip_s).packed)
    return x509_ext(OID_SAN, der_seq(bytes(items)), critical=False)


def ext_name_constraints(
    permitted_dns: list[str] | None = None,
    excluded_dns: list[str] | None = None,
    permitted_ips: list[str] | None = None,
    excluded_ips: list[str] | None = None,
    critical: bool = True,
) -> bytes:
    def _subtrees(dns_list: list[str], ip_list: list[str]) -> bytes:
        out = bytearray()
        for d in dns_list:
            out += der_seq(der_tlv(0x82, d.encode("ascii")))
        for cidr in ip_list:
            net = ipaddress.ip_network(cidr, strict=False)
            out += der_seq(der_tlv(0x87, net.network_address.packed + net.netmask.packed))
        return bytes(out)

    body = bytearray()
    perm = _subtrees(permitted_dns or [], permitted_ips or [])
    excl = _subtrees(excluded_dns or [], excluded_ips or [])
    if perm:
        body += der_ctx(0, perm, constructed=True)
    if excl:
        body += der_ctx(1, excl, constructed=True)
    return x509_ext(OID_NAME_CONSTRAINTS, der_seq(bytes(body)), critical=critical)


def ext_skid(key_id: bytes) -> bytes:
    return x509_ext(OID_SKID, der_octet_string(key_id), critical=False)


def ext_akid(key_id: bytes) -> bytes:
    return x509_ext(OID_AKID, der_seq(der_tlv(0x80, key_id)), critical=False)


def build_x509_cert(
    subject_cn: str,
    issuer_cn: str,
    subject_spki: bytes,
    signer_key: P256Key,
    serial: int,
    not_before: int = DEFAULT_NOW - 86400 * 30,
    not_after: int = DEFAULT_NOW + 86400 * 365,
    extensions: list[bytes] | None = None,
    inner_sig_oid: str = OID_ECDSA_SHA256,
    outer_sig_oid: str | None = None,
    corrupt_sig: bool = False,
    trailing_bytes: bytes = b"",
) -> bytes:
    sig_alg_inner = der_seq(der_oid(inner_sig_oid))
    sig_alg_outer = der_seq(der_oid(outer_sig_oid or inner_sig_oid))
    tbs = bytearray()
    tbs += der_ctx(0, der_int(2), constructed=True)  # v3
    tbs += der_int(serial)
    tbs += sig_alg_inner
    tbs += der_dn(issuer_cn)
    tbs += der_seq(der_time(not_before) + der_time(not_after))
    tbs += der_dn(subject_cn)
    tbs += subject_spki
    if extensions:
        tbs += der_ctx(3, der_seq(b"".join(extensions)), constructed=True)
    tbs_der = der_seq(bytes(tbs))
    sig = bytearray(signer_key.sign_der(tbs_der))
    if corrupt_sig:
        sig[-1] ^= 0x01
    return der_seq(tbs_der + sig_alg_outer + der_bit_string(bytes(sig))) + trailing_bytes


def build_x509_crl(
    issuer_cn: str,
    signer_key: P256Key,
    revoked_serials: list[int],
    this_update: int = DEFAULT_NOW - 3600,
    next_update: int = DEFAULT_NOW + 86400,
    corrupt_sig: bool = False,
) -> bytes:
    sig_alg = der_seq(der_oid(OID_ECDSA_SHA256))
    tbs = bytearray()
    tbs += der_int(1)  # v2
    tbs += sig_alg
    tbs += der_dn(issuer_cn)
    tbs += der_time(this_update)
    tbs += der_time(next_update)
    if revoked_serials:
        entries = b"".join(
            der_seq(der_int(s) + der_time(this_update - 60)) for s in revoked_serials
        )
        tbs += der_seq(entries)
    # RFC 5280 Section 5.2.3: Conforming v2 CRL issuers MUST include cRLNumber (2.5.29.20).
    crl_num_ext = x509_ext("2.5.29.20", der_int(1), critical=False)
    tbs += der_ctx(0, der_seq(crl_num_ext), constructed=True)
    tbs_der = der_seq(bytes(tbs))
    sig = bytearray(signer_key.sign_der(tbs_der))
    if corrupt_sig:
        sig[-1] ^= 0x01
    return der_seq(tbs_der + sig_alg + der_bit_string(bytes(sig)))


def build_ocsp_response(
    issuer_cn: str,
    issuer_key: P256Key,
    leaf_serial: int,
    status: str = "good",
    this_update: int = DEFAULT_NOW - 3600,
    next_update: int = DEFAULT_NOW + 86400,
    corrupt_sig: bool = False,
) -> bytes:
    hash_alg = der_seq(der_oid(OID_SHA256) + der_null())
    issuer_name_hash = hashlib.sha256(der_dn(issuer_cn)).digest()
    issuer_key_hash = hashlib.sha256(issuer_key.pub_bytes).digest()
    cert_id = der_seq(
        hash_alg
        + der_octet_string(issuer_name_hash)
        + der_octet_string(issuer_key_hash)
        + der_int(leaf_serial)
    )
    if status == "good":
        cert_status = b"\x80\x00"
    elif status == "revoked":
        cert_status = der_ctx(1, der_gentime(this_update - 60), constructed=True)
    else:
        cert_status = b"\x82\x00"
    single = der_seq(
        cert_id
        + cert_status
        + der_gentime(this_update)
        + der_ctx(0, der_gentime(next_update), constructed=True)
    )
    resp_id = der_ctx(2, der_octet_string(issuer_key.skid), constructed=True)
    tbs_resp = der_seq(resp_id + der_gentime(this_update) + der_seq(single))
    sig_alg = der_seq(der_oid(OID_ECDSA_SHA256))
    sig = bytearray(issuer_key.sign_der(tbs_resp))
    if corrupt_sig:
        sig[-1] ^= 0x01
    basic = der_seq(tbs_resp + sig_alg + der_bit_string(bytes(sig)))
    resp_bytes = der_ctx(0, der_seq(der_oid(OID_OCSP_BASIC) + der_octet_string(basic)), True)
    return der_seq(der_tlv(0x0A, b"\x00") + resp_bytes)


# ---- Harness Subprocess Client ----------------------------------------------

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

    def _send_recv(self, line: str) -> list[str]:
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        resp = self.proc.stdout.readline()
        if not resp:
            err = self.proc.stderr.read() if self.proc.stderr else ""
            raise RuntimeError(f"x509_harness exited prematurely: {err}")
        return resp.strip().split("\t")

    def verify(
        self,
        case_id: str,
        leaf_der: bytes,
        inters_der: list[bytes],
        anchors_der: list[bytes],
        peer: str = "-",
        now_unix: int = DEFAULT_NOW,
        role: str = "SERVER",
        mode: str = "BUILD",
        max_depth: int = -1,
    ) -> tuple[bool, str]:
        leaf_h = leaf_der.hex() if leaf_der else "-"
        inter_h = ",".join(c.hex() for c in inters_der if c) or "-"
        anch_h = ",".join(c.hex() for c in anchors_der if c) or "-"
        cols = self._send_recv(
            f"VERIFY\t{case_id}\t{mode}\t{role}\t{now_unix}\t{peer}\t{leaf_h}\t{inter_h}\t{anch_h}\t{max_depth}"
        )
        if len(cols) >= 4 and cols[0] == "VERDICT":
            return cols[2] == "OK", cols[3]
        return False, f"ProtocolError:{cols}"

    def check_crl(
        self,
        case_id: str,
        leaf_der: bytes,
        issuer_der: bytes,
        crl_der: bytes,
        now_unix: int = DEFAULT_NOW,
    ) -> tuple[str, str]:
        cols = self._send_recv(
            f"CRL\t{case_id}\t{now_unix}\t{leaf_der.hex()}\t{issuer_der.hex()}\t{crl_der.hex()}"
        )
        if len(cols) >= 4 and cols[0] == "CRL_VERDICT":
            return cols[2], cols[3]
        return "ERR", f"ProtocolError:{cols}"

    def check_ocsp(
        self,
        case_id: str,
        leaf_der: bytes,
        issuer_der: bytes | None,
        ocsp_der: bytes,
        now_unix: int = DEFAULT_NOW,
    ) -> tuple[bool, str]:
        iss_h = issuer_der.hex() if issuer_der else "-"
        cols = self._send_recv(
            f"OCSP\t{case_id}\t{now_unix}\t{leaf_der.hex()}\t{iss_h}\t{ocsp_der.hex()}"
        )
        if len(cols) >= 4 and cols[0] == "OCSP_VERDICT":
            return cols[2] == "OK", cols[3]
        return False, f"ProtocolError:{cols}"

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
    skipped: int = 0

    def record(self, suite: str, cid: str, ok: bool, detail: str) -> None:
        if ok:
            self.passed += 1
            print(f"  [PASS] [{suite:9s}] {cid} ({detail})")
        else:
            self.failed += 1
            print(f"  [FAIL] [{suite:9s}] {cid}: {detail}")


def make_ca_cert(
    cn: str,
    key: P256Key,
    issuer_cn: str,
    issuer_key: P256Key,
    serial: int,
    path_len: int | None = None,
    extra_exts: list[bytes] | None = None,
    not_before: int = DEFAULT_NOW - 86400 * 30,
    not_after: int = DEFAULT_NOW + 86400 * 365,
    include_bc: bool = True,
    is_ca: bool = True,
    ku_byte: int | None = 0x06,
    ku_unused: int = 1,
    corrupt_sig: bool = False,
) -> bytes:
    exts: list[bytes] = []
    if include_bc:
        exts.append(ext_basic_constraints(is_ca=is_ca, path_len=path_len))
    if ku_byte is not None:
        exts.append(ext_key_usage(ku_byte, ku_unused))
    exts.append(ext_skid(key.skid))
    exts.append(ext_akid(issuer_key.skid))
    if extra_exts:
        exts.extend(extra_exts)
    return build_x509_cert(
        cn, issuer_cn, key.spki_der(), issuer_key, serial,
        not_before=not_before, not_after=not_after,
        extensions=exts, corrupt_sig=corrupt_sig,
    )


def make_leaf_cert(
    cn: str,
    key: P256Key,
    issuer_cn: str,
    issuer_key: P256Key,
    serial: int,
    dns_sans: list[str] | None = None,
    ip_sans: list[str] | None = None,
    eku_oids: list[str] | None = None,
    extra_exts: list[bytes] | None = None,
    not_before: int = DEFAULT_NOW - 86400 * 10,
    not_after: int = DEFAULT_NOW + 86400 * 90,
    spki_override: bytes | None = None,
    inner_sig_oid: str = OID_ECDSA_SHA256,
    outer_sig_oid: str | None = None,
    corrupt_sig: bool = False,
    trailing_bytes: bytes = b"",
) -> bytes:
    exts: list[bytes] = [
        ext_basic_constraints(is_ca=False, critical=True),
        ext_key_usage(0x80, 7, critical=True),
        ext_akid(issuer_key.skid),
    ]
    if dns_sans or ip_sans:
        exts.append(ext_san(dns_names=dns_sans, ips=ip_sans))
    if eku_oids is not None:
        exts.append(ext_eku(eku_oids))
    if extra_exts:
        exts.extend(extra_exts)
    return build_x509_cert(
        cn, issuer_cn, spki_override or key.spki_der(), issuer_key, serial,
        not_before=not_before, not_after=not_after, extensions=exts,
        inner_sig_oid=inner_sig_oid, outer_sig_oid=outer_sig_oid,
        corrupt_sig=corrupt_sig, trailing_bytes=trailing_bytes,
    )


def _limbo_case(
    cid: str,
    trusted: list[bytes],
    inters: list[bytes],
    peer_cert: bytes,
    expected_result: str,
    peer_name: dict[str, str] | None = None,
    validation_kind: str = "SERVER",
    validation_time: str = "2026-01-01T00:00:00Z",
    mode: str = "BUILD",
) -> dict[str, object]:
    return {
        "id": cid,
        "validation_kind": validation_kind,
        "trusted_certs": [der_to_pem(c) for c in trusted],
        "untrusted_intermediates": [der_to_pem(c) for c in inters],
        "peer_certificate": der_to_pem(peer_cert),
        "peer_certificate_expected_peer_name": peer_name,
        "validation_time": validation_time,
        "expected_result": expected_result,
        "_harness_mode": mode,
    }


def run_limbo_document(
    client: HarnessClient, doc: dict[str, object], stats: SuiteStats, limit: int = 0
) -> None:
    testcases = doc.get("testcases", [])
    assert isinstance(testcases, list)
    for idx, tc in enumerate(testcases):
        if limit > 0 and idx >= limit:
            break
        cid = str(tc.get("id", f"tc-{idx}"))
        expected_str = str(tc.get("expected_result", "FAILURE")).upper()
        if expected_str not in ("SUCCESS", "FAILURE"):
            stats.skipped += 1
            continue
        trusted_pems = tc.get("trusted_certs") or []
        inter_pems = tc.get("untrusted_intermediates") or []
        if len(trusted_pems) > 16 or len(inter_pems) > 16:
            stats.skipped += 1
            continue
        peer_pem = str(tc.get("peer_certificate") or "")
        trusted_der = [pem_to_der(p) for p in trusted_pems]
        inter_der = [pem_to_der(p) for p in inter_pems]
        peer_der = pem_to_der(peer_pem)
        pn = tc.get("expected_peer_name") or tc.get("peer_certificate_expected_peer_name")
        peer_val = "-"
        if (
            isinstance(pn, dict)
            and pn.get("value")
            and str(pn.get("kind", "")).upper() in ("DNS", "IP", "RFC822", "")
        ):
            peer_val = str(pn["value"])
        role = str(tc.get("validation_kind", "SERVER")).upper()
        if role not in ("SERVER", "CLIENT"):
            role = "SERVER"
        now_u = parse_iso_time(tc.get("validation_time"))
        mode = str(tc.get("_harness_mode", "BUILD"))
        raw_depth = tc.get("max_chain_depth")
        max_d = int(raw_depth) if raw_depth is not None else -1
        got_ok, reason = client.verify(
            cid, peer_der, inter_der, trusted_der,
            peer=peer_val, now_unix=now_u, role=role, mode=mode, max_depth=max_d,
        )
        crl_pems = tc.get("crls") or []
        if got_ok and crl_pems:
            issuers = [c for c in (inter_der + trusted_der) if c]
            for crl_pem in crl_pems:
                crl_der = pem_to_der(str(crl_pem))
                crl_ok = False
                saw_matching_crl = False
                last_reason = "CrlRejected"
                for iss in issuers:
                    crl_st, crl_r = client.check_crl(cid, peer_der, iss, crl_der, now_unix=now_u)
                    if crl_st in ("DIFF_ISSUER", "BAD_ISSUER"):
                        continue
                    saw_matching_crl = True
                    if crl_st == "OK":
                        crl_ok = True
                        break
                    last_reason = f"{crl_st}:{crl_r}"
                    crl_ok = False
                    break
                if saw_matching_crl and not crl_ok:
                    got_ok = False
                    reason = last_reason
                    break
        want_ok = expected_str == "SUCCESS"
        stats.record(
            "limbo",
            cid,
            got_ok == want_ok,
            f"want={expected_str} got={'SUCCESS' if got_ok else 'FAILURE'} ({reason})",
        )


def build_local_limbo_document() -> dict[str, object]:
    """Builds 24 real PEM/DER x509-limbo torture testcases in C2SP limbo.json schema."""
    root_k = P256Key("limbo-root")
    int_k = P256Key("limbo-int")
    int2_k = P256Key("limbo-int2")
    leaf_k = P256Key("limbo-leaf")
    rogue_k = P256Key("limbo-rogue")

    root = make_ca_cert("Wing Limbo Root CA", root_k, "Wing Limbo Root CA", root_k, 1)
    inter = make_ca_cert("Wing Limbo Int CA", int_k, "Wing Limbo Root CA", root_k, 2)
    inter_p0 = make_ca_cert(
        "Wing Limbo PathLen0 CA", int_k, "Wing Limbo Root CA", root_k, 3, path_len=0
    )
    inter_sub = make_ca_cert("Wing Limbo Sub CA", int2_k, "Wing Limbo PathLen0 CA", int_k, 4)
    inter_not_ca = make_ca_cert(
        "Wing Limbo NonCA Int", int_k, "Wing Limbo Root CA", root_k, 5, is_ca=False
    )

    cases: list[dict[str, object]] = []
    # 1. Valid 3-cert ECDSA P-256 chain
    leaf_ok = make_leaf_cert(
        "example.com", leaf_k, "Wing Limbo Int CA", int_k, 101,
        dns_sans=["example.com"], eku_oids=[OID_EKU_SERVER_AUTH],
    )
    cases.append(_limbo_case(
        "limbo::valid-dns-san-chain", [root], [inter], leaf_ok, "SUCCESS",
        {"kind": "DNS", "value": "example.com"},
    ))
    # 2. Valid OpenSSL RSA-2048 chain (or P-256 fallback if openssl absent)
    rsa_pair = make_openssl_rsa2048_chain("rsa.example.com")
    if rsa_pair is not None:
        cases.append(_limbo_case(
            "limbo::valid-openssl-rsa2048-chain", [rsa_pair[0]], [], rsa_pair[1], "SUCCESS",
            {"kind": "DNS", "value": "rsa.example.com"},
            validation_time=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        ))
    else:
        cases.append(_limbo_case(
            "limbo::valid-ecdsa-direct-root", [root], [], make_leaf_cert(
                "rsa.example.com", leaf_k, "Wing Limbo Root CA", root_k, 102,
                dns_sans=["rsa.example.com"], eku_oids=[OID_EKU_SERVER_AUTH],
            ), "SUCCESS", {"kind": "DNS", "value": "rsa.example.com"},
        ))
    # 3-6. SAN wildcard rules (RFC 6125 Section 6.4.3)
    leaf_wc = make_leaf_cert(
        "*.example.com", leaf_k, "Wing Limbo Int CA", int_k, 103,
        dns_sans=["*.example.com"], eku_oids=[OID_EKU_SERVER_AUTH],
    )
    cases.append(_limbo_case(
        "limbo::san-wildcard-leftmost-valid", [root], [inter], leaf_wc, "SUCCESS",
        {"kind": "DNS", "value": "sub.example.com"},
    ))
    cases.append(_limbo_case(
        "limbo::san-wildcard-apex-reject", [root], [inter], leaf_wc, "FAILURE",
        {"kind": "DNS", "value": "example.com"},
    ))
    cases.append(_limbo_case(
        "limbo::san-wildcard-multilevel-reject", [root], [inter], leaf_wc, "FAILURE",
        {"kind": "DNS", "value": "a.b.example.com"},
    ))
    leaf_bad_wc = make_leaf_cert(
        "a.*.example.com", leaf_k, "Wing Limbo Int CA", int_k, 104,
        dns_sans=["a.*.example.com"], eku_oids=[OID_EKU_SERVER_AUTH],
    )
    cases.append(_limbo_case(
        "limbo::san-wildcard-nonleftmost-reject", [root], [inter], leaf_bad_wc, "FAILURE",
        {"kind": "DNS", "value": "a.b.example.com"},
    ))
    # 7-9. IP SANs (IPv4 match, IPv4 mismatch, IPv6 match)
    leaf_ip = make_leaf_cert(
        "ip-leaf", leaf_k, "Wing Limbo Int CA", int_k, 105,
        ip_sans=["192.0.2.1", "2001:db8::1"], eku_oids=[OID_EKU_SERVER_AUTH],
    )
    cases.append(_limbo_case(
        "limbo::san-ip-ipv4-valid", [root], [inter], leaf_ip, "SUCCESS",
        {"kind": "IP", "value": "192.0.2.1"},
    ))
    cases.append(_limbo_case(
        "limbo::san-ip-ipv4-mismatch", [root], [inter], leaf_ip, "FAILURE",
        {"kind": "IP", "value": "192.0.2.2"},
    ))
    cases.append(_limbo_case(
        "limbo::san-ip-ipv6-valid", [root], [inter], leaf_ip, "SUCCESS",
        {"kind": "IP", "value": "2001:db8::1"},
    ))
    # 10. CN-without-SAN rejection (RFC 6125 / CA/B Forum)
    leaf_cn_only = make_leaf_cert(
        "example.com", leaf_k, "Wing Limbo Int CA", int_k, 106,
        dns_sans=None, eku_oids=[OID_EKU_SERVER_AUTH],
    )
    cases.append(_limbo_case(
        "limbo::cn-without-san-reject", [root], [inter], leaf_cn_only, "FAILURE",
        {"kind": "DNS", "value": "example.com"},
    ))
    # 11. Weak RSA-1024 key rejection
    leaf_rsa1024 = make_leaf_cert(
        "weak.example.com", leaf_k, "Wing Limbo Int CA", int_k, 107,
        dns_sans=["weak.example.com"], eku_oids=[OID_EKU_SERVER_AUTH],
        spki_override=make_rsa1024_spki_der(),
    )
    cases.append(_limbo_case(
        "limbo::weak-rsa1024-leaf-reject", [root], [inter], leaf_rsa1024, "FAILURE",
        {"kind": "DNS", "value": "weak.example.com"},
    ))
    # 12-14. EKU serverAuth vs clientAuth mismatch
    leaf_client_eku = make_leaf_cert(
        "client.example.com", leaf_k, "Wing Limbo Int CA", int_k, 108,
        dns_sans=["client.example.com"], eku_oids=[OID_EKU_CLIENT_AUTH],
    )
    cases.append(_limbo_case(
        "limbo::eku-clientauth-on-server-reject", [root], [inter], leaf_client_eku, "FAILURE",
        {"kind": "DNS", "value": "client.example.com"}, validation_kind="SERVER",
    ))
    cases.append(_limbo_case(
        "limbo::eku-clientauth-on-client-valid", [root], [inter], leaf_client_eku, "SUCCESS",
        {"kind": "DNS", "value": "client.example.com"}, validation_kind="CLIENT",
    ))
    cases.append(_limbo_case(
        "limbo::eku-serverauth-on-client-reject", [root], [inter], leaf_ok, "FAILURE",
        {"kind": "DNS", "value": "example.com"}, validation_kind="CLIENT",
    ))
    # 15. Critical unknown extension rejection
    leaf_crit = make_leaf_cert(
        "crit.example.com", leaf_k, "Wing Limbo Int CA", int_k, 109,
        dns_sans=["crit.example.com"], eku_oids=[OID_EKU_SERVER_AUTH],
        extra_exts=[x509_ext("1.2.3.4.5.6.7", b"\x05\x00", critical=True)],
    )
    cases.append(_limbo_case(
        "limbo::critical-unknown-ext-reject", [root], [inter], leaf_crit, "FAILURE",
        {"kind": "DNS", "value": "crit.example.com"},
    ))
    # 16. Self-signed leaf not in trust store
    leaf_self = make_leaf_cert(
        "self.example.com", rogue_k, "self.example.com", rogue_k, 110,
        dns_sans=["self.example.com"], eku_oids=[OID_EKU_SERVER_AUTH],
    )
    cases.append(_limbo_case(
        "limbo::self-signed-leaf-untrusted-reject", [root], [], leaf_self, "FAILURE",
        {"kind": "DNS", "value": "self.example.com"},
    ))
    # 17. pathLenConstraint=0 violation
    leaf_under_sub = make_leaf_cert(
        "deep.example.com", leaf_k, "Wing Limbo Sub CA", int2_k, 111,
        dns_sans=["deep.example.com"], eku_oids=[OID_EKU_SERVER_AUTH],
    )
    cases.append(_limbo_case(
        "limbo::pathlen-zero-violation-reject", [root], [inter_p0, inter_sub], leaf_under_sub,
        "FAILURE", {"kind": "DNS", "value": "deep.example.com"},
    ))
    # 18. Expired leaf
    leaf_expired = make_leaf_cert(
        "expired.example.com", leaf_k, "Wing Limbo Int CA", int_k, 112,
        dns_sans=["expired.example.com"], eku_oids=[OID_EKU_SERVER_AUTH],
        not_before=DEFAULT_NOW - 86400 * 60, not_after=DEFAULT_NOW - 60,
    )
    cases.append(_limbo_case(
        "limbo::expired-leaf-reject", [root], [inter], leaf_expired, "FAILURE",
        {"kind": "DNS", "value": "expired.example.com"},
    ))
    # 19. Not-yet-valid leaf
    leaf_future = make_leaf_cert(
        "future.example.com", leaf_k, "Wing Limbo Int CA", int_k, 113,
        dns_sans=["future.example.com"], eku_oids=[OID_EKU_SERVER_AUTH],
        not_before=DEFAULT_NOW + 3600, not_after=DEFAULT_NOW + 86400 * 30,
    )
    cases.append(_limbo_case(
        "limbo::not-yet-valid-leaf-reject", [root], [inter], leaf_future, "FAILURE",
        {"kind": "DNS", "value": "future.example.com"},
    ))
    # 20. basicConstraints CA=false intermediate
    leaf_nonca = make_leaf_cert(
        "nonca.example.com", leaf_k, "Wing Limbo NonCA Int", int_k, 114,
        dns_sans=["nonca.example.com"], eku_oids=[OID_EKU_SERVER_AUTH],
    )
    cases.append(_limbo_case(
        "limbo::intermediate-ca-false-reject", [root], [inter_not_ca], leaf_nonca, "FAILURE",
        {"kind": "DNS", "value": "nonca.example.com"},
    ))
    # 21. Chain cycle (Leaf -> IntA -> Leaf duplicate cycle in DIRECT mode)
    cases.append(_limbo_case(
        "limbo::chain-cycle-reject", [root], [inter, leaf_ok], leaf_ok, "FAILURE",
        {"kind": "DNS", "value": "example.com"}, mode="DIRECT",
    ))
    # 22. Mismatched inner vs outer signatureAlgorithm OID
    leaf_mismatch_sig = make_leaf_cert(
        "sigalg.example.com", leaf_k, "Wing Limbo Int CA", int_k, 115,
        dns_sans=["sigalg.example.com"], eku_oids=[OID_EKU_SERVER_AUTH],
        inner_sig_oid=OID_ECDSA_SHA256, outer_sig_oid=OID_ECDSA_SHA384,
    )
    cases.append(_limbo_case(
        "limbo::mismatched-inner-outer-sigalg-reject", [root], [inter], leaf_mismatch_sig,
        "FAILURE", {"kind": "DNS", "value": "sigalg.example.com"},
    ))
    # 23. Trailing DER garbage after outer Certificate SEQUENCE
    leaf_trailing = make_leaf_cert(
        "trail.example.com", leaf_k, "Wing Limbo Int CA", int_k, 116,
        dns_sans=["trail.example.com"], eku_oids=[OID_EKU_SERVER_AUTH],
        trailing_bytes=b"\x05\x00\xde\xad",
    )
    cases.append(_limbo_case(
        "limbo::trailing-der-garbage-reject", [root], [inter], leaf_trailing, "FAILURE",
        {"kind": "DNS", "value": "trail.example.com"},
    ))
    # 24. Forbidden SHA-1 signature algorithm
    leaf_sha1 = make_leaf_cert(
        "sha1.example.com", leaf_k, "Wing Limbo Int CA", int_k, 117,
        dns_sans=["sha1.example.com"], eku_oids=[OID_EKU_SERVER_AUTH],
        inner_sig_oid=OID_ECDSA_SHA1, outer_sig_oid=OID_ECDSA_SHA1,
    )
    cases.append(_limbo_case(
        "limbo::sha1-signature-reject", [root], [inter], leaf_sha1, "FAILURE",
        {"kind": "DNS", "value": "sha1.example.com"},
    ))
    return {"version": 1, "testcases": cases}


# ---- BetterTLS Suite (NameConstraints + Path Building / Cross-Signing) ------

def run_bettertls_local(client: HarnessClient, stats: SuiteStats) -> None:
    root_k = P256Key("btls-root")
    root_nc_k = P256Key("btls-root-nc")
    old_root_k = P256Key("btls-old-root")
    int1_k = P256Key("btls-int1")
    int2_k = P256Key("btls-int2")
    decoy_k = P256Key("btls-decoy")
    leaf_k = P256Key("btls-leaf")

    root = make_ca_cert("BetterTLS Root CA", root_k, "BetterTLS Root CA", root_k, 10)
    # Intermediate with DNS permitted + excluded NameConstraints
    int_dns_nc = make_ca_cert(
        "BetterTLS DNS NC CA", int1_k, "BetterTLS Root CA", root_k, 11,
        extra_exts=[ext_name_constraints(
            permitted_dns=["example.com"], excluded_dns=["bad.example.com"],
        )],
    )
    # Intermediate with IPv4 permitted + excluded NameConstraints
    int_ip_nc = make_ca_cert(
        "BetterTLS IP NC CA", int2_k, "BetterTLS Root CA", root_k, 12,
        extra_exts=[ext_name_constraints(
            permitted_ips=["10.0.0.0/8"], excluded_ips=["10.99.0.0/16"],
        )],
    )
    # TrustAnchor Root carrying NameConstraints directly (RFC 5280 / BetterTLS)
    root_nc = make_ca_cert(
        "BetterTLS Constrained Root", root_nc_k, "BetterTLS Constrained Root", root_nc_k, 13,
        extra_exts=[ext_name_constraints(
            permitted_dns=["corp.test"], excluded_ips=["10.20.0.0/16"],
        )],
    )
    int_under_root_nc = make_ca_cert(
        "BetterTLS Sub Under RootNC", int1_k, "BetterTLS Constrained Root", root_nc_k, 14,
    )

    def _check(
        cid: str, leaf: bytes, inters: list[bytes], anchors: list[bytes],
        peer: str, want_ok: bool,
    ) -> None:
        got_ok, reason = client.verify(cid, leaf, inters, anchors, peer=peer)
        stats.record(
            "bettertls", cid, got_ok == want_ok,
            f"want={'OK' if want_ok else 'FAIL'} got={'OK' if got_ok else 'FAIL'} ({reason})",
        )

    # 1-4: Intermediate DNS NameConstraints
    _check("bettertls::nc-int-dns-permitted-pass",
           make_leaf_cert("app.example.com", leaf_k, "BetterTLS DNS NC CA", int1_k, 201,
                          dns_sans=["app.example.com"]),
           [int_dns_nc], [root], "app.example.com", True)
    _check("bettertls::nc-int-dns-permitted-fail",
           make_leaf_cert("evil.org", leaf_k, "BetterTLS DNS NC CA", int1_k, 202,
                          dns_sans=["evil.org"]),
           [int_dns_nc], [root], "evil.org", False)
    _check("bettertls::nc-int-dns-excluded-fail",
           make_leaf_cert("x.bad.example.com", leaf_k, "BetterTLS DNS NC CA", int1_k, 203,
                          dns_sans=["x.bad.example.com"]),
           [int_dns_nc], [root], "x.bad.example.com", False)
    _check("bettertls::nc-int-dns-excluded-pass",
           make_leaf_cert("good.example.com", leaf_k, "BetterTLS DNS NC CA", int1_k, 204,
                          dns_sans=["good.example.com"]),
           [int_dns_nc], [root], "good.example.com", True)
    # 5-7: Intermediate IP NameConstraints
    _check("bettertls::nc-int-ip-permitted-pass",
           make_leaf_cert("ip-ok", leaf_k, "BetterTLS IP NC CA", int2_k, 205, ip_sans=["10.1.2.3"]),
           [int_ip_nc], [root], "10.1.2.3", True)
    _check("bettertls::nc-int-ip-permitted-fail",
           make_leaf_cert("ip-out", leaf_k, "BetterTLS IP NC CA", int2_k, 206,
                          ip_sans=["192.168.1.1"]),
           [int_ip_nc], [root], "192.168.1.1", False)
    _check("bettertls::nc-int-ip-excluded-fail",
           make_leaf_cert("ip-excl", leaf_k, "BetterTLS IP NC CA", int2_k, 207,
                          ip_sans=["10.99.5.5"]),
           [int_ip_nc], [root], "10.99.5.5", False)
    # 8-10: TrustAnchor Root NameConstraints (anchor not sent in wire chain!)
    _check("bettertls::nc-root-anchor-dns-permitted-pass",
           make_leaf_cert("api.corp.test", leaf_k, "BetterTLS Sub Under RootNC", int1_k, 208,
                          dns_sans=["api.corp.test"]),
           [int_under_root_nc], [root_nc], "api.corp.test", True)
    _check("bettertls::nc-root-anchor-dns-permitted-fail",
           make_leaf_cert("outside.example.com", leaf_k, "BetterTLS Sub Under RootNC", int1_k, 209,
                          dns_sans=["outside.example.com"]),
           [int_under_root_nc], [root_nc], "outside.example.com", False)
    _check("bettertls::nc-root-anchor-ip-excluded-fail",
           make_leaf_cert("ip-root-excl", leaf_k, "BetterTLS Sub Under RootNC", int1_k, 210,
                          ip_sans=["10.20.5.5"]),
           [int_under_root_nc], [root_nc], "10.20.5.5", False)

    # 11: Out-of-order intermediates [Int1, Int2] for Leaf -> Int2 -> Int1 -> Root
    int_top = make_ca_cert("BetterTLS Top Int", int1_k, "BetterTLS Root CA", root_k, 15)
    int_mid = make_ca_cert("BetterTLS Mid Int", int2_k, "BetterTLS Top Int", int1_k, 16)
    leaf_ooo = make_leaf_cert("ooo.example.com", leaf_k, "BetterTLS Mid Int", int2_k, 211,
                              dns_sans=["ooo.example.com"])
    _check("bettertls::pathbuild-out-of-order-intermediates",
           leaf_ooo, [int_top, int_mid], [root], "ooo.example.com", True)

    # 12: Cross-signed intermediate: expired/untrusted branch + valid trusted branch
    int_cross_bad = make_ca_cert(
        "BetterTLS Cross Int", int1_k, "BetterTLS Old Expired Root", old_root_k, 17,
        not_before=DEFAULT_NOW - 86400 * 60, not_after=DEFAULT_NOW - 86400,
    )
    int_cross_good = make_ca_cert(
        "BetterTLS Cross Int", int1_k, "BetterTLS Root CA", root_k, 18,
    )
    leaf_cross = make_leaf_cert("cross.example.com", leaf_k, "BetterTLS Cross Int", int1_k, 212,
                                dns_sans=["cross.example.com"])
    _check("bettertls::pathbuild-cross-signed-alt-path",
           leaf_cross, [int_cross_bad, int_cross_good], [root], "cross.example.com", True)

    # 13: Unrelated decoy intermediates + out-of-order valid chain
    decoy_ca = make_ca_cert("BetterTLS Decoy CA", decoy_k, "BetterTLS Decoy CA", decoy_k, 19)
    _check("bettertls::pathbuild-decoy-noise-intermediates",
           leaf_ooo, [decoy_ca, int_top, int_mid], [root], "ooo.example.com", True)

    # 14: End-entity NameConstraints forbidden (RFC 5280 Section 4.2.1.10)
    leaf_with_nc = make_leaf_cert(
        "nc-ee.example.com", leaf_k, "BetterTLS Top Int", int1_k, 213,
        dns_sans=["nc-ee.example.com"],
        extra_exts=[ext_name_constraints(permitted_dns=["example.com"])],
    )
    _check("bettertls::nc-end-entity-forbidden",
           leaf_with_nc, [int_top], [root], "nc-ee.example.com", False)


# ---- NIST PKITS Suite (RFC 5280 Chain, CRL, OCSP + --pkits-dir Corpus) ------

def run_pkits_local(client: HarnessClient, stats: SuiteStats) -> None:
    ta_k = P256Key("pkits-ta")
    ca1_k = P256Key("pkits-ca1")
    ca2_k = P256Key("pkits-ca2")
    si_k = P256Key("pkits-self-issued")
    ee_k = P256Key("pkits-ee")

    ta = make_ca_cert("PKITS Trust Anchor", ta_k, "PKITS Trust Anchor", ta_k, 1)
    good_ca = make_ca_cert("PKITS Good CA", ca1_k, "PKITS Trust Anchor", ta_k, 2)
    bad_sig_ca = make_ca_cert(
        "PKITS BadSig CA", ca1_k, "PKITS Trust Anchor", ta_k, 3, corrupt_sig=True
    )
    not_yet_ca = make_ca_cert(
        "PKITS Future CA", ca1_k, "PKITS Trust Anchor", ta_k, 4,
        not_before=DEFAULT_NOW + 7200, not_after=DEFAULT_NOW + 86400 * 30,
    )
    expired_ca = make_ca_cert(
        "PKITS Expired CA", ca1_k, "PKITS Trust Anchor", ta_k, 5,
        not_before=DEFAULT_NOW - 86400 * 60, not_after=DEFAULT_NOW - 120,
    )
    no_bc_ca = make_ca_cert(
        "PKITS NoBC CA", ca1_k, "PKITS Trust Anchor", ta_k, 6, include_bc=False
    )
    false_bc_ca = make_ca_cert(
        "PKITS FalseBC CA", ca1_k, "PKITS Trust Anchor", ta_k, 7, is_ca=False
    )
    no_kcs_ca = make_ca_cert(
        "PKITS NoKeyCertSign CA", ca1_k, "PKITS Trust Anchor", ta_k, 8, ku_byte=0x80, ku_unused=7
    )
    pl0_ca = make_ca_cert(
        "PKITS PathLen0 CA", ca1_k, "PKITS Trust Anchor", ta_k, 9, path_len=0
    )
    sub_under_pl0 = make_ca_cert(
        "PKITS Sub Under PL0", ca2_k, "PKITS PathLen0 CA", ca1_k, 10
    )
    # Self-issued intermediate: subject == issuer ("PKITS PathLen0 CA"), different key!
    self_issued_ca = make_ca_cert(
        "PKITS PathLen0 CA", si_k, "PKITS PathLen0 CA", ca1_k, 11
    )

    def _chain(cid: str, leaf: bytes, inters: list[bytes], want_ok: bool) -> None:
        got_ok, reason = client.verify(cid, leaf, inters, [ta], peer="-")
        stats.record(
            "pkits", cid, got_ok == want_ok,
            f"want={'OK' if want_ok else 'FAIL'} got={'OK' if got_ok else 'FAIL'} ({reason})",
        )

    ee_good = make_leaf_cert("ee1", ee_k, "PKITS Good CA", ca1_k, 301, dns_sans=["ee.pkits.test"])
    ee_badsig = make_leaf_cert(
        "ee2", ee_k, "PKITS Good CA", ca1_k, 302, dns_sans=["ee.pkits.test"], corrupt_sig=True
    )
    _chain("pkits::4.1.1-valid-signature", ee_good, [good_ca], True)
    _chain("pkits::4.1.2-invalid-ca-signature",
           make_leaf_cert("ee", ee_k, "PKITS BadSig CA", ca1_k, 303), [bad_sig_ca], False)
    _chain("pkits::4.1.3-invalid-ee-signature", ee_badsig, [good_ca], False)
    _chain("pkits::4.2.1-valid-validity", ee_good, [good_ca], True)
    _chain("pkits::4.2.2-invalid-ca-notbefore",
           make_leaf_cert("ee", ee_k, "PKITS Future CA", ca1_k, 304), [not_yet_ca], False)
    _chain("pkits::4.2.5-invalid-ca-notafter",
           make_leaf_cert("ee", ee_k, "PKITS Expired CA", ca1_k, 305), [expired_ca], False)
    _chain("pkits::4.6.1-missing-basic-constraints",
           make_leaf_cert("ee", ee_k, "PKITS NoBC CA", ca1_k, 306), [no_bc_ca], False)
    _chain("pkits::4.6.2-basic-constraints-ca-false",
           make_leaf_cert("ee", ee_k, "PKITS FalseBC CA", ca1_k, 307), [false_bc_ca], False)
    _chain("pkits::4.6.7-keyusage-missing-keycertsign",
           make_leaf_cert("ee", ee_k, "PKITS NoKeyCertSign CA", ca1_k, 308), [no_kcs_ca], False)
    _chain("pkits::4.6.8-pathlen-zero-valid-leaf",
           make_leaf_cert("ee", ee_k, "PKITS PathLen0 CA", ca1_k, 309), [pl0_ca], True)
    _chain("pkits::4.6.9-pathlen-zero-fail-subca",
           make_leaf_cert("ee", ee_k, "PKITS Sub Under PL0", ca2_k, 310),
           [pl0_ca, sub_under_pl0], False)
    # RFC 5280 Section 6.1.4(l): self-issued intermediate does not decrement pathLenConstraint
    _chain("pkits::4.6.13-self-issued-intermediate-pathlen",
           make_leaf_cert("ee", ee_k, "PKITS PathLen0 CA", si_k, 311),
           [self_issued_ca, pl0_ca], True)
    # CRL verification & revocation (RFC 5280 Section 5)
    crl_clean = build_x509_crl("PKITS Good CA", ca1_k, [999, 1000])
    crl_revoked = build_x509_crl("PKITS Good CA", ca1_k, [250, 301, 450])
    crl_badsig = build_x509_crl("PKITS Good CA", ca1_k, [301], corrupt_sig=True)
    crl_expired = build_x509_crl(
        "PKITS Good CA", ca1_k, [],
        this_update=DEFAULT_NOW - 7200, next_update=DEFAULT_NOW - 60,
    )
    for cid, crl_der, want_st in (
        ("pkits::4.4.1-crl-valid-unrevoked", crl_clean, "OK"),
        ("pkits::4.4.2-crl-revoked-leaf", crl_revoked, "REVOKED"),
        ("pkits::4.4.3-crl-invalid-signature", crl_badsig, "BAD_SIG"),
        ("pkits::4.4.4-crl-expired", crl_expired, "EXPIRED"),
    ):
        st, reason = client.check_crl(cid, ee_good, good_ca, crl_der)
        stats.record("pkits", cid, st == want_st, f"want={want_st} got={st} ({reason})")

    # OCSP stapling verification (RFC 6066 Section 8, RFC 6960)
    ocsp_good = build_ocsp_response("PKITS Good CA", ca1_k, 301, status="good")
    ocsp_revoked = build_ocsp_response("PKITS Good CA", ca1_k, 301, status="revoked")
    ocsp_badsig = build_ocsp_response("PKITS Good CA", ca1_k, 301, status="good", corrupt_sig=True)
    ocsp_wrong_ser = build_ocsp_response("PKITS Good CA", ca1_k, 999, status="good")
    for cid, ocsp_der, want_ok in (
        ("pkits::ocsp-stapling-good", ocsp_good, True),
        ("pkits::ocsp-stapling-revoked", ocsp_revoked, False),
        ("pkits::ocsp-stapling-bad-sig", ocsp_badsig, False),
        ("pkits::ocsp-stapling-wrong-serial", ocsp_wrong_ser, False),
    ):
        got_ok, reason = client.check_ocsp(cid, ee_good, good_ca, ocsp_der)
        stats.record(
            "pkits", cid, got_ok == want_ok,
            f"want={'OK' if want_ok else 'FAIL'} got={'OK' if got_ok else 'FAIL'} ({reason})",
        )


def run_pkits_dir(client: HarnessClient, pkits_dir: Path, stats: SuiteStats) -> None:
    """Evaluates an external NIST PKITS DER corpus directory (certs/ + crls/)."""
    certs_dir = pkits_dir / "certs" if (pkits_dir / "certs").is_dir() else pkits_dir
    ta_path = certs_dir / "TrustAnchorRootCertificate.crt"
    if not ta_path.is_file():
        print(f"[!] Missing TrustAnchorRootCertificate.crt in {certs_dir}", file=sys.stderr)
        stats.failed += 1
        return
    ta_der = ta_path.read_bytes()
    ca_ders: list[bytes] = []
    for p in sorted(certs_dir.glob("*CACert*.crt")):
        if len(ca_ders) < 16:
            ca_ders.append(p.read_bytes())
    ee_paths = sorted(certs_dir.glob("*EE.crt"))
    if not ee_paths:
        print(f"[!] No *EE.crt certificates found in {certs_dir}", file=sys.stderr)
        stats.failed += 1
        return
    # PKITS corpus standard validation time: 2011-04-16T00:00:00Z
    pkits_now = 1302912000
    for ee_p in ee_paths:
        stem = ee_p.stem
        if stem.startswith("Valid"):
            want_ok = True
        elif stem.startswith("Invalid"):
            want_ok = False
        else:
            stats.skipped += 1
            continue
        got_ok, reason = client.verify(
            f"pkits-dir::{stem}", ee_p.read_bytes(), ca_ders, [ta_der],
            peer="-", now_unix=pkits_now, role="ANY", mode="BUILD",
        )
        stats.record(
            "pkits-dir", stem, got_ok == want_ok,
            f"want={'OK' if want_ok else 'FAIL'} got={'OK' if got_ok else 'FAIL'} ({reason})",
        )


def fetch_limbo_json() -> Path:
    cache_dir = Path(tempfile.gettempdir()) / "goose_wing_x509_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    dst = cache_dir / "limbo.json"
    print(f"[*] Fetching C2SP/x509-limbo corpus from {LIMBO_RAW_URL}...")
    req = urllib.request.Request(LIMBO_RAW_URL, headers={"User-Agent": "goose-wing-x509-suites/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        dst.write_bytes(resp.read())
    print(f"[+] Saved limbo.json ({dst.stat().st_size} bytes) to {dst}")
    return dst


def main() -> None:
    parser = argparse.ArgumentParser(
        description="X.509 PKI Conformance Suites (x509-limbo, BetterTLS, NIST PKITS) for goose-wing"
    )
    parser.add_argument(
        "--suite", choices=["all", "limbo", "bettertls", "pkits"], default="all",
        help="Target conformance suite to run",
    )
    parser.add_argument("--local", action="store_true", help="Run offline local test vectors")
    parser.add_argument("--limbo-json", default="", help="Path to external C2SP limbo.json")
    parser.add_argument("--pkits-dir", default="", help="Path to extracted NIST PKITS DER corpus")
    parser.add_argument("--fetch", action="store_true", help="Fetch latest C2SP/x509-limbo JSON")
    parser.add_argument("--docker", action="store_true", help="Run suites via docker compose")
    parser.add_argument("--rebuild", action="store_true", help="Force rebuild x509_harness")
    parser.add_argument("--limit", type=int, default=0, help="Max external limbo testcases (0=all)")
    args = parser.parse_args()

    if args.docker:
        compose_file = SUITE_DIR / "docker-compose.yml"
        cmd = [
            "docker", "compose", "-f", str(compose_file), "up", "--build",
            "--abort-on-container-exit", "--exit-code-from", "x509-runner",
        ]
        print(f"[*] Running X.509 suites via docker compose ({compose_file.name})...")
        sys.exit(subprocess.run(cmd, check=False, cwd=str(ROOT_DIR)).returncode)

    exe = ensure_harness_binary(force_rebuild=args.rebuild)
    client = HarnessClient(exe)
    stats = SuiteStats()
    try:
        if args.suite in ("all", "limbo"):
            if args.limbo_json:
                print(f"\nExecuting external x509-limbo corpus ({args.limbo_json})...")
                doc = json.loads(Path(args.limbo_json).read_text(encoding="utf-8"))
                run_limbo_document(client, doc, stats, limit=args.limit)
            elif args.fetch:
                fetched = fetch_limbo_json()
                doc = json.loads(fetched.read_text(encoding="utf-8"))
                run_limbo_document(client, doc, stats, limit=args.limit)
            else:
                print("\nExecuting local x509-limbo torture suite (24 vectors)...")
                run_limbo_document(client, build_local_limbo_document(), stats)

        if args.suite in ("all", "bettertls"):
            print("\nExecuting BetterTLS NameConstraints & Path-Building suite (14 vectors)...")
            run_bettertls_local(client, stats)

        if args.suite in ("all", "pkits"):
            if args.pkits_dir:
                print(f"\nExecuting external NIST PKITS DER corpus ({args.pkits_dir})...")
                run_pkits_dir(client, Path(args.pkits_dir), stats)
            else:
                print("\nExecuting NIST PKITS RFC 5280 chain, CRL & OCSP suite (20 vectors)...")
                run_pkits_local(client, stats)
    finally:
        client.close()

    total = stats.passed + stats.failed
    print(
        f"\nCompleted: {stats.passed}/{total} passed, "
        f"{stats.failed} failed, {stats.skipped} skipped."
    )
    sys.exit(0 if stats.failed == 0 and total > 0 else 1)


if __name__ == "__main__":
    main()
