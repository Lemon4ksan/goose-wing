#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""Cryptographic test vector conformance runner for goose-wing.

Drives `tools/crypto_vectors/harness.goose` over line-based stdin/stdout against
curated or full upstream C2SP/Wycheproof, C2SP/CCTV, and NIST ACVP corpora.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
import sys
import urllib.request
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

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
SUITE_DIR = Path(__file__).resolve().parent
CACHE_DIR = ROOT_DIR / ".lit" / "cache" / "crypto_vectors"
HARNESS_SRC = SUITE_DIR / "harness.goose"
HARNESS_EXE = CACHE_DIR / ("harness.exe" if sys.platform == "win32" else "harness")


@dataclass
class SuiteStats:
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    failures: list[str] | None = None

    def __post_init__(self) -> None:
        if self.failures is None:
            self.failures = []

    def record_pass(self) -> None:
        self.passed += 1

    def record_skip(self) -> None:
        self.skipped += 1

    def record_fail(self, msg: str) -> None:
        self.failed += 1
        assert self.failures is not None
        self.failures.append(msg)


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der_tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


def _der_pos_int(hex_str: str) -> bytes:
    raw = bytes.fromhex(hex_str)
    raw = raw.lstrip(b"\x00") or b"\x00"
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _der_tlv(0x02, raw)


def rsa_pkcs1_pub_der_from_key(key_obj: dict) -> str:
    n_der = _der_pos_int(key_obj["modulus"])
    e_der = _der_pos_int(key_obj["publicExponent"])
    return _der_tlv(0x30, n_der + e_der).hex()


def ec_uncompressed_from_key(key_obj: dict, coord_bytes: int) -> str:
    if key_obj.get("uncompressed"):
        return str(key_obj["uncompressed"]).lower()
    wx = bytes.fromhex(key_obj["wx"]).lstrip(b"\x00").rjust(coord_bytes, b"\x00")
    wy = bytes.fromhex(key_obj["wy"]).lstrip(b"\x00").rjust(coord_bytes, b"\x00")
    return (b"\x04" + wx[-coord_bytes:] + wy[-coord_bytes:]).hex()


def hex_or_dash(h: str) -> str:
    s = h.strip().lower()
    return s if s else "-"


def build_harness(force: bool = False) -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if (
        not force
        and HARNESS_EXE.exists()
        and HARNESS_EXE.stat().st_mtime >= HARNESS_SRC.stat().st_mtime
    ):
        return HARNESS_EXE
    env = os.environ.copy()
    if sys.platform == "win32" and "GOOSE_CC" not in env:
        gcc_bat = ROOT_DIR / "tools" / "gcc_stack.bat"
        if gcc_bat.exists():
            env["GOOSE_CC"] = str(gcc_bat)
    cmd = ["goose", "build", "-O2", "-o", str(HARNESS_EXE), str(HARNESS_SRC)]
    res = subprocess.run(cmd, cwd=ROOT_DIR, env=env, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Failed to build harness.goose:\n{res.stdout}\n{res.stderr}")
    return HARNESS_EXE


class HarnessClient:
    def __init__(self, exe_path: Path) -> None:
        self._proc = subprocess.Popen(
            [str(exe_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
            cwd=ROOT_DIR,
        )

    def call(self, *fields: str) -> list[str]:
        assert self._proc.stdin is not None and self._proc.stdout is not None
        line = "\t".join(fields) + "\n"
        self._proc.stdin.write(line)
        self._proc.stdin.flush()
        resp = self._proc.stdout.readline()
        if not resp:
            err = self._proc.stderr.read() if self._proc.stderr else ""
            raise RuntimeError(f"Harness terminated unexpectedly on {fields[0]}: {err}")
        return resp.rstrip("\r\n").split("\t")

    def close(self) -> None:
        if self._proc.stdin:
            self._proc.stdin.close()
        self._proc.wait(timeout=10)


def _eval_wycheproof_aead(
    client: HarnessClient, alg: str, group: dict, stats: SuiteStats
) -> None:
    key_bits = int(group.get("keySize", 0))
    iv_bits = int(group.get("ivSize", 0))
    tag_bits = int(group.get("tagSize", 0))
    if alg == "AES-GCM":
        if key_bits == 128 and iv_bits == 96 and tag_bits == 128:
            seal_cmd, open_cmd = "AES128_GCM_SEAL", "AES128_GCM_OPEN"
        elif key_bits == 256 and iv_bits == 96 and tag_bits == 128:
            seal_cmd, open_cmd = "AES256_GCM_SEAL", "AES256_GCM_OPEN"
        else:
            for _ in group.get("tests", []):
                stats.record_skip()
            return
    elif alg == "CHACHA20-POLY1305" and key_bits == 256 and iv_bits == 96 and tag_bits == 128:
        seal_cmd, open_cmd = "CHACHA20_POLY1305_SEAL", "CHACHA20_POLY1305_OPEN"
    else:
        for _ in group.get("tests", []):
            stats.record_skip()
        return

    for tc in group.get("tests", []):
        tc_id = tc["tcId"]
        res = tc["result"]
        k, iv, aad = hex_or_dash(tc["key"]), hex_or_dash(tc["iv"]), hex_or_dash(tc["aad"])
        msg, ct, tag = hex_or_dash(tc["msg"]), hex_or_dash(tc["ct"]), hex_or_dash(tc["tag"])
        got_open = client.call(open_cmd, k, iv, aad, ct, tag)
        if res == "valid":
            got_seal = client.call(seal_cmd, k, iv, aad, msg)
            ok_seal = got_seal[0] == "OK" and got_seal[1] == ct and got_seal[2] == tag
            ok_open = got_open[0] == "OK" and got_open[1] == msg
            if ok_seal and ok_open:
                stats.record_pass()
            else:
                stats.record_fail(f"Wycheproof {alg} tcId={tc_id} expected valid, got {got_seal}/{got_open}")
        elif res == "invalid":
            if got_open[0] == "FAIL":
                stats.record_pass()
            else:
                stats.record_fail(f"Wycheproof {alg} tcId={tc_id} expected invalid, got {got_open}")
        else:
            if got_open[0] == "FAIL" or (got_open[0] == "OK" and got_open[1] == msg):
                stats.record_pass()
            else:
                stats.record_fail(f"Wycheproof {alg} tcId={tc_id} acceptable mismatch: {got_open}")


def _check_verify_verdict(
    label: str, tc_id: int, expected: str, got_ok: bool, stats: SuiteStats
) -> None:
    if expected == "valid":
        if got_ok:
            stats.record_pass()
        else:
            stats.record_fail(f"{label} tcId={tc_id}: expected valid, got FAIL")
    elif expected == "invalid":
        if not got_ok:
            stats.record_pass()
        else:
            stats.record_fail(f"{label} tcId={tc_id}: expected invalid, got OK")
    else:
        stats.record_pass()


def _eval_wycheproof_xdh(client: HarnessClient, group: dict, stats: SuiteStats) -> None:
    if group.get("curve") != "curve25519":
        for _ in group.get("tests", []):
            stats.record_skip()
        return
    for tc in group.get("tests", []):
        tc_id, expected = tc["tcId"], tc["result"]
        got = client.call("X25519", hex_or_dash(tc["private"]), hex_or_dash(tc["public"]))
        exp_ss = hex_or_dash(tc.get("shared", ""))
        if expected == "valid":
            if got[0] == "OK" and got[1] == exp_ss:
                stats.record_pass()
            else:
                stats.record_fail(f"Wycheproof X25519 tcId={tc_id}: got {got}, expected {exp_ss}")
        elif expected == "invalid":
            if got[0] == "FAIL":
                stats.record_pass()
            else:
                stats.record_fail(f"Wycheproof X25519 tcId={tc_id}: expected FAIL, got {got}")
        else:
            if got[0] == "FAIL" or (got[0] == "OK" and got[1] == exp_ss):
                stats.record_pass()
            else:
                stats.record_fail(f"Wycheproof X25519 tcId={tc_id}: acceptable mismatch {got}")


def _eval_wycheproof_sig(
    client: HarnessClient, alg: str, group: dict, stats: SuiteStats
) -> None:
    key_obj = group.get("key", {})
    sha = group.get("sha", "")
    cmd = ""
    pub_hex = ""
    if alg == "ECDSA":
        curve = key_obj.get("curve", "")
        if curve == "secp256r1" and sha == "SHA-256":
            cmd, pub_hex = "ECDSA_P256_VERIFY_DER", ec_uncompressed_from_key(key_obj, 32)
        elif curve == "secp384r1" and sha == "SHA-384":
            cmd, pub_hex = "ECDSA_P384_VERIFY_DER", ec_uncompressed_from_key(key_obj, 48)
    elif alg == "EDDSA" and key_obj.get("curve") == "edwards25519":
        cmd, pub_hex = "ED25519_VERIFY", hex_or_dash(key_obj.get("pk", ""))
    elif alg == "RSASSA-PKCS1-v1_5" and sha == "SHA-256":
        cmd, pub_hex = "RSA_PKCS1_SHA256_VERIFY_DER", rsa_pkcs1_pub_der_from_key(key_obj)
    elif alg == "RSASSA-PSS" and sha == "SHA-256" and group.get("mgfSha") == "SHA-256" and group.get("sLen") == 32:
        cmd, pub_hex = "RSA_PSS_SHA256_VERIFY_DER", rsa_pkcs1_pub_der_from_key(key_obj)
    if not cmd:
        for _ in group.get("tests", []):
            stats.record_skip()
        return
    for tc in group.get("tests", []):
        got = client.call(cmd, pub_hex, hex_or_dash(tc["msg"]), hex_or_dash(tc["sig"]))
        _check_verify_verdict(f"Wycheproof {alg}", tc["tcId"], tc["result"], got[0] == "OK", stats)


def _eval_wycheproof_hkdf_or_mac(
    client: HarnessClient, alg: str, group: dict, stats: SuiteStats
) -> None:
    if alg in ("HKDF-SHA-256", "HKDF-SHA-384"):
        cmd = "HKDF_SHA256" if alg == "HKDF-SHA-256" else "HKDF_SHA384"
        for tc in group.get("tests", []):
            got = client.call(
                cmd, hex_or_dash(tc["salt"]), hex_or_dash(tc["ikm"]), hex_or_dash(tc["info"]), str(tc["size"])
            )
            exp = hex_or_dash(tc.get("okm", ""))
            ok = got[0] == "OK" and got[1] == exp
            _check_verify_verdict(f"Wycheproof {alg}", tc["tcId"], tc["result"], ok, stats)
        return
    if alg in ("HMACSHA256", "HMACSHA384"):
        cmd = "HMAC_SHA256" if alg == "HMACSHA256" else "HMAC_SHA384"
        tag_bytes = int(group.get("tagSize", 0)) // 8
        for tc in group.get("tests", []):
            got = client.call(cmd, hex_or_dash(tc["key"]), hex_or_dash(tc["msg"]))
            exp = hex_or_dash(tc.get("tag", ""))
            ok = got[0] == "OK" and got[1][: tag_bytes * 2] == exp
            _check_verify_verdict(f"Wycheproof {alg}", tc["tcId"], tc["result"], ok, stats)
        return
    for _ in group.get("tests", []):
        stats.record_skip()


def run_wycheproof_doc(client: HarnessClient, doc: dict | list, stats: SuiteStats) -> None:
    items = doc if isinstance(doc, list) else [doc]
    for item in items:
        alg = str(item.get("algorithm", ""))
        for group in item.get("testGroups", []):
            if alg in ("AES-GCM", "CHACHA20-POLY1305"):
                _eval_wycheproof_aead(client, alg, group, stats)
            elif alg == "XDH":
                _eval_wycheproof_xdh(client, group, stats)
            elif alg in ("ECDSA", "EDDSA", "RSASSA-PKCS1-v1_5", "RSASSA-PSS"):
                _eval_wycheproof_sig(client, alg, group, stats)
            elif alg in ("HKDF-SHA-256", "HKDF-SHA-384", "HMACSHA256", "HMACSHA384"):
                _eval_wycheproof_hkdf_or_mac(client, alg, group, stats)
            else:
                for _ in group.get("tests", []):
                    stats.record_skip()


def run_cctv_doc(client: HarnessClient, doc: dict, stats: SuiteStats) -> None:
    for tc in doc.get("mlkem768_modulus", []):
        got = client.call("MLKEM768_ENCAPS", hex_or_dash(tc["ek"]), hex_or_dash(tc.get("m", "00" * 32)))
        ok = (got[0] == "OK") == bool(tc["valid"])
        if ok:
            stats.record_pass()
        else:
            stats.record_fail(f"CCTV {tc['id']}: expected valid={tc['valid']}, got {got[0]}")
    for tc in doc.get("mlkem768_implicit_rejection", []):
        got = client.call("MLKEM768_DECAPS", hex_or_dash(tc["ct"]), hex_or_dash(tc["dk"]))
        exp = hex_or_dash(tc["expected_ss"])
        if got[0] == "OK" and got[1] == exp:
            stats.record_pass()
        else:
            stats.record_fail(f"CCTV {tc['id']}: expected ss={exp}, got {got}")
    for tc in doc.get("ed25519", []):
        got = client.call("ED25519_VERIFY", hex_or_dash(tc["pk"]), hex_or_dash(tc["msg"]), hex_or_dash(tc["sig"]))
        if (got[0] == "OK") == bool(tc["valid"]):
            stats.record_pass()
        else:
            stats.record_fail(f"CCTV {tc['id']}: expected valid={tc['valid']}, got {got[0]}")


def run_cctv_modulus_txt(client: HarnessClient, path: Path, stats: SuiteStats) -> None:
    """Runs official C2SP/CCTV ML-KEM/modulus/ML-KEM-768.txt (one invalid hex ek per line)."""
    zero_m = "00" * 32
    for idx, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        got = client.call("MLKEM768_ENCAPS", line.lower(), zero_m)
        if got[0] == "FAIL":
            stats.record_pass()
        else:
            stats.record_fail(f"CCTV {path.name}:{idx}: non-canonical ek was accepted")


def _eval_acvp_mlkem(client: HarnessClient, mode: str, group: dict, stats: SuiteStats) -> None:
    if group.get("parameterSet") != "ML-KEM-768":
        for _ in group.get("tests", []):
            stats.record_skip()
        return
    fn_name = group.get("function", "")
    for tc in group.get("tests", []):
        tc_id = tc["tcId"]
        if mode == "keyGen":
            got = client.call("MLKEM768_KEYGEN", hex_or_dash(tc["d"]), hex_or_dash(tc["z"]))
            if got[0] == "OK" and got[1] == tc["ek"].lower() and got[2] == tc["dk"].lower():
                stats.record_pass()
            else:
                stats.record_fail(f"ACVP ML-KEM-768 keyGen tcId={tc_id} mismatch")
        elif fn_name == "encapsulation":
            got = client.call("MLKEM768_ENCAPS", hex_or_dash(tc["ek"]), hex_or_dash(tc["m"]))
            if got[0] == "OK" and got[1] == tc["c"].lower() and got[2] == tc["k"].lower():
                stats.record_pass()
            else:
                stats.record_fail(f"ACVP ML-KEM-768 encaps tcId={tc_id} mismatch")
        elif fn_name == "decapsulation":
            got = client.call("MLKEM768_DECAPS", hex_or_dash(tc["c"]), hex_or_dash(tc["dk"]))
            if got[0] == "OK" and got[1] == tc["k"].lower():
                stats.record_pass()
            else:
                stats.record_fail(f"ACVP ML-KEM-768 decaps tcId={tc_id}: got {got}")
        elif fn_name == "encapsulationKeyCheck":
            got = client.call("MLKEM768_ENCAPS", hex_or_dash(tc["ek"]), "00" * 32)
            if (got[0] == "OK") == bool(tc["testPassed"]):
                stats.record_pass()
            else:
                stats.record_fail(f"ACVP ML-KEM-768 ekCheck tcId={tc_id} mismatch")
        else:
            stats.record_skip()


def _eval_acvp_hash_or_hmac(client: HarnessClient, alg: str, group: dict, stats: SuiteStats) -> None:
    hash_cmds = {"SHA2-256": "SHA256", "SHA2-384": "SHA384", "SHA2-512": "SHA512"}
    hmac_cmds = {"HMAC-SHA2-256": "HMAC_SHA256", "HMAC-SHA2-384": "HMAC_SHA384"}
    if alg in hash_cmds:
        cmd = hash_cmds[alg]
        for tc in group.get("tests", []):
            if tc.get("len", 0) % 8 != 0:
                stats.record_skip()
                continue
            got = client.call(cmd, hex_or_dash(tc["msg"]))
            if got[0] == "OK" and got[1] == tc["md"].lower():
                stats.record_pass()
            else:
                stats.record_fail(f"ACVP {alg} tcId={tc['tcId']} digest mismatch")
        return
    if alg in hmac_cmds:
        cmd = hmac_cmds[alg]
        for tc in group.get("tests", []):
            got = client.call(cmd, hex_or_dash(tc["key"]), hex_or_dash(tc["msg"]))
            mac_len_hex = int(tc.get("macLen", len(tc["mac"]) * 4)) // 4
            if got[0] == "OK" and got[1][:mac_len_hex] == tc["mac"].lower():
                stats.record_pass()
            else:
                stats.record_fail(f"ACVP {alg} tcId={tc['tcId']} MAC mismatch")
        return
    for _ in group.get("tests", []):
        stats.record_skip()


def _eval_acvp_aes_gcm(client: HarnessClient, group: dict, stats: SuiteStats) -> None:
    key_bits = int(group.get("keyLen", 0))
    iv_bits = int(group.get("ivLen", 0))
    tag_bits = int(group.get("tagLen", 0))
    direction = group.get("direction", "")
    if key_bits not in (128, 256) or iv_bits != 96 or tag_bits != 128:
        for _ in group.get("tests", []):
            stats.record_skip()
        return
    prefix = "AES128_GCM" if key_bits == 128 else "AES256_GCM"
    for tc in group.get("tests", []):
        k, iv, aad = hex_or_dash(tc["key"]), hex_or_dash(tc["iv"]), hex_or_dash(tc.get("aad", ""))
        if direction == "encrypt":
            got = client.call(f"{prefix}_SEAL", k, iv, aad, hex_or_dash(tc["pt"]))
            if got[0] == "OK" and got[1] == hex_or_dash(tc["ct"]) and got[2] == hex_or_dash(tc["tag"]):
                stats.record_pass()
            else:
                stats.record_fail(f"ACVP AES-{key_bits}-GCM encrypt tcId={tc['tcId']} mismatch")
        else:
            got = client.call(f"{prefix}_OPEN", k, iv, aad, hex_or_dash(tc["ct"]), hex_or_dash(tc["tag"]))
            if tc.get("testPassed", True):
                if got[0] == "OK" and got[1] == hex_or_dash(tc["pt"]):
                    stats.record_pass()
                else:
                    stats.record_fail(f"ACVP AES-{key_bits}-GCM decrypt tcId={tc['tcId']} failed")
            elif got[0] == "FAIL":
                stats.record_pass()
            else:
                stats.record_fail(f"ACVP AES-{key_bits}-GCM decrypt tcId={tc['tcId']} accepted invalid")


def run_acvp_doc(client: HarnessClient, doc: dict | list, stats: SuiteStats) -> None:
    items = doc if isinstance(doc, list) else [doc]
    for item in items:
        alg = str(item.get("algorithm", ""))
        mode = str(item.get("mode", ""))
        for group in item.get("testGroups", []):
            if alg == "ML-KEM":
                _eval_acvp_mlkem(client, mode, group, stats)
            elif alg in ("SHA2-256", "SHA2-384", "SHA2-512", "HMAC-SHA2-256", "HMAC-SHA2-384"):
                _eval_acvp_hash_or_hmac(client, alg, group, stats)
            elif alg == "AES-GCM":
                _eval_acvp_aes_gcm(client, group, stats)
            else:
                for _ in group.get("tests", []):
                    stats.record_skip()


UPSTREAM_FETCH_URLS: dict[str, list[tuple[str, str]]] = {
    "wycheproof": [
        ("wycheproof/aes_gcm_test.json", "https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/aes_gcm_test.json"),
        ("wycheproof/chacha20_poly1305_test.json", "https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/chacha20_poly1305_test.json"),
        ("wycheproof/x25519_test.json", "https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/x25519_test.json"),
        ("wycheproof/ecdsa_secp256r1_sha256_test.json", "https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/ecdsa_secp256r1_sha256_test.json"),
        ("wycheproof/ecdsa_secp384r1_sha384_test.json", "https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/ecdsa_secp384r1_sha384_test.json"),
        ("wycheproof/ed25519_test.json", "https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/ed25519_test.json"),
        ("wycheproof/rsa_signature_2048_sha256_test.json", "https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/rsa_signature_2048_sha256_test.json"),
        ("wycheproof/rsa_pss_2048_sha256_mgf1_32_test.json", "https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/rsa_pss_2048_sha256_mgf1_32_test.json"),
        ("wycheproof/hkdf_sha256_test.json", "https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/hkdf_sha256_test.json"),
        ("wycheproof/hkdf_sha384_test.json", "https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/hkdf_sha384_test.json"),
        ("wycheproof/hmac_sha256_test.json", "https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/hmac_sha256_test.json"),
        ("wycheproof/hmac_sha384_test.json", "https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/hmac_sha384_test.json"),
    ],
    "cctv": [
        ("cctv/ML-KEM-768-modulus.txt", "https://raw.githubusercontent.com/C2SP/CCTV/main/ML-KEM/modulus/ML-KEM-768.txt"),
    ],
    "acvp": [
        ("acvp/mlkem_keygen_internalProjection.json", "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json"),
        ("acvp/mlkem_encapDecap_internalProjection.json", "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json"),
    ],
}


def fetch_upstream_corpora(dest: Path, suite: str) -> None:
    targets = ["wycheproof", "cctv", "acvp"] if suite == "all" else [suite]
    for name in targets:
        for rel, url in UPSTREAM_FETCH_URLS.get(name, []):
            out_path = dest / rel
            out_path.parent.mkdir(parents=True, exist_ok=True)
            print(f"[fetch] {url} -> {out_path}")
            req = urllib.request.Request(url, headers={"User-Agent": "goose-wing-crypto-vectors/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                out_path.write_bytes(resp.read())


def run_directory(client: HarnessClient, corpus_dir: Path, suite: str, stats: SuiteStats) -> None:
    for path in sorted(corpus_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix == ".txt" and "ml-kem-768" in path.name.lower() and suite in ("all", "cctv"):
            run_cctv_modulus_txt(client, path, stats)
            continue
        if path.suffix != ".json":
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        sample = data[0] if isinstance(data, list) and data else data
        if not isinstance(sample, dict):
            continue
        if "schema" in sample and suite in ("all", "wycheproof"):
            run_wycheproof_doc(client, data, stats)
        elif "vsId" in sample and suite in ("all", "acvp"):
            run_acvp_doc(client, data, stats)
        elif sample.get("suite") == "C2SP/CCTV" and suite in ("all", "cctv"):
            run_cctv_doc(client, sample, stats)


def run_docker(suite: str) -> int:
    tag = "goose-wing-crypto-vectors:local"
    build = subprocess.run(
        ["docker", "build", "-f", str(SUITE_DIR / "Dockerfile"), "-t", tag, str(ROOT_DIR)],
        cwd=ROOT_DIR,
    )
    if build.returncode != 0:
        return build.returncode
    run = subprocess.run(["docker", "run", "--rm", tag, "--local", "--suite", suite], cwd=ROOT_DIR)
    return run.returncode


def main() -> None:
    parser = argparse.ArgumentParser(description="goose-wing Wycheproof / CCTV / ACVP vector runner")
    parser.add_argument("--suite", choices=["all", "wycheproof", "cctv", "acvp"], default="all")
    parser.add_argument("--local", action="store_true", help="Run curated offline adversarial vectors")
    parser.add_argument("--dir", type=Path, default=None, help="Directory of downloaded upstream corpora")
    parser.add_argument("--fetch", action="store_true", help="Download official upstream JSON corpora")
    parser.add_argument("--docker", action="store_true", help="Build and run inside Docker container")
    args = parser.parse_args()

    if args.docker:
        sys.exit(run_docker(args.suite))
    if args.fetch:
        fetch_dir = args.dir or (CACHE_DIR / "upstream")
        fetch_upstream_corpora(fetch_dir, args.suite)
        if not args.local and args.dir is None:
            print(f"[crypto_vectors] Downloaded upstream corpora to {fetch_dir}")
            sys.exit(0)

    exe = build_harness()
    stats = SuiteStats()
    client = HarnessClient(exe)
    try:
        if args.dir is not None:
            run_directory(client, args.dir, args.suite, stats)
        else:
            if args.suite in ("all", "wycheproof"):
                run_wycheproof_doc(client, json.loads((SUITE_DIR / "vectors_wycheproof.json").read_text(encoding="utf-8")), stats)
            if args.suite in ("all", "cctv"):
                run_cctv_doc(client, json.loads((SUITE_DIR / "vectors_cctv.json").read_text(encoding="utf-8")), stats)
            if args.suite in ("all", "acvp"):
                run_acvp_doc(client, json.loads((SUITE_DIR / "vectors_acvp.json").read_text(encoding="utf-8")), stats)
    finally:
        client.close()

    for fail in stats.failures or []:
        print(f"FAIL: {fail}", file=sys.stderr)
    print(f"[crypto_vectors] suite={args.suite} passed={stats.passed} failed={stats.failed} skipped={stats.skipped}")
    sys.exit(0 if stats.failed == 0 and stats.passed > 0 else 1)


if __name__ == "__main__":
    main()
