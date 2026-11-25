#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""scripts/diff_fuzz.py.

Differential fuzzing and Google Wycheproof cross-implementation oracle suite for goose-wing.
Compares SHA-256/384/512, HMAC-SHA256/384/512, HKDF-SHA256/384 (RFC 5869),
ChaCha20-Poly1305 (RFC 8439), XChaCha20-Poly1305, AES-128/256-GCM (NIST SP 800-38D),
X25519 (RFC 7748), Ed25519 (RFC 8032), Deflate (RFC 1951), Zlib (RFC 1950),
Gzip (RFC 1952), Base64 / Base64URL (RFC 4648), and HTTP/1.1 request framing (RFC 9112)
against external reference implementations and official Wycheproof JSON test vectors.
"""

import argparse
import base64
import gzip
import hashlib
import hmac
import json
import os
import random
import subprocess
import sys
import zlib
from pathlib import Path

VectorTuple = tuple[str, list[bytes], str]


def build_oracle(root: Path, cc: str) -> Path:
    cache_dir = root / ".lit" / "cache" / "fuzz"
    cache_dir.mkdir(parents=True, exist_ok=True)
    exe_name = "diff_oracle.exe" if os.name == "nt" else "diff_oracle"
    exe_path = cache_dir / exe_name
    src_path = root / "tests" / "fuzz" / "diff_oracle.goose"

    cmd = ["goose", "build", "--cc", cc, "-O2", "-o", str(exe_path), str(src_path)]
    res = subprocess.run(cmd, cwd=root, capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(f"Failed to build diff_oracle:\n{res.stdout}\n{res.stderr}\n")
        raise RuntimeError("diff_oracle build failed")
    return exe_path


def hkdf_reference(hash_ctor, ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    hash_len = hash_ctor().digest_size
    actual_salt = salt if salt else (b"\x00" * hash_len)
    prk = hmac.new(actual_salt, ikm, hash_ctor).digest()
    okm = bytearray()
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hash_ctor).digest()
        okm.extend(t)
        counter += 1
    return bytes(okm[:length])


def raw_deflate_compress(data: bytes, level: int = 6) -> bytes:
    comp = zlib.compressobj(level, zlib.DEFLATED, -15)
    return comp.compress(data) + comp.flush()


def load_wycheproof_vectors(wycheproof_dir: Path) -> list[VectorTuple]:
    vectors: list[VectorTuple] = []
    if not wycheproof_dir.exists():
        return vectors

    # 1. ChaCha20-Poly1305 (RFC 8439)
    chacha_file = wycheproof_dir / "chacha20_poly1305_test.json"
    if chacha_file.exists():
        doc = json.loads(chacha_file.read_text(encoding="utf-8"))
        for group in doc.get("testGroups", []):
            if (
                group.get("ivSize") != 96
                or group.get("keySize") != 256
                or group.get("tagSize") != 128
            ):
                continue
            for tc in group.get("tests", []):
                key = bytes.fromhex(tc["key"])
                iv = bytes.fromhex(tc["iv"])
                aad = bytes.fromhex(tc["aad"])
                msg = bytes.fromhex(tc["msg"])
                ct = bytes.fromhex(tc["ct"])
                tag = bytes.fromhex(tc["tag"])
                valid = tc["result"] in ("valid", "acceptable")
                exp_open = (f"OK {msg.hex()}" if msg else "OK") if valid else "ERR"
                vectors.append(("chacha20_open", [key + iv, aad, ct + tag], exp_open))
                if valid:
                    vectors.append(
                        ("chacha20_seal", [key + iv, aad, msg], f"OK {(ct + tag).hex()}")
                    )

    # 2. XChaCha20-Poly1305
    xchacha_file = wycheproof_dir / "xchacha20_poly1305_test.json"
    if xchacha_file.exists():
        doc = json.loads(xchacha_file.read_text(encoding="utf-8"))
        for group in doc.get("testGroups", []):
            if (
                group.get("ivSize") != 192
                or group.get("keySize") != 256
                or group.get("tagSize") != 128
            ):
                continue
            for tc in group.get("tests", []):
                key = bytes.fromhex(tc["key"])
                iv = bytes.fromhex(tc["iv"])
                aad = bytes.fromhex(tc["aad"])
                msg = bytes.fromhex(tc["msg"])
                ct = bytes.fromhex(tc["ct"])
                tag = bytes.fromhex(tc["tag"])
                valid = tc["result"] in ("valid", "acceptable")
                exp_open = (f"OK {msg.hex()}" if msg else "OK") if valid else "ERR"
                vectors.append(("xchacha20_open", [key + iv, aad, ct + tag], exp_open))

    # 3. AES-128-GCM and AES-256-GCM (NIST SP 800-38D)
    aes_gcm_file = wycheproof_dir / "aes_gcm_test.json"
    if aes_gcm_file.exists():
        doc = json.loads(aes_gcm_file.read_text(encoding="utf-8"))
        for group in doc.get("testGroups", []):
            if group.get("ivSize") != 96 or group.get("tagSize") != 128:
                continue
            ksize = group.get("keySize")
            if ksize not in (128, 256):
                continue
            open_op = "aes128_gcm_open" if ksize == 128 else "aes256_gcm_open"
            seal_op = "aes128_gcm_seal" if ksize == 128 else "aes256_gcm_seal"
            for tc in group.get("tests", []):
                key = bytes.fromhex(tc["key"])
                iv = bytes.fromhex(tc["iv"])
                aad = bytes.fromhex(tc["aad"])
                msg = bytes.fromhex(tc["msg"])
                ct = bytes.fromhex(tc["ct"])
                tag = bytes.fromhex(tc["tag"])
                valid = tc["result"] in ("valid", "acceptable")
                exp_open = (f"OK {msg.hex()}" if msg else "OK") if valid else "ERR"
                vectors.append((open_op, [key + iv, aad, ct + tag], exp_open))
                if valid:
                    vectors.append((seal_op, [key + iv, aad, msg], f"OK {(ct + tag).hex()}"))

    # 4. X25519 (RFC 7748)
    x25519_file = wycheproof_dir / "x25519_test.json"
    if x25519_file.exists():
        doc = json.loads(x25519_file.read_text(encoding="utf-8"))
        for group in doc.get("testGroups", []):
            if group.get("curve") != "curve25519":
                continue
            for tc in group.get("tests", []):
                priv = bytes.fromhex(tc["private"])
                pub = bytes.fromhex(tc["public"])
                shared = bytes.fromhex(tc["shared"])
                if len(priv) == 32 and len(pub) == 32 and len(shared) == 32:
                    vectors.append(("x25519", [priv, pub], f"OK {shared.hex()}"))

    # 5. Ed25519 (RFC 8032)
    ed25519_file = wycheproof_dir / "ed25519_test.json"
    if ed25519_file.exists():
        doc = json.loads(ed25519_file.read_text(encoding="utf-8"))
        for group in doc.get("testGroups", []):
            pk_hex = group.get("publicKey", {}).get("pk", "")
            pk = bytes.fromhex(pk_hex)
            for tc in group.get("tests", []):
                if tc["result"] == "acceptable":
                    continue
                msg = bytes.fromhex(tc["msg"])
                sig = bytes.fromhex(tc["sig"])
                valid = tc["result"] == "valid"
                vectors.append(("ed25519_verify", [pk, msg, sig], "OK" if valid else "ERR"))

    # 6. HKDF-SHA256 and HKDF-SHA384 (RFC 5869)
    for hkdf_op, fname in (
        ("hkdf_sha256", "hkdf_sha256_test.json"),
        ("hkdf_sha384", "hkdf_sha384_test.json"),
    ):
        hkdf_file = wycheproof_dir / fname
        if not hkdf_file.exists():
            continue
        doc = json.loads(hkdf_file.read_text(encoding="utf-8"))
        for group in doc.get("testGroups", []):
            for tc in group.get("tests", []):
                ikm = bytes.fromhex(tc["ikm"])
                salt = bytes.fromhex(tc["salt"])
                info = bytes.fromhex(tc["info"])
                size = int(tc["size"])
                if size < 0 or size > 16384:
                    continue
                len_be = size.to_bytes(2, "big")
                valid = tc["result"] in ("valid", "acceptable")
                okm = bytes.fromhex(tc["okm"])
                exp = (f"OK {okm.hex()}" if okm else "OK") if valid else "ERR"
                vectors.append((hkdf_op, [ikm, salt, len_be + info], exp))

    # 7. ECDSA P-256 and P-384 (DER and IEEE P1363)
    for ecdsa_op, fname in (
        ("ecdsa_p256_verify", "ecdsa_secp256r1_sha256_test.json"),
        ("ecdsa_p256_verify", "ecdsa_secp256r1_sha256_p1363_test.json"),
        ("ecdsa_p384_verify", "ecdsa_secp384r1_sha384_test.json"),
        ("ecdsa_p384_verify", "ecdsa_secp384r1_sha384_p1363_test.json"),
    ):
        ec_file = wycheproof_dir / fname
        if not ec_file.exists():
            continue
        doc = json.loads(ec_file.read_text(encoding="utf-8"))
        for group in doc.get("testGroups", []):
            pub = bytes.fromhex(group.get("publicKey", {}).get("uncompressed", ""))
            if not pub:
                continue
            for tc in group.get("tests", []):
                if tc["result"] == "acceptable":
                    continue
                msg = bytes.fromhex(tc["msg"])
                sig = bytes.fromhex(tc["sig"])
                vectors.append((ecdsa_op, [pub, msg, sig], "OK" if tc["result"] == "valid" else "ERR"))

    # 8. RSA PKCS#1 v1.5 and RSASSA-PSS verification
    rsa_files = (
        ("rsa_pkcs1_sha256_verify", "rsa_signature_2048_sha256_test.json"),
        ("rsa_pkcs1_sha384_verify", "rsa_signature_2048_sha384_test.json"),
        ("rsa_pkcs1_sha256_verify", "rsa_signature_3072_sha256_test.json"),
        ("rsa_pkcs1_sha384_verify", "rsa_signature_3072_sha384_test.json"),
        ("rsa_pkcs1_sha256_verify", "rsa_signature_4096_sha256_test.json"),
        ("rsa_pkcs1_sha384_verify", "rsa_signature_4096_sha384_test.json"),
        ("rsa_pss_sha256_verify", "rsa_pss_2048_sha256_mgf1_32_test.json"),
        ("rsa_pss_sha384_verify", "rsa_pss_2048_sha384_mgf1_48_test.json"),
        ("rsa_pss_sha256_verify", "rsa_pss_3072_sha256_mgf1_32_test.json"),
        ("rsa_pss_sha256_verify", "rsa_pss_4096_sha256_mgf1_32_test.json"),
        ("rsa_pss_sha384_verify", "rsa_pss_4096_sha384_mgf1_48_test.json"),
        ("rsa_pss_sha512_verify", "rsa_pss_4096_sha512_mgf1_64_test.json"),
    )
    for rsa_op, fname in rsa_files:
        rsa_file = wycheproof_dir / fname
        if not rsa_file.exists():
            continue
        doc = json.loads(rsa_file.read_text(encoding="utf-8"))
        for group in doc.get("testGroups", []):
            pk = group.get("publicKey", {})
            n_be = bytes.fromhex(pk.get("modulus", "")).lstrip(b"\x00")
            e_be = bytes.fromhex(pk.get("publicExponent", "")).lstrip(b"\x00")
            if not n_be or not e_be or len(n_be) > 512:
                continue
            packed_ne = len(n_be).to_bytes(2, "big") + n_be + e_be
            for tc in group.get("tests", []):
                if tc["result"] == "acceptable":
                    continue
                msg = bytes.fromhex(tc["msg"])
                sig = bytes.fromhex(tc["sig"])
                if len(msg) > 8192 or len(sig) > 8192:
                    continue
                vectors.append((rsa_op, [packed_ne, msg, sig], "OK" if tc["result"] == "valid" else "ERR"))

    # 9. ML-KEM-768 (FIPS 203)
    mlkem_file = wycheproof_dir / "mlkem_768_test.json"
    if mlkem_file.exists():
        doc = json.loads(mlkem_file.read_text(encoding="utf-8"))
        for group in doc.get("testGroups", []):
            gtype = group.get("type", "")
            for tc in group.get("tests", []):
                if gtype == "MLKEMTest" and tc["result"] == "valid":
                    seed = bytes.fromhex(tc["seed"])
                    ek = bytes.fromhex(tc["ek"])
                    ct = bytes.fromhex(tc["c"])
                    ss = bytes.fromhex(tc["K"])
                    vectors.append(("mlkem768_keygen_decaps", [seed, ct], f"OK {(ek + ss).hex()}"))
                elif gtype == "MLKEMEncapsTest":
                    ek = bytes.fromhex(tc["ek"])
                    m = bytes.fromhex(tc["m"])
                    if tc["result"] == "invalid":
                        vectors.append(("mlkem768_encaps", [ek, m], "ERR"))
                    elif tc["result"] == "valid":
                        ct = bytes.fromhex(tc["c"])
                        ss = bytes.fromhex(tc["K"])
                        vectors.append(("mlkem768_encaps", [ek, m], f"OK {(ct + ss).hex()}"))

    return vectors


def generate_vectors(
    rng: random.Random, rounds: int, wycheproof_dir: Path
) -> tuple[list[VectorTuple], int]:
    vectors: list[VectorTuple] = []

    boundary_lengths = [
        0,
        1,
        2,
        3,
        4,
        15,
        16,
        31,
        32,
        55,
        56,
        57,
        63,
        64,
        65,
        111,
        112,
        113,
        127,
        128,
        129,
        255,
        256,
        512,
        1024,
        4096,
    ]

    payloads: list[bytes] = [b""]
    for length in boundary_lengths:
        if length > 0:
            payloads.append(rng.randbytes(length))
    payloads.append(b"A" * 300)
    payloads.append(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n" * 40)
    payloads.append(bytes(range(256)) * 8)

    for _ in range(rounds):
        payloads.append(rng.randbytes(rng.randint(0, 1500)))

    for data in payloads:
        vectors.append(("sha256", [data], f"OK {hashlib.sha256(data).hexdigest()}"))
        vectors.append(("sha384", [data], f"OK {hashlib.sha384(data).hexdigest()}"))
        vectors.append(("sha512", [data], f"OK {hashlib.sha512(data).hexdigest()}"))

        key = rng.randbytes(rng.choice([0, 1, 16, 32, 64, 65, 128, 129, 200]))
        mac256 = hmac.new(key, data, hashlib.sha256).hexdigest()
        mac384 = hmac.new(key, data, hashlib.sha384).hexdigest()
        mac512 = hmac.new(key, data, hashlib.sha512).hexdigest()
        vectors.append(("hmac_sha256", [key, data], f"OK {mac256}"))
        vectors.append(("hmac_sha384", [key, data], f"OK {mac384}"))
        vectors.append(("hmac_sha512", [key, data], f"OK {mac512}"))

        if len(data) <= 256:
            salt = rng.randbytes(rng.choice([0, 16, 32]))
            info = rng.randbytes(rng.choice([0, 8, 24]))
            out_sz = rng.choice([16, 32, 42, 64, 96])
            okm256 = hkdf_reference(hashlib.sha256, data if data else b"\x0b", salt, info, out_sz)
            okm384 = hkdf_reference(hashlib.sha384, data if data else b"\x0b", salt, info, out_sz)
            len_be = out_sz.to_bytes(2, "big")
            vectors.append(
                (
                    "hkdf_sha256",
                    [data if data else b"\x0b", salt, len_be + info],
                    f"OK {okm256.hex()}",
                )
            )
            vectors.append(
                (
                    "hkdf_sha384",
                    [data if data else b"\x0b", salt, len_be + info],
                    f"OK {okm384.hex()}",
                )
            )

        expected_data = f"OK {data.hex()}" if data else "OK"

        # Reference Zlib -> goose-wing zlib_decompress
        for level in (0, 1, 6, 9):
            z_comp = zlib.compress(data, level=level)
            vectors.append(("zlib_decompress", [z_comp], expected_data))

        # goose-wing zlib_compress -> Reference Zlib decompress
        vectors.append(("zlib_compress", [data], "VERIFY_ZLIB_COMPRESS"))

        # Reference Raw Deflate -> goose-wing deflate_decompress
        def_comp = raw_deflate_compress(data, level=6)
        vectors.append(("deflate_decompress", [def_comp], expected_data))

        # goose-wing deflate_compress -> Reference Raw Deflate decompress
        vectors.append(("deflate_compress", [data], "VERIFY_DEFLATE_COMPRESS"))

        # Reference Gzip -> goose-wing gzip_decompress
        gz_comp = gzip.compress(data, compresslevel=6)
        vectors.append(("gzip_decompress", [gz_comp], expected_data))

        # goose-wing gzip_compress -> Reference Gzip decompress
        vectors.append(("gzip_compress", [data], "VERIFY_GZIP_COMPRESS"))

        # Base64 & Base64URL
        b64_std = base64.b64encode(data)
        b64_url = base64.urlsafe_b64encode(data).rstrip(b"=")
        vectors.append(("b64_encode", [data], f"OK {b64_std.hex()}" if b64_std else "OK"))
        vectors.append(("b64_decode", [b64_std], expected_data))
        vectors.append(("b64url_encode", [data], f"OK {b64_url.hex()}" if b64_url else "OK"))
        vectors.append(("b64url_decode", [b64_url], expected_data))

    # Corrupted Zlib / Gzip / Deflate streams (must return ERR on both sides)
    for _ in range(40):
        raw = rng.randbytes(rng.randint(1, 128))
        try:
            zlib.decompress(raw)
        except zlib.error:
            vectors.append(("zlib_decompress", [raw], "ERR"))
        try:
            gzip.decompress(raw)
        except Exception:
            vectors.append(("gzip_decompress", [raw], "ERR"))

    # HTTP/1.1 request framing oracle vectors
    http_cases = [
        (
            b"GET /api/v1/health HTTP/1.1\r\nHost: example.com\r\n\r\n",
            f"OK GET {b'/api/v1/health'.hex()} 1 0 0",
        ),
        (
            b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello",
            f"OK POST {b'/submit'.hex()} 1 5 0",
        ),
        (
            b"PUT /stream HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nworld\r\n0\r\n\r\n",
            f"OK PUT {b'/stream'.hex()} 1 5 1",
        ),
        (
            b"POST /smuggle HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "ERR",
        ),
        (
            b"GET /no-host HTTP/1.1\r\nUser-Agent: test\r\n\r\n",
            "ERR",
        ),
    ]
    for raw_req, expected in http_cases:
        vectors.append(("http1_req", [raw_req], expected))

    wycheproof_vecs = load_wycheproof_vectors(wycheproof_dir)
    vectors.extend(wycheproof_vecs)
    return vectors, len(wycheproof_vecs)


def main() -> int:
    parser = argparse.ArgumentParser(description="Differential fuzzing oracle for goose-wing")
    parser.add_argument("--cc", default="gcc", help="C compiler")
    parser.add_argument("--rounds", type=int, default=50, help="Additional random payload rounds")
    parser.add_argument("--seed", type=int, default=0x5EED2026, help="PRNG seed")
    parser.add_argument(
        "--wycheproof-dir",
        default="",
        help="Optional path to Google Wycheproof JSON testvectors directory",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    try:
        oracle_exe = build_oracle(root, args.cc)
    except RuntimeError:
        return 1

    wp_dir = (
        Path(args.wycheproof_dir)
        if args.wycheproof_dir
        else (
            root
            / "vendor"
            / "uWebSockets"
            / "uSockets"
            / "boringssl"
            / "third_party"
            / "wycheproof_testvectors"
        )
    )

    rng = random.Random(args.seed)
    vectors, wp_count = generate_vectors(rng, args.rounds, wp_dir)

    cache_dir = root / ".lit" / "cache" / "fuzz"
    input_file = cache_dir / "diff_vectors.txt"
    with input_file.open("w", encoding="utf-8") as f:
        for op, arg_list, _ in vectors:
            joined = ":".join(a.hex() for a in arg_list)
            f.write(f"{op} {joined}\n")

    res = subprocess.run(
        [str(oracle_exe), str(input_file)],
        cwd=root,
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        sys.stderr.write(f"diff_oracle execution failed:\n{res.stdout}\n{res.stderr}\n")
        return 1

    lines = [line.strip() for line in res.stdout.splitlines() if line.strip()]
    if len(lines) != len(vectors):
        sys.stderr.write(f"Line count mismatch: expected {len(vectors)}, got {len(lines)}\n")
        return 1

    mismatches = 0
    for idx, ((op, arg_list, expected), actual) in enumerate(zip(vectors, lines, strict=True)):
        arg1 = arg_list[0]
        if expected == "VERIFY_ZLIB_COMPRESS":
            if not actual.startswith("OK "):
                sys.stderr.write(f"[{idx}] {op} failed: {actual}\n")
                mismatches += 1
                continue
            comp_bytes = bytes.fromhex(actual[3:])
            if zlib.decompress(comp_bytes) != arg1:
                sys.stderr.write(f"[{idx}] {op} roundtrip mismatch (len {len(arg1)})\n")
                mismatches += 1
        elif expected == "VERIFY_DEFLATE_COMPRESS":
            if not actual.startswith("OK "):
                sys.stderr.write(f"[{idx}] {op} failed: {actual}\n")
                mismatches += 1
                continue
            comp_bytes = bytes.fromhex(actual[3:])
            if zlib.decompress(comp_bytes, -15) != arg1:
                sys.stderr.write(f"[{idx}] {op} roundtrip mismatch (len {len(arg1)})\n")
                mismatches += 1
        elif expected == "VERIFY_GZIP_COMPRESS":
            if not actual.startswith("OK "):
                sys.stderr.write(f"[{idx}] {op} failed: {actual}\n")
                mismatches += 1
                continue
            comp_bytes = bytes.fromhex(actual[3:])
            if gzip.decompress(comp_bytes) != arg1:
                sys.stderr.write(f"[{idx}] {op} roundtrip mismatch (len {len(arg1)})\n")
                mismatches += 1
        else:
            if actual != expected:
                sys.stderr.write(
                    f"[{idx}] {op} mismatch:\n  expected: {expected}\n  actual:   {actual}\n"
                )
                mismatches += 1

    if mismatches > 0:
        sys.stderr.write(
            f"FAILED: {mismatches} differential oracle mismatches out of {len(vectors)}\n"
        )
        return 1

    print(f"OK DIFF_ORACLE_VECTORS: {len(vectors)} WYCHEPROOF_VECTORS: {wp_count} MISMATCHES: 0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
