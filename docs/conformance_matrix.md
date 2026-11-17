# External conformance matrix

This document records reproducible execution metrics and verification commands
for external protocol conformance suites and cryptographic oracles evaluated
against [goose-wing](../README.md).

## External conformance summary

| Suite | Target standard | Total cases | Passed | Failed | Compliance | Driver command |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| h2spec | RFC 9113 / RFC 7540 | 145 (146 strict) | 145 (146 strict) | 0 | 100.0% | `python tools/h2spec.py all` |
| Autobahn WebSocket | RFC 6455 | 301 | 293 (5 non-strict, 3 info) | 0 | 100.0% | `python tools/autobahn.py` |
| Project Wycheproof | RFC 8439, RFC 8446, NIST SP 800-38D | 5,761 vectors (6,829 oracle runs) | 5,761 | 0 | 100.0% (0 mismatches) | `python scripts/diff_fuzz.py --rounds 20` |
| QPACK differential (nghttp3) | RFC 9204 | 185 (plus quiche check) | 185 | 0 | 100.0% | `python scripts/qpack_differential.py` |
| H2 + TLS 1.3 differential (Go) | RFC 8446 / RFC 9113 | 13 Go/Wing (incl. 1-byte frag) | 13 | 0 | 100.0% (4 OpenSSL checks target Go h1) | `python scripts/h2_tls_differential.py -v` |
| Curated BoGo & x509-limbo | RFC 8446, RFC 5280, RFC 6125 | 13 curated LIT checks | 13 | 0 | 100.0% of subset | `goose-lit tests/lit/verify_bogo_x509_limbo.goose` |

---

## 1. HTTP/2 conformance (h2spec)

The HTTP/2 conformance suite executes `tools/bin/h2spec.exe` against the native
server compiled from [tools/h2spec/server.goose](../tools/h2spec/server.goose)
via [tools/h2spec.py](../tools/h2spec.py).

```bash
python tools/h2spec.py all
# Strict mode:
python tools/h2spec.py -S all
```

- Standard test run: 145 tests, 145 passed, 0 skipped, 0 failed (100.0%).
- Strict mode test run (`-S`): 146 tests, 146 passed, 0 skipped, 0 failed
  (100.0%).
- Execution duration: ~0.53 seconds.

Verified specification sections:

- Starting HTTP/2: client connection preface validation (RFC 9113 §3.4 / RFC
  7540 §3.5), including immediate TCP termination on invalid connection preface
  (`INVALID CONNECTION PREFACE\r\n\r\n`).
- Streams and multiplexing: PRIORITY, WINDOW_UPDATE, and RST_STREAM frames on
  idle, half-closed, and closed streams (RFC 9113 §5.1).
- Frame definitions: DATA (RFC 9113 §6.1), HEADERS (RFC 9113 §6.2), PRIORITY
  (RFC 9113 §6.3), RST_STREAM (RFC 9113 §6.4), SETTINGS (RFC 9113 §6.5,
  `SETTINGS_MAX_HEADER_LIST_SIZE = 16384`), PING (RFC 9113 §6.7), GOAWAY (RFC
  9113 §6.8), WINDOW_UPDATE (RFC 9113 §6.9), and CONTINUATION reassembly with
  `continuation_stream_id` reset on `END_HEADERS` (RFC 9113 §6.10).
- HTTP message exchanges: GET, HEAD, POST requests, and chunked trailers.
- HPACK compression: indexed representations, literal fields with incremental
  indexing, Huffman coding, and dynamic table size updates (RFC 7541 §2, §4, §5,
  §6).

---

## 2. WebSocket conformance (Autobahn testsuite)

The WebSocket conformance suite executes `tools/bin/kosoku.exe` against the
native server compiled from
[tools/autobahn/server.goose](../tools/autobahn/server.goose) via
[tools/autobahn.py](../tools/autobahn.py).

```bash
python tools/autobahn.py
```

- Total cases executed: 301.
- Test outcomes: 293 passed, 5 non-strict, 3 informational, 0 failed (100.0% RFC
  6455 core compliance).

| Category | Description | Cases | Outcome |
| :--- | :--- | :--- | :--- |
| Category 1 | Framing basics (payload sizes from 0 B to 1 MB) | 16/16 | 100% OK |
| Category 2 | Pings and Pongs | 11/11 | 100% OK |
| Category 3 | Reserved bits (RSV1..3 rejection) | 7/7 | 100% OK |
| Category 4 | Opcodes (control and non-control handling) | 10/10 | 100% OK |
| Category 5 | Message fragmentation | 20/20 | 100% OK |
| Category 6 | UTF-8 validation (RFC 3629 boundary cases) | 145/145 | 100% OK |
| Category 7 | Close handshake (RFC 6455 §7.4 status codes) | 37/37 | 100% OK |
| Category 9 | Frame size limits and performance | 54/54 | 100% OK |
| Category 10 | Miscellaneous | 1/1 | 100% OK |

---

## 3. Cryptographic differential fuzzing (Project Wycheproof)

Cryptographic primitives and wire codecs in `core/crypto` and `wing/tls` are
cross-checked against Project Wycheproof test vectors and reference
implementations using [scripts/diff_fuzz.py](../scripts/diff_fuzz.py).

```bash
python scripts/diff_fuzz.py --rounds 20
```

- Total differential oracle vectors executed: 6,829.
- Total Project Wycheproof test vectors executed: 5,761.
- Observed mismatches: 0.

Verified cryptographic domains:

- Hash and digest functions: SHA-256, SHA-384, SHA-512, and HMAC.
- Key derivation: HKDF-Extract and HKDF-Expand (RFC 5869).
- Authenticated ciphers (AEAD): ChaCha20-Poly1305 (RFC 8439),
  XChaCha20-Poly1305, AES-128-GCM, and AES-256-GCM (NIST SP 800-38D).
- Asymmetric primitives and signatures: X25519 (RFC 7748), Ed25519 (RFC 8032),
  ECDSA P-256, ECDSA P-384, RSA PKCS#1 v1.5, and RSASSA-PSS.
- Post-quantum key encapsulation: ML-KEM-768 (FIPS 203 draft).
- Wire codecs and compression: Deflate (RFC 1951), Zlib (RFC 1950), Gzip (RFC
  1952), and Base64/Base64url (RFC 4648).

---

## 4. Curated BoGo TLS 1.3 and x509-limbo checks

Negative security vectors modeled after BoringSSL BoGo TLS 1.3 invariants and
Trail of Bits x509-limbo certificate edge cases are verified via
[tests/lit/verify_bogo_x509_limbo.goose](../tests/lit/verify_bogo_x509_limbo.goose).
These represent a curated 13-check regression subset inside the LIT suite rather
than the full external Go/Python BoGo or upstream x509-limbo corpus.

```bash
goose-lit tests/lit/verify_bogo_x509_limbo.goose
```

- Suites executed: 1/1 passed (100.0%).
- Curated checks: 13/13 passed (100.0% of the LIT subset).

Verified security categories:

1. BoGo TLS 1.3 CCS flood rejection: middlebox compatibility CCS payload must be
   exactly 1 byte (`0x01`); malformed or repeated records abort.
2. BoGo sequence number exhaustion: TLS 1.3 record sequence counter bounds
   checked; connection terminates before $2^{64}-1$ wrap-around.
3. BoGo inner plaintext validation: reject all-zero `TLSInnerPlaintext` missing
   valid content-type indicator.
4. BoGo downgrade sentinel detection: server rejects embedded downgrade
   sentinels in `ServerHello.random`.
5. BoGo duplicate extension rejection: handshake rejects ClientHello or
   EncryptedExtensions containing repeated extension types.
6. BoGo forbidden extensions in EncryptedExtensions: Early Data, Key Share, or
   Cookie extensions inside EncryptedExtensions trigger decode error.
7. BoGo SignatureScheme binding: certificates validate signature algorithms
   strictly against negotiated SignatureScheme parameters.
8. x509-limbo single-label wildcard rules: RFC 6125 §6.4.3 wildcard `*` matches
   one domain label; multi-label matches rejected.
9. x509-limbo embedded NUL rejection: ASN.1 string fields containing `\x00`
   characters rejected immediately to prevent truncation bypasses.
10. x509-limbo indefinite length rejection: BER indefinite length encodings
    rejected under strict DER parsing rules.
11. x509-limbo unsupported critical extensions: reject certificates with
    unrecognized critical extension OIDs.
12. x509-limbo validity boundary enforcement: time comparisons enforce
    `notBefore` and `notAfter` boundaries.
13. x509-limbo basic constraints enforcement: end-entity leaf certificate
    attempting to sign subordinate certificates rejected.

---

## 5. Cross-project wire differential oracles (QPACK and TLS 1.3 / HTTP/2)

- QPACK against `vendor/nghttp3` and `vendor/quiche` compile check via
  [scripts/qpack_differential.py](../scripts/qpack_differential.py):
  - Wing to `nghttp3` (Huffman): 60/60 passed.
  - Wing to `nghttp3` (Raw): 60/60 passed.
  - `nghttp3` to Wing (Encode and decode): 60/60 passed.
  - Malformed wire negative vectors: 5/5 passed.
  - Total matched: 185/185; `vendor/quiche` verified via
    `cargo check --offline --no-default-features` (wire roundtrip against quiche
    is not yet automated in the Python oracle).
- TLS 1.3 + HTTP/2 differential oracle via
  [scripts/h2_tls_differential.py](../scripts/h2_tls_differential.py):
  - Wing client vs Go `net/http` / `net/http2` server: 13/13 passed, including
    live 1-byte TCP record fragmentation (`h2_1byte_frag`) across the proxy.
  - Note on OpenSSL interactive scenarios: the 4 `openssl_*` checks now connect
    `openssl s_client` to Go `h2oracle`'s `h1_port` rather than Wing's
    `serve_tls` endpoint, so live OpenSSL server-side testing of Wing remains an
    open follow-up item.
