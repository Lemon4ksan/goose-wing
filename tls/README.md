# `tls`

Zero-allocation TLS 1.3 cryptographic record layer (RFC 8446), X.509 PKI certificate validation (RFC 5280), Encrypted Client Hello (ECH, RFC 9849), Hybrid Post-Quantum Key Exchange (FIPS 203), and Certificate Compression (RFC 8879).

## Public API

### TLS Record Layer & Alert Protocol (`record.goose`, RFC 8446 §5)

- **`enum TlsAlert`**: TLS alert codes (`CloseNotify`, `UnexpectedMessage`, `BadRecordMac`, `RecordOverflow`, `HandshakeFailure`, `BadCertificate`, `UnsupportedCertificate`, `CertificateRevoked`, `CertificateExpired`, `CertificateUnknown`, `IllegalParameter`, `UnknownCa`, `AccessDenied`, `DecodeError`).
- **`fn tls_alert_to_u8(alert: TlsAlert) -> u8`**: Maps typed `TlsAlert` to wire byte code.
- **`fn u8_to_tls_alert(code: u8) -> TlsAlert, bool`**: Validates and maps wire alert byte to typed `TlsAlert`.
- **`fn compute_record_nonce(iv: const u8[12]&, seq_num: u64) -> u8[12], bool`**: Derives RFC 8446 §5.3 per-record 96-bit nonce (`iv ^ seq_num`), rejecting $2^{64}-1$ to defend against counter overflow.
- **`fn increment_record_seq_num(seq_num: u64&) -> bool`**: Monotonically increments record sequence number.
- **`fn unpack_tls_inner_plaintext(decrypted: const u8[:]) -> const u8[:], u8, TlsAlert`**: Constant-time trailer scan removing zero-padding and extracting true inner `ContentType`.
- **`fn tls_record_decrypt_aes128_gcm(key: const u8[16]&, iv: const u8[12]&, seq_num: u64, record_header: const u8[:], record_payload: const u8[:], out_plaintext: u8[>..]&) -> u8, TlsAlert`**: Decrypts and authenticates an AES-128-GCM record with zero-leakage memory wiping on MAC failure.

### Key Schedule & Transcript Cryptography (`key_schedule.goose`, RFC 8446 §7)

- **`fn hkdf_extract(salt: const u8[:], ikm: const u8[:]) -> u8[32]`**: HMAC-SHA256 HKDF-Extract.
- **`fn hkdf_expand_label(secret: const u8[32]&, label: const u8[:], context: const u8[:], out_len: u16) -> u8[32]`**: RFC 8446 §7.1 labeled HKDF-Expand.
- **`fn derive_secret(secret: const u8[32]&, label: const u8[:], transcript_hash: const u8[32]&) -> u8[32]`**: Computes phase-specific secret from transcript hash.

### X.509 PKI & Hostname Verification (`x509.goose`, RFC 5280, RFC 6125)

- **`struct X509Certificate`**: Parsed certificate holding serial, subject, issuer, validity window, public key, and SAN entries.
- **`struct CertStore`**: Collection of trusted root trust anchors.
- **`fn parse_x509_certificate(der: const u8[:], out_cert: X509Certificate&) -> bool`**: Strict ASN.1 DER parser for X.509 v3 certificates.
- **`fn verify_certificate_chain(chain: const X509Certificate[:], store: const CertStore&, hostname: const u8[:], now_sec: i64) -> bool`**: Validates certificate chain signatures, path constraints, expiration, and RFC 6125 SAN matching.

### Hybrid Post-Quantum Key Exchange (`post_quantum.goose`, FIPS 203 / RFC 10024)

- **`struct PostQuantumKeyShare`**: Hybrid ephemeral client key share combining classical ECDH (X25519, P-256, P-384) with ML-KEM (Kyber768/1024).
- **`struct PostQuantumServerShare`**: Hybrid server response ciphertext and ephemeral public key.
- **`fn generate_x25519_mlkem768_key_share() -> PostQuantumKeyShare`**: Generates composite quantum-safe client key share.

### Encrypted Client Hello & HPKE (`ech.goose`, `hpke.goose`, RFC 9849, RFC 9180)

- **`struct EchConfig`**: Decoded ECH configuration holding public name, KEM, and symmetric cipher suites.
- **`fn parse_ech_config(raw: const u8[:], out: EchConfig&) -> bool`**: Parses ECHConfigList structures from DNS HTTPS records.
- **`fn build_ech_outer_extension<B>(ech_config: const EchConfig&, inner_bytes: const u8[:], out: B&) -> bool`**: Encapsulates ClientHelloInner inside ClientHelloOuter via DHKEM-X25519-HKDF-SHA256 HPKE.

### Certificate Compression (`cert_compression.goose`, RFC 8879)

- **`fn decompress_certificate_message<B>(compressed_msg: const u8[:], out_der: B&) -> bool`**: Decompresses zlib, brotli, or zstd compressed certificate payloads with decompression bomb defenses.
