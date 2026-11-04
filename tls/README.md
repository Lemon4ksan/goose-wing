# `tls`

Zero-allocation TLS 1.3 cryptographic record layer (RFC 8446), X.509 PKI certificate validation (RFC 5280), Encrypted Client Hello (ECH, RFC 9849), Hybrid Post-Quantum Key Exchange (RFC 10024 / FIPS 203), and Certificate Compression (RFC 8879).

## Public API

### TLS Record Layer & Alert Protocol (`record.goose`, RFC 8446 §5)

- **`enum TlsAlert`**: RFC 8446 typed alert codes (`CloseNotify`, `UnexpectedMessage`, `BadRecordMac`, `RecordOverflow`, `HandshakeFailure`, `BadCertificate`, `UnsupportedCertificate`, `CertificateRevoked`, `CertificateExpired`, `CertificateUnknown`, `IllegalParameter`, `UnknownCa`, `AccessDenied`, `DecodeError`, etc.).
- **`fn tls_alert_to_u8(alert: TlsAlert) -> u8`**: Maps typed `TlsAlert` to RFC wire byte code.
- **`fn u8_to_tls_alert(code: u8) -> TlsAlert, bool`**: Validates and maps wire alert byte to typed `TlsAlert`.
- **`fn compute_record_nonce(iv: const u8[12]&, seq_num: u64) -> u8[12], bool`**: Derives RFC 8446 §5.3 per-record 96-bit nonce (`iv ^ seq_num`), rejecting $2^{64}-1$ against counter overflow.
- **`fn increment_record_seq_num(seq_num: u64&) -> bool`**: Monotonically increments record sequence number.
- **`fn parse_tls_record_header(buf: const u8[:]) -> u8, u16, u16, TlsAlert, bool`**: Validates 5-byte TLS record header, bounds, and content type.
- **`fn tls_record_seal_into(cipher_suite: u16, key: const u8[:], iv: const u8[12]&, seq_num: u64, inner_type: u8, plaintext: const u8[:], dst: u8[:]) -> i64, TlsAlert, bool`**: In-place zero-allocation record layer encryptor with AEAD dispatch.
- **`fn tls_record_open_into(cipher_suite: u16, key: const u8[:], iv: const u8[12]&, seq_num: u64, record_raw: const u8[:], dst: u8[:]) -> i64, u8, TlsAlert, bool`**: In-place authenticated AEAD decryption and inner content type extraction.

### Key Schedule & Transcript Cryptography (`key_schedule.goose`, RFC 8446 §7)

- **`struct KeySchedule`**: Stateful TLS 1.3 key schedule engine holding early, handshake, and master traffic secrets.
- **`fn ks_init(cipher_suite: u16) -> KeySchedule, bool`**: Initializes key schedule with negotiated cipher suite (SHA-256 or SHA-384).
- **`fn ks_init_early_secret(ks: KeySchedule&, psk: const u8[:]) -> bool`**: Injects 0-RTT PSK or zero-seed into Early Secret.
- **`fn ks_advance_to_handshake(ks: KeySchedule&, ecdhe_shared_secret: const u8[:]) -> bool`**: Transitions Early Secret to Handshake Secret via (EC)DHE shared secret.
- **`fn ks_advance_to_master(ks: KeySchedule&, transcript_hash: const u8[:]) -> bool`**: Transitions Handshake Secret to Master Secret and derives application traffic keys.
- **`fn hkdf_expand_label(hash_id: u8, secret: const u8[:], label: const u8[:], context: const u8[:], out_len: u8, out_key: u8[:]) -> bool`**: Labeled HKDF expansion (RFC 8446 §7.1).
- **`fn derive_secret(hash_id: u8, hash_len: u8, secret: const u8[:], label: const u8[:], transcript_hash: const u8[:], out_secret: u8[:]) -> bool`**: Derives epoch-specific traffic secrets from running transcript hash.

### X.509 PKI & Hostname Verification (`x509.goose`, RFC 5280, RFC 6125)

- **`struct ParsedCert`**: Zero-allocation X.509 v3 certificate holding span offsets for serial, subject, issuer, validity window, SPKI, and SANs.
- **`struct CertStore`**: Bounded collection of trusted root CA certificates.
- **`fn parse_x509_cert(der: const u8[:], out: ParsedCert&) -> bool`**: Strict ASN.1 DER parser validating canonical integer padding and X.509 structures.
- **`fn verify_certificate_chain(chain_der: const u8[:], store: const CertStore&, hostname: const u8[:], now_unix: i64) -> TlsAlert`**: Validates certificate chain signatures, path constraints, temporal bounds, and RFC 6125 SAN matching.
- **`fn validate_ocsp_stapling(raw_ocsp: const u8[:], leaf_cert: const ParsedCert&, leaf_raw: const u8[:], now_unix: i64) -> TlsAlert`**: Validates RFC 6066 / RFC 6960 OCSP stapling response against leaf certificate.
- **`fn parse_x509_crl(raw_crl: const u8[:], out: ParsedCrl&) -> bool`**: Parses RFC 5280 CRL lists and extracts revoked serial numbers.

### Hybrid Post-Quantum Key Exchange (`post_quantum.goose`, RFC 10024 / FIPS 203)

- **`struct PostQuantumKeyShare`**: Hybrid ephemeral client key share combining classical ECDH (X25519) with ML-KEM-768.
- **`struct PostQuantumServerShare`**: Hybrid server response ciphertext (ML-KEM-768) and classical ephemeral public key.
- **`fn format_hybrid_key_share<B>(share: const PostQuantumKeyShare&, out: B&)`**: Formats RFC 10024 hybrid KeyShareEntry for ClientHello.
- **`fn parse_hybrid_key_share(share: PostQuantumKeyShare&, raw: const u8[:]) -> bool`**: Parses and validates hybrid ClientHello key share wire bytes.
- **`fn format_hybrid_server_key_share<B>(share: const PostQuantumServerShare&, out: B&)`**: Formats RFC 10024 hybrid KeyShareEntry for ServerHello.
- **`fn parse_hybrid_server_key_share(share: PostQuantumServerShare&, raw: const u8[:]) -> bool`**: Parses and validates hybrid ServerHello key share wire bytes.

### Encrypted Client Hello & HPKE (`ech.goose`, `hpke.goose`, RFC 9849, RFC 9180)

- **`struct EchConfig`**: Decoded ECH configuration holding public name, KEM, and symmetric cipher suites.
- **`struct HpkeContext`**: Authenticated HPKE encryption context with key, base nonce, sequence counter, and exporter secret.
- **`fn parse_ech_config(raw: const u8[:], out: EchConfig&) -> bool`**: Parses individual ECHConfig structure with validation.
- **`fn parse_ech_config_list(raw: const u8[:], out_list: EchConfigList&) -> bool`**: Parses RFC 9849 ECHConfigList structures from DNS HTTPS / SVCB records.
- **`fn pad_ech_inner<B>(inner_bytes: const u8[:], max_name_len: u8, real_sni_len: i64, out_padded: B&) -> bool`**: Applies RFC 9849 §6.1.3 length-hiding padding to ClientHelloInner.
- **`fn build_ech_outer_extension<B>(config_id: u8, cs: const EchCipherSuite&, enc: const u8[32]&, ciphertext: const u8[:], out: B&) -> bool`**: Encapsulates ClientHelloOuter ECH extension.

### Certificate Compression (`cert_compression.goose`, RFC 8879)

- **`struct CompressedCertificate`**: RFC 8879 compressed certificate handshake message structure.
- **`fn encode_compressed_certificate<B>(msg: const CompressedCertificate&, out: B&) -> bool`**: Encodes CompressedCertificate message to wire bytes.
- **`fn parse_compressed_certificate_msg(raw: const u8[:], out: CompressedCertificate&) -> bool`**: Parses CompressedCertificate wire bytes with 1024x bomb ratio check.
- **`fn decompress_certificate_message<B>(msg: CompressedCertificate, max_allowed_len: u32, out_cert: B&) -> bool`**: Decompresses zlib, brotli, or zstd compressed certificate payloads with strict buffer hygiene.
