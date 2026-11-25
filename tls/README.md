# `tls`

`tls` provides TLS 1.3 client and server handshakes (RFC 8446), encrypted socket
transport, pluggable native backends (OpenSSL, BoringSSL, Schannel, and
PureGoose), X.509 certificate chain verification (RFC 5280), PEM loading (RFC
7468), CRL and OCSP revocation checks (RFC 6960), Encrypted Client Hello (RFC
9849), and record-layer primitives shared with QUIC (RFC 9001).

Public types, configuration structs, and functions live in `namespace tls;`.
Internal wire codecs, PKI sub-parsers, post-quantum NTT/ML-KEM routines, and
backend state machines live in `namespace tls_internal;` across the
`*_internal.goose` modules.

## Quick start

Open a TCP socket, run a TLS 1.3 client handshake using system roots, exchange
application data, and close the session cleanly:

```goose
import wing;

let fd = net::tcp_connect("example.com", 443, 5000);
if fd > 0 {
    var cfg = tls::ClientHandshakeConfig { .. };
    let _ = cfg.server_name.try_set("example.com");
    let _ = cfg.alpn.try_set("h2,http/1.1");

    let slot, ok = tls::client_handshake(fd, cfg);
    if ok {
        let req = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
        let _ = tls::transport_send(fd, slot, req);

        var rx: u8[4096] = [0; 4096];
        let n = tls::transport_recv_slice(fd, slot, rx[..], 5000);
        if n > 0 {
            // Process rx[..n]
        }
        tls::transport_close(fd, slot);
    } else {
        net::tcp_close(fd);
    }
}
```

## Recipes

### TLS 1.3 client over an IP-pinned socket with explicit SNI

To prevent DNS rebinding between address validation and connection, connect to a
numeric IP literal with `net::tcp_connect_ip` (or `net::tcp_connect_resolved`)
and set the expected hostname in `cfg.server_name`. The TLS handshake sends that
hostname in the SNI extension and verifies it against the server certificate's
Subject Alternative Name (SAN) extension.

```goose
import wing;

let fd = net::tcp_connect_ip("93.184.216.34", 443, 5000, net::IpFamily.Ipv4Only);
if fd > 0 {
    var cfg = tls::ClientHandshakeConfig {
        handshake_timeout_ms: 5000,
        ..
    };
    let _ = cfg.server_name.try_set("example.com");
    let _ = cfg.alpn.try_set("http/1.1");

    let slot, ok = tls::client_handshake(fd, cfg);
    if ok {
        let negotiated = tls::session_alpn(slot);
        let _ = tls::transport_send(fd, slot, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        var buf: u8[4096] = [0; 4096];
        let n = tls::transport_recv_slice(fd, slot, buf[..], 5000);
        tls::transport_close(fd, slot);
    } else {
        net::tcp_close(fd);
    }
}
```

### TLS 1.3 server with PEM certificate and key

Load an X.509 certificate and its matching Ed25519 or ECDSA P-256 private key
from PEM into `ServerHandshakeConfig`, then accept TCP connections and run
`tls::server_handshake`.

```goose
import wing;

var srv_cfg = tls::ServerHandshakeConfig {
    handshake_timeout_ms: 5000,
    ..
};
let _ = srv_cfg.alpn.try_set("h2,http/1.1");
let ok_creds = tls::load_server_credentials_pem(cert_pem, key_pem, srv_cfg);

if ok_creds {
    let lst = net::tcp_listen("127.0.0.1", 8443);
    let cfd = net::tcp_accept(lst, 5000);
    if cfd > 0 {
        let slot, ok_hs = tls::server_handshake(cfd, srv_cfg);
        if ok_hs {
            var rx: u8[4096] = [0; 4096];
            let n = tls::transport_recv_slice(cfd, slot, rx[..], 5000);
            if n > 0 {
                let reply = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
                let _ = tls::transport_send(cfd, slot, reply);
            }
            tls::transport_close(cfd, slot);
        } else {
            net::tcp_close(cfd);
        }
    }
    net::tcp_close(lst);
}
```

For tests and local loopback harnesses without external PEM files, generate a
self-signed Ed25519 certificate DER in memory with
`tls::build_test_ed25519_cert_der`.

### Switching between PureGoose and OpenSSL or Schannel backends

`tls::TlsBackendConfig` selects between `SystemOnly` (fail-closed OS/system
TLS), `Auto` (system TLS with `PureGoose` fallback for ECH/PQ/virtual-clock
features), `SystemOpenSsl`, `SystemSchannel`, `SystemSecureTransport`, and
`PureGoose`. Native system backends also support TLS 1.2 opt-in via
`TlsMinVersion.Tls12`. See [`../SECURITY.md`](../SECURITY.md) for TLS backend
threat-model and audit notes.

```goose
import wing;

var bcfg = tls::TlsBackendConfig {
    kind:        tls::TlsBackendKind.SystemOnly,
    min_version: tls::TlsMinVersion.Tls13,
    ..
};
let _ = bcfg.server_name.try_set("example.com");
let _ = bcfg.alpn_wire.try_set("\x02h2\x08http/1.1");

let fd = net::tcp_connect("example.com", 443, 5000);
if fd > 0 {
    let slot_id, alpn, st = tls::endpoint_client_handshake_fd(fd, bcfg, 5000);
    if st == tls::TlsBackendStatus.Ok {
        let active, ok_ak = tls::endpoint_transport_active_kind(slot_id);
        let _ = tls::endpoint_transport_send(fd, slot_id, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        var rx: u8[4096] = [0; 4096];
        let n = tls::endpoint_transport_recv_slice(fd, slot_id, rx[..], 5000);
        tls::endpoint_transport_close(fd, slot_id);
    } else {
        net::tcp_close(fd);
    }
}
```

For event loops or custom transports, drive `tls::tls_endpoint_open` directly
with `tls_endpoint_feed_wire`, `tls_endpoint_step_handshake`, and
`tls_endpoint_drain_wire`, or wrap a non-blocking socket with
`tls::tls_stream_open`.

### Custom CA trust anchors, mTLS, CRL, and OCSP

Populate a `TrustAnchorStore` from PEM bundles or files and disable OS roots
when pinning to a private CA. On the client, attach a client certificate and
private key seed for mutual TLS (mTLS), attach a DER CRL, or require OCSP
stapling. On the server, set `require_client_cert: true` and supply
`client_trust_store`.

```goose
import wing;

var store = tls::TrustAnchorStore { .. };
let loaded, ok_ca = tls::load_trust_anchors_pem_file(store, "/etc/my-pki/root-ca.pem");

// Client with pinned CA, mTLS credentials, CRL, and strict OCSP stapling:
var cli_cfg = tls::ClientHandshakeConfig {
    trust_store:           store,
    use_system_roots:      false,
    require_ocsp_stapling: true,
    client_priv_seed:      client_key_seed,
    ..
};
let _ = cli_cfg.server_name.try_set("api.internal.example");
let _ = cli_cfg.client_cert_der.try_set(client_cert_der[..]);
let _ = cli_cfg.crl_der.try_set(ca_crl_der[..]);

// Server requiring client certificates signed by the same private CA:
var srv_cfg = tls::ServerHandshakeConfig {
    require_client_cert: true,
    client_trust_store:  store,
    ..
};
let _ = tls::load_server_credentials_pem(server_cert_pem, server_key_pem, srv_cfg);
```

To check revocation offline against a parsed CRL or DER OCSP response:

```goose
import wing;

var crl = tls::ParsedCrl { .. };
if tls::parse_x509_crl(raw_crl_der, crl) {
    let revoked = tls::crl_is_revoked(crl, cert_serial_u64);
}
let ocsp_alert = tls::validate_ocsp_stapling(raw_ocsp_der, leaf_cert, leaf_der, now_unix, issuer_der);
```

### X.509 certificate parsing and chain verification

Parse DER certificates into `ParsedCert` structs, add one or more trust anchors,
validate the full RFC 5280 chain, and check hostname matching against SAN
entries.

```goose
import wing;

var leaf = tls::ParsedCert { .. };
var inter = tls::ParsedCert { .. };
if tls::parse_x509_certificate(leaf_der, leaf) && tls::parse_x509_certificate(inter_der, inter) {
    var store = tls::TrustAnchorStore { .. };
    let _ = tls::add_trust_anchor_cert_der(store, root_ca_der);

    var chain: tls::ParsedCert[..8] = [];
    var raws:  const u8[:][..8]     = [];
    let _ = chain.try_push(leaf);
    let _ = chain.try_push(inter);
    let _ = raws.try_push(leaf_der);
    let _ = raws.try_push(inter_der);

    let alert = tls::verify_certificate_chain(
        chain, raws, store, now_unix, tls::CertValidationRole.Server,
    );
    let host_ok = tls::match_cert_san_host(leaf, leaf_der, "api.example.com");
    if alert == tls::Alert.CloseNotify && host_ok {
        // Certificate chain and hostname verified.
    }
}
```

## Public API reference

### Handshakes and live socket transport

Runs blocking TLS 1.3 handshakes on TCP descriptors, exchanges encrypted
application records, and manages active cipher slots and post-handshake control
messages (`tls/client_handshake.goose`, `tls/server_handshake.goose`,
`tls/session.goose`).

```goose
fn client_handshake(fd: i64, config: const ClientHandshakeConfig&) -> u16, bool
fn server_handshake(fd: i64, config: const ServerHandshakeConfig&) -> u16, bool
fn server_handshake_with_ch(fd: i64, ch_msg: const u8[:], config: const ServerHandshakeConfig&) -> u16, bool
recursive fn transport_send(fd: i64, slot_idx: u16, data: const u8[:]) -> i32
recursive fn transport_recv_slice(fd: i64, slot_idx: u16, dst: u8[:], timeout_ms: u32 = 5000) -> i32
recursive fn transport_close(fd: i64, slot_idx: u16)
inline fn session_alpn(slot_idx: u16) -> const u8[:]
inline fn session_is_resumed(slot_idx: u16) -> bool
fn session_export_keying_material(slot_idx: u16, label: const u8[:], context: const u8[:], length: u16, out: u8[..256]&) -> bool
recursive fn send_key_update(fd: i64, slot_idx: u16, request_update: u8) -> bool
fn send_new_session_ticket(fd: i64, slot_idx: u16, ticket_lifetime: u32, ticket_nonce: const u8[:], ticket: const u8[:], max_early_data_size: u32 = 0) -> bool
fn try_enable_ktls(slot_idx: u16, fd: i64) -> net_internal::SmartNicSession, bool
fn build_test_ed25519_cert_der(seed: const u8[32]&, common_name: const u8[:], dns_san: const u8[:], ip_san: const u8[:], out_der: u8[..2048]&) -> bool
```

### Pluggable backends and non-blocking streams

Provides a uniform sans-IO endpoint, blocking fd adapter, and non-blocking
reactor stream over PureGoose, OpenSSL/BoringSSL, Schannel, and SecureTransport
(`tls/backend.goose`, `tls/stream.goose`, `tls/types.goose`).

```goose
fn tls_backend_available(kind: TlsBackendKind) -> bool
fn tls_endpoint_open(cfg: const TlsBackendConfig&) -> TlsEndpoint, TlsBackendStatus
fn tls_endpoint_close(ep: TlsEndpoint&)
fn tls_endpoint_feed_wire(ep: TlsEndpoint&, ciphertext: const u8[:]) -> i64, TlsBackendStatus
fn tls_endpoint_drain_wire(ep: TlsEndpoint&, dst: u8[:]) -> i64, TlsBackendStatus
fn tls_endpoint_step_handshake(ep: TlsEndpoint&) -> TlsBackendStatus
fn tls_endpoint_write_app(ep: TlsEndpoint&, plaintext: const u8[:]) -> i64, TlsBackendStatus
fn tls_endpoint_read_app(ep: TlsEndpoint&, dst: u8[:]) -> i64, TlsBackendStatus
fn tls_endpoint_selected_alpn(ep: const TlsEndpoint&) -> u8[..255]
fn tls_endpoint_is_established(ep: const TlsEndpoint&) -> bool
fn tls_endpoint_pending_wire(ep: const TlsEndpoint&) -> i64
fn tls_endpoint_shutdown(ep: TlsEndpoint&) -> TlsBackendStatus
fn endpoint_client_handshake_fd(fd: i64, cfg: const TlsBackendConfig&, timeout_ms: u32 = 5000) -> i64, u8[..64], TlsBackendStatus
fn endpoint_server_handshake_fd(fd: i64, cfg: const TlsBackendConfig&, timeout_ms: u32 = 5000) -> i64, u8[..64], TlsBackendStatus
recursive fn endpoint_transport_send(fd: i64, slot_id: i64, data: const u8[:]) -> i32
recursive fn endpoint_transport_recv_slice(fd: i64, slot_id: i64, dst: u8[:], timeout_ms: u32 = 5000) -> i32
recursive fn endpoint_transport_close(fd: i64, slot_id: i64)
fn endpoint_transport_active_kind(slot_id: i64) -> TlsBackendKind, bool
fn tls_stream_open(fd: i64, cfg: const TlsBackendConfig&) -> TlsStream, TlsBackendStatus
fn tls_stream_step_handshake(s: TlsStream&) -> TlsBackendStatus
fn tls_stream_write(s: TlsStream&, plaintext: const u8[:]) -> i64, TlsBackendStatus
fn tls_stream_read(s: TlsStream&, dst: u8[:]) -> i64, TlsBackendStatus
fn tls_stream_flush_wire(s: TlsStream&) -> i64, TlsBackendStatus
fn tls_stream_poll_events(s: const TlsStream&) -> u32
fn tls_stream_shutdown(s: TlsStream&) -> TlsBackendStatus
fn tls_stream_close(s: TlsStream&)
```

### X.509 certificates, SAN matching, and PEM loading

Parses X.509 DER certificates and PEM bundles, loads OS or file-based trust
anchors, verifies certificate chains, and matches hostnames against SAN entries
(`tls/x509.goose`, `tls/x509_san.goose`, `tls/pem.goose`).

```goose
fn parse_x509_certificate(raw_cert: const u8[:], out: ParsedCert&) -> bool
fn add_trust_anchor(store: TrustAnchorStore&, subject_raw: const u8[:], spki_raw: const u8[:]) -> bool
fn add_trust_anchor_cert_der(store: TrustAnchorStore&, raw_cert_der: const u8[:]) -> bool
fn verify_certificate_chain(chain_certs: const ParsedCert[..8]&, raw_certs: const u8[:][..8]&, trust_store: const TrustAnchorStore&, now_unix: i64, role: CertValidationRole = CertValidationRole.Server) -> Alert
fn match_cert_san_host(cert: const ParsedCert&, raw_cert: const u8[:], host: const u8[:]) -> bool
fn match_dns_san(san_pattern: const u8[:], host: const u8[:]) -> bool
fn match_ip_san(san_ip: const u8[:], host: const u8[:]) -> bool
fn pem_next_block<B>(raw: const u8[:], idx: i64&, out_label: u8[..64]&, out_der: B&) -> bool
fn add_trust_anchors_pem(store: TrustAnchorStore&, pem_bundle: const u8[:]) -> i64, bool
fn load_trust_anchors_pem_file(store: TrustAnchorStore&, path: const u8[:]) -> i64, bool
fn parse_private_key_pem(pem: const u8[:], out_key: u8[32]&) -> PrivateKeyKind, bool
fn load_server_credentials_pem(cert_pem: const u8[:], key_pem: const u8[:], out_cfg: ServerHandshakeConfig&) -> bool
fn load_system_roots_for_issuer(store: TrustAnchorStore&, issuer_raw: const u8[:]) -> i64
```

### Revocation checking (CRL and OCSP)

Parses X.509 CRLs and OCSP responses, checks serial revocation, and verifies
issuer signatures and validity windows (`tls/crl.goose`, `tls/ocsp.goose`).

```goose
fn parse_x509_crl(raw_crl: const u8[:], out: ParsedCrl&) -> bool
fn crl_is_revoked(crl: const ParsedCrl&, serial: u64) -> bool
fn check_crl_der_revocation(raw_crl: const u8[:], target_serial: u64, issuer_cert: const ParsedCert&, issuer_raw: const u8[:], now_unix: i64) -> Alert
fn x509_verify_crl_signature(crl: const ParsedCrl&, raw_crl: const u8[:], issuer_cert: const ParsedCert&, issuer_raw: const u8[:]) -> Alert
fn parse_ocsp_response(raw_ocsp: const u8[:], out: ParsedOcspResponse&) -> bool
fn validate_ocsp_stapling(raw_ocsp: const u8[:], leaf_cert: const ParsedCert&, leaf_raw: const u8[:], now_unix: i64, issuer_raw_der: const u8[:] = "") -> Alert
fn x509_verify_ocsp_signature(resp: const ParsedOcspResponse&, raw_ocsp: const u8[:], issuer_cert: const ParsedCert&, issuer_raw: const u8[:]) -> Alert
fn unwrap_ocsp_response(ext_data: const u8[:]) -> const u8[:], bool
```

### Encrypted Client Hello (ECH)

Parses ECHConfigList records from DNS HTTPS RRs, selects compatible HPKE cipher
suites, seals ClientHelloInner payloads, and validates retry configs
(`tls/ech.goose`).

```goose
fn parse_ech_config(raw: const u8[:], out: EchConfig&) -> bool
fn parse_ech_config_list(raw: const u8[:], out: EchConfigList&) -> bool
fn select_ech_config(list: const EchConfigList&, out_cfg: EchConfig&, out_cs: EchCipherSuite&) -> bool
fn seal_ech_inner<B>(config: const EchConfig&, cs: const EchCipherSuite&, outer_aad: const u8[:], inner_padded: const u8[:], ephemeral_sk: const u8[32]&, out_enc: u8[32]&, out_ct: B&) -> bool
fn parse_and_validate_ech_retry_configs(ext_data: const u8[:], out_config_list: EchConfigList&) -> bool
fn verify_ech_acceptance_confirmation(ext_data: const u8[:], expected_confirmation: const u8[8]&) -> bool
```

### Session tickets

Caches client resumption tickets per hostname and seals or opens stateless
server tickets with rotated STEKs (`tls/ticket.goose`).

```goose
fn store_session_ticket(server_name: const u8[:], ticket: const u8[:], psk: const u8[:], age_add: u32, lifetime: u32, cipher_suite: u16 = rfc::TLS_CIPHER_AES_128_GCM_SHA256, issued_at_ms: i64 = 0)
fn lookup_session_ticket<B>(server_name: const u8[:], out_ticket: B&, out_psk: u8[32]&, out_age_add: u32&, now_ms: i64 = 0) -> bool
fn lookup_session_ticket_full<B>(server_name: const u8[:], out_ticket: B&, out_psk: u8[..48]&, out_age_add: u32&, out_cipher_suite: u16&, now_ms: i64 = 0) -> bool
fn clear_session_tickets()
fn seal_stateless_ticket<B>(ring: const TicketKeyRing&, psk: const u8[..48]&, cipher_suite: u16, issued_at_ms: i64, nonce_iv: const u8[12]&, out_ticket: B&) -> bool
fn open_stateless_ticket(ring: const TicketKeyRing&, raw_ticket: const u8[:], now_ms: i64) -> CachedSessionTicket, bool
```

### Record layer and QUIC crypto streams

Seals and decrypts TLS 1.3 AEAD records, computes nonces, and ingests QUIC
CRYPTO frames for `quic/` and reactor callers (`tls/record.goose`,
`tls/session.goose`).

```goose
fn record_seal_into(cipher_suite: u16, key: const u8[:], iv: const u8[12]&, seq_num: u64, inner_type: u8, plaintext: const u8[:], out_ciphertext: u8[:]) -> i64, Alert, bool
fn record_decrypt_into(cipher_suite: u16, key: const u8[:], iv: const u8[12]&, seq_num: u64, record_header: const u8[:], record_payload: const u8[:], out_plaintext: u8[:]) -> i64, u8, Alert, bool
checkfree fn parse_record_header(hdr_bytes: const u8[:]) -> u8, u16, u16, Alert, bool
checkfree inline fn compute_record_nonce(iv: const u8[12]&, seq_num: u64) -> u8[12], bool
checkfree inline fn increment_record_seq_num(seq_num: u64&) -> bool
checkfree fn unpack_inner_plaintext(decrypted: const u8[:]) -> const u8[:], u8, Alert
checkfree fn provide_quic_data(conn: QuicCryptoConn&, level: QuicEncryptionLevel, data: const u8[:]) -> Alert
checkfree fn quic_crypto_stream_ingest(stream: QuicCryptoStream&, offset: u64, data: const u8[:]) -> i64, bool
checkfree inline fn quic_extract_hp_sample(pkt: const u8[:], pn_offset: u32) -> const u8[:], bool
fn cipher_slot_seal_app_data<B>(slot_idx: u16, plain_in: const u8[:], out_cipher: B&) -> bool
fn cipher_slot_unseal_records<B>(slot_idx: u16, cipher_in: const u8[:], out_plain: B&) -> i64, SliceUnsealStatus
fn cipher_slot_seal_close_notify<B>(slot_idx: u16, out_cipher: B&) -> bool
```
