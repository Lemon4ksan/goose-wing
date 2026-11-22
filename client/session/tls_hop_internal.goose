// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal TLS handshake, ALPN wire encoding, mTLS/CRL loading, HSTS, ECH lookup, and config knob sync helpers.
namespace client_internal;

import std;
import core;
import rfc.http;
import rfc.tls;
import dns.cache;
import http.response;
import http.hsts;
import net.pool;
import net.transport;
import tls.types;
import tls.asn1;
import tls.x509;
import tls.pem;
import tls.crl;
import tls.handshake;
import tls.session;
import tls.backend;
import wire.pipeline;
import client.redirect;
import client.interceptor;
import client.client;

fn sync_session_pool_knobs(session: client::Session&) {
    let idle_ns: i64 = if session.pool_idle_timeout_ms > 0 {
        core::mul_sat_i64(session.pool_idle_timeout_ms, 1000000)
    } else {
        -1
    };
    net::configure_stream_pool(
        session.pool,
        session.max_conns_per_host,
        session.disable_keepalive,
        idle_ns,
    );
}

fn apply_client_config_knobs(c: client::Client&, cfg: const client::Config&) {
    let eff_mode = if cfg.redirect_mode != client::RedirectMode.Follow {
        cfg.redirect_mode
    } else if !cfg.follow_redirects {
        client::RedirectMode.Manual
    } else {
        client::RedirectMode.Follow
    };
    c.redirect_mode = eff_mode;
    c.follow_redirects = (eff_mode == client::RedirectMode.Follow);
    c.max_redirects = cfg.max_redirects;
    c.https_only = cfg.https_only;
    c.ssrf_guard.https_only = cfg.https_only;
    c.enable_referer = cfg.enable_referer;
    c.default_referrer_policy = cfg.default_referrer_policy;
    c.enable_hsts = cfg.enable_hsts;
    c.enable_doh = cfg.enable_doh;
    c.enable_ech = cfg.enable_ech;
    c.http2_prior_knowledge = cfg.http2_prior_knowledge;
    c.auto_decompress = cfg.auto_decompress;
    c.max_response_body_bytes = max(cfg.max_response_body_bytes, 0);
    c.verify_content_digest = cfg.verify_content_digest;
    c.enable_early_data = cfg.enable_early_data;
    c.enable_har_telemetry = cfg.enable_har_telemetry;
    c.allow_loopback_ssrf = cfg.allow_loopback_ssrf;
    if cfg.allow_loopback_ssrf {
        c.ssrf_guard.deny_local_network = false;
    }
    c.max_retries = cfg.max_retries;
    if cfg.max_retries > 0 {
        let _ = client::add_retry(c.pipeline, cfg.max_retries, true);
    }
    c.connect_timeout_ms = max(cfg.connect_timeout_ms, 0);
    c.tls_handshake_timeout_ms = max(cfg.tls_handshake_timeout_ms, 0);
    c.read_timeout_ms = max(cfg.read_timeout_ms, 0);
    c.pool_idle_timeout_ms = max(cfg.pool_idle_timeout_ms, 0);
    let _ = c.tls_client_cert_file.try_set(cfg.tls_client_cert_file);
    let _ = c.tls_client_key_file.try_set(cfg.tls_client_key_file);
    c.tls_enable_pq_hybrid = cfg.tls_enable_pq_hybrid;
    let _ = c.tls_alpn.try_set(cfg.tls_alpn);
    c.tls_enable_session_tickets = cfg.tls_enable_session_tickets;
    c.tls_require_ocsp_stapling = cfg.tls_require_ocsp_stapling;
    let _ = c.tls_crl_file.try_set(cfg.tls_crl_file);
    let _ = c.tls_keylog_file.try_set(cfg.tls_keylog_file);
    c.enable_ktls_offload = cfg.enable_ktls_offload;
    c.ip_family = cfg.ip_family;
    let _ = c.local_bind_addr.try_set(cfg.local_bind_addr);
    c.tcp_nodelay = cfg.tcp_nodelay;
    c.tcp_keepalive_idle_sec = cfg.tcp_keepalive_idle_sec;
    c.tcp_keepalive_intvl_sec = cfg.tcp_keepalive_intvl_sec;
    c.tcp_keepalive_cnt = cfg.tcp_keepalive_cnt;
    c.disable_keepalive = cfg.disable_keepalive;
    c.max_conns_per_host = max(cfg.max_conns_per_host, 0);
    c.use_env_proxy = cfg.use_env_proxy;
    sync_session_pool_knobs(c);
}

// RFC 7301 Section 3.1: The Application-Layer Protocol Negotiation Extension -
// Encodes a comma-separated ALPN protocol list into length-prefixed wire bytes.
//
// Example:
//   alpn_csv = "h2,http/1.1"
//   returns: ok = true, out_wire = [2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1']
fn encode_alpn_csv_to_wire(alpn_csv: const u8[:], out_wire: u8[..64]&) -> bool {
    var wire_buf: u8[..64] = [];
    var tokenizer = core::make_byte_tokenizer(alpn_csv, ',');
    while true {
        let tok, has_tok = core::token_next(tokenizer);
        guard has_tok else { break; }
        let proto = tok.trim_lws();
        guard proto.len > 0 else { continue; }
        guard proto.len <= 255 else { return false; }
        guard wire_buf.try_push(proto.len as u8) && wire_buf.try_append(proto) else {
            return false;
        }
    }
    guard wire_buf.len > 0 else { return false; }
    return out_wire.try_set(wire_buf[..]);
}

// Parses leaf and up to 3 intermediate `"CERTIFICATE"` PEM blocks for client mTLS.
//
// Example:
//   raw_pem = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
//   returns: ok = true, leaf_der populated with leaf X.509 DER
fn parse_client_pem_cert_chain(
    raw_pem:     const u8[:],
    leaf_der:    u8[..4096]&,
    chain_ders:  u8[..4096][..3]&,
    parsed_leaf: tls::ParsedCert&,
) -> bool {
    var idx:       i64             = 0;
    var label:     u8[..64]        = [];
    var der:       u8[..4096]      = [];
    var tmp_leaf:  u8[..4096]      = [];
    var tmp_chain: u8[..4096][..3] = [];
    var tmp_parsed = tls::ParsedCert { .. };
    guard tls::pem_next_block(raw_pem, idx, label, der) && label[..] == "CERTIFICATE" else {
        return false;
    }
    guard tls::parse_x509_certificate(der[..], tmp_parsed) && tmp_leaf.try_set(der[..]) else {
        return false;
    }
    while idx < raw_pem.len {
        if core::find(raw_pem[idx..], "-----BEGIN ") < 0 { break; }
        guard tls::pem_next_block(raw_pem, idx, label, der) else { return false; }
        guard label[..] == "CERTIFICATE" else { continue; }
        var chain_parsed = tls::ParsedCert { .. };
        guard tls::parse_x509_certificate(der[..], chain_parsed) else { return false; }
        guard tmp_chain.try_push(copy(der)) else { return false; }
    }
    guard leaf_der.try_set(tmp_leaf[..]) else { return false; }
    chain_ders = copy(tmp_chain);
    parsed_leaf = tmp_parsed;
    return true;
}

fn load_client_mtls_pem_files(
    cert_file: const u8[:],
    key_file:  const u8[:],
    cfg:       tls::ClientHandshakeConfig&,
) -> bool {
    guard cert_file.len > 0 && key_file.len > 0 else { return false; }
    var raw_cert: u8[>..] = [];
    var raw_key:  u8[>..] = [];
    defer core::secure_zeroize_slice(raw_cert[..]);
    defer core::secure_zeroize_slice(raw_key[..]);
    guard read_file(cert_file, raw_cert) && raw_cert.len > 0 && raw_cert.len <= 131072 else {
        return false;
    }
    guard read_file(key_file, raw_key) && raw_key.len > 0 && raw_key.len <= 65536 else {
        return false;
    }
    var leaf_der:   u8[..4096]      = [];
    var chain_ders: u8[..4096][..3] = [];
    var parsed_leaf = tls::ParsedCert { .. };
    guard parse_client_pem_cert_chain(raw_cert[..], leaf_der, chain_ders, parsed_leaf) else {
        return false;
    }
    var priv_seed: u8[32] = [0; 32];
    defer core::secure_zeroize_32(priv_seed);
    let key_kind, ok_key = tls::parse_private_key_pem(raw_key[..], priv_seed);
    guard ok_key else { return false; }
    let spki_oid = tls::span_slice(leaf_der[..], parsed_leaf.spki_alg_oid);
    let valid_alg = (key_kind == tls::PrivateKeyKind.Ed25519 && spki_oid == rfc::OID_ED25519[..]) ||
        (key_kind == tls::PrivateKeyKind.EcdsaP256 && spki_oid == rfc::OID_SECP256R1[..]);
    guard valid_alg else { return false; }
    guard cfg.client_cert_der.try_set(leaf_der[..]) else { return false; }
    cfg.client_chain_der = copy(chain_ders);
    cfg.client_priv_seed = priv_seed;
    return true;
}

fn load_crl_der_file(path: const u8[:], out_crl_der: u8[..4096]&) -> bool {
    guard path.len > 0 && path.len <= 4096 else { return false; }
    var raw: u8[>..] = [];
    defer core::secure_zeroize_slice(raw[..]);
    guard read_file(path, raw) && raw.len > 0 && raw.len <= 16384 else { return false; }
    var der_buf: u8[..4096] = [];
    if core::find(raw[..], "-----BEGIN ") >= 0 {
        var idx:   i64      = 0;
        var label: u8[..64] = [];
        guard tls::pem_next_block(raw[..], idx, label, der_buf) && label[..] == "X509 CRL" else {
            return false;
        }
    } else {
        guard der_buf.try_set(raw[..]) else { return false; }
    }
    var parsed = tls::ParsedCrl { .. };
    guard tls::parse_x509_crl(der_buf[..], parsed) else { return false; }
    return out_crl_der.try_set(der_buf[..]);
}

fn stage_client_url_hsts(
    url_buf:     u8[..2048]&,
    hsts:        const http::HstsCache&,
    enable_hsts: bool,
    now_sec:     i64,
) -> wire::StageVerdict {
    if enable_hsts {
        var upgraded_url: u8[..2048] = [];
        if http::hsts_upgrade_url(hsts, url_buf[..], now_sec, upgraded_url) {
            let _ = url_buf.try_set(upgraded_url[..]);
        }
    }
    return wire::StageVerdict.Continue;
}

fn stage_client_url_hsts(
    current_url: core::Url&,
    hsts:        const http::HstsCache&,
    enable_hsts: bool,
    now_sec:     i64,
) -> wire::StageVerdict {
    if enable_hsts && !current_url.is_secure_scheme() {
        var upgraded_url: u8[..2048] = [];
        if http::hsts_upgrade_url(hsts, current_url.href[..], now_sec, upgraded_url) {
            let parsed_upgraded, _ = core::parse_url(upgraded_url[..]);
            if parsed_upgraded.valid {
                current_url = parsed_upgraded;
            }
        }
    }
    return wire::StageVerdict.Continue;
}

// Looks up a fresh cached ECHConfigList for `domain` in `dns_cache`.
fn lookup_cached_ech_config(
    dns_cache: const dns::Cache&,
    domain:    const u8[:],
    now_sec:   i64,
) -> u8[..512], bool {
    var ech: u8[..512] = [];
    let cached, cache_status = dns_cache.lookup(domain, rfc::DNS_QTYPE_HTTPS, now_sec);
    if cached && cache_status == dns::CacheStatus.Fresh {
        for &rec in cached.https_records {
            if rec.has_ech && rec.ech_config_list.len > 0 {
                let ok_set = ech.try_set(rec.ech_config_list[..]);
                return ech, ok_set;
            }
        }
    }
    return ech, false;
}

fn establish_https_proxy_transport(
    session:     const client::Session&,
    raw_sock:    i64,
    proxy_host:  const u8[:],
    eff_timeout: u32,
    now_sec:     i64,
) -> net::Transport, http::Error {
    let host_is_hsts = session.enable_hsts && session.hsts.is_hsts_host(proxy_host, now_sec);
    let effective_insecure_skip = session.insecure_skip_verify && !host_is_hsts;
    if session.tls_backend != tls::TlsBackendKind.PureGoose {
        var bcfg = tls::TlsBackendConfig {
            kind:                   session.tls_backend,
            min_version:            session.tls_min_version,
            is_server:              false,
            insecure_skip_verify:   effective_insecure_skip,
            use_system_roots:       session.tls_use_system_roots,
            trust_store:            session.trust_store,
            enable_pq_hybrid:       session.tls_enable_pq_hybrid,
            enable_session_tickets: session.tls_enable_session_tickets,
            require_ocsp_stapling:  session.tls_require_ocsp_stapling,
            ..
        };
        let _ = bcfg.server_name.try_set(proxy_host);
        let alpn_h1: u8[9] = [8, 'h', 't', 't', 'p', '/', '1', '.', '1'];
        let _ = bcfg.alpn_wire.try_set(alpn_h1[..]);
        if session.tls_ca_file.len > 0 {
            let _ = bcfg.ca_file.try_set(session.tls_ca_file[..]);
        }
        let ep_slot, _, st = tls::endpoint_client_handshake_fd(raw_sock, bcfg, eff_timeout);
        guard st == tls::TlsBackendStatus.Ok && ep_slot >= 0 else {
            return net::Transport.Disconnected,
                http::make_error(rfc::STATUS_BAD_GATEWAY, "tls", "HTTPS proxy TLS handshake failed");
        }
        return net::Transport.TlsBackend { fd: raw_sock, endpoint_slot: ep_slot }, http::Error { .. };
    }

    var tls_cfg = tls::ClientHandshakeConfig { .. };
    let _ = tls_cfg.server_name.try_set(proxy_host);
    let _ = tls_cfg.alpn.try_set("http/1.1");
    tls_cfg.trust_store = session.trust_store;
    tls_cfg.insecure_skip_verify = effective_insecure_skip;
    tls_cfg.use_system_roots = session.tls_use_system_roots;
    tls_cfg.enable_pq_hybrid = session.tls_enable_pq_hybrid;
    tls_cfg.enable_session_tickets = session.tls_enable_session_tickets;
    tls_cfg.require_ocsp_stapling = session.tls_require_ocsp_stapling;
    tls_cfg.handshake_timeout_ms = eff_timeout;
    tls_cfg.virtual_clock_sec = if session.virtual_clock_us == 1700000000000000 { 0 } else { now_sec };
    let slot_idx, ok_tls = tls::client_handshake(raw_sock, tls_cfg);
    guard ok_tls else {
        return net::Transport.Disconnected,
            http::make_error(rfc::STATUS_BAD_GATEWAY, "tls", "HTTPS proxy TLS 1.3 handshake failed");
    }
    return net::Transport.Tls { fd: raw_sock, record_seq_rx: 0, record_seq_tx: 0, cipher_slot: slot_idx },
        http::Error { .. };
}

fn establish_backend_tls_connection(
    session:                 const client::Session&,
    sock:                    i64,
    host_str:                const u8[:],
    effective_insecure_skip: bool,
    tls_timeout_ms:          u32,
) -> i64, u8[..64], http::Error {
    var bcfg = tls::TlsBackendConfig {
        kind:                   session.tls_backend,
        min_version:            session.tls_min_version,
        is_server:              false,
        insecure_skip_verify:   effective_insecure_skip,
        use_system_roots:       session.tls_use_system_roots,
        trust_store:            session.trust_store,
        enable_pq_hybrid:       session.tls_enable_pq_hybrid,
        enable_session_tickets: session.tls_enable_session_tickets,
        require_ocsp_stapling:  session.tls_require_ocsp_stapling,
        ..
    };
    let _ = bcfg.server_name.try_set(host_str);
    let alpn_csv = if session.tls_alpn.len > 0 { session.tls_alpn[..] } else { "h2,http/1.1" };
    guard encode_alpn_csv_to_wire(alpn_csv, bcfg.alpn_wire) else {
        return -1, [], http::make_error(rfc::STATUS_BAD_GATEWAY, "tls", "invalid TLS ALPN configuration");
    }
    if session.tls_ca_file.len > 0 {
        let _ = bcfg.ca_file.try_set(session.tls_ca_file[..]);
    }
    if session.tls_client_cert_file.len > 0 || session.tls_client_key_file.len > 0 {
        guard session.tls_client_cert_file.len > 0 && session.tls_client_key_file.len > 0 else {
            return -1, [], http::make_error(rfc::STATUS_BAD_GATEWAY, "tls", "incomplete client mTLS configuration");
        }
        let _ = bcfg.cert_pem_file.try_set(session.tls_client_cert_file[..]);
        let _ = bcfg.key_pem_file.try_set(session.tls_client_key_file[..]);
    }
    if session.tls_crl_file.len > 0 {
        guard load_crl_der_file(session.tls_crl_file[..], bcfg.crl_der) else {
            return -1, [], http::make_error(rfc::STATUS_BAD_GATEWAY, "tls", "TLS CRL file load failed");
        }
    }
    if session.tls_keylog_file.len > 0 {
        let _ = bcfg.keylog_file.try_set(session.tls_keylog_file[..]);
    }
    let ep_slot, neg_alpn, st = tls::endpoint_client_handshake_fd(sock, bcfg, tls_timeout_ms);
    if st == tls::TlsBackendStatus.Ok && ep_slot >= 0 {
        return ep_slot, neg_alpn, http::Error { .. };
    }
    let msg = match st {
        VerifyError => "TLS certificate verification failed",
        Unavailable => "TLS backend unavailable",
        _ => "TLS handshake failed",
    };
    return -1, neg_alpn, http::make_error(rfc::STATUS_BAD_GATEWAY, "tls", msg);
}

fn prepare_pure_tls_client_config(
    session:                 const client::Session&,
    host_str:                const u8[:],
    ech_list:                const u8[:],
    effective_insecure_skip: bool,
    tls_timeout_ms:          u32,
    now_sec:                 i64,
    tls_cfg:                 tls::ClientHandshakeConfig&,
) -> http::Error {
    let _ = tls_cfg.server_name.try_set(host_str);
    let alpn_csv = if session.tls_alpn.len > 0 { session.tls_alpn[..] } else { "h2,http/1.1" };
    let _ = tls_cfg.alpn.try_set(alpn_csv);
    tls_cfg.trust_store = session.trust_store;
    if !effective_insecure_skip && tls_cfg.trust_store.anchors.len == 0 && session.tls_ca_file.len > 0 {
        let _, ok_ca = tls::load_trust_anchors_pem_file(tls_cfg.trust_store, session.tls_ca_file[..]);
        guard ok_ca else {
            return http::make_error(rfc::STATUS_BAD_GATEWAY, "tls", "TLS CA bundle load failed");
        }
    }
    tls_cfg.insecure_skip_verify = effective_insecure_skip;
    tls_cfg.use_system_roots = session.tls_use_system_roots;
    tls_cfg.virtual_clock_sec = if session.virtual_clock_us == 1700000000000000 { 0 } else { now_sec };
    tls_cfg.enable_pq_hybrid = session.tls_enable_pq_hybrid;
    tls_cfg.enable_session_tickets = session.tls_enable_session_tickets;
    tls_cfg.require_ocsp_stapling = session.tls_require_ocsp_stapling;
    tls_cfg.handshake_timeout_ms = tls_timeout_ms;
    if session.tls_keylog_file.len > 0 {
        let _ = tls_cfg.keylog_file.try_set(session.tls_keylog_file[..]);
    }
    if ech_list.len > 0 {
        let _ = tls_cfg.ech_config_list.try_set(ech_list);
    }
    if session.tls_client_cert_file.len > 0 || session.tls_client_key_file.len > 0 {
        guard load_client_mtls_pem_files(
            session.tls_client_cert_file[..], session.tls_client_key_file[..], tls_cfg,
        ) else {
            return http::make_error(rfc::STATUS_BAD_GATEWAY, "tls", "client mTLS credential load failed");
        }
    }
    if session.tls_crl_file.len > 0 {
        guard load_crl_der_file(session.tls_crl_file[..], tls_cfg.crl_der) else {
            return http::make_error(rfc::STATUS_BAD_GATEWAY, "tls", "TLS CRL file load failed");
        }
    }
    return http::Error { .. };
}

fn establish_https_transport(
    session:        const client::Session&,
    sock:           i64,
    host_str:       const u8[:],
    ech_list:       const u8[:],
    tls_timeout_ms: u32,
    now_sec:        i64,
) -> net::Transport, net::NegotiatedProtocol, http::Error {
    let host_is_hsts = session.enable_hsts && session.hsts.is_hsts_host(host_str, now_sec);
    let effective_insecure_skip = session.insecure_skip_verify && !host_is_hsts;
    if session.tls_backend != tls::TlsBackendKind.PureGoose {
        let ep_slot, neg_alpn, tls_err = establish_backend_tls_connection(
            session, sock, host_str, effective_insecure_skip, tls_timeout_ms,
        );
        guard http::ok(tls_err) else {
            return net::Transport.Disconnected, net::NegotiatedProtocol.Http11, tls_err;
        }
        let neg_proto = if neg_alpn[..] == "h2" {
            net::NegotiatedProtocol.Http2
        } else {
            net::NegotiatedProtocol.Http11
        };
        return net::Transport.TlsBackend { fd: sock, endpoint_slot: ep_slot }, neg_proto, http::Error { .. };
    }

    var tls_cfg = tls::ClientHandshakeConfig { .. };
    defer core::secure_zeroize_32(tls_cfg.client_priv_seed);
    let prep_err = prepare_pure_tls_client_config(
        session, host_str, ech_list, effective_insecure_skip, tls_timeout_ms, now_sec, tls_cfg,
    );
    guard http::ok(prep_err) else {
        return net::Transport.Disconnected, net::NegotiatedProtocol.Http11, prep_err;
    }

    let slot_idx, ok_tls = tls::client_handshake(sock, tls_cfg);
    guard ok_tls else {
        return net::Transport.Disconnected,
            net::NegotiatedProtocol.Http11,
            http::make_error(rfc::STATUS_BAD_GATEWAY, "tls", "TLS 1.3 handshake failed");
    }
    if session.enable_ktls_offload {
        let _, _ = tls::try_enable_ktls(slot_idx, sock);
    }
    let neg_proto = if tls::session_alpn(slot_idx) == "h2" {
        net::NegotiatedProtocol.Http2
    } else {
        net::NegotiatedProtocol.Http11
    };
    let t = net::Transport.Tls {
        fd: sock, record_seq_rx: 0, record_seq_tx: 0, cipher_slot: slot_idx,
    };
    return t, neg_proto, http::Error { .. };
}
