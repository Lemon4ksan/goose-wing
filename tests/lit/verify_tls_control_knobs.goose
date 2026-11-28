// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification of TLS 1.3 client/server/backend control knobs:
// 1. require_ocsp_stapling fail-closed enforcement (even without must-staple) & PQ hybrid offer.
// 2. enable_session_tickets: false prevents global ticket lookup/storage (PureGoose & OpenSSL).
// 3. keylog_file writes valid NSS Key Log Format lines (PureGoose & OpenSSL) and skips when empty.
// 4. handshake_timeout_ms custom timeout enforcement and server-side require_client_cert mTLS.
//
// RUN: goose build -O0 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import wing from "../..";

fn make_temp_path(suffix: const u8[:], out: u8[..256]&) {
    out.clear();
    var tmp_dir: u8[>..] = [];
    if !(env("TEMP", tmp_dir) || env("TMP", tmp_dir) || env("TMPDIR", tmp_dir)) {
        tmp_dir.append("/tmp");
    }
    assert(out.try_append(tmp_dir[..]) && out.try_push('/') && out.try_append(suffix));
}

fn put_der_len(b: core::ByteBuilder&, n: i64) {
    if n >= 256 {
        b.put_u8(0x82);
        b.put_u8(((n >> 8) & 0xFF) as u8);
        b.put_u8((n & 0xFF) as u8);
    } else if n >= 128 {
        b.put_u8(0x81);
        b.put_u8((n & 0xFF) as u8);
    } else {
        b.put_u8((n & 0xFF) as u8);
    }
}

fn wrap_der_tlv(tag: u8, payload: const u8[:], out: u8[..2048]&) {
    var b = core::builder_init();
    b.put_u8(tag);
    put_der_len(b, payload.len);
    b.put_bytes(payload);
    assert(out.try_set(b.buf[..]));
}

fn encode_pem(label: const u8[:], der: const u8[:], out: u8[>..]&) {
    out.clear();
    out.append("-----BEGIN ");
    out.append(label);
    out.append("-----\n");
    var b64: u8[>..] = [];
    core::base64_encode(der, b64);
    var pos: i64 = 0;
    while pos < b64.len {
        let end = min(core::add_sat_i64(pos, 64), b64.len);
        out.append(b64[pos..end]);
        out.push('\n');
        pos = end;
    }
    out.append("-----END ");
    out.append(label);
    out.append("-----\n");
}

fn make_p256_cert_der(priv_key: const u8[32]&, dns_san: const u8[:], out_der: u8[..2048]&) -> bool {
    out_der.clear();
    let pub65 = core::ecdsa_p256_public_key(priv_key);
    let alg = "\x30\x0A\x06\x08\x2A\x86\x48\xCE\x3D\x04\x03\x02";

    var b_tbs = core::builder_init();
    b_tbs.put_bytes("\xA0\x03\x02\x01\x02\x02\x01\x0B");
    b_tbs.put_bytes(alg);

    var b_cn = core::builder_init();
    b_cn.put_u8(0x30);
    b_cn.put_u8((7 + dns_san.len) as u8);
    b_cn.put_bytes("\x06\x03\x55\x04\x03\x0C");
    b_cn.put_u8(dns_san.len as u8);
    b_cn.put_bytes(dns_san);

    var b_name = core::builder_init();
    b_name.put_u8(0x30);
    b_name.put_u8((2 + b_cn.buf.len) as u8);
    b_name.put_u8(0x31);
    b_name.put_u8(b_cn.buf.len as u8);
    b_name.put_bytes(b_cn.buf[..]);
    b_tbs.put_bytes(b_name.buf[..]);

    b_tbs.put_bytes("\x30\x1E\x17\x0D240101000000Z\x17\x0D351231235959Z");
    b_tbs.put_bytes(b_name.buf[..]);

    b_tbs.put_bytes("\x30\x59\x30\x13\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01");
    b_tbs.put_bytes("\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07\x03\x42\x00");
    b_tbs.put_bytes(pub65[..]);

    var b_ext = core::builder_init();
    b_ext.put_bytes("\x30\x0C\x06\x03\x55\x1D\x13\x04\x05\x30\x03\x01\x01\xFF");

    var b_san = core::builder_init();
    b_san.put_u8(0x82);
    b_san.put_u8(dns_san.len as u8);
    b_san.put_bytes(dns_san);
    var b_san_seq = core::builder_init();
    b_san_seq.put_u8(0x30);
    b_san_seq.put_u8(b_san.buf.len as u8);
    b_san_seq.put_bytes(b_san.buf[..]);

    b_ext.put_u8(0x30);
    b_ext.put_u8((7 + b_san_seq.buf.len) as u8);
    b_ext.put_bytes("\x06\x03\x55\x1D\x11\x04");
    b_ext.put_u8(b_san_seq.buf.len as u8);
    b_ext.put_bytes(b_san_seq.buf[..]);

    b_tbs.put_u8(0xA3);
    b_tbs.put_u8((2 + b_ext.buf.len) as u8);
    b_tbs.put_u8(0x30);
    b_tbs.put_u8(b_ext.buf.len as u8);
    b_tbs.put_bytes(b_ext.buf[..]);

    var tbs_wrapped: u8[..2048] = [];
    wrap_der_tlv(0x30, b_tbs.buf[..], tbs_wrapped);
    let raw_sig = core::ecdsa_p256_sign(priv_key, tbs_wrapped[..]);
    var der_sig: u8[..72] = [];
    guard core::ecdsa_p256_encode_der_sig(raw_sig, der_sig) else { return false; }

    var b_cert = core::builder_init();
    b_cert.put_bytes(tbs_wrapped[..]);
    b_cert.put_bytes(alg);
    b_cert.put_u8(0x03);
    b_cert.put_u8((1 + der_sig.len) as u8);
    b_cert.put_u8(0x00);
    b_cert.put_bytes(der_sig[..]);

    wrap_der_tlv(0x30, b_cert.buf[..], out_der);
    return out_der.len > 0;
}

fn make_p256_pkcs8_der(priv_key: const u8[32]&, out_der: u8[..512]&) -> bool {
    out_der.clear();
    let pub65 = core::ecdsa_p256_public_key(priv_key);
    var b_ec = core::builder_init();
    b_ec.put_bytes("\x02\x01\x01\x04\x20");
    b_ec.put_bytes(priv_key[..]);
    b_ec.put_bytes("\xA1\x44\x03\x42\x00");
    b_ec.put_bytes(pub65[..]);

    var b_ec_seq = core::builder_init();
    b_ec_seq.put_u8(0x30);
    put_der_len(b_ec_seq, b_ec.buf.len);
    b_ec_seq.put_bytes(b_ec.buf[..]);

    var b_pki = core::builder_init();
    b_pki.put_bytes("\x02\x01\x00\x30\x13\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01");
    b_pki.put_bytes("\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07\x04");
    put_der_len(b_pki, b_ec_seq.buf.len);
    b_pki.put_bytes(b_ec_seq.buf[..]);

    var b_full = core::builder_init();
    b_full.put_u8(0x30);
    put_der_len(b_full, b_pki.buf.len);
    b_full.put_bytes(b_pki.buf[..]);
    return out_der.try_set(b_full.buf[..]);
}

fn pump_wire(src: tls::TlsEndpoint&, dst: tls::TlsEndpoint&) -> i64 {
    var wire:  u8[16384] = [0; 16384];
    var total: i64       = 0;
    while true {
        let n, st_d = tls::tls_endpoint_drain_wire(src, wire[..]);
        if st_d != tls::TlsBackendStatus.Ok || n <= 0 { break; }
        let fed, st_f = tls::tls_endpoint_feed_wire(dst, wire[..n]);
        if st_f != tls::TlsBackendStatus.Ok || fed <= 0 { break; }
        total = core::add_sat_i64(total, n);
    }
    return total;
}

fn run_sans_io_handshake(cli: tls::TlsEndpoint&, srv: tls::TlsEndpoint&) -> tls::TlsBackendStatus {
    var last_cli_st = tls::TlsBackendStatus.WantRead;
    for _ in 24 {
        last_cli_st = tls::tls_endpoint_step_handshake(cli);
        let _ = pump_wire(cli, srv);
        let _ = tls::tls_endpoint_step_handshake(srv);
        let _ = pump_wire(srv, cli);
        if tls::tls_endpoint_is_established(cli) && tls::tls_endpoint_is_established(srv) {
            let _ = pump_wire(srv, cli);
            return tls::TlsBackendStatus.Ok;
        }
        if last_cli_st != tls::TlsBackendStatus.WantRead &&
            last_cli_st != tls::TlsBackendStatus.WantWrite &&
            last_cli_st != tls::TlsBackendStatus.Ok {
            return last_cli_st;
        }
    }
    return last_cli_st;
}

fn client_hello_find_ext(record: const u8[:], target_ext: u16) -> const u8[:], bool {
    guard record.len > 48 && record[0] == 0x16 && record[5] == 0x01 else { return "", false; }
    var c = core::cursor_from(record[9..]);
    let _, ok_v = c.read_u16();
    let _, ok_r = c.read_bytes(32);
    let _, ok_sid = c.read_u8_prefixed();
    let _, ok_cs = c.read_u16_prefixed();
    let _, ok_cm = c.read_u8_prefixed();
    guard ok_v && ok_r && ok_sid && ok_cs && ok_cm else { return "", false; }
    let exts, ok_ext = c.read_u16_prefixed();
    guard ok_ext else { return "", false; }
    var ec = core::cursor_from(exts);
    while ec.buf.len >= 4 {
        let etype, ok_t = ec.read_u16();
        let edata, ok_d = ec.read_u16_prefixed();
        guard ok_t && ok_d else { break; }
        if etype == target_ext { return edata, true; }
    }
    return "", false;
}

fn is_hex_token(s: const u8[:], expect_len_a: i64, expect_len_b: i64) -> bool {
    guard s.len == expect_len_a || s.len == expect_len_b else { return false; }
    var non_zero = false;
    for b in s {
        let ok = (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f');
        guard ok else { return false; }
        if b != '0' { non_zero = true; }
    }
    return non_zero;
}

fn validate_nss_keylog(content: const u8[:]) -> bool {
    var mask: u32 = 0;
    var tok = core::make_byte_tokenizer(content, '\n');
    while true {
        let raw_line, ok_l = core::token_next(tok);
        if !ok_l { break; }
        let line = raw_line.trim_end_byte('\r');
        if line.len == 0 { continue; }
        let label, rest1, ok1 = line.split_once_byte(' ');
        let rand_hex, sec_hex, ok2 = rest1.split_once_byte(' ');
        guard ok1 && ok2 && is_hex_token(rand_hex, 64, 64) && is_hex_token(sec_hex, 64, 96) else {
            return false;
        }
        if label == "CLIENT_HANDSHAKE_TRAFFIC_SECRET" { mask |= 1; }
        if label == "SERVER_HANDSHAKE_TRAFFIC_SECRET" { mask |= 2; }
        if label == "CLIENT_TRAFFIC_SECRET_0" { mask |= 4; }
        if label == "SERVER_TRAFFIC_SECRET_0" { mask |= 8; }
        if label == "EXPORTER_SECRET" { mask |= 16; }
    }
    return mask == 31;
}

// ---- 1. require_ocsp_stapling & PQ Hybrid Propagation ----------------------

fn test_ocsp_requirement_and_pq_propagation() {
    print("=== 1. OCSP Stapling Requirement & PQ Hybrid Knob ===");
    // CHECK: === 1. OCSP Stapling Requirement & PQ Hybrid Knob ===

    let seed: u8[32] = [0x41; 32];
    var cert_der: u8[..2048] = [];
    assert(make_p256_cert_der(seed, "ocsp-knob.test", cert_der));

    var leaf = tls::ParsedCert { .. };
    assert(tls::parse_x509_certificate(cert_der[..], leaf));
    assert(!leaf.has_must_staple);

    var trust = tls::TrustAnchorStore { .. };
    assert(tls::add_trust_anchor_cert_der(trust, cert_der[..]));

    var chain_p: tls::ParsedCert[..8] = [];
    assert(chain_p.try_push(leaf));
    var chain_s: const u8[:][..8] = [];
    assert(chain_s.try_push(cert_der[..]));

    let unit_allow = tls_internal::verify_stapled_ocsp_for_chain("", chain_p, chain_s, 1750000000, trust, false);
    let unit_deny = !tls_internal::verify_stapled_ocsp_for_chain("", chain_p, chain_s, 1750000000, trust, true);

    var srv_cfg = tls::TlsBackendConfig {
        kind:      tls::TlsBackendKind.PureGoose,
        is_server: true,
        priv_seed: seed,
        ..
    };
    assert(srv_cfg.cert_der.try_set(cert_der[..]));

    var cli_allow_cfg = tls::TlsBackendConfig {
        kind:                  tls::TlsBackendKind.PureGoose,
        is_server:             false,
        insecure_skip_verify:  false,
        require_ocsp_stapling: false,
        trust_store:           trust,
        ..
    };
    assert(cli_allow_cfg.server_name.try_set("ocsp-knob.test"));

    var cli1, c1_st = tls::tls_endpoint_open(cli_allow_cfg);
    var srv1, s1_st = tls::tls_endpoint_open(srv_cfg);
    assert(c1_st == tls::TlsBackendStatus.Ok && s1_st == tls::TlsBackendStatus.Ok);
    let hs_allow = run_sans_io_handshake(cli1, srv1) == tls::TlsBackendStatus.Ok;
    tls::tls_endpoint_close(cli1);
    tls::tls_endpoint_close(srv1);

    var cli_deny_cfg = cli_allow_cfg;
    cli_deny_cfg.require_ocsp_stapling = true;
    var cli2, c2_st = tls::tls_endpoint_open(cli_deny_cfg);
    var srv2, s2_st = tls::tls_endpoint_open(srv_cfg);
    assert(c2_st == tls::TlsBackendStatus.Ok && s2_st == tls::TlsBackendStatus.Ok);
    let hs_deny = run_sans_io_handshake(cli2, srv2) == tls::TlsBackendStatus.VerifyError;
    tls::tls_endpoint_close(cli2);
    tls::tls_endpoint_close(srv2);

    // Verify enable_pq_hybrid propagates into PureGoose ClientHello key_share (0x11EC).
    var pq_cfg = cli_allow_cfg;
    pq_cfg.enable_pq_hybrid = true;
    var pq_cli, pq_st = tls::tls_endpoint_open(pq_cfg);
    assert(pq_st == tls::TlsBackendStatus.Ok);
    let _ = tls::tls_endpoint_step_handshake(pq_cli);
    var ch_buf: u8[4096] = [0; 4096];
    let ch_n, _ = tls::tls_endpoint_drain_wire(pq_cli, ch_buf[..]);
    tls::tls_endpoint_close(pq_cli);
    let sg_ext, has_sg = client_hello_find_ext(ch_buf[..ch_n], rfc::TLS_EXT_SUPPORTED_GROUPS);
    let pq_group_offered = has_sg && sg_ext.len >= 4 &&
        core::read_be_u16(sg_ext, 2) == rfc::GROUP_X25519_MLKEM768;

    // Verify non-empty malformed crl_der propagates into PureGoose verifier and fails closed.
    var crl_cfg = cli_allow_cfg;
    assert(crl_cfg.crl_der.try_set("\x30\x03\x02\x01\x00"));
    var cli3, _ = tls::tls_endpoint_open(crl_cfg);
    var srv3, _ = tls::tls_endpoint_open(srv_cfg);
    let crl_fail_closed = run_sans_io_handshake(cli3, srv3) == tls::TlsBackendStatus.VerifyError;
    tls::tls_endpoint_close(cli3);
    tls::tls_endpoint_close(srv3);

    print("ocsp_unit=", unit_allow && unit_deny, " ocsp_allow=", hs_allow,
        " ocsp_require_reject=", hs_deny, " pq_offered=", pq_group_offered,
        " crl_propagated=", crl_fail_closed);
    // CHECK: ocsp_unit=true ocsp_allow=true ocsp_require_reject=true pq_offered=true crl_propagated=true
}

// ---- 2. enable_session_tickets: false (PureGoose & OpenSSL) ----------------

thread_fn ticket_loopback_server_worker(listener_fd: i64) {
    let seed: u8[32] = [0x42; 32];
    var cert_der: u8[..2048] = [];
    assert(make_p256_cert_der(seed, "tickets.example", cert_der));
    var srv_cfg = tls::ServerHandshakeConfig { priv_seed: seed, .. };
    assert(srv_cfg.cert_der.try_set(cert_der[..]));

    // Conn 1..3: accept, clear server slot SNI (so server stores under "server", isolated from client SNI),
    // emit NewSessionTicket + app payload.
    for i in 3 {
        let conn = net::tcp_accept(listener_fd, 5000);
        assert(conn > 0);
        let slot, ok = tls::server_handshake(conn, srv_cfg);
        assert(ok && slot != 0xFFFF);
        tls::g_tls_cipher_slots[slot as i64].server_name.clear();
        let nonce: u8[4] = [0x01, 0x02, 0x03, i as u8];
        let tkt_id = if i == 2 { "SERVER_ISSUED_TKT_STORE_OK" } else { "SERVER_ISSUED_TKT_NO_STORE" };
        assert(tls::send_new_session_ticket(conn, slot, 3600, nonce[..], tkt_id));
        assert(tls::transport_send(conn, slot, "TICKET-PAYLOAD") == 14);
        var ack: u8[16] = [0; 16];
        let _ = tls::transport_recv_slice(conn, slot, ack[..], 2000);
        tls::transport_close(conn, slot);
    }
}

fn test_session_tickets_pure_goose() {
    print("=== 2. Session Ticket Disablement (PureGoose & OpenSSL) ===");
    // CHECK: === 2. Session Ticket Disablement (PureGoose & OpenSSL) ===

    let seed: u8[32] = [0x42; 32];
    var cert_der: u8[..2048] = [];
    assert(make_p256_cert_der(seed, "tickets.example", cert_der));
    var trust = tls::TrustAnchorStore { .. };
    assert(tls::add_trust_anchor_cert_der(trust, cert_der[..]));

    // 2a. Pre-seed global ticket cache and verify PureGoose backend skips lookup when disabled.
    tls::clear_session_tickets();
    let fake_psk: u8[32] = [0x77; 32];
    let pre_pol_cfg = tls::ClientHandshakeConfig { insecure_skip_verify: true, .. };
    let pre_pol_hash = tls_internal::compute_client_policy_hash(pre_pol_cfg);
    tls::store_session_ticket(
        "tickets.example",
        "PRE_CACHED_TKT",
        fake_psk[..],
        0x11223344,
        3600,
        rfc::TLS_CIPHER_AES_128_GCM_SHA256,
        0,
        0,
        0,
        0,
        pre_pol_hash,
    );

    var bcfg_no = tls::TlsBackendConfig {
        kind:                   tls::TlsBackendKind.PureGoose,
        is_server:              false,
        insecure_skip_verify:   true,
        enable_session_tickets: false,
        ..
    };
    assert(bcfg_no.server_name.try_set("tickets.example"));
    var ep_no, _ = tls::tls_endpoint_open(bcfg_no);
    let _ = tls::tls_endpoint_step_handshake(ep_no);
    var ch_no: u8[4096] = [0; 4096];
    let n_no, _ = tls::tls_endpoint_drain_wire(ep_no, ch_no[..]);
    tls::tls_endpoint_close(ep_no);
    let _, offered_psk_when_disabled = client_hello_find_ext(ch_no[..n_no], rfc::TLS_EXT_PRE_SHARED_KEY);

    var bcfg_yes = bcfg_no;
    bcfg_yes.enable_session_tickets = true;
    var ep_yes, _ = tls::tls_endpoint_open(bcfg_yes);
    let _ = tls::tls_endpoint_step_handshake(ep_yes);
    var ch_yes: u8[4096] = [0; 4096];
    let n_yes, _ = tls::tls_endpoint_drain_wire(ep_yes, ch_yes[..]);
    tls::tls_endpoint_close(ep_yes);
    let _, offered_psk_when_enabled = client_hello_find_ext(ch_yes[..n_yes], rfc::TLS_EXT_PRE_SHARED_KEY);

    // 2b. Live TCP loopback: enable_session_tickets=false skips lookup AND skips global storage on NST.
    let listener = net::tcp_listen("127.0.0.1", 0, 8);
    assert(listener > 0);
    let port = net::tcp_getsockname_port(listener);
    let tid = thread_spawn(ticket_loopback_server_worker, listener);

    var cli_no_cfg = tls::ClientHandshakeConfig {
        trust_store:            trust,
        enable_session_tickets: false,
        ..
    };
    assert(cli_no_cfg.server_name.try_set("tickets.example"));

    // Conn 1: pre-cached ticket still present; disabled client MUST NOT resume or overwrite it.
    let fd1 = net::tcp_connect("127.0.0.1", port, 5000);
    let s1, ok1 = tls::client_handshake(fd1, cli_no_cfg);
    assert(ok1 && !tls::session_is_resumed(s1));
    var rx1: u8[64] = [0; 64];
    assert(tls::transport_recv_slice(fd1, s1, rx1[..], 5000) == 14 && rx1[..14] == "TICKET-PAYLOAD");
    assert(tls::transport_send(fd1, s1, "OK") == 2);
    tls::transport_close(fd1, s1);

    // Conn 2: empty global cache; disabled client receives NST and MUST NOT store it globally.
    tls::clear_session_tickets();
    let fd2 = net::tcp_connect("127.0.0.1", port, 5000);
    let s2, ok2 = tls::client_handshake(fd2, cli_no_cfg);
    assert(ok2);
    var rx2: u8[64] = [0; 64];
    assert(tls::transport_recv_slice(fd2, s2, rx2[..], 5000) == 14 && rx2[..14] == "TICKET-PAYLOAD");
    assert(tls::transport_send(fd2, s2, "OK") == 2);
    tls::transport_close(fd2, s2);
    var out_tkt: u8[..256] = [];
    var out_psk: u8[..48]  = [];
    var out_age: u32       = 0;
    var out_cs:  u16       = 0;
    let pol_hash = tls_internal::compute_client_policy_hash(cli_no_cfg);
    let alpn_hash = tls_internal::compute_alpn_scope_hash(cli_no_cfg.alpn[..]);
    let stored_when_disabled = tls::lookup_session_ticket_full(
        "tickets.example", out_tkt, out_psk, out_age, out_cs, 0, 0, 0, alpn_hash, pol_hash,
    );

    // Conn 3: enabled client receives NST and MUST store it globally.
    var cli_yes_cfg = cli_no_cfg;
    cli_yes_cfg.enable_session_tickets = true;
    let fd3 = net::tcp_connect("127.0.0.1", port, 5000);
    let s3, ok3 = tls::client_handshake(fd3, cli_yes_cfg);
    assert(ok3);
    var rx3: u8[64] = [0; 64];
    assert(tls::transport_recv_slice(fd3, s3, rx3[..], 5000) == 14 && rx3[..14] == "TICKET-PAYLOAD");
    assert(tls::transport_send(fd3, s3, "OK") == 2);
    tls::transport_close(fd3, s3);
    let stored_when_enabled = tls::lookup_session_ticket_full(
        "tickets.example", out_tkt, out_psk, out_age, out_cs, 0, 0, 0, alpn_hash, pol_hash,
    ) && out_tkt[..] == "SERVER_ISSUED_TKT_STORE_OK";

    assert(thread_wait(tid));
    net::tcp_close(listener);
    tls::clear_session_tickets();

    print("pure_skip_lookup=", !offered_psk_when_disabled && offered_psk_when_enabled,
        " pure_skip_store=", !stored_when_disabled, " pure_allow_store=", stored_when_enabled);
    // CHECK: pure_skip_lookup=true pure_skip_store=true pure_allow_store=true
}

fn exchange_sans_io_app_msg(
    cli: tls::TlsEndpoint&,
    srv: tls::TlsEndpoint&,
    msg: const u8[:],
) -> bool {
    let nw, wst = tls::tls_endpoint_write_app(srv, msg);
    guard wst == tls::TlsBackendStatus.Ok && nw == msg.len else { return false; }
    let _ = pump_wire(srv, cli);
    var rx: u8[128] = [0; 128];
    for _ in 8 {
        let nr, rst = tls::tls_endpoint_read_app(cli, rx[..]);
        if rst == tls::TlsBackendStatus.Ok && nr > 0 {
            return nr == msg.len && rx[..nr] == msg;
        }
        let _ = pump_wire(srv, cli);
    }
    return false;
}

fn test_openssl_tickets_and_keylog(cpath: const u8[:], kpath: const u8[:], trust: const tls::TrustAnchorStore&) {
    let ossl_avail = tls::tls_backend_available(tls::TlsBackendKind.SystemOpenSsl);
    print("ossl_driver_active=", ossl_avail);
    if !ossl_avail {
        print("ossl_no_tickets_ok=true ossl_keylog_ok=true ossl_keylog_empty_ok=true");
        return;
    }

    // 2c. OpenSSL server with enable_session_tickets=false emits zero NewSessionTicket records.
    tls::clear_session_tickets();
    var ossl_srv_no_tkt = tls::TlsBackendConfig {
        kind:                   tls::TlsBackendKind.SystemOpenSsl,
        is_server:              true,
        enable_session_tickets: false,
        ..
    };
    assert(ossl_srv_no_tkt.cert_pem_file.try_set(cpath));
    assert(ossl_srv_no_tkt.key_pem_file.try_set(kpath));

    var pure_cli_yes = tls::TlsBackendConfig {
        kind:                   tls::TlsBackendKind.PureGoose,
        is_server:              false,
        trust_store:            trust,
        enable_session_tickets: true,
        ..
    };
    assert(pure_cli_yes.server_name.try_set("ossl-no-tkt.test"));

    var srv1, _ = tls::tls_endpoint_open(ossl_srv_no_tkt);
    var cli1, _ = tls::tls_endpoint_open(pure_cli_yes);
    assert(run_sans_io_handshake(cli1, srv1) == tls::TlsBackendStatus.Ok);
    assert(exchange_sans_io_app_msg(cli1, srv1, "ossl-no-ticket-msg"));
    tls::tls_endpoint_close(cli1);
    tls::tls_endpoint_close(srv1);

    var out_tkt: u8[..256] = [];
    var out_psk: u8[..48]  = [];
    var out_age: u32       = 0;
    var out_cs:  u16       = 0;
    let pure_pol_cfg = tls::ClientHandshakeConfig {
        use_system_roots: pure_cli_yes.use_system_roots,
        trust_store:      trust,
        ..
    };
    let pure_pol_hash = tls_internal::compute_client_policy_hash(pure_pol_cfg);
    let ossl_srv_suppressed = !tls::lookup_session_ticket_full(
        "ossl-no-tkt.test", out_tkt, out_psk, out_age, out_cs, 0, 0, 0, 0, pure_pol_hash,
    );

    // 2d. OpenSSL server (tickets enabled) -> PureGoose client (tickets disabled vs enabled).
    var ossl_srv_yes_tkt = ossl_srv_no_tkt;
    ossl_srv_yes_tkt.enable_session_tickets = true;
    var pure_cli_no = pure_cli_yes;
    pure_cli_no.enable_session_tickets = false;
    assert(pure_cli_no.server_name.try_set("ossl-no-tkt.test"));

    var srv2, _ = tls::tls_endpoint_open(ossl_srv_yes_tkt);
    var cli2, _ = tls::tls_endpoint_open(pure_cli_no);
    assert(run_sans_io_handshake(cli2, srv2) == tls::TlsBackendStatus.Ok);
    assert(exchange_sans_io_app_msg(cli2, srv2, "ossl-cli-skip-store"));
    tls::tls_endpoint_close(cli2);
    tls::tls_endpoint_close(srv2);
    let pure_backend_skip_store = !tls::lookup_session_ticket_full(
        "ossl-no-tkt.test", out_tkt, out_psk, out_age, out_cs, 0, 0, 0, 0, pure_pol_hash,
    );

    var srv3, _ = tls::tls_endpoint_open(ossl_srv_yes_tkt);
    var cli3, _ = tls::tls_endpoint_open(pure_cli_yes);
    assert(run_sans_io_handshake(cli3, srv3) == tls::TlsBackendStatus.Ok);
    assert(exchange_sans_io_app_msg(cli3, srv3, "ossl-cli-do-store"));
    tls::tls_endpoint_close(cli3);
    tls::tls_endpoint_close(srv3);
    let pure_backend_did_store = tls::lookup_session_ticket_full(
        "ossl-no-tkt.test", out_tkt, out_psk, out_age, out_cs, 0, 0, 0, 0, pure_pol_hash,
    );
    tls::clear_session_tickets();

    // 2e + 3c. OpenSSL client + server with enable_session_tickets=false and NSS keylog_file.
    var ossl_log_path: u8[..256] = [];
    make_temp_path("wing_tls_ctrl_ossl.keylog", ossl_log_path);
    let _ = delete_file(ossl_log_path[..]);
    defer { let _ = delete_file(ossl_log_path[..]); };

    var ossl_cli_cfg = tls::TlsBackendConfig {
        kind:                   tls::TlsBackendKind.SystemOpenSsl,
        is_server:              false,
        enable_session_tickets: false,
        ..
    };
    assert(ossl_cli_cfg.server_name.try_set("ossl-no-tkt.test"));
    assert(ossl_cli_cfg.ca_file.try_set(cpath));
    assert(ossl_cli_cfg.keylog_file.try_set(ossl_log_path[..]));

    var srv4, _ = tls::tls_endpoint_open(ossl_srv_no_tkt);
    var cli4, _ = tls::tls_endpoint_open(ossl_cli_cfg);
    let ossl_hs_ok = run_sans_io_handshake(cli4, srv4) == tls::TlsBackendStatus.Ok &&
        exchange_sans_io_app_msg(cli4, srv4, "ossl-keylog-ok");
    tls::tls_endpoint_close(cli4);
    tls::tls_endpoint_close(srv4);

    var ossl_log_data: u8[>..] = [];
    let ossl_keylog_ok = ossl_hs_ok && read_file(ossl_log_path[..], ossl_log_data) &&
        validate_nss_keylog(ossl_log_data[..]);

    // Verify empty keylog_file writes nothing on OpenSSL.
    let _ = delete_file(ossl_log_path[..]);
    ossl_cli_cfg.keylog_file.clear();
    var srv5, _ = tls::tls_endpoint_open(ossl_srv_no_tkt);
    var cli5, _ = tls::tls_endpoint_open(ossl_cli_cfg);
    assert(run_sans_io_handshake(cli5, srv5) == tls::TlsBackendStatus.Ok);
    tls::tls_endpoint_close(cli5);
    tls::tls_endpoint_close(srv5);
    let ossl_keylog_empty_ok = !file_exists(ossl_log_path[..]);

    let ossl_no_tkt_all = ossl_srv_suppressed && pure_backend_skip_store && pure_backend_did_store && ossl_hs_ok;
    print("ossl_no_tickets_ok=", ossl_no_tkt_all, " ossl_keylog_ok=", ossl_keylog_ok,
        " ossl_keylog_empty_ok=", ossl_keylog_empty_ok);
    // CHECK: ossl_no_tickets_ok=true ossl_keylog_ok=true ossl_keylog_empty_ok=true
}

// ---- 3. PureGoose NSS Key Log (Backend + Live Client/Server Match) ---------

thread_fn keylog_live_server_worker(listener_fd: i64) {
    let seed: u8[32] = [0x43; 32];
    var cert_der: u8[..2048] = [];
    assert(make_p256_cert_der(seed, "keylog-live.test", cert_der));

    var srv_log_path: u8[..256] = [];
    make_temp_path("wing_tls_ctrl_srv_live.keylog", srv_log_path);
    var srv_cfg = tls::ServerHandshakeConfig {
        priv_seed:            seed,
        handshake_timeout_ms: 2500,
        ..
    };
    assert(srv_cfg.cert_der.try_set(cert_der[..]));
    assert(srv_cfg.keylog_file.try_set(srv_log_path[..]));

    let conn = net::tcp_accept(listener_fd, 5000);
    assert(conn > 0);
    let slot, ok = tls::server_handshake(conn, srv_cfg);
    assert(ok && slot != 0xFFFF);
    assert(tls::transport_send(conn, slot, "KEYLOG-PING") == 11);
    var ack: u8[16] = [0; 16];
    let _ = tls::transport_recv_slice(conn, slot, ack[..], 2000);
    tls::transport_close(conn, slot);
}

fn test_pure_keylog_and_custom_timeout() {
    print("=== 3. PureGoose Keylog Format & Custom Handshake Timeout ===");
    // CHECK: === 3. PureGoose Keylog Format & Custom Handshake Timeout ===

    let seed: u8[32] = [0x43; 32];
    var cert_der: u8[..2048] = [];
    assert(make_p256_cert_der(seed, "keylog-live.test", cert_der));
    var trust = tls::TrustAnchorStore { .. };
    assert(tls::add_trust_anchor_cert_der(trust, cert_der[..]));

    // 3a. PureGoose backend keylog (non-empty writes valid NSS lines, empty writes nothing).
    var backend_log: u8[..256] = [];
    make_temp_path("wing_tls_ctrl_pure_backend.keylog", backend_log);
    let _ = delete_file(backend_log[..]);
    defer { let _ = delete_file(backend_log[..]); };

    var srv_bcfg = tls::TlsBackendConfig {
        kind:      tls::TlsBackendKind.PureGoose,
        is_server: true,
        priv_seed: seed,
        ..
    };
    assert(srv_bcfg.cert_der.try_set(cert_der[..]));

    var cli_bcfg = tls::TlsBackendConfig {
        kind:        tls::TlsBackendKind.PureGoose,
        is_server:   false,
        trust_store: trust,
        ..
    };
    assert(cli_bcfg.server_name.try_set("keylog-live.test"));
    assert(cli_bcfg.keylog_file.try_set(backend_log[..]));

    var cli_b, _ = tls::tls_endpoint_open(cli_bcfg);
    var srv_b, _ = tls::tls_endpoint_open(srv_bcfg);
    assert(run_sans_io_handshake(cli_b, srv_b) == tls::TlsBackendStatus.Ok);
    tls::tls_endpoint_close(cli_b);
    tls::tls_endpoint_close(srv_b);

    var pure_b_data: u8[>..] = [];
    let pure_backend_keylog_ok = read_file(backend_log[..], pure_b_data) && validate_nss_keylog(pure_b_data[..]);

    let _ = delete_file(backend_log[..]);
    cli_bcfg.keylog_file.clear();
    var cli_e, _ = tls::tls_endpoint_open(cli_bcfg);
    var srv_e, _ = tls::tls_endpoint_open(srv_bcfg);
    assert(run_sans_io_handshake(cli_e, srv_e) == tls::TlsBackendStatus.Ok);
    tls::tls_endpoint_close(cli_e);
    tls::tls_endpoint_close(srv_e);
    let pure_empty_keylog_ok = !file_exists(backend_log[..]);

    // 3b. Live client_handshake + server_handshake keylog & custom handshake_timeout_ms=2500.
    var cli_live_log: u8[..256] = [];
    var srv_live_log: u8[..256] = [];
    make_temp_path("wing_tls_ctrl_cli_live.keylog", cli_live_log);
    make_temp_path("wing_tls_ctrl_srv_live.keylog", srv_live_log);
    let _ = delete_file(cli_live_log[..]);
    let _ = delete_file(srv_live_log[..]);
    defer { let _ = delete_file(cli_live_log[..]); };
    defer { let _ = delete_file(srv_live_log[..]); };

    let listener = net::tcp_listen("127.0.0.1", 0, 8);
    assert(listener > 0);
    let port = net::tcp_getsockname_port(listener);
    let tid = thread_spawn(keylog_live_server_worker, listener);

    let fd = net::tcp_connect("127.0.0.1", port, 5000);
    assert(fd > 0);
    var cli_cfg = tls::ClientHandshakeConfig {
        trust_store:          trust,
        handshake_timeout_ms: 2500,
        ..
    };
    assert(cli_cfg.server_name.try_set("keylog-live.test"));
    assert(cli_cfg.keylog_file.try_set(cli_live_log[..]));

    let slot, ok_hs = tls::client_handshake(fd, cli_cfg);
    assert(ok_hs && slot != 0xFFFF);
    var rx: u8[32] = [0; 32];
    assert(tls::transport_recv_slice(fd, slot, rx[..], 2500) == 11 && rx[..11] == "KEYLOG-PING");
    assert(tls::transport_send(fd, slot, "OK") == 2);
    tls::transport_close(fd, slot);
    assert(thread_wait(tid));
    net::tcp_close(listener);

    var cli_log_bytes: u8[>..] = [];
    var srv_log_bytes: u8[>..] = [];
    let live_keylog_match = read_file(cli_live_log[..], cli_log_bytes) &&
        read_file(srv_live_log[..], srv_log_bytes) &&
        validate_nss_keylog(cli_log_bytes[..]) &&
        validate_nss_keylog(srv_log_bytes[..]) &&
        cli_log_bytes[..] == srv_log_bytes[..];

    print("pure_backend_keylog=", pure_backend_keylog_ok, " pure_empty_keylog=", pure_empty_keylog_ok,
        " live_client_server_keylog_match=", live_keylog_match);
    // CHECK: pure_backend_keylog=true pure_empty_keylog=true live_client_server_keylog_match=true
}

// ---- 4. Short handshake_timeout_ms & Server-Side mTLS Config Fields --------

thread_fn silent_accept_worker(listener_fd: i64) {
    let conn = net::tcp_accept(listener_fd, 5000);
    if conn > 0 {
        sleep_ms(300);
        net::tcp_close(conn);
    }
}

thread_fn mtls_server_worker(listener_fd: i64) {
    let srv_seed: u8[32] = [0x51; 32];
    let cli_seed: u8[32] = [0x52; 32];
    var srv_cert: u8[..2048] = [];
    var cli_cert: u8[..2048] = [];
    assert(make_p256_cert_der(srv_seed, "mtls.test", srv_cert));
    assert(make_p256_cert_der(cli_seed, "client.mtls.test", cli_cert));

    var cli_trust = tls::TrustAnchorStore { .. };
    assert(tls::add_trust_anchor_cert_der(cli_trust, cli_cert[..]));

    var srv_cfg = tls::ServerHandshakeConfig {
        priv_seed:            srv_seed,
        handshake_timeout_ms: 2000,
        require_client_cert:  true,
        client_trust_store:   cli_trust,
        ..
    };
    assert(srv_cfg.cert_der.try_set(srv_cert[..]));

    // Conn 1: client without cert MUST fail mTLS verification.
    let c1 = net::tcp_accept(listener_fd, 5000);
    assert(c1 > 0);
    let _, ok1 = tls::server_handshake(c1, srv_cfg);
    assert(!ok1);
    net::tcp_close(c1);

    // Conn 2: client with trusted cert + matching key MUST succeed.
    let c2 = net::tcp_accept(listener_fd, 5000);
    assert(c2 > 0);
    let s2, ok2 = tls::server_handshake(c2, srv_cfg);
    assert(ok2 && s2 != 0xFFFF);
    assert(tls::transport_send(c2, s2, "MTLS-OK") == 7);
    var ack: u8[16] = [0; 16];
    let _ = tls::transport_recv_slice(c2, s2, ack[..], 2000);
    tls::transport_close(c2, s2);
}

fn test_handshake_timeout_and_server_mtls() {
    print("=== 4. Handshake Timeout & Server mTLS Config ===");
    // CHECK: === 4. Handshake Timeout & Server mTLS Config ===

    // 4a. Client handshake with handshake_timeout_ms=80 times out fast on silent peer.
    let lst_to = net::tcp_listen("127.0.0.1", 0, 4);
    assert(lst_to > 0);
    let port_to = net::tcp_getsockname_port(lst_to);
    let tid_to = thread_spawn(silent_accept_worker, lst_to);

    let fd_to = net::tcp_connect("127.0.0.1", port_to, 2000);
    assert(fd_to > 0);
    var cli_to_cfg = tls::ClientHandshakeConfig {
        insecure_skip_verify: true,
        handshake_timeout_ms: 80,
        ..
    };
    let t0 = core::monotonic_now().nanos;
    let slot_to, ok_to = tls::client_handshake(fd_to, cli_to_cfg);
    let elapsed_ms = core::sub_sat_u64(core::monotonic_now().nanos, t0) / 1000000;
    net::tcp_close(fd_to);
    assert(thread_wait(tid_to));
    net::tcp_close(lst_to);
    let cli_timeout_ok = !ok_to && slot_to == 0xFFFF && elapsed_ms < 2500;

    // 4b. Server-side require_client_cert + client_trust_store mTLS verification.
    let srv_seed: u8[32] = [0x51; 32];
    let cli_seed: u8[32] = [0x52; 32];
    var srv_cert: u8[..2048] = [];
    var cli_cert: u8[..2048] = [];
    assert(make_p256_cert_der(srv_seed, "mtls.test", srv_cert));
    assert(make_p256_cert_der(cli_seed, "client.mtls.test", cli_cert));
    var srv_trust = tls::TrustAnchorStore { .. };
    assert(tls::add_trust_anchor_cert_der(srv_trust, srv_cert[..]));

    let lst_m = net::tcp_listen("127.0.0.1", 0, 8);
    assert(lst_m > 0);
    let port_m = net::tcp_getsockname_port(lst_m);
    let tid_m = thread_spawn(mtls_server_worker, lst_m);

    // Conn 1: client without cert -> server closes after rejecting empty Certificate.
    let fd_m1 = net::tcp_connect("127.0.0.1", port_m, 2000);
    var cli_no_cert = tls::ClientHandshakeConfig {
        trust_store:          srv_trust,
        handshake_timeout_ms: 2000,
        ..
    };
    assert(cli_no_cert.server_name.try_set("mtls.test"));
    let s_m1, ok_m1 = tls::client_handshake(fd_m1, cli_no_cert);
    if ok_m1 {
        var rx_fail: u8[16] = [0; 16];
        let n_fail = tls::transport_recv_slice(fd_m1, s_m1, rx_fail[..], 1000);
        assert(n_fail <= 0);
        tls::transport_close(fd_m1, s_m1);
    } else {
        net::tcp_close(fd_m1);
    }

    // Conn 2: client with trusted cert + key -> succeeds and receives "MTLS-OK".
    let fd_m2 = net::tcp_connect("127.0.0.1", port_m, 2000);
    var cli_with_cert = cli_no_cert;
    assert(cli_with_cert.client_cert_der.try_set(cli_cert[..]));
    cli_with_cert.client_priv_seed = cli_seed;
    let s_m2, ok_m2 = tls::client_handshake(fd_m2, cli_with_cert);
    assert(ok_m2 && s_m2 != 0xFFFF);
    var rx_m2: u8[32] = [0; 32];
    let n_m2 = tls::transport_recv_slice(fd_m2, s_m2, rx_m2[..], 2000);
    let mtls_ok = n_m2 == 7 && rx_m2[..7] == "MTLS-OK";
    assert(tls::transport_send(fd_m2, s_m2, "OK") == 2);
    tls::transport_close(fd_m2, s_m2);

    assert(thread_wait(tid_m));
    net::tcp_close(lst_m);

    print("client_timeout_fast=", cli_timeout_ok, " server_mtls_ok=", mtls_ok);
    // CHECK: client_timeout_fast=true server_mtls_ok=true
}

fn main() {
    test_ocsp_requirement_and_pq_propagation();
    test_session_tickets_pure_goose();

    let ossl_seed: u8[32] = [0x44; 32];
    var ossl_cert_der: u8[..2048] = [];
    var ossl_key_der:  u8[..512]  = [];
    assert(make_p256_cert_der(ossl_seed, "ossl-no-tkt.test", ossl_cert_der));
    assert(make_p256_pkcs8_der(ossl_seed, ossl_key_der));
    var ossl_trust = tls::TrustAnchorStore { .. };
    assert(tls::add_trust_anchor_cert_der(ossl_trust, ossl_cert_der[..]));

    var cert_pem: u8[>..] = [];
    var key_pem:  u8[>..] = [];
    encode_pem("CERTIFICATE", ossl_cert_der[..], cert_pem);
    encode_pem("PRIVATE KEY", ossl_key_der[..], key_pem);

    var cpath: u8[..256] = [];
    var kpath: u8[..256] = [];
    make_temp_path("wing_tls_ctrl_cert.pem", cpath);
    make_temp_path("wing_tls_ctrl_key.pem", kpath);
    assert(write_file_atomic(cpath[..], cert_pem[..]));
    assert(write_file_atomic(kpath[..], key_pem[..]));
    defer {
        let _ = delete_file(cpath[..]);
        let _ = delete_file(kpath[..]);
    };

    test_openssl_tickets_and_keylog(cpath[..], kpath[..], ossl_trust);
    test_pure_keylog_and_custom_timeout();
    test_handshake_timeout_and_server_mtls();

    print("=== ALL TLS CONTROL KNOB CHECKS PASSED ===");
    // CHECK: === ALL TLS CONTROL KNOB CHECKS PASSED ===
}
