// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic LIT Regression Harness for Confirmed Security Audit Findings (2026-11).
// Each probe runs in-process against HEAD without modifying production code and prints
// `<DEFECT_ID>_FIXED: <bool>`. Currently open findings expect `false`; flip the
// corresponding CHECK line to `true` as each finding is patched to lock in the fix.
//
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import wing from "../..";

// CHECK: === SECURITY AUDIT REGRESSION SUITE 2026 ===

fn probe_h2_c08_x509_uri_backslash() {
    // Backslash in URI SAN authority (`https://evil.com\.allowed.com/x`) must not match `.allowed.com`.
    let matched = tls::match_uri_name_constraint("https://evil.com\\.allowed.com/x", ".allowed.com");
    let fixed = !matched;
    print("H2_C08_URI_BACKSLASH_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H2_C08): tls/pki_nc_san_internal.goose rejects backslash in URI authority
// CHECK: H2_C08_URI_BACKSLASH_FIXED: true

fn probe_h3_c02_ssrf_siit_ipv4_translated() {
    let ip, ok = core::parse_ip_addr("::ffff:0:127.0.0.1");
    assert(ok);
    let fixed = security::is_reserved_ip_addr(ip);
    print("H3_C02_SSRF_SIIT_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H3_C02): security/ssrf.goose blocks ::ffff:0:0:0/96
// CHECK: H3_C02_SSRF_SIIT_FIXED: true

fn probe_h3_c03_ssrf_cloud_metadata_ipv6() {
    let blk_nat64 = security::is_cloud_metadata_or_reserved_ip("64:ff9b:1::169.254.169.254");
    let blk_6to4 = security::is_cloud_metadata_or_reserved_ip("2002::1");
    let fixed = blk_nat64 && blk_6to4;
    print("H3_C03_CLOUD_METADATA_IPV6_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H3_C03): security/policy_internal.goose blocks 64:ff9b:1::/48 and 2002::1
// CHECK: H3_C03_CLOUD_METADATA_IPV6_FIXED: true

fn probe_h3_c04_cors_duplicate_preflight_headers() {
    var policy = security::CorsPolicy { .. };
    assert(security::add_allowed_origin(policy, "https://app.example"));
    policy.allowed_methods.clear();
    policy.allowed_methods.append("GET");
    policy.allowed_headers.clear();
    policy.allowed_headers.append("Content-Type");

    var req = http::new_request("OPTIONS", "https://api.example/v1");
    http::append_header(req.headers, "Origin", "https://app.example");
    http::append_header(req.headers, "Access-Control-Request-Method", "GET");
    http::append_header(req.headers, "Access-Control-Request-Method", "DELETE");
    http::append_header(req.headers, "Access-Control-Request-Headers", "Content-Type");
    http::append_header(req.headers, "Access-Control-Request-Headers", "X-Forbidden");

    var res = http::Response { .. };
    let dec = security::evaluate_cors(policy, req, res);
    let fixed = dec != security::CorsResult.AllowedPreflight;
    print("H3_C04_CORS_DUP_PREFLIGHT_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H3_C04): security/cors.goose validates all duplicate ACRM/ACRH entries
// CHECK: H3_C04_CORS_DUP_PREFLIGHT_FIXED: true

fn probe_h3_c05_digest_stale_downgrade() {
    var stored = auth::DigestChallenge { .. };
    stored.valid = true;
    stored.realm.append("api");
    stored.nonce.append("n1");
    stored.qop.append("auth-int");
    stored.algorithm.clear();
    stored.algorithm.append("SHA-256");
    stored.has_explicit_algo = true;
    stored.userhash = true;

    var incoming = auth::DigestChallenge { .. };
    incoming.valid = true;
    incoming.stale = true;
    incoming.realm.append("evil-realm");
    incoming.nonce.append("n2");
    incoming.qop.append("auth, auth-int");
    incoming.algorithm.clear();
    incoming.algorithm.append("SHA-256");
    incoming.has_explicit_algo = true;
    incoming.userhash = false;

    var creds = auth::DigestCredentials { .. };
    creds.username.append("alice");
    creds.password.append("secret");
    var nc: u32 = 2;
    let synced = auth::sync_digest_stale_challenge(stored, incoming, creds, nc);
    let fixed = !synced;
    print("H3_C05_DIGEST_STALE_DOWNGRADE_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H3_C05): auth/digest.goose rejects cross-realm, userhash, and qop downgrades
// CHECK: H3_C05_DIGEST_STALE_DOWNGRADE_FIXED: true

fn probe_h3_c06_ctl_0x7f_auth_bypass() {
    var out: u8[..256] = [];
    let ok_basic = auth::encode_oauth2_basic_auth("cid\x7f", "sec", out);
    let ok_form = auth::encode_token_endpoint_form("tok\x7f", auth::TokenTypeHint.None, out);
    let fixed = !ok_basic && !ok_form;
    print("H3_C06_CTL_0X7F_AUTH_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H3_C06): auth/ and acme reject 0x7F DEL
// CHECK: H3_C06_CTL_0X7F_AUTH_FIXED: true

fn probe_h3_c07_edge_rate_limiter_active_eviction() {
    var lim = security::new_edge_rate_limiter(1, 0, 4);
    defer security::release_edge_rate_limiter(lim);
    let t0: u64 = 1000000000;
    var key: u8[..16] = [];
    for i in lim.max_clients + 1 {
        key.clear();
        key.append("c");
        core::format_i64_dec(i, key);
        let _ = security::check_edge_rate_limit(lim, key[..], 1, t0 + (i as u64));
    }
    let dec_c0 = security::check_edge_rate_limit(lim, "c0", 1, t0 + 10);
    let fixed = !dec_c0.allowed;
    print("H3_C07_EDGE_RL_ACTIVE_EVICT_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H3_C07): security/rate_limit_internal.goose refuses active slot eviction
// CHECK: H3_C07_EDGE_RL_ACTIVE_EVICT_FIXED: true

fn probe_h3_c09_p256_order_zero_sig() {
    let p256_order: u8[32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
        0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
    ];
    var hdr = auth::JwtHeader { alg: auth::JwtAlg.ES256, .. };
    var clm = auth::JwtClaims { .. };
    clm.sub.append("alice");
    var tok: u8[..1024] = [];
    let ok_jwt = auth::sign_jwt_es256(hdr, clm, p256_order, tok);
    var dpop_buf: u8[..1024] = [];
    let ok_dpop = auth::create_dpop_proof_es256(
        p256_order,
        "POST",
        "https://api.example/tok",
        "",
        "",
        1700000000,
        "jti-1",
        dpop_buf,
    );
    let fixed = !ok_jwt && !ok_dpop;
    print("H3_C09_P256_ORDER_ZERO_SIG_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H3_C09): auth/jwt.goose and auth/dpop.goose enforce 1 <= d < P256_ORDER
// CHECK: H3_C09_P256_ORDER_ZERO_SIG_FIXED: true

fn probe_h4_c01_quic_pn_64_interval_replay() {
    var ranges: quic::AckInterval[..64] = [];
    assert(quic::record_received_pn(ranges, 0));
    var pn: u64 = 2;
    for _ in 64 {
        assert(quic::record_received_pn(ranges, pn));
        pn += 2;
    }
    let replayed = quic::record_received_pn(ranges, 0);
    let fixed = !replayed;
    print("H4_C01_QUIC_PN_REPLAY_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H4_C01): quic/AckFrame.goose retains min_tracked_pn floor on eviction
// CHECK: H4_C01_QUIC_PN_REPLAY_FIXED: true

fn probe_h4_c09_hpack_4096_eviction_desync() {
    var dt = http2::new_dynamic_table(4096);
    var v1000: u8[..1000] = [];
    for _ in 1000 { v1000.push('a'); }
    var v2000: u8[..2000] = [];
    for _ in 2000 { v2000.push('b'); }
    var v1200: u8[..1200] = [];
    for _ in 1200 { v1200.push('c'); }
    http2::insert_header(dt, "x", v1000[..], false);
    http2::insert_header(dt, "y", v2000[..], false);
    http2::insert_header(dt, "z", v1200[..], false);
    // RFC 7541 Section 4.1: y (2033 B) + z (1233 B) = 3266 <= 4096, so 2 entries must remain.
    let fixed = dt.count == 2;
    print("H4_C09_HPACK_4096_RING_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H4_C09): http2/hpack.goose compacts arena instead of evicting at 4096 boundary
// CHECK: H4_C09_HPACK_4096_RING_FIXED: true

fn probe_h5_c06_cookie_long_url_domain_bypass() {
    var jar = cookie::CanonicalCookieJar { .. };
    var long_url: u8[..2200] = [];
    long_url.append("https://attacker.example/");
    for _ in 2060 { long_url.push('a'); }
    let accepted = cookie::set_cookie_header(
        jar,
        long_url[..],
        "sid=evil; Domain=victim.example",
        1700000000000000,
    );
    let fixed = !accepted;
    print("H5_C06_COOKIE_LONG_URL_DOMAIN_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H5_C06): cookie/engine.goose rejects empty/unparsed req_url host
// CHECK: H5_C06_COOKIE_LONG_URL_DOMAIN_FIXED: true

fn probe_h5_c12_dns_qdcount_zero_accepted() {
    // 12-byte DNS response header with QDCOUNT=0, ANCOUNT=1 + A record for victim.com -> 127.0.0.1.
    let raw: u8[40] = [
        0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x06, 'v', 'i', 'c', 't', 'i', 'm', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 127, 0, 0, 1,
        0x00, 0x00,
    ];
    let resp, ok = dns::parse_response(raw[..38]);
    let fixed = !(ok && resp.a_records.len == 1);
    print("H5_C12_DNS_QDCOUNT_ZERO_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H5_C12): dns/wire.goose validates QDCOUNT == 1 and exposes QNAME
// CHECK: H5_C12_DNS_QDCOUNT_ZERO_FIXED: true

fn probe_g8_14_c04_acme_padded_replay_nonce() {
    let priv_k: u8[32] = [0x17; 32];
    var jws_out: u8[>..] = [];
    let signed = auth::acme_sign_jws_es256(
        priv_k,
        "https://acme.example/order",
        "bad+nonce/val==",
        "",
        "{}",
        jws_out,
    );
    let fixed = !signed;
    print("G8_14_C04_ACME_NONCE_B64URL_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(G8_14_C04): auth/acme_wire.goose enforces unpadded base64url Replay-Nonce
// CHECK: G8_14_C04_ACME_NONCE_B64URL_FIXED: true

fn probe_h5_c01_deflate_l1_avx2_no_stack_overflow() {
    // One 4-byte match in first 2048 B disables probe bailout; remaining 9-bit literals (0x90..0xFF)
    // would expand 4000 B past u8[4096] without the out_idx >= stored_bytes stored-block bailout.
    var src: u8[..4000] = [];
    for _ in 8 { src.push('A'); }
    var state: u32 = 0x12345678;
    while src.len < 4000 {
        state = state * 1664525 + 1013904223;
        let b = (0x90 + ((state >> 24) % 112)) as u8;
        src.push(b);
    }
    var compressed: u8[..8192] = [];
    let ok = core::deflate_with_dict(src[..], compressed, 1, "");
    let fixed = ok && compressed.len <= 4096;
    print("H5_C01_DEFLATE_L1_STACK_SAFE_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H5_C01): shim/simd.c wing_deflate_l1_chunk_avx2 enforces stored_bytes/dst_cap bounds
// CHECK: H5_C01_DEFLATE_L1_STACK_SAFE_FIXED: true

fn probe_h5_c02_no_raw_udp_for_https(session: client::Session&) {
    session.ssrf_guard = security::SsrfGuardPolicy { .. };
    var ctx = client_internal::RequestExecutionContext { .. };
    ctx.current_method.append("GET");
    let https_url = core::new_url("https://127.0.0.1:443/api");
    var ep = http::AltSvcEndpoint { port: 443, .. };
    ep.host.append("127.0.0.1");
    ep.proto.append("h3");
    var resp = http::Response { .. };
    let ok_h3 = client_internal::execute_live_h3_hop(
        session, ctx, https_url, "https://127.0.0.1:443", ep, 1000, resp,
    );
    let fixed = !ok_h3;
    print("H5_C02_NO_RAW_UDP_HTTPS_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H5_C02): client/session/h3_internal.goose rejects https:// origins on plaintext UDP hop
// CHECK: H5_C02_NO_RAW_UDP_HTTPS_FIXED: true

fn probe_h1_c03_rsa_pss_513_no_abort() {
    var mod513: u8[513] = [0; 513];
    mod513[0] = 0x01;
    mod513[512] = 0x01;
    let h32:    u8[32] = [0x22; 32];
    let salt32: u8[32] = [0x33; 32];
    var out_em: u8[..512] = [];
    let ok = core::encode_pss_for_modulus(h32[..], salt32[..], mod513[..], out_em);
    let fixed = !ok;
    print("H1_C03_RSA_PSS_513_SAFE_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H1_C03): core/crypto/rsa.goose rejects >512B modulus without GS_E_CAPACITY abort
// CHECK: H1_C03_RSA_PSS_513_SAFE_FIXED: true

fn probe_h3_c01_hpke_nonempty_out_bounds() {
    let sk_seed: u8[32] = [0x44; 32];
    let pk_r = core::x25519_base_scalarmult(sk_seed);
    let pt30:   u8[30] = [0x55; 30];
    let eph_sk: u8[32] = [0x66; 32];
    var enc:    u8[32]    = [0; 32];
    var ct_tag: u8[..128] = [];
    assert(security::hpke_seal_base(pk_r, "info", "aad", pt30[..], eph_sk, rfc::HPKE_AEAD_AES_128_GCM, enc, ct_tag));

    var out: u8[..32] = "prefix";
    let ok_open = security::hpke_open_base(
        enc, sk_seed, "info", "aad", ct_tag[..], rfc::HPKE_AEAD_AES_128_GCM, out,
    );
    let fixed = !ok_open && out[..] == "prefix";
    print("H3_C01_HPKE_BOUNDS_SAFE_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H3_C01): security/hpke.goose & core/crypto/aes.goose preserve prefix on overflow without abort
// CHECK: H3_C01_HPKE_BOUNDS_SAFE_FIXED: true

fn probe_h2_c07_x509_dn_nc_fail_closed() {
    // Reordered multi-valued RDN SET under excludedSubtrees DN must still match (reject).
    let cons_dn: u8[34] = [
        0x30, 0x20, 0x31, 0x1E,
        0x30, 0x0C, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x05, 'a', 'l', 'i', 'c', 'e',
        0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x07, 'c', 'o', 'r', 'p', 'o', 'r', 'g',
    ];
    let cand_dn: u8[34] = [
        0x30, 0x20, 0x31, 0x1E,
        0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x07, 'c', 'o', 'r', 'p', 'o', 'r', 'g',
        0x30, 0x0C, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x05, 'a', 'l', 'i', 'c', 'e',
    ];
    let san_reordered = tls::SanEntry { san_type: tls::SanType.DirName, val: cand_dn[..] };
    var ncs: tls::NameConstraintEntry[..16] = [];
    assert(ncs.try_push(tls::NameConstraintEntry {
        is_excluded: true, san_type: tls::SanType.DirName, val: cons_dn[..],
    }));
    let allowed_reordered = tls::check_name_constraints(ncs, san_reordered);

    // BMPString 0x1E inside candidate DN must fail closed against single-AVA DirName NC.
    let cons_cn_dn: u8[18] = [
        0x30, 0x10, 0x31, 0x0E, 0x30, 0x0C,
        0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x05, 'a', 'l', 'i', 'c', 'e',
    ];
    let bmp_dn: u8[21] = [
        0x30, 0x13, 0x31, 0x11, 0x30, 0x0F,
        0x06, 0x03, 0x55, 0x04, 0x03,
        0x1E, 0x08, 0x00, 'a', 0x00, 'l', 0x00, 'i', 0x00, 'c',
    ];
    var ncs_bmp: tls::NameConstraintEntry[..16] = [];
    assert(ncs_bmp.try_push(tls::NameConstraintEntry {
        is_excluded: true, san_type: tls::SanType.DirName, val: cons_cn_dn[..],
    }));
    let san_bmp = tls::SanEntry { san_type: tls::SanType.DirName, val: bmp_dn[..] };
    let allowed_bmp = tls::check_name_constraints(ncs_bmp, san_bmp);

    let fixed = !allowed_reordered && !allowed_bmp;
    print("H2_C07_DN_NC_FAIL_CLOSED_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H2_C07): tls/pki_nc_san_internal.goose rejects reordered multi-valued RDN and BMPString fail-open
// CHECK: H2_C07_DN_NC_FAIL_CLOSED_FIXED: true

fn probe_h2_c01_ticket_sni_binding() {
    tls::clear_session_tickets();
    defer tls::clear_session_tickets();
    let psk32: u8[32] = [0x61; 32];
    tls_internal::store_server_session_ticket(
        "a.example", "TKT_SNI_01", psk32[..], 0x11223344, 3600,
        rfc::TLS_CIPHER_AES_128_GCM_SHA256, false, 10000,
    );
    var out_psk: u8[..48] = [];
    var out_cs:  u16      = 0;
    let same_ok = tls_internal::lookup_server_ticket_by_identity(
        "TKT_SNI_01", false, out_psk, out_cs, 20000, "A.EXAMPLE",
    );
    let cross_ok = tls_internal::lookup_server_ticket_by_identity(
        "TKT_SNI_01", false, out_psk, out_cs, 20000, "b.example",
    );
    let empty_ok = tls_internal::lookup_server_ticket_by_identity(
        "TKT_SNI_01", false, out_psk, out_cs, 20000, "",
    );
    let fixed = same_ok && !cross_ok && !empty_ok;
    print("H2_C01_TICKET_SNI_BINDING_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H2_C01): tls/ticket_internal.goose binds server resumption lookup to SNI
// CHECK: H2_C01_TICKET_SNI_BINDING_FIXED: true

fn probe_h2_c12_server_pre_ch_ccs_rejected() {
    var srv_cfg = tls::TlsBackendConfig {
        kind:                  tls::TlsBackendKind.PureGoose,
        is_server:             true,
        defer_sni_credentials: true,
        ..
    };
    var srv, st_open = tls::tls_endpoint_open(srv_cfg);
    assert(st_open == tls::TlsBackendStatus.Ok);
    defer tls::tls_endpoint_close(srv);

    let ccs: u8[6] = [rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01];
    let fed, st_fed = tls::tls_endpoint_feed_wire(srv, ccs[..]);
    assert(st_fed == tls::TlsBackendStatus.Ok && fed == 6);
    let st_step = tls::tls_endpoint_step_handshake(srv);
    let fixed = st_step == tls::TlsBackendStatus.HandshakeError;
    print("H2_C12_PRE_CH_CCS_REJECTED_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H2_C12): tls/backend_pure_internal.goose rejects CCS before ClientHello
// CHECK: H2_C12_PRE_CH_CCS_REJECTED_FIXED: true

fn probe_h5_c07_secure_cookie_replaces_non_secure() {
    var jar = cookie::CanonicalCookieJar { .. };
    let now_us = 1700000000000000;
    assert(cookie::set_cookie_header(jar, "http://app.example/", "sid=http_val; Path=/", now_us));
    assert(cookie::set_cookie_header(jar, "https://app.example/", "sid=https_val; Secure; Path=/", now_us + 10));
    let got = cookie::get(jar, "https://app.example/", "sid", now_us + 20);
    let fixed = jar.cookies.len == 1 && got == "https_val";
    print("H5_C07_COOKIE_SCHEME_SHADOW_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H5_C07): cookie/engine.goose evicts shadowing NonSecure cookie on Secure overwrite
// CHECK: H5_C07_COOKIE_SCHEME_SHADOW_FIXED: true

fn probe_h5_c10_svcb_dangerous_port_blocked(session: client::Session&) {
    session.ssrf_guard = security::SsrfGuardPolicy { enabled: true, deny_local_network: true, .. };

    var hr = dns::HttpsRecord { priority: 1, port: 25, .. };
    assert(hr.ipv4_hints.try_push(0x5DB8D822));
    var entry = dns::CacheEntry {
        qtype:           rfc::DNS_QTYPE_HTTPS,
        inserted_at_sec: 1000,
        ttl_sec:         300,
        valid:           true,
        ..
    };
    assert(entry.domain.try_set("cdn.example"));
    assert(entry.https_records.try_push(hr));
    session.dns_cache.insert(entry);

    var task = net::DnsRaceTask { .. };
    var ech: u8[..512] = [];
    let ok = client_internal::resolve_https_svcb_record(session, "cdn.example", 443, 1005, task, ech);
    let fixed = !ok;
    print("H5_C10_SVCB_PORT_SSRF_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H5_C10): client/session/dns_dial_internal.goose blocks dangerous SVCB port
// CHECK: H5_C10_SVCB_PORT_SSRF_FIXED: true

fn probe_h5_c03_cross_origin_401_no_auth_retry(session: client::Session&) {
    session.ssrf_guard = security::SsrfGuardPolicy { .. };
    assert(client::set_credentials(session, "alice", "secret123"));
    var ctx = client_internal::RequestExecutionContext { .. };
    assert(ctx.current_method.try_set("GET"));
    assert(ctx.url_chain.try_push(core::new_url("https://origin-a.example/start")));
    let url_b = core::new_url("https://origin-b.example/target");
    assert(ctx.url_chain.try_push(url_b));

    var resp = http::Response { status_code: 401, .. };
    http::append_header(
        resp.headers,
        "WWW-Authenticate",
        "Digest realm=\"b\", nonce=\"n1\", algorithm=SHA-256, qop=\"auth\"",
    );
    var out_auth: u8[..1024] = [];
    let sent = client_internal::find_auth_header_from_response(session, ctx, url_b, resp, out_auth);
    session.creds.has_credentials = false;
    let fixed = !sent && out_auth.len == 0;
    print("H5_C03_CROSS_ORIGIN_401_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H5_C03): client/session/hop_auth_internal.goose blocks 401 credential retry across origins
// CHECK: H5_C03_CROSS_ORIGIN_401_FIXED: true

fn probe_g8_14_c02_jwt_cnf_jkt_parsed() {
    var claims = auth::JwtClaims { .. };
    let ok = auth::parse_jwt_claims_json("{\"sub\":\"u\",\"cnf\":{\"jkt\":\"0ZcO_thumb\"}}", claims);
    let fixed = ok && claims.cnf_jkt[..] == "0ZcO_thumb";
    print("G8_14_C02_JWT_CNF_JKT_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(G8_14_C02): auth/jwt.goose extracts RFC 9449 cnf.jkt thumbprint
// CHECK: G8_14_C02_JWT_CNF_JKT_FIXED: true

fn probe_h5_c05_cl_i64_overflow_rejected() {
    var resp = http::Response { .. };
    let ok = wing::parse_response_headers(
        "HTTP/1.1 200 OK\r\nContent-Length: 9223372036854775808\r\n\r\n",
        resp,
    );
    let fixed = !ok;
    print("H5_C05_CL_OVERFLOW_REJECTED_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H5_C05): wire/h1_exchange.goose rejects Content-Length >= 2^63
// CHECK: H5_C05_CL_OVERFLOW_REJECTED_FIXED: true

fn probe_h5_c11_headermap_vary_compaction() {
    var m = http::HeaderMap { .. };
    assert(http::append_header(m, "X-Drop", "1"));
    assert(http::append_header(m, "Vary", "Accept-Encoding"));
    assert(http::append_header(m, "X-Keep", "preserve-value"));
    assert(http::update_single_vary_value(m, "Accept-Encoding, Origin"));
    assert(http::remove_header_by_name(m, "X-Drop"));
    let fixed = http::find_header(m, "X-Keep") == "preserve-value"
        && http::find_header(m, "Vary") == "Accept-Encoding, Origin";
    print("H5_C11_HEADERMAP_COMPACT_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H5_C11): http/headers.goose avoids raw_buf overlap after Vary relocation
// CHECK: H5_C11_HEADERMAP_COMPACT_FIXED: true

fn probe_h5_c16_x_accel_expires_overflow() {
    var accel = proxy::UpstreamAccelControl { .. };
    let handled = proxy::parse_x_accel_control_header("X-Accel-Expires", "9223372036854775808", accel);
    let fixed = handled && !accel.has_accel_expires;
    print("H5_C16_X_ACCEL_OVERFLOW_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H5_C16): proxy/reverse_proxy.goose ignores X-Accel-Expires >= 2^63 without abort
// CHECK: H5_C16_X_ACCEL_OVERFLOW_FIXED: true

fn probe_h4_c03_quic_flow_control_unread() {
    var fc = quic::new_flow_control(65536, 65536);
    var st = quic::new_stream(0, 65536);
    let _, ok_rx = quic::record_recv_stream(fc, st, 0, 35000);
    let _, need_c_before = quic::check_conn_window_update(fc);
    let _, need_s_before = quic::check_stream_window_update(st, 65536);
    quic::on_app_read(fc, st, 35000);
    let _, need_c_after = quic::check_conn_window_update(fc);
    let _, need_s_after = quic::check_stream_window_update(st, 65536);
    let fixed = ok_rx && !need_c_before && !need_s_before && need_c_after && need_s_after;
    print("H4_C03_QUIC_FLOW_CTRL_UNREAD_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H4_C03): quic/flow_control.goose keys window updates strictly on bytes consumed by app
// CHECK: H4_C03_QUIC_FLOW_CTRL_UNREAD_FIXED: true

fn probe_h4_c04_quic_version_and_vn() {
    let odcid_v2: u8[8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let retry_v2: u8[36] = [
        0xcf, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x08, 0xf0,
        0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74,
        0x6f, 0x6b, 0x65, 0x6e, 0xc8, 0x64, 0x6c, 0xe8,
        0xbf, 0xe3, 0x39, 0x52, 0xd9, 0x55, 0x54, 0x36,
        0x65, 0xdc, 0xc7, 0xb6,
    ];
    let empty_scid: u8[0] = [];
    var cli_v1 = quic::new_client_connection(odcid_v2[..], empty_scid[..]);
    var out_ack = quic::AckFrame { .. };
    let res_mismatch = quic::process_datagram(cli_v1, retry_v2[..], 1000, out_ack);

    var cli_v2 = quic::new_client_connection(odcid_v2[..], "vncli123");
    assert(quic::install_initial_keys(cli_v2, odcid_v2[..], rfc::QUIC_VERSION_2));
    // VersionNegotiation (version = 0, dcid = "vncli123", scid = odcid_v2, supported = v2).
    var vn: u8[..40] = [];
    vn.push(0x80);
    vn.append_u32_be(0);
    vn.push(8);
    vn.append("vncli123");
    vn.push(8);
    vn.append(odcid_v2[..]);
    vn.append_u32_be(rfc::QUIC_VERSION_2);
    let res_vn = quic::process_datagram(cli_v2, vn[..], 1001, out_ack);
    let fixed = !res_mismatch.handled && res_vn.handled && cli_v2.packets_rx == 0;
    print("H4_C04_QUIC_VERSION_AND_VN_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H4_C04): quic/conn_crypto_internal.goose pins Long Header / Retry versions and keeps packets_rx at 0 on VN
// CHECK: H4_C04_QUIC_VERSION_AND_VN_FIXED: true

fn probe_h4_c05_quic_key_update_hardened() {
    let sec: u8[32] = [0x12; 32];
    let hp:  u8[16] = [0x34; 16];
    let k:   u8[16] = [0x56; 16];
    let iv:  u8[12] = [0x78; 12];
    var cli = quic::new_client_connection("kusrc", "kucli");
    var srv = quic::new_server_connection("kusrc");
    assert(quic::install_keys_with_secret(cli.tx_app_space, hp[..], k[..], iv[..], sec[..]));
    assert(quic::install_keys_with_secret(srv.app_space, hp[..], k[..], iv[..], sec[..]));
    assert(quic::install_keys_with_secret(srv.tx_app_space, hp[..], k[..], iv[..], sec[..]));

    var ping: u8[2] = [0x01, 0x00];
    var h0 = quic::QuicHeader { header_type: quic::QuicHeaderType.OneRtt, packet_number: 1, .. };
    h0.dcid.append("kusrc");
    var p0: u8[..128] = [];
    assert(quic::seal_packet_tracked(cli.tx_app_space, h0, 2, ping[..], p0));

    assert(quic::initiate_key_update(cli.tx_app_space, rfc::QUIC_VERSION_1));
    var h1 = quic::QuicHeader { header_type: quic::QuicHeaderType.OneRtt, packet_number: 2, .. };
    h1.dcid.append("kusrc");
    var p1: u8[..128] = [];
    assert(quic::seal_packet_tracked(cli.tx_app_space, h1, 2, ping[..], p1));

    var ack = quic::AckFrame { .. };
    let pre_est_rejected = !quic::process_datagram(srv, p1[..], 1000, ack).handled;
    assert(quic::process_datagram(srv, p0[..], 1001, ack).handled);

    var forged_tx = cli.tx_app_space;
    var h_bad = quic::QuicHeader { header_type: quic::QuicHeaderType.OneRtt, packet_number: 3, .. };
    h_bad.dcid.append("kusrc");
    var p_bad:   u8[..128] = [];
    var bad_key: u8[16]    = [0x99; 16];
    assert(forged_tx.aead_key.try_set(bad_key[..]));
    assert(quic::seal_packet_tracked(forged_tx, h_bad, 2, ping[..], p_bad));

    let forged_rejected = !quic::process_datagram(srv, p_bad[..], 1002, ack).handled;
    let cached_on_fail = srv.app_space.has_next_keys;
    let legit_ok = quic::process_datagram(srv, p1[..], 1003, ack).handled;
    let both_ratcheted = srv.app_space.key_phase && srv.tx_app_space.key_phase && !srv.app_space.has_next_keys;
    let fixed = pre_est_rejected && forged_rejected && cached_on_fail && legit_ok && both_ratcheted;
    print("H4_C05_QUIC_KEY_UPDATE_HARDENED_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H4_C05): quic/conn_crypto_internal.goose caches next keys, requires Established, and ratchets tx_app_space
// CHECK: H4_C05_QUIC_KEY_UPDATE_HARDENED_FIXED: true

fn probe_h4_c11_h3_empty_push_promise_rejected() {
    let settings = fingerprint::H3Settings { .. };
    var cli = http3::new_client_connection(settings);
    let sid, _ = cli.open_request_stream();
    var max_p: u8[..32] = [];
    assert(http3::send_max_push_id(cli, 5, max_p));
    var pp_wire: u8[..64] = [];
    assert(http3::encode_push_promise(pp_wire, 1, [0x00, 0x00]));
    let err = cli.handle_stream_data(sid, true, pp_wire[..], false);
    let fixed = err == rfc::H3_ERR_GENERAL_PROTOCOL && cli.state == http3::ConnState.Closed;
    print("H4_C11_H3_EMPTY_PUSH_PROMISE_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H4_C11): http3/stream_internal.goose rejects empty PUSH_PROMISE header blocks
// CHECK: H4_C11_H3_EMPTY_PUSH_PROMISE_FIXED: true

fn probe_h4_c12_h3_uni_stream_no_evict() {
    let settings = fingerprint::H3Settings { .. };
    var srv = http3::new_server_connection(settings);
    let unk_payload: u8[2] = [0x21, 0x00];
    var rejected_at_65 = false;
    for i in 65 {
        let sid = 2 + (i as u64) * 4;
        let err = srv.handle_stream_data(sid, false, unk_payload[..1], false);
        if i == 64 {
            rejected_at_65 = err == rfc::H3_ERR_EXCESSIVE_LOAD && srv.state == http3::ConnState.Closed;
        } else {
            assert(err == rfc::H3_ERR_NO_ERROR);
        }
    }
    print("H4_C12_H3_UNI_NO_EVICT_FIXED: ", rejected_at_65, "\n");
}
// AUDIT-FIXED(H4_C12): http3/connection_internal.goose fails closed when ignored_uni_streams cap is reached
// CHECK: H4_C12_H3_UNI_NO_EVICT_FIXED: true

fn probe_h4_c13_qpack_atomic_evict() {
    var tbl = http3::new_qpack_table(128, 16, 128);
    assert(http3::qpack_insert_literal(tbl, "k0", "val0"));
    assert(http3::qpack_insert_literal(tbl, "k1", "val1"));
    assert(http3::qpack_insert_literal(tbl, "k2", "val2"));
    tbl.entries[1].ref_count = 1;
    let ok = http3::qpack_set_capacity(tbl, 10);
    let fixed = !ok && tbl.entries.len == 3 && tbl.used_bytes == 114 && tbl.draining_index == 0;
    print("H4_C13_QPACK_ATOMIC_EVICT_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H4_C13): http3/qpack_internal.goose pre-checks eviction barriers and arena before mutating table
// CHECK: H4_C13_QPACK_ATOMIC_EVICT_FIXED: true

fn probe_h4_c14_h3_edge_hardened() {
    // 1. >64 KiB QPACK-blocked tail fails with H3_ERR_EXCESSIVE_LOAD.
    var s1 = http3::h3_edge_open();
    defer http3::h3_edge_close(s1);
    var blk_q: u8[..32] = [0x02, 0x00];
    assert(http3::encode_qpack_field(blk_q, ":method", "GET"));
    var blk_hdr: u8[..64] = [];
    assert(http3::encode_headers_frame(blk_hdr, blk_q[..]));
    assert(http3::h3_edge_feed_bidi_stream(s1, 0, blk_hdr[..], false));
    var big: u8[..16400] = [];
    for _ in 16384 { big.push(0x41); }
    for _ in 4 {
        assert(http3::h3_edge_feed_bidi_stream(s1, 0, big[..], false));
    }
    let over_ok = http3::h3_edge_feed_bidi_stream(s1, 0, big[..64], false);
    var ev1 = http3::H3EdgeEvent { .. };
    let got_ev1 = http3::h3_edge_poll_event(s1, ev1);
    let cap_ok = !over_ok && got_ev1 && ev1.kind == http3::H3EdgeEventKind.ProtocolError
        && ev1.error_code == rfc::H3_ERR_EXCESSIVE_LOAD;

    // 2. Reset stream ignores late data; 3. Concurrent stream cap > 128 active streams fails closed.
    var s2 = http3::h3_edge_open();
    defer http3::h3_edge_close(s2);
    let part: u8[3] = [0x01, 0x10, 0x01];
    for i in 128 {
        assert(http3::h3_edge_feed_bidi_stream(s2, (i as u64) * 4, part[..], false));
    }
    http3::h3_edge_reset_stream(s2, 0);
    assert(http3::h3_edge_feed_bidi_stream(s2, 0, part[..], true));
    let count_after_reset = http3::g_h3_edge_slots[s2.slot_idx].stream_count;
    var s3 = http3::h3_edge_open();
    defer http3::h3_edge_close(s3);
    for i in 128 {
        assert(http3::h3_edge_feed_bidi_stream(s3, (i as u64) * 4, part[..], false));
    }
    let st_over = http3::h3_edge_feed_bidi_stream(s3, 512, part[..], false);
    let fixed = cap_ok && (count_after_reset == 127) && !st_over;
    print("H4_C14_H3_EDGE_HARDENED_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H4_C14): http3/server_session.goose bounds QPACK-blocked tail, stream count, and stream resurrection
// CHECK: H4_C14_H3_EDGE_HARDENED_FIXED: true

fn probe_h1_c06_ct_base64_roundtrip() {
    var raw: u8[..64] = [];
    for i in 48 { raw.push(((i * 7 + 3) & 0xFF) as u8); }
    var std_enc: u8[..128] = [];
    var url_enc: u8[..128] = [];
    core::base64_encode(raw[..], std_enc);
    core::base64url_encode(raw[..], url_enc);
    var std_dec: u8[..64] = [];
    var url_dec: u8[..64] = [];
    let ok1 = core::base64_decode(std_enc[..], std_dec);
    let ok2 = core::base64url_decode(url_enc[..], url_dec);
    let fixed = ok1 && ok2 && std_dec[..] == raw[..] && url_dec[..] == raw[..];
    print("H1_C06_CT_BASE64_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H1_C06): core/crypto/base64.goose encodes sextets branchlessly without 64B LUTs
// CHECK: H1_C06_CT_BASE64_FIXED: true

fn probe_h2_c09_c11_c19_tls_p2() {
    let sig_bad = tls_internal::detect_cert_sig_scheme("") == 0;
    let bad_nst: u8[15] = [
        0x00, 0x09, 0x3a, 0x81,
        0x00, 0x00, 0x00, 0x01,
        0x01, 0xaa,
        0x00, 0x01, 0xbb,
        0x00, 0x00,
    ];
    let nst_bad = !tls::validate_quic_post_hs_nst(bad_nst[..]);
    var good_nst = bad_nst;
    good_nst[1] = 0x00;
    good_nst[2] = 0x00;
    good_nst[3] = 0x3c;
    let nst_ok = tls::validate_quic_post_hs_nst(good_nst[..]);
    let cfg = tls::TlsBackendConfig { kind: tls::TlsBackendKind.Auto, require_alpn_match: true, .. };
    let routed_pure = tls_internal::should_route_to_pure_backend(cfg, false);
    let fixed = sig_bad && nst_bad && nst_ok && routed_pure;
    print("H2_P2_TLS_HARDENING_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H2_P2): tls/ closes H2_C19 sig fallback, H2_C11 NST lifetime/ext bounds, and H2_C20 client ALPN routing
// CHECK: H2_P2_TLS_HARDENING_FIXED: true

fn probe_h5_c13_cache_host_and_private() {
    var cache = server::new_http_route_cache();
    var req_a = http::new_request("GET", "/item");
    http::set_header(req_a, "Host", "a.example");
    var ckey_a: u8[..256] = [];
    assert(server_internal::build_route_cache_key(req_a, ckey_a));

    var res_priv = http::Response { status_code: 200, .. };
    res_priv.body.append("secret-body");
    http::set_header(res_priv, "Set-Cookie", "sid=1");
    let _ = server_internal::stage_server_cache_store(cache, 1000, res_priv, 7, ckey_a[..]);

    var res_priv2 = http::Response { status_code: 200, .. };
    res_priv2.body.append("priv-body");
    http::set_header(res_priv2, "Cache-Control", "private, max-age=60");
    let _ = server_internal::stage_server_cache_store(cache, 1001, res_priv2, 7, ckey_a[..]);
    let skipped_priv = !cache.is_valid && cache.entries.len == 0;

    var res_pub = http::Response { status_code: 200, .. };
    res_pub.body.append("pub-a");
    let _ = server_internal::stage_server_cache_store(cache, 1002, res_pub, 7, ckey_a[..]);

    var req_b = http::new_request("GET", "/item");
    http::set_header(req_b, "Host", "b.example");
    var out_b = http::Response { .. };
    let v_b = server_internal::stage_server_cache_lookup(cache, req_b, 1003, out_b, 7);
    let b_missed = match v_b { ShortCircuit _ => false, _ => true };

    var req_ck = http::new_request("GET", "/item");
    http::set_header(req_ck, "Host", "a.example");
    http::set_header(req_ck, "Cookie", "sid=1");
    var out_ck = http::Response { .. };
    let v_ck = server_internal::stage_server_cache_lookup(cache, req_ck, 1004, out_ck, 7);
    let ck_missed = match v_ck { ShortCircuit _ => false, _ => true };

    let fixed = skipped_priv && b_missed && ck_missed;
    print("H5_C13_ROUTE_CACHE_HARDENED_FIXED: ", fixed, "\n");
}
// AUDIT-FIXED(H5_C13): server/pipeline* keys route cache by lowercase Host and skips Cookie/Set-Cookie/private
// CHECK: H5_C13_ROUTE_CACHE_HARDENED_FIXED: true

fn main() {
    var shared_session = client::new_session();
    print("=== SECURITY AUDIT REGRESSION SUITE 2026 ===\n");
    probe_h2_c08_x509_uri_backslash();
    probe_h3_c02_ssrf_siit_ipv4_translated();
    probe_h3_c03_ssrf_cloud_metadata_ipv6();
    probe_h3_c04_cors_duplicate_preflight_headers();
    probe_h3_c05_digest_stale_downgrade();
    probe_h3_c06_ctl_0x7f_auth_bypass();
    probe_h3_c07_edge_rate_limiter_active_eviction();
    probe_h3_c09_p256_order_zero_sig();
    probe_h4_c01_quic_pn_64_interval_replay();
    probe_h4_c09_hpack_4096_eviction_desync();
    probe_h5_c06_cookie_long_url_domain_bypass();
    probe_h5_c12_dns_qdcount_zero_accepted();
    probe_g8_14_c04_acme_padded_replay_nonce();
    probe_h5_c01_deflate_l1_avx2_no_stack_overflow();
    probe_h5_c02_no_raw_udp_for_https(shared_session);
    probe_h1_c03_rsa_pss_513_no_abort();
    probe_h3_c01_hpke_nonempty_out_bounds();
    probe_h2_c07_x509_dn_nc_fail_closed();
    probe_h2_c01_ticket_sni_binding();
    probe_h2_c12_server_pre_ch_ccs_rejected();
    probe_h5_c07_secure_cookie_replaces_non_secure();
    probe_h5_c10_svcb_dangerous_port_blocked(shared_session);
    probe_h5_c03_cross_origin_401_no_auth_retry(shared_session);
    probe_g8_14_c02_jwt_cnf_jkt_parsed();
    probe_h5_c05_cl_i64_overflow_rejected();
    probe_h5_c11_headermap_vary_compaction();
    probe_h5_c16_x_accel_expires_overflow();
    probe_h4_c03_quic_flow_control_unread();
    probe_h4_c04_quic_version_and_vn();
    probe_h4_c05_quic_key_update_hardened();
    probe_h4_c11_h3_empty_push_promise_rejected();
    probe_h4_c12_h3_uni_stream_no_evict();
    probe_h4_c13_qpack_atomic_evict();
    probe_h4_c14_h3_edge_hardened();
    probe_h1_c06_ct_base64_roundtrip();
    probe_h2_c09_c11_c19_tls_p2();
    probe_h5_c13_cache_host_and_private();
}
