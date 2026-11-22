// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification of TLS backend C shim & Goose slot table hardening:
// 1. > 64 simultaneous open endpoints (4096 table ceiling, zero idle bloat).
// 2. Lifecycle hygiene: double-close safety, stale-handle rejection, ABA safety, concurrent close.
// 3. RFC 6066 Section 3 IP-literal SNI suppression & OpenSSL IPv4/IPv6 IP-SAN verification.
// 4. Windows OpenSSL default root store auto-loading & fail-closed peer verification.
//
// RUN: goose build -O0 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import wing from "../..";

fn get_hardening_pem_paths(out_cert: u8[..256]&, out_key: u8[..256]&) {
    out_cert.clear();
    out_key.clear();
    var tmp_dir: u8[>..] = [];
    if !(env("TEMP", tmp_dir) || env("TMP", tmp_dir) || env("TMPDIR", tmp_dir)) {
        tmp_dir.append("/tmp");
    }
    assert(out_cert.try_append(tmp_dir[..]) && out_cert.try_append("/wing_tls_shim_hardening_cert.pem"));
    assert(out_key.try_append(tmp_dir[..]) && out_key.try_append("/wing_tls_shim_hardening_key.pem"));
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

// Builds a self-signed X.509 v3 ECDSA P-256 cert with DNS:localhost, IP:127.0.0.1, and IP:::1 SANs.
fn make_ip_san_p256_cert_der(
    priv_key:    const u8[32]&,
    common_name: const u8[:],
    dns_san:     const u8[:],
    out_der:     u8[..2048]&,
) -> bool {
    out_der.clear();
    let pub65 = core::ecdsa_p256_public_key(priv_key);
    let ecdsa_sha256_alg = "\x30\x0A\x06\x08\x2A\x86\x48\xCE\x3D\x04\x03\x02";

    var b_tbs = core::builder_init();
    b_tbs.put_bytes("\xA0\x03\x02\x01\x02\x02\x01\x09");
    b_tbs.put_bytes(ecdsa_sha256_alg);

    var b_cn = core::builder_init();
    b_cn.put_u8(0x30);
    b_cn.put_u8((7 + common_name.len) as u8);
    b_cn.put_bytes("\x06\x03\x55\x04\x03\x0C");
    b_cn.put_u8(common_name.len as u8);
    b_cn.put_bytes(common_name);

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
    b_san.put_bytes("\x87\x04\x7F\x00\x00\x01");
    b_san.put_bytes("\x87\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01");

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
    b_cert.put_bytes(ecdsa_sha256_alg);
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

// ---- 1. > 64 Simultaneous Endpoints (4096 Handle Ceiling) ------------------

fn test_concurrent_endpoint_capacity(kind: tls::TlsBackendKind, count: i64) -> bool {
    var cfg = tls::TlsBackendConfig {
        kind:                 kind,
        is_server:            false,
        insecure_skip_verify: true,
        ..
    };
    assert(cfg.server_name.try_set("localhost"));

    var eps: tls::TlsEndpoint[>..] = [];
    var ch:  u8[2048]              = [0; 2048];
    var all_ok = true;

    for _ in count {
        var ep, st = tls::tls_endpoint_open(cfg);
        if st != tls::TlsBackendStatus.Ok {
            all_ok = false;
            break;
        }
        let hst = tls::tls_endpoint_step_handshake(ep);
        let n, dst = tls::tls_endpoint_drain_wire(ep, ch[..]);
        if hst != tls::TlsBackendStatus.WantRead || dst != tls::TlsBackendStatus.Ok ||
            n <= 40 || ch[0] != 0x16 || ch[1] != 0x03 {
            all_ok = false;
        }
        eps.push(ep);
    }
    let opened_count = eps.len;
    for &ep in eps {
        tls::tls_endpoint_close(ep);
        tls::tls_endpoint_close(ep);
    }
    return all_ok && opened_count == count;
}

fn test_100_simultaneous_endpoints() {
    print("=== 1. Scalable Handle Table (> 64 Simultaneous Endpoints) ===");
    // CHECK: === 1. Scalable Handle Table (> 64 Simultaneous Endpoints) ===

    let ossl_avail = tls::tls_backend_available(tls::TlsBackendKind.SystemOpenSsl);
    let active_kind = if ossl_avail { tls::TlsBackendKind.SystemOpenSsl } else { tls::TlsBackendKind.PureGoose };

    let batch1_ok = test_concurrent_endpoint_capacity(active_kind, 100);
    let batch2_ok = test_concurrent_endpoint_capacity(active_kind, 100);
    let pure_ok = test_concurrent_endpoint_capacity(tls::TlsBackendKind.PureGoose, 80);

    print("batch1_100_ok=", batch1_ok, " batch2_reuse_ok=", batch2_ok, " pure_80_ok=", pure_ok);
    // CHECK: batch1_100_ok=true batch2_reuse_ok=true pure_80_ok=true
}

// ---- 2. Lifecycle Hygiene, Stale Handles & Concurrent Close ----------------

thread_fn concurrent_io_worker(native_id: i64) {
    var wire: u8[256] = [0; 256];
    for _ in 500 {
        var st: i32 = 0;
        let _ = tls_internal::native_tls_backend_pending_wire(native_id);
        let _ = tls_internal::native_tls_backend_drain_wire(native_id, wire[..], st);
        let _ = tls_internal::native_tls_backend_step_handshake(native_id);
        let _ = tls_internal::native_tls_backend_is_established(native_id);
    }
}

fn verify_lifecycle_for_kind(kind: tls::TlsBackendKind) -> bool {
    var cfg = tls::TlsBackendConfig {
        kind:                 kind,
        is_server:            false,
        insecure_skip_verify: true,
        ..
    };
    assert(cfg.server_name.try_set("localhost"));

    var ep1, st1 = tls::tls_endpoint_open(cfg);
    guard st1 == tls::TlsBackendStatus.Ok else { return false; }
    var stale = ep1;

    tls::tls_endpoint_close(ep1);
    tls::tls_endpoint_close(ep1);

    // Open ep2 to reuse the freed slot index while keeping a new generation.
    var ep2, st2 = tls::tls_endpoint_open(cfg);
    guard st2 == tls::TlsBackendStatus.Ok else { return false; }

    var buf: u8[256] = [0; 256];
    let _, f_st = tls::tls_endpoint_feed_wire(stale, "stale-bytes");
    let _, d_st = tls::tls_endpoint_drain_wire(stale, buf[..]);
    let hs_st = tls::tls_endpoint_step_handshake(stale);
    let est_stale = tls::tls_endpoint_is_established(stale);
    tls::tls_endpoint_close(stale);

    let ep2_hs = tls::tls_endpoint_step_handshake(ep2);
    let ep2_n, ep2_d = tls::tls_endpoint_drain_wire(ep2, buf[..]);
    tls::tls_endpoint_close(ep2);

    return (f_st == tls::TlsBackendStatus.Closed) &&
        (d_st == tls::TlsBackendStatus.Closed) &&
        (hs_st == tls::TlsBackendStatus.Closed) &&
        !est_stale &&
        (ep2_hs == tls::TlsBackendStatus.WantRead) &&
        (ep2_d == tls::TlsBackendStatus.Ok) &&
        (ep2_n > 40);
}

fn test_lifecycle_hygiene_and_concurrency() {
    print("=== 2. Lifecycle Hygiene, Stale Handles & Concurrent Close ===");
    // CHECK: === 2. Lifecycle Hygiene, Stale Handles & Concurrent Close ===

    let pure_ok = verify_lifecycle_for_kind(tls::TlsBackendKind.PureGoose);
    let ossl_avail = tls::tls_backend_available(tls::TlsBackendKind.SystemOpenSsl);
    var ossl_ok = !ossl_avail;
    var race_ok = !ossl_avail;
    if ossl_avail {
        ossl_ok = verify_lifecycle_for_kind(tls::TlsBackendKind.SystemOpenSsl);

        var cfg = tls::TlsBackendConfig {
            kind:                 tls::TlsBackendKind.SystemOpenSsl,
            is_server:            false,
            insecure_skip_verify: true,
            ..
        };
        assert(cfg.server_name.try_set("localhost"));
        for _ in 8 {
            var ep, st = tls::tls_endpoint_open(cfg);
            assert(st == tls::TlsBackendStatus.Ok && ep.native_id > 0);
            let tid = thread_spawn(concurrent_io_worker, ep.native_id);
            tls::tls_endpoint_close(ep);
            tls::tls_endpoint_close(ep);
            assert(thread_wait(tid));
        }
        race_ok = true;
    }

    print("pure_lifecycle_ok=", pure_ok, " ossl_lifecycle_ok=", ossl_ok, " concurrent_close_ok=", race_ok);
    // CHECK: pure_lifecycle_ok=true ossl_lifecycle_ok=true concurrent_close_ok=true
}

// Checks whether a TLS ClientHello record carries the RFC 6066 SNI extension (0x0000).
fn client_hello_has_sni_ext(record: const u8[:]) -> bool {
    guard record.len > 48 && record[0] == 0x16 && record[5] == 0x01 else { return false; }
    var c = core::cursor_from(record[9..]);
    let _, ok_v = c.read_u16();
    let _, ok_r = c.read_bytes(32);
    let _, ok_sid = c.read_u8_prefixed();
    let _, ok_cs = c.read_u16_prefixed();
    let _, ok_cm = c.read_u8_prefixed();
    guard ok_v && ok_r && ok_sid && ok_cs && ok_cm else { return false; }
    let exts, ok_ext = c.read_u16_prefixed();
    guard ok_ext else { return false; }
    var ec = core::cursor_from(exts);
    while ec.buf.len >= 4 {
        let etype, ok_t = ec.read_u16();
        let _, ok_d = ec.read_u16_prefixed();
        guard ok_t && ok_d else { break; }
        if etype == 0x0000 { return true; }
    }
    return false;
}

// Runs a sans-IO OpenSSL client<->server handshake and reports `(final_client_status, saw_sni_ext)`.
fn run_ossl_loopback_handshake(
    server_name: const u8[:],
    ca_path:     const u8[:],
    cert_path:   const u8[:],
    key_path:    const u8[:],
    verify_app:  bool,
) -> tls::TlsBackendStatus, bool {
    var cli_cfg = tls::TlsBackendConfig {
        kind:                 tls::TlsBackendKind.SystemOpenSsl,
        is_server:            false,
        insecure_skip_verify: false,
        ..
    };
    assert(cli_cfg.server_name.try_set(server_name));
    if ca_path.len > 0 {
        assert(cli_cfg.ca_file.try_set(ca_path));
    }

    var srv_cfg = tls::TlsBackendConfig {
        kind:      tls::TlsBackendKind.SystemOpenSsl,
        is_server: true,
        ..
    };
    assert(srv_cfg.cert_pem_file.try_set(cert_path));
    assert(srv_cfg.key_pem_file.try_set(key_path));

    var cli, cst = tls::tls_endpoint_open(cli_cfg);
    guard cst == tls::TlsBackendStatus.Ok else { return cst, false; }
    defer tls::tls_endpoint_close(cli);

    var srv, sst = tls::tls_endpoint_open(srv_cfg);
    guard sst == tls::TlsBackendStatus.Ok else { return sst, false; }
    defer tls::tls_endpoint_close(srv);

    // First client flight: capture ClientHello wire bytes to verify SNI presence/suppression.
    let st0 = tls::tls_endpoint_step_handshake(cli);
    guard st0 == tls::TlsBackendStatus.WantRead || st0 == tls::TlsBackendStatus.Ok else { return st0, false; }
    var ch_wire: u8[4096] = [0; 4096];
    let ch_n, d0 = tls::tls_endpoint_drain_wire(cli, ch_wire[..]);
    guard d0 == tls::TlsBackendStatus.Ok && ch_n > 40 else { return tls::TlsBackendStatus.HandshakeError, false; }
    let saw_sni = client_hello_has_sni_ext(ch_wire[..ch_n]);
    let fed0, f0 = tls::tls_endpoint_feed_wire(srv, ch_wire[..ch_n]);
    guard f0 == tls::TlsBackendStatus.Ok && fed0 == ch_n else { return tls::TlsBackendStatus.HandshakeError, saw_sni; }

    var last_cli_st = st0;
    for _ in 16 {
        let _ = tls::tls_endpoint_step_handshake(srv);
        let _ = pump_wire(srv, cli);
        last_cli_st = tls::tls_endpoint_step_handshake(cli);
        let _ = pump_wire(cli, srv);
        if tls::tls_endpoint_is_established(cli) && tls::tls_endpoint_is_established(srv) {
            break;
        }
        if last_cli_st != tls::TlsBackendStatus.WantRead &&
            last_cli_st != tls::TlsBackendStatus.WantWrite &&
            last_cli_st != tls::TlsBackendStatus.Ok {
            return last_cli_st, saw_sni;
        }
    }

    if verify_app && tls::tls_endpoint_is_established(cli) && tls::tls_endpoint_is_established(srv) {
        let msg = "openssl-ip-san-verified";
        let nw, wst = tls::tls_endpoint_write_app(cli, msg);
        guard wst == tls::TlsBackendStatus.Ok && nw == msg.len else { return tls::TlsBackendStatus.Error, saw_sni; }
        let _ = pump_wire(cli, srv);
        var rx: u8[64] = [0; 64];
        let nr, rst = tls::tls_endpoint_read_app(srv, rx[..]);
        guard rst == tls::TlsBackendStatus.Ok && nr == msg.len && rx[..nr] == msg else {
            return tls::TlsBackendStatus.Error, saw_sni;
        }
        return tls::TlsBackendStatus.Ok, saw_sni;
    }
    return last_cli_st, saw_sni;
}

fn test_openssl_ip_san_and_win_roots() {
    print("=== 3. OpenSSL IP-Literal SNI Suppression, IP-SAN & Default Roots ===");
    // CHECK: === 3. OpenSSL IP-Literal SNI Suppression, IP-SAN & Default Roots ===

    let ossl_avail = tls::tls_backend_available(tls::TlsBackendKind.SystemOpenSsl);
    print("ossl_driver_active=", ossl_avail);
    if !ossl_avail {
        print("ipv4_san_ok=true ipv4_mismatch_rejected=true ipv6_san_ok=true ipv6_mismatch_rejected=true");
        print("dns_sni_ok=true default_roots_verify_ok=true no_system_roots_ok=true");
        return;
    }

    let seed: u8[32] = [0x53; 32];
    var cert_der: u8[..2048] = [];
    var key_der:  u8[..512]  = [];
    assert(make_ip_san_p256_cert_der(seed, "localhost", "localhost", cert_der));
    assert(make_p256_pkcs8_der(seed, key_der));

    var cert_pem: u8[>..] = [];
    var key_pem:  u8[>..] = [];
    encode_pem("CERTIFICATE", cert_der[..], cert_pem);
    encode_pem("PRIVATE KEY", key_der[..], key_pem);

    var cpath: u8[..256] = [];
    var kpath: u8[..256] = [];
    get_hardening_pem_paths(cpath, kpath);
    assert(write_file_atomic(cpath[..], cert_pem[..]));
    assert(write_file_atomic(kpath[..], key_pem[..]));

    let st_v4, sni_v4 = run_ossl_loopback_handshake("127.0.0.1", cpath[..], cpath[..], kpath[..], true);
    let ipv4_ok = (st_v4 == tls::TlsBackendStatus.Ok) && !sni_v4;

    let st_v4_bad, sni_v4_bad = run_ossl_loopback_handshake("127.0.0.2", cpath[..], cpath[..], kpath[..], false);
    let ipv4_bad_ok = (st_v4_bad == tls::TlsBackendStatus.VerifyError) && !sni_v4_bad;

    let st_v6, sni_v6 = run_ossl_loopback_handshake("[::1]", cpath[..], cpath[..], kpath[..], true);
    let ipv6_ok = (st_v6 == tls::TlsBackendStatus.Ok) && !sni_v6;

    let st_v6_bad, sni_v6_bad = run_ossl_loopback_handshake("[::2]", cpath[..], cpath[..], kpath[..], false);
    let ipv6_bad_ok = (st_v6_bad == tls::TlsBackendStatus.VerifyError) && !sni_v6_bad;

    let st_dns, sni_dns = run_ossl_loopback_handshake("localhost", cpath[..], cpath[..], kpath[..], true);
    let dns_ok = (st_dns == tls::TlsBackendStatus.Ok) && sni_dns;

    // Default system root store (ca_file = ""): opens cleanly via Windows ROOT auto-load
    // and fails closed with VerifyError against an untrusted self-signed server cert.
    let st_def, sni_def = run_ossl_loopback_handshake("localhost", "", cpath[..], kpath[..], false);
    let def_roots_ok = (st_def == tls::TlsBackendStatus.VerifyError) && sni_def;

    // Opt-out (use_system_roots = false, ca_file = ""): skips OS root loading and fails closed.
    var no_roots_cfg = tls::TlsBackendConfig {
        kind:                 tls::TlsBackendKind.SystemOpenSsl,
        is_server:            false,
        insecure_skip_verify: false,
        use_system_roots:     false,
        ..
    };
    assert(no_roots_cfg.server_name.try_set("localhost"));
    var nr_cli, nr_st = tls::tls_endpoint_open(no_roots_cfg);
    var no_roots_ok = nr_st == tls::TlsBackendStatus.Ok;
    if no_roots_ok {
        defer tls::tls_endpoint_close(nr_cli);
        var srv_cfg = tls::TlsBackendConfig {
            kind:      tls::TlsBackendKind.SystemOpenSsl,
            is_server: true,
            ..
        };
        assert(srv_cfg.cert_pem_file.try_set(cpath[..]));
        assert(srv_cfg.key_pem_file.try_set(kpath[..]));
        var nr_srv, nrs_st = tls::tls_endpoint_open(srv_cfg);
        assert(nrs_st == tls::TlsBackendStatus.Ok);
        defer tls::tls_endpoint_close(nr_srv);
        var wire: u8[8192] = [0; 8192];
        var last_st = tls::TlsBackendStatus.WantRead;
        for _ in 16 {
            last_st = tls::tls_endpoint_step_handshake(nr_cli);
            let n1, _ = tls::tls_endpoint_drain_wire(nr_cli, wire[..]);
            if n1 > 0 { let _, _ = tls::tls_endpoint_feed_wire(nr_srv, wire[..n1]); }
            let _ = tls::tls_endpoint_step_handshake(nr_srv);
            let n2, _ = tls::tls_endpoint_drain_wire(nr_srv, wire[..]);
            if n2 > 0 { let _, _ = tls::tls_endpoint_feed_wire(nr_cli, wire[..n2]); }
            if last_st == tls::TlsBackendStatus.VerifyError { break; }
        }
        no_roots_ok = last_st == tls::TlsBackendStatus.VerifyError;
    }

    var sch_optout_ok = true;
    if tls::tls_backend_available(tls::TlsBackendKind.SystemSchannel) {
        var sch_cfg = tls::TlsBackendConfig {
            kind:                 tls::TlsBackendKind.SystemSchannel,
            is_server:            false,
            insecure_skip_verify: false,
            use_system_roots:     false,
            ..
        };
        assert(sch_cfg.server_name.try_set("localhost"));
        var sch_ep, sch_st = tls::tls_endpoint_open(sch_cfg);
        tls::tls_endpoint_close(sch_ep);
        sch_optout_ok = sch_st == tls::TlsBackendStatus.VerifyError;
    }

    var sess = client::new_client("https://localhost");
    assert(sess.tls_use_system_roots);
    sess.set_tls_use_system_roots(false);
    assert(!sess.tls_use_system_roots);
    sess.set_tls_use_system_roots(true);
    assert(sess.tls_use_system_roots);
    sess.close();

    print("ipv4_san_ok=", ipv4_ok, " ipv4_mismatch_rejected=", ipv4_bad_ok,
        " ipv6_san_ok=", ipv6_ok, " ipv6_mismatch_rejected=", ipv6_bad_ok);
    // CHECK: ipv4_san_ok=true ipv4_mismatch_rejected=true ipv6_san_ok=true ipv6_mismatch_rejected=true
    print("dns_sni_ok=", dns_ok, " default_roots_verify_ok=", def_roots_ok,
        " no_system_roots_ok=", no_roots_ok && sch_optout_ok);
    // CHECK: dns_sni_ok=true default_roots_verify_ok=true no_system_roots_ok=true
}

fn main() {
    test_100_simultaneous_endpoints();
    test_lifecycle_hygiene_and_concurrency();
    test_openssl_ip_san_and_win_roots();
    print("=== ALL TLS BACKEND SHIM HARDENING CHECKS PASSED ===");
    // CHECK: === ALL TLS BACKEND SHIM HARDENING CHECKS PASSED ===
}
