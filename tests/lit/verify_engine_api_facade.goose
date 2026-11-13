// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// End-to-end verification of the public `wing::` and `wire::` Engine API facade
// (uses only public wing::, wire::, rfc::, and core:: surfaces).
// RUN: goose %s | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

fn must_unhex(hex_str: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    assert(wire_kit::parse_hex(hex_str, out));
    return out;
}

fn make_pem_block(label: const u8[:], der: const u8[:], out: u8[>..]&) {
    out.append("-----BEGIN ");
    out.append(label);
    out.append("-----\n");
    var b64: u8[>..] = [];
    core::base64_encode(der, b64);
    var i: i64 = 0;
    while i < b64.len {
        let end = min(i + 64, b64.len);
        out.append(b64[i..end]);
        out.push('\n');
        i = end;
    }
    out.append("-----END ");
    out.append(label);
    out.append("-----\n");
}

fn is_all_zero(buf: const u8[:]) -> bool {
    for b in buf {
        if b != 0 { return false; }
    }
    return true;
}

fn test_client_ca_and_ssrf_facade() {
    let seed1: u8[32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x02,
    ];
    let seed2: u8[32] = [
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
    ];
    var cert1_der: u8[..2048] = [];
    var cert2_der: u8[..2048] = [];
    assert(wing::build_test_ed25519_cert_der(seed1, "ca1.wing.test", "ca1.wing.test", "", cert1_der));
    assert(wing::build_test_ed25519_cert_der(seed2, "ca2.wing.test", "ca2.wing.test", "", cert2_der));

    var bundle_pem: u8[>..] = [];
    make_pem_block("CERTIFICATE", cert1_der[..], bundle_pem);
    make_pem_block("CERTIFICATE", cert2_der[..], bundle_pem);

    var sess = wing::new_session(wing::SessionConfig { insecure_skip_verify: true, .. });
    let cnt1, ok1 = wing::configure_session_tls_ca_pem(sess, bundle_pem[..]);
    assert(ok1 && cnt1 == 2 && sess.trust_store.anchors.len == 2);
    assert(!sess.insecure_skip_verify);
    assert(sess.ssrf_guard.deny_local_network);

    // Loopback test-harness mode sets deny_local_network = false without disabling CA verification.
    var local_sess = wing::new_session(wing::SessionConfig { insecure_skip_verify: true, .. });
    let cnt2, ok2 = wing::configure_session_tls_ca_pem(local_sess, bundle_pem[..], true);
    assert(ok2 && cnt2 == 2 && !local_sess.insecure_skip_verify);
    assert(!local_sess.ssrf_guard.deny_local_network);

    let parsed_local_url, url_err = core::parse_url("https://127.0.0.1:8443/health");
    assert(url_err == core::UrlParseError.None);

    var ssrf_strict = sess.ssrf_guard;
    ssrf_strict.enabled = true;
    assert(wing::validate_url_against_ssrf(parsed_local_url, ssrf_strict) != wing::RedirectError.None);

    var ssrf_local = local_sess.ssrf_guard;
    ssrf_local.enabled = true;
    assert(wing::validate_url_against_ssrf(parsed_local_url, ssrf_local) == wing::RedirectError.None);

    // Negative PEM / rollback cases on Session.
    let c_empty, ok_empty = wing::configure_session_tls_ca_pem(sess, "");
    assert(!ok_empty && c_empty == 0 && sess.trust_store.anchors.len == 2);
    let bad_pem = "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";
    let c_bad, ok_bad = wing::configure_session_tls_ca_pem(sess, bad_pem);
    assert(!ok_bad && c_bad == 0 && sess.trust_store.anchors.len == 2);

    // File-backed trust anchor loading (positive via OS temp dir + negative/nonexistent).
    let c_miss, ok_miss = wing::load_trust_anchors_pem_file(sess, "nonexistent_wing_ca_bundle.pem");
    assert(!ok_miss && c_miss == 0 && sess.trust_store.anchors.len == 2);
    let c_empty_path, ok_empty_path = wing::load_trust_anchors_pem_file(sess, "");
    assert(!ok_empty_path && c_empty_path == 0 && sess.trust_store.anchors.len == 2);

    var tmp_dir: u8[>..] = [];
    if env("TEMP", tmp_dir) || env("TMP", tmp_dir) || env("TMPDIR", tmp_dir) {
        var ca_path: u8[>..] = [];
        ca_path.append(tmp_dir[..]);
        ca_path.append("/wing_engine_api_facade_test_ca.pem");
        assert(write_file_atomic(ca_path[..], bundle_pem[..]));

        var file_sess = wing::new_session(wing::SessionConfig { insecure_skip_verify: true, .. });
        let fc1, fok1 = wing::load_trust_anchors_pem_file(file_sess, ca_path[..]);
        assert(fok1 && fc1 == 2 && file_sess.trust_store.anchors.len == 2);
        assert(!file_sess.insecure_skip_verify);

        var direct_store = wing::TrustAnchorStore {};
        let fc2, fok2 = wing::load_trust_anchors_pem_file(direct_store, ca_path[..]);
        assert(fok2 && fc2 == 2 && direct_store.anchors.len == 2);

        // Bad file contents MUST roll back existing anchors cleanly.
        assert(write_file_atomic(ca_path[..], bad_pem));
        let fc_bad, fok_bad = wing::load_trust_anchors_pem_file(direct_store, ca_path[..]);
        assert(!fok_bad && fc_bad == 0 && direct_store.anchors.len == 2);
    }

    print("client_ca_facade_ok: true");
    // CHECK: client_ca_facade_ok: true
}

fn test_wire_tls13_facade() {
    let cs = rfc::TLS_CIPHER_AES_128_GCM_SHA256;
    let shared = must_unhex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    let th_hello = must_unhex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
    let th_cv = must_unhex("7c11c487c607ef4d1975f514f05677f22e4e4a1f62f262c7be7e17f9e532b9b0");
    let th_sf = must_unhex("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");

    var hs, ok_hs = wire::derive_tls13_handshake_keys(cs, shared[..], th_hello[..]);
    assert(ok_hs && hs.client.active && hs.server.active);
    assert(hs.client.seq_num == 0 && hs.server.seq_num == 0);
    assert(core::ct_eq_bytes(hs.server.key[..16], must_unhex("3fce516009c21727d0f2e4e86ee403bc")[..]));
    assert(core::ct_eq_bytes(hs.server.iv[..], must_unhex("5d313eb2671276ee13000b30")[..]));
    assert(core::ct_eq_bytes(hs.client.key[..16], must_unhex("dbfaa693d1762c5b666af5d950258d01")[..]));
    assert(core::ct_eq_bytes(hs.client.iv[..], must_unhex("5bd3c71b836e0b76bb73265f")[..]));

    // Verify compute_tls13_finished_verify_data matches RFC 8448 client Finished vector using th_sf.
    let c_fin, ok_cfin = wire::compute_tls13_finished_verify_data(hs.client, th_sf[..]);
    assert(ok_cfin && c_fin.len == 32);
    var c_fin_msg: u8[>..] = [];
    c_fin_msg.append([0x14, 0x00, 0x00, 0x20]);
    c_fin_msg.append(c_fin[..]);
    var sealed_cfin: u8[>..] = [];
    let alert_cf, ok_scf = wire::seal_tls13_record(
        hs.client,
        rfc::TLS_CONTENT_HANDSHAKE,
        c_fin_msg[..],
        sealed_cfin,
    );
    var exp_cfin_rec: u8[>..] = [];
    exp_cfin_rec.append(must_unhex("170303003575ec4dc238cce60b298044a71e219c56cc77b0517fe9b93c7a4bfc")[..]);
    exp_cfin_rec.append(must_unhex("44d87f38f80338ac98fc46deb384bd1caeacab6867d726c40546")[..]);
    assert(ok_scf && alert_cf == wing::TlsAlert.CloseNotify && hs.client.seq_num == 1);
    assert(core::ct_eq_bytes(sealed_cfin[..], exp_cfin_rec[..]));

    // Zeroize handshake keys and verify complete scrub.
    wire::zeroize_tls_traffic_keys(hs);
    assert(!hs.client.active && !hs.server.active);
    assert(is_all_zero(hs.client.secret[..]) && is_all_zero(hs.client.key[..]));
    let _, ok_zero_fin = wire::compute_tls13_finished_verify_data(hs.server, th_cv[..]);
    assert(!ok_zero_fin);

    // Derive RFC 8448 application keys for both sender and peer receiver.
    var tx, ok_tx = wire::derive_tls13_app_keys(cs, shared[..], th_hello[..], th_sf[..]);
    var rx, ok_rx = wire::derive_tls13_app_keys(cs, shared[..], th_hello[..], th_sf[..]);
    assert(ok_tx && ok_rx);
    assert(core::ct_eq_bytes(tx.server.key[..16], must_unhex("9f02283b6c9c07efc26bb9f2ac92e356")[..]));
    assert(core::ct_eq_bytes(tx.server.iv[..], must_unhex("cf782b88dd83549aadf1e984")[..]));
    assert(core::ct_eq_bytes(tx.client.key[..16], must_unhex("17422dda596ed5d9acd890e3c63f5051")[..]));
    assert(core::ct_eq_bytes(tx.client.iv[..], must_unhex("5b78923dee08579033e523d9")[..]));
    assert(core::ct_eq_bytes(
        tx.exporter_secret[..32],
        must_unhex("fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50")[..],
    ));

    // Seal two sequential client records (seq 0 app data + seq 1 close_notify alert) matching RFC 8448.
    var app_plain: u8[>..] = [];
    app_plain.append(must_unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")[..]);
    app_plain.append(must_unhex("202122232425262728292a2b2c2d2e2f3031")[..]);
    var exp_c_app: u8[>..] = [];
    exp_c_app.append(must_unhex("1703030043a23f7054b62c94d0affafe8228ba55cbefacea42f914aa66bcab3f")[..]);
    exp_c_app.append(must_unhex("2b9819a8a5b46b395bd54a9a20441e2b62974e1f5a6292a2977014bd1e3deae6")[..]);
    exp_c_app.append(must_unhex("3aeebb21694915e4")[..]);

    var wire_stream: u8[>..] = [];
    let a1, s1_ok = wire::seal_tls13_record(
        tx.client,
        rfc::TLS_CONTENT_APPLICATION_DATA,
        app_plain[..],
        wire_stream,
    );
    assert(s1_ok && a1 == wing::TlsAlert.CloseNotify && tx.client.seq_num == 1);
    assert(core::ct_eq_bytes(wire_stream[..], exp_c_app[..]));

    let close_plain = must_unhex("0100");
    let exp_c_alert = must_unhex("1703030013c9872760655666b74d7ff1153efd6db6d0b0e3");
    let rec2_off = wire_stream.len;
    let a2, s2_ok = wire::seal_tls13_record(tx.client, rfc::TLS_CONTENT_ALERT, close_plain[..], wire_stream);
    assert(s2_ok && a2 == wing::TlsAlert.CloseNotify && tx.client.seq_num == 2);
    assert(core::ct_eq_bytes(wire_stream[rec2_off..], exp_c_alert[..]));

    // Sequential decryption via wire::open_tls13_record_at increments rx.client.seq_num automatically.
    var cur: i64     = 0;
    var pt1: u8[>..] = [];
    let t1, d_a1, d_ok1 = wire::open_tls13_record_at(rx.client, wire_stream[..], cur, pt1);
    assert(d_ok1 && d_a1 == wing::TlsAlert.CloseNotify && t1 == rfc::TLS_CONTENT_APPLICATION_DATA);
    assert(rx.client.seq_num == 1 && cur == exp_c_app.len);
    assert(core::ct_eq_bytes(pt1[..], app_plain[..]));

    var pt2: u8[>..] = [];
    let t2, d_a2, d_ok2 = wire::open_tls13_record_at(rx.client, wire_stream[..], cur, pt2);
    assert(d_ok2 && d_a2 == wing::TlsAlert.CloseNotify && t2 == rfc::TLS_CONTENT_ALERT);
    assert(rx.client.seq_num == 2 && cur == wire_stream.len);
    assert(core::ct_eq_bytes(pt2[..], close_plain[..]));

    // Replay / wrong seq_num MUST fail with BadRecordMac and preserve out/seq_num.
    let saved_pt_len = pt1.len;
    let rep_t, rep_alert, rep_ok = wire::open_tls13_record(rx.client, exp_c_app[..], pt1);
    assert(!rep_ok && rep_t == 0 && rep_alert == wing::TlsAlert.BadRecordMac);
    assert(rx.client.seq_num == 2 && pt1.len == saved_pt_len);

    // Trailing garbage in single-record helper MUST fail with DecodeError and roll back seq_num.
    var single_rx, ok_srx = wire::init_tls13_record_state(cs, tx.client.secret[..32]);
    assert(ok_srx);
    var trailing = copy(exp_c_app);
    trailing.push(0x00);
    let tr_t, tr_alert, tr_ok = wire::open_tls13_record(single_rx, trailing[..], pt1);
    assert(!tr_ok && tr_t == 0 && tr_alert == wing::TlsAlert.DecodeError);
    assert(single_rx.seq_num == 0 && pt1.len == saved_pt_len);

    // KeyUpdate rotation resets seq_num = 0 and interoperates across peers.
    assert(wire::update_tls13_traffic_keys(tx.client));
    assert(wire::update_tls13_traffic_keys(rx.client));
    assert(tx.client.seq_num == 0 && rx.client.seq_num == 0);
    var upd_rec: u8[>..] = [];
    let ua, uok = wire::seal_tls13_record(tx.client, rfc::TLS_CONTENT_APPLICATION_DATA, "after-ku", upd_rec);
    assert(uok && ua == wing::TlsAlert.CloseNotify && tx.client.seq_num == 1);
    var upd_pt: u8[>..] = [];
    let ut, uda, udok = wire::open_tls13_record(rx.client, upd_rec[..], upd_pt);
    assert(udok && uda == wing::TlsAlert.CloseNotify && ut == rfc::TLS_CONTENT_APPLICATION_DATA);
    assert(upd_pt[..] == "after-ku" && rx.client.seq_num == 1);

    wire::zeroize_tls_traffic_keys(tx);
    wire::zeroize_tls_traffic_keys(rx);
    wire::zeroize_tls_record_state(single_rx);

    print("wire_tls13_facade_ok: true");
    // CHECK: wire_tls13_facade_ok: true
}

fn test_wire_hpack_and_h2_facade() {
    let _, bad_cap = wire::init_hpack_state(8192, 8192);
    assert(!bad_cap);
    let _, bad_lim = wire::init_hpack_state(4096, 0);
    assert(!bad_lim);

    var enc, ok_enc = wire::init_hpack_state(4096, 8192);
    var dec, ok_dec = wire::init_hpack_state(4096, 8192);
    assert(ok_enc && ok_dec);

    let _, bad_meth = wire::make_h2_request_pseudo("", "https", "api.wing.test", "/");
    assert(!bad_meth);
    let _, bad_status = wire::make_h2_response_pseudo(99);
    assert(!bad_status);

    let req_pseudo, ok_reqp = wire::make_h2_request_pseudo("POST", "https", "api.wing.test", "/v1/items");
    let resp_pseudo, ok_respp = wire::make_h2_response_pseudo(204);
    assert(ok_reqp && ok_respp && resp_pseudo.status == 204 && resp_pseudo.has_status);

    var req_hdrs = wing::HeaderMap {};
    assert(wing::append_header(req_hdrs, "Content-Type", "application/json"));
    wing::set_header(req_hdrs, "Authorization", "Bearer top-secret-token", true);
    assert(wing::append_header(req_hdrs, "X-Trace-Id", "trace-42"));

    var hpack_wire: u8[>..] = [];
    assert(wire::hpack_encode_header_block(enc, req_pseudo, req_hdrs, hpack_wire, true));
    assert(enc.blocks_encoded == 1 && enc.bytes_encoded == (hpack_wire.len as u64));

    var out_pseudo = wire::WireH2PseudoHeaders {};
    var out_hdrs = wing::HeaderMap {};
    let derr = wire::hpack_decode_block(dec, hpack_wire[..], out_pseudo, out_hdrs);
    assert(derr == rfc::H2_ERR_NO_ERROR);
    assert(out_pseudo.method[..] == "POST" && out_pseudo.scheme[..] == "https");
    assert(out_pseudo.authority[..] == "api.wing.test" && out_pseudo.path[..] == "/v1/items");
    assert(dec.blocks_decoded == 1 && dec.bytes_decoded == (hpack_wire.len as u64));
    assert(wing::get_header(out_hdrs, "x-trace-id") == "trace-42");
    assert(wing::get_header(out_hdrs, "authorization") == "Bearer top-secret-token");

    // Truncated HPACK block MUST fail and roll back decoder counters and outputs.
    assert(hpack_wire.len > 1);
    let bad_err = wire::hpack_decode_block(dec, hpack_wire[..^1], out_pseudo, out_hdrs);
    assert(bad_err != rfc::H2_ERR_NO_ERROR);
    assert(dec.blocks_decoded == 1 && out_hdrs.entries.len == 0 && !out_pseudo.has_method);

    // Table size reset bounds.
    assert(!wire::hpack_reset_table_size(enc, 8192));
    assert(wire::hpack_reset_table_size(enc, 512));

    // HTTP/2 HEADERS frame framing over WireHpackState.
    var h2_wire: u8[>..] = [];
    assert(!wire::encode_h2_headers_frame_from_map(enc, 0, req_pseudo, req_hdrs, true, h2_wire));
    assert(h2_wire.len == 0);
    assert(wire::encode_h2_headers_frame_from_map(enc, 1, req_pseudo, req_hdrs, true, h2_wire));
    let f_hdr, err_fhdr = wire::decode_h2_frame_header(h2_wire[..]);
    assert(
        err_fhdr == rfc::H2_ERR_NO_ERROR && f_hdr.frame_type == rfc::H2_FRAME_HEADERS &&
        f_hdr.stream_id == 1,
    );
    assert((f_hdr.flags & rfc::H2_FLAG_END_STREAM) != 0);
    assert((f_hdr.flags & rfc::H2_FLAG_END_HEADERS) != 0);

    print("wire_hpack_h2_facade_ok: true");
    // CHECK: wire_hpack_h2_facade_ok: true
}

fn main() {
    test_client_ca_and_ssrf_facade();
    test_wire_tls13_facade();
    test_wire_hpack_and_h2_facade();
}
