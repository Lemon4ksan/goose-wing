// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// End-to-end verification of the public `wing::` and `wire::` Engine API facade
// (uses only public wing::, wire::, rfc::, and core:: surfaces).
// RUN: goose %s | %FileCheck %s

import std;
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
    assert(tls::build_test_ed25519_cert_der(seed1, "ca1.wing.test", "ca1.wing.test", "", cert1_der));
    assert(tls::build_test_ed25519_cert_der(seed2, "ca2.wing.test", "ca2.wing.test", "", cert2_der));

    var bundle_pem: u8[>..] = [];
    make_pem_block("CERTIFICATE", cert1_der[..], bundle_pem);
    make_pem_block("CERTIFICATE", cert2_der[..], bundle_pem);

    var sess = client::new_session(client::SessionConfig { insecure_skip_verify: true, .. });
    let cnt1, ok1 = client::configure_session_tls_ca_pem(sess, bundle_pem[..]);
    assert(ok1 && cnt1 == 2 && sess.trust_store.anchors.len == 2);
    assert(!sess.insecure_skip_verify);
    assert(sess.ssrf_guard.deny_local_network);

    // Loopback test-harness mode sets deny_local_network = false without disabling CA verification.
    var local_sess = client::new_session(client::SessionConfig { insecure_skip_verify: true, .. });
    let cnt2, ok2 = client::configure_session_tls_ca_pem(local_sess, bundle_pem[..], true);
    assert(ok2 && cnt2 == 2 && !local_sess.insecure_skip_verify);
    assert(!local_sess.ssrf_guard.deny_local_network);

    let parsed_local_url, url_err = core::parse_url("https://127.0.0.1:8443/health");
    assert(url_err == core::UrlParseError.None);

    var ssrf_strict = sess.ssrf_guard;
    ssrf_strict.enabled = true;
    assert(client::validate_url_against_ssrf(parsed_local_url, ssrf_strict) != client::RedirectError.None);

    var ssrf_local = local_sess.ssrf_guard;
    ssrf_local.enabled = true;
    assert(client::validate_url_against_ssrf(parsed_local_url, ssrf_local) == client::RedirectError.None);

    // Negative PEM / rollback cases on Session.
    let c_empty, ok_empty = client::configure_session_tls_ca_pem(sess, "");
    assert(!ok_empty && c_empty == 0 && sess.trust_store.anchors.len == 2);
    let bad_pem = "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";
    let c_bad, ok_bad = client::configure_session_tls_ca_pem(sess, bad_pem);
    assert(!ok_bad && c_bad == 0 && sess.trust_store.anchors.len == 2);

    // File-backed trust anchor loading (positive via OS temp dir + negative/nonexistent).
    let c_miss, ok_miss = client::load_trust_anchors_pem_file(sess, "nonexistent_wing_ca_bundle.pem");
    assert(!ok_miss && c_miss == 0 && sess.trust_store.anchors.len == 2);
    let c_empty_path, ok_empty_path = client::load_trust_anchors_pem_file(sess, "");
    assert(!ok_empty_path && c_empty_path == 0 && sess.trust_store.anchors.len == 2);

    var tmp_dir: u8[>..] = [];
    if env("TEMP", tmp_dir) || env("TMP", tmp_dir) || env("TMPDIR", tmp_dir) {
        var ca_path: u8[>..] = [];
        ca_path.append(tmp_dir[..]);
        ca_path.append("/wing_engine_api_facade_test_ca.pem");
        assert(write_file_atomic(ca_path[..], bundle_pem[..]));

        var file_sess = client::new_session(client::SessionConfig { insecure_skip_verify: true, .. });
        let fc1, fok1 = client::load_trust_anchors_pem_file(file_sess, ca_path[..]);
        assert(fok1 && fc1 == 2 && file_sess.trust_store.anchors.len == 2);
        assert(!file_sess.insecure_skip_verify);

        var direct_store = tls::TrustAnchorStore {};
        let fc2, fok2 = tls::load_trust_anchors_pem_file(direct_store, ca_path[..]);
        assert(fok2 && fc2 == 2 && direct_store.anchors.len == 2);

        // Bad file contents MUST roll back existing anchors cleanly.
        assert(write_file_atomic(ca_path[..], bad_pem));
        let fc_bad, fok_bad = tls::load_trust_anchors_pem_file(direct_store, ca_path[..]);
        assert(!fok_bad && fc_bad == 0 && direct_store.anchors.len == 2);
    }

    print("client_ca_facade_ok: true");
    // CHECK: client_ca_facade_ok: true
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

    var req_hdrs = http::HeaderMap {};
    assert(http::append_header(req_hdrs, "Content-Type", "application/json"));
    http::set_header(req_hdrs, "Authorization", "Bearer top-secret-token", true);
    assert(http::append_header(req_hdrs, "X-Trace-Id", "trace-42"));

    var hpack_wire: u8[>..] = [];
    assert(wire::hpack_encode_header_block(enc, req_pseudo, req_hdrs, hpack_wire, true));
    assert(enc.blocks_encoded == 1 && enc.bytes_encoded == (hpack_wire.len as u64));

    var out_pseudo = wire::WireH2PseudoHeaders {};
    var out_hdrs = http::HeaderMap {};
    let derr = wire::hpack_decode_block(dec, hpack_wire[..], out_pseudo, out_hdrs);
    assert(derr == rfc::H2_ERR_NO_ERROR);
    assert(out_pseudo.method[..] == "POST" && out_pseudo.scheme[..] == "https");
    assert(out_pseudo.authority[..] == "api.wing.test" && out_pseudo.path[..] == "/v1/items");
    assert(dec.blocks_decoded == 1 && dec.bytes_decoded == (hpack_wire.len as u64));
    assert(http::get_header(out_hdrs, "x-trace-id") == "trace-42");
    assert(http::get_header(out_hdrs, "authorization") == "Bearer top-secret-token");

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
    test_wire_hpack_and_h2_facade();
}
