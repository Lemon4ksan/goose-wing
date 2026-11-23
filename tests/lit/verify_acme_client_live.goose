// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Goose LIT Verification Suite: Live RFC 8555 ACME v2 HTTP-01 Client.
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import json;
import wing from "../..";

struct MockAcmeServerCfg {
    listener_fd: i64,
    port:        u16,
    cert_priv:   u8[32],
    acct_pub:    u8[65],
}

struct Http01PublishEvent {
    token:    u8[..64],
    key_auth: u8[..256],
}

struct MockHttp01Hook {
    publish_count:      i32       = 0,
    clear_count:        i32       = 0,
    published_token:    u8[..64]  = [],
    published_key_auth: u8[..256] = [],
    cleared_token:      u8[..64]  = [],
    clear_ok:           bool      = false,
}

fn acme_publish_http01(h: MockHttp01Hook&, token: const u8[:], key_auth: const u8[:]) -> bool {
    h.publish_count += 1;
    guard h.published_token.try_set(token) && h.published_key_auth.try_set(key_auth) else {
        return false;
    }
    var ev = Http01PublishEvent { .. };
    guard ev.token.try_set(token) && ev.key_auth.try_set(key_auth) else { return false; }
    qput(ev);
    return true;
}

fn acme_clear_http01(h: MockHttp01Hook&, token: const u8[:]) {
    h.clear_count += 1;
    let _ = h.cleared_token.try_set(token);
    if h.published_token[..] == token {
        h.clear_ok = true;
    }
}

fn make_account_priv() -> u8[32] {
    return [
        0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16,
        0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6, 0x93,
        0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12,
        0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21,
    ];
}

fn make_cert_priv() -> u8[32] {
    return [
        0x31, 0x41, 0x59, 0x26, 0x53, 0x58, 0x97, 0x93,
        0x23, 0x84, 0x62, 0x64, 0x33, 0x83, 0x27, 0x95,
        0x02, 0x88, 0x41, 0x97, 0x16, 0x93, 0x99, 0x37,
        0x51, 0x05, 0x82, 0x09, 0x74, 0x94, 0x45, 0x92,
    ];
}

fn make_ca_priv() -> u8[32] {
    return [
        0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
        0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10,
    ];
}

// ---- X.509 P-256 Chain & PKCS#8 PEM Builders for Mock CA -------------------

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

fn append_pem(label: const u8[:], der: const u8[:], out: u8[>..]&) {
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

fn build_cn_name_der(cn: const u8[:], out: u8[..256]&) {
    var b_cn = core::builder_init();
    b_cn.put_u8(0x30);
    b_cn.put_u8((7 + cn.len) as u8);
    b_cn.put_bytes("\x06\x03\x55\x04\x03\x0C");
    b_cn.put_u8(cn.len as u8);
    b_cn.put_bytes(cn);

    var b_name = core::builder_init();
    b_name.put_u8(0x30);
    b_name.put_u8((2 + b_cn.buf.len) as u8);
    b_name.put_u8(0x31);
    b_name.put_u8(b_cn.buf.len as u8);
    b_name.put_bytes(b_cn.buf[..]);
    assert(out.try_set(b_name.buf[..]));
}

fn make_p256_signed_cert_der(
    subj_priv:   const u8[32]&,
    issuer_priv: const u8[32]&,
    issuer_cn:   const u8[:],
    dns_san:     const u8[:],
    serial:      u8,
    is_ca:       bool,
    out_der:     u8[..2048]&,
) -> bool {
    let pub65 = core::ecdsa_p256_public_key(subj_priv);
    let alg = "\x30\x0A\x06\x08\x2A\x86\x48\xCE\x3D\x04\x03\x02";
    var issuer_der: u8[..256] = [];
    var subj_der:   u8[..256] = [];
    build_cn_name_der(issuer_cn, issuer_der);
    build_cn_name_der(dns_san, subj_der);

    var b_tbs = core::builder_init();
    b_tbs.put_bytes("\xA0\x03\x02\x01\x02\x02\x01");
    b_tbs.put_u8(serial);
    b_tbs.put_bytes(alg);
    b_tbs.put_bytes(issuer_der[..]);
    b_tbs.put_bytes("\x30\x1E\x17\x0D240101000000Z\x17\x0D351231235959Z");
    b_tbs.put_bytes(subj_der[..]);
    b_tbs.put_bytes("\x30\x59\x30\x13\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01");
    b_tbs.put_bytes("\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07\x03\x42\x00");
    b_tbs.put_bytes(pub65[..]);

    var b_ext = core::builder_init();
    if is_ca {
        b_ext.put_bytes("\x30\x0C\x06\x03\x55\x1D\x13\x04\x05\x30\x03\x01\x01\xFF");
    } else {
        b_ext.put_bytes("\x30\x09\x06\x03\x55\x1D\x13\x04\x02\x30\x00");
    }
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
    let raw_sig = core::ecdsa_p256_sign(issuer_priv, tbs_wrapped[..]);
    var der_sig: u8[..72] = [];
    guard core::ecdsa_p256_encode_der_sig(raw_sig, der_sig) else { return false; }

    var b_cert = core::builder_init();
    b_cert.put_bytes(tbs_wrapped[..]);
    b_cert.put_bytes(alg);
    b_cert.put_u8(0x03);
    b_cert.put_u8((1 + der_sig.len) as u8);
    b_cert.put_u8(0x00);
    b_cert.put_bytes(der_sig[..]);

    var tmp_der: u8[..2048] = [];
    wrap_der_tlv(0x30, b_cert.buf[..], tmp_der);
    return out_der.try_set(tmp_der[..]);
}

fn make_p256_pkcs8_der(priv_key: const u8[32]&, out_der: u8[..512]&) -> bool {
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

// ---- Loopback Mock RFC 8555 HTTP/1.1 Server --------------------------------

struct MockHttpReq {
    method:       u8[..16]  = [],
    path:         u8[..256] = [],
    content_type: u8[..128] = [],
    accept:       u8[..128] = [],
    body:         u8[>..]   = [],
}

fn read_mock_http_request(conn: i64, out_req: MockHttpReq&) -> bool {
    var raw:     u8[>..]  = [];
    var rx:      u8[4096] = [0; 4096];
    var hdr_end: i64      = -1;
    while hdr_end < 0 {
        let n = net::tcp_recv_slice(conn, rx[..], 5000);
        guard n > 0 else { return false; }
        raw.append(rx[..n]);
        hdr_end = core::fast_find_crlfcrlf(raw[..]);
    }
    let body_start = hdr_end + 4;
    let head_block = raw[..hdr_end];
    let req_line, hdrs_part, has_nl = head_block.split_once_byte('\n');
    let clean_req_line = req_line.trim_end_byte('\r');
    let sp1 = clean_req_line.index_of_byte(' ');
    guard sp1 > 0 else { return false; }
    let rest_line = clean_req_line[(sp1 + 1)..];
    let sp2 = rest_line.index_of_byte(' ');
    guard sp2 > 0 else { return false; }
    assert(out_req.method.try_set(clean_req_line[..sp1]));
    assert(out_req.path.try_set(rest_line[..sp2]));

    var cl_val: i64 = 0;
    if has_nl {
        var rem = hdrs_part;
        while rem.len > 0 {
            let line_raw, tail, more = rem.split_once_byte('\n');
            let line = line_raw.trim_end_byte('\r');
            let col = line.index_of_byte(':');
            if col > 0 {
                let name = line[..col];
                let val = line[(col + 1)..].trim_lws();
                if name.eq_ascii_fold("content-length") {
                    let v, ok = val.parse_u64_dec();
                    assert(ok);
                    cl_val = v as i64;
                } else if name.eq_ascii_fold("content-type") {
                    let _ = out_req.content_type.try_set(val);
                } else if name.eq_ascii_fold("accept") {
                    let _ = out_req.accept.try_set(val);
                }
            }
            if !more { break; }
            rem = tail;
        }
    }
    while raw.len < body_start + cl_val {
        let n = net::tcp_recv_slice(conn, rx[..], 5000);
        guard n > 0 else { return false; }
        raw.append(rx[..n]);
    }
    out_req.body.clear();
    out_req.body.append(raw[body_start..(body_start + cl_val)]);
    return true;
}

fn send_mock_http_resp(
    conn:         i64,
    status_line:  const u8[:],
    content_type: const u8[:],
    nonce:        const u8[:],
    location:     const u8[:],
    body:         const u8[:],
    is_head:      bool = false,
) {
    var out: u8[>..] = [];
    out.append(status_line);
    if content_type.len > 0 {
        out.append("Content-Type: ");
        out.append(content_type);
        out.append("\r\n");
    }
    if nonce.len > 0 {
        out.append("Replay-Nonce: ");
        out.append(nonce);
        out.append("\r\n");
    }
    if location.len > 0 {
        out.append("Location: ");
        out.append(location);
        out.append("\r\n");
    }
    out.append("Content-Length: ");
    body.len.format_i64_dec(out);
    out.append("\r\nConnection: close\r\n\r\n");
    if !is_head && body.len > 0 {
        out.append(body);
    }
    var off: i64 = 0;
    while off < out.len {
        let sent = net::tcp_send(conn, out[off..]);
        assert(sent > 0);
        off += sent;
    }
}

fn verify_acme_jws_request(
    req:            const MockHttpReq&,
    acct_pub:       const u8[:],
    expected_url:   const u8[:],
    expected_nonce: const u8[:],
    expected_kid:   const u8[:],
    out_payload:    u8[>..]&,
) {
    assert(req.method[..] == "POST");
    assert(req.content_type[..] == "application/jose+json");

    var prot_b64: u8[..2048] = [];
    var pay_b64:  u8[..4096] = [];
    var sig_b64:  u8[..128]  = [];
    var r = json::reader(req.body[..]);
    assert(json::peek(r) == '{');
    json::each_member(r) { k =>
        if k == "protected" {
            assert(core::read_json_string_into(r, prot_b64));
        } else if k == "payload" {
            assert(core::read_json_string_into(r, pay_b64));
        } else if k == "signature" {
            assert(core::read_json_string_into(r, sig_b64));
        } else {
            assert(false);
        }
    };
    assert(json::finish(r));

    var prot_json: u8[..2048] = [];
    assert(core::base64url_decode(prot_b64[..], prot_json));
    var alg_v:   u8[..32]  = [];
    var nonce_v: u8[..128] = [];
    var url_v:   u8[..256] = [];
    var kid_v:   u8[..256] = [];
    var has_jwk = false;
    var has_kid = false;
    var pr = json::reader(prot_json[..]);
    assert(json::peek(pr) == '{');
    json::each_member(pr) { k =>
        if k == "alg" {
            assert(core::read_json_string_into(pr, alg_v));
        } else if k == "nonce" {
            assert(core::read_json_string_into(pr, nonce_v));
        } else if k == "url" {
            assert(core::read_json_string_into(pr, url_v));
        } else if k == "kid" {
            has_kid = true;
            assert(core::read_json_string_into(pr, kid_v));
        } else if k == "jwk" {
            has_jwk = true;
            json::skip(pr);
        } else {
            assert(false);
        }
    };
    assert(json::finish(pr));
    assert(alg_v[..] == "ES256");
    assert(nonce_v[..] == expected_nonce);
    assert(url_v[..] == expected_url);
    if expected_kid.len == 0 {
        assert(has_jwk && !has_kid);
    } else {
        assert(has_kid && !has_jwk && kid_v[..] == expected_kid);
    }

    var sig_raw: u8[..128] = [];
    assert(core::base64url_decode(sig_b64[..], sig_raw) && sig_raw.len == 64);
    var sig_in: u8[>..] = [];
    sig_in.append(prot_b64[..]);
    sig_in.push('.');
    sig_in.append(pay_b64[..]);
    assert(core::ecdsa_p256_verify_p1363(acct_pub, sig_in[..], sig_raw[..]));

    out_payload.clear();
    if pay_b64.len > 0 {
        assert(core::base64url_decode(pay_b64[..], out_payload));
    }
}

fn make_base_url(port: u16, path: const u8[:], out: u8[..256]&) {
    out.clear();
    out.append("http://127.0.0.1:");
    port.format_u64_dec(out);
    out.append(path);
}

fn verify_csr_payload_der(payload_json: const u8[:]) {
    var csr_b64: u8[..4096] = [];
    var r = json::reader(payload_json);
    assert(json::peek(r) == '{');
    json::each_member(r) { k =>
        if k == "csr" {
            assert(core::read_json_string_into(r, csr_b64));
        } else {
            json::skip(r);
        }
    };
    assert(json::finish(r) && csr_b64.len > 64);
    var csr_der: u8[..4096] = [];
    assert(core::base64url_decode(csr_b64[..], csr_der));
    assert(csr_der.len > 64 && csr_der[0] == 0x30);
}

thread_fn mock_acme_happy_server(cfg: MockAcmeServerCfg) {
    var base: u8[..256] = [];
    make_base_url(cfg.port, "", base);

    var u_nonce:  u8[..256] = [];
    var u_acct:   u8[..256] = [];
    var u_acct1:  u8[..256] = [];
    var u_order:  u8[..256] = [];
    var u_order1: u8[..256] = [];
    var u_authz1: u8[..256] = [];
    var u_chall1: u8[..256] = [];
    var u_fin1:   u8[..256] = [];
    var u_cert1:  u8[..256] = [];
    make_base_url(cfg.port, "/new-nonce", u_nonce);
    make_base_url(cfg.port, "/new-acct", u_acct);
    make_base_url(cfg.port, "/acct/1", u_acct1);
    make_base_url(cfg.port, "/new-order", u_order);
    make_base_url(cfg.port, "/order/1", u_order1);
    make_base_url(cfg.port, "/authz/1", u_authz1);
    make_base_url(cfg.port, "/chall/1", u_chall1);
    make_base_url(cfg.port, "/finalize/1", u_fin1);
    make_base_url(cfg.port, "/cert/1", u_cert1);

    let ca_priv = make_ca_priv();
    var leaf_der: u8[..2048] = [];
    var ca_der:   u8[..2048] = [];
    assert(make_p256_signed_cert_der(cfg.cert_priv, ca_priv, "Mock ACME CA", "example.com", 0x05, false, leaf_der));
    assert(make_p256_signed_cert_der(ca_priv, ca_priv, "Mock ACME CA", "Mock ACME CA", 0x01, true, ca_der));
    var fullchain_pem: u8[>..] = [];
    append_pem("CERTIFICATE", leaf_der[..], fullchain_pem);
    append_pem("CERTIFICATE", ca_der[..], fullchain_pem);

    var new_order_hits:  i32       = 0;
    var order_poll_hits: i32       = 0;
    var active_nonce:    u8[..128] = "nonce-init-1";
    var payload:         u8[>..]   = [];
    var done = false;

    while !done {
        let conn = net::tcp_accept(cfg.listener_fd, 5000);
        assert(conn > 0);
        var req = MockHttpReq { .. };
        assert(read_mock_http_request(conn, req));

        if req.method[..] == "GET" && req.path[..] == "/directory" {
            let body = str(
                "{\"newNonce\":\"", u_nonce[..],
                "\",\"newAccount\":\"", u_acct[..],
                "\",\"newOrder\":\"", u_order[..], "\"}",
            );
            send_mock_http_resp(conn, "HTTP/1.1 200 OK\r\n", "application/json", "", "", body[..]);
        } else if req.method[..] == "HEAD" && req.path[..] == "/new-nonce" {
            assert(active_nonce.try_set("nonce-init-1"));
            send_mock_http_resp(conn, "HTTP/1.1 200 OK\r\n", "", active_nonce[..], "", "", true);
        } else if req.path[..] == "/new-acct" {
            verify_acme_jws_request(req, cfg.acct_pub[..], u_acct[..], active_nonce[..], "", payload);
            assert(core::contains(payload[..], "\"termsOfServiceAgreed\":true"));
            assert(core::contains(payload[..], "\"mailto:ops@example.com\""));
            assert(active_nonce.try_set("nonce-acct-2"));
            let body = "{\"status\":\"valid\"}";
            send_mock_http_resp(conn, "HTTP/1.1 201 Created\r\n", "application/json", active_nonce[..], u_acct1[..], body);
        } else if req.path[..] == "/new-order" {
            new_order_hits += 1;
            verify_acme_jws_request(req, cfg.acct_pub[..], u_order[..], active_nonce[..], u_acct1[..], payload);
            if new_order_hits == 1 {
                assert(active_nonce.try_set("nonce-bad-retry-3"));
                let err_body = "{\"type\":\"urn:ietf:params:acme:error:badNonce\",\"detail\":\"stale\"}";
                send_mock_http_resp(
                    conn, "HTTP/1.1 400 Bad Request\r\n", "application/problem+json",
                    active_nonce[..], "", err_body,
                );
            } else {
                assert(active_nonce.try_set("nonce-ord-4"));
                let body = str(
                    "{\"status\":\"pending\",\"authorizations\":[\"", u_authz1[..],
                    "\"],\"finalize\":\"", u_fin1[..], "\"}",
                );
                send_mock_http_resp(
                    conn, "HTTP/1.1 201 Created\r\n", "application/json",
                    active_nonce[..], u_order1[..], body[..],
                );
            }
        } else if req.path[..] == "/authz/1" {
            verify_acme_jws_request(req, cfg.acct_pub[..], u_authz1[..], active_nonce[..], u_acct1[..], payload);
            assert(payload.len == 0);
            assert(active_nonce.try_set("nonce-az-5"));
            let body = str(
                "{\"status\":\"pending\",\"challenges\":[{\"type\":\"http-01\",\"url\":\"",
                u_chall1[..], "\",\"status\":\"pending\",\"token\":\"LoqXcYV8q5ONbJQxbmR7SC\"}]}",
            );
            send_mock_http_resp(conn, "HTTP/1.1 200 OK\r\n", "application/json", active_nonce[..], "", body[..]);
        } else if req.path[..] == "/chall/1" {
            verify_acme_jws_request(req, cfg.acct_pub[..], u_chall1[..], active_nonce[..], u_acct1[..], payload);
            assert(payload[..] == "{}");
            let pub_ev, has_pub = qpoll<Http01PublishEvent>();
            assert(has_pub);
            assert(pub_ev.token[..] == "LoqXcYV8q5ONbJQxbmR7SC");
            assert(active_nonce.try_set("nonce-ch-6"));
            let body = str(
                "{\"type\":\"http-01\",\"url\":\"", u_chall1[..],
                "\",\"status\":\"pending\",\"token\":\"LoqXcYV8q5ONbJQxbmR7SC\"}",
            );
            send_mock_http_resp(conn, "HTTP/1.1 200 OK\r\n", "application/json", active_nonce[..], "", body[..]);
        } else if req.path[..] == "/order/1" {
            order_poll_hits += 1;
            verify_acme_jws_request(req, cfg.acct_pub[..], u_order1[..], active_nonce[..], u_acct1[..], payload);
            assert(payload.len == 0);
            if order_poll_hits == 1 {
                assert(active_nonce.try_set("nonce-p1-7"));
                let body = str(
                    "{\"status\":\"pending\",\"authorizations\":[\"", u_authz1[..],
                    "\"],\"finalize\":\"", u_fin1[..], "\"}",
                );
                send_mock_http_resp(conn, "HTTP/1.1 200 OK\r\n", "application/json", active_nonce[..], "", body[..]);
            } else if order_poll_hits == 2 {
                assert(active_nonce.try_set("nonce-p2-8"));
                let body = str(
                    "{\"status\":\"ready\",\"authorizations\":[\"", u_authz1[..],
                    "\"],\"finalize\":\"", u_fin1[..], "\"}",
                );
                send_mock_http_resp(conn, "HTTP/1.1 200 OK\r\n", "application/json", active_nonce[..], "", body[..]);
            } else {
                assert(active_nonce.try_set("nonce-p3-10"));
                let body = str(
                    "{\"status\":\"valid\",\"authorizations\":[\"", u_authz1[..],
                    "\"],\"finalize\":\"", u_fin1[..],
                    "\",\"certificate\":\"", u_cert1[..], "\"}",
                );
                send_mock_http_resp(conn, "HTTP/1.1 200 OK\r\n", "application/json", active_nonce[..], "", body[..]);
            }
        } else if req.path[..] == "/finalize/1" {
            verify_acme_jws_request(req, cfg.acct_pub[..], u_fin1[..], active_nonce[..], u_acct1[..], payload);
            verify_csr_payload_der(payload[..]);
            assert(active_nonce.try_set("nonce-fin-9"));
            let body = str(
                "{\"status\":\"processing\",\"authorizations\":[\"", u_authz1[..],
                "\"],\"finalize\":\"", u_fin1[..], "\"}",
            );
            send_mock_http_resp(conn, "HTTP/1.1 200 OK\r\n", "application/json", active_nonce[..], "", body[..]);
        } else if req.path[..] == "/cert/1" {
            verify_acme_jws_request(req, cfg.acct_pub[..], u_cert1[..], active_nonce[..], u_acct1[..], payload);
            assert(payload.len == 0);
            assert(req.accept[..] == "application/pem-certificate-chain");
            assert(active_nonce.try_set("nonce-cert-11"));
            send_mock_http_resp(
                conn, "HTTP/1.1 200 OK\r\n", "application/pem-certificate-chain",
                active_nonce[..], "", fullchain_pem[..],
            );
            done = true;
        } else {
            assert(false);
        }
        net::tcp_close(conn);
    }
    assert(new_order_hits == 2 && order_poll_hits == 3);
}

thread_fn mock_acme_invalid_order_server(cfg: MockAcmeServerCfg) {
    var u_nonce:  u8[..256] = [];
    var u_acct:   u8[..256] = [];
    var u_acct1:  u8[..256] = [];
    var u_order:  u8[..256] = [];
    var u_order1: u8[..256] = [];
    var u_authz1: u8[..256] = [];
    var u_chall1: u8[..256] = [];
    var u_fin1:   u8[..256] = [];
    make_base_url(cfg.port, "/new-nonce", u_nonce);
    make_base_url(cfg.port, "/new-acct", u_acct);
    make_base_url(cfg.port, "/acct/1", u_acct1);
    make_base_url(cfg.port, "/new-order", u_order);
    make_base_url(cfg.port, "/order/1", u_order1);
    make_base_url(cfg.port, "/authz/1", u_authz1);
    make_base_url(cfg.port, "/chall/1", u_chall1);
    make_base_url(cfg.port, "/finalize/1", u_fin1);

    var active_nonce:   u8[..128] = "inv-nonce-1";
    var new_order_hits: i32       = 0;
    var payload:        u8[>..]   = [];
    var done = false;

    while !done {
        let conn = net::tcp_accept(cfg.listener_fd, 5000);
        assert(conn > 0);
        var req = MockHttpReq { .. };
        assert(read_mock_http_request(conn, req));

        if req.method[..] == "GET" && req.path[..] == "/directory" {
            let body = str(
                "{\"newNonce\":\"", u_nonce[..],
                "\",\"newAccount\":\"", u_acct[..],
                "\",\"newOrder\":\"", u_order[..], "\"}",
            );
            send_mock_http_resp(conn, "HTTP/1.1 200 OK\r\n", "application/json", "", "", body[..]);
        } else if req.method[..] == "HEAD" && req.path[..] == "/new-nonce" {
            if new_order_hits == 0 {
                assert(active_nonce.try_set("inv-nonce-1"));
            } else {
                assert(active_nonce.try_set("inv-nonce-refetched"));
            }
            send_mock_http_resp(conn, "HTTP/1.1 204 No Content\r\n", "", active_nonce[..], "", "", true);
        } else if req.path[..] == "/new-acct" {
            verify_acme_jws_request(req, cfg.acct_pub[..], u_acct[..], active_nonce[..], "", payload);
            assert(active_nonce.try_set("inv-nonce-2"));
            send_mock_http_resp(
                conn, "HTTP/1.1 200 OK\r\n", "application/json",
                active_nonce[..], u_acct1[..], "{\"status\":\"valid\"}",
            );
        } else if req.path[..] == "/new-order" {
            new_order_hits += 1;
            verify_acme_jws_request(req, cfg.acct_pub[..], u_order[..], active_nonce[..], u_acct1[..], payload);
            if new_order_hits == 1 {
                // Force badNonce WITHOUT Replay-Nonce header to verify HEAD /new-nonce fallback!
                let err_body = "{\"type\":\"urn:ietf:params:acme:error:badNonce\",\"detail\":\"missing\"}";
                send_mock_http_resp(
                    conn, "HTTP/1.1 400 Bad Request\r\n", "application/problem+json",
                    "", "", err_body,
                );
            } else {
                assert(active_nonce.try_set("inv-nonce-3"));
                let body = str(
                    "{\"status\":\"pending\",\"authorizations\":[\"", u_authz1[..],
                    "\"],\"finalize\":\"", u_fin1[..], "\"}",
                );
                send_mock_http_resp(
                    conn, "HTTP/1.1 201 Created\r\n", "application/json",
                    active_nonce[..], u_order1[..], body[..],
                );
            }
        } else if req.path[..] == "/authz/1" {
            verify_acme_jws_request(req, cfg.acct_pub[..], u_authz1[..], active_nonce[..], u_acct1[..], payload);
            assert(active_nonce.try_set("inv-nonce-4"));
            let body = str(
                "{\"status\":\"pending\",\"challenges\":[{\"type\":\"http-01\",\"url\":\"",
                u_chall1[..], "\",\"status\":\"pending\",\"token\":\"InvalidOrderTok0123456789\"}]}",
            );
            send_mock_http_resp(conn, "HTTP/1.1 200 OK\r\n", "application/json", active_nonce[..], "", body[..]);
        } else if req.path[..] == "/chall/1" {
            verify_acme_jws_request(req, cfg.acct_pub[..], u_chall1[..], active_nonce[..], u_acct1[..], payload);
            let pub_ev, has_pub = qpoll<Http01PublishEvent>();
            assert(has_pub && pub_ev.token[..] == "InvalidOrderTok0123456789");
            assert(active_nonce.try_set("inv-nonce-5"));
            let body = str(
                "{\"type\":\"http-01\",\"url\":\"", u_chall1[..],
                "\",\"status\":\"pending\",\"token\":\"InvalidOrderTok0123456789\"}",
            );
            send_mock_http_resp(conn, "HTTP/1.1 200 OK\r\n", "application/json", active_nonce[..], "", body[..]);
        } else if req.path[..] == "/order/1" {
            verify_acme_jws_request(req, cfg.acct_pub[..], u_order1[..], active_nonce[..], u_acct1[..], payload);
            assert(active_nonce.try_set("inv-nonce-6"));
            let body = str(
                "{\"status\":\"invalid\",\"authorizations\":[\"", u_authz1[..],
                "\"],\"finalize\":\"", u_fin1[..], "\"}",
            );
            send_mock_http_resp(conn, "HTTP/1.1 200 OK\r\n", "application/json", active_nonce[..], "", body[..]);
            done = true;
        } else {
            assert(false);
        }
        net::tcp_close(conn);
    }
    assert(new_order_hits == 2);
}

// 1. Live RFC 8555 ACME v2 full issuance flow with badNonce retry, polling, CSR, and PEM loading
// CHECK: ACME_LIVE_FULLCHAIN_ISSUANCE: PASS
fn test_live_acme_happy_issuance() {
    let acct_priv = make_account_priv();
    let cert_priv = make_cert_priv();
    let acct_pub = core::ecdsa_p256_public_key(acct_priv);

    let lst = net::tcp_listen("127.0.0.1", 0, 16);
    assert(lst > 0);
    let port = net::tcp_getsockname_port(lst);
    assert(port > 0);

    let tid = thread_spawn(mock_acme_happy_server, MockAcmeServerCfg {
        listener_fd: lst,
        port:        port,
        cert_priv:   cert_priv,
        acct_pub:    acct_pub,
    });

    var sess = client::new_session(client::Config { timeout_ms: 5000, .. });
    defer sess.close();
    sess.ssrf_guard.enabled = false;

    var dir_url: u8[..256] = [];
    make_base_url(port, "/directory", dir_url);
    var cfg = client::AcmeClientConfig {
        directory_url:     dir_url,
        contact_email:     "ops@example.com",
        accept_tos:        true,
        poll_interval_ms:  5,
        max_poll_attempts: 8,
    };
    var acme = client::AcmeSession { .. };

    assert(client::acme_fetch_directory(sess, cfg.directory_url[..], acme.dir));
    assert(client::acme_fetch_nonce(sess, acme.dir.new_nonce[..], acme.nonce));
    assert(acme.nonce[..] == "nonce-init-1");
    assert(client::acme_ensure_account(sess, acme, acct_priv, cfg));

    var exp_acct_url: u8[..256] = [];
    make_base_url(port, "/acct/1", exp_acct_url);
    assert(acme.kid[..] == exp_acct_url[..]);

    var domains: u8[..255][..1] = [];
    var d1:      u8[..255]      = "example.com";
    domains.push(d1);

    var hook = MockHttp01Hook { .. };
    var fullchain_pem: u8[>..] = [];
    assert(client::acme_obtain_cert_http01(
        sess, acme, acct_priv, cert_priv, cfg, domains[..], hook, fullchain_pem,
    ));
    assert(thread_wait(tid));
    net::tcp_close(lst);

    assert(hook.publish_count == 1 && hook.clear_count == 1);
    assert(hook.published_token[..] == "LoqXcYV8q5ONbJQxbmR7SC");
    assert(hook.cleared_token[..] == "LoqXcYV8q5ONbJQxbmR7SC");
    assert(hook.clear_ok);
    assert(acme.nonce[..] == "nonce-cert-11");

    var key_der: u8[..512] = [];
    assert(make_p256_pkcs8_der(cert_priv, key_der));
    var key_pem: u8[>..] = [];
    append_pem("PRIVATE KEY", key_der[..], key_pem);

    var srv_cfg = tls::ServerHandshakeConfig { .. };
    assert(tls::load_server_credentials_pem(fullchain_pem[..], key_pem[..], srv_cfg));
    assert(srv_cfg.extra_certs_der.len == 1);
    assert(srv_cfg.key_kind == tls::PrivateKeyKind.EcdsaP256);

    print("ACME_LIVE_FULLCHAIN_ISSUANCE: PASS\n");
}

// 2. Defer HTTP-01 token cleanup on invalid order failure + HEAD newNonce fallback on 400 badNonce
// CHECK: ACME_LIVE_DEFER_CLEANUP_ON_INVALID: PASS
fn test_live_acme_invalid_order_defer_cleanup() {
    let acct_priv = make_account_priv();
    let cert_priv = make_cert_priv();
    let acct_pub = core::ecdsa_p256_public_key(acct_priv);

    let lst = net::tcp_listen("127.0.0.1", 0, 16);
    assert(lst > 0);
    let port = net::tcp_getsockname_port(lst);
    assert(port > 0);

    let tid = thread_spawn(mock_acme_invalid_order_server, MockAcmeServerCfg {
        listener_fd: lst,
        port:        port,
        cert_priv:   cert_priv,
        acct_pub:    acct_pub,
    });

    var sess = client::new_session(client::Config { timeout_ms: 5000, .. });
    defer sess.close();
    sess.ssrf_guard.enabled = false;

    var dir_url: u8[..256] = [];
    make_base_url(port, "/directory", dir_url);
    var cfg = client::AcmeClientConfig {
        directory_url:     dir_url,
        accept_tos:        true,
        poll_interval_ms:  5,
        max_poll_attempts: 4,
        ..
    };
    var acme = client::AcmeSession { .. };

    assert(client::acme_ensure_account(sess, acme, acct_priv, cfg));
    var domains: u8[..255][..1] = [];
    var d1:      u8[..255]      = "example.org";
    domains.push(d1);

    var hook = MockHttp01Hook { .. };
    var fullchain_pem: u8[>..] = "dirty-sentinel";
    let ok = client::acme_obtain_cert_http01(
        sess, acme, acct_priv, cert_priv, cfg, domains[..], hook, fullchain_pem,
    );
    assert(!ok);
    assert(fullchain_pem.len == 0);
    assert(thread_wait(tid));
    net::tcp_close(lst);

    assert(hook.publish_count == 1 && hook.clear_count == 1);
    assert(hook.published_token[..] == "InvalidOrderTok0123456789");
    assert(hook.cleared_token[..] == "InvalidOrderTok0123456789");
    assert(hook.clear_ok);

    print("ACME_LIVE_DEFER_CLEANUP_ON_INVALID: PASS\n");
}

// 3. Fail-closed boundary checks (ToS, invalid domains, SSRF, dirty URLs, transactional clears)
// CHECK: ACME_CLIENT_BOUNDARY_GUARDS: PASS
fn test_acme_client_boundary_guards() {
    let acct_priv = make_account_priv();
    let cert_priv = make_cert_priv();
    var sess = client::new_session();
    defer sess.close();
    sess.ssrf_guard = security::SsrfGuardPolicy { .. };

    // Dirty URL clears out_dir / out_nonce transactionally
    var dir = auth::AcmeDirectory { new_nonce: "https://ex/n", .. };
    assert(!client::acme_fetch_directory(sess, "ftp://ex/dir", dir));
    assert(dir.new_nonce.len == 0);
    var nonce: u8[..128] = "stale";
    assert(!client::acme_fetch_nonce(sess, "http://127.0.0.1:9999/new-nonce", nonce));
    assert(nonce.len == 0);

    // SSRF guard rejects loopback directory URL cleanly
    assert(!client::acme_fetch_directory(sess, "http://127.0.0.1:9999/directory", dir));

    // accept_tos == false rejected cleanly
    var acme = client::AcmeSession {
        dir: auth::AcmeDirectory {
            new_nonce:   "https://acme.example/n",
            new_account: "https://acme.example/a",
            new_order:   "https://acme.example/o",
        },
        ..
    };
    var cfg_no_tos = client::AcmeClientConfig { accept_tos: false, .. };
    assert(!client::acme_ensure_account(sess, acme, acct_priv, cfg_no_tos));
    assert(acme.kid.len == 0);

    // Invalid domains and empty domains clear out_fullchain_pem
    var hook = MockHttp01Hook { .. };
    var pem: u8[>..] = "stale";
    let empty_doms: u8[..255][..1] = [];
    assert(!client::acme_obtain_cert_http01(
        sess, acme, acct_priv, cert_priv, cfg_no_tos, empty_doms[..], hook, pem,
    ));
    assert(pem.len == 0);

    var wild_doms: u8[..255][..1] = [];
    var dw:        u8[..255]      = "*.example.com";
    wild_doms.push(dw);
    pem.append("stale");
    assert(!client::acme_obtain_cert_http01(
        sess, acme, acct_priv, cert_priv, cfg_no_tos, wild_doms[..], hook, pem,
    ));
    assert(pem.len == 0 && hook.publish_count == 0);

    // Invalid Replay-Nonce (space), missing/SSRF Location on newAccount, badNonce retry exhaustion, body overflow
    let _ = sess.mock_route("HEAD", "https://acme.example/bad-nonce", 200, "");
    sess.add_mock_header("Replay-Nonce", "bad nonce with space");
    let _ = nonce.try_set("stale");
    assert(!client::acme_fetch_nonce(sess, "https://acme.example/bad-nonce", nonce));
    assert(nonce.len == 0);

    let _ = sess.mock_route("POST", "https://acme.example/a-ssrf", 201, "{\"status\":\"valid\"}");
    sess.add_mock_header("Replay-Nonce", "n-ssrf");
    sess.add_mock_header("Location", "http://169.254.169.254/latest/meta-data");
    var acme_m = client::AcmeSession {
        dir: auth::AcmeDirectory {
            new_nonce:   "https://acme.example/n",
            new_account: "https://acme.example/a-ssrf",
            new_order:   "https://acme.example/o-bad",
        },
        nonce: "init-m",
        ..
    };
    let cfg_tos = client::AcmeClientConfig { accept_tos: true, .. };
    assert(!client::acme_ensure_account(sess, acme_m, acct_priv, cfg_tos));
    assert(acme_m.kid.len == 0 && acme_m.nonce[..] == "n-ssrf");

    let _ = sess.mock_route(
        "POST",
        "https://acme.example/o-bad",
        400,
        "{\"type\":\"urn:ietf:params:acme:error:badNonce\",\"detail\":\"always bad\"}",
    );
    sess.add_mock_header("Replay-Nonce", "n-exhaust");
    assert(acme_m.kid.try_set("https://acme.example/acct/99"));
    var ok_doms: u8[..255][..1] = [];
    var dok:     u8[..255]      = "example.net";
    ok_doms.push(dok);
    pem.append("stale");
    assert(!client::acme_obtain_cert_http01(
        sess, acme_m, acct_priv, cert_priv, cfg_tos, ok_doms[..], hook, pem,
    ));
    assert(pem.len == 0 && acme_m.nonce[..] == "n-exhaust");

    sess.max_response_body_bytes = 16;
    let _ = sess.mock_route(
        "GET",
        "https://acme.example/dir-big",
        200,
        "{\"newNonce\":\"https://acme.example/n\",\"newAccount\":\"https://acme.example/a\",\"newOrder\":\"https://acme.example/o\"}",
    );
    assert(dir.new_nonce.try_set("https://acme.example/stale"));
    assert(!client::acme_fetch_directory(sess, "https://acme.example/dir-big", dir));
    assert(dir.new_nonce.len == 0);

    print("ACME_CLIENT_BOUNDARY_GUARDS: PASS\n");
}

fn main() {
    test_live_acme_happy_issuance();
    test_live_acme_invalid_order_defer_cleanup();
    test_acme_client_boundary_guards();
}
