// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose build --debug -O0 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import wing from "../..";

extern fn lit_crypto_random_bytes(out: u8[:]) -> i32 = "wing_crypto_random_bytes";

fn test_csprng_windows_and_posix() {
    var r1: u8[32] = [0; 32];
    var r2: u8[32] = [0; 32];
    let rc1 = lit_crypto_random_bytes(r1[..]);
    let rc2 = lit_crypto_random_bytes(r2[..]);
    var nz1: i64 = 0;
    var nz2: i64 = 0;
    for b in r1 { if b != 0 { nz1 += 1; } }
    for b in r2 { if b != 0 { nz2 += 1; } }
    let distinct = r1[..] != r2[..];
    print("csprng: rc=", rc1, ",", rc2, " nz=", nz1 > 0, ",", nz2 > 0, " distinct=", distinct);
}

fn test_query_helpers() {
    var b64: u8[..64] = [];
    let ok64 = core::append_query_component("a&b=c+d#e%f g", b64);

    var b1024: u8[..1024] = [];
    let ok1024 = core::append_query_component("ok-1024", b1024);

    var bvec: u8[>..] = [];
    let okvec = core::append_query_component("x=1&y=2", bvec);

    var bsmall: u8[..4] = "k=";
    let ok_ovf = core::append_query_component("a&b", bsmall);

    print(
        "query_comp: ", ok64, " ", b64[..], " ", ok1024, " ", okvec, " ", bvec[..],
        " ovf=", ok_ovf, " rollback=", bsmall[..],
    );

    let qs = "?k=hello%20world&flag&empty=&z=1";
    var out: u8[..64] = [];
    let m_val = core::get_query_param_fast(qs, "k", out);
    let val_ok = m_val == core::QueryParamMatch.Value && out[..] == "hello world";

    let m_flag = core::get_query_param_fast(qs, "flag", out);
    let flag_ok = m_flag == core::QueryParamMatch.Valueless && out.len == 0;

    let m_empty = core::get_query_param_fast(qs, "empty", out);
    let empty_ok = m_empty == core::QueryParamMatch.Value && out.len == 0;

    let m_miss = core::get_query_param_fast(qs, "nope", out);
    let miss_ok = m_miss == core::QueryParamMatch.Missing;

    var tiny: u8[..4] = [];
    let m_tiny = core::get_query_param_fast(qs, "k", tiny);
    let tiny_ok = m_tiny == core::QueryParamMatch.Missing && tiny.len == 0;

    let alpha_ok = core::is_ascii_alphanumeric('Z') && !core::is_ascii_alphanumeric('-');
    let case_ok = core::to_lower_ascii_byte('A') == 'a' && core::to_upper_ascii_byte('z') == 'Z';
    print(
        "query_match: val=", val_ok, " flag=", flag_ok, " empty=", empty_ok,
        " miss=", miss_ok, " tiny=", tiny_ok, " ascii=", alpha_ok && case_ok,
    );
}

fn test_multipart_writer_and_roundtrip() {
    let w_auto1, ok_a1 = http::new_multipart_writer();
    let w_auto2, ok_a2 = http::new_multipart_writer();
    let auto_distinct = ok_a1 && ok_a2 && w_auto1.boundary[..] != w_auto2.boundary[..];

    let _, bad_crlf = http::new_multipart_writer("bad\r\n");
    let _, bad_sp = http::new_multipart_writer("trailing ");
    let w_q, ok_q = http::new_multipart_writer("test-b=1");
    let ct_q = http::multipart_content_type(w_q);

    var w, ok_w = http::new_multipart_writer("GooseBoundary42");
    let ok_f1 = w.write_field("chat_id", "987654");
    let saved_len = w.body.len;
    let bad_inj_name = w.write_field("evil\r\nX-Injected: 1", "v");
    let bad_inj_ct = w.write_file("doc", "a.pdf", "application/pdf\r\nX-Bad: 1", "abc");
    let rollback_ok = !bad_inj_name && !bad_inj_ct && w.body.len == saved_len;

    let pdf_bytes: const u8[:] = "%PDF-1.7\x00\x01\r\n%%EOF";
    let ok_file1 = w.write_file("document", "my \"file\"\\1.pdf", "application/pdf", pdf_bytes);
    let ok_file2 = w.write_file("raw", "blob.bin", "", "RAWDATA");

    var req = http::new_post("https://api.telegram.org/bot123/sendDocument");
    let ok_attach = req.multipart(w);
    let post_finish_reject = !w.write_field("late", "no");

    let parsed, perr = http::parse_multipart(req.body[..], w.boundary[..]);
    let rt_ok = perr == http::MultipartError.None &&
        parsed.parts.len == 3 &&
        parsed.parts[0].name[..] == "chat_id" &&
        parsed.parts[0].data == "987654" &&
        parsed.parts[1].name[..] == "document" &&
        parsed.parts[1].filename[..] == "my \"file\"\\1.pdf" &&
        parsed.parts[1].content_type[..] == "application/pdf" &&
        parsed.parts[1].data == pdf_bytes &&
        parsed.parts[2].name[..] == "raw" &&
        parsed.parts[2].content_type[..] == "application/octet-stream" &&
        parsed.parts[2].data == "RAWDATA";

    var cd_small: u8[..12] = "X";
    let cd_ovf = http::format_content_disposition("field", "file.txt", cd_small);
    let cd_rb = !cd_ovf && cd_small[..] == "X";

    print(
        "multipart: auto=", auto_distinct, " bad_b=", !bad_crlf && !bad_sp,
        " ct_q=", ok_q && ct_q[..] == "multipart/form-data; boundary=\"test-b=1\"",
        " write=", ok_w && ok_f1 && ok_file1 && ok_file2 && ok_attach && post_finish_reject,
        " rb=", rollback_ok && cd_rb,
        " ct_hdr=", req.header("Content-Type") == "multipart/form-data; boundary=GooseBoundary42",
        " rt=", rt_ok,
    );
}

fn test_stack_footprint() {
    var srv = server::new_http_server("127.0.0.1", 0);
    var s1 = client::new_session();
    var s2 = client::new_session("https://example.org");
    print("stack: srv=", srv.port, " s1=", s1.enable_cookie_jar, " s2=", s2.base_url[..]);
}

fn test_refactored_subsystems() {
    // 1. Decompressor non-generic core + bounded-buffer bridges (Zstd, Brotli, Deflate)
    let msg: const u8[:] = "goose-wing prerelease decompression roundtrip payload 1234567890";
    var z_comp: u8[>..] = [];
    let zc_ok = core::zstd_compress(msg, z_comp);
    var z_vec: u8[>..]   = [];
    var z_fix: u8[..128] = [];
    var z_sm:  u8[..8]   = [];
    let zd1, _ = core::zstd_decompress(z_comp[..], z_vec);
    let zd2, _ = core::zstd_decompress(z_comp[..], z_fix);
    let zd3, zerr = core::zstd_decompress(z_comp[..], z_sm);
    let z_ok = zc_ok && zd1 && zd2 && z_vec[..] == msg && z_fix[..] == msg &&
        !zd3 && zerr == core::CompressError.OutputBufferOverflow;

    var b_comp: u8[>..] = [];
    let bc_ok = core::brotli_compress(msg, b_comp);
    var b_vec: u8[>..]   = [];
    var b_fix: u8[..128] = [];
    var b_sm:  u8[..8]   = [];
    let bd1, _ = core::brotli_decompress(b_comp[..], b_vec);
    let bd2, _ = core::brotli_decompress(b_comp[..], b_fix);
    let bd3, berr = core::brotli_decompress(b_comp[..], b_sm);
    let b_ok = bc_ok && bd1 && bd2 && b_vec[..] == msg && b_fix[..] == msg &&
        !bd3 && berr == core::CompressError.OutputBufferOverflow;

    var d_comp: u8[>..] = [];
    let dc_ok = core::deflate(msg, d_comp);
    var d_vec: u8[>..]   = [];
    var d_fix: u8[..128] = [];
    var d_sm:  u8[..8]   = [];
    let dd1, _ = core::inflate(d_comp[..], d_vec);
    let dd2, _ = core::inflate(d_comp[..], d_fix);
    let dd3, derr = core::inflate(d_comp[..], d_sm);
    let d_ok = dc_ok && dd1 && dd2 && d_vec[..] == msg && d_fix[..] == msg &&
        !dd3 && derr == core::CompressError.OutputBufferOverflow;

    // 2. Table-driven WellKnownHeader + HPACK static field + PSL suffix classifiers
    let hdr_ok = http::classify_well_known_header("Host") == http::WellKnownHeader.Host &&
        http::classify_well_known_header("TE") == http::WellKnownHeader.TE &&
        http::classify_well_known_header("Content-Type") == http::WellKnownHeader.ContentType &&
        http::classify_well_known_header("Access-Control-Allow-Credentials") == http::WellKnownHeader.AccessControlAllowCredentials &&
        http::classify_well_known_header("Strict-Transport-Security") == http::WellKnownHeader.StrictTransportSecurity &&
        http::classify_well_known_header("X-Custom-Header") == http::WellKnownHeader.Unknown;

    var enc_dt = http2::new_dynamic_table(4096);
    var dec_dt = http2::new_dynamic_table(4096);
    var hpack_wire: u8[>..] = [];
    http2::encode_hpack_field(enc_dt, hpack_wire, ":method", "GET", http2::HpackIndexing.Incremental, false);
    http2::encode_hpack_field(enc_dt, hpack_wire, ":scheme", "https", http2::HpackIndexing.Incremental, false);
    http2::encode_hpack_field(enc_dt, hpack_wire, ":path", "/", http2::HpackIndexing.Incremental, false);
    http2::encode_hpack_field(enc_dt, hpack_wire, "accept-encoding", "gzip, deflate", http2::HpackIndexing.Incremental, false);
    http2::encode_hpack_field(enc_dt, hpack_wire, "www-authenticate", "Bearer", http2::HpackIndexing.Incremental, false);
    var p_hdrs = http2::PseudoHeaders { .. };
    var out_map = http::HeaderMap { .. };
    let h_err = http2::decode_hpack_to_map(dec_dt, hpack_wire[..], p_hdrs, out_map);
    let hpack_ok = h_err == 0 &&
        p_hdrs.method[..] == "GET" &&
        p_hdrs.scheme[..] == "https" &&
        p_hdrs.path[..] == "/" &&
        out_map.get_header("accept-encoding") == "gzip, deflate" &&
        out_map.get_header("www-authenticate") == "Bearer";

    let psl_ok = core::is_known_one_level_suffix("com") &&
        core::is_known_one_level_suffix("local") &&
        !core::is_known_one_level_suffix("zz") &&
        core::is_known_two_level_suffix("co.uk") &&
        core::is_known_two_level_suffix("state.us") &&
        !core::is_known_two_level_suffix("foo.bar");

    // 3. Lazy HPACK slot pool + 64-slot StreamPool reclamation
    var pool = net::new_stream_pool(64, 64, 64);
    let nak = net::new_network_anonymization_key("https://pool-verify.org");
    let key = net::new_pool_key(
        net::PoolScheme.Https, "pool-verify.org", 443,
        net::new_direct_proxy_chain(), nak, net::TlsAndDnsPolicy { .. },
    );
    var cids: i32[64] = [0; 64];
    var all_reg = true;
    for i in 64 {
        let cid = net::register_connection(pool, key, net::NegotiatedProtocol.Http2, "10.0.0.1", 100, (i + 1) * 1000);
        if cid <= 0 { all_reg = false; }
        cids[i] = cid;
    }
    let hs0 = net::ensure_hpack_slot(pool.conns[0]);
    let ok_close = net::close_pooled_connection(pool, cids[0]);
    let c65 = net::register_connection(pool, key, net::NegotiatedProtocol.Http2, "10.0.0.1", 100, 999000);
    let pool_ok = all_reg && hs0 >= 0 && ok_close && pool.conns[0].hpack_slot == -1 && c65 == 65;

    // 4. Pipelined server turn value-return refactor
    var srv = server::new_http_server("127.0.0.1", 8080);
    server::add_static_get_route(srv, "/ping", "text/plain", "pong", 1);
    var wire_out: u8[..4096] = [];
    let raw_req = "GET /ping HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\nGET /ping HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    let handled, consumed, ok_pipe, wants_close = server::handle_connection_wire_pipelined_stream(
        srv, "127.0.0.1", raw_req, 1700000000000000000, wire_out,
    );
    let pipe_ok = ok_pipe && handled == 2 && consumed == raw_req.len && wants_close &&
        core::contains(wire_out[..], "pong");

    print(
        "refactored: zstd=", z_ok, " brotli=", b_ok, " deflate=", d_ok,
        " hdr=", hdr_ok, " hpack=", hpack_ok, " psl=", psl_ok,
        " pool=", pool_ok, " pipe=", pipe_ok,
    );
}

fn test_live_tls_interop_fixes() {
    // 1. Finding #9: CertificateEntry.extensions with stapled OCSP (no double u16 prefix)
    let cert_msg: u8[23] = [
        0x00,                   // request_context_len = 0
        0x00, 0x00, 0x13,       // certificate_list_len = 19
        0x00, 0x00, 0x04,       // cert_data len = 4
        'C', 'E', 'R', 'T',
        0x00, 0x0A,             // extensions_len = 10
        0x00, 0x05, 0x00, 0x06, // ext status_request (5), ext_len = 6
        0x01, 0x00, 0x00, 0x02, // status_type = ocsp (1), ocsp_len = 2
        0x30, 0x00,
    ];
    var certs: const u8[:][..8] = [];
    let ocsp_der, ok_chain = tls_internal::parse_certificate_chain_and_ocsp(cert_msg[..], certs);
    let f9_ok = ok_chain && certs.len == 1 && certs[0] == "CERT" &&
        ocsp_der.len == 2 && ocsp_der[0] == 0x30 && ocsp_der[1] == 0x00;

    // 2. Finding #10: EncryptedExtensions with RFC 8446 §4.2.7 supported_groups (0x000a)
    let ee_ok_wire: u8[23] = [
        0x00, 0x15,             // total ext len = 21
        0x00, 0x00, 0x00, 0x00, // server_name (0)
        0x00, 0x0A, 0x00, 0x04, // supported_groups (10), len = 4
        0x00, 0x02, 0x00, 0x1D, // NamedGroupList len = 2, x25519
        0x00, 0x10, 0x00, 0x05, // alpn (16), len = 5
        0x00, 0x03, 0x02, 'h', '2',
    ];
    let ee_bad_grp: u8[10] = [
        0x00, 0x08,
        0x00, 0x0A, 0x00, 0x04,
        0x00, 0x03, 0x00, 0x1D, // invalid odd NamedGroupList length
    ];
    var neg_alpn: u8[..32] = [];
    let ok_ee1 = tls_internal::parse_encrypted_extensions_alpn(ee_ok_wire[..], neg_alpn, "h2,http/1.1");
    let ee1_alpn_ok = ok_ee1 && neg_alpn[..] == "h2";
    let ok_ee2 = tls_internal::parse_encrypted_extensions_alpn(ee_bad_grp[..], neg_alpn, "h2,http/1.1");
    let f10_ok = ee1_alpn_ok && !ok_ee2;

    // 3. Finding #11: Legacy zero serial [0x00] accepted in X.509 TBS parser, strict validate_asn1_integer unchanged
    let ser_zero_tlv: u8[3] = [0x02, 0x01, 0x00];
    let ser_neg_tlv:  u8[3] = [0x02, 0x01, 0x80];
    let ser_pad_tlv:  u8[4] = [0x02, 0x02, 0x00, 0x01];
    var c_z = core::cursor_from(ser_zero_tlv[..]);
    var c_n = core::cursor_from(ser_neg_tlv[..]);
    var c_p = core::cursor_from(ser_pad_tlv[..]);
    var dummy_cert = tls::ParsedCert { .. };
    let zero_arr: u8[1] = [0x00];
    let f11_ok = tls_internal::read_tbs_serial(ser_zero_tlv[..], c_z, dummy_cert) &&
        !tls_internal::read_tbs_serial(ser_neg_tlv[..], c_n, dummy_cert) &&
        !tls_internal::read_tbs_serial(ser_pad_tlv[..], c_p, dummy_cert) &&
        !tls::validate_asn1_integer(zero_arr[..], true);

    // 4. Finding #12: RFC 6960 §4.1.1 issuerNameHash hashes DER SEQUENCE TLV of Name
    let dn_inner: const u8[:] = "\x31\x0B\x30\x09\x06\x03\x55\x04\x03\x0C\x02CA";
    var dn_tlv: u8[..64] = [];
    dn_tlv.push(0x30);
    dn_tlv.push(dn_inner.len as u8);
    dn_tlv.append(dn_inner);
    let h_tlv = core::sha1(dn_tlv[..]);
    let h_raw = core::sha1(dn_inner);
    let oid_sha1: const u8[5] = [0x2B, 0x0E, 0x03, 0x02, 0x1A];
    let f12_ok = tls_internal::x509_verify_ocsp_issuer_name_hash(oid_sha1[..], h_tlv[..], dn_inner) &&
        !tls_internal::x509_verify_ocsp_issuer_name_hash(oid_sha1[..], h_raw[..], dn_inner);

    // 5. Finding #13: On-demand OS root store lookup rejects empty/unknown issuer DNs cleanly
    var empty_store = tls::TrustAnchorStore { .. };
    let f13_ok = tls::load_system_roots_for_issuer(empty_store, "") == 0 &&
        tls::load_system_roots_for_issuer(empty_store, dn_inner) == 0 &&
        empty_store.anchors.len == 0;

    print(
        "tls_interop: ocsp_ext=", f9_ok, " ee_grp=", f10_ok,
        " zero_ser=", f11_ok, " ocsp_dn=", f12_ok, " sys_roots=", f13_ok,
    );
}

fn main() {
    test_csprng_windows_and_posix();
    test_query_helpers();
    test_multipart_writer_and_roundtrip();
    test_stack_footprint();
    test_refactored_subsystems();
    test_live_tls_interop_fixes();
}

// CHECK: csprng: rc=0,0 nz=true,true distinct=true
// CHECK-NEXT: query_comp: true a%26b%3Dc%2Bd%23e%25f%20g true true x%3D1%26y%3D2 ovf=false rollback=k=
// CHECK-NEXT: query_match: val=true flag=true empty=true miss=true tiny=true ascii=true
// CHECK-NEXT: multipart: auto=true bad_b=true ct_q=true write=true rb=true ct_hdr=true rt=true
// CHECK-NEXT: stack: srv=0 s1=true s2=https://example.org
// CHECK-NEXT: refactored: zstd=true brotli=true deflate=true hdr=true hpack=true psl=true pool=true pipe=true
// CHECK-NEXT: tls_interop: ocsp_ext=true ee_grp=true zero_ser=true ocsp_dn=true sys_roots=true
