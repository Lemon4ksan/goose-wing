// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Adversarial bounds & static RAM budget LIT verification across all 5 checkfree
// untrusted ingress parser families: HTTP/1.1, HTTP/2 & HPACK, QUIC & HTTP/3 & QPACK,
// TLS 1.3 & ASN.1, and DNS & HTTPS/SVCB.
// RUN: goose %s | %FileCheck %s

import std;
import wing from "../..";

fn test_h1_adversarial_bounds() {
    let empty: const u8[:] = "";
    let one:   const u8[1] = ['G'];

    // 1. Method & lexical token/value scanners on empty, 1-byte, and malformed slices
    let _, _, m_empty = http::match_http_method_u32(empty);
    let _, _, m_one = http::match_http_method_u32(one[..]);
    let _, _, m_trunc = http::match_http_method_u32("GET");
    let m_ok_s, m_ok_len, m_ok = http::match_http_method_u32("GET / HTTP/1.1\r\n");
    assert(!m_empty && !m_one && !m_trunc && m_ok && m_ok_len == 4 && m_ok_s == "GET");

    assert(!http::is_valid_token_swar(empty));
    assert(!http::is_valid_header_name(empty));
    assert(!http::is_valid_header_name("Bad\x00Name"));
    assert(!http::is_valid_header_name("X-Long-Valid-Prefix-Bad\x7F"));
    assert(!http::is_valid_header_name_h2("Content-Type"));
    assert(!http::is_valid_header_name_h2(":"));
    assert(http::is_valid_header_name_h2(":authority"));
    assert(!http::is_valid_header_value("ok\x7Fbad"));

    let _, _, v_empty = http::scan_header_field_value_swar(empty);
    let _, _, v_bare_cr = http::scan_header_field_value_swar("hello\rworld");
    let _, _, v_del = http::scan_header_field_value_swar("0123456789abcdef\x7F\r\n");
    let v_len, v_crlf, v_ok = http::scan_header_field_value_swar("example.com\r\n");
    assert(!v_empty && !v_bare_cr && !v_del && v_ok && v_len == 11 && v_crlf == 2);

    // 2. Chunked hex size, extensions, and single-register FSM adversarial inputs
    let _, ce_empty = http::parse_chunk_size_hex(empty);
    let _, ce_ovf = http::parse_chunk_size_hex("FFFFFFFFFFFFFFFFF");
    let _, ce_ext = http::parse_chunk_size_hex("4;ext=\"unterminated");
    let _, ce_bws = http::parse_chunk_size_hex("4 ");
    assert(ce_empty == http::ChunkedDecodeError.InvalidChunkSizeHex);
    assert(ce_ovf == http::ChunkedDecodeError.ChunkSizeOverflow);
    assert(ce_ext == http::ChunkedDecodeError.InvalidChunkExtension);
    assert(ce_bws == http::ChunkedDecodeError.InvalidChunkSizeHex);

    var cur: i64 = 0;
    let _, rl_empty = http::read_chunk_size_line(empty, cur);
    let _, rl_bare_lf = http::read_chunk_size_line("4\nWiki\r\n", cur);
    assert(rl_empty == http::ChunkedDecodeError.UnexpectedEof && cur == 0);
    assert(rl_bare_lf == http::ChunkedDecodeError.BareLfInChunkSize && cur == 0);

    var dec = http_internal::new_chunk_fsm_decoder();
    var off: i64 = 0;
    let st_bad_hdr = http_internal::feed_chunk_header(dec, "4\n", off);
    assert(st_bad_hdr == http_internal::ChunkFsmStatus.Error);
    http_internal::chunk_fsm_reset(dec);
    off = 0;
    let st_hdr = http_internal::feed_chunk_header(dec, "4\r\n", off);
    assert(st_hdr == http_internal::ChunkFsmStatus.NeedMore && http_internal::chunk_fsm_has_size(dec.state));
    var body_off: i64 = 0;
    let st_bad_body, _ = http_internal::feed_chunk_body(dec, "Wiki\n\n", body_off);
    assert(st_bad_body == http_internal::ChunkFsmStatus.Error);

    // 3. RAM cap: consume_chunk_data must reject chunk_size > MAX_CHUNKED_BODY_BYTES fail-closed
    var out_body: u8[>..] = [];
    var ccur:     i64     = 0;
    let huge_sz = (http::MAX_CHUNKED_BODY_BYTES as u64) + 1;
    let c_err = http_internal::consume_chunk_data("abcd\r\n", ccur, huge_sz, out_body);
    assert(c_err == http::ChunkedDecodeError.UnexpectedEof && out_body.len == 0 && ccur == 0);

    // 4. RAM cap: parse_url_with_overflow rejects URL > MAX_OVERFLOW_URL_BYTES (65535 B)
    var arena = http::OverflowArena { .. };
    var huge_url: u8[>..] = [];
    huge_url.append("https://example.com/");
    for _ in 65540 {
        huge_url.push('a');
    }
    let uv, u_err = http::parse_url_with_overflow(huge_url[..], arena);
    assert(!uv.valid && u_err == core::UrlParseError.InputTooLong && arena.spill_url.len == 0);

    // 5. RAM cap: parse_headers_with_overflow rejects > 128 + 512 (640) headers fail-closed
    var hmap = http::HeaderMap { .. };
    var many_hdrs: u8[>..] = [];
    for i in 650 {
        many_hdrs.append("X-");
        many_hdrs.push('0' + (((i / 100) % 10) as u8));
        many_hdrs.push('0' + (((i / 10) % 10) as u8));
        many_hdrs.push('0' + ((i % 10) as u8));
        many_hdrs.append(":1\r\n");
    }
    many_hdrs.append("\r\n");
    let ov_err = http::parse_headers_with_overflow(many_hdrs[..], hmap, arena);
    assert(ov_err == http::HeaderParseError.CapacityExceeded && arena.spill_entries.len == 0);

    // 6. HeaderSpan OOB guard, Bloom filter, server H1 status line, and response body cap
    let bad_span = http::HeaderSpan { name_pos: 100, name_len: 50, val_pos: 200, val_len: 50, id: 0 };
    assert(http::name_slice(bad_span, "Host: a") == "");
    assert(http::val_slice(bad_span, "Host: a") == "");
    var bf = http::HeaderBloomFilter { .. };
    assert(http::is_empty(bf));
    http::add_header(bf, "Host");
    assert(http::might_have_header(bf, "HOST"));

    var res = http::Response { .. };
    assert(!server_internal::parse_http1_wire_status_line(empty, res));
    assert(!server_internal::parse_http1_wire_status_line("HTTP/1.1 999 BAD", res));
    assert(server_internal::parse_http1_wire_status_line("HTTP/1.1 200 OK", res) && res.status_code == 200);
    assert(!server::is_h2_client_preface(one[..]));
    assert(server::is_partial_h2_client_preface("PRI "));
    assert(!server_internal::validate_host_header_chars("bad/host"));
    assert(!server_internal::validate_request_target_chars("/bad#frag"));
    assert(server_internal::swar_find_space(empty, 0) == -1);

    let huge_cl_resp = "HTTP/1.1 200 OK\r\nContent-Length: 20000000\r\n\r\nshort";
    let ok_huge_resp, _ = server::parse_http1_wire_response(huge_cl_resp, res);
    assert(!ok_huge_resp && res.body.len == 0);

    print("H1_CHECKFREE_ADVERSARIAL: OK");
}

fn test_h2_hpack_adversarial_bounds() {
    let empty:  const u8[:] = "";
    let one:    const u8[1] = [0x00];
    let trunc8: const u8[8] = [0, 0, 4, 0, 0, 0, 0, 0];

    // 1. Frame header, padding, priority, settings, and ALTSVC bounds
    let _, e0 = http2::parse_frame_header(empty);
    let _, e1 = http2::parse_frame_header(one[..]);
    let _, e8 = http2::parse_frame_header(trunc8[..]);
    assert(e0 == rfc::H2_ERR_FRAME_SIZE_ERROR && e1 == rfc::H2_ERR_FRAME_SIZE_ERROR);
    assert(e8 == rfc::H2_ERR_FRAME_SIZE_ERROR);

    let oversize_hdr: const u8[9] = [0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
    let _, e_ov = http2::parse_frame_header(oversize_hdr[..], 16384);
    assert(e_ov == rfc::H2_ERR_FRAME_SIZE_ERROR);

    let pad_hdr = http2::FrameHeader { length: 2, frame_type: 0, flags: rfc::H2_FLAG_PADDED, stream_id: 1 };
    let bad_pad: const u8[2] = [0x05, 0xAA];
    let _, e_pad = http2::extract_padded_frame_payload(pad_hdr, bad_pad[..]);
    assert(e_pad == rfc::H2_ERR_PROTOCOL_ERROR);

    let prio_hdr = http2::FrameHeader { length: 5, frame_type: 1, flags: rfc::H2_FLAG_PRIORITY, stream_id: 1 };
    let self_dep: const u8[5] = [0x00, 0x00, 0x00, 0x01, 0x0F];
    let _, e_self = http2::extract_headers_frame_payload(prio_hdr, self_dep[..], false);
    assert(e_self == rfc::H2_ERR_PROTOCOL_ERROR);

    assert(http2::validate_settings_parameter(rfc::H2_SETTING_ENABLE_PUSH, 2) == rfc::H2_ERR_PROTOCOL_ERROR);
    assert(http2::validate_settings_parameter(rfc::H2_SETTING_MAX_FRAME_SIZE, 100) == rfc::H2_ERR_PROTOCOL_ERROR);
    assert(http2::validate_settings_parameter(rfc::H2_SETTING_INITIAL_WINDOW_SIZE, 0x80000000) ==
           rfc::H2_ERR_FLOW_CONTROL_ERROR);

    let bad_altsvc: const u8[4] = [0x00, 0x20, 'h', '2'];
    let _, e_as = http2::parse_altsvc_frame(bad_altsvc[..], 0);
    assert(e_as == rfc::H2_ERR_FRAME_SIZE_ERROR);

    // 2. HPACK integer overflow, Huffman invalid padding, DynamicTable bounds, and 64 KiB Huffman cap
    let _, _, hi_empty = http2::hpack_decode_int(empty, 0, 5);
    let trunc_int: const u8[1] = [0xFF];
    let _, _, hi_trunc = http2::hpack_decode_int(trunc_int[..], 0, 5);
    let ovf_int: const u8[6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    let _, _, hi_ovf = http2::hpack_decode_int(ovf_int[..], 0, 5);
    assert(!hi_empty && !hi_trunc && !hi_ovf);

    var huff_out: u8[>..] = [];
    let bad_pad_huff: const u8[1] = [0x00];
    assert(!http2::huff_decode_bytes(bad_pad_huff[..], huff_out));

    // RAM cap: > 32768-byte Huffman input would expand beyond 64 KiB cap; must fail closed
    var huge_huff: u8[>..] = [];
    for _ in 33000 {
        huge_huff.push(0x00);
    }
    huff_out.clear();
    assert(!http2::huff_decode_bytes(huge_huff[..], huff_out) && huff_out.len == 0);

    var dt = http2::new_dynamic_table(4096);
    let _, _, idx0_ok = http2::get_indexed_header_slices(dt, 0);
    let _, _, idx_oob = http2::get_indexed_header_slices(dt, 99999);
    assert(!idx0_ok && !idx_oob);
    http2::insert_header(dt, "x-test", "1");
    let hn, hv, idx_dyn = http2::get_indexed_header_slices(dt, 62);
    assert(idx_dyn && hn == "x-test" && hv == "1");
    assert(!http2::is_valid_authority(empty) && !http2::is_valid_path("no-slash"));

    print("H2_HPACK_CHECKFREE_ADVERSARIAL: OK");
}

fn test_quic_h3_qpack_adversarial_bounds() {
    let empty: const u8[:] = "";
    let one:   const u8[1] = [0xC0];

    // 1. QUIC varint boundary & max 62-bit value
    let _, _, v0 = quic::decode_varint(empty, 0);
    let t2:   const u8[1] = [0x40];
    let t4:   const u8[3] = [0x80, 0x01, 0x02];
    let t8:   const u8[7] = [0xC0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    let maxv: const u8[8] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    let _, _, v2 = quic::decode_varint(t2[..], 0);
    let _, _, v4 = quic::decode_varint(t4[..], 0);
    let _, _, v8 = quic::decode_varint(t8[..], 0);
    let vmax, voff, vok = quic::decode_varint(maxv[..], 0);
    assert(!v0 && !v2 && !v4 && !v8 && vok && voff == 8 && vmax == 4611686018427387903);

    // 2. QUIC packet headers & frame decoders on hostile/truncated inputs
    let _, h0 = quic::parse_header(empty);
    let _, h1 = quic::parse_header(one[..]);
    let bad_cid: const u8[8] = [0xC0, 0x00, 0x00, 0x00, 0x01, 21, 0x00, 0x00];
    let _, h_cid = quic::parse_header(bad_cid[..]);
    let short_trunc: const u8[4] = [0x40, 0x01, 0x02, 0x03];
    let _, h_sh = quic::parse_header(short_trunc[..], 20);
    assert(!h0 && !h1 && !h_cid && !h_sh);

    let _, _, f_empty = quic::decode_frame(empty, 0);
    // STREAM frame with LEN bit set (0x0A), stream_id=0, length=50, only 2 bytes remaining
    let bad_stream: const u8[5] = [0x0A, 0x00, 0x32, 0xAA, 0xBB];
    let _, _, f_st = quic::decode_frame(bad_stream[..], 0);
    // CRYPTO frame (0x06), offset=0, length=40, only 1 byte remaining
    let bad_crypto: const u8[4] = [0x06, 0x00, 0x28, 0xAA];
    let _, _, f_cr = quic::decode_frame(bad_crypto[..], 0);
    // ACK frame (0x02), largest=1, delay=0, count=0, first_ack_range=5 (> largest -> underflow)
    let bad_ack: const u8[5] = [0x02, 0x01, 0x00, 0x00, 0x05];
    let _, _, f_ack = quic::decode_frame(bad_ack[..], 0);
    // ACK_FREQUENCY (0xAF -> varint [0x40, 0xAF]), seq=0, threshold=0 (forbidden)
    let bad_af: const u8[6] = [0x40, 0xAF, 0x00, 0x00, 0x01, 0x00];
    let _, _, f_af = quic::decode_frame(bad_af[..], 0);
    assert(!f_empty && !f_st && !f_cr && !f_ack && !f_af);

    let _, pn_bad = quic::decode_packet_number_checked(10, 1, 0);
    let _, pn_bad5 = quic::decode_packet_number_checked(10, 1, 5);
    assert(!pn_bad && !pn_bad5);

    // 3. HTTP/3 framing & QPACK integer/RIC/Base/field-cap bounds
    let _, fh_empty = http3::parse_frame_header(empty, 0);
    let fh_trunc: const u8[1] = [0x00];
    let _, fh_t = http3::parse_frame_header(fh_trunc[..], 0);
    let _, go_empty = http3::parse_goaway_frame(empty);
    let go_extra: const u8[2] = [0x04, 0x00];
    let _, go_trail = http3::parse_goaway_frame(go_extra[..]);
    let _, cp_empty = http3::parse_cancel_push(empty);
    let _, mp_empty = http3::parse_max_push_id(empty);
    assert(!fh_empty && !fh_t && !go_empty && !go_trail && !cp_empty && !mp_empty);

    let q_ovf: const u8[10] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    let _, _, qi_ovf = http3::qpack_decode_int(q_ovf[..], 0, 7);
    let _, ric_err = http3::decode_ric(1, 0, 0);
    let _, base_err = http3::decode_base(1, 0, 0);
    let _, stat_oob = http3::get_qpack_static_field(99);
    assert(!qi_ovf && ric_err != http3::QpackError.None && base_err != http3::QpackError.None && !stat_oob);
    assert(!http3::validate_qpack_field_val("bad\r\nval"));

    // RAM cap: QPACK dynamic HeaderField[>..] push caps at 128 fields
    var qfields: http3::HeaderField[>..] = [];
    let dummy_f = http3::HeaderField { .. };
    var pushed: i64 = 0;
    for _ in 140 {
        if http3::try_push_header_field(qfields, dummy_f) {
            pushed++;
        }
    }
    assert(pushed == 128 && qfields.len == 128);

    print("QUIC_H3_QPACK_CHECKFREE_ADVERSARIAL: OK");
}

fn test_tls_asn1_adversarial_bounds() {
    let empty:  const u8[:] = "";
    let one:    const u8[1] = [0x17];
    let trunc4: const u8[4] = [0x17, 0x03, 0x03, 0x00];

    // 1. TLS 1.3 record header, inner plaintext, alert, nonce, CCS, and QUIC CRYPTO stream bounds
    let _, _, _, _, r0 = tls::parse_record_header(empty);
    let _, _, _, _, r1 = tls::parse_record_header(one[..]);
    let _, _, _, _, r4 = tls::parse_record_header(trunc4[..]);
    let rec_ovf: const u8[5] = [0x17, 0x03, 0x03, 0x41, 0x01]; // 16641 > 16640
    let _, _, _, a_ovf, r_ovf = tls::parse_record_header(rec_ovf[..]);
    assert(!r0 && !r1 && !r4 && !r_ovf && a_ovf == tls::Alert.RecordOverflow);

    let _, _, ip_empty = tls::unpack_inner_plaintext(empty);
    let zeros: const u8[4] = [0, 0, 0, 0];
    let _, _, ip_zero = tls::unpack_inner_plaintext(zeros[..]);
    assert(ip_empty == tls::Alert.UnexpectedMessage && ip_zero == tls::Alert.UnexpectedMessage);

    let _, _, _, al_empty = tls::parse_alert_message(empty);
    let bad_al: const u8[2] = [0x03, 0x0A];
    let _, _, _, al_bad = tls::parse_alert_message(bad_al[..]);
    assert(!al_empty && !al_bad);

    let iv: const u8[12] = [0; 12];
    let _, nonce_max = tls::compute_record_nonce(iv, 0xFFFFFFFFFFFFFFFF);
    assert(!nonce_max);

    let bad_ccs: const u8[1] = [0x00];
    assert(tls::validate_change_cipher_spec_record(empty) == tls::Alert.DecodeError);
    assert(tls::validate_change_cipher_spec_record(bad_ccs[..]) == tls::Alert.UnexpectedMessage);

    let _, hp_bad = tls::quic_extract_hp_sample(trunc4[..], 0);
    let _, hp_short = tls::quic_extract_hp_sample(trunc4[..], 2);
    assert(!hp_bad && !hp_short);

    var qcs = tls::QuicCryptoStream { .. };
    let _, qcs_gap = tls::quic_crypto_stream_ingest(qcs, 10, "abc");
    assert(!qcs_gap && qcs.buf.len == 0);

    // 2. ASN.1 DER length-of-length overflow, non-canonical forms, INTEGER, and BIT STRING
    let b_indef: const u8[2] = [0x30, 0x80];
    var c_indef = core::ByteCursor { buf: b_indef[..] };
    var tag: u8 = 0;
    var val = core::ByteCursor { buf: empty };
    assert(!tls::get_any_asn1_element(c_indef, tag, val));

    let b_lol5: const u8[7] = [0x30, 0x85, 0x01, 0x02, 0x03, 0x04, 0x05];
    var c_lol5 = core::ByteCursor { buf: b_lol5[..] };
    assert(!tls::get_any_asn1_element(c_lol5, tag, val));

    let b_noncanon: const u8[4] = [0x30, 0x82, 0x00, 0x80];
    var c_noncanon = core::ByteCursor { buf: b_noncanon[..] };
    assert(!tls::get_any_asn1_element(c_noncanon, tag, val));

    let b_trunc: const u8[4] = [0x30, 0x10, 0x01, 0x02];
    var c_trunc = core::ByteCursor { buf: b_trunc[..] };
    assert(!tls::get_any_asn1_element(c_trunc, tag, val));

    let bad_int:       const u8[2] = [0x00, 0x01];
    let bad_bs_unused: const u8[2] = [0x08, 0x00];
    let bad_bs_trail:  const u8[2] = [0x01, 0x01];
    assert(!tls::validate_asn1_integer(empty, false) && !tls::validate_asn1_integer(bad_int[..], false));
    assert(!tls::validate_asn1_bit_string(empty) && !tls::validate_asn1_bit_string(bad_bs_unused[..]));
    assert(!tls::validate_asn1_bit_string(bad_bs_trail[..]));

    print("TLS_ASN1_CHECKFREE_ADVERSARIAL: OK");
}

fn test_dns_adversarial_bounds() {
    let empty:   const u8[:]  = "";
    let one:     const u8[1]  = [0x00];
    let trunc11: const u8[11] = [0; 11];

    // 1. DNS wire packet header/question/answer bounds
    let _, r0 = dns::parse_response(empty);
    let _, r1 = dns::parse_response(one[..]);
    let _, r11 = dns::parse_response(trunc11[..]);
    assert(!r0 && !r1 && !r11);

    // 2. DNS name decoding: compression pointer self-loop, mutual loop, OOB pointer, bad label
    var name_out: u8[..256] = [];
    var idx:      i64       = 0;
    let self_loop: const u8[2] = [0xC0, 0x00];
    assert(!dns::decode_name(self_loop[..], idx, name_out) && idx == 0);

    let mutual_loop: const u8[4] = [0xC0, 0x02, 0xC0, 0x00];
    idx = 0;
    assert(!dns::decode_name(mutual_loop[..], idx, name_out) && idx == 0);

    let oob_ptr: const u8[2] = [0xC0, 0xFF];
    idx = 0;
    assert(!dns::decode_name(oob_ptr[..], idx, name_out) && idx == 0);

    let trunc_lbl: const u8[3] = [0x05, 'a', 'b'];
    idx = 0;
    assert(!dns::decode_name(trunc_lbl[..], idx, name_out) && idx == 0);

    let bad_bits: const u8[2] = [0x40, 0x00];
    idx = 0;
    assert(!dns::decode_name(bad_bits[..], idx, name_out) && idx == 0);

    // 3. DNS SVCB / HTTPS SvcParams bounds & ordering
    var hrec = dns::HttpsRecord { .. };
    let trunc_param:      const u8[3]  = [0x00, 0x01, 0x00];
    let oob_param:        const u8[5]  = [0x00, 0x01, 0x00, 0x10, 0x02];
    let bad_order:        const u8[10] = [0x00, 0x03, 0x00, 0x02, 0x01, 0xBB, 0x00, 0x01, 0x00, 0x00];
    let bad_mandatory_k2: const u8[6]  = [0x00, 0x00, 0x00, 0x02, 0x00, 0x02];
    assert(!dns::parse_https_svc_params(hrec, trunc_param[..]));
    assert(!dns::parse_https_svc_params(hrec, oob_param[..]));
    assert(!dns::parse_https_svc_params(hrec, bad_order[..]));
    assert(!dns::parse_https_svc_params(hrec, bad_mandatory_k2[..]));

    print("DNS_CHECKFREE_ADVERSARIAL: OK");
}

fn test_static_ram_budgets() {
    assert(wire::verify_ingress_budget_bounds());

    let h1 = wire::h1_connection_ram_budget();
    let h2 = wire::h2_connection_ram_budget();
    let h3 = wire::h3_connection_ram_budget();
    let tls_b = wire::tls_connection_ram_budget();
    let dns_b = wire::dns_packet_ram_budget();

    assert(h1.per_connection_bytes == 178686 && h1.per_request_bytes == 23040);
    assert(h1.max_payload_bytes == 10485760 && h1.max_header_block_bytes == 65535);
    assert(h2.per_connection_bytes == 1383808 && h2.per_request_bytes == 12928);
    assert(h2.max_frame_or_record_len == 16384 && h2.max_header_block_bytes == 65536);
    assert(h3.per_connection_bytes == 3535232 && h3.per_request_bytes == 29376);
    assert(h3.max_header_block_bytes == 559104 && h3.max_concurrent_streams == 100);
    assert(tls_b.per_connection_bytes == 65792 && tls_b.max_frame_or_record_len == 16640);
    assert(dns_b.per_connection_bytes == 9056 && dns_b.max_frame_or_record_len == 4096);

    print("RAM_BUDGET_H1=", h1.per_connection_bytes, " H2=", h2.per_connection_bytes,
          " H3=", h3.per_connection_bytes, " TLS=", tls_b.per_connection_bytes,
          " DNS=", dns_b.per_connection_bytes);
}

// CHECK: H1_CHECKFREE_ADVERSARIAL: OK
// CHECK-NEXT: H2_HPACK_CHECKFREE_ADVERSARIAL: OK
// CHECK-NEXT: QUIC_H3_QPACK_CHECKFREE_ADVERSARIAL: OK
// CHECK-NEXT: TLS_ASN1_CHECKFREE_ADVERSARIAL: OK
// CHECK-NEXT: DNS_CHECKFREE_ADVERSARIAL: OK
// CHECK-NEXT: RAM_BUDGET_H1=178686 H2=1383808 H3=3535232 TLS=65792 DNS=9056
fn main() {
    test_h1_adversarial_bounds();
    test_h2_hpack_adversarial_bounds();
    test_quic_h3_qpack_adversarial_bounds();
    test_tls_asn1_adversarial_bounds();
    test_dns_adversarial_bounds();
    test_static_ram_budgets();
}
