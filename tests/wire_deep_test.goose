// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

fn test_wire_hpack_and_h2(t: lit::T&) {
    t.run("HPACK integer, string, WireHpackState, and HTTP/2 pseudo rules") { sub =>
        var buf: u8[..512] = [];
        sub.assert_true(wire::hpack_encode_int(buf, 1337, 5, 0x20), "encode int 1337 prefix 5");
        sub.assert_false(wire::hpack_encode_int(buf, 10, 0, 0), "prefix bits 0 rejected");
        var off: u64 = 0;
        let dec_v, ok_v = wire::hpack_decode_int(buf[..], off, 5);
        sub.assert_true(ok_v && dec_v == 1337 && off == (buf.len as u64), "decode int 1337");

        // Integer overflow must fail cleanly without advancing offset
        let ovf_bytes: u8[11] = [0x1F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];
        var ovf_off: u64 = 0;
        let _, bad_ovf = wire::hpack_decode_int(ovf_bytes[..], ovf_off, 5);
        sub.assert_false(bad_ovf, "HPACK int overflow rejected");
        sub.assert_true(ovf_off == 0, "HPACK int overflow transactional cursor");

        buf.clear();
        sub.assert_true(wire::hpack_encode_indexed(buf, 2), "encode indexed :method GET");
        sub.assert_false(wire::hpack_encode_indexed(buf, 0), "indexed 0 rejected");
        sub.assert_true(wire::hpack_encode_literal_without_indexing(buf, "x-req", "val"), "literal without indexing");
        sub.assert_true(wire::hpack_encode_literal_never_indexed(buf, "authorization", "sec"), "literal never indexed");

        var s_enc: u8[..128] = [];
        sub.assert_true(wire::hpack_encode_string(s_enc, "hello-wire"), "encode string");
        var s_off: u64       = 0;
        var s_out: u8[..128] = [];
        sub.assert_true(wire::hpack_decode_string(s_enc[..], s_off, s_out) && s_out[..] == "hello-wire", "decode raw string");
        let huff_bytes: u8[5] = [0x83, 0x86, 0x41, 0x8A, 0x08];
        var h_off: u64 = 0;
        s_out.clear();
        sub.assert_false(wire::hpack_decode_string(huff_bytes[..], h_off, s_out) && h_off == 0, "invalid Huffman string fails cleanly");

        // Stateful WireHpackState roundtrip + cookies coalescing + CONTINUATION splitting
        let st_enc_init, ok_s1 = wire::init_hpack_state(4096, 8192);
        let st_dec_init, ok_s2 = wire::init_hpack_state(4096, 8192);
        sub.assert_true(ok_s1 && ok_s2, "init_hpack_state ok");
        let _, bad_st = wire::init_hpack_state(999999, 8192);
        sub.assert_false(bad_st, "oversize hpack table rejected");

        var st_enc = st_enc_init;
        var st_dec = st_dec_init;
        sub.assert_true(wire::hpack_reset_table_size(st_enc, 1024), "reset table size");
        sub.assert_false(wire::hpack_reset_table_size(st_enc, 65536), "oversize reset rejected");

        let req_p, ok_rp = wire::make_h2_request_pseudo("POST", "https", "api.example.com", "/submit");
        sub.assert_true(ok_rp, "make_h2_request_pseudo");
        let _, bad_rp = wire::make_h2_request_pseudo("BAD METHOD", "https", "api.example.com", "/");
        sub.assert_false(bad_rp, "bad method rejected");
        let resp_p, ok_sp = wire::make_h2_response_pseudo(200);
        sub.assert_true(ok_sp && resp_p.status == 200, "make_h2_response_pseudo");

        var hdrs = http::HeaderMap { .. };
        let _ = http::append_header(hdrs, "cookie", "a=1");
        let _ = http::append_header(hdrs, "cookie", "b=2");
        let _ = http::append_header(hdrs, "TE", "trailers");
        let _ = http::append_header(hdrs, "Connection", "keep-alive");
        let _ = http::append_header(hdrs, "x-custom", "value-1234567890");

        var blk: u8[..4096] = [];
        sub.assert_true(wire::hpack_encode_header_block(st_enc, req_p, hdrs, blk, true), "encode request hpack");
        var dec_p = wire::WireH2PseudoHeaders {};
        var dec_hdrs = http::HeaderMap { .. };
        let derr = wire::hpack_decode_block(st_dec, blk[..], dec_p, dec_hdrs, true);
        sub.assert_true(derr == rfc::H2_ERR_NO_ERROR, "decode request hpack");
        sub.assert_bytes_eq(dec_p.method[..], "POST", "decoded method");
        sub.assert_bytes_eq(http::get_header(dec_hdrs, "cookie"), "a=1; b=2", "coalesced cookies");

        // Framed HEADERS + CONTINUATION when max_frame_size is tiny
        var framed: u8[..4096] = [];
        sub.assert_true(wire::encode_h2_headers_frame_from_map(st_enc, 1, req_p, hdrs, true, framed, 8), "HEADERS + CONTINUATION");
        var reader = wire::new_wire_h2_frame_reader(framed[..]);
        var nframes: i64 = 0;
        while wire::has_next(reader) {
            let fhdr, fpay, fok = wire::next_frame(reader);
            sub.assert_true(fok && fhdr.stream_id == 1 && fpay.len <= 8, "valid frame slice");
            nframes += 1;
        }
        sub.assert_true(nframes >= 2, "split into multiple frames");

        // Truncated frame rollback check on single frame slice
        var trunc_cur: i64 = 0;
        let _, _, bad_trunc = wire::read_wire_h2_frame(framed[..8], trunc_cur);
        sub.assert_true(trunc_cur == 0 && !bad_trunc, "truncated read check");

        // 1xx with END_STREAM rejected; trailer rules check
        let p103, ok_103 = wire::make_h2_response_pseudo(103);
        sub.assert_true(ok_103, "103 pseudo");
        var bad_out: u8[..256] = [];
        sub.assert_false(wire::encode_h2_headers_frame_from_map(st_enc, 3, p103, hdrs, true, bad_out, 16384), "1xx END_STREAM rejected");

        // Trailer with forbidden header rejected
        var tr_hdrs = http::HeaderMap { .. };
        let _ = http::append_header(tr_hdrs, "content-length", "5");
        var tr_p = http2::PseudoHeaders { is_trailer: true, .. };
        var dt_raw = http2::new_dynamic_table(4096);
        sub.assert_false(wire::encode_hpack_from_map(dt_raw, tr_p, tr_hdrs, bad_out, true), "forbidden trailer header rejected");
        var ok_tr = http::HeaderMap { .. };
        let _ = http::append_header(ok_tr, "x-checksum", "ok");
        bad_out.clear();
        sub.assert_true(wire::encode_hpack_from_map(dt_raw, tr_p, ok_tr, bad_out, false), "valid trailer encoded");
    };

    t.run("HTTP/2 control frames and Extended CONNECT / classic CONNECT") { sub =>
        var out: u8[..1024] = [];
        let settings: wire::WireSetting[2] = [
            wire::h2_setting(rfc::H2_SETTING_ENABLE_PUSH, 0),
            wire::h2_setting(rfc::H2_SETTING_MAX_FRAME_SIZE, 16384),
        ];
        sub.assert_true(wire::encode_settings_frame(settings[..], out), "encode SETTINGS");
        let hdr, dh_err = wire::decode_h2_frame_header(out[..]);
        sub.assert_true(dh_err == rfc::H2_ERR_NO_ERROR && hdr.frame_type == rfc::H2_FRAME_SETTINGS && hdr.length == 12, "decode SETTINGS header");

        let bad_settings: wire::WireSetting[1] = [wire::h2_setting(rfc::H2_SETTING_MAX_FRAME_SIZE, 100)];
        sub.assert_false(wire::encode_settings_frame(bad_settings[..], out), "invalid max frame size setting rejected");

        out.clear();
        sub.assert_true(wire::encode_window_update_frame(1, 65535, out), "encode WINDOW_UPDATE");
        sub.assert_false(wire::encode_window_update_frame(1, 0, out), "zero increment rejected");
        sub.assert_true(wire::encode_priority_update_frame(1, 3, true, out), "encode PRIORITY_UPDATE");
        sub.assert_false(wire::encode_priority_update_frame(0, 3, false, out), "stream 0 PRIORITY_UPDATE rejected");
        sub.assert_false(wire::encode_priority_update_frame(1, 9, false, out), "urgency 9 rejected");
        sub.assert_true(wire::encode_rst_stream_frame(1, rfc::H2_ERR_CANCEL, out), "encode RST_STREAM");
        let ping_data: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
        sub.assert_true(wire::encode_ping_frame(ping_data, true, out), "encode PING ACK");
        sub.assert_true(wire::encode_data_frame(1, "payload", true, out), "encode DATA END_STREAM");
        sub.assert_false(wire::encode_data_frame(0, "payload", true, out), "stream 0 DATA rejected");

        // Classic CONNECT and Extended CONNECT (RFC 8441) through encode_hpack_from_map
        var dt = http2::new_dynamic_table(4096);
        let empty_hdrs = http::HeaderMap { .. };
        var conn_p = http2::PseudoHeaders { method: "CONNECT", authority: "tunnel.example:443", has_method: true, has_authority: true, .. };
        var ext_p = http2::PseudoHeaders {
            method:     "CONNECT", scheme: "https", authority: "ws.example", path: "/chat", protocol: "websocket",
            has_method: true, has_scheme: true, has_authority: true, has_path: true, has_protocol: true, ..
        };
        var hbuf: u8[..512] = [];
        sub.assert_true(wire::encode_hpack_from_map(dt, conn_p, empty_hdrs, hbuf, true), "classic CONNECT valid");
        hbuf.clear();
        sub.assert_true(wire::encode_hpack_from_map(dt, ext_p, empty_hdrs, hbuf, true), "extended CONNECT valid");
    };
}

fn test_wire_pipeline_and_h3(t: lit::T&) {
    t.run("WirePipeline stages, bindings, masks, and ingress budgets") { sub =>
        sub.assert_true(wire::verify_ingress_budget_bounds(), "verify_ingress_budget_bounds");

        var pipe = wire::default_client_pipeline();
        let srv = wire::default_server_pipeline();
        sub.assert_true(srv.role == wire::PipelineRole.Server && srv.ingress_stages.len > 0, "default_server_pipeline");

        sub.assert_true(wire::add_ingress_stage(pipe, wire::STAGE_ID_USER_0), "add ingress user 0");
        sub.assert_true(wire::add_egress_stage(pipe, wire::STAGE_ID_USER_1), "add egress user 1");
        sub.assert_true(wire::is_ingress_stage_enabled(pipe, wire::STAGE_ID_USER_0), "user 0 ingress enabled");
        sub.assert_true(wire::is_egress_stage_enabled(pipe, wire::STAGE_ID_USER_1), "user 1 egress enabled");

        wire::disable_ingress_stage(pipe, wire::STAGE_USER_0);
        sub.assert_false(wire::is_ingress_stage_enabled(pipe, wire::STAGE_ID_USER_0), "disabled by mask bit");
        wire::enable_ingress_stage(pipe, wire::STAGE_ID_USER_0);
        sub.assert_true(wire::is_ingress_stage_enabled(pipe, wire::STAGE_ID_USER_0), "enabled by stage_id");
        wire::disable_ingress_stage(pipe, wire::STAGE_ID_USER_0);
        wire::enable_ingress_stage(pipe, wire::STAGE_USER_0);
        wire::disable_egress_stage(pipe, wire::STAGE_ID_USER_1);
        wire::enable_egress_stage(pipe, wire::STAGE_ID_USER_1);
        wire::disable_egress_stage(pipe, wire::STAGE_USER_1);
        wire::enable_egress_stage(pipe, wire::STAGE_USER_1);

        sub.assert_true(wire::add_stage_binding(pipe, wire::STAGE_ID_USER_2, 1), "add_stage_binding");
        sub.assert_false(wire::add_stage_binding(pipe, wire::STAGE_ID_USER_2, 4), "invalid param_slot rejected");
        sub.assert_true(pipe.has_custom_order, "has_custom_order set");

        let bad_bindings: wire::StageBinding[1] = [wire::StageBinding { stage_id: 99, param_slot: 0 }];
        sub.assert_false(wire::replace_ingress_bindings(pipe, bad_bindings[..]), "invalid stage_id rolled back");
        sub.assert_true(pipe.has_custom_order, "rollback preserved custom_order");

        let good_bindings: wire::StageBinding[2] = [
            wire::StageBinding { stage_id: wire::STAGE_ID_USER_0, param_slot: 0 },
            wire::StageBinding { stage_id: wire::STAGE_ID_USER_3, param_slot: 2 },
        ];
        sub.assert_true(wire::replace_ingress_bindings(pipe, good_bindings[..]), "replace_ingress_bindings ok");
        wire::clear_stage_bindings(pipe);
        sub.assert_false(pipe.has_custom_order, "clear_stage_bindings");

        var pstate = wire::begin_pipeline();
        sub.assert_true(wire::step(pstate, wire::StageVerdict.Continue), "step continue");
        sub.assert_false(wire::step(pstate, wire::StageVerdict.ShortCircuit { status_code: 403 }), "short circuit");
        sub.assert_false(wire::step(pstate, wire::StageVerdict.Continue), "remains short-circuited");
    };

    t.run("HTTP/3 QPACK framing encode/decode, Extended CONNECT, cookies, and guards") { sub =>
        var qt_enc = http3::new_qpack_table(4096);
        var qt_dec = http3::new_qpack_table(4096);
        var enc_stream: u8[..1024] = [];
        var frame:      u8[..4096] = [];

        let pseudo = http3::PseudoHeaders {
            method:     "GET", scheme: "https", authority: "h3.example.com", path: "/index.html",
            has_method: true, has_scheme: true, has_authority: true, has_path: true, ..
        };
        var hdrs = http::HeaderMap { .. };
        let _ = http::append_header(hdrs, "cookie", "c1=v1");
        let _ = http::append_header(hdrs, "cookie", "c2=v2");
        let _ = http::append_header(hdrs, "te", "trailers");
        let _ = http::append_header(hdrs, "x-trace", "abc");

        sub.assert_true(wire::encode_h3_headers_from_map(qt_enc, 0, pseudo, hdrs, enc_stream, frame), "encode H3 headers");
        // Skip HTTP/3 frame varint type+len using http3::parse_frame_header if needed; unwrap frame payload
        let fh, pok = http3::parse_frame_header(frame[..], 0);
        sub.assert_true(pok && fh.frame_type == rfc::H3_FRAME_HEADERS, "parsed H3 HEADERS frame");
        let off_i = fh.header_len as i64;
        let pay = frame[off_i..off_i + (fh.payload_len as i64)];

        var enc_off: u64 = 0;
        while enc_off < (enc_stream.len as u64) {
            let next_eo, eerr = http3::qpack_process_encoder_instruction(qt_dec, enc_stream[..], enc_off);
            sub.assert_true(eerr == http3::QpackError.None && next_eo > enc_off, "qpack_process_encoder_instruction");
            enc_off = next_eo;
        }
        var out_p = http3::PseudoHeaders {};
        var out_h = http::HeaderMap { .. };
        let qerr = wire::decode_h3_headers_to_map(qt_dec, 0, pay, out_p, out_h);
        sub.assert_true(qerr == http3::QpackError.None, "decode_h3_headers_to_map ok");
        sub.assert_bytes_eq(out_p.method[..], "GET", "decoded H3 method");
        sub.assert_bytes_eq(http::get_header(out_h, "cookie"), "c1=v1; c2=v2", "H3 cookie coalesced");

        // Invalid stream ID (server-initiated/unidirectional) rejected
        var bad_frame: u8[..512] = [];
        sub.assert_false(wire::encode_h3_headers_from_map(qt_enc, 1, pseudo, hdrs, enc_stream, bad_frame), "stream_id 1 rejected");
        sub.assert_true(wire::decode_h3_headers_to_map(qt_dec, 1, pay, out_p, out_h) == http3::QpackError.MessageError, "decode stream_id 1 rejected");

        // Response + TE forbidden in response
        let resp_p = http3::PseudoHeaders { status: 200, has_status: true, .. };
        frame.clear();
        enc_stream.clear();
        let empty_h = http::HeaderMap { .. };
        sub.assert_true(wire::encode_h3_headers_from_map(qt_enc, 4, resp_p, empty_h, enc_stream, frame), "encode H3 response");

        // Data frame + Extended CONNECT + classic CONNECT + OPTIONS *
        var df: u8[..64] = [];
        sub.assert_true(wire::encode_h3_data_frame("hi", df), "encode_h3_data_frame");
        let ext_c = http3::PseudoHeaders {
            method:     "CONNECT", scheme: "https", authority: "wt.example", path: "/wt", protocol: "webtransport",
            has_method: true, has_scheme: true, has_authority: true, has_path: true, has_protocol: true, ..
        };
        frame.clear();
        sub.assert_true(wire::encode_h3_headers_from_map(qt_enc, 8, ext_c, empty_h, enc_stream, frame), "H3 extended CONNECT");
        let cls_c = http3::PseudoHeaders { method: "CONNECT", authority: "h:443", has_method: true, has_authority: true, .. };
        frame.clear();
        sub.assert_true(wire::encode_h3_headers_from_map(qt_enc, 12, cls_c, empty_h, enc_stream, frame), "H3 classic CONNECT");
        let opt_p = http3::PseudoHeaders { method: "OPTIONS", scheme: "https", authority: "h", path: "*", has_method: true, has_scheme: true, has_authority: true, has_path: true, .. };
        frame.clear();
        sub.assert_true(wire::encode_h3_headers_from_map(qt_enc, 16, opt_p, empty_h, enc_stream, frame), "H3 OPTIONS *");
    };
}

fn test_wire_h1_and_exchange(t: lit::T&) {
    t.run("H1 request/response encoding, decoding, TE/CL smuggling guards, Keep-Alive & Sink") { sub =>
        var hdrs = http::HeaderMap { .. };
        let _ = http::append_header(hdrs, "Connection", "x-hop, keep-alive");
        let _ = http::append_header(hdrs, "x-hop", "drop");
        let _ = http::append_header(hdrs, "TE", "trailers");
        let _ = http::append_header(hdrs, "X-App", "1");

        var wire_out: u8[..4096] = [];
        sub.assert_true(wire::encode_h1_request("POST", "/api?a=1", "example.com", hdrs, "body", wire::H1HeaderFilterMode.StripHopByHop, wire_out), "encode H1 request StripHopByHop");
        sub.assert_false(core::contains(wire_out[..], "x-hop:"), "hop-by-hop stripped");
        sub.assert_true(core::contains(wire_out[..], "Content-Length: 4\r\n"), "auto Content-Length");

        // HTTP/1.1 without Host rejected; HTTP/1.0 with TE rejected; CRLF injection rejected
        let empty_h = http::HeaderMap { .. };
        sub.assert_false(wire::encode_h1_request("GET", "/", "", empty_h, "", wire::H1HeaderFilterMode.PreserveAll, wire_out), "missing Host on 1.1 rejected");
        sub.assert_false(wire::encode_h1_request("GET", "/bad target", "example.com", empty_h, "", wire::H1HeaderFilterMode.PreserveAll, wire_out), "space in target rejected");
        var te_h = http::HeaderMap { .. };
        let _ = http::append_header(te_h, "Transfer-Encoding", "chunked");
        sub.assert_false(wire::encode_h1_request("POST", "/", "example.com", te_h, "x", wire::H1HeaderFilterMode.PreserveAll, wire_out, "HTTP/1.0"), "TE on HTTP/1.0 rejected");

        // OverflowArena spill request encode
        var arena = http::OverflowArena { .. };
        let _ = http::append_header(hdrs, "X-Main", "m");
        wire_out.clear();
        sub.assert_true(wire::encode_h1_request_spill("GET", "/s", "example.com", hdrs, arena, "", wire::H1HeaderFilterMode.PreserveAll, wire_out), "encode_h1_request_spill");

        // H1 responses: 200, 204, HEAD body suppression, forbidden CL on 204
        wire_out.clear();
        sub.assert_true(wire::encode_h1_response(200, "", "goose-wing", empty_h, "hello", false, wire_out), "encode H1 200 response");
        var out_st: u16 = 0;
        var dec_h = http::HeaderMap { .. };
        let body_off, perr = wire::decode_h1_response_head(wire_out[..], out_st, dec_h);
        sub.assert_true(perr == http::HeaderParseError.None && out_st == 200, "decode_h1_response_head 200");
        sub.assert_bytes_eq(wire_out[body_off..], "hello", "body offset exact");

        let _, inc_err = wire::decode_h1_response_head("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n", out_st, dec_h);
        sub.assert_true(inc_err == http::HeaderParseError.Incomplete, "incomplete headers detected");
        let _, bare_err = wire::decode_h1_response_head("HTTP/1.1 200 OK\r\nX-A: 1\n\r\n\r\n", out_st, dec_h);
        sub.assert_true(bare_err == http::HeaderParseError.InvalidHeaderValue || bare_err == http::HeaderParseError.MalformedStatusLine, "bare LF rejected");

        // SWAR header field name scan
        let fn_idx, fn_ok = wire::scan_h1_wire_field_name("Content-Type: text/plain\r\n");
        sub.assert_true(fn_ok && fn_idx == 12, "SWAR scan_h1_wire_field_name");
        let _, bad_fn = wire::scan_h1_wire_field_name(": empty\r\n");
        sub.assert_false(bad_fn, "leading colon rejected");

        // serialize_h1_request (CONNECT, POST zero CL, TRACE with body rejected)
        let url_val, uerr = core::parse_url("https://api.example.com/v1?q=2");
        sub.assert_true(uerr == core::UrlParseError.None, "parse url");
        var req = http::Request { method: "POST", .. };
        sub.assert_true(wing::serialize_h1_request(req, url_val, wire_out), "serialize POST 0 CL");
        var conn_req = http::Request { method: "CONNECT", .. };
        sub.assert_true(wing::serialize_h1_request(conn_req, url_val, wire_out), "serialize CONNECT");
        var trace_req = http::Request { method: "TRACE", .. };
        trace_req.body.append("forbidden");
        sub.assert_false(wing::serialize_h1_request(trace_req, url_val, wire_out), "TRACE with body rejected");

        // parse_response_headers + TE/CL conflict stripping + duplicate mismatched CL rejected
        var resp = http::Response { .. };
        sub.assert_true(wing::parse_response_headers("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 99\r\n\r\n", resp), "TE+CL parsed with strip");
        sub.assert_true(resp.had_te_cl_conflict && !http::has_header(resp.headers, "Content-Length"), "conflicting CL stripped");
        sub.assert_false(wing::parse_response_headers("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n", resp), "mismatched duplicate CL rejected");
        sub.assert_true(wing::parse_response_headers("HTTP/1.0 204 No Content\r\n\r\n", resp) && resp.status_code == 204, "headerless 204 parsed");

        // has_rogue_empty_status_framing & classify_h1_transfer_encoding
        var rogue_h = http::HeaderMap { .. };
        let _ = http::append_header(rogue_h, "Content-Length", "10");
        sub.assert_true(wing::has_rogue_empty_status_framing("GET", 204, rogue_h), "non-zero CL on GET 204 is rogue");
        sub.assert_false(wing::has_rogue_empty_status_framing("HEAD", 204, rogue_h), "HEAD 204 allowed");
        sub.assert_true(wing::classify_h1_transfer_encoding("gzip, chunked") == 1, "gzip, chunked -> 1");
        sub.assert_true(wing::classify_h1_transfer_encoding("chunked, gzip") == 2, "chunked not final -> 2");
        sub.assert_true(wing::classify_h1_transfer_encoding("chunked, chunked") == 0, "duplicate chunked rejected -> 0");
        sub.assert_true(wing::classify_h1_transfer_encoding(",chunked") == 0, "leading comma rejected -> 0");

        // Keep-Alive hints & budget & deadline
        let ka = wing::parse_keep_alive_header("timeout=5, max=10, foo=\"bar\"");
        sub.assert_true(ka.has_timeout && ka.timeout_sec == 5 && ka.has_max_reqs && ka.max_reqs == 10, "parse_keep_alive_header");
        let cfg = wing::ExchangeTimeouts { .. };
        let budget_ns, ka_ok = wing::resolve_peer_keep_alive_budget(ka, 1, cfg);
        sub.assert_true(ka_ok && budget_ns == 4000000000, "keep_alive margin applied");
        let _, ka_maxed = wing::resolve_peer_keep_alive_budget(ka, 10, cfg);
        sub.assert_false(ka_maxed, "max_reqs reached");
        let ms_left, has_ms = wing::remaining_deadline_ms(1005000000, 1000000000);
        sub.assert_true(has_ms && ms_left == 5, "remaining_deadline_ms 5ms");
        let _, expired_ms = wing::remaining_deadline_ms(1000, 2000);
        sub.assert_false(expired_ms, "expired deadline false");

        // BufferedBodySink checks
        var sink_resp = http::Response { .. };
        var sink = wing::BufferedBodySink { resp: sink_resp, max_response_bytes: 10 };
        var head = wing::ResponseHead { status_code: 200, .. };
        let _ = http::append_header(head.headers, "Content-Length", "5");
        sub.assert_true(wing::on_headers(sink, head) == wing::StreamSinkVerdict.Continue, "sink on_headers ok");
        sub.assert_true(wing::on_data(sink, "12345") == wing::StreamSinkVerdict.Continue, "sink on_data 5B");
        sub.assert_true(wing::on_data(sink, "678901") == wing::StreamSinkVerdict.AbortExchange, "sink exceeds max_response_bytes");
        let tr_empty = http::HeaderMap { .. };
        wing::on_complete(sink, tr_empty);
    };
}

fn main() {
    let runner = lit::new_runner("Wire Deep Verification Suite");
    lit::run_case(runner, "1. HPACK & HTTP/2 Framing", test_wire_hpack_and_h2);
    lit::run_case(runner, "2. Pipeline & HTTP/3 QPACK", test_wire_pipeline_and_h3);
    lit::run_case(runner, "3. HTTP/1.1 Framing & Exchange Helpers", test_wire_h1_and_exchange);
    assert(lit::finish(runner));
}
