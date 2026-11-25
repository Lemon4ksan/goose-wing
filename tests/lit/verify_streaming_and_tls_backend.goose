// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification of Unified Zero-Copy H1/H2/H3 Streaming with Backpressure
// and Pluggable TLS Backends (PureGoose / Schannel / OpenSSL / Auto).
//
// RUN: goose build -O0 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import wing from "../..";

const LARGE_TOTAL_BYTES: i64 = 2 * 1024 * 1024;
const LARGE_CHUNK_BYTES: i64 = 65536;

// Single protocol-agnostic handler driving HTTP/1.1, HTTP/2, and HTTP/3 identically.
fn pump_unified_handler(
    stream:  server::ResponseStream&,
    res:     http::Response&,
    payload: const u8[:],
    offset:  i64&,
    is_last: bool,
) -> server::StreamWriteStatus {
    if !stream.headers_sent {
        let st_hdr = server::stream_begin(stream, res);
        guard st_hdr == server::StreamWriteStatus.Ok else { return st_hdr; }
    }
    while offset < payload.len {
        let written, st = server::stream_write(stream, payload[offset..]);
        offset = core::add_sat_i64(offset, written);
        if st != server::StreamWriteStatus.Ok {
            return st;
        }
    }
    if is_last {
        return server::stream_end(stream);
    }
    return server::StreamWriteStatus.Ok;
}

fn fill_pattern_chunk(buf: u8[:], seed: u64) {
    var x: u64 = seed ^ 0x9E3779B97F4A7C15;
    for i in buf.len {
        x = (x * 6364136223846793005) + 1442695040888963407;
        buf[i] = ((x >> 24) & 0xFF) as u8;
    }
}

fn make_json_100_payload() -> const u8[:] {
    return "{\"ok\":true,\"stream\":\"unified-zero-copy\",\"protocol\":\"agnostic\",\"size\":100,\"pad\":\"0123456789abcdef12\"}";
}

// ---- 1. HTTP/1.1 Unified Streaming (Live TCP Loopback, Zero 16 KB Ceiling) -

fn send_h1_response_blocking(
    sock_fd:  i64,
    is_large: bool,
) -> u8[32] {
    var stream = server::make_http1_response_stream(sock_fd, "goose-wing-stream");
    var res = http::Response { status_code: rfc::STATUS_OK, .. };
    var hasher = core::Sha256Ctx { .. };

    if !is_large {
        http::set_header(res, rfc::HEADER_CONTENT_TYPE, "application/json");
        let body = make_json_100_payload();
        assert(body.len == 100);
        core::sha256_update(hasher, body);
        var off: i64 = 0;
        let st = pump_unified_handler(stream, res, body, off, true);
        assert(st == server::StreamWriteStatus.Ok && off == 100);
        assert(server::stream_end(stream) == server::StreamWriteStatus.Ok);
        return core::sha256_final(hasher);
    }

    http::set_header(res, rfc::HEADER_CONTENT_TYPE, "application/octet-stream");
    var chunk_buf: u8[65536] = [0; 65536];
    let num_chunks = LARGE_TOTAL_BYTES / LARGE_CHUNK_BYTES;
    for idx in num_chunks {
        fill_pattern_chunk(chunk_buf[..], (idx + 1) as u64);
        core::sha256_update(hasher, chunk_buf[..]);
        var off: i64 = 0;
        let is_last = (idx + 1) == num_chunks;
        while true {
            let st = pump_unified_handler(stream, res, chunk_buf[..], off, is_last);
            if st == server::StreamWriteStatus.Ok { break; }
            assert(st == server::StreamWriteStatus.WouldBlock);
            sleep_ms(1);
        }
        assert(off == LARGE_CHUNK_BYTES);
    }
    assert(server::stream_end(stream) == server::StreamWriteStatus.Ok);
    assert(stream.body_bytes_sent == (LARGE_TOTAL_BYTES as u64));
    return core::sha256_final(hasher);
}

thread_fn h1_loopback_server_worker(listener_fd: i64) {
    let conn1 = net::tcp_accept(listener_fd, 5000);
    assert(conn1 > 0);
    let _ = send_h1_response_blocking(conn1, false);
    net::tcp_close(conn1);

    let conn2 = net::tcp_accept(listener_fd, 5000);
    assert(conn2 > 0);
    let _ = send_h1_response_blocking(conn2, true);
    net::tcp_close(conn2);
}

fn recv_and_hash_h1_chunked(port: u16) -> u64, u8[32] {
    let fd = net::tcp_connect("127.0.0.1", port, 5000);
    assert(fd > 0);
    defer net::tcp_close(fd);

    var hdr_buf: u8[..4096] = [];
    var dec = client::ChunkedStreamDecoder { .. };
    var hasher = core::Sha256Ctx { .. };
    var total_body: u64 = 0;
    var headers_done = false;
    var rx_buf:    u8[32768]   = [0; 32768];
    var plain_out: u8[..32768] = [];

    while !client::is_complete(dec) {
        let n = net::tcp_recv_slice(fd, rx_buf[..], 5000);
        assert(n > 0);
        var data = rx_buf[..n];
        if !headers_done {
            let need = min(data.len, core::sub_sat_i64(hdr_buf.cap, hdr_buf.len));
            assert(hdr_buf.try_append(data[..need]));
            let hend = core::fast_find_crlfcrlf(hdr_buf[..]);
            if hend < 0 { continue; }
            headers_done = true;
            let body_off = core::add_sat_i64(hend, 4);
            let hdr_slice = hdr_buf[..body_off];
            assert(core::contains(hdr_slice, "Transfer-Encoding: chunked"));
            var tail_in_hdr = hdr_buf[body_off..];
            if tail_in_hdr.len > 0 {
                plain_out.clear();
                let _, ok_c = client::feed_chunked_stream(dec, tail_in_hdr, plain_out, -1);
                assert(ok_c);
                if plain_out.len > 0 {
                    core::sha256_update(hasher, plain_out[..]);
                    total_body = core::add_sat_u64(total_body, plain_out.len as u64);
                }
            }
            data = data[need..];
        }
        if headers_done && data.len > 0 && !client::is_complete(dec) {
            plain_out.clear();
            let _, ok_c = client::feed_chunked_stream(dec, data, plain_out, -1);
            assert(ok_c);
            if plain_out.len > 0 {
                core::sha256_update(hasher, plain_out[..]);
                total_body = core::add_sat_u64(total_body, plain_out.len as u64);
            }
        }
    }
    return total_body, core::sha256_final(hasher);
}

fn test_http1_unified_streaming() {
    print("=== 1. HTTP/1.1 Unified Zero-Copy Streaming ===");
    // CHECK: === 1. HTTP/1.1 Unified Zero-Copy Streaming ===

    let listener = net::tcp_listen("127.0.0.1", 0, 8);
    assert(listener > 0);
    let port = net::tcp_getsockname_port(listener);
    assert(port > 0);

    let tid = thread_spawn(h1_loopback_server_worker, listener);

    let small_len, small_hash = recv_and_hash_h1_chunked(port);
    let exp_small = core::sha256(make_json_100_payload());
    let small_ok = (small_len == 100) && core::ct_eq_bytes(small_hash[..], exp_small[..]);

    let large_len, large_hash = recv_and_hash_h1_chunked(port);
    assert(thread_wait(tid));
    net::tcp_close(listener);

    var exp_h = core::Sha256Ctx { .. };
    var pbuf: u8[65536] = [0; 65536];
    let num_chunks = LARGE_TOTAL_BYTES / LARGE_CHUNK_BYTES;
    for idx in num_chunks {
        fill_pattern_chunk(pbuf[..], (idx + 1) as u64);
        core::sha256_update(exp_h, pbuf[..]);
    }
    let exp_large = core::sha256_final(exp_h);
    let large_ok = (large_len == (LARGE_TOTAL_BYTES as u64)) && core::ct_eq_bytes(large_hash[..], exp_large[..]);
    print("h1_small_100_ok=", small_ok, " h1_large_2mb_ok=", large_ok);
    // CHECK: h1_small_100_ok=true h1_large_2mb_ok=true

    // Verify non-blocking WouldBlock (-2) partial offset tracking over a 16 KB virtual pipe
    let pipe_slot, ok_pipe = net::alloc_virtual_pipe_slot();
    assert(ok_pipe);
    defer net::free_virtual_pipe_slot(pipe_slot);
    let tx_fd = net::virtual_pipe_to_fd(pipe_slot, false);
    let rx_fd = net::virtual_pipe_to_fd(pipe_slot, true);

    var nb_stream = server::make_http1_response_stream(tx_fd, "goose-wing");
    var nb_res = http::Response { status_code: rfc::STATUS_OK, .. };
    http::set_header(nb_res, rfc::HEADER_CONTENT_TYPE, "application/octet-stream");
    fill_pattern_chunk(pbuf[..], 999);
    let exp_nb = core::sha256(pbuf[..]);

    var nb_off:         i64 = 0;
    var nb_would_block: i64 = 0;
    var dec = client::ChunkedStreamDecoder { .. };
    var nb_hdr_done = false;
    var nb_hdr_buf: u8[..4096] = [];
    var nb_hasher = core::Sha256Ctx { .. };
    var rx_tmp:    u8[8192]   = [0; 8192];
    var plain_tmp: u8[..8192] = [];

    while true {
        let st = pump_unified_handler(nb_stream, nb_res, pbuf[..], nb_off, true);
        if st == server::StreamWriteStatus.WouldBlock {
            nb_would_block = core::add_sat_i64(nb_would_block, 1);
        }
        while true {
            let rn = net::virtual_fd_recv(rx_fd, rx_tmp[..]);
            if rn <= 0 { break; }
            var slice = rx_tmp[..rn];
            if !nb_hdr_done {
                let take = min(slice.len, core::sub_sat_i64(nb_hdr_buf.cap, nb_hdr_buf.len));
                assert(nb_hdr_buf.try_append(slice[..take]));
                let hend = core::fast_find_crlfcrlf(nb_hdr_buf[..]);
                if hend >= 0 {
                    nb_hdr_done = true;
                    let tail = nb_hdr_buf[core::add_sat_i64(hend, 4)..];
                    if tail.len > 0 {
                        plain_tmp.clear();
                        let _, ok_d = client::feed_chunked_stream(dec, tail, plain_tmp, -1);
                        assert(ok_d);
                        core::sha256_update(nb_hasher, plain_tmp[..]);
                    }
                    slice = slice[take..];
                } else {
                    slice = slice[slice.len..];
                }
            }
            if nb_hdr_done && slice.len > 0 && !client::is_complete(dec) {
                plain_tmp.clear();
                let _, ok_d = client::feed_chunked_stream(dec, slice, plain_tmp, -1);
                assert(ok_d);
                core::sha256_update(nb_hasher, plain_tmp[..]);
            }
        }
        if st == server::StreamWriteStatus.Ok && client::is_complete(dec) { break; }
    }
    let got_nb = core::sha256_final(nb_hasher);
    let nb_ok = nb_would_block > 0 && core::ct_eq_bytes(got_nb[..], exp_nb[..]);
    print("h1_nonblocking_wouldblock_ok=", nb_ok);
    // CHECK: h1_nonblocking_wouldblock_ok=true

    // Verify fixed Content-Length H1 streaming and ServerCork direct helpers
    var fix_stream = server::make_http1_response_stream(-1, "goose-wing");
    var fix_res = http::Response { status_code: rfc::STATUS_OK, .. };
    http::set_header(fix_res, rfc::HEADER_CONTENT_LENGTH, "11");
    assert(server::stream_begin(fix_stream, fix_res) == server::StreamWriteStatus.Ok);
    assert(server::stream_can_write(fix_stream) == 11);
    let nw, stw = server::stream_write(fix_stream, "hello world");
    assert(nw == 11 && stw == server::StreamWriteStatus.Ok);
    assert(server::stream_can_write(fix_stream) == 0);
    assert(server::stream_end(fix_stream) == server::StreamWriteStatus.Ok);
    var fix_wire: u8[512] = [0; 512];
    let fn_len = server::stream_drain_wire(fix_stream, fix_wire[..]);
    assert(fn_len > 0 && core::ends_with(fix_wire[..fn_len], "\r\n\r\nhello world"));
}

// ---- 2. HTTP/2 Unified Streaming + Two-Level Window Backpressure -----------

struct H2WireConsumer {
    hpack_dec:   http2::DynamicTable = http2::new_dynamic_table(4096),
    headers_ok:  bool                = false,
    end_stream:  bool                = false,
    data_bytes:  u64                 = 0,
    data_frames: u64                 = 0,
    hasher:      core::Sha256Ctx     = core::Sha256Ctx { .. },
    buf:         u8[..32768]         = [],
}

fn consume_h2_wire(c: H2WireConsumer&, incoming: const u8[:]) {
    assert(c.buf.try_append(incoming));
    while c.buf.len >= 9 {
        let hdr, err = http2::parse_frame_header(c.buf[..9], 16384);
        assert(err == rfc::H2_ERR_NO_ERROR);
        let total = core::add_sat_i64(9, hdr.length);
        if c.buf.len < total { break; }
        let payload = c.buf[9..total];
        if hdr.frame_type == rfc::H2_FRAME_HEADERS {
            var pseudo = http2::PseudoHeaders { .. };
            var hmap = http::HeaderMap { .. };
            let derr = http2::decode_hpack_to_map(c.hpack_dec, payload, pseudo, hmap, 8192, false);
            assert(derr == rfc::H2_ERR_NO_ERROR && pseudo.status == 200);
            c.headers_ok = true;
        } else if hdr.frame_type == rfc::H2_FRAME_DATA {
            if payload.len > 0 {
                core::sha256_update(c.hasher, payload);
                c.data_bytes = core::add_sat_u64(c.data_bytes, payload.len as u64);
                c.data_frames = core::add_sat_u64(c.data_frames, 1);
            }
            if (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0 {
                c.end_stream = true;
            }
        }
        c.buf.compact_wire_buffer(total);
    }
}

fn drain_h2_stream(stream: server::ResponseStream&, consumer: H2WireConsumer&) {
    var wire: u8[16384] = [0; 16384];
    while true {
        let n = server::stream_drain_wire(stream, wire[..]);
        if n <= 0 { break; }
        consume_h2_wire(consumer, wire[..n]);
    }
}

fn test_http2_unified_streaming() {
    print("=== 2. HTTP/2 Unified Streaming & Window Backpressure ===");
    // CHECK: === 2. HTTP/2 Unified Streaming & Window Backpressure ===

    // 2a. 100-byte JSON response via exact same unified handler
    var s_small = server::make_http2_response_stream(1, 2048, 1024, 16384);
    var r_small = http::Response { status_code: rfc::STATUS_OK, .. };
    http::set_header(r_small, rfc::HEADER_CONTENT_TYPE, "application/json");
    let json100 = make_json_100_payload();
    var off_s: i64 = 0;
    assert(pump_unified_handler(s_small, r_small, json100, off_s, true) == server::StreamWriteStatus.Ok);
    assert(server::stream_end(s_small) == server::StreamWriteStatus.Ok);
    var c_small = H2WireConsumer { .. };
    drain_h2_stream(s_small, c_small);
    let h2_s_hash = core::sha256_final(c_small.hasher);
    let exp_s = core::sha256(json100);
    let h2_small_ok = c_small.headers_ok && c_small.end_stream &&
        c_small.data_bytes == 100 && core::ct_eq_bytes(h2_s_hash[..], exp_s[..]);

    // 2b. 2 MB payload starting with tiny 1024-byte stream window & 2048-byte conn window
    var s_large = server::make_http2_response_stream(3, 2048, 1024, 16384);
    var r_large = http::Response { status_code: rfc::STATUS_OK, .. };
    http::set_header(r_large, rfc::HEADER_CONTENT_TYPE, "application/octet-stream");
    assert(server::stream_can_write(s_large) == 1024);

    var c_large = H2WireConsumer { .. };
    var exp_h = core::Sha256Ctx { .. };
    var chunk_buf:    u8[65536] = [0; 65536];
    var would_blocks: i64       = 0;
    var first_clamped_1024 = false;

    let num_chunks = LARGE_TOTAL_BYTES / LARGE_CHUNK_BYTES;
    for idx in num_chunks {
        fill_pattern_chunk(chunk_buf[..], (idx + 101) as u64);
        core::sha256_update(exp_h, chunk_buf[..]);
        var off: i64 = 0;
        let is_last = (idx + 1) == num_chunks;
        while true {
            let st = pump_unified_handler(s_large, r_large, chunk_buf[..], off, is_last);
            drain_h2_stream(s_large, c_large);
            if st == server::StreamWriteStatus.Ok { break; }
            assert(st == server::StreamWriteStatus.WouldBlock);
            would_blocks = core::add_sat_i64(would_blocks, 1);
            if idx == 0 && would_blocks == 1 {
                first_clamped_1024 = (off == 1024) &&
                    (server::stream_can_write(s_large) == 0) &&
                    (s_large.h2_stream_send_window == 0) &&
                    (s_large.h2_conn_send_window == 1024);
            }
            if server::stream_can_write(s_large) == 0 {
                server::stream_on_window_update(s_large, 65536, 65536);
            }
        }
        assert(off == LARGE_CHUNK_BYTES);
    }
    assert(server::stream_end(s_large) == server::StreamWriteStatus.Ok);
    drain_h2_stream(s_large, c_large);

    let got_h2 = core::sha256_final(c_large.hasher);
    let exp_h2 = core::sha256_final(exp_h);
    let h2_large_ok = c_large.headers_ok && c_large.end_stream &&
        first_clamped_1024 && would_blocks > 1 &&
        c_large.data_bytes == (LARGE_TOTAL_BYTES as u64) &&
        core::ct_eq_bytes(got_h2[..], exp_h2[..]);
    print("h2_small_100_ok=", h2_small_ok, " h2_clamped_1024=", first_clamped_1024, " h2_large_2mb_ok=", h2_large_ok);
    // CHECK: h2_small_100_ok=true h2_clamped_1024=true h2_large_2mb_ok=true
}

// ---- 3. HTTP/3 / QUIC Unified Streaming + Credit Backpressure --------------

var g_h3_qpack_dec: http3::QpackTable = http3::new_qpack_table(0, 0, 0);

struct H3WireConsumer {
    headers_ok:  bool            = false,
    data_bytes:  u64             = 0,
    data_frames: u64             = 0,
    hasher:      core::Sha256Ctx = core::Sha256Ctx { .. },
    buf:         u8[..32768]     = [],
}

fn consume_h3_wire(c: H3WireConsumer&, incoming: const u8[:]) {
    assert(c.buf.try_append(incoming));
    while c.buf.len > 0 {
        let fhdr, ok_h = http3::parse_frame_header(c.buf[..], 0);
        if !ok_h { break; }
        let total = core::add_sat_i64(fhdr.header_len as i64, fhdr.payload_len as i64);
        if c.buf.len < total { break; }
        let payload = c.buf[(fhdr.header_len as i64)..total];
        if fhdr.frame_type == rfc::H3_FRAME_HEADERS {
            var pseudo = http3::PseudoHeaders { .. };
            var hmap = http::HeaderMap { .. };
            let qerr = http3::decode_qpack_to_map(g_h3_qpack_dec, payload, pseudo, hmap, 16384);
            assert(qerr == http3::QpackError.None && pseudo.status == 200);
            c.headers_ok = true;
        } else if fhdr.frame_type == rfc::H3_FRAME_DATA {
            core::sha256_update(c.hasher, payload);
            c.data_bytes = core::add_sat_u64(c.data_bytes, payload.len as u64);
            c.data_frames = core::add_sat_u64(c.data_frames, 1);
        }
        c.buf.compact_wire_buffer(total);
    }
}

fn drain_h3_stream(stream: server::ResponseStream&, consumer: H3WireConsumer&) {
    var wire: u8[16384] = [0; 16384];
    while true {
        let n = server::stream_drain_wire(stream, wire[..]);
        if n <= 0 { break; }
        consume_h3_wire(consumer, wire[..n]);
    }
}

fn test_http3_unified_streaming() {
    print("=== 3. HTTP/3 QUIC Unified Streaming & Credit Backpressure ===");
    // CHECK: === 3. HTTP/3 QUIC Unified Streaming & Credit Backpressure ===

    // 3a. 100-byte JSON response via exact same unified handler
    var s_small = server::make_http3_response_stream(0, 4096, 1500);
    var r_small = http::Response { status_code: rfc::STATUS_OK, .. };
    http::set_header(r_small, rfc::HEADER_CONTENT_TYPE, "application/json");
    let json100 = make_json_100_payload();
    var off_s: i64 = 0;
    assert(pump_unified_handler(s_small, r_small, json100, off_s, true) == server::StreamWriteStatus.Ok);
    assert(server::stream_end(s_small) == server::StreamWriteStatus.Ok);
    var c_small = H3WireConsumer { .. };
    drain_h3_stream(s_small, c_small);
    let h3_s_hash = core::sha256_final(c_small.hasher);
    let exp_s = core::sha256(json100);
    let h3_small_ok = c_small.headers_ok && s_small.h3_fin_emitted &&
        s_small.quic_stream.send_state == quic::QuicSendState.DataSent &&
        c_small.data_bytes == 100 && core::ct_eq_bytes(h3_s_hash[..], exp_s[..]);

    // 3b. 2 MB payload starting with tiny 1500-byte QUIC stream credit
    var s_large = server::make_http3_response_stream(4, 4096, 1500);
    var r_large = http::Response { status_code: rfc::STATUS_OK, .. };
    http::set_header(r_large, rfc::HEADER_CONTENT_TYPE, "application/octet-stream");
    assert(server::stream_can_write(s_large) == 1500);

    var c_large = H3WireConsumer { .. };
    var exp_h = core::Sha256Ctx { .. };
    var chunk_buf:    u8[65536] = [0; 65536];
    var would_blocks: i64       = 0;
    var first_clamped_1500 = false;

    let num_chunks = LARGE_TOTAL_BYTES / LARGE_CHUNK_BYTES;
    for idx in num_chunks {
        fill_pattern_chunk(chunk_buf[..], (idx + 201) as u64);
        core::sha256_update(exp_h, chunk_buf[..]);
        var off: i64 = 0;
        let is_last = (idx + 1) == num_chunks;
        while true {
            let st = pump_unified_handler(s_large, r_large, chunk_buf[..], off, is_last);
            drain_h3_stream(s_large, c_large);
            if st == server::StreamWriteStatus.Ok { break; }
            assert(st == server::StreamWriteStatus.WouldBlock);
            would_blocks = core::add_sat_i64(would_blocks, 1);
            if idx == 0 && would_blocks == 1 {
                first_clamped_1500 = (off == 1500) && (server::stream_can_write(s_large) == 0);
                // Test absolute MAX_DATA / MAX_STREAM_DATA replenishment
                server::stream_on_quic_max_data(s_large, 131072, 65536);
            } else if server::stream_can_write(s_large) == 0 {
                server::stream_on_window_update(s_large, 65536, 65536);
            }
        }
        assert(off == LARGE_CHUNK_BYTES);
    }
    assert(server::stream_end(s_large) == server::StreamWriteStatus.Ok);
    drain_h3_stream(s_large, c_large);

    let got_h3 = core::sha256_final(c_large.hasher);
    let exp_h3 = core::sha256_final(exp_h);
    let h3_large_ok = c_large.headers_ok && s_large.h3_fin_emitted &&
        s_large.quic_stream.send_state == quic::QuicSendState.DataSent &&
        first_clamped_1500 && would_blocks > 1 &&
        c_large.data_bytes == (LARGE_TOTAL_BYTES as u64) &&
        core::ct_eq_bytes(got_h3[..], exp_h3[..]);
    print("h3_small_100_ok=", h3_small_ok, " h3_clamped_1500=", first_clamped_1500, " h3_large_2mb_ok=", h3_large_ok);
    // CHECK: h3_small_100_ok=true h3_clamped_1500=true h3_large_2mb_ok=true
}

// ---- 4. Request & Client Body Streaming Backpressure Windows ---------------

fn test_request_and_client_backpressure() {
    print("=== 4. Request & Client Pull-Rate Backpressure ===");
    // CHECK: === 4. Request & Client Pull-Rate Backpressure ===

    // HTTP/2 request window: 2048 stream, 4096 conn, 50% threshold
    var w2 = server::make_request_stream_window(server::WindowProtocol.Http2, 5, 2048, 4096, 50);
    assert(server::request_window_available(w2) == 2048);
    assert(server::request_window_on_ingress(w2, 2048));
    assert(w2.is_backpressured && server::request_window_available(w2) == 0);
    // Peer violating flow control must be rejected
    assert(!server::request_window_on_ingress(w2, 1));
    // Partial consumption below 50% threshold (512 < 1024) must NOT emit WINDOW_UPDATE
    let rep_low = server::request_window_on_consume(w2, 512);
    assert(!rep_low.should_update_stream && !rep_low.should_update_conn);
    // Consuming 512 more hits 1024 (50% of stream window) -> emits stream WINDOW_UPDATE
    let rep_hi = server::request_window_on_consume(w2, 512);
    assert(rep_hi.should_update_stream && rep_hi.stream_increment == 1024 && !rep_hi.should_update_conn);
    var h2_wu_wire: u8[..64] = [];
    assert(server::request_window_encode_h2_updates(w2, rep_hi, h2_wu_wire));
    assert(h2_wu_wire.len == 13);
    let wu_hdr, wu_err = http2::parse_frame_header(h2_wu_wire[..9], 16384);
    assert(wu_err == rfc::H2_ERR_NO_ERROR && wu_hdr.frame_type == rfc::H2_FRAME_WINDOW_UPDATE && wu_hdr.stream_id == 5);
    assert(core::read_be_u32(h2_wu_wire[..], 9) == 1024);

    // HTTP/3 QUIC request window: 2048 stream, 2048 conn, 50% threshold
    var w3 = server::make_request_stream_window(server::WindowProtocol.Http3, 4, 2048, 2048, 50);
    assert(server::request_window_on_ingress(w3, 2048));
    let rep3 = server::request_window_on_consume(w3, 1500);
    assert(rep3.should_update_stream && rep3.should_update_conn);
    assert(rep3.stream_increment == 3548 && rep3.conn_increment == 3548);
    var q_wire: u8[..64] = [];
    assert(server::request_window_encode_quic_updates(w3, rep3, q_wire));
    let ftype, off1, ok1 = quic::decode_varint(q_wire[..], 0);
    let max_d, _, ok2 = quic::decode_varint(q_wire[..], off1);
    assert(ok1 && ok2 && ftype == rfc::QUIC_FRAME_MAX_DATA && max_d == 3548);

    // Client pull-rate stream window
    var cw = client::make_client_stream_window(4096, 50);
    assert(client::client_window_can_receive(cw) == 4096);
    assert(client::client_window_on_ingress(cw, 4096));
    assert(client::client_window_can_receive(cw) == 0);
    assert(!client::client_window_on_ingress(cw, 1));
    let d1, ok_c1 = client::client_window_on_consume(cw, 1024);
    assert(!ok_c1 && d1 == 0);
    let d2, ok_c2 = client::client_window_on_consume(cw, 1024);
    assert(ok_c2 && d2 == 2048 && client::client_window_can_receive(cw) == 2048);

    print("req_h2_bp_ok=true req_h3_bp_ok=true client_bp_ok=true");
    // CHECK: req_h2_bp_ok=true req_h3_bp_ok=true client_bp_ok=true
}

// ---- 5. Pluggable TLS Backends (PureGoose + Schannel + OpenSSL + Auto) -----

fn pump_tls_wire(src: tls::TlsEndpoint&, dst: tls::TlsEndpoint&) -> i64 {
    var wire:  u8[16384] = [0; 16384];
    var total: i64       = 0;
    while true {
        let n, st_d = tls::tls_endpoint_drain_wire(src, wire[..]);
        assert(st_d == tls::TlsBackendStatus.Ok);
        if n <= 0 { break; }
        let fed, st_f = tls::tls_endpoint_feed_wire(dst, wire[..n]);
        assert(st_f == tls::TlsBackendStatus.Ok && fed == n);
        total = core::add_sat_i64(total, n);
    }
    return total;
}

fn test_pluggable_tls_backends() {
    print("=== 5. Pluggable TLS Backend (PureGoose / Schannel / OpenSSL) ===");
    // CHECK: === 5. Pluggable TLS Backend (PureGoose / Schannel / OpenSSL) ===

    assert(tls::tls_backend_available(tls::TlsBackendKind.PureGoose));
    assert(tls::tls_backend_available(tls::TlsBackendKind.Auto));

    // Build test Ed25519 certificate for localhost
    let seed: u8[32] = [0x5A; 32];
    var cert_der: u8[..2048] = [];
    assert(tls::build_test_ed25519_cert_der(seed, "localhost", "localhost", "127.0.0.1", cert_der));

    var trust = tls::TrustAnchorStore { .. };
    assert(tls::add_trust_anchor_cert_der(trust, cert_der[..]));

    // RFC 7301 ALPN wire format: \x02h2\x08http/1.1
    let alpn_wire: u8[12] = [2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'];

    var cli_cfg = tls::TlsBackendConfig {
        kind:                 tls::TlsBackendKind.PureGoose,
        is_server:            false,
        insecure_skip_verify: false,
        trust_store:          trust,
        ..
    };
    assert(cli_cfg.server_name.try_set("localhost"));
    assert(cli_cfg.alpn_wire.try_set(alpn_wire[..]));

    var srv_cfg = tls::TlsBackendConfig {
        kind:      tls::TlsBackendKind.PureGoose,
        is_server: true,
        priv_seed: seed,
        ..
    };
    assert(srv_cfg.cert_der.try_set(cert_der[..]));
    assert(srv_cfg.alpn_wire.try_set(alpn_wire[..]));

    var cli_ep, cli_st = tls::tls_endpoint_open(cli_cfg);
    var srv_ep, srv_st = tls::tls_endpoint_open(srv_cfg);
    assert(cli_st == tls::TlsBackendStatus.Ok && srv_st == tls::TlsBackendStatus.Ok);

    for _ in 12 {
        let cs = tls::tls_endpoint_step_handshake(cli_ep);
        assert(cs == tls::TlsBackendStatus.Ok || cs == tls::TlsBackendStatus.WantRead);
        let _ = pump_tls_wire(cli_ep, srv_ep);
        let ss = tls::tls_endpoint_step_handshake(srv_ep);
        assert(ss == tls::TlsBackendStatus.Ok || ss == tls::TlsBackendStatus.WantRead);
        let _ = pump_tls_wire(srv_ep, cli_ep);
        if tls::tls_endpoint_is_established(cli_ep) && tls::tls_endpoint_is_established(srv_ep) {
            break;
        }
    }
    let est_ok = tls::tls_endpoint_is_established(cli_ep) && tls::tls_endpoint_is_established(srv_ep);
    let cli_alpn = tls::tls_endpoint_selected_alpn(cli_ep);
    let srv_alpn = tls::tls_endpoint_selected_alpn(srv_ep);
    let alpn_ok = (cli_alpn[..] == "h2") && (srv_alpn[..] == "h2");
    print("pure_handshake_ok=", est_ok, " pure_alpn=", cli_alpn[..], " alpn_match=", alpn_ok);
    // CHECK: pure_handshake_ok=true pure_alpn=h2 alpn_match=true

    // Bidirectional encrypted app data (including multi-record 36 KB payload)
    let msg_c2s = "GET /stream HTTP/2 via PureGoose TlsEndpoint";
    let wc, st_wc = tls::tls_endpoint_write_app(cli_ep, msg_c2s);
    assert(st_wc == tls::TlsBackendStatus.Ok && wc == msg_c2s.len);
    assert(pump_tls_wire(cli_ep, srv_ep) > msg_c2s.len);
    var rx_s: u8[256] = [0; 256];
    let rs, st_rs = tls::tls_endpoint_read_app(srv_ep, rx_s[..]);
    assert(st_rs == tls::TlsBackendStatus.Ok && rx_s[..rs] == msg_c2s);

    var big_tx: u8[36000] = [0; 36000];
    fill_pattern_chunk(big_tx[..], 777);
    let exp_big = core::sha256(big_tx[..]);
    var rx_hash = core::Sha256Ctx { .. };
    var tx_off:   i64      = 0;
    var rx_total: i64      = 0;
    var rx_chunk: u8[8192] = [0; 8192];
    while rx_total < big_tx.len {
        if tx_off < big_tx.len {
            let nw, stw = tls::tls_endpoint_write_app(srv_ep, big_tx[tx_off..]);
            assert(stw == tls::TlsBackendStatus.Ok || stw == tls::TlsBackendStatus.WantWrite);
            tx_off = core::add_sat_i64(tx_off, nw);
        }
        let _ = pump_tls_wire(srv_ep, cli_ep);
        while true {
            let nr, str = tls::tls_endpoint_read_app(cli_ep, rx_chunk[..]);
            if nr <= 0 {
                assert(str == tls::TlsBackendStatus.WantRead || str == tls::TlsBackendStatus.Ok);
                break;
            }
            core::sha256_update(rx_hash, rx_chunk[..nr]);
            rx_total = core::add_sat_i64(rx_total, nr);
        }
    }
    let got_big = core::sha256_final(rx_hash);
    let bidir_ok = core::ct_eq_bytes(got_big[..], exp_big[..]);
    print("pure_bidir_36kb_ok=", bidir_ok);
    // CHECK: pure_bidir_36kb_ok=true

    // Idempotent close
    tls::tls_endpoint_close(cli_ep);
    tls::tls_endpoint_close(cli_ep);
    tls::tls_endpoint_close(srv_ep);
    tls::tls_endpoint_close(srv_ep);
    assert(!tls::tls_endpoint_is_established(cli_ep));

    // Negative verification check: untrusted cert must yield VerifyError
    var bad_cli_cfg = tls::TlsBackendConfig {
        kind:                 tls::TlsBackendKind.PureGoose,
        is_server:            false,
        insecure_skip_verify: false,
        ..
    };
    assert(bad_cli_cfg.server_name.try_set("localhost"));
    var bad_cli, _ = tls::tls_endpoint_open(bad_cli_cfg);
    var bad_srv, _ = tls::tls_endpoint_open(srv_cfg);
    var saw_verify_err = false;
    for _ in 8 {
        let cs = tls::tls_endpoint_step_handshake(bad_cli);
        if cs == tls::TlsBackendStatus.VerifyError {
            saw_verify_err = true;
            break;
        }
        let _ = pump_tls_wire(bad_cli, bad_srv);
        let _ = tls::tls_endpoint_step_handshake(bad_srv);
        let _ = pump_tls_wire(bad_srv, bad_cli);
    }
    tls::tls_endpoint_close(bad_cli);
    tls::tls_endpoint_close(bad_srv);
    print("pure_untrusted_verify_err=", saw_verify_err);
    // CHECK: pure_untrusted_verify_err=true

    // Native backend probe & lifecycle (Schannel on Windows, OpenSSL dynamic probe, Auto)
    let sch_avail = tls::tls_backend_available(tls::TlsBackendKind.SystemSchannel);
    var sch_ok = !sch_avail;
    if sch_avail {
        var sch_cfg = tls::TlsBackendConfig {
            kind:                 tls::TlsBackendKind.SystemSchannel,
            is_server:            false,
            insecure_skip_verify: true,
            ..
        };
        assert(sch_cfg.server_name.try_set("localhost"));
        assert(sch_cfg.alpn_wire.try_set(alpn_wire[..]));
        var sch_ep, sst = tls::tls_endpoint_open(sch_cfg);
        assert(sst == tls::TlsBackendStatus.Ok);
        let hst = tls::tls_endpoint_step_handshake(sch_ep);
        assert(hst == tls::TlsBackendStatus.WantRead);
        var ch_wire: u8[2048] = [0; 2048];
        let ch_n, dst = tls::tls_endpoint_drain_wire(sch_ep, ch_wire[..]);
        // Real Schannel ClientHello: TLS record type 0x16, version 0x03, HS type 0x01
        sch_ok = (dst == tls::TlsBackendStatus.Ok) && (ch_n > 40) &&
            (ch_wire[0] == 0x16) && (ch_wire[1] == 0x03) && (ch_wire[5] == 0x01) &&
            !tls::tls_endpoint_is_established(sch_ep);
        tls::tls_endpoint_close(sch_ep);
        tls::tls_endpoint_close(sch_ep);
    }

    let ossl_avail = tls::tls_backend_available(tls::TlsBackendKind.SystemOpenSsl);
    var ossl_cfg = tls::TlsBackendConfig {
        kind:                 tls::TlsBackendKind.SystemOpenSsl,
        is_server:            false,
        insecure_skip_verify: true,
        ..
    };
    assert(ossl_cfg.server_name.try_set("localhost"));
    assert(ossl_cfg.alpn_wire.try_set(alpn_wire[..]));
    var ossl_ep, ost = tls::tls_endpoint_open(ossl_cfg);
    var ossl_clean = false;
    if ossl_avail {
        assert(ost == tls::TlsBackendStatus.Ok);
        let _ = tls::tls_endpoint_step_handshake(ossl_ep);
        var och: u8[2048] = [0; 2048];
        let on, _ = tls::tls_endpoint_drain_wire(ossl_ep, och[..]);
        ossl_clean = (on > 40) && (och[0] == 0x16) && (och[1] == 0x03);
        tls::tls_endpoint_close(ossl_ep);
        tls::tls_endpoint_close(ossl_ep);
    } else {
        ossl_clean = (ost == tls::TlsBackendStatus.Unavailable);
    }

    var auto_cfg = tls::TlsBackendConfig {
        kind:                 tls::TlsBackendKind.Auto,
        min_version:          tls::TlsMinVersion.Tls12,
        is_server:            false,
        insecure_skip_verify: true,
        ..
    };
    assert(auto_cfg.server_name.try_set("localhost"));
    var auto_ep, ast = tls::tls_endpoint_open(auto_cfg);
    assert(ast == tls::TlsBackendStatus.Ok);
    let _ = tls::tls_endpoint_step_handshake(auto_ep);
    var ach: u8[2048] = [0; 2048];
    let an, _ = tls::tls_endpoint_drain_wire(auto_ep, ach[..]);
    let auto_ok = (an > 40) && (ach[0] == 0x16) && (ach[1] == 0x03);
    tls::tls_endpoint_close(auto_ep);
    tls::tls_endpoint_close(auto_ep);

    // SecureTransport must reject TLS 1.3-only everywhere (no silent downgrade to TLS 1.2)
    var st_strict_cfg = tls::TlsBackendConfig {
        kind:        tls::TlsBackendKind.SystemSecureTransport,
        min_version: tls::TlsMinVersion.Tls13,
        ..
    };
    var st_strict_ep, st_strict_st = tls::tls_endpoint_open(st_strict_cfg);
    let st_strict_rejected = st_strict_st == tls::TlsBackendStatus.Unavailable;
    tls::tls_endpoint_close(st_strict_ep);

    // SystemOnly must never silently fall back to PureGoose when Pure-only features are requested.
    var sys_pq_cfg = tls::TlsBackendConfig {
        kind:             tls::TlsBackendKind.SystemOnly,
        enable_pq_hybrid: true,
        ..
    };
    var sys_pq_ep, sys_pq_st = tls::tls_endpoint_open(sys_pq_cfg);
    let sys_pq_rejected = sys_pq_st == tls::TlsBackendStatus.Unavailable;
    tls::tls_endpoint_close(sys_pq_ep);

    let sys_avail = tls::tls_backend_available(tls::TlsBackendKind.SystemOnly);
    var sys_open_ok = !sys_avail;
    if sys_avail {
        var sys_cfg = tls::TlsBackendConfig {
            kind:                 tls::TlsBackendKind.SystemOnly,
            min_version:          tls::TlsMinVersion.Tls12,
            is_server:            false,
            insecure_skip_verify: true,
            ..
        };
        assert(sys_cfg.server_name.try_set("localhost"));
        var sys_ep, sys_st = tls::tls_endpoint_open(sys_cfg);
        assert(sys_st == tls::TlsBackendStatus.Ok);
        assert(sys_ep.active_kind != tls::TlsBackendKind.PureGoose);
        let _ = tls::tls_endpoint_step_handshake(sys_ep);
        var sysh: u8[2048] = [0; 2048];
        let sn, _ = tls::tls_endpoint_drain_wire(sys_ep, sysh[..]);
        sys_open_ok = (sn > 40) && (sysh[0] == 0x16) && (sysh[1] == 0x03);
        tls::tls_endpoint_close(sys_ep);
    }
    let bad_ak, bad_ak_ok = tls::endpoint_transport_active_kind(-1);
    assert(!bad_ak_ok && bad_ak == tls::TlsBackendKind.PureGoose);

    // Schannel with explicit TlsMinVersion.Tls12 fallback on Windows
    var sch12_ok = !sch_avail;
    if sch_avail {
        var sch12_cfg = tls::TlsBackendConfig {
            kind:                 tls::TlsBackendKind.SystemSchannel,
            min_version:          tls::TlsMinVersion.Tls12,
            is_server:            false,
            insecure_skip_verify: true,
            ..
        };
        assert(sch12_cfg.server_name.try_set("localhost"));
        var sch12_ep, s12_st = tls::tls_endpoint_open(sch12_cfg);
        assert(s12_st == tls::TlsBackendStatus.Ok);
        let h12 = tls::tls_endpoint_step_handshake(sch12_ep);
        assert(h12 == tls::TlsBackendStatus.WantRead);
        var ch12: u8[2048] = [0; 2048];
        let n12, d12 = tls::tls_endpoint_drain_wire(sch12_ep, ch12[..]);
        sch12_ok = (d12 == tls::TlsBackendStatus.Ok) && (n12 > 40) && (ch12[0] == 0x16) && (ch12[1] == 0x03);
        tls::tls_endpoint_close(sch12_ep);
    }

    print("native_schannel_ok=", sch_ok && sch12_ok, " native_openssl_clean=", ossl_clean,
        " st_strict_reject=", st_strict_rejected, " sys_only_ok=", sys_pq_rejected && sys_open_ok,
        " auto_ok=", auto_ok);
    // CHECK: native_schannel_ok=true native_openssl_clean=true st_strict_reject=true sys_only_ok=true auto_ok=true
}

// ---- 6. Non-Blocking TlsStream, Pre-Connect TCP Options & mTLS Fail-Closed --

fn test_tls_stream_mtls_and_tcp_opts() {
    print("=== 6. Non-Blocking TlsStream, TCP Connect Options & mTLS Guards ===");
    // CHECK: === 6. Non-Blocking TlsStream, TCP Connect Options & mTLS Guards ===

    let seed: u8[32] = [0x6B; 32];
    var cert_der: u8[..2048] = [];
    assert(tls::build_test_ed25519_cert_der(seed, "localhost", "localhost", "127.0.0.1", cert_der));

    var trust = tls::TrustAnchorStore { .. };
    assert(tls::add_trust_anchor_cert_der(trust, cert_der[..]));

    var cli_cfg = tls::TlsBackendConfig {
        kind:                 tls::TlsBackendKind.PureGoose,
        is_server:            false,
        insecure_skip_verify: false,
        trust_store:          trust,
        ..
    };
    assert(cli_cfg.server_name.try_set("localhost"));

    var srv_cfg = tls::TlsBackendConfig {
        kind:      tls::TlsBackendKind.PureGoose,
        is_server: true,
        priv_seed: seed,
        ..
    };
    assert(srv_cfg.cert_der.try_set(cert_der[..]));

    // 6a. Virtual pipe non-blocking TlsStream + WantRead + graceful CloseNotify
    let p_slot, p_ok = net::alloc_virtual_pipe_slot();
    assert(p_ok);
    let a_fd = net::virtual_pipe_to_fd(p_slot, false);
    let b_fd = net::virtual_pipe_to_fd(p_slot, true);
    var c_st, c_open = tls::tls_stream_open(a_fd, cli_cfg);
    var s_st, s_open = tls::tls_stream_open(b_fd, srv_cfg);
    assert(c_open == tls::TlsBackendStatus.Ok && s_open == tls::TlsBackendStatus.Ok);

    for _ in 12 {
        let cs = tls::tls_stream_step_handshake(c_st);
        assert(cs == tls::TlsBackendStatus.Ok || cs == tls::TlsBackendStatus.WantRead ||
            cs == tls::TlsBackendStatus.WantWrite);
        let ss = tls::tls_stream_step_handshake(s_st);
        assert(ss == tls::TlsBackendStatus.Ok || ss == tls::TlsBackendStatus.WantRead ||
            ss == tls::TlsBackendStatus.WantWrite);
        if tls::tls_endpoint_is_established(c_st.ep) && tls::tls_endpoint_is_established(s_st.ep) {
            break;
        }
    }
    let vp_est = tls::tls_endpoint_is_established(c_st.ep) && tls::tls_endpoint_is_established(s_st.ep);
    var rx_tmp: u8[128] = [0; 128];
    let n_empty, st_empty = tls::tls_stream_read(s_st, rx_tmp[..]);
    let want_read_ok = (n_empty == 0) && (st_empty == tls::TlsBackendStatus.WantRead);

    let w_msg = "hello-over-nonblocking-tls-stream";
    let wn, wst = tls::tls_stream_write(c_st, w_msg);
    assert(wn == w_msg.len && wst == tls::TlsBackendStatus.Ok);
    let rn, rst = tls::tls_stream_read(s_st, rx_tmp[..]);
    let data_ok = (rst == tls::TlsBackendStatus.Ok) && (rn == w_msg.len) && (rx_tmp[..rn] == w_msg);

    let sh_st = tls::tls_stream_shutdown(c_st);
    let _, peer_close_st = tls::tls_stream_read(s_st, rx_tmp[..]);
    let close_notify_ok = (sh_st == tls::TlsBackendStatus.Ok) && (peer_close_st == tls::TlsBackendStatus.Closed);
    let poll_mask_ok = (tls::tls_stream_poll_events(s_st) & net::EPOLL_READ) != 0;

    tls::tls_stream_close(c_st);
    tls::tls_stream_close(c_st);
    tls::tls_stream_close(s_st);
    net::virtual_fd_close(a_fd);
    net::virtual_fd_close(b_fd);
    print("vpipe_tls_stream_ok=", vp_est && want_read_ok && data_ok && close_notify_ok && poll_mask_ok);
    // CHECK: vpipe_tls_stream_ok=true

    // 6b. Live loopback TCP socket with net::tcp_connect_with_options + non-blocking TlsStream
    let lfd = net::tcp_listen("127.0.0.1", 0, 16);
    assert(lfd > 0);
    let _ = net::tcp_set_nonblocking(lfd, true);
    let lport = net::tcp_getsockname_port(lfd);
    assert(lport > 0);

    var cstate: i32 = -1;
    var cerr:   i32 = -1;
    let copts = net::TcpConnectOptions {
        dst_ip:      "127.0.0.1",
        dst_port:    lport,
        ttl:         64,
        mss:         1460,
        rcvbuf:      65536,
        tcp_nodelay: true,
        ..
    };
    let cfd = net::tcp_connect_with_options(copts, cstate, cerr);
    assert(cfd > 0 && (cstate == 0 || cstate == 1));
    assert(net::tcp_set_rcvbuf(cfd, 65536) && !net::tcp_set_rcvbuf(cfd, 0));
    assert(!net::tcp_set_mss(cfd, 100));
    let _ = net::tcp_set_mss(cfd, 1460);

    var sfd: i64 = -1;
    for _ in 100 {
        sfd = net::tcp_accept_nonblocking(lfd);
        if sfd > 0 { break; }
        sleep_ms(1);
    }
    assert(sfd > 0);
    let _ = net::tcp_set_nonblocking(sfd, true);

    var live_c, lco = tls::tls_stream_open(cfd, cli_cfg);
    var live_s, lso = tls::tls_stream_open(sfd, srv_cfg);
    assert(lco == tls::TlsBackendStatus.Ok && lso == tls::TlsBackendStatus.Ok);

    for _ in 200 {
        let _ = tls::tls_stream_step_handshake(live_c);
        let _ = tls::tls_stream_step_handshake(live_s);
        if tls::tls_endpoint_is_established(live_c.ep) && tls::tls_endpoint_is_established(live_s.ep) {
            break;
        }
        sleep_ms(1);
    }
    let live_est = tls::tls_endpoint_is_established(live_c.ep) && tls::tls_endpoint_is_established(live_s.ep);
    let ping = "tcp-opts-live-tls-ping";
    let pw, pws = tls::tls_stream_write(live_c, ping);
    assert(pw == ping.len && (pws == tls::TlsBackendStatus.Ok || pws == tls::TlsBackendStatus.WantWrite));
    var live_rx:  u8[128] = [0; 128];
    var got_live: i64     = 0;
    for _ in 100 {
        let _ = tls::tls_stream_flush_wire(live_c);
        let r, rs = tls::tls_stream_read(live_s, live_rx[..]);
        if r > 0 && rs == tls::TlsBackendStatus.Ok {
            got_live = r;
            break;
        }
        sleep_ms(1);
    }
    let live_ok = live_est && (got_live == ping.len) && (live_rx[..got_live] == ping);
    tls::tls_stream_close(live_c);
    tls::tls_stream_close(live_s);
    net::tcp_close(cfd);
    net::tcp_close(sfd);
    net::tcp_close(lfd);
    print("live_tcp_opts_tls_stream_ok=", live_ok);
    // CHECK: live_tcp_opts_tls_stream_ok=true

    // 6c. Legacy tls::transport_recv_slice must not spin on WouldBlock (-2) or peer EOF (0)
    let vp2, vp2_ok = net::alloc_virtual_pipe_slot();
    assert(vp2_ok);
    let fd_r = net::virtual_pipe_to_fd(vp2, false);
    let fd_w = net::virtual_pipe_to_fd(vp2, true);
    let tslot = tls::alloc_cipher_slot();
    assert(tslot != 0xFFFF);
    let k16:  u8[16] = [0x11; 16];
    let iv12: u8[12] = [0x22; 12];
    tls_internal::init_cipher_slot_for_test(tslot, rfc::TLS_CIPHER_AES_128_GCM_SHA256, k16[..], iv12, k16[..], iv12);
    var leg_buf: u8[64] = [0; 64];
    let leg_wb = tls::transport_recv_slice(fd_r, tslot, leg_buf[..], 0);
    net::virtual_fd_close(fd_w);
    let leg_eof = tls::transport_recv_slice(fd_r, tslot, leg_buf[..], 0);
    tls::free_cipher_slot(tslot);
    net::virtual_fd_close(fd_r);
    print("legacy_recv_no_spin_ok=", (leg_wb == -2) && (leg_eof == 0));
    // CHECK: legacy_recv_no_spin_ok=true

    // 6d. Fail-closed mTLS / PEM config guards (never silently drop PEM credentials or custom CA in Auto)
    var half_cfg = tls::TlsBackendConfig {
        kind:                 tls::TlsBackendKind.Auto,
        is_server:            false,
        insecure_skip_verify: true,
        ..
    };
    assert(half_cfg.cert_pem_file.try_set("nonexistent-client.pem"));
    let _, half_st = tls::tls_endpoint_open(half_cfg);

    var mtls_cfg = tls::TlsBackendConfig {
        kind:                 tls::TlsBackendKind.Auto,
        is_server:            false,
        insecure_skip_verify: true,
        ..
    };
    assert(mtls_cfg.cert_pem_file.try_set("nonexistent-client.pem"));
    assert(mtls_cfg.key_pem_file.try_set("nonexistent-client.key"));
    let _, mtls_st = tls::tls_endpoint_open(mtls_cfg);

    var ca_cfg = tls::TlsBackendConfig {
        kind:                 tls::TlsBackendKind.Auto,
        is_server:            false,
        insecure_skip_verify: false,
        ..
    };
    assert(ca_cfg.ca_file.try_set("nonexistent-ca.pem"));
    let _, ca_st = tls::tls_endpoint_open(ca_cfg);

    let fail_closed_ok = (half_st != tls::TlsBackendStatus.Ok) &&
        (mtls_st != tls::TlsBackendStatus.Ok) &&
        (ca_st != tls::TlsBackendStatus.Ok);
    print("mtls_fail_closed_ok=", fail_closed_ok);
    // CHECK: mtls_fail_closed_ok=true

    // 6e. Non-blocking net::tcp_connect_begin + net::tcp_connect_poll + IP-literal TLS SAN ("127.0.0.1")
    let nb_lfd = net::tcp_listen("127.0.0.1", 0, 16);
    assert(nb_lfd > 0);
    let _ = net::tcp_set_nonblocking(nb_lfd, true);
    let nb_port = net::tcp_getsockname_port(nb_lfd);
    assert(nb_port > 0);

    var nb_st: i32 = -1;
    let nb_cfd = net::tcp_connect_begin("127.0.0.1", nb_port, nb_st);
    assert(nb_cfd > 0 && (nb_st == 0 || nb_st == 1));
    var nb_connected = (nb_st == 0);
    for _ in 100 {
        if nb_connected { break; }
        let pst = net::tcp_connect_poll(nb_cfd);
        if pst == 0 {
            nb_connected = true;
            break;
        }
        assert(pst == 1);
        sleep_ms(1);
    }
    var nb_sfd: i64 = -1;
    for _ in 100 {
        nb_sfd = net::tcp_accept_nonblocking(nb_lfd);
        if nb_sfd > 0 { break; }
        sleep_ms(1);
    }
    assert(nb_connected && nb_sfd > 0);
    let _ = net::tcp_set_nonblocking(nb_sfd, true);

    var ip_cli_cfg = tls::TlsBackendConfig {
        kind:                 tls::TlsBackendKind.Auto,
        is_server:            false,
        insecure_skip_verify: false,
        trust_store:          trust,
        ..
    };
    assert(ip_cli_cfg.server_name.try_set("127.0.0.1"));
    var ip_c, ico = tls::tls_stream_open(nb_cfd, ip_cli_cfg);
    var ip_s, iso = tls::tls_stream_open(nb_sfd, srv_cfg);
    assert(ico == tls::TlsBackendStatus.Ok && iso == tls::TlsBackendStatus.Ok);
    for _ in 200 {
        let _ = tls::tls_stream_step_handshake(ip_c);
        let _ = tls::tls_stream_step_handshake(ip_s);
        if tls::tls_endpoint_is_established(ip_c.ep) && tls::tls_endpoint_is_established(ip_s.ep) {
            break;
        }
        sleep_ms(1);
    }
    let ip_tls_ok = tls::tls_endpoint_is_established(ip_c.ep) && tls::tls_endpoint_is_established(ip_s.ep);
    tls::tls_stream_close(ip_c);
    tls::tls_stream_close(ip_s);
    net::tcp_close(nb_cfd);
    net::tcp_close(nb_sfd);
    net::tcp_close(nb_lfd);
    print("nb_connect_poll_and_ip_san_ok=", nb_connected && ip_tls_ok);
    // CHECK: nb_connect_poll_and_ip_san_ok=true
}

fn main() {
    test_http1_unified_streaming();
    test_http2_unified_streaming();
    test_http3_unified_streaming();
    test_request_and_client_backpressure();
    test_pluggable_tls_backends();
    test_tls_stream_mtls_and_tcp_opts();
    print("=== ALL STREAMING AND PLUGGABLE TLS VERIFICATION PASSED ===");
    // CHECK: === ALL STREAMING AND PLUGGABLE TLS VERIFICATION PASSED ===
}
