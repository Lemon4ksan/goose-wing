// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for server cache, cork, edge_filter, profiler, sni, soa_timer, and stream_consumer.
namespace server_internal;

import std;
import core from "..";
import rfc.http;
import http.headers;
import http.headers.lexical;
import http.headers.chunked;
import http.response;
import net.tcp;
import tls.x509;
import .cache;
import .cork;
import .edge_filter;
import .h1_codec;
import .h1_codec_internal;
import .profiler;
import .sni;
import .soa_timer;
import .stream_consumer;

// Detaches `idx` from the intrusive doubly-linked LRU list in O(1).
fn detach_cache_lru(cache: server::HttpRouteCache&, idx: i32) {
    guard idx >= 0 && idx < cache.entries.len else { return; }
    let node .= cache.entries[idx as i64];
    let prev = node.prev_lru;
    let next = node.next_lru;
    if prev >= 0 {
        cache.entries[prev as i64].next_lru = next;
    } else if cache.lru_head == idx {
        cache.lru_head = next;
    }
    if next >= 0 {
        cache.entries[next as i64].prev_lru = prev;
    } else if cache.lru_tail == idx {
        cache.lru_tail = prev;
    }
    node.prev_lru = -1;
    node.next_lru = -1;
}

// Appends `idx` to the MRU tail (`lru_tail`) of the intrusive LRU list in O(1).
fn attach_cache_lru_tail(cache: server::HttpRouteCache&, idx: i32) {
    guard idx >= 0 && idx < cache.entries.len else { return; }
    let node .= cache.entries[idx as i64];
    node.prev_lru = cache.lru_tail;
    node.next_lru = -1;
    if cache.lru_tail >= 0 {
        cache.entries[cache.lru_tail as i64].next_lru = idx;
    } else {
        cache.lru_head = idx;
    }
    cache.lru_tail = idx;
}

// Promotes `idx` to the MRU tail in O(1) (`OrderedDict.move_to_end` equivalent).
fn touch_cache_lru(cache: server::HttpRouteCache&, idx: i32) {
    guard idx >= 0 && idx < cache.entries.len else { return; }
    if cache.lru_tail == idx {
        return;
    }
    detach_cache_lru(cache, idx);
    attach_cache_lru_tail(cache, idx);
}

inline fn route_entry_matches(
    e:          const server::CacheEntry&,
    handler_id: i32,
    url_key:    const u8[:],
) -> bool {
    guard e.is_valid && e.wire.len > 0 else { return false; }
    if handler_id >= 0 && e.handler_id >= 0 && e.handler_id != handler_id {
        return false;
    }
    if url_key.len > 0 && e.url_key.len > 0 && e.url_key[..] != url_key {
        return false;
    }
    return true;
}

inline fn sync_active_cache_entry(c: server::HttpRouteCache&, e: const server::CacheEntry&) {
    if !c.is_valid || c.handler_id != e.handler_id || c.created_ms != e.created_ms || c.url_key[..] != e.url_key[..] {
        let _ = c.wire.try_set(e.wire[..]);
        let _ = c.content_type.try_set(e.content_type[..]);
        let _ = c.url_key.try_set(e.url_key[..]);
        let _ = c.etag.try_set(e.etag[..]);
        c.handler_id = e.handler_id;
        c.created_ms = e.created_ms;
        c.is_valid = true;
    }
}

inline fn classify_cache_age(c: const server::HttpRouteCache&, created_ms: u64, now_ms: u64) -> server::CacheLookup {
    let age = core::sub_sat_u64(now_ms, created_ms);
    if age <= c.lower_expiry_ms {
        return server::CacheLookup.HitFresh;
    }
    if age <= c.upper_expiry_ms {
        return server::CacheLookup.HitStaleNeedsUpdate;
    }
    return server::CacheLookup.Miss;
}

inline fn populate_cache_entry(
    entry:        server::CacheEntry&,
    now_ms:       u64,
    wire_data:    const u8[:],
    handler_id:   i32,
    content_type: const u8[:],
    url_key:      const u8[:],
    etag:         const u8[:],
) {
    let _ = entry.wire.try_set(wire_data);
    let _ = entry.content_type.try_set(content_type);
    let _ = entry.url_key.try_set(url_key);
    let _ = entry.etag.try_set(etag);
    entry.handler_id = handler_id;
    entry.created_ms = now_ms;
    entry.is_valid = true;
}

// RFC 9112 Section 7.1: Chunked Transfer Coding - writes `<hex>\r\n<payload>\r\n` atomically into `sc`.
fn cork_write_chunk_frame(sc: server::ServerCork&, chunk_hdr: const u8[:], payload: const u8[:]) -> i32 {
    guard sc.sock_fd > 0 else { return -1; }
    let head_body_len = core::add_sat_i64(chunk_hdr.len, payload.len);
    let frame_len = core::add_sat_i64(head_body_len, 2);
    if frame_len <= sc.buffer.cork_available() {
        let _ = sc.buffer.cork_write(chunk_hdr);
        let _ = sc.buffer.cork_write(payload);
        let _ = sc.buffer.cork_write("\r\n");
        return frame_len as i32;
    }

    let flushed = server::server_cork_flush(sc);
    guard flushed >= 0 && sc.buffer.cork_is_empty() else { return -1; }

    if frame_len < core::CORK_BUFFER_CAP {
        let _ = sc.buffer.cork_write(chunk_hdr);
        let _ = sc.buffer.cork_write(payload);
        let _ = sc.buffer.cork_write("\r\n");
        return frame_len as i32;
    }

    let w1 = net::tcp_send2(sc.sock_fd, chunk_hdr, payload);
    guard w1 >= 0 else { return -1; }
    let w2 = net::tcp_send(sc.sock_fd, "\r\n");
    guard w2 >= 0 else { return -1; }
    return core::add_sat_i64(w1, w2) as i32;
}

fn write_cork_chunked_response_stream<Res>(sc: server::ServerCork&, res: const Res&, server_name: const u8[:]) -> i32 {
    // RFC 9112 Section 6.1: Transfer-Encoding - forbidden in 1xx/204/304 and HTTP/1.0 responses
    guard sc.sock_fd > 0
        && !rfc::is_empty_body_status(res.status_code)
        && res.protocol[..] != "HTTP/1.0" else {
        return -1;
    }
    if res.body.len <= 8192 {
        var wire_out: u8[..16384] = [];
        serialize_http1_chunked_response(res, server_name, 4096, wire_out);
        return server::server_cork_write(sc, wire_out[..]);
    }
    var empty_res = http::Response {
        status_code:   res.status_code,
        headers:       res.headers,
        trailers:      res.trailers,
        presence_mask: res.presence_mask,
        ..
    };
    var hdr_wire: u8[..8192] = [];
    serialize_http1_chunked_response(empty_res, server_name, 4096, hdr_wire);
    let term_idx = core::fast_find_crlfcrlf(hdr_wire[..]);
    guard term_idx >= 0 else { return -1; }
    let hdr_end = core::add_sat_i64(term_idx, 4);
    let hdr_sent = server::server_cork_write(sc, hdr_wire[..hdr_end]);
    guard hdr_sent >= 0 else { return -1; }
    var total_written: i32 = hdr_sent;
    var off:           i64 = 0;
    while off < res.body.len {
        let chunk_n = min(core::sub_sat_i64(res.body.len, off), 4096);
        let chunk_u64 = chunk_n as u64;
        var chunk_hdr: u8[..32] = [];
        chunk_u64.format_u64_hex(chunk_hdr);
        chunk_hdr.append("\r\n");
        let chunk_end = core::add_sat_i64(off, chunk_n);
        let w_chunk = cork_write_chunk_frame(sc, chunk_hdr[..], res.body[off..chunk_end]);
        guard w_chunk >= 0 else { return -1; }
        total_written = core::add_sat_i64(total_written, w_chunk) as i32;
        off = chunk_end;
    }
    let tail_slice = hdr_wire[hdr_end..];
    let w_tail = server::server_cork_write(sc, tail_slice);
    guard w_tail >= 0 else { return -1; }
    return core::add_sat_i64(total_written, w_tail) as i32;
}

fn has_non_empty_header_value(headers: const http::HeaderMap&, req_name: const u8[:]) -> bool {
    for &e in headers.entries {
        if http::entry_name(headers, e).eq_ascii_fold(req_name) && http::entry_value(headers, e).trim_lws().len > 0 {
            return true;
        }
    }
    return false;
}

extern fn wing_bench_begin_suite(suite_name: const u8[:], default_target_ns: i64) = "wing_bench_begin_suite";

extern fn wing_bench_should_run(bench_name: const u8[:]) -> i32 = "wing_bench_should_run";

extern fn wing_bench_begin_pass(
    bench_name: const u8[:], pass_idx: i32, target_ns: i64,
) -> i64 = "wing_bench_begin_pass";

extern fn wing_bench_end_pass(pass_idx: i32, cur_n: i64, target_ns: i64) -> i64 = "wing_bench_end_pass";

extern fn wing_bench_reset_timer() = "wing_bench_reset_timer";

extern fn wing_bench_stop_timer() = "wing_bench_stop_timer";

extern fn wing_bench_start_timer() = "wing_bench_start_timer";

extern fn wing_bench_set_bytes(n_bytes: i64) = "wing_bench_set_bytes";

extern fn wing_bench_mark_has_sub() = "wing_bench_mark_has_sub";

extern fn wing_bench_consume_has_sub() -> i32 = "wing_bench_consume_has_sub";

extern fn wing_bench_report_metric(val: f64, unit: const u8[:]) = "wing_bench_report_metric";

extern fn wing_bench_commit(bench_name: const u8[:], final_n: i64, bytes_per_op: i64) = "wing_bench_commit";

extern fn wing_bench_print_report() = "wing_bench_print_report";

struct BenchPostPassSchedule {
    steady_state_n: i64 = 1,
    watermark_n:    i64 = 1,
}

inline fn execute_bench_passes<F: fn(server::Bench&)>(b: server::Bench&) {
    var cur_n: i64 = 1;
    while true {
        let _ = wing_bench_begin_pass(b.name[..], 0, b.target_ns);
        b.n = cur_n;
        b.pass_kind = 0;
        F(b);
        let res_n = wing_bench_end_pass(0, cur_n, b.target_ns);
        if res_n > 0 {
            cur_n = res_n;
            break;
        }
        cur_n = core::sub_sat_i64(0, res_n);
    }

    let schedule = BenchPostPassSchedule { steady_state_n: cur_n, watermark_n: 1 };
    const for <N, A> in fields<BenchPostPassSchedule> {
        let pass_idx: i32 = if N == "steady_state_n" { 1 } else { 2 };
        let pass_n = schedule.A;
        let _ = wing_bench_begin_pass(b.name[..], pass_idx, b.target_ns);
        b.n = pass_n;
        b.pass_kind = pass_idx;
        F(b);
        let _ = wing_bench_end_pass(pass_idx, pass_n, b.target_ns);
    }
    wing_bench_commit(b.name[..], cur_n, b.bytes_per_op);
}

inline fn is_valid_sni_pattern(p_norm: const u8[:]) -> bool {
    guard p_norm.len > 0 && p_norm.len <= server::MAX_SNI_HOSTNAME_LEN && p_norm != "*" else { return false; }
    guard !tls::x509_is_ip_literal(p_norm) && !p_norm.contains_byte(':') else { return false; }
    if p_norm[0] == '*' {
        guard p_norm.len >= 3 && p_norm[1] == '.' && p_norm[2..].contains_byte('.') else {
            return false;
        }
    }
    return tls::validate_san_dns_name(p_norm);
}

inline fn is_valid_sni_hostname(h_norm: const u8[:]) -> bool {
    guard h_norm.len > 0 && !h_norm.contains_byte('*') else { return false; }
    guard !tls::x509_is_ip_literal(h_norm) && !h_norm.contains_byte(':') else { return false; }
    return tls::validate_san_dns_name(h_norm);
}

// Advances high-water mark for allocated connection slots.
inline fn advance_high_water_mark(current_limit: i64, slot: i64) -> i64 {
    let next_slot = core::add_sat_i64(slot, 1);
    return max(next_slot, current_limit);
}

// Records an expired connection slot into output array and returns incremented count.
inline fn record_expired_conn(dst: i64[:], current_count: i64, slot: i64) -> i64 {
    dst[current_count] = slot;
    return core::add_sat_i64(current_count, 1);
}

fn push_inactive_soa_slot(table: server::SoAConnTable&) {
    table.fds.push(server::SOA_INVALID_FD);
    table.timeout_ticks.push(server::SOA_INVALID_TICK);
    table.leftover_lens.push(0);
    table.leftover_offs.push(-1);
    table.tls_ct_lens.push(0);
    table.tls_ct_offs.push(-1);
    table.conn_slots.push(-1);
    table.is_h2.push(false);
    table.h2_slot_map.push(-1);
    table.has_tls.push(false);
    table.tls_slots.push(0xFFFF);
    table.has_peer_ip.push(false);
    table.peer_ip_hashes.push(0);
    table.peer_ips.push([]);
}

// Resets all parallel SoA columns for `slot`.
inline fn reset_soa_slot_fields(table: server::SoAConnTable&, slot: i64, fd: i64, timeout_tick: u8) {
    table.fds[slot] = fd;
    table.timeout_ticks[slot] = timeout_tick;
    table.leftover_lens[slot] = 0;
    table.leftover_offs[slot] = -1;
    table.tls_ct_lens[slot] = 0;
    table.tls_ct_offs[slot] = -1;
    table.conn_slots[slot] = -1;
    table.is_h2[slot] = false;
    table.h2_slot_map[slot] = -1;
    table.has_tls[slot] = false;
    table.tls_slots[slot] = 0xFFFF;
    table.has_peer_ip[slot] = false;
    table.peer_ip_hashes[slot] = 0;
    table.peer_ips[slot].clear();
}

// Returns whether `slot` is within the materialized bounds of the SoA connection table.
inline fn is_valid_slot(table: const server::SoAConnTable&, slot: i64) -> bool {
    return slot >= 0 && slot < table.fds.len;
}

// Returns whether `slot` is in bounds and currently holds an active file descriptor.
inline fn is_active_slot(table: const server::SoAConnTable&, slot: i64) -> bool {
    return is_valid_slot(table, slot) && table.fds[slot] > 0;
}

inline fn trim_soa_high_water_mark(table: server::SoAConnTable&) {
    while table.count > 0 && table.count <= table.fds.len {
        let last_idx = core::sub_sat_i64(table.count, 1);
        guard is_valid_slot(table, last_idx) && table.fds[last_idx] < 0 else {
            break;
        }
        table.count = last_idx;
    }
}

inline fn peek_terminal_zero_chunk(incoming: const u8[:], cursor: i64&) -> bool {
    guard cursor < incoming.len else { return false; }
    var peek_cur = cursor;
    let next_sz, next_err = http::read_chunk_size_line(incoming, peek_cur);
    guard next_err == http::ChunkedDecodeError.None && next_sz == 0 else { return false; }
    let tr_err = http::parse_chunked_trailers(incoming, peek_cur);
    guard tr_err == http::ChunkedDecodeError.None else { return false; }
    cursor = peek_cur;
    return true;
}

inline fn feed_fixed_length_http_stream(
    consumer: server::HttpStreamConsumer&,
    incoming: const u8[:],
) -> i64, bool, bool {
    let remaining = core::sub_sat_i64(consumer.content_length, consumer.bytes_received);
    guard remaining > 0 else {
        consumer.is_finished = true;
        return 0, true, true;
    }

    let chunk_len = min(incoming.len, remaining);
    consumer.bytes_received = core::add_sat_i64(consumer.bytes_received, chunk_len);
    let is_last = consumer.bytes_received >= consumer.content_length;
    if is_last {
        consumer.is_finished = true;
    }
    return chunk_len, is_last, true;
}

// Steps one frame of a chunked HTTP stream at `cursor`, returning `(data_slice, has_data, is_last, ok)`.
// On partial input (`UnexpectedEof`), returns `has_data = false, is_last = false, ok = true` and leaves `cursor`
// at the start of the incomplete chunk.
//
// Example:
//   incoming = "5\r\nhello\r\n0\r\n\r\n", cursor = 0
//   returns: data_slice = "hello", has_data = true, is_last = true, ok = true, cursor = 15
fn step_chunked_http_stream_frame(
    consumer: server::HttpStreamConsumer&,
    incoming: const u8[:],
    cursor:   i64&,
) -> const u8[:], bool, bool, bool {
    let chunk_start = cursor;
    let chunk_size, line_err = http::read_chunk_size_line(incoming, cursor);
    if line_err == http::ChunkedDecodeError.UnexpectedEof {
        cursor = chunk_start;
        return "", false, false, true;
    }
    guard line_err == http::ChunkedDecodeError.None && chunk_size <= (server::MAX_SERVER_BODY_LIMIT as u64) else {
        cursor = chunk_start;
        return "", false, false, false;
    }
    if chunk_size == 0 {
        let tr_err = http::parse_chunked_trailers(incoming, cursor);
        if tr_err == http::ChunkedDecodeError.UnexpectedEof {
            cursor = chunk_start;
            return "", false, false, true;
        }
        guard tr_err == http::ChunkedDecodeError.None else {
            cursor = chunk_start;
            return "", false, false, false;
        }
        consumer.is_finished = true;
        return "", false, true, true;
    }
    let csize = chunk_size as i64;
    let data_end = core::add_sat_i64(cursor, csize);
    let frame_end = core::add_sat_i64(data_end, 2);
    if frame_end > incoming.len {
        cursor = chunk_start;
        return "", false, false, true;
    }
    guard incoming[data_end] == '\r' && incoming[core::add_sat_i64(data_end, 1)] == '\n' else {
        cursor = chunk_start;
        return "", false, false, false;
    }
    let next_received = core::add_sat_i64(consumer.bytes_received, csize);
    guard next_received <= server::MAX_SERVER_BODY_LIMIT else {
        cursor = chunk_start;
        return "", false, false, false;
    }
    let data_slice = incoming[cursor..data_end];
    cursor = frame_end;
    consumer.bytes_received = next_received;

    let finished_now = peek_terminal_zero_chunk(incoming, cursor);
    if finished_now {
        consumer.is_finished = true;
    }
    return data_slice, true, finished_now, true;
}
