// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for server cache, cork, edge_filter, profiler, sni, soa_timer, and stream_consumer.
namespace server_internal;

import std;
import core;
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

// Returns whether `slot` is within the materialized bounds of the SoA connection table.
inline fn is_valid_slot(table: const server::SoAConnTable&, slot: i64) -> bool {
    return slot >= 0 && slot < table.fds.len;
}

// Returns whether `slot` is in bounds and currently holds an active file descriptor.
inline fn is_active_slot(table: const server::SoAConnTable&, slot: i64) -> bool {
    return is_valid_slot(table, slot) && table.fds[slot] > 0;
}

inline fn soa_free_mark_free(table: server::SoAConnTable&, slot: i64) {
    guard slot >= 0 else { return; }
    let l0_idx = slot >> 6;
    let l0_bit = (slot & 63) as u32;
    while table.free_l0.len <= l0_idx {
        table.free_l0.push(0);
    }
    table.free_l0[l0_idx] |= (1 as u64) << l0_bit;
    let l1_idx = l0_idx >> 6;
    let l1_bit = (l0_idx & 63) as u32;
    while table.free_l1.len <= l1_idx {
        table.free_l1.push(0);
    }
    table.free_l1[l1_idx] |= (1 as u64) << l1_bit;
}

inline fn soa_free_mark_used(table: server::SoAConnTable&, slot: i64) {
    guard slot >= 0 else { return; }
    let l0_idx = slot >> 6;
    guard l0_idx < table.free_l0.len else { return; }
    let l0_bit = (slot & 63) as u32;
    table.free_l0[l0_idx] &= ~((1 as u64) << l0_bit);
    if table.free_l0[l0_idx] == 0 {
        let l1_idx = l0_idx >> 6;
        let l1_bit = (l0_idx & 63) as u32;
        if l1_idx < table.free_l1.len {
            table.free_l1[l1_idx] &= ~((1 as u64) << l1_bit);
        }
    }
}

inline fn soa_free_find_lowest(table: const server::SoAConnTable&, limit: i64) -> i64 {
    for l1_i in table.free_l1.len {
        let w1 = table.free_l1[l1_i];
        guard w1 != 0 else { continue; }
        let l0_idx = core::add_sat_i64(l1_i << 6, ctz(w1));
        guard l0_idx < table.free_l0.len else { return -1; }
        let w0 = table.free_l0[l0_idx];
        guard w0 != 0 else { return -1; }
        let slot = core::add_sat_i64(l0_idx << 6, ctz(w0));
        if slot < limit {
            return slot;
        }
        return -1;
    }
    return -1;
}

inline fn soa_wheel_unlink(table: server::SoAConnTable&, slot: i64) {
    guard is_valid_slot(table, slot) else { return; }
    let old_b = table.timeout_ticks[slot] as i64;
    table.timeout_ticks[slot] = server::SOA_INVALID_TICK;
    guard old_b >= 0 && old_b < 240 else { return; }
    let prev_s = table.timer_links[slot].prev;
    let next_s = table.timer_links[slot].next;
    if prev_s >= 0 {
        table.timer_links[prev_s].next = next_s;
    } else if table.wheel_heads[old_b] == (slot as i32) {
        table.wheel_heads[old_b] = next_s;
    }
    if next_s >= 0 {
        table.timer_links[next_s].prev = prev_s;
    }
    table.timer_links[slot].prev = -1;
    table.timer_links[slot].next = -1;
    if table.wheel_heads[old_b] < 0 {
        let w = old_b >> 6;
        let bit = (old_b & 63) as u32;
        table.wheel_mask[w] &= ~((1 as u64) << bit);
    }
}

inline fn soa_wheel_link(table: server::SoAConnTable&, slot: i64, new_tick: u8) {
    guard is_valid_slot(table, slot) else { return; }
    table.timeout_ticks[slot] = new_tick;
    let b = new_tick as i64;
    guard b >= 0 && b < 240 else { return; }
    let old_head = table.wheel_heads[b];
    table.timer_links[slot].prev = -1;
    table.timer_links[slot].next = old_head;
    if old_head >= 0 {
        table.timer_links[old_head].prev = slot as i32;
    }
    table.wheel_heads[b] = slot as i32;
    let w = b >> 6;
    let bit = (b & 63) as u32;
    table.wheel_mask[w] |= (1 as u64) << bit;
}

inline fn soa_wheel_relink(table: server::SoAConnTable&, slot: i64, new_tick: u8) {
    guard is_valid_slot(table, slot) else { return; }
    guard table.timeout_ticks[slot] != new_tick else { return; }
    soa_wheel_unlink(table, slot);
    soa_wheel_link(table, slot, new_tick);
}

inline fn set_wheel_mask_range(mask: u64[4]&, lo: i64, hi: i64) {
    guard lo >= 0 && hi >= lo && hi < 240 else { return; }
    let lo_w = lo >> 6;
    let hi_w = hi >> 6;
    for w in lo_w..core::add_sat_i64(hi_w, 1) {
        let start_bit = if w == lo_w { (lo & 63) as u32 } else { 0 };
        let end_bit = if w == hi_w { (hi & 63) as u32 } else { 63 };
        let lo_m = ~(((1 as u64) << start_bit) - 1);
        let hi_m = if end_bit == 63 { 0xFFFFFFFFFFFFFFFF } else { ((1 as u64) << (end_bit + 1)) - 1 };
        mask[w] |= lo_m & hi_m;
    }
}

inline fn build_elapsed_wheel_mask(wheel: const core::TickTimerWheel&) -> u64[4] {
    if wheel.last_elapsed >= core::TICK_TIMER_MODULO {
        return [0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x0000FFFFFFFFFFFF];
    }
    var mask: u64[4] = [0; 4];
    let mod_n = core::TICK_TIMER_MODULO as i64;
    let prev = wheel.prev_tick as i64;
    let el = wheel.last_elapsed as i64;
    let start = core::rem_euclid_i64(core::add_sat_i64(prev, 1), mod_n);
    let end = core::rem_euclid_i64(core::add_sat_i64(prev, el), mod_n);
    if start <= end {
        set_wheel_mask_range(mask, start, end);
    } else {
        set_wheel_mask_range(mask, start, 239);
        set_wheel_mask_range(mask, 0, end);
    }
    return mask;
}

inline fn collect_wheel_bucket_expired(
    table:       const server::SoAConnTable&,
    bucket:      i64,
    out_expired: i64[:],
    expired_n:   i64,
) -> i64 {
    guard bucket >= 0 && bucket < 240 else { return expired_n; }
    var count = expired_n;
    var cur = table.wheel_heads[bucket];
    while cur >= 0 && count < out_expired.len {
        let next_s = table.timer_links[cur].next;
        if is_active_slot(table, cur) && table.timeout_ticks[cur] == (bucket as u8) {
            count = record_expired_conn(out_expired, count, cur);
        }
        cur = next_s;
    }
    return count;
}

fn push_inactive_soa_slot(table: server::SoAConnTable&) {
    let slot = table.fds.len;
    table.fds.push(server::SOA_INVALID_FD);
    table.generations.push(1);
    table.timeout_ticks.push(server::SOA_INVALID_TICK);
    table.half_close_deadlines_ms.push(0);
    table.tx_stall_deadlines_ms.push(0);
    table.leftover_lens.push(0);
    table.leftover_offs.push(-1);
    table.tls_ct_lens.push(0);
    table.tls_ct_offs.push(-1);
    table.conn_slots.push(-1);
    table.is_h2.push(false);
    table.h2_slot_map.push(-1);
    table.has_tls.push(false);
    table.tls_slots.push(0xFFFF);
    table.tls_hs_map.push(-1);
    table.tls_snis.push([]);
    table.has_peer_ip.push(false);
    table.peer_ip_hashes.push(0);
    table.peer_ips.push([]);
    table.timer_links.push(server::SoATimerLink { .. });
    soa_free_mark_free(table, slot);
}

// Resets all parallel SoA columns for `slot`.
inline fn reset_soa_slot_fields(table: server::SoAConnTable&, slot: i64, fd: i64, timeout_tick: u8) {
    soa_wheel_unlink(table, slot);
    let next_gen = core::add_sat_u64(table.generations[slot], 1);
    table.generations[slot] = if next_gen > 0xFFFFFFFF || next_gen == 0 { 1 } else { next_gen as u32 };
    table.fds[slot] = fd;
    if fd > 0 {
        soa_free_mark_used(table, slot);
        soa_wheel_link(table, slot, timeout_tick);
    } else {
        soa_free_mark_free(table, slot);
        table.timeout_ticks[slot] = server::SOA_INVALID_TICK;
    }
    table.half_close_deadlines_ms[slot] = 0;
    table.tx_stall_deadlines_ms[slot] = 0;
    table.leftover_lens[slot] = 0;
    table.leftover_offs[slot] = -1;
    table.tls_ct_lens[slot] = 0;
    table.tls_ct_offs[slot] = -1;
    table.conn_slots[slot] = -1;
    table.is_h2[slot] = false;
    table.h2_slot_map[slot] = -1;
    table.has_tls[slot] = false;
    table.tls_slots[slot] = 0xFFFF;
    table.tls_hs_map[slot] = -1;
    table.tls_snis[slot].clear();
    table.has_peer_ip[slot] = false;
    table.peer_ip_hashes[slot] = 0;
    table.peer_ips[slot].clear();
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
