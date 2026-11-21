// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Incremental streaming, chunked transfer encoding (RFC 9112 Section 7.1),
// and chunked upload/download progress pipeline.
namespace client;

import std;
import core;
import rfc.http;
import http.request;
import http.response;
import http.headers;
import http.headers.chunked;
import .internal;

// ---- RFC 9112 Chunked Transfer Framing -----------------------------------

// Encodes a single chunk frame: `<hex-size>\r\n<data>\r\n`.
fn encode_chunk<B>(data: const u8[:], out: B&) -> bool {
    guard data.len > 0 else { return true; }
    let chunk_len = data.len as! u64;
    var hex_buf: u8[..24] = [];
    chunk_len.format_u64_hex(hex_buf);
    let needed = core::add_sat_i64(data.len, core::add_sat_i64(hex_buf.len, 4));
    guard client_internal::has_chunk_buf_space(out, needed) else { return false; }
    return out.try_append(hex_buf[..]) && out.try_append("\r\n") &&
        out.try_append(data) && out.try_append("\r\n");
}

// Encodes the terminal 0-size chunk: `0\r\n\r\n` (or with trailers).
fn encode_chunk_end<B>(out: B&) -> bool {
    return out.try_append("0\r\n\r\n");
}

// Encodes trailer header: `<name>: <value>\r\n` (RFC 9112 Section 7.1.2).
fn encode_chunk_trailer<B>(name: const u8[:], val: const u8[:], out: B&) -> bool {
    guard http::is_valid_header_name(name) && http::is_valid_header_value(val) &&
        !rfc::is_disallowed_trailer_field(name) else {
        return false;
    }
    let needed = core::add_sat_i64(name.len, core::add_sat_i64(val.len, 4));
    guard client_internal::has_chunk_buf_space(out, needed) else { return false; }
    return out.try_append(name) && out.try_append(": ") &&
        out.try_append(val) && out.try_append("\r\n");
}

// Encodes an entire body buffer as RFC 9112 chunked transfer frames with optional trailers.
fn encode_chunked_payload<B>(
    body:       const u8[:],
    trailers:   const http::HeaderMap&,
    chunk_size: i64,
    out:        B&,
) -> bool {
    let total_needed = client_internal::measure_chunked_payload_wire_len(body, trailers, chunk_size);
    guard client_internal::has_chunk_buf_space(out, total_needed) else { return false; }
    let step = if chunk_size > 0 { chunk_size } else { 4096 };
    if body.len > 0 {
        var offset: i64 = 0;
        while offset < body.len {
            let end_off = min(offset + step, body.len);
            guard encode_chunk(body[offset..end_off], out) else { return false; }
            offset = end_off;
        }
    }

    if trailers.entries.len == 0 {
        return encode_chunk_end(out);
    }
    guard out.try_append("0\r\n") else { return false; }
    for &e in trailers.entries {
        let tname = http::entry_name(trailers, e);
        let tval = http::entry_value(trailers, e);
        if http::is_valid_header_name(tname) && http::is_valid_header_value(tval) &&
            !rfc::is_disallowed_trailer_field(tname) {
            guard encode_chunk_trailer(tname, tval, out) else { return false; }
        }
    }
    return out.try_append("\r\n");
}

// ---- Chunk Stream Writer (for Chunked Uploads) ---------------------------

struct ChunkWriter {
    trailers: http::HeaderMap = http::HeaderMap { .. },
    finished: bool            = false,
    buffer:   u8[>..]         = [],
}

fn write_chunk(writer: ChunkWriter&, data: const u8[:]) {
    guard !writer.finished && data.len > 0 else { return; }
    let _ = encode_chunk(data, writer.buffer);
}

fn add_trailer(writer: ChunkWriter&, name: const u8[:], val: const u8[:]) -> bool {
    guard !writer.finished && http::is_valid_header_name(name) && !rfc::is_disallowed_trailer_field(name) else {
        return false;
    }
    guard writer.trailers.entries.len < 16 else { return false; }
    return http::append_header(writer.trailers, name, val);
}

fn finish_chunk_writer(writer: ChunkWriter&) {
    guard !writer.finished else { return; }
    writer.finished = true;
    if writer.trailers.entries.len == 0 {
        let _ = encode_chunk_end(writer.buffer);
        return;
    }
    writer.buffer.append("0\r\n");
    for &e in writer.trailers.entries {
        let _ = encode_chunk_trailer(
            http::entry_name(writer.trailers, e),
            http::entry_value(writer.trailers, e),
            writer.buffer,
        );
    }
    writer.buffer.append("\r\n");
}

// ---- Incremental Chunked Stream Decoder (RFC 9112) -----------------------

enum ChunkedStreamState {
    ChunkSizeLine,
    ChunkData,
    ChunkDataCrlf,
    Trailers,
    Complete,
    Error,
}

struct ChunkedStreamDecoder {
    state:                 ChunkedStreamState       = ChunkedStreamState.ChunkSizeLine,
    expected_chunk_size:   u64                      = 0,
    chunk_bytes_remaining: u64                      = 0,
    crlf_step:             i32                      = 0,
    line_buf:              u8[..1024]               = [],
    trailers:              http::HeaderMap          = http::HeaderMap { .. },
    trailer_count:         i32                      = 0,
    total_trailer_bytes:   i64                      = 0,
    bytes_consumed_total:  u64                      = 0,
    error_code:            http::ChunkedDecodeError = http::ChunkedDecodeError.None,
}

fn is_complete(dec: const ChunkedStreamDecoder&) -> bool {
    return dec.state == ChunkedStreamState.Complete;
}

fn has_error(dec: const ChunkedStreamDecoder&) -> bool {
    return dec.state == ChunkedStreamState.Error;
}

// Feeds incoming wire slice into incremental decoder and emits decoded payload bytes into `out`.
// When `max_emit >= 0`, pauses consumption once `max_emit` bytes have been emitted.
// Returns `(bytes_consumed_from_input, ok)`.
//
// Example:
//   input = "5\r\nHello\r\n0\r\n\r\n"
//   returns: consumed = 15, ok = true (out = "Hello", dec.state = Complete)
fn feed_chunked_stream<B>(
    dec:      ChunkedStreamDecoder&,
    input:    const u8[:],
    out:      B&,
    max_emit: i64 = -1,
) -> i64, bool {
    guard dec.state != ChunkedStreamState.Error && dec.state != ChunkedStreamState.Complete else {
        return 0, dec.state == ChunkedStreamState.Complete;
    }

    var cursor: i64 = 0;
    let initial_out_len = out.len;
    var committed = false;
    defer if !committed { out.resize(initial_out_len); };

    while cursor < input.len && dec.state != ChunkedStreamState.Complete && dec.state != ChunkedStreamState.Error {
        if max_emit >= 0 && (out.len - initial_out_len) >= max_emit {
            break;
        }

        if dec.state == ChunkedStreamState.ChunkSizeLine {
            let b = input[cursor];
            cursor++;
            guard client_internal::step_chunk_size_line(dec, b) else { return cursor, false; }
        } else if dec.state == ChunkedStreamState.ChunkDataCrlf {
            let b = input[cursor];
            cursor++;
            guard client_internal::step_chunk_data_crlf(dec, b) else { return cursor, false; }
        } else if dec.state == ChunkedStreamState.Trailers {
            let b = input[cursor];
            cursor++;
            guard client_internal::step_chunk_trailer(dec, b) else { return cursor, false; }
        } else if dec.state == ChunkedStreamState.ChunkData {
            let avail = input.len - cursor;
            let needed = dec.chunk_bytes_remaining as i64;
            var to_take = min(avail, needed);
            if max_emit >= 0 {
                let emitted = out.len - initial_out_len;
                let cap_rem = max_emit - emitted;
                to_take = min(to_take, cap_rem);
            }

            out.append(input[cursor..(cursor + to_take)]);
            cursor += to_take;
            dec.bytes_consumed_total += to_take as! u64;
            dec.chunk_bytes_remaining -= to_take as! u64;

            if dec.chunk_bytes_remaining == 0 {
                dec.state = ChunkedStreamState.ChunkDataCrlf;
                dec.crlf_step = 0;
            }
        }
    }

    committed = true;
    return cursor, true;
}

// ---- Incremental Stream Reader & Progress Tracking -----------------------

enum StreamReadStatus {
    Data,
    Eof,
    Error,
}

struct StreamProgress {
    bytes_processed: u64  = 0,
    total_bytes:     i64  = -1,
    percent:         f64  = 0.0,
    is_finished:     bool = false,
}

struct StreamReader {
    cursor:         i64                  = 0,
    content_length: i64                  = -1,
    is_chunked:     bool                 = false,
    chunk_decoder:  ChunkedStreamDecoder = ChunkedStreamDecoder { .. },
    bytes_read:     u64                  = 0,
    finished:       bool                 = false,
    raw_data:       u8[>..]              = [],
}

// Parses a decimal Content-Length header value with 64-bit overflow validation (RFC 9110 Section 8.6).
//
// Example:
//   cl = "1024"
//   returns: 1024, ok = true
fn parse_content_length_value(cl: const u8[:]) -> i64, bool {
    let clean = cl.trim_lws();
    let val, ok = clean.parse_u64_dec();
    guard ok && val <= 9223372036854775807 else { return -1, false; }
    return val as! i64, true;
}

fn new_stream_reader(resp: const http::Response&) -> StreamReader {
    var reader = StreamReader { .. };
    let te = http::header(resp, "Transfer-Encoding");
    if header_has_token(te, "chunked") {
        reader.is_chunked = true;
    }

    let cl = http::header(resp, "Content-Length");
    if cl.len > 0 {
        let val, ok = parse_content_length_value(cl);
        reader.content_length = if ok { val } else { -1 };
    }
    let body_len = if !reader.is_chunked && reader.content_length >= 0 {
        min(resp.body.len, reader.content_length)
    } else {
        resp.body.len
    };
    reader.raw_data.append(resp.body[..body_len]);
    return reader;
}

// Reads the next chunk from the stream (up to max_bytes).
// Retains unconsumed chunk remainder across calls so small max_bytes reads
// do not truncate or discard chunk data.
// Returns (status, is_eof).
fn read_chunk<B>(reader: StreamReader&, max_bytes: i64, out: B&) -> StreamReadStatus, bool {
    guard !reader.finished else { return StreamReadStatus.Eof, true; }

    let remaining = reader.raw_data.len - reader.cursor;
    let dec_active = !is_complete(reader.chunk_decoder) && !has_error(reader.chunk_decoder);
    let has_chunk_work = reader.is_chunked && dec_active;
    guard remaining > 0 || has_chunk_work else {
        reader.finished = true;
        return StreamReadStatus.Eof, true;
    }

    out.clear();
    if reader.is_chunked {
        return client_internal::read_chunk_chunked(reader, max_bytes, out);
    }
    return client_internal::read_chunk_identity(reader, max_bytes, remaining, out);
}

// Reads all remaining data from the stream into `out`.
fn read_all<B>(reader: StreamReader&, out: B&) -> u64 {
    guard !reader.finished else { return 0; }
    let remaining = core::sub_sat_i64(reader.raw_data.len, reader.cursor);
    guard remaining > 0 || (reader.is_chunked && !is_complete(reader.chunk_decoder)) else {
        reader.finished = true;
        return 0;
    }

    if reader.is_chunked {
        let prev_len = out.len;
        var committed = false;
        defer if !committed { out.resize(prev_len); };
        let consumed, ok_dec = feed_chunked_stream(
            reader.chunk_decoder, reader.raw_data[reader.cursor..], out, -1,
        );
        reader.cursor = core::add_sat_i64(reader.cursor, consumed);
        reader.finished = true;
        // RFC 9112 Section 7.1: Chunked Transfer Coding - Reject incomplete or malformed chunked stream and roll back out.
        guard ok_dec && is_complete(reader.chunk_decoder) else {
            reader.chunk_decoder.state = ChunkedStreamState.Error;
            return 0;
        }
        committed = true;
        let emitted = core::sub_sat_i64(out.len, prev_len) as! u64;
        reader.bytes_read = core::add_sat_u64(reader.bytes_read, emitted);
        return emitted;
    }

    out.append(reader.raw_data[reader.cursor..]);
    reader.cursor = reader.raw_data.len;
    reader.bytes_read = core::add_sat_u64(reader.bytes_read, remaining as! u64);
    reader.finished = true;
    return remaining as! u64;
}

// Looks up a decoded chunk trailer by case-insensitive name.
fn trailer(reader: const StreamReader&, name: const u8[:]) -> const u8[:] {
    return http::find_header(reader.chunk_decoder.trailers, name);
}

// Copies decoded chunk trailers to a target Response object.
fn copy_trailers_to_response(reader: const StreamReader&, resp: http::Response&) {
    http::append_all_headers(reader.chunk_decoder.trailers, resp.trailers);
}

// Calculates current stream progress.
fn stream_progress(reader: const StreamReader&) -> StreamProgress {
    var p = StreamProgress {
        bytes_processed: reader.bytes_read,
        total_bytes:     reader.content_length,
        is_finished:     reader.finished,
        ..
    };
    if reader.content_length > 0 {
        p.percent = min(100.0, (reader.bytes_read as! f64 / reader.content_length) * 100.0);
    }
    return p;
}

// ---- Client Pull-Rate Flow-Control Backpressure Window ---------------------

// Tracks bounded ingress credit for streaming downloads so slow consumers pause reads
// or defer H2 WINDOW_UPDATE / QUIC MAX_STREAM_DATA replenishment without growing buffers.
struct ClientStreamWindow {
    window_size:    u64 = 65536,
    bytes_received: u64 = 0,
    bytes_consumed: u64 = 0,
    advertised_max: u64 = 65536,
    unacked_bytes:  u64 = 0,
    threshold_pct:  u32 = 50,
}

fn make_client_stream_window(window_size: u64 = 65536, threshold_pct: u32 = 50) -> ClientStreamWindow {
    let eff_win = max(window_size, 1);
    let eff_pct = clamp(threshold_pct as i64, 1, 100) as u32;
    return ClientStreamWindow {
        window_size:    eff_win,
        advertised_max: eff_win,
        threshold_pct:  eff_pct,
        ..
    };
}

// Records bytes arriving from the network without granting new peer send credit.
fn client_window_on_ingress(win: ClientStreamWindow&, received: u64) -> bool {
    guard received > 0 else { return true; }
    let next_rx = core::add_sat_u64(win.bytes_received, received);
    guard next_rx <= win.advertised_max else { return false; }
    win.bytes_received = next_rx;
    return true;
}

// Returns how many more bytes the peer may send before the client receive window closes.
fn client_window_can_receive(win: const ClientStreamWindow&) -> u64 {
    return core::sub_sat_u64(win.advertised_max, win.bytes_received);
}

// Records application bytes pulled from the stream and returns `(credit_delta, should_replenish)`.
fn client_window_on_consume(win: ClientStreamWindow&, consumed: u64) -> u64, bool {
    guard consumed > 0 else { return 0, false; }
    let unread = core::sub_sat_u64(win.bytes_received, win.bytes_consumed);
    let take = min(consumed, unread);
    guard take > 0 else { return 0, false; }
    win.bytes_consumed = core::add_sat_u64(win.bytes_consumed, take);
    win.unacked_bytes = core::add_sat_u64(win.unacked_bytes, take);
    let scaled, _ = core::div_rem_u64(core::mul_sat_u64(win.window_size, win.threshold_pct), 100);
    let thresh = max(scaled, 1);
    guard win.unacked_bytes >= thresh else { return 0, false; }
    let delta = win.unacked_bytes;
    win.advertised_max = core::add_sat_u64(win.advertised_max, delta);
    win.unacked_bytes = 0;
    return delta, true;
}
