// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Incremental streaming, chunked transfer encoding (RFC 9112 Section 7.1),
// and chunked upload/download progress pipeline.
namespace wing;

import std;
import core from "..";
import client.profile;
import client.request;
import client.response;
import http.digest_fields;
import http.headers;
import http.headers.chunked_fsm;

// ---- RFC 9112 Chunked Transfer Framing -----------------------------------

inline fn has_chunk_buf_space<B>(out: const B&, needed: i64) -> bool {
    return needed >= 0 && core::sub_sat_i64(out.cap, out.len) >= needed;
}

inline fn has_chunk_buf_space(_out: const u8[>..]&, needed: i64) -> bool {
    return needed >= 0;
}

inline fn count_chunk_hex_digits(len_val: i64) -> i64 {
    var v = len_val;
    var digits: i64 = 0;
    while v > 0 {
        v = v >> 4;
        digits = core::add_sat_i64(digits, 1);
    }
    return max(digits, 1);
}

inline fn measure_chunked_payload_wire_len(
    body:       const u8[:],
    trailers:   const HeaderMap&,
    chunk_size: i64,
) -> i64 {
    let step = if chunk_size > 0 { chunk_size } else { 4096 };
    var total: i64 = 0;
    if body.len > 0 {
        var offset: i64 = 0;
        while offset < body.len {
            let end_off = min(core::add_sat_i64(offset, step), body.len);
            let c_len = core::sub_sat_i64(end_off, offset);
            let hex_digits = count_chunk_hex_digits(c_len);
            let frame_len = core::add_sat_i64(hex_digits, core::add_sat_i64(c_len, 4));
            total = core::add_sat_i64(total, frame_len);
            offset = end_off;
        }
    }
    total = core::add_sat_i64(total, 5);
    for &e in trailers.entries {
        let tname = entry_name(trailers, e);
        let tval = entry_value(trailers, e);
        if is_valid_header_name(tname) && is_valid_header_value(tval) && !rfc::is_disallowed_trailer_field(tname) {
            let tr_len = core::add_sat_i64(tname.len, core::add_sat_i64(tval.len, 4));
            total = core::add_sat_i64(total, tr_len);
        }
    }
    return total;
}

// Encodes a single chunk frame: `<hex-size>\r\n<data>\r\n`
fn encode_chunk<B>(data: const u8[:], out: B&) -> bool {
    guard data.len > 0 else { return true; }
    let chunk_len = data.len as! u64;
    var hex_buf: u8[..24] = [];
    chunk_len.format_u64_hex(hex_buf);
    let needed = core::add_sat_i64(data.len, core::add_sat_i64(hex_buf.len, 4));
    guard has_chunk_buf_space(out, needed) else { return false; }
    return out.try_append(hex_buf[..]) && out.try_append("\r\n") &&
        out.try_append(data) && out.try_append("\r\n");
}

// Encodes the terminal 0-size chunk: `0\r\n\r\n` (or with trailers)
fn encode_chunk_end<B>(out: B&) -> bool {
    return out.try_append("0\r\n\r\n");
}

// Encodes trailer header: `<name>: <value>\r\n` (RFC 9112 §7.1.2)
fn encode_chunk_trailer<B>(name: const u8[:], val: const u8[:], out: B&) -> bool {
    guard is_valid_header_name(name) && is_valid_header_value(val) && !rfc::is_disallowed_trailer_field(name) else {
        return false;
    }
    let needed = core::add_sat_i64(name.len, core::add_sat_i64(val.len, 4));
    guard has_chunk_buf_space(out, needed) else { return false; }
    return out.try_append(name) && out.try_append(": ") &&
        out.try_append(val) && out.try_append("\r\n");
}

// Encodes an entire body buffer as RFC 9112 chunked transfer frames with optional trailers.
fn encode_chunked_payload<B>(
    body:       const u8[:],
    trailers:   const HeaderMap&,
    chunk_size: i64,
    out:        B&,
) -> bool {
    let total_needed = measure_chunked_payload_wire_len(body, trailers, chunk_size);
    guard has_chunk_buf_space(out, total_needed) else { return false; }
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
        let tname = entry_name(trailers, e);
        let tval = entry_value(trailers, e);
        if is_valid_header_name(tname) && is_valid_header_value(tval) && !rfc::is_disallowed_trailer_field(tname) {
            guard encode_chunk_trailer(tname, tval, out) else { return false; }
        }
    }
    return out.try_append("\r\n");
}

// ---- Chunk Stream Writer (for Chunked Uploads) ---------------------------

struct ChunkWriter {
    trailers: HeaderMap = HeaderMap { .. },
    finished: bool      = false,
    buffer:   u8[>..]   = [],
}

fn write_chunk(writer: ChunkWriter&, data: const u8[:]) {
    guard !writer.finished && data.len > 0 else { return; }
    encode_chunk(data, writer.buffer);
}

fn add_trailer(writer: ChunkWriter&, name: const u8[:], val: const u8[:]) -> bool {
    guard !writer.finished && is_valid_header_name(name) && !rfc::is_disallowed_trailer_field(name) else {
        return false;
    }
    guard writer.trailers.entries.len < 16 else { return false; }
    return append_header(writer.trailers, name, val);
}

fn finish_chunk_writer(writer: ChunkWriter&) {
    guard !writer.finished else { return; }
    writer.finished = true;
    if writer.trailers.entries.len == 0 {
        let _ = encode_chunk_end(writer.buffer);
    } else {
        writer.buffer.push('0');
        writer.buffer.push('\r');
        writer.buffer.push('\n');
        for i in writer.trailers.entries.len {
            let e = writer.trailers.entries[i];
            var name_buf: u8[..256]  = [];
            var val_buf:  u8[..8192] = [];
            guard name_buf.try_set(entry_name(writer.trailers, e)) &&
                val_buf.try_set(entry_value(writer.trailers, e)) else {
                continue;
            }
            let _ = encode_chunk_trailer(name_buf[..], val_buf[..], writer.buffer);
        }
        writer.buffer.push('\r');
        writer.buffer.push('\n');
    }
}

// ---- 2b. Incremental Chunked Stream Decoder (RFC 9112) -----------------------

enum ChunkedStreamState {
    ChunkSizeLine,
    ChunkData,
    ChunkDataCrlf,
    Trailers,
    Complete,
    Error,
}

struct ChunkedStreamDecoder {
    state:                 ChunkedStreamState = ChunkedStreamState.ChunkSizeLine,
    expected_chunk_size:   u64                = 0,
    chunk_bytes_remaining: u64                = 0,
    crlf_step:             i32                = 0,
    line_buf:              u8[..1024]         = [],
    trailers:              HeaderMap          = HeaderMap { .. },
    trailer_count:         i32                = 0,
    total_trailer_bytes:   i64                = 0,
    bytes_consumed_total:  u64                = 0,
    error_code:            ChunkedDecodeError = ChunkedDecodeError.None,
}

fn is_complete(dec: const ChunkedStreamDecoder&) -> bool {
    return dec.state == ChunkedStreamState.Complete;
}

fn has_error(dec: const ChunkedStreamDecoder&) -> bool {
    return dec.state == ChunkedStreamState.Error;
}

fn append_trailer_item(trailers: HeaderMap&, name: const u8[:], val: const u8[:]) -> bool {
    guard trailers.entries.len < 16 else { return false; }
    return append_header(trailers, name, val);
}

fn step_chunk_size_line(dec: ChunkedStreamDecoder&, b: u8) -> bool {
    dec.bytes_consumed_total++;
    if b == '\n' {
        guard dec.line_buf.len > 0 && dec.line_buf[dec.line_buf.len - 1] == '\r' else {
            dec.state = ChunkedStreamState.Error;
            dec.error_code = ChunkedDecodeError.BareLfInChunkSize;
            return false;
        }
        let size_line = dec.line_buf[..^1];
        var csize: u64 = 0;
        let parse_err = parse_chunk_size_hex(size_line, csize);
        guard parse_err == ChunkedDecodeError.None else {
            dec.state = ChunkedStreamState.Error;
            dec.error_code = parse_err;
            return false;
        }
        dec.line_buf.clear();
        dec.expected_chunk_size = csize;

        if csize == 0 {
            dec.state = ChunkedStreamState.Trailers;
        } else {
            dec.chunk_bytes_remaining = csize;
            dec.state = ChunkedStreamState.ChunkData;
        }
        return true;
    }
    guard dec.line_buf.try_push(b) else {
        dec.state = ChunkedStreamState.Error;
        dec.error_code = ChunkedDecodeError.InvalidChunkExtension;
        return false;
    }
    return true;
}

fn step_chunk_data_crlf(dec: ChunkedStreamDecoder&, b: u8) -> bool {
    dec.bytes_consumed_total++;
    if dec.crlf_step == 0 {
        if b == '\r' {
            dec.crlf_step = 1;
            return true;
        }
        dec.state = ChunkedStreamState.Error;
        dec.error_code = if b == '\n' {
            ChunkedDecodeError.BareLfInChunkData
        } else {
            ChunkedDecodeError.MalformedChunkEnding
        };
        return false;
    }
    if b == '\n' {
        dec.state = ChunkedStreamState.ChunkSizeLine;
        dec.crlf_step = 0;
        return true;
    }
    dec.state = ChunkedStreamState.Error;
    dec.error_code = ChunkedDecodeError.MalformedChunkEnding;
    return false;
}

fn process_trailer_line(dec: ChunkedStreamDecoder&) -> bool {
    guard dec.line_buf.len > 0 && dec.line_buf[dec.line_buf.len - 1] == '\r' else {
        dec.state = ChunkedStreamState.Error;
        dec.error_code = ChunkedDecodeError.BareLfInTrailer;
        return false;
    }
    let tr_line = dec.line_buf[..^1];

    if tr_line.len == 0 {
        dec.state = ChunkedStreamState.Complete;
        dec.line_buf.clear();
        return true;
    }

    let next_count = dec.trailer_count + 1;
    let next_bytes = core::add_sat_i64(dec.total_trailer_bytes, tr_line.len);
    let col_idx = tr_line.index_of_byte(':');
    guard next_count <= 16 && next_bytes <= 4096 && col_idx > 0 else {
        dec.state = ChunkedStreamState.Error;
        dec.error_code = ChunkedDecodeError.DisallowedTrailer;
        return false;
    }

    let hname = tr_line[..col_idx];
    let hval = tr_line[(col_idx + 1)..].trim_lws();
    if !is_valid_header_name(hname) || !is_valid_header_value(hval) || rfc::is_disallowed_trailer_field(hname) {
        dec.state = ChunkedStreamState.Error;
        dec.error_code = ChunkedDecodeError.DisallowedTrailer;
        return false;
    }

    guard append_trailer_item(dec.trailers, hname, hval) else {
        dec.state = ChunkedStreamState.Error;
        dec.error_code = ChunkedDecodeError.DisallowedTrailer;
        return false;
    }
    dec.trailer_count = next_count;
    dec.total_trailer_bytes = next_bytes;
    dec.line_buf.clear();
    return true;
}

fn step_chunk_trailer(dec: ChunkedStreamDecoder&, b: u8) -> bool {
    dec.bytes_consumed_total++;
    if b == '\n' {
        return process_trailer_line(dec);
    }
    guard dec.line_buf.try_push(b) else {
        dec.state = ChunkedStreamState.Error;
        dec.error_code = ChunkedDecodeError.DisallowedTrailer;
        return false;
    }
    return true;
}

// Feeds incoming wire slice into incremental decoder.
// Emits decoded chunk body payload bytes directly into out_body.
// When max_emit >= 0, pauses consumption once max_emit bytes have been emitted.
// Returns (ok, bytes_consumed_from_input).
fn feed_chunked_stream<B>(
    dec:      ChunkedStreamDecoder&,
    input:    const u8[:],
    out_body: B&,
    max_emit: i64 = -1,
) -> bool, i64 {
    guard dec.state != ChunkedStreamState.Error && dec.state != ChunkedStreamState.Complete else {
        return dec.state == ChunkedStreamState.Complete, 0;
    }

    var cursor: i64 = 0;
    let initial_out_len = out_body.len;

    while cursor < input.len && dec.state != ChunkedStreamState.Complete && dec.state != ChunkedStreamState.Error {
        if max_emit >= 0 && (out_body.len - initial_out_len) >= max_emit {
            break;
        }

        if dec.state == ChunkedStreamState.ChunkSizeLine {
            let b = input[cursor];
            cursor++;
            guard step_chunk_size_line(dec, b) else { return false, cursor; }
        } else if dec.state == ChunkedStreamState.ChunkData {
            let avail = input.len - cursor;
            let needed = dec.chunk_bytes_remaining as i64;
            var to_take = min(avail, needed);
            if max_emit >= 0 {
                let emitted = out_body.len - initial_out_len;
                let cap_rem = max_emit - emitted;
                to_take = min(to_take, cap_rem);
            }

            out_body.append(input[cursor..(cursor + to_take)]);
            cursor += to_take;
            dec.bytes_consumed_total += to_take as! u64;
            dec.chunk_bytes_remaining -= to_take as! u64;

            if dec.chunk_bytes_remaining == 0 {
                dec.state = ChunkedStreamState.ChunkDataCrlf;
                dec.crlf_step = 0;
            }
        } else if dec.state == ChunkedStreamState.ChunkDataCrlf {
            let b = input[cursor];
            cursor++;
            guard step_chunk_data_crlf(dec, b) else { return false, cursor; }
        } else if dec.state == ChunkedStreamState.Trailers {
            let b = input[cursor];
            cursor++;
            guard step_chunk_trailer(dec, b) else { return false, cursor; }
        }
    }

    return true, cursor;
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

// Parses a decimal Content-Length header value with 64-bit overflow validation (RFC 9110 §8.6).
//
// Example:
//   cl = "1024"
//   returns: 1024, ok = true
fn parse_content_length_value(cl: const u8[:]) -> i64, bool {
    let clean = cl.trim_lws();
    guard clean.len > 0 else { return -1, false; }
    var num: i64 = 0;
    for b in clean {
        guard b >= '0' && b <= '9' else { return -1, false; }
        let d = (b - '0') as i64;
        guard num <= (9223372036854775807 / 10) else { return -1, false; }
        guard num < (9223372036854775807 / 10) || d <= 7 else { return -1, false; }
        num = num * 10 + d;
    }
    return num, true;
}

fn new_stream_reader(resp: const Response&) -> StreamReader {
    var reader = StreamReader { .. };
    let te = header(resp, "Transfer-Encoding");
    if header_has_token(te, "chunked") {
        reader.is_chunked = true;
    }

    let cl = header(resp, "Content-Length");
    if cl.len > 0 {
        let val, ok = parse_content_length_value(cl);
        if ok {
            reader.content_length = val;
        } else {
            reader.content_length = -1;
        }
    }
    let body_len = if !reader.is_chunked && reader.content_length >= 0 {
        min(resp.body.len, reader.content_length)
    } else {
        resp.body.len
    };
    reader.raw_data.append(resp.body[..body_len]);
    return reader;
}

fn read_chunk_chunked<B>(reader: StreamReader&, max_bytes: i64, out: B&) -> StreamReadStatus, bool {
    guard !has_error(reader.chunk_decoder) else {
        reader.finished = true;
        return StreamReadStatus.Error, false;
    }

    let prev_len = out.len;
    let limit = if max_bytes > 0 { max_bytes } else { -1 };
    let ok_dec, consumed = feed_chunked_stream(
        reader.chunk_decoder,
        reader.raw_data[reader.cursor..],
        out,
        limit,
    );
    reader.cursor += consumed;
    guard ok_dec else {
        reader.finished = true;
        return StreamReadStatus.Error, false;
    }

    let emitted = (out.len - prev_len) as! u64;
    reader.bytes_read += emitted;

    let is_eof = is_complete(reader.chunk_decoder);
    if is_eof {
        reader.finished = true;
    }
    if emitted > 0 {
        return StreamReadStatus.Data, is_eof;
    }
    if is_eof {
        return StreamReadStatus.Eof, true;
    }
    // RFC 9112 Section 7.1: Chunked Transfer Coding - Premature EOF before terminating 0-chunk is a framing error.
    reader.chunk_decoder.state = ChunkedStreamState.Error;
    reader.finished = true;
    return StreamReadStatus.Error, false;
}

fn read_chunk_identity<B>(reader: StreamReader&, max_bytes: i64, remaining: i64, out: B&) -> StreamReadStatus, bool {
    let to_read = if max_bytes > 0 { min(remaining, max_bytes) } else { remaining };
    out.append(reader.raw_data[reader.cursor..(reader.cursor + to_read)]);
    reader.cursor += to_read;
    reader.bytes_read += to_read as! u64;

    let is_eof = reader.cursor >= reader.raw_data.len;
    if is_eof {
        reader.finished = true;
    }
    return StreamReadStatus.Data, is_eof;
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
        return read_chunk_chunked(reader, max_bytes, out);
    }
    return read_chunk_identity(reader, max_bytes, remaining, out);
}

// Reads all remaining data from the stream into out buffer
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
        let ok_dec, consumed = feed_chunked_stream(reader.chunk_decoder, reader.raw_data[reader.cursor..], out, -1);
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
    return find_header(reader.chunk_decoder.trailers, name);
}

// Copies decoded chunk trailers to a target Response object.
fn copy_trailers_to_response(reader: const StreamReader&, resp: Response&) {
    append_all_headers(reader.chunk_decoder.trailers, resp.trailers);
}

// Calculates current stream progress
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
