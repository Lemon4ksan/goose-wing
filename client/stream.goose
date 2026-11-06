// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Incremental streaming, chunked transfer encoding (RFC 9112 Section 7.1),
// and chunked upload/download progress pipeline.
namespace wing;

import std;
import client.profile;
import client.request;
import client.response;
import http.headers;
import http.headers.chunked_fsm;

// ---- RFC 9112 Chunked Transfer Framing -----------------------------------

// Encodes a single chunk frame: `<hex-size>\r\n<data>\r\n`
fn encode_chunk<B>(data: const u8[:], out: B&) {
    core::format_u64_hex(data.len as! u64, out);
    out.push('\r');
    out.push('\n');
    out.append(data);
    out.push('\r');
    out.push('\n');
}

// Encodes the terminal 0-size chunk: `0\r\n\r\n` (or with trailers)
fn encode_chunk_end<B>(out: B&) {
    out.push('0');
    out.push('\r');
    out.push('\n');
    out.push('\r');
    out.push('\n');
}

// Encodes trailer header: `<name>: <value>\r\n`
fn encode_chunk_trailer<B>(name: const u8[:], val: const u8[:], out: B&) {
    out.append(name);
    out.push(':');
    out.push(' ');
    out.append(val);
    out.push('\r');
    out.push('\n');
}

// Encodes an entire body buffer as RFC 9112 chunked transfer frames with optional trailers.
fn encode_chunked_payload<B>(
    body:       const u8[:],
    trailers:   const HeaderMap&,
    chunk_size: i64,
    out:        B&,
) {
    let step = if chunk_size > 0 { chunk_size } else { 4096 };
    if body.len > 0 {
        var offset: i64 = 0;
        while offset < body.len {
            let end_off = if offset + step < body.len { offset + step } else { body.len };
            encode_chunk(body[offset..end_off], out);
            offset = end_off;
        }
    }

    if trailers.entries.len == 0 {
        encode_chunk_end(out);
    } else {
        out.push('0');
        out.push('\r');
        out.push('\n');
        for &e in trailers.entries {
            encode_chunk_trailer(entry_name(trailers, e), entry_value(trailers, e), out);
        }
        out.push('\r');
        out.push('\n');
    }
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
    guard !writer.finished && !rfc::is_disallowed_trailer_field(name) else { return false; }
    guard writer.trailers.entries.len < 16 else { return false; }
    return append_header(writer.trailers, name, val);
}

fn finish_chunk_writer(writer: ChunkWriter&) {
    guard !writer.finished else { return; }
    writer.finished = true;
    if writer.trailers.entries.len == 0 {
        encode_chunk_end(writer.buffer);
    } else {
        writer.buffer.push('0');
        writer.buffer.push('\r');
        writer.buffer.push('\n');
        for &e in writer.trailers.entries {
            encode_chunk_trailer(entry_name(writer.trailers, e), entry_value(writer.trailers, e), writer.buffer);
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

fn has_header_whitespace(s: const u8[:]) -> bool {
    for b in s {
        if b == ' ' || b == '\t' || b == '\r' {
            return true;
        }
    }
    return false;
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
        let size_line = dec.line_buf[..(dec.line_buf.len - 1)];
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
    guard dec.line_buf.len < dec.line_buf.cap else {
        dec.state = ChunkedStreamState.Error;
        dec.error_code = ChunkedDecodeError.InvalidChunkExtension;
        return false;
    }
    dec.line_buf.push(b);
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
    let tr_line = dec.line_buf[..(dec.line_buf.len - 1)];

    if tr_line.len == 0 {
        dec.state = ChunkedStreamState.Complete;
        dec.line_buf.clear();
        return true;
    }

    dec.trailer_count++;
    guard dec.trailer_count <= 16 else {
        dec.state = ChunkedStreamState.Error;
        dec.error_code = ChunkedDecodeError.DisallowedTrailer;
        return false;
    }

    dec.total_trailer_bytes += tr_line.len;
    guard dec.total_trailer_bytes <= 4096 else {
        dec.state = ChunkedStreamState.Error;
        dec.error_code = ChunkedDecodeError.DisallowedTrailer;
        return false;
    }

    var col_idx: i64 = -1;
    for i in tr_line.len {
        if tr_line[i] == ':' {
            col_idx = i;
            break;
        }
    }
    guard col_idx > 0 else {
        dec.state = ChunkedStreamState.Error;
        dec.error_code = ChunkedDecodeError.DisallowedTrailer;
        return false;
    }

    let hname = tr_line[..col_idx];
    if has_header_whitespace(hname) || rfc::is_disallowed_trailer_field(hname) {
        dec.state = ChunkedStreamState.Error;
        dec.error_code = ChunkedDecodeError.DisallowedTrailer;
        return false;
    }

    let hval = trim_lws(tr_line[(col_idx + 1)..]);
    guard append_trailer_item(dec.trailers, hname, hval) else {
        dec.state = ChunkedStreamState.Error;
        dec.error_code = ChunkedDecodeError.DisallowedTrailer;
        return false;
    }
    dec.line_buf.clear();
    return true;
}

fn step_chunk_trailer(dec: ChunkedStreamDecoder&, b: u8) -> bool {
    dec.bytes_consumed_total++;
    if b == '\n' {
        return process_trailer_line(dec);
    }
    guard dec.line_buf.len < dec.line_buf.cap else {
        dec.state = ChunkedStreamState.Error;
        dec.error_code = ChunkedDecodeError.DisallowedTrailer;
        return false;
    }
    dec.line_buf.push(b);
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
            var to_take = if avail < needed { avail } else { needed };
            if max_emit >= 0 {
                let emitted = out_body.len - initial_out_len;
                let cap_rem = max_emit - emitted;
                to_take = if to_take < cap_rem { to_take } else { cap_rem };
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
    let clean = core::trim_lws(cl);
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
    return StreamReadStatus.Data, false;
}

fn read_chunk_identity<B>(reader: StreamReader&, max_bytes: i64, remaining: i64, out: B&) -> StreamReadStatus, bool {
    let to_read = if max_bytes > 0 && remaining > max_bytes { max_bytes } else { remaining };
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
    let remaining = reader.raw_data.len - reader.cursor;
    guard remaining > 0 || (reader.is_chunked && !is_complete(reader.chunk_decoder)) else {
        reader.finished = true;
        return 0;
    }

    if reader.is_chunked {
        let prev_len = out.len;
        let ok_dec, consumed = feed_chunked_stream(reader.chunk_decoder, reader.raw_data[reader.cursor..], out, -1);
        reader.cursor += consumed;
        let emitted = (out.len - prev_len) as! u64;
        reader.bytes_read += emitted;
        if is_complete(reader.chunk_decoder) || !ok_dec {
            reader.finished = true;
        }
        return emitted;
    }

    out.append(reader.raw_data[reader.cursor..]);
    reader.cursor = reader.raw_data.len;
    reader.bytes_read += remaining as! u64;
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
        p.percent = (reader.bytes_read as! f64 / reader.content_length) * 100.0;
        if p.percent > 100.0 { p.percent = 100.0; }
    }
    return p;
}

// ---- 4. Push-Streaming Sinks & Monomorphized Decorators ---------------------

// Zero-allocation push sink appending directly into caller-owned byte buffer.
struct ArenaSink {
    max_bytes: i64 = 16777216,
}

inline fn emit<B>(sink: ArenaSink, chunk: const u8[:], out: B&) -> bool {
    guard out.len + chunk.len <= sink.max_bytes else { return false; }
    out.append(chunk);
    return true;
}

// Feeds incoming wire slice through 64-bit ChunkFsmDecoder and emits clean slices into sink.
fn pump_chunk_fsm<Sink, B>(
    dec:  internal::ChunkFsmDecoder&,
    wire: const u8[:],
    sink: Sink,
    out:  B&,
) -> internal::ChunkFsmStatus, i64 {
    var total_consumed: i64 = 0;
    var cursor:         i64 = 0;
    while cursor < wire.len {
        let st, consumed, chunk = internal::chunk_fsm_feed(dec, wire[cursor..]);
        cursor += consumed;
        total_consumed += consumed;
        if chunk.len > 0 {
            guard sink.emit(chunk, out) else {
                return internal::ChunkFsmStatus.Error, total_consumed;
            }
        }
        if st == internal::ChunkFsmStatus.Complete || st == internal::ChunkFsmStatus.Error {
            return st, total_consumed;
        }
    }
    return internal::ChunkFsmStatus.NeedMore, total_consumed;
}
