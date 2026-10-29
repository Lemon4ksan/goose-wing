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

// ---- 1. RFC 9112 Chunked Transfer Framing -----------------------------------

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
    body: const u8[:],
    trailers: const HeaderItem[..16]&,
    chunk_size: i64,
    out: B&,
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

    if trailers.len == 0 {
        encode_chunk_end(out);
    } else {
        out.push('0');
        out.push('\r');
        out.push('\n');
        for &t in trailers {
            encode_chunk_trailer(t.name[..], t.value[..], out);
        }
        out.push('\r');
        out.push('\n');
    }
}

// ---- 2. Chunk Stream Writer (for Chunked Uploads) ---------------------------

struct ChunkWriter {
    trailers: HeaderItem[..16] = [],
    finished: bool = false,
    buffer: u8[>..] = [],
}

fn new_chunk_writer() -> ChunkWriter {
    return ChunkWriter { .. };
}

fn write_chunk(writer: ChunkWriter&, data: const u8[:]) {
    guard !writer.finished && data.len > 0 else { return; }
    encode_chunk(data, writer.buffer);
}

fn add_trailer(writer: ChunkWriter&, name: const u8[:], val: const u8[:]) {
    guard !writer.finished && !is_disallowed_trailer_field(name) && writer.trailers.len < writer.trailers.cap else { return; }
    writer.trailers.push(make_header(name, val));
}

fn finish_chunk_writer(writer: ChunkWriter&) {
    guard !writer.finished else { return; }
    writer.finished = true;
    if writer.trailers.len == 0 {
        encode_chunk_end(writer.buffer);
    } else {
        writer.buffer.push('0');
        writer.buffer.push('\r');
        writer.buffer.push('\n');
        for &t in writer.trailers {
            encode_chunk_trailer(t.name[..], t.value[..], writer.buffer);
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
    state: ChunkedStreamState = ChunkedStreamState.ChunkSizeLine,
    expected_chunk_size: u64 = 0,
    chunk_bytes_remaining: u64 = 0,
    crlf_step: i32 = 0,
    line_buf: u8[..1024] = [],
    trailers: HeaderItem[..16] = [],
    trailer_count: i32 = 0,
    total_trailer_bytes: i64 = 0,
    bytes_consumed_total: u64 = 0,
    error_code: ChunkedDecodeError = ChunkedDecodeError.None,
}

fn new_chunked_stream_decoder() -> ChunkedStreamDecoder {
    return ChunkedStreamDecoder { .. };
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

fn append_trailer_item(trailers: HeaderItem[..16]&, name: const u8[:], val: const u8[:]) {
    guard trailers.len < trailers.cap else { return; }
    var item = HeaderItem { .. };
    item.name.append(name);
    item.value.append(val);
    trailers.push(item);
}

// Feeds incoming wire slice into incremental decoder.
// Emits decoded chunk body payload bytes directly into out_body.
// Returns (ok, bytes_consumed_from_input).
fn feed_chunked_stream<B>(
    dec: ChunkedStreamDecoder&,
    input: const u8[:],
    out_body: B&,
) -> bool, i64 {
    guard dec.state != ChunkedStreamState.Error && dec.state != ChunkedStreamState.Complete else {
        return dec.state == ChunkedStreamState.Complete, 0;
    }

    var cursor: i64 = 0;
    while cursor < input.len && dec.state != ChunkedStreamState.Complete && dec.state != ChunkedStreamState.Error {
        if dec.state == ChunkedStreamState.ChunkSizeLine {
            let b = input[cursor];
            cursor++;
            dec.bytes_consumed_total++;

            if b == '\n' {
                if dec.line_buf.len == 0 || dec.line_buf[dec.line_buf.len - 1] != '\r' {
                    dec.state = ChunkedStreamState.Error;
                    dec.error_code = ChunkedDecodeError.BareLfInChunkSize;
                    return false, cursor;
                }
                let size_line = dec.line_buf[..(dec.line_buf.len - 1)];
                var csize: u64 = 0;
                let parse_err = parse_chunk_size_hex(size_line, csize);
                if parse_err != ChunkedDecodeError.None {
                    dec.state = ChunkedStreamState.Error;
                    dec.error_code = parse_err;
                    return false, cursor;
                }
                dec.line_buf.clear();
                dec.expected_chunk_size = csize;

                if csize == 0 {
                    dec.state = ChunkedStreamState.Trailers;
                } else {
                    dec.chunk_bytes_remaining = csize;
                    dec.state = ChunkedStreamState.ChunkData;
                }
            } else {
                guard dec.line_buf.len < dec.line_buf.cap else {
                    dec.state = ChunkedStreamState.Error;
                    dec.error_code = ChunkedDecodeError.InvalidChunkExtension;
                    return false, cursor;
                }
                dec.line_buf.push(b);
            }
        } else if dec.state == ChunkedStreamState.ChunkData {
            let avail = input.len - cursor;
            let needed = dec.chunk_bytes_remaining as i64;
            let to_take = if avail < needed { avail } else { needed };

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
            dec.bytes_consumed_total++;

            if dec.crlf_step == 0 {
                if b == '\r' {
                    dec.crlf_step = 1;
                } else if b == '\n' {
                    dec.state = ChunkedStreamState.Error;
                    dec.error_code = ChunkedDecodeError.BareLfInChunkData;
                    return false, cursor;
                } else {
                    dec.state = ChunkedStreamState.Error;
                    dec.error_code = ChunkedDecodeError.MalformedChunkEnding;
                    return false, cursor;
                }
            } else {
                if b == '\n' {
                    dec.state = ChunkedStreamState.ChunkSizeLine;
                    dec.crlf_step = 0;
                } else {
                    dec.state = ChunkedStreamState.Error;
                    dec.error_code = ChunkedDecodeError.MalformedChunkEnding;
                    return false, cursor;
                }
            }
        } else if dec.state == ChunkedStreamState.Trailers {
            let b = input[cursor];
            cursor++;
            dec.bytes_consumed_total++;

            if b == '\n' {
                if dec.line_buf.len == 0 || dec.line_buf[dec.line_buf.len - 1] != '\r' {
                    dec.state = ChunkedStreamState.Error;
                    dec.error_code = ChunkedDecodeError.BareLfInTrailer;
                    return false, cursor;
                }
                let tr_line = dec.line_buf[..(dec.line_buf.len - 1)];

                if tr_line.len == 0 {
                    dec.state = ChunkedStreamState.Complete;
                    dec.line_buf.clear();
                    return true, cursor;
                }

                dec.trailer_count++;
                if dec.trailer_count > 16 {
                    dec.state = ChunkedStreamState.Error;
                    dec.error_code = ChunkedDecodeError.DisallowedTrailer;
                    return false, cursor;
                }

                dec.total_trailer_bytes += tr_line.len;
                if dec.total_trailer_bytes > 4096 {
                    dec.state = ChunkedStreamState.Error;
                    dec.error_code = ChunkedDecodeError.DisallowedTrailer;
                    return false, cursor;
                }

                var col_idx: i64 = -1;
                for i in tr_line.len {
                    if tr_line[i] == ':' {
                        col_idx = i;
                        break;
                    }
                }
                if col_idx <= 0 {
                    dec.state = ChunkedStreamState.Error;
                    dec.error_code = ChunkedDecodeError.DisallowedTrailer;
                    return false, cursor;
                }

                let hname = tr_line[..col_idx];
                // RFC 9112 §5.1 / §7.1: Header/trailer field name must not contain whitespace
                // nor can there be whitespace before colon (preventing HTTP smuggling bypass).
                if has_header_whitespace(hname) || is_disallowed_trailer_field(hname) {
                    dec.state = ChunkedStreamState.Error;
                    dec.error_code = ChunkedDecodeError.DisallowedTrailer;
                    return false, cursor;
                }

                let hval = trim_lws(tr_line[(col_idx + 1)..]);
                append_trailer_item(dec.trailers, hname, hval);
                dec.line_buf.clear();
            } else {
                guard dec.line_buf.len < dec.line_buf.cap else {
                    dec.state = ChunkedStreamState.Error;
                    dec.error_code = ChunkedDecodeError.DisallowedTrailer;
                    return false, cursor;
                }
                dec.line_buf.push(b);
            }
        }
    }

    return true, cursor;
}

// ---- 3. Incremental Stream Reader & Progress Tracking -----------------------

struct StreamProgress {
    bytes_processed: u64 = 0,
    total_bytes: i64 = -1,
    percent: f64 = 0.0,
    is_finished: bool = false,
}

struct StreamReader {
    cursor: i64 = 0,
    content_length: i64 = -1,
    is_chunked: bool = false,
    chunk_decoder: ChunkedStreamDecoder = ChunkedStreamDecoder { .. },
    bytes_read: u64 = 0,
    finished: bool = false,
    raw_data: u8[>..] = [],
}

fn new_stream_reader(resp: const Response&) -> StreamReader {
    var reader = StreamReader { .. };
    reader.raw_data.append(resp.body[..]);

    let te = header(resp, "Transfer-Encoding");
    if eq_ascii_fold(te, "chunked") {
        reader.is_chunked = true;
    }

    let cl = header(resp, "Content-Length");
    if cl.len > 0 {
        var num: i64 = 0;
        var has_digit = false;
        for b in cl {
            if b >= '0' && b <= '9' {
                num = num * 10 + (b - '0');
                has_digit = true;
            }
        }
        if has_digit {
            reader.content_length = num;
        }
    }
    return reader;
}

// Reads the next chunk from the stream (up to max_bytes).
// Returns (has_bytes, is_eof).
fn read_chunk<B>(reader: StreamReader&, max_bytes: i64, out: B&) -> bool, bool {
    guard !reader.finished else { return false, true; }

    let remaining = reader.raw_data.len - reader.cursor;
    guard remaining > 0 else {
        reader.finished = true;
        return false, true;
    }

    out.clear();
    if reader.is_chunked {
        var temp_body: u8[>..] = [];
        let ok_dec, consumed = feed_chunked_stream(reader.chunk_decoder, reader.raw_data[reader.cursor..], temp_body);
        reader.cursor += consumed;
        let to_take = if max_bytes > 0 && temp_body.len > max_bytes { max_bytes } else { temp_body.len };
        if to_take > 0 {
            out.append(temp_body[..to_take]);
            reader.bytes_read += to_take as! u64;
        }
        if is_complete(reader.chunk_decoder) || !ok_dec || reader.cursor >= reader.raw_data.len {
            reader.finished = true;
            return to_take > 0, true;
        }
        return to_take > 0, false;
    }

    let to_read = if remaining < max_bytes { remaining } else { max_bytes };
    out.append(reader.raw_data[reader.cursor..reader.cursor + to_read]);
    reader.cursor += to_read;
    reader.bytes_read += to_read as! u64;

    if reader.cursor >= reader.raw_data.len {
        reader.finished = true;
        return true, true;
    }
    return true, false;
}

// Reads all remaining data from the stream into out buffer
fn read_all<B>(reader: StreamReader&, out: B&) -> u64 {
    guard !reader.finished else { return 0; }
    let remaining = reader.raw_data.len - reader.cursor;
    guard remaining > 0 else {
        reader.finished = true;
        return 0;
    }

    if reader.is_chunked {
        let prev_len = out.len;
        let ok_dec, consumed = feed_chunked_stream(reader.chunk_decoder, reader.raw_data[reader.cursor..], out);
        reader.cursor += consumed;
        let emitted = (out.len - prev_len) as! u64;
        reader.bytes_read += emitted;
        reader.finished = true;
        return emitted;
    }

    out.append(reader.raw_data[reader.cursor..]);
    reader.cursor = reader.raw_data.len;
    reader.bytes_read += remaining as! u64;
    reader.finished = true;
    return remaining as! u64;
}

// Calculates current stream progress
fn stream_progress(reader: const StreamReader&) -> StreamProgress {
    var p = StreamProgress {
        bytes_processed: reader.bytes_read,
        total_bytes: reader.content_length,
        is_finished: reader.finished,
        ..
    };
    if reader.content_length > 0 {
        p.percent = (reader.bytes_read as! f64 / reader.content_length) * 100.0;
        if p.percent > 100.0 { p.percent = 100.0; }
    }
    return p;
}
