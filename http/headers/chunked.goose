// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9112 chunked transfer coding & smuggling defense engine.
namespace http;

import std;
import core;
import http.headers.internal;

// RFC 9112 Section 7.1: Chunked Transfer Coding & Smuggling Defense Diagnostics
enum ChunkedDecodeError {
    None,
    EmptyInput,
    InvalidChunkSizeHex,
    BareLfInChunkSize,
    BareLfInChunkData,
    BareLfInTrailer,
    InvalidChunkExtension,
    ChunkSizeOverflow,
    UnexpectedEof,
    MalformedChunkEnding,
    DisallowedTrailer,
    ExcessiveFramingOverhead,
}

const CHUNK_OVERHEAD_MIN_BYTES: i64 = 102400;

inline fn is_chunk_overhead_excessive(total_read: i64, total_overhead: i64) -> bool {
    return total_overhead >= CHUNK_OVERHEAD_MIN_BYTES &&
           core::sub_sat_i64(total_read, total_overhead) < (total_read >> 2);
}

// Parses a quoted string value in a chunk extension.
// Advances cursor past the closing quote.
//
// Example:
//   s = "\";foo=\\\"bar\\\"\"", cursor = 5
//   returns: true, cursor advances past quote
fn parse_chunk_ext_quoted_val(s: const u8[:], cursor: i64&) -> bool {
    let saved_cursor = cursor;
    var committed = false;
    defer if !committed { cursor = saved_cursor; };
    cursor++; // skip opening quote
    while cursor < s.len {
        let qc = s[cursor];
        if qc == '\\' {
            guard cursor + 1 < s.len else { return false; }
            let esc = s[cursor + 1];
            guard esc == '\t' || (esc >= 0x20 && esc <= 0x7E) || esc >= 0x80 else { return false; }
            cursor += 2;
            continue;
        }
        if qc == '"' {
            cursor++;
            committed = true;
            return true;
        }
        cursor++;
    }
    return false;
}

// Parses all chunk extensions following the chunk size hex.
// Leaves `cursor` unchanged on error.
//
// Example:
//   s = ";ext1;ext2=val", cursor = 0
//   returns: ChunkedDecodeError.None
fn parse_chunk_extensions(s: const u8[:], cursor: i64&) -> ChunkedDecodeError {
    let saved_cursor = cursor;
    var committed = false;
    defer if !committed { cursor = saved_cursor; };

    http_internal::skip_bws(s, cursor);
    guard cursor < s.len && s[cursor] == ';' else {
        return ChunkedDecodeError.InvalidChunkSizeHex;
    }
    while cursor < s.len {
        let err = http_internal::parse_chunk_ext_param(s, cursor);
        guard err == ChunkedDecodeError.None else { return err; }
    }
    committed = true;
    return ChunkedDecodeError.None;
}

// Parses hex chunk size line, validating extensions and bounds.
//
// Example:
//   chunk_size_line = "1a;ext=1"
//   returns: 26, ChunkedDecodeError.None
fn parse_chunk_size_hex(chunk_size_line: const u8[:]) -> u64, ChunkedDecodeError {
    let char_err = http_internal::validate_chunk_size_line_chars(chunk_size_line);
    guard char_err == ChunkedDecodeError.None else { return 0, char_err; }

    var cursor: i64 = 0;
    let hex_len = http_internal::scan_hex_digits(chunk_size_line, cursor);
    guard hex_len > 0 else {
        return 0, ChunkedDecodeError.InvalidChunkSizeHex;
    }

    let sig_start = http_internal::find_significant_hex_start(chunk_size_line, hex_len);
    if hex_len - sig_start > 16 {
        return 0, ChunkedDecodeError.ChunkSizeOverflow;
    }

    var chunk_size: u64 = 0;
    let hex_err = http_internal::parse_hex_chunk_value(chunk_size_line, sig_start, hex_len, chunk_size);
    guard hex_err == ChunkedDecodeError.None else { return 0, hex_err; }

    if cursor < chunk_size_line.len {
        let ext_err = parse_chunk_extensions(chunk_size_line, cursor);
        guard ext_err == ChunkedDecodeError.None else { return 0, ext_err; }
    }

    return chunk_size, ChunkedDecodeError.None;
}

// Parses a single trailer field line into out_trailers.
//
// Example:
//   tr_line = "ETag: \"xyzzy\""
//   returns: ChunkedDecodeError.None, trailer appended
fn parse_single_trailer_field(tr_line: const u8[:], out_trailers: HeaderMap&) -> ChunkedDecodeError {
    let col_idx = tr_line.index_of_byte(':');
    guard col_idx > 0 else {
        return ChunkedDecodeError.DisallowedTrailer;
    }

    let hname = tr_line[..col_idx];
    guard is_valid_header_name(hname) && !rfc::is_disallowed_trailer_field(hname) else {
        return ChunkedDecodeError.DisallowedTrailer;
    }

    let val_slice = tr_line[(col_idx + 1)..];
    let trimmed_val = val_slice.trim_lws();
    guard is_valid_header_value(trimmed_val) && out_trailers.entries.len < 16 else {
        return ChunkedDecodeError.DisallowedTrailer;
    }

    guard hname.len <= 64 && trimmed_val.len <= 2048 else {
        return ChunkedDecodeError.DisallowedTrailer;
    }
    guard out_trailers.append_header(hname, trimmed_val) else {
        return ChunkedDecodeError.DisallowedTrailer;
    }
    return ChunkedDecodeError.None;
}

// RFC 9112 Section 7.1.2: Parse chunked trailers and populate out_trailers list.
// Leaves `cursor` unchanged and clears `out_trailers` on error.
//
// Example:
//   raw = "ETag: 123\r\n\r\n", cursor = 0
//   returns: ChunkedDecodeError.None, out_trailers populated
fn parse_chunked_trailers_with_out(
    raw:          const u8[:],
    cursor:       i64&,
    out_trailers: HeaderMap&,
) -> ChunkedDecodeError {
    let saved_cursor = cursor;
    var committed = false;
    reset_for_keep_alive(out_trailers);
    defer if !committed {
        cursor = saved_cursor;
        reset_for_keep_alive(out_trailers);
        out_trailers.valid = false;
    };

    var trailer_count:       i32 = 0;
    var total_trailer_bytes: i64 = 0;

    while cursor < raw.len {
        let rel_nl = raw[cursor..].index_of_byte('\n');
        guard rel_nl >= 0 else { return ChunkedDecodeError.UnexpectedEof; }
        let tr_end = cursor + rel_nl;

        // RFC 9112 Section 7.1.2: Reject bare LF in trailer lines (prevent framing desync)
        if tr_end == cursor || raw[tr_end - 1] != '\r' {
            return ChunkedDecodeError.BareLfInTrailer;
        }

        let tr_line = raw[cursor..tr_end - 1];
        cursor = tr_end + 1;

        if tr_line.len == 0 {
            committed = true;
            return ChunkedDecodeError.None;
        }

        trailer_count++;
        total_trailer_bytes += tr_line.len;
        guard trailer_count <= 16 && total_trailer_bytes <= 4096 else {
            return ChunkedDecodeError.DisallowedTrailer;
        }

        let field_err = parse_single_trailer_field(tr_line, out_trailers);
        guard field_err == ChunkedDecodeError.None else { return field_err; }
    }
    return ChunkedDecodeError.UnexpectedEof;
}

// Parses chunked trailers discarding output fields.
//
// Example:
//   raw = "\r\n", cursor = 0
//   returns: ChunkedDecodeError.None, cursor = 2
fn parse_chunked_trailers(raw: const u8[:], cursor: i64&) -> ChunkedDecodeError {
    var dummy = HeaderMap { .. };
    return parse_chunked_trailers_with_out(raw, cursor, dummy);
}

// Reads one chunk-size CRLF line starting at `cursor` (RFC 9112 Section 7.1).
// Leaves `cursor` unchanged on error.
//
// Example:
//   raw = "4\r\nWiki\r\n", cursor = 0
//   returns: 4, ChunkedDecodeError.None, cursor = 3
fn read_chunk_size_line(raw: const u8[:], cursor: i64&) -> u64, ChunkedDecodeError {
    let rel_nl = raw[cursor..].index_of_byte('\n');
    guard rel_nl >= 0 else { return 0, ChunkedDecodeError.UnexpectedEof; }
    let line_end = cursor + rel_nl;

    if line_end == cursor || raw[line_end - 1] != '\r' {
        return 0, ChunkedDecodeError.BareLfInChunkSize;
    }

    let chunk_size_line = raw[cursor..line_end - 1];
    let chunk_size, size_err = parse_chunk_size_hex(chunk_size_line);
    guard size_err == ChunkedDecodeError.None else { return 0, size_err; }

    cursor = line_end + 1;
    return chunk_size, ChunkedDecodeError.None;
}

// Decodes a chunked transfer-encoded payload into out_body and extracts trailers (RFC 9112 Section 7.1).
// Returns (status_error, total_bytes_consumed_from_raw).
//
// Example:
//   raw = "4\r\nWiki\r\n0\r\n\r\n"
//   returns: ChunkedDecodeError.None, consumed = 14, out_body = "Wiki"
fn decode_chunked_body_with_trailers(
    raw:          const u8[:],
    out_body:     u8[>..]&,
    out_trailers: HeaderMap&,
) -> ChunkedDecodeError, i64 {
    guard raw.len > 0 else { return ChunkedDecodeError.EmptyInput, 0; }
    out_body.clear();
    out_trailers.clear();
    var committed = false;
    defer if !committed {
        out_body.clear();
        out_trailers.clear();
    };

    var cursor:         i64 = 0;
    var total_overhead: i64 = 0;
    while cursor < raw.len {
        let header_start = cursor;
        let chunk_size, line_err = read_chunk_size_line(raw, cursor);
        guard line_err == ChunkedDecodeError.None else { return line_err, 0; }
        total_overhead = core::add_sat_i64(total_overhead, core::sub_sat_i64(cursor, header_start));

        if chunk_size == 0 {
            let tr_start = cursor;
            let tr_err = parse_chunked_trailers_with_out(raw, cursor, out_trailers);
            guard tr_err == ChunkedDecodeError.None else { return tr_err, 0; }
            total_overhead = core::add_sat_i64(total_overhead, core::sub_sat_i64(cursor, tr_start));
            guard !is_chunk_overhead_excessive(cursor, total_overhead) else {
                return ChunkedDecodeError.ExcessiveFramingOverhead, 0;
            }
            committed = true;
            return ChunkedDecodeError.None, cursor;
        }

        let data_err = http_internal::consume_chunk_data(raw, cursor, chunk_size, out_body);
        guard data_err == ChunkedDecodeError.None else { return data_err, 0; }
        total_overhead = core::add_sat_i64(total_overhead, 2);
        if is_chunk_overhead_excessive(cursor, total_overhead) {
            return ChunkedDecodeError.ExcessiveFramingOverhead, 0;
        }
    }

    return ChunkedDecodeError.UnexpectedEof, 0;
}

// Decodes a chunked transfer-encoded payload into out_body (RFC 9112 Section 7.1).
// Chunk size lines and data chunks must end with CRLF; bare LF returns an error.
//
// Example:
//   raw = "4\r\nWiki\r\n0\r\n\r\n"
//   returns: ChunkedDecodeError.None, out_body = "Wiki"
fn decode_chunked_body(raw: const u8[:], out_body: u8[>..]&) -> ChunkedDecodeError {
    var dummy = HeaderMap { .. };
    let err, _ = decode_chunked_body_with_trailers(raw, out_body, dummy);
    return err;
}
