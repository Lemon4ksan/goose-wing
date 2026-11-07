// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9112 chunked transfer coding & smuggling defense engine.
namespace wing;

import std;
import core from "../..";

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

fn skip_bws(s: const u8[:], cursor: i64&) {
    while cursor < s.len && (s[cursor] == ' ' || s[cursor] == '\t') {
        cursor++;
    }
}

// Parses a quoted string value in a chunk extension.
// Advances cursor past the closing quote.
//
// Example:
//   s = "\";foo=\\\"bar\\\"\"", cursor = 5
//   returns: true, cursor advances past quote
fn parse_chunk_ext_quoted_val(s: const u8[:], cursor: i64&) -> bool {
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
            return true;
        }
        cursor++;
    }
    return false;
}

// Parses a token name in a chunk extension.
// Advances cursor past the name.
//
// Example:
//   s = "ext_name=val", cursor = 0
//   returns: true, cursor = 8
fn parse_chunk_ext_name(s: const u8[:], cursor: i64&) -> bool {
    let name_start = cursor;
    while cursor < s.len && is_tchar(s[cursor]) {
        cursor++;
    }
    return cursor > name_start;
}

// Parses a parameter value (token or quoted string) in a chunk extension.
//
// Example:
//   s = "token; next", cursor = 0
//   returns: ChunkedDecodeError.None
fn parse_chunk_ext_param_val(s: const u8[:], cursor: i64&) -> ChunkedDecodeError {
    guard cursor < s.len else { return ChunkedDecodeError.InvalidChunkExtension; }
    if s[cursor] == '"' {
        guard parse_chunk_ext_quoted_val(s, cursor) else {
            return ChunkedDecodeError.InvalidChunkExtension;
        }
        return ChunkedDecodeError.None;
    }
    let val_start = cursor;
    while cursor < s.len && is_tchar(s[cursor]) {
        cursor++;
    }
    guard cursor > val_start else {
        return ChunkedDecodeError.InvalidChunkExtension;
    }
    return ChunkedDecodeError.None;
}

// Parses a single chunk extension parameter: ;name[=val]
//
// Example:
//   s = ";name=val", cursor = 0
//   returns: ChunkedDecodeError.None, cursor = 9
fn parse_chunk_ext_param(s: const u8[:], cursor: i64&) -> ChunkedDecodeError {
    guard cursor < s.len && s[cursor] == ';' else {
        return ChunkedDecodeError.InvalidChunkExtension;
    }
    cursor++; // skip ';'
    skip_bws(s, cursor);

    guard parse_chunk_ext_name(s, cursor) else {
        return ChunkedDecodeError.InvalidChunkExtension;
    }
    skip_bws(s, cursor);

    if cursor < s.len && s[cursor] == '=' {
        cursor++; // skip '='
        skip_bws(s, cursor);
        let val_err = parse_chunk_ext_param_val(s, cursor);
        guard val_err == ChunkedDecodeError.None else { return val_err; }
        skip_bws(s, cursor);
    }
    return ChunkedDecodeError.None;
}

// Parses all chunk extensions following the chunk size hex.
//
// Example:
//   s = ";ext1;ext2=val", cursor = 0
//   returns: ChunkedDecodeError.None
fn parse_chunk_extensions(s: const u8[:], cursor: i64&) -> ChunkedDecodeError {
    skip_bws(s, cursor);
    guard cursor < s.len && s[cursor] == ';' else {
        return ChunkedDecodeError.InvalidChunkSizeHex;
    }
    while cursor < s.len {
        let err = parse_chunk_ext_param(s, cursor);
        guard err == ChunkedDecodeError.None else { return err; }
    }
    return ChunkedDecodeError.None;
}

// Parses hex digits into an integer chunk size.
//
// Example:
//   chunk_size_line = "1a;ext", sig_start = 0, hex_len = 2
//   returns: ChunkedDecodeError.None, out_size = 26
fn parse_hex_chunk_value(
    chunk_size_line: const u8[:],
    sig_start:       i64,
    hex_len:         i64,
    out_size:        u64&,
) -> ChunkedDecodeError {
    var chunk_size: u64 = 0;
    for b in chunk_size_line[sig_start..hex_len] {
        let val = core::hex_digit_to_val(b);
        guard val >= 0 else {
            return ChunkedDecodeError.InvalidChunkSizeHex;
        }
        if chunk_size > 0x07FFFFFFFFFFFFFF {
            return ChunkedDecodeError.ChunkSizeOverflow;
        }
        chunk_size = (chunk_size << 4) | (val as! u64);
    }
    out_size = chunk_size;
    return ChunkedDecodeError.None;
}

fn validate_chunk_size_line_chars(chunk_size_line: const u8[:]) -> ChunkedDecodeError {
    guard chunk_size_line.len > 0 else {
        return ChunkedDecodeError.InvalidChunkSizeHex;
    }
    guard chunk_size_line.len <= 1024 else {
        return ChunkedDecodeError.InvalidChunkExtension;
    }
    for b in chunk_size_line {
        if b == '\r' || (b < 0x20 && b != 0x09) || b == 0x7F {
            return ChunkedDecodeError.InvalidChunkExtension;
        }
    }
    if chunk_size_line[0] == ' ' || chunk_size_line[0] == '\t' {
        return ChunkedDecodeError.InvalidChunkSizeHex;
    }
    return ChunkedDecodeError.None;
}

fn is_hex_char(b: u8) -> bool {
    return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F');
}

// Scans contiguous hex digits from cursor.
//
// Example:
//   s = "1a2b;ext", cursor = 0
//   returns: 4, cursor = 4
fn scan_hex_digits(s: const u8[:], cursor: i64&) -> i64 {
    while cursor < s.len && is_hex_char(s[cursor]) {
        cursor++;
    }
    return cursor;
}

fn find_significant_hex_start(s: const u8[:], hex_len: i64) -> i64 {
    var sig_start: i64 = 0;
    while sig_start < hex_len && s[sig_start] == '0' {
        sig_start++;
    }
    return sig_start;
}

// Parses hex chunk size line, validating extensions and bounds.
//
// Example:
//   chunk_size_line = "1a;ext=1"
//   returns: ChunkedDecodeError.None, out_size = 26
fn parse_chunk_size_hex(chunk_size_line: const u8[:], out_size: u64&) -> ChunkedDecodeError {
    let char_err = validate_chunk_size_line_chars(chunk_size_line);
    guard char_err == ChunkedDecodeError.None else { return char_err; }

    var cursor: i64 = 0;
    let hex_len = scan_hex_digits(chunk_size_line, cursor);
    guard hex_len > 0 else {
        return ChunkedDecodeError.InvalidChunkSizeHex;
    }

    let sig_start = find_significant_hex_start(chunk_size_line, hex_len);
    if hex_len - sig_start > 16 {
        return ChunkedDecodeError.ChunkSizeOverflow;
    }

    var chunk_size: u64 = 0;
    let hex_err = parse_hex_chunk_value(chunk_size_line, sig_start, hex_len, chunk_size);
    guard hex_err == ChunkedDecodeError.None else { return hex_err; }

    if cursor < chunk_size_line.len {
        let ext_err = parse_chunk_extensions(chunk_size_line, cursor);
        guard ext_err == ChunkedDecodeError.None else { return ext_err; }
    }

    out_size = chunk_size;
    return ChunkedDecodeError.None;
}

// Parses a single trailer field line into out_trailers.
//
// Example:
//   tr_line = "ETag: \"xyzzy\""
//   returns: ChunkedDecodeError.None, trailer appended
fn parse_single_trailer_field(tr_line: const u8[:], out_trailers: HeaderMap&) -> ChunkedDecodeError {
    let col_idx = core::index_of_byte(tr_line, ':');
    guard col_idx > 0 else {
        return ChunkedDecodeError.DisallowedTrailer;
    }

    let hname = tr_line[..col_idx];
    guard is_valid_header_name(hname) && !rfc::is_disallowed_trailer_field(hname) else {
        return ChunkedDecodeError.DisallowedTrailer;
    }

    let val_slice = tr_line[(col_idx + 1)..];
    let trimmed_val = trim_lws(val_slice);
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
//
// Example:
//   raw = "ETag: 123\r\n\r\n", cursor = 0
//   returns: ChunkedDecodeError.None, out_trailers populated
fn parse_chunked_trailers_with_out(
    raw:          const u8[:],
    cursor:       i64&,
    out_trailers: HeaderMap&,
) -> ChunkedDecodeError {
    var trailer_count:       i32 = 0;
    var total_trailer_bytes: i64 = 0;

    while cursor < raw.len {
        let rel_nl = core::index_of_byte(raw[cursor..], '\n');
        guard rel_nl >= 0 else { return ChunkedDecodeError.UnexpectedEof; }
        let tr_end = cursor + rel_nl;

        // RFC 9112 Section 7.1.2: Reject bare LF in trailer lines (prevent framing desync)
        if tr_end == cursor || raw[tr_end - 1] != '\r' {
            return ChunkedDecodeError.BareLfInTrailer;
        }

        let tr_line = raw[cursor..tr_end - 1];
        cursor = tr_end + 1;

        if tr_line.len == 0 {
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

fn consume_chunk_data(raw: const u8[:], cursor: i64&, chunk_size: u64, out_body: u8[>..]&) -> ChunkedDecodeError {
    guard chunk_size <= (raw.len as u64) else {
        return ChunkedDecodeError.UnexpectedEof;
    }
    let csize = chunk_size as! i64;
    guard csize <= raw.len - cursor else {
        return ChunkedDecodeError.UnexpectedEof;
    }

    let end_pos = cursor + csize;
    if end_pos < raw.len && raw[end_pos] == '\n' {
        return ChunkedDecodeError.BareLfInChunkData;
    }

    guard end_pos + 1 < raw.len else {
        return ChunkedDecodeError.UnexpectedEof;
    }

    guard raw[end_pos] == '\r' && raw[end_pos + 1] == '\n' else {
        return ChunkedDecodeError.MalformedChunkEnding;
    }

    let chunk_data = raw[cursor..end_pos];
    out_body.append(chunk_data);
    cursor = end_pos + 2;
    return ChunkedDecodeError.None;
}

fn read_chunk_size_line(raw: const u8[:], cursor: i64&, out_size: u64&) -> ChunkedDecodeError {
    let rel_nl = core::index_of_byte(raw[cursor..], '\n');
    guard rel_nl >= 0 else { return ChunkedDecodeError.UnexpectedEof; }
    let line_end = cursor + rel_nl;

    if line_end == cursor || raw[line_end - 1] != '\r' {
        return ChunkedDecodeError.BareLfInChunkSize;
    }

    let chunk_size_line = raw[cursor..line_end - 1];
    var chunk_size: u64 = 0;
    let size_err = parse_chunk_size_hex(chunk_size_line, chunk_size);
    guard size_err == ChunkedDecodeError.None else { return size_err; }

    cursor = line_end + 1;
    out_size = chunk_size;
    return ChunkedDecodeError.None;
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
    out_body.clear();
    out_trailers.clear();
    guard raw.len > 0 else { return ChunkedDecodeError.EmptyInput, 0; }

    var cursor:         i64 = 0;
    var total_overhead: i64 = 0;
    while cursor < raw.len {
        let header_start = cursor;
        var chunk_size: u64 = 0;
        let line_err = read_chunk_size_line(raw, cursor, chunk_size);
        guard line_err == ChunkedDecodeError.None else {
            out_body.clear();
            out_trailers.clear();
            return line_err, 0;
        }
        total_overhead = core::add_sat_i64(total_overhead, core::sub_sat_i64(cursor, header_start));

        if chunk_size == 0 {
            let tr_start = cursor;
            let tr_err = parse_chunked_trailers_with_out(raw, cursor, out_trailers);
            guard tr_err == ChunkedDecodeError.None else {
                out_body.clear();
                out_trailers.clear();
                return tr_err, 0;
            }
            total_overhead = core::add_sat_i64(total_overhead, core::sub_sat_i64(cursor, tr_start));
            guard !is_chunk_overhead_excessive(cursor, total_overhead) else {
                out_body.clear();
                out_trailers.clear();
                return ChunkedDecodeError.ExcessiveFramingOverhead, 0;
            }
            return ChunkedDecodeError.None, cursor;
        }

        let data_err = consume_chunk_data(raw, cursor, chunk_size, out_body);
        guard data_err == ChunkedDecodeError.None else {
            out_body.clear();
            out_trailers.clear();
            return data_err, 0;
        }
        total_overhead = core::add_sat_i64(total_overhead, 2);
        if is_chunk_overhead_excessive(cursor, total_overhead) {
            out_body.clear();
            out_trailers.clear();
            return ChunkedDecodeError.ExcessiveFramingOverhead, 0;
        }
    }

    out_body.clear();
    out_trailers.clear();
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
