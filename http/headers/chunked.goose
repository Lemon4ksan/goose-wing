// RFC 9112 chunked transfer coding & smuggling defense engine.
namespace wing;

import std;
import core from "../..";
import http.headers;

// RFC 9112 Section 7.1.2: Disallowed trailer fields threatening message framing or routing
fn is_disallowed_trailer_field(hname: const u8[:]) -> bool {
    return eq_ascii_fold(hname, "content-length") ||
           eq_ascii_fold(hname, "transfer-encoding") ||
           eq_ascii_fold(hname, "trailer") ||
           eq_ascii_fold(hname, "host") ||
           eq_ascii_fold(hname, "authorization") ||
           eq_ascii_fold(hname, "proxy-authorization") ||
           eq_ascii_fold(hname, "set-cookie") ||
           eq_ascii_fold(hname, "cookie") ||
           eq_ascii_fold(hname, "content-range") ||
           eq_ascii_fold(hname, "te");
}

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
}

fn parse_chunk_size_hex(chunk_size_line: const u8[:], out_size: u64&) -> ChunkedDecodeError {
    // RFC 9112 Section 7.1.1 & Go #64433 / CVE-2023-39326: Chunk line / extension length bound
    guard chunk_size_line.len <= 1024 else {
        return ChunkedDecodeError.InvalidChunkExtension;
    }

    // RFC 9112 Section 7.1.1: Reject bare CR or non-HTAB control characters in chunk extensions
    for b in chunk_size_line {
        if b == '\r' || (b < 0x20 && b != 0x09) {
            return ChunkedDecodeError.InvalidChunkExtension;
        }
    }

    let semi_idx = core::index_of_byte(chunk_size_line, ';');
    let hex_slice = if semi_idx >= 0 {
        trim_lws(chunk_size_line[..semi_idx])
    } else {
        trim_lws(chunk_size_line)
    };

    guard hex_slice.len > 0 && hex_slice.len <= 16 else {
        return ChunkedDecodeError.InvalidChunkSizeHex;
    }

    var chunk_size: u64 = 0;
    for b in hex_slice {
        let val = core::hex_digit_to_val(b);
        guard val >= 0 else {
            return ChunkedDecodeError.InvalidChunkSizeHex;
        }
        if chunk_size > 0x0FFFFFFFFFFFFFFF {
            return ChunkedDecodeError.ChunkSizeOverflow;
        }
        chunk_size = (chunk_size << 4) | (val as! u64);
    }

    out_size = chunk_size;
    return ChunkedDecodeError.None;
}

// RFC 9112 Section 7.1.2: Parse chunked trailers and populate out_trailers list
fn parse_chunked_trailers_with_out(raw: const u8[:], cursor: i64&, out_trailers: HeaderItem[..16]&) -> ChunkedDecodeError {
    var trailer_count: i32 = 0;
    var total_trailer_bytes: i64 = 0;
    let max_trailers: i32 = 16;
    let max_trailer_bytes: i64 = 4096;

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
        guard trailer_count <= max_trailers else {
            return ChunkedDecodeError.DisallowedTrailer;
        }
        total_trailer_bytes += tr_line.len;
        guard total_trailer_bytes <= max_trailer_bytes else {
            return ChunkedDecodeError.DisallowedTrailer;
        }

        let col_idx = core::index_of_byte(tr_line, ':');
        guard col_idx > 0 else {
            return ChunkedDecodeError.DisallowedTrailer;
        }

        // RFC 9112 Section 5.1 & Go #81143 / CVE-2019-16276:
        // Reject whitespace before colon or non-tchar bytes in trailer field-name (no normalization).
        let hname = tr_line[..col_idx];
        guard is_valid_header_name(hname) else {
            return ChunkedDecodeError.DisallowedTrailer;
        }
        if is_disallowed_trailer_field(hname) {
            return ChunkedDecodeError.DisallowedTrailer;
        }

        let val_slice = tr_line[(col_idx + 1)..];
        let trimmed_val = trim_lws(val_slice);
        guard is_valid_header_value(trimmed_val) else {
            return ChunkedDecodeError.DisallowedTrailer;
        }
        guard out_trailers.len < out_trailers.cap else {
            return ChunkedDecodeError.DisallowedTrailer;
        }

        var item = HeaderItem { .. };
        guard hname.len <= item.name.cap && trimmed_val.len <= item.value.cap else {
            return ChunkedDecodeError.DisallowedTrailer;
        }
        item.name.append(hname);
        item.value.append(trimmed_val);
        out_trailers.push(item);
    }
    return ChunkedDecodeError.UnexpectedEof;
}

fn parse_chunked_trailers(raw: const u8[:], cursor: i64&) -> ChunkedDecodeError {
    var dummy: HeaderItem[..16] = [];
    return parse_chunked_trailers_with_out(raw, cursor, dummy);
}

// Decodes a chunked transfer-encoded payload into out_body and extracts trailers (RFC 9112 Section 7.1).
// Returns (status_error, total_bytes_consumed_from_raw).
fn decode_chunked_body_with_trailers(
    raw: const u8[:],
    out_body: u8[>..]&,
    out_trailers: HeaderItem[..16]&
) -> ChunkedDecodeError, i64 {
    guard raw.len > 0 else { return ChunkedDecodeError.EmptyInput, 0; }

    var cursor: i64 = 0;
    while cursor < raw.len {
        let rel_nl = core::index_of_byte(raw[cursor..], '\n');
        guard rel_nl >= 0 else { return ChunkedDecodeError.UnexpectedEof, 0; }
        let line_end = cursor + rel_nl;

        if line_end == cursor || raw[line_end - 1] != '\r' {
            return ChunkedDecodeError.BareLfInChunkSize, 0;
        }

        let chunk_size_line = raw[cursor..line_end - 1];
        var chunk_size: u64 = 0;
        let size_err = parse_chunk_size_hex(chunk_size_line, chunk_size);
        guard size_err == ChunkedDecodeError.None else { return size_err, 0; }

        cursor = line_end + 1;

        if chunk_size == 0 {
            let tr_err = parse_chunked_trailers_with_out(raw, cursor, out_trailers);
            if tr_err == ChunkedDecodeError.None {
                return ChunkedDecodeError.None, cursor;
            }
            return tr_err, 0;
        }

        // Guard 64-bit signed cast & addition overflow (e.g. FFFFFFFFFFFFFFFF\r\n)
        guard chunk_size <= (raw.len as u64) else {
            if chunk_size > 0x7FFFFFFFFFFFFFF0 {
                return ChunkedDecodeError.ChunkSizeOverflow, 0;
            }
            return ChunkedDecodeError.UnexpectedEof, 0;
        }
        let csize = chunk_size as! i64;
        guard csize <= raw.len - cursor - 2 else {
            return ChunkedDecodeError.UnexpectedEof, 0;
        }

        let chunk_data = raw[cursor..cursor + csize];
        out_body.append(chunk_data);
        cursor += csize;

        if raw[cursor] == '\n' {
            return ChunkedDecodeError.BareLfInChunkData, 0;
        }
        guard raw[cursor] == '\r' && raw[cursor + 1] == '\n' else {
            return ChunkedDecodeError.MalformedChunkEnding, 0;
        }
        cursor += 2;
    }

    return ChunkedDecodeError.UnexpectedEof, 0;
}

// Decodes a chunked transfer-encoded payload into out_body (RFC 9112 Section 7.1).
// Chunk size lines and data chunks must end with CRLF; bare LF returns an error.
fn decode_chunked_body(raw: const u8[:], out_body: u8[>..]&) -> ChunkedDecodeError {
    var dummy: HeaderItem[..16] = [];
    let err, _ = decode_chunked_body_with_trailers(raw, out_body, dummy);
    return err;
}
