// The Goose Gzip compression container: RFC 1952 Specification.
namespace wing;

import std;
import core.compress.checksum;
import core.compress.deflate;

const GZIP_ID1: u8 = 0x1F;
const GZIP_ID2: u8 = 0x8B;
const GZIP_CM_DEFLATE: u8 = 8;

const GZIP_FLG_FTEXT: u8 = 0x01;
const GZIP_FLG_FHCRC: u8 = 0x02;
const GZIP_FLG_FEXTRA: u8 = 0x04;
const GZIP_FLG_FNAME: u8 = 0x08;
const GZIP_FLG_FCOMMENT: u8 = 0x10;

// Compresses src into out using RFC 1952 Gzip format with full metadata (filename, comment, FHCRC).
fn gzip_compress_with_header<B>(
    src: const u8[:],
    out: B&,
    level: i32 = 6,
    filename: const u8[:] = "",
    comment: const u8[:] = "",
    include_fhcrc: bool = false,
) -> bool {
    let out_start = out.len;
    var flg: u8 = 0;
    if filename.len > 0 { flg |= GZIP_FLG_FNAME; }
    if comment.len > 0 { flg |= GZIP_FLG_FCOMMENT; }
    if include_fhcrc { flg |= GZIP_FLG_FHCRC; }

    out.push(GZIP_ID1);
    out.push(GZIP_ID2);
    out.push(GZIP_CM_DEFLATE);
    out.push(flg);
    out.push(0); // MTIME (4 bytes 0)
    out.push(0);
    out.push(0);
    out.push(0);
    out.push(if level >= 6 { 2 } else { 4 }); // XFL
    out.push(3); // OS = Unix

    if filename.len > 0 {
        for i in filename.len {
            out.push(filename[i]);
        }
        out.push(0); // Null terminator
    }

    if comment.len > 0 {
        for i in comment.len {
            out.push(comment[i]);
        }
        out.push(0); // Null terminator
    }

    if include_fhcrc {
        let hdr_bytes = out[out_start..];
        let h_crc = crc32(hdr_bytes) & 0xFFFF;
        out.push((h_crc & 0xFF) as u8);
        out.push(((h_crc >> 8) & 0xFF) as u8);
    }

    guard deflate(src, out, level) else { return false; }

    let c = crc32(src);
    out.push((c & 0xFF) as u8);
    out.push(((c >> 8) & 0xFF) as u8);
    out.push(((c >> 16) & 0xFF) as u8);
    out.push(((c >> 24) & 0xFF) as u8);

    let isize = (src.len as u64) & 0xFFFFFFFF;
    out.push((isize & 0xFF) as u8);
    out.push(((isize >> 8) & 0xFF) as u8);
    out.push(((isize >> 16) & 0xFF) as u8);
    out.push(((isize >> 24) & 0xFF) as u8);

    return true;
}

// Compresses src into out using standard RFC 1952 Gzip format.
fn gzip_compress<B>(src: const u8[:], out: B&, level: i32 = 6) -> bool {
    return gzip_compress_with_header(src, out, level, "", "", false);
}

// Reads a 32-bit little-endian unsigned integer from src at offset.
fn read_gzip_u32_le(src: const u8[:], offset: i64) -> u32 {
    let b0 = src[offset] as u32;
    let b1 = (src[offset + 1] as u32) << 8;
    let b2 = (src[offset + 2] as u32) << 16;
    let b3 = (src[offset + 3] as u32) << 24;
    return b0 | b1 | b2 | b3;
}

// Advances offset past a null-terminated header string in src.
fn skip_gzip_cstring(src: const u8[:], offset: i64) -> i64, bool {
    var pos = offset;
    while pos < src.len && src[pos] != 0 {
        pos++;
    }
    guard pos < src.len else { return pos, false; }
    return pos + 1, true;
}

// Validates the RFC 1952 Gzip header and returns the payload start offset.
// Supports FEXTRA, FNAME, FCOMMENT, and FHCRC (validating the 16-bit header CRC32).
fn parse_gzip_header_offset(src: const u8[:], start: i64) -> i64, CompressError {
    guard start + 10 <= src.len else { return start, CompressError.InputBufferTruncated; }
    guard src[start] == GZIP_ID1 && src[start + 1] == GZIP_ID2 && src[start + 2] == GZIP_CM_DEFLATE else {
        return start, CompressError.InvalidHeader;
    }

    let flg = src[start + 3];
    var offset: i64 = start + 10;

    if (flg & GZIP_FLG_FEXTRA) != 0 {
        guard offset + 2 <= src.len else { return start, CompressError.InputBufferTruncated; }
        let xlen = src[offset] | ((src[offset + 1] as i64) << 8);
        offset += 2 + xlen;
        guard offset <= src.len else { return start, CompressError.InputBufferTruncated; }
    }
    if (flg & GZIP_FLG_FNAME) != 0 {
        let next_off, ok = skip_gzip_cstring(src, offset);
        guard ok else { return start, CompressError.InputBufferTruncated; }
        offset = next_off;
    }
    if (flg & GZIP_FLG_FCOMMENT) != 0 {
        let next_off, ok = skip_gzip_cstring(src, offset);
        guard ok else { return start, CompressError.InputBufferTruncated; }
        offset = next_off;
    }
    if (flg & GZIP_FLG_FHCRC) != 0 {
        guard offset + 2 <= src.len else { return start, CompressError.InputBufferTruncated; }
        let expected_crc16 = src[offset] | ((src[offset + 1] as u32) << 8);
        let actual_crc16 = crc32(src[start..offset]) & 0xFFFF;
        guard expected_crc16 == actual_crc16 else { return start, CompressError.ChecksumMismatch; }
        offset += 2;
    }
    return offset, CompressError.None;
}

// Decompresses RFC 1952 Gzip stream from src into out with output quota guard.
// Fully supports concatenated Gzip members (RFC 1952 multi-member streams) and FHCRC.
fn gzip_decompress_with_limit<B>(src: const u8[:], out: B&, max_output_bytes: i64 = 0) -> CompressError {
    guard src.len > 0 else { return CompressError.InputBufferTruncated; }
    var offset: i64 = 0;

    while offset < src.len {
        let member_start = offset;
        let payload_offset, hdr_err = parse_gzip_header_offset(src, member_start);
        guard hdr_err == CompressError.None else { return hdr_err; }

        let member_out_start = out.len;
        let err, consumed = inflate_ex(src[payload_offset..], out, "", max_output_bytes);
        guard err == CompressError.None else { return err; }

        let trailer_offset = payload_offset + consumed;
        guard trailer_offset + 8 <= src.len else { return CompressError.InputBufferTruncated; }

        let decomp_slice = out[member_out_start..];
        let expected_crc = read_gzip_u32_le(src, trailer_offset);
        let expected_isize = read_gzip_u32_le(src, trailer_offset + 4);

        guard crc32(decomp_slice) == expected_crc else {
            return CompressError.ChecksumMismatch;
        }
        let actual_isize = ((decomp_slice.len as u64) & 0xFFFFFFFF) as u32;
        guard actual_isize == expected_isize else {
            return CompressError.SizeMismatch;
        }

        offset = trailer_offset + 8;
    }

    return CompressError.None;
}

// Decompresses RFC 1952 Gzip stream from src into out.
// Validates headers, flags (including FHCRC), concatenated members, CRC-32, and ISIZE.
fn gzip_decompress<B>(src: const u8[:], out: B&) -> CompressError {
    return gzip_decompress_with_limit(src, out, 0);
}
