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

// Compresses src into out using RFC 1952 Gzip format.
fn gzip_compress<B>(src: const u8[:], out: B&, level: i32 = 6) -> bool {
    // 10-byte standard Gzip header
    out.push(GZIP_ID1);
    out.push(GZIP_ID2);
    out.push(GZIP_CM_DEFLATE);
    out.push(0); // FLG = 0 (no extra, no name, no comment, no crc16)
    out.push(0); // MTIME (4 bytes 0 = no timestamp)
    out.push(0);
    out.push(0);
    out.push(0);
    out.push(if level >= 6 { 2 } else { 4 }); // XFL (2 = max compression, 4 = fastest)
    out.push(3); // OS = 3 (Unix)

    // Deflate compressed payload
    guard deflate(src, out, level) else { return false; }

    // 8-byte footer: CRC-32 (4 bytes LE) + ISIZE (4 bytes LE)
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

// Decompresses RFC 1952 Gzip stream from src into out.
// Validates headers, flags, deflate stream, CRC-32, and uncompressed size.
fn gzip_decompress<B>(src: const u8[:], out: B&) -> CompressError {
    guard src.len >= 18 else { return CompressError.InputBufferTruncated; }

    guard src[0] == GZIP_ID1 && src[1] == GZIP_ID2 else {
        return CompressError.InvalidHeader;
    }
    guard src[2] == GZIP_CM_DEFLATE else {
        return CompressError.InvalidHeader;
    }

    let flg = src[3];
    var offset: i64 = 10;

    // FEXTRA
    if (flg & GZIP_FLG_FEXTRA) != 0 {
        guard offset + 2 <= src.len else { return CompressError.InputBufferTruncated; }
        let xlen = (src[offset] as i64) | ((src[offset + 1] as i64) << 8);
        offset += 2 + xlen;
        guard offset <= src.len else { return CompressError.InputBufferTruncated; }
    }

    // FNAME (null-terminated string)
    if (flg & GZIP_FLG_FNAME) != 0 {
        while offset < src.len && src[offset] != 0 {
            offset++;
        }
        guard offset < src.len else { return CompressError.InputBufferTruncated; }
        offset++; // Skip trailing null
    }

    // FCOMMENT (null-terminated string)
    if (flg & GZIP_FLG_FCOMMENT) != 0 {
        while offset < src.len && src[offset] != 0 {
            offset++;
        }
        guard offset < src.len else { return CompressError.InputBufferTruncated; }
        offset++; // Skip trailing null
    }

    // FHCRC (2-byte header CRC16)
    if (flg & GZIP_FLG_FHCRC) != 0 {
        guard offset + 2 <= src.len else { return CompressError.InputBufferTruncated; }
        offset += 2;
    }

    guard offset + 8 <= src.len else { return CompressError.InputBufferTruncated; }

    let deflate_end = src.len - 8;
    guard offset <= deflate_end else { return CompressError.InputBufferTruncated; }

    let deflate_payload = src[offset..deflate_end];
    let out_start = out.len;

    let err = inflate(deflate_payload, out);
    guard err == CompressError.None else { return err; }

    let decomp_slice = out[out_start..];

    // Validate 8-byte trailer
    let expected_crc = (src[deflate_end] as u32) |
                       ((src[deflate_end + 1] as u32) << 8) |
                       ((src[deflate_end + 2] as u32) << 16) |
                       ((src[deflate_end + 3] as u32) << 24);

    let expected_isize = (src[deflate_end + 4] as u32) |
                         ((src[deflate_end + 5] as u32) << 8) |
                         ((src[deflate_end + 6] as u32) << 16) |
                         ((src[deflate_end + 7] as u32) << 24);

    let actual_crc = crc32(decomp_slice);
    guard actual_crc == expected_crc else {
        return CompressError.ChecksumMismatch;
    }

    let actual_isize = (decomp_slice.len as u64) & 0xFFFFFFFF;
    guard (actual_isize as u32) == expected_isize else {
        return CompressError.SizeMismatch;
    }

    return CompressError.None;
}
