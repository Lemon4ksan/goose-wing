// The Goose Zlib compression container: RFC 1950 Specification.
namespace core;

import std;
import core.compress.checksum;
import core.compress.deflate;

// Compresses src into out using RFC 1950 Zlib format with optional preset dictionary.
fn zlib_compress_with_dict<B>(src: const u8[:], out: B&, level: i32 = 6, dict: const u8[:] = "") -> bool {
    let cmf: u8 = 0x78; // CM=8 (deflate), CINFO=7 (32K window)
    var flg: u32 = if level >= 6 { 0x80 } else { 0x00 }; // FLEVEL

    if dict.len > 0 {
        flg |= 0x20; // FDICT bit
    }

    // Compute FCHECK such that (CMF * 256 + FLG) is a multiple of 31
    let rem = ((cmf as u32) * 256 + flg) % 31;
    if rem != 0 {
        flg += 31 - rem;
    }

    out.push(cmf);
    out.push((flg & 0xFF) as u8);

    if dict.len > 0 {
        let dict_adler = adler32(dict);
        out.push(((dict_adler >> 24) & 0xFF) as u8);
        out.push(((dict_adler >> 16) & 0xFF) as u8);
        out.push(((dict_adler >> 8) & 0xFF) as u8);
        out.push((dict_adler & 0xFF) as u8);
    }

    // Deflate compressed payload
    guard deflate_with_dict(src, out, level, dict) else { return false; }

    // 4-byte Adler-32 in Big-Endian
    let a = adler32(src);
    out.push(((a >> 24) & 0xFF) as u8);
    out.push(((a >> 16) & 0xFF) as u8);
    out.push(((a >> 8) & 0xFF) as u8);
    out.push((a & 0xFF) as u8);

    return true;
}

// Compresses src into out using RFC 1950 Zlib format.
fn zlib_compress<B>(src: const u8[:], out: B&, level: i32 = 6) -> bool {
    return zlib_compress_with_dict(src, out, level, "");
}

// Reads a 32-bit big-endian unsigned integer from src at offset.
fn read_zlib_u32_be(src: const u8[:], offset: i64) -> u32 {
    return read_be_u32(src, offset);
}

// Decompresses RFC 1950 Zlib stream from src into out with optional preset dictionary and quota guard.
// Validates headers, FCHECK, DICTID, and Adler-32 checksum.
fn zlib_decompress_with_dict_limit<B>(
    src: const u8[:],
    out: B&,
    dict: const u8[:] = "",
    max_output_bytes: i64 = 0,
) -> CompressError {
    guard src.len >= 6 else { return CompressError.InputBufferTruncated; }

    let cmf: u32 = src[0];
    let flg: u32 = src[1];
    guard (cmf * 256 + flg) % 31 == 0 && (cmf & 0x0F) == 8 else {
        return CompressError.InvalidHeader;
    }

    var deflate_start: i64 = 2;
    if ((flg >> 5) & 1) != 0 {
        guard src.len >= 10 else { return CompressError.InputBufferTruncated; }
        guard dict.len > 0 else { return CompressError.NeedDictionary; }
        guard adler32(dict) == read_zlib_u32_be(src, 2) else {
            return CompressError.DictionaryMismatch;
        }
        deflate_start = 6;
    }

    guard deflate_start + 4 <= src.len else { return CompressError.InputBufferTruncated; }

    let out_start = out.len;
    let err, consumed = inflate_ex(src[deflate_start..], out, dict, max_output_bytes);
    guard err == CompressError.None else { return err; }

    let adler_offset = deflate_start + consumed;
    guard adler_offset + 4 <= src.len else { return CompressError.InputBufferTruncated; }

    guard adler32(out[out_start..]) == read_zlib_u32_be(src, adler_offset) else {
        return CompressError.ChecksumMismatch;
    }
    return CompressError.None;
}

// Decompresses RFC 1950 Zlib stream from src into out with optional preset dictionary.
fn zlib_decompress_with_dict<B>(src: const u8[:], out: B&, dict: const u8[:] = "") -> CompressError {
    return zlib_decompress_with_dict_limit(src, out, dict, 0);
}

// Decompresses RFC 1950 Zlib stream from src into out.
// Validates headers, FCHECK, Adler-32 checksum.
fn zlib_decompress<B>(src: const u8[:], out: B&) -> CompressError {
    return zlib_decompress_with_dict_limit(src, out, "", 0);
}

// Decompresses RFC 1950 Zlib stream with output quota guard (preventing decompression bombs).
fn zlib_decompress_with_limit<B>(src: const u8[:], out: B&, max_output_bytes: i64) -> CompressError {
    return zlib_decompress_with_dict_limit(src, out, "", max_output_bytes);
}
