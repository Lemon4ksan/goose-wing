// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

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
        write_be_u32(out, adler32(dict));
    }

    // Deflate compressed payload
    guard deflate_with_dict(src, out, level, dict) else {
        out.clear();
        return false;
    }

    // 4-byte Adler-32 in Big-Endian
    write_be_u32(out, adler32(src));

    return true;
}

// Compresses src into out using RFC 1950 Zlib format.
fn zlib_compress<B>(src: const u8[:], out: B&, level: i32 = 6) -> bool {
    return zlib_compress_with_dict(src, out, level, "");
}

// Decompresses RFC 1950 Zlib stream from src into out with optional preset dictionary and quota guard.
// Validates headers, FCHECK, DICTID, and Adler-32 checksum.
fn zlib_decompress_with_dict_limit<B>(
    src:              const u8[:],
    out:              B&,
    dict:             const u8[:] = "",
    max_output_bytes: i64         = 0,
) -> CompressError {
    guard src.len >= 6 else { return CompressError.InputBufferTruncated; }

    let cmf: u32 = src[0];
    let flg: u32 = src[1];
    guard (cmf * 256 + flg) % 31 == 0 && (cmf & 0x0F) == 8 && (cmf >> 4) <= 7 else {
        return CompressError.InvalidHeader;
    }

    var deflate_start: i64 = 2;
    if ((flg >> 5) & 1) != 0 {
        guard src.len >= 10 else { return CompressError.InputBufferTruncated; }
        guard dict.len > 0 else { return CompressError.NeedDictionary; }
        guard adler32(dict) == read_be_u32(src, 2) else {
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

    guard adler32(out[out_start..]) == read_be_u32(src, adler_offset) else {
        return CompressError.ChecksumMismatch;
    }
    // RFC 1950 exact finality: Zlib streams do not concatenate; trailing data indicates bitstream corruption
    guard adler_offset + 4 == src.len else {
        return CompressError.CorruptedBitstream;
    }
    return CompressError.None;
}

// Decompresses RFC 1950 Zlib stream from src into out with optional preset dictionary.
fn zlib_decompress_with_dict<B>(src: const u8[:], out: B&, dict: const u8[:] = "") -> bool, CompressError {
    let err = zlib_decompress_with_dict_limit(src, out, dict, 0);
    return err == CompressError.None, err;
}

// Decompresses RFC 1950 Zlib stream from src into out.
// Validates headers, FCHECK, Adler-32 checksum.
fn zlib_decompress<B>(src: const u8[:], out: B&) -> bool, CompressError {
    let err = zlib_decompress_with_dict_limit(src, out, "", 0);
    return err == CompressError.None, err;
}

// Decompresses RFC 1950 Zlib stream with output quota guard (preventing decompression bombs).
fn zlib_decompress_with_limit<B>(src: const u8[:], out: B&, max_output_bytes: i64) -> bool, CompressError {
    let err = zlib_decompress_with_dict_limit(src, out, "", max_output_bytes);
    return err == CompressError.None, err;
}
