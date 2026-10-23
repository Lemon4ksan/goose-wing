// The Goose standard compression subsystem: candidate for `core::compress`.
//
// Clean-Room Native Implementations:
// 1. Checksums : IEEE 802.3 CRC-32 (0xEDB88320) & RFC 1950 Adler-32.
// 2. Deflate   : RFC 1951 Deflate compressor & Inflate decompressor (LZ77 + Canonical Huffman).
// 3. Gzip      : RFC 1952 Gzip stream compressor & decompressor with header/trailer validation.
// 4. Zlib      : RFC 1950 Zlib container format.
//
// Zero Heap Memory Model:
// - All allocations operate on Data Stacks via bump-pointers and bounded arrays.
// - Sliding windows (32 KB), hash chains, and Huffman tables require 0 malloc calls.
// - Compliant with the Goose for C++ and Rust Programmers architecture.
namespace wing;

import std;
import core.compress.checksum;
import core.compress.deflate;
import core.compress.gzip;
import core.compress.zlib;
import core.compress.stream;

// Compresses input slice using Gzip format into out_buf. Returns true on success.
fn compress_gzip<B>(src: const u8[:], out_buf: B&, level: i32 = 6) -> bool {
    return gzip_compress(src, out_buf, level);
}

// Decompresses Gzip stream from in_buf into out_buf. Returns (true, CompressError.None) on success.
fn decompress_gzip<B>(in_buf: const u8[:], out_buf: B&) -> bool, CompressError {
    let err = gzip_decompress(in_buf, out_buf);
    return err == CompressError.None, err;
}

// Compresses input slice using Zlib format into out_buf. Returns true on success.
fn compress_zlib<B>(src: const u8[:], out_buf: B&, level: i32 = 6) -> bool {
    return zlib_compress(src, out_buf, level);
}

// Compresses input slice using Zlib format with a preset dictionary.
fn compress_zlib_dict<B>(src: const u8[:], out_buf: B&, level: i32 = 6, dict: const u8[:] = "") -> bool {
    return zlib_compress_with_dict(src, out_buf, level, dict);
}

// Decompresses Zlib stream from in_buf into out_buf. Returns (true, CompressError.None) on success.
fn decompress_zlib<B>(in_buf: const u8[:], out_buf: B&) -> bool, CompressError {
    let err = zlib_decompress(in_buf, out_buf);
    return err == CompressError.None, err;
}

// Decompresses Zlib stream with a preset dictionary.
fn decompress_zlib_dict<B>(in_buf: const u8[:], out_buf: B&, dict: const u8[:] = "") -> bool, CompressError {
    let err = zlib_decompress_with_dict(in_buf, out_buf, dict);
    return err == CompressError.None, err;
}

// Compresses input slice using raw RFC 1951 Deflate into out_buf.
fn compress_deflate<B>(src: const u8[:], out_buf: B&, level: i32 = 6) -> bool {
    return deflate(src, out_buf, level);
}

// Compresses input slice using raw Deflate with a preset dictionary.
fn compress_deflate_dict<B>(src: const u8[:], out_buf: B&, level: i32 = 6, dict: const u8[:] = "") -> bool {
    return deflate_with_dict(src, out_buf, level, dict);
}

// Decompresses raw RFC 1951 Deflate stream from in_buf into out_buf.
fn decompress_deflate<B>(in_buf: const u8[:], out_buf: B&) -> bool, CompressError {
    let err = inflate(in_buf, out_buf);
    return err == CompressError.None, err;
}

// Decompresses raw Deflate stream with a preset dictionary.
fn decompress_deflate_dict<B>(in_buf: const u8[:], out_buf: B&, dict: const u8[:] = "") -> bool, CompressError {
    let err = inflate_with_dict(in_buf, out_buf, dict);
    return err == CompressError.None, err;
}

// Universal auto-detecting decompressor: automatically determines container format (Gzip, Zlib, Deflate).
fn decompress<B>(in_buf: const u8[:], out_buf: B&, dict: const u8[:] = "") -> bool, CompressError {
    let err = decompress_auto(in_buf, out_buf, dict);
    return err == CompressError.None, err;
}
