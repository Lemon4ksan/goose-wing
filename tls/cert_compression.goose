// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 8879 TLS Certificate Compression Engine.
// Supports Brotli and Zstandard decompression of X.509 Certificate chains in TLS 1.3.
namespace internal;

import std;
import core from "..";

// ---- CompressedCertificate Message Model ---------------------------------

// RFC 8879 Section 4: Compressed Certificate Message - Structure
struct CompressedCertificate {
    algorithm:                      u16         = rfc::CERT_COMPRESSION_BROTLI,
    uncompressed_length:            u32         = 0,
    compressed_certificate_message: const u8[:] = "",
}

// ---- Wire Encoding and Decoding (RFC 8879 §4) -----------------------------

// RFC 8879 Section 4: Compressed Certificate Message - Serializer
fn encode_compressed_certificate<B>(
    msg: const CompressedCertificate&,
    out: B&,
) -> bool {
    guard msg.uncompressed_length > 0 && msg.uncompressed_length <= rfc::MAX_UNCOMPRESSED_CERT_SIZE else {
        return false;
    }
    guard msg.compressed_certificate_message.len >= 1
        && msg.compressed_certificate_message.len <= (rfc::MAX_UNCOMPRESSED_CERT_SIZE as i64) else {
        return false;
    }
    guard rfc::is_valid_compression_algorithm(msg.algorithm) else { return false; }

    var b = core::builder_init();
    b.put_u16(msg.algorithm);
    b.put_u24(msg.uncompressed_length);
    // RFC 8879 §4 / RFC 8446 §3.4: opaque compressed_certificate_message<1..2^24-1>
    guard b.start_u24_prefix() else { return false; }
    b.put_bytes(msg.compressed_certificate_message);
    guard b.finish_u24_prefix() else { return false; }
    return out.try_append(b.buf[..]);
}

// RFC 8879 Section 4: Compressed Certificate Message - Parser
//
// Example:
//   raw = [0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, ... (compressed data)]
//   returns: ok = true, msg.algorithm = 2, msg.uncompressed_length = 256, msg.compressed_certificate_message = slice
fn parse_compressed_certificate_msg(
    raw: const u8[:],
    out: CompressedCertificate&,
) -> bool {
    var c = core::cursor_from(raw);
    let algo, ok_a = c.read_u16();
    var ulen: u32 = 0;
    let ok_u = c.get_u24(ulen);
    let comp_cursor, ok_c = c.read_u24_sub_cursor();
    guard ok_a && ok_u && ok_c && c.buf.len == 0 else { return false; }
    guard rfc::is_valid_compression_algorithm(algo) else { return false; }
    guard ulen > 0 && ulen <= rfc::MAX_UNCOMPRESSED_CERT_SIZE else { return false; }

    let comp_len = comp_cursor.buf.len as u32;
    guard comp_len >= 1 && rfc::is_within_decompression_ratio(ulen, comp_len) else { return false; }

    out.algorithm = algo;
    out.uncompressed_length = ulen;
    out.compressed_certificate_message = comp_cursor.buf;
    return true;
}

// ---- Safe Decompression Engine (RFC 8879 §4) ------------------------------

// RFC 8879 Section 4: Compressed Certificate Message - Safe Decompression Handler
// Verifies uncompressed size against maximum buffer bound and prevents decompression bombs.
fn decompress_certificate_message<B>(
    msg:             CompressedCertificate,
    max_allowed_len: u32,
    out_cert:        B&,
) -> bool {
    guard msg.uncompressed_length > 0 && msg.uncompressed_length <= max_allowed_len else { return false; }
    let comp_len = msg.compressed_certificate_message.len as u32;
    guard rfc::is_within_decompression_ratio(msg.uncompressed_length, comp_len) else {
        return false;
    }
    return decompress_certificate_payload(
        msg.compressed_certificate_message,
        msg.algorithm,
        msg.uncompressed_length,
        out_cert,
    );
}

fn decompress_certificate_payload<B>(
    comp_data:    const u8[:],
    algo:         u16,
    expected_len: u32,
    out_cert:     B&,
) -> bool {
    guard expected_len <= rfc::MAX_UNCOMPRESSED_CERT_SIZE else { return false; }
    if algo == rfc::CERT_COMPRESSION_BROTLI {
        return decompress_certificate_brotli(comp_data, expected_len, out_cert);
    }
    if algo == rfc::CERT_COMPRESSION_ZLIB {
        return decompress_certificate_zlib(comp_data, expected_len, out_cert);
    }
    if algo == rfc::CERT_COMPRESSION_ZSTD {
        return decompress_certificate_zstd(comp_data, expected_len, out_cert);
    }
    return false;
}

// RFC 8879 Section 4: Compressed Certificate Handshake Message - Decompress Brotli Certificate
// Decompresses raw Brotli stream with exact uncompressed length verification.
fn decompress_certificate_brotli<B>(
    compressed_data:  const u8[:],
    uncompressed_len: u32,
    out_cert:         B&,
) -> bool {
    guard uncompressed_len > 0 && uncompressed_len <= rfc::MAX_UNCOMPRESSED_CERT_SIZE else { return false; }
    guard (uncompressed_len as i64) <= out_cert.cap else { return false; }
    out_cert.clear();
    let ok, _ = core::brotli_decompress_with_limit(compressed_data, out_cert, uncompressed_len as i64);
    guard ok && (out_cert.len as u32) == uncompressed_len else {
        out_cert.clear();
        return false;
    }
    return true;
}

// Decompresses raw zlib stream with exact uncompressed length verification.
fn decompress_certificate_zlib<B>(
    compressed_data:  const u8[:],
    uncompressed_len: u32,
    out_cert:         B&,
) -> bool {
    guard uncompressed_len > 0 && uncompressed_len <= rfc::MAX_UNCOMPRESSED_CERT_SIZE else { return false; }
    guard (uncompressed_len as i64) <= out_cert.cap else { return false; }
    out_cert.clear();
    let ok, _ = core::zlib_decompress_with_limit(compressed_data, out_cert, uncompressed_len as i64);
    guard ok && (out_cert.len as u32) == uncompressed_len else {
        out_cert.clear();
        return false;
    }
    return true;
}

// Decompresses raw Zstandard stream with exact uncompressed length verification.
fn decompress_certificate_zstd<B>(
    compressed_data:  const u8[:],
    uncompressed_len: u32,
    out_cert:         B&,
) -> bool {
    guard uncompressed_len > 0 && uncompressed_len <= rfc::MAX_UNCOMPRESSED_CERT_SIZE else { return false; }
    guard (uncompressed_len as i64) <= out_cert.cap else { return false; }
    out_cert.clear();
    let ok, _ = core::zstd_decompress_with_limit(compressed_data, out_cert, uncompressed_len as i64);
    guard ok && (out_cert.len as u32) == uncompressed_len else {
        out_cert.clear();
        return false;
    }
    return true;
}
