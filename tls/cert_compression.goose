// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 8879 TLS Certificate Compression Engine.
// Supports Brotli and Zstandard decompression of X.509 Certificate chains in TLS 1.3.
namespace internal;

import std;
import core from "..";

// ---- 1. RFC 8879 Compression Algorithm Identifiers -------------------------

// RFC 8879 Section 3: Negotiating Certificate Compression - Compression Algorithm Identifiers
const CERT_COMPRESSION_ZLIB:      u16 = 1; // RFC 8879 Section 3 (zlib)
const CERT_COMPRESSION_BROTLI:    u16 = 2; // RFC 8879 Section 3 (brotli)
const CERT_COMPRESSION_ZSTD:      u16 = 3; // RFC 8879 Section 3 (zstd)
const CERT_COMPRESSION_ZSTD_IANA: u16 = 3; // RFC 8879 Section 3 official IANA codepoint

// RFC 8879 Section 4: Compressed Certificate Handshake Message - Decompression Ceiling
const MAX_UNCOMPRESSED_CERT_SIZE: u32 = 65536; // 64 KB decompression ceiling (bomb defense)

// RFC 8879 Section 4: Decompression Bomb Ratio Guard - Expansion Ceiling
// Validates uncompressed expansion does not exceed 1024x compression ratio ceiling.
inline fn is_within_decompression_ratio(uncompressed_len: u32, compressed_len: u32) -> bool {
    guard compressed_len > 0 else { return false; }
    guard uncompressed_len <= MAX_UNCOMPRESSED_CERT_SIZE else { return false; }
    return (uncompressed_len >> 10) <= compressed_len;
}

// Returns true if algorithm is recognized by RFC 8879
fn is_valid_compression_algorithm(algo: u16) -> bool {
    return algo == CERT_COMPRESSION_BROTLI
        || algo == CERT_COMPRESSION_ZSTD
        || algo == CERT_COMPRESSION_ZSTD_IANA
        || algo == CERT_COMPRESSION_ZLIB;
}

// ---- 2. CompressedCertificate Message Model ---------------------------------

// RFC 8879 Section 4: Compressed Certificate Handshake Message - Structure
struct CompressedCertificate {
    algorithm:                      u16         = CERT_COMPRESSION_BROTLI,
    uncompressed_length:            u32         = 0,
    compressed_certificate_message: const u8[:] = "",
}

// ---- 3. Wire Encoding and Decoding (RFC 8879 §4) -----------------------------

// RFC 8879 Section 4: Compressed Certificate Handshake Message - Serializer
fn encode_compressed_certificate<B>(
    msg: const CompressedCertificate&,
    out: B&,
) -> bool {
    guard msg.uncompressed_length > 0 && msg.uncompressed_length <= MAX_UNCOMPRESSED_CERT_SIZE else { return false; }
    let comp_len = msg.compressed_certificate_message.len as u32;
    guard comp_len >= 1 && comp_len <= 0xFFFFFF && comp_len <= MAX_UNCOMPRESSED_CERT_SIZE else {
        return false;
    }
    guard is_valid_compression_algorithm(msg.algorithm) else { return false; }

    out.push(((msg.algorithm >> 8) & 0xFF) as u8);
    out.push((msg.algorithm & 0xFF) as u8);
    out.push(((msg.uncompressed_length >> 16) & 0xFF) as u8);
    out.push(((msg.uncompressed_length >> 8) & 0xFF) as u8);
    out.push((msg.uncompressed_length & 0xFF) as u8);
    // RFC 8879 §4 / RFC 8446 §3.4: opaque compressed_certificate_message<1..2^24-1>
    out.push(((comp_len >> 16) & 0xFF) as u8);
    out.push(((comp_len >> 8) & 0xFF) as u8);
    out.push((comp_len & 0xFF) as u8);
    out.append(msg.compressed_certificate_message);
    return true;
}

// RFC 8879 Section 4: Compressed Certificate Handshake Message - Parser
//
// Example:
//   raw = [0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, ... (compressed data)]
//   returns: ok = true, msg.algorithm = 2, msg.uncompressed_length = 256, msg.compressed_certificate_message = slice
fn parse_compressed_certificate_msg(
    raw: const u8[:],
    out: CompressedCertificate&,
) -> bool {
    guard raw.len >= 8 else { return false; }

    let algo = core::read_be_u16(raw, 0);
    guard is_valid_compression_algorithm(algo) else { return false; }

    let ulen = core::read_be_u24(raw, 2);
    guard ulen > 0 && ulen <= MAX_UNCOMPRESSED_CERT_SIZE else { return false; }

    let comp_len = core::read_be_u24(raw, 5);
    guard comp_len >= 1 else { return false; }
    guard (raw.len - 8) as u32 == comp_len else { return false; }

    let comp_data = raw[8..8 + (comp_len as i64)];
    guard is_within_decompression_ratio(ulen, comp_len) else { return false; }

    out.algorithm = algo;
    out.uncompressed_length = ulen;
    out.compressed_certificate_message = comp_data;
    return true;
}

// ---- 4. Safe Decompression Engine (RFC 8879 §4) ------------------------------

// RFC 8879 Section 4: Compressed Certificate Handshake Message - Safe Decompression Handler
// Verifies uncompressed size against maximum buffer bound and prevents decompression bombs.
fn decompress_certificate_message<B>(
    msg:             CompressedCertificate,
    max_allowed_len: u32,
    out_cert:        B&,
) -> bool {
    guard msg.uncompressed_length > 0 && msg.uncompressed_length <= max_allowed_len else { return false; }
    let comp_len = msg.compressed_certificate_message.len as u32;
    guard is_within_decompression_ratio(msg.uncompressed_length, comp_len) else {
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
    if algo == CERT_COMPRESSION_BROTLI {
        let ok, _ = core::brotli_decompress_with_limit(
            comp_data,
            out_cert,
            expected_len as i64,
        );
        guard ok && (out_cert.len as u32) == expected_len else { return false; }
        return true;
    } else if algo == CERT_COMPRESSION_ZLIB {
        let ok, _ = core::zlib_decompress(
            comp_data,
            out_cert,
        );
        guard ok && (out_cert.len as u32) == expected_len else { return false; }
        return true;
    } else if algo == CERT_COMPRESSION_ZSTD || algo == CERT_COMPRESSION_ZSTD_IANA {
        let ok, _ = core::zstd_decompress_with_limit(
            comp_data,
            out_cert,
            expected_len as i64,
        );
        guard ok && (out_cert.len as u32) == expected_len else { return false; }
        return true;
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
    guard uncompressed_len > 0 else { return false; }
    guard is_within_decompression_ratio(uncompressed_len, compressed_data.len as u32) else {
        return false;
    }

    let ok, _ = core::brotli_decompress_with_limit(compressed_data, out_cert, uncompressed_len as i64);
    guard ok && (out_cert.len as u32) == uncompressed_len else { return false; }
    return true;
}
