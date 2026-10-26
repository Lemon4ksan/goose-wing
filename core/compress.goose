// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// The Goose standard compression subsystem: candidate for `core::compress`.
//
// Clean-Room Native Implementations:
// 1. Checksums : IEEE 802.3 CRC-32 (0xEDB88320) & RFC 1950 Adler-32.
// 2. Deflate   : RFC 1951 Deflate compressor & Inflate decompressor (LZ77 + Canonical Huffman).
// 3. Gzip      : RFC 1952 Gzip stream compressor & decompressor with header/trailer validation.
// 4. Zlib      : RFC 1950 Zlib container format.
// 5. Zstandard : RFC 8878 Zstandard container format.
// 6. Brotli    : RFC 7932 Brotli container format.
// 7. Streaming : ZStream streaming codecs, flush modes, and auto-detection.
//
// Zero Heap Memory Model:
// - All allocations operate on Data Stacks via bump-pointers and bounded arrays.
// - Sliding windows (32 KB), hash chains, and Huffman tables require 0 malloc calls.
// - Compliant with the Goose for C++ and Rust Programmers architecture.
namespace core;

import std;
import core.compress.checksum;
import core.compress.deflate;
import core.compress.gzip;
import core.compress.zlib;
import core.compress.stream;
import core.compress.zstd;
import core.compress.brotli_dict;
import core.compress.brotli;
