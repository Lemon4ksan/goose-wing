// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: Core Compression Engine (Deflate, Brotli, Dictionaries) Suite
import std;
import core from "..";
import wing from "..";

// ============================================================================// --- Component: core_compress ---
// Test suite for Goose compression (`core::compress`).
//
// Verification Coverage:
// 1. RFC 1950 Adler-32 & IEEE 802.3 CRC-32 Checksum Standards
// 2. RFC 1951 Deflate & Inflate (Stored and LZ77 + Fixed Huffman)
// 3. RFC 1952 Gzip Container Round-Trip & Header/Footer Verification
// 4. RFC 1950 Zlib Container Round-Trip & Adler-32 Verification
// 5. Extreme & Boundary Vectors (Empty, 1-byte, 35KB Sliding Window Wrap)
// 6. Corrupt Bitstream & Tampering Defenses (Checksum/Size/Truncation detection)

fn test_checksums(t: core::T&) {
    t.run("CRC-32 Known Test Vectors") { sub =>
        let empty_buf: u8[0] = [];
        sub.assert_eq(core::crc32(empty_buf[..]), 0x00000000 as u32, "CRC-32 of empty buffer must be 0x00000000");

        let vec1 = "123456789";
        sub.assert_eq(core::crc32(vec1), 0xCBF43926 as u32, "CRC-32 of 123456789 must match 0xCBF43926");

        let vec2 = "The quick brown fox jumps over the lazy dog";
        sub.assert_eq(core::crc32(vec2), 0x414FA339 as u32, "CRC-32 of fox pangram must match 0x414FA339");

        // Incremental CRC-32
        let part1 = "12345";
        let part2 = "6789";
        let c1 = core::crc32_update(0, part1);
        let c2 = core::crc32_update(c1, part2);
        sub.assert_eq(c2, 0xCBF43926 as u32, "Incremental CRC-32 must match one-shot");
    };

    t.run("Adler-32 Known Test Vectors") { sub =>
        let empty_buf: u8[0] = [];
        sub.assert_eq(core::adler32(empty_buf[..]), 0x00000001 as u32, "Adler-32 of empty buffer must be 1");

        let vec1 = "123456789";
        sub.assert_eq(core::adler32(vec1), 0x091E01DE as u32, "Adler-32 of 123456789 must match 0x091E01DE");

        let vec2 = "The quick brown fox jumps over the lazy dog";
        sub.assert_eq(core::adler32(vec2), 0x5BDC0FDA as u32, "Adler-32 of fox pangram must match 0x5BDC0FDA");

        // Incremental Adler-32
        let part1 = "12345";
        let part2 = "6789";
        let a1 = core::adler32_update(1, part1);
        let a2 = core::adler32_update(a1, part2);
        sub.assert_eq(a2, 0x091E01DE as u32, "Incremental Adler-32 must match one-shot");
    };

    t.run("XXH64 & RFC 8878 Content Checksum Known Vectors") { sub =>
        let empty_buf: u8[0] = [];
        sub.assert_eq(core::xxh64(empty_buf[..], 0), 0xEF46DB3751D8E999 as u64, "XXH64 empty buffer");
        sub.assert_eq(core::xxh64_digest_32(empty_buf[..]), 0x51D8E999 as u32, "RFC 8878 32-bit checksum of empty");

        let s1 = "a";
        sub.assert_eq(core::xxh64(s1, 0), 0xD24EC4F1A98C6E5B as u64, "XXH64 'a'");
        sub.assert_eq(core::xxh64_digest_32(s1), 0xA98C6E5B as u32, "RFC 8878 32-bit checksum of 'a'");

        let s5 = "hello";
        sub.assert_eq(core::xxh64(s5, 0), 0x26C7827D889F6DA3 as u64, "XXH64 'hello'");
        sub.assert_eq(core::xxh64_digest_32(s5), 0x889F6DA3 as u32, "RFC 8878 32-bit checksum of 'hello'");

        let s32 = "12345678901234567890123456789012";
        sub.assert_eq(core::xxh64(s32, 0), 0x40FD1AA52D98274C as u64, "XXH64 32-byte string");
        sub.assert_eq(core::xxh64_digest_32(s32), 0x2D98274C as u32, "RFC 8878 32-bit checksum of 32-byte string");
    };
}

fn test_deflate_stored_and_fixed(t: core::T&) {
    t.run("Deflate Stored Blocks (Level 0)") { sub =>
        let msg = "Stored block mode test: no compression, verbatim payload framing.";
        var comp: u8[>..] = [];
        let ok_c = core::deflate(msg, comp, 0);
        sub.assert_true(ok_c, "Deflate level 0 must succeed");
        sub.assert_true(comp.len > msg.len, "Stored block contains 5-byte framing overhead");

        var decomp: u8[>..] = [];
        let ok_d, err = core::inflate(comp[..], decomp);
        sub.assert_true(ok_d, "Decompress stored block must succeed");
        sub.assert_eq(err, core::CompressError.None, "Error must be None");
        sub.assert_eq(decomp[..], msg, "Decompressed payload must match original");
    };

    t.run("Deflate LZ77 & Fixed Huffman (Level 6)") { sub =>
        let msg = "Hello, world! This is a test of Goose native compression. Hello, world! This is a test!";
        var comp: u8[>..] = [];
        let ok_c = core::deflate(msg, comp, 6);
        sub.assert_true(ok_c, "Deflate level 6 must succeed");

        var decomp: u8[>..] = [];
        let ok_d, err = core::inflate(comp[..], decomp);
        sub.assert_true(ok_d, "Inflate level 6 output must succeed");
        sub.assert_eq(err, core::CompressError.None, "Error must be None");
        sub.assert_eq(decomp[..], msg, "Decompressed payload must match original");
    };

    t.run("Repetitive Data Massive Compression Ratio") { sub =>
        var rep: u8[>..] = [];
        for i in 1000 {
            rep.append("ABCDEFGHIJ");
        }
        sub.assert_eq(rep.len, 10000, "Uncompressed payload is 10,000 bytes");

        var comp: u8[>..] = [];
        let ok_c = core::deflate(rep[..], comp, 6);
        sub.assert_true(ok_c, "Compression must succeed");
        sub.assert_true(comp.len < 150, "10,000 repetitive bytes must compress under 150 bytes");

        var decomp: u8[>..] = [];
        let ok_d, err = core::inflate(comp[..], decomp);
        sub.assert_true(ok_d, "Decompression must succeed");
        sub.assert_eq(err, core::CompressError.None, "Error must be None");
        sub.assert_eq(decomp.len, rep.len, "Length must match");
        sub.assert_eq(decomp[..], rep[..], "Decompressed bytes must match original");
    };
}

fn test_gzip_container(t: core::T&) {
    t.run("Gzip Compression and Decompression Round-Trip") { sub =>
        let payload = "{\"status\":200,\"message\":\"Goose zero-heap compression is lightning fast!\",\"data\":[1,2,3,4,5]}";
        var gz: u8[>..] = [];
        let ok_c = core::gzip_compress(payload, gz, 6);
        sub.assert_true(ok_c, "gzip_compress must succeed");

        // Verify standard Gzip magic bytes (0x1F, 0x8B) and deflate method (8)
        sub.assert_true(gz.len >= 18, "Gzip stream must have at least 18 bytes");
        sub.assert_eq(gz[0], 0x1F, "ID1 must be 0x1F");
        sub.assert_eq(gz[1], 0x8B, "ID2 must be 0x8B");
        sub.assert_eq(gz[2], 0x08, "CM must be 8 (deflate)");

        var restored: u8[>..] = [];
        let ok_d, err = core::gzip_decompress(gz[..], restored);
        sub.assert_true(ok_d, "gzip_decompress must succeed");
        sub.assert_eq(err, core::CompressError.None, "Error must be None");
        sub.assert_eq(restored[..], payload, "Restored content must match original");
    };

    t.run("Gzip Checksum Tampering Rejection") { sub =>
        let payload = "Sensitive banking payload requiring strict CRC-32 integrity.";
        var gz: u8[>..] = [];
        core::gzip_compress(payload, gz, 6);

        // Corrupt trailer CRC32 (located at len - 8)
        let crc_idx = gz.len - 8;
        gz[crc_idx] ^= 0xFF;

        var restored: u8[>..] = [];
        let ok_d, err = core::gzip_decompress(gz[..], restored);
        sub.assert_false(ok_d, "Tampered CRC-32 must be rejected");
        sub.assert_eq(err, core::CompressError.ChecksumMismatch, "Error must be ChecksumMismatch");
    };

    t.run("Gzip Size Tampering Rejection") { sub =>
        let payload = "Testing uncompressed size validation.";
        var gz: u8[>..] = [];
        core::gzip_compress(payload, gz, 6);

        // Corrupt trailer ISIZE (located at len - 4)
        let isize_idx = gz.len - 4;
        gz[isize_idx] ^= 0x01;

        var restored: u8[>..] = [];
        let ok_d, err = core::gzip_decompress(gz[..], restored);
        sub.assert_false(ok_d, "Tampered ISIZE must be rejected");
        sub.assert_eq(err, core::CompressError.SizeMismatch, "Error must be SizeMismatch");
    };

    t.run("Gzip Truncated Stream Rejection") { sub =>
        let payload = "Short payload to test truncated input handling.";
        var gz: u8[>..] = [];
        core::gzip_compress(payload, gz, 6);

        // Truncate last 5 bytes
        let trunc_len = gz.len - 5;
        let trunc_slice = gz[..trunc_len];

        var restored: u8[>..] = [];
        let ok_d, err = core::gzip_decompress(trunc_slice, restored);
        sub.assert_false(ok_d, "Truncated stream must fail");
        sub.assert_ne(err, core::CompressError.None, "Error must not be None on truncated stream");
    };
}

fn test_zlib_container(t: core::T&) {
    t.run("Zlib Compression and Decompression Round-Trip") { sub =>
        let payload = "Zlib RFC 1950 container format verification with Big-Endian Adler-32.";
        var zb: u8[>..] = [];
        let ok_c = core::zlib_compress(payload, zb, 6);
        sub.assert_true(ok_c, "compress_zlib must succeed");

        // Verify CMF (0x78) and FCHECK modulo 31
        let cmf = zb[0] as u32;
        let flg = zb[1] as u32;
        sub.assert_eq(cmf, 0x78 as u32, "CMF must be 0x78 (deflate, 32K window)");
        sub.assert_eq((cmf * 256 + flg) % 31, 0 as u32, "Header checksum (CMF*256 + FLG) % 31 must be 0");

        var restored: u8[>..] = [];
        let ok_d, err = core::zlib_decompress(zb[..], restored);
        sub.assert_true(ok_d, "decompress_zlib must succeed");
        sub.assert_eq(err, core::CompressError.None, "Error must be None");
        sub.assert_eq(restored[..], payload, "Restored content must match original");
    };

    t.run("Zlib Adler-32 Tampering Rejection") { sub =>
        let payload = "Adler-32 tamper test payload.";
        var zb: u8[>..] = [];
        core::zlib_compress(payload, zb, 6);

        // Corrupt Adler-32 (last byte)
        let last_idx = zb.len - 1;
        zb[last_idx] ^= 0x55;

        var restored: u8[>..] = [];
        let ok_d, err = core::zlib_decompress(zb[..], restored);
        sub.assert_false(ok_d, "Tampered Adler-32 must be rejected");
        sub.assert_eq(err, core::CompressError.ChecksumMismatch, "Error must be ChecksumMismatch");
    };

    t.run("Zlib Invalid Header Rejection") { sub =>
        let payload = "Invalid header test.";
        var zb: u8[>..] = [];
        core::zlib_compress(payload, zb, 6);

        // Corrupt CMF
        zb[0] = 0xFF;

        var restored: u8[>..] = [];
        let ok_d, err = core::zlib_decompress(zb[..], restored);
        sub.assert_false(ok_d, "Invalid header must be rejected");
        sub.assert_eq(err, core::CompressError.InvalidHeader, "Error must be InvalidHeader");
    };
}

fn test_boundary_and_large_buffers(t: core::T&) {
    t.run("Single Byte Round-Trip") { sub =>
        let single: u8[1] = [0x5A];
        var gz: u8[>..] = [];
        core::gzip_compress(single[..], gz, 6);

        var restored: u8[>..] = [];
        let ok_d, err = core::gzip_decompress(gz[..], restored);
        sub.assert_true(ok_d, "Single byte decompress must succeed");
        sub.assert_eq(restored.len, 1, "Length must be 1");
        sub.assert_eq(restored[0], 0x5A, "Byte value must match");
    };

    t.run("Two Identical Bytes Round-Trip") { sub =>
        let two: u8[2] = [0x42, 0x42];
        var gz: u8[>..] = [];
        core::gzip_compress(two[..], gz, 6);

        var restored: u8[>..] = [];
        let ok_d, err = core::gzip_decompress(gz[..], restored);
        sub.assert_true(ok_d, "Two bytes decompress must succeed");
        sub.assert_eq(restored.len, 2, "Length must be 2");
        sub.assert_eq(restored[0], 0x42, "Byte 0 must match");
        sub.assert_eq(restored[1], 0x42, "Byte 1 must match");
    };

    t.run("Empty Buffer Gzip Round-Trip") { sub =>
        let empty_buf: u8[0] = [];
        var gz: u8[>..] = [];
        core::gzip_compress(empty_buf[..], gz, 6);

        var restored: u8[>..] = [];
        let ok_d, err = core::gzip_decompress(gz[..], restored);
        sub.assert_true(ok_d, "Empty buffer decompress must succeed");
        sub.assert_eq(restored.len, 0, "Length must be 0");
    };

    t.run("35 KB Window Wrap Round-Trip") { sub =>
        // Generate 35 KB with repeating 128-byte pattern (exceeding 32 KB sliding window)
        var large: u8[>..] = [];
        for i in 280 {
            for j in 128 {
                let byte_val = ((i * 7 + j * 13) & 0xFF) as u8;
                large.push(byte_val);
            }
        }
        sub.assert_eq(large.len, 35840, "Size must be 35,840 bytes (> 32 KB)");

        var comp: u8[>..] = [];
        let ok_c = core::gzip_compress(large[..], comp, 6);
        sub.assert_true(ok_c, "Large gzip compression must succeed");

        var restored: u8[>..] = [];
        let ok_d, err = core::gzip_decompress(comp[..], restored);
        sub.assert_true(ok_d, "Large gzip decompression must succeed");
        sub.assert_eq(err, core::CompressError.None, "Error must be None");
        sub.assert_eq(restored.len, large.len, "Decompressed size must match 35,840 bytes");
        sub.assert_eq(restored[..], large[..], "Payload must match exactly byte-for-byte");
    };
}

fn test_dynamic_huffman_and_btypes(t: core::T&) {
    t.run("BTYPE Bit Header Verification") { sub =>
        let payload = "Deflate block header specification requires bit 0 to be BFINAL, and bits 1-2 to be BTYPE. Level 0 produces stored blocks (BTYPE 00). Level 1-5 produces fixed Huffman (BTYPE 01). Level 6+ produces dynamic Huffman (BTYPE 10) with custom canonical prefix code trees. Deflate block header specification requires bit 0 to be BFINAL, and bits 1-2 to be BTYPE.";

        // Level 0 (Stored): BFINAL=1, BTYPE=00 -> lowest 3 bits are 0b001 = 1
        var c0: u8[>..] = [];
        core::deflate(payload, c0, 0);
        let btype0 = (c0[0] >> 1) & 0x03;
        sub.assert_eq(btype0, 0 as u8, "Level 0 must emit BTYPE 00 (Stored block)");

        // Level 1 (Fixed): BFINAL=1, BTYPE=01 -> lowest 3 bits are 0b011 = 3
        var c1: u8[>..] = [];
        core::deflate(payload, c1, 1);
        let btype1 = (c1[0] >> 1) & 0x03;
        sub.assert_eq(btype1, 1 as u8, "Level 1 must emit BTYPE 01 (Fixed Huffman block)");

        // Level 6 (Dynamic): BFINAL=1, BTYPE=10 -> lowest 3 bits are 0b101 = 5
        var c6: u8[>..] = [];
        core::deflate(payload, c6, 6);
        let btype6 = (c6[0] >> 1) & 0x03;
        sub.assert_eq(btype6, 2 as u8, "Level 6 must emit BTYPE 10 (Dynamic Huffman block)");
    };

    t.run("Dynamic Huffman Code Optimization") { sub =>
        // Skewed alphabet: 'E' and 'T' repeat constantly with minimal entropy
        var skewed: u8[>..] = [];
        for i in 200 {
            skewed.append("EEEEETTTTTEEEEEETTTTTTEEEEEETTTTTT");
        }

        var comp_fixed: u8[>..] = [];
        core::deflate(skewed[..], comp_fixed, 1);

        var comp_dyn: u8[>..] = [];
        core::deflate(skewed[..], comp_dyn, 6);

        sub.assert_true(comp_dyn.len > 0, "Dynamic compression must succeed");
        sub.assert_true(comp_dyn.len <= comp_fixed.len, "Dynamic Huffman must match or beat Fixed Huffman size");

        var restored: u8[>..] = [];
        let ok_d, err = core::inflate(comp_dyn[..], restored);
        sub.assert_true(ok_d, "Dynamic Huffman decompression must succeed");
        sub.assert_eq(restored.len, skewed.len, "Restored length must match exactly");
        sub.assert_eq(restored[..], skewed[..], "Restored payload must match verbatim");
    };
}

fn test_streaming_and_flush_modes(t: core::T&) {
    t.run("ZStream SyncFlush WebSockets Framing") { sub =>
        var stream = core::new_zstream_compressor(core::ContainerFormat.Raw, 6);
        var wire: u8[>..] = [];

        let msg1 = "First streaming message chunk over WebSocket connection. ";
        let ok1 = stream.write(msg1, wire, core::FlushMode.SyncFlush);
        sub.assert_true(ok1, "First chunk write with SyncFlush must succeed");

        // Verify SyncFlush emitted RFC 1951 sync marker 00 00 FF FF at end of buffer
        sub.assert_true(wire.len >= 4, "Stream must have at least 4 bytes");
        let wlen = wire.len;
        sub.assert_eq(wire[wlen - 4], 0x00, "Sync marker byte 0 must be 0x00");
        sub.assert_eq(wire[wlen - 3], 0x00, "Sync marker byte 1 must be 0x00");
        sub.assert_eq(wire[wlen - 2], 0xFF, "Sync marker byte 2 must be 0xFF");
        sub.assert_eq(wire[wlen - 1], 0xFF, "Sync marker byte 3 must be 0xFF");

        // Second chunk matches history from first chunk
        let msg2 = "Second streaming message chunk over WebSocket connection with extra tail.";
        let ok2 = stream.write(msg2, wire, core::FlushMode.Finish);
        sub.assert_true(ok2, "Second chunk write with Finish must succeed");

        var combined: u8[>..] = [];
        combined.append(msg1);
        combined.append(msg2);

        var restored: u8[>..] = [];
        let ok_d, err = core::inflate(wire[..], restored);
        sub.assert_true(ok_d, "Decompressing SyncFlushed multi-block stream must succeed");
        sub.assert_eq(restored.len, combined.len, "Decompressed length must match sum of chunks");
        sub.assert_eq(restored[..], combined[..], "Decompressed stream payload must match verbatim");
    };

    t.run("ZStream FullFlush Archive Checkpoints") { sub =>
        var stream = core::new_zstream_compressor(core::ContainerFormat.Raw, 6);
        var wire: u8[>..] = [];

        let part1 = "Checkpoint block A: independent data partition. ";
        stream.write(part1, wire, core::FlushMode.FullFlush);

        let part2 = "Checkpoint block B: second isolated data partition.";
        stream.write(part2, wire, core::FlushMode.Finish);

        var combined: u8[>..] = [];
        combined.append(part1);
        combined.append(part2);

        var restored: u8[>..] = [];
        let ok_d, err = core::inflate(wire[..], restored);
        sub.assert_true(err == core::CompressError.None, "err must be None");
        sub.assert_true(err != core::CompressError.DistanceOutOfBounds, "err is not DistanceOutOfBounds");
        sub.assert_true(err != core::CompressError.InputBufferTruncated, "err is not InputBufferTruncated");
        sub.assert_true(err != core::CompressError.InvalidBlockType, "err is not InvalidBlockType");
        sub.assert_true(err != core::CompressError.InvalidHuffmanCode, "err is not InvalidHuffmanCode");
        sub.assert_true(ok_d, "Decompressing FullFlushed stream must succeed");
        sub.assert_eq(restored.len, combined.len, "Decompressed length must match combined");
        sub.assert_eq(restored[..], combined[..], "Decompressed payload must match verbatim");
    };
}

fn test_preset_dictionary_and_fdict(t: core::T&) {
    t.run("RFC 1950 FDICT Zlib Compression & Verification") { sub =>
        let dict = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";
        let payload = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0 CustomRequestData/2.0";

        var comp: u8[>..] = [];
        let ok_c = core::zlib_compress_with_dict(payload, comp, 6, dict);
        sub.assert_true(ok_c, "Zlib dictionary compression must succeed");

        // Verify FDICT bit (bit 5) in FLG byte (byte 1)
        let flg = comp[1] as u32;
        sub.assert_true((flg & 0x20) != 0, "FLG byte bit 5 (FDICT) must be set");

        // Verify 4-byte DICTID in bytes 2..6 matches adler32(dict)
        let expected_dict_id = core::adler32(dict);
        let actual_dict_id = ((comp[2] as u32) << 24) |
                             ((comp[3] as u32) << 16) |
                             ((comp[4] as u32) << 8) |
                             (comp[5] as u32);
        sub.assert_eq(actual_dict_id, expected_dict_id, "DICTID must match Adler-32 of dictionary");

        // Decompress with missing dictionary must fail with NeedDictionary
        var bad1: u8[>..] = [];
        let ok_d1, err1 = core::zlib_decompress_with_dict(comp[..], bad1, "");
        sub.assert_false(ok_d1, "Decompress without dictionary must fail");
        sub.assert_eq(err1, core::CompressError.NeedDictionary, "Error must be NeedDictionary");

        // Decompress with wrong dictionary must fail with DictionaryMismatch
        var bad2: u8[>..] = [];
        let ok_d2, err2 = core::zlib_decompress_with_dict(comp[..], bad2, "Wrong Dictionary Content Here");
        sub.assert_false(ok_d2, "Decompress with wrong dictionary must fail");
        sub.assert_eq(err2, core::CompressError.DictionaryMismatch, "Error must be DictionaryMismatch");

        // Decompress with correct dictionary must succeed
        var restored: u8[>..] = [];
        let ok_d3, err3 = core::zlib_decompress_with_dict(comp[..], restored, dict);
        sub.assert_true(ok_d3, "Decompress with correct dictionary must succeed");
        sub.assert_eq(err3, core::CompressError.None, "Error must be None");
        sub.assert_eq(restored[..], payload, "Restored payload must match original");
    };

    t.run("Raw Deflate Preset Dictionary Round-Trip") { sub =>
        let dict = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nServer: Wing\r\n";
        let payload = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{\"success\":true}";

        var comp: u8[>..] = [];
        let ok_c = core::deflate_with_dict(payload, comp, 6, dict);
        sub.assert_true(ok_c, "Deflate dict compression must succeed");

        var restored: u8[>..] = [];
        let ok_d, err = core::inflate_with_dict(comp[..], restored, dict);
        sub.assert_true(ok_d, "Deflate dict decompression must succeed");
        sub.assert_eq(err, core::CompressError.None, "Error must be None");
        sub.assert_eq(restored[..], payload, "Restored text must match verbatim");
    };
}

fn test_universal_autodetect(t: core::T&) {
    t.run("Auto-Detect Gzip, Zlib, and Raw Deflate") { sub =>
        let original = "Universal automatic decompressor test for Wing stdlib candidate.";

        // 1. Gzip
        var gz: u8[>..] = [];
        core::gzip_compress(original, gz, 6);
        sub.assert_eq(core::detect_container_format(gz[..]), core::ContainerFormat.Gzip, "Format must be Gzip");

        var out_gz: u8[>..] = [];
        let ok_gz, err_gz = core::decompress_auto(gz[..], out_gz);
        sub.assert_true(ok_gz, "Auto-decompress Gzip must succeed");
        sub.assert_eq(err_gz, core::CompressError.None, "Error must be None");
        sub.assert_eq(out_gz[..], original, "Gzip output must match original");

        // 2. Zlib
        var zb: u8[>..] = [];
        core::zlib_compress(original, zb, 6);
        sub.assert_eq(core::detect_container_format(zb[..]), core::ContainerFormat.Zlib, "Format must be Zlib");

        var out_zb: u8[>..] = [];
        let ok_zb, err_zb = core::decompress_auto(zb[..], out_zb);
        sub.assert_true(ok_zb, "Auto-decompress Zlib must succeed");
        sub.assert_eq(err_zb, core::CompressError.None, "Error must be None");
        sub.assert_eq(out_zb[..], original, "Zlib output must match original");

        // 3. Raw Deflate
        var df: u8[>..] = [];
        core::deflate(original, df, 6);
        sub.assert_eq(core::detect_container_format(df[..]), core::ContainerFormat.Raw, "Format must be Raw Deflate");

        var out_df: u8[>..] = [];
        let ok_df, err_df = core::decompress_auto(df[..], out_df);
        sub.assert_true(ok_df, "Auto-decompress Raw Deflate must succeed");
        sub.assert_eq(err_df, core::CompressError.None, "Error must be None");
        sub.assert_eq(out_df[..], original, "Deflate output must match original");
    };
}

fn test_lazy_matching_and_stored_cost_selection(t: core::T&) {
    t.run("Lazy Matching Ratio Advantage") { sub =>
        var src: u8[>..] = [];
        let pattern = "The quick brown fox jumps over the lazy dog repeatedly in structured sequences. ";
        for i in 25 {
            src.append(pattern);
        }

        var l1_out: u8[>..] = [];
        core::deflate(src[..], l1_out, 1);

        var l9_out: u8[>..] = [];
        core::deflate(src[..], l9_out, 9);

        sub.assert_true(l9_out.len <= l1_out.len, "Level 9 lazy matching must be equal or smaller than level 1 greedy");

        var restored: u8[>..] = [];
        let ok, err = core::inflate(l9_out[..], restored);
        sub.assert_true(ok, "Decompressing level 9 must succeed");
        sub.assert_eq(err, core::CompressError.None, "Error must be None");
        sub.assert_eq(restored[..], src[..], "Restored payload must match original verbatim");
    };

    t.run("Incompressible Data Stored Block Selection") { sub =>
        var random_data: u8[1024] = [0; 1024];
        var seed: u32 = 123456789;
        for i in 1024 {
            seed = seed * 1664525 + 1013904223;
            random_data[i] = ((seed >> 16) & 0xFF) as u8;
        }

        var comp: u8[>..] = [];
        core::deflate(random_data[..], comp, 6);

        // Exact bit-cost selection guarantees stored block envelope overhead is <= 15 bytes
        sub.assert_true(comp.len <= (random_data.len + 15), "Deflate must never expand incompressible data beyond framing");

        var restored: u8[>..] = [];
        let ok, err = core::inflate(comp[..], restored);
        sub.assert_true(ok, "Decompressing incompressible stored block must succeed");
        sub.assert_eq(err, core::CompressError.None, "Error must be None");
        sub.assert_eq(restored[..], random_data[..], "Restored incompressible payload must match bit-for-bit");
    };
}

fn test_concatenated_gzip_and_fhcrc(t: core::T&) {
    t.run("Concatenated Gzip Members (RFC 1952 multi-member)") { sub =>
        let part1 = "First concatenated gzip archive member. ";
        let part2 = "Second concatenated gzip archive member with independent payload.";

        var gz1: u8[>..] = [];
        core::gzip_compress(part1, gz1, 6);

        var gz2: u8[>..] = [];
        core::gzip_compress(part2, gz2, 6);

        var combined_gz: u8[>..] = [];
        combined_gz.append(gz1[..]);
        combined_gz.append(gz2[..]);

        var combined_text: u8[>..] = [];
        combined_text.append(part1);
        combined_text.append(part2);

        var restored: u8[>..] = [];
        let ok, err = core::gzip_decompress(combined_gz[..], restored);
        sub.assert_true(ok, "Decompressing concatenated Gzip stream must succeed");
        sub.assert_eq(err, core::CompressError.None, "Error must be None");
        sub.assert_eq(restored.len, combined_text.len, "Length must match combined length");
        sub.assert_eq(restored[..], combined_text[..], "Payload must match concatenation verbatim");
    };

    t.run("Gzip Header Metadata and FHCRC Verification") { sub =>
        let payload = "Config file with filename, comment, and 16-bit header CRC.";
        var gz: u8[>..] = [];
        let ok_c = core::gzip_compress_with_header(payload, gz, 6, "config.ini", "production settings", true);
        sub.assert_true(ok_c, "Gzip compress with header and FHCRC must succeed");

        var restored: u8[>..] = [];
        let ok_d, err_d = core::gzip_decompress(gz[..], restored);
        sub.assert_true(ok_d, "Decompressing Gzip with valid FHCRC must succeed");
        sub.assert_eq(err_d, core::CompressError.None, "Error must be None");
        sub.assert_eq(restored[..], payload, "Restored payload must match");

        // Tamper with header byte to invalidate FHCRC
        var tampered: u8[>..] = [];
        tampered.append(gz[..]);
        tampered[10] ^= 0x55; // Tamper character in filename

        var restored_fail: u8[>..] = [];
        let ok_fail, err_fail = core::gzip_decompress(tampered[..], restored_fail);
        sub.assert_true(!ok_fail, "Decompressing tampered header must fail");
        sub.assert_eq(err_fail, core::CompressError.ChecksumMismatch, "Error must be ChecksumMismatch");
    };
}

fn test_zipbomb_quota_guards(t: core::T&) {
    t.run("Deflate Quota Overflow Cutoff") { sub =>
        var bomb: u8[>..] = [];
        for i in 15000 {
            bomb.push(0x42);
        }

        var wire: u8[>..] = [];
        core::deflate(bomb[..], wire, 6);

        var restored: u8[>..] = [];
        let ok, err = core::inflate_with_limit(wire[..], restored, 500);
        sub.assert_true(!ok, "Decompression exceeding quota must fail");
        sub.assert_eq(err, core::CompressError.OutputBufferOverflow, "Error must be OutputBufferOverflow");
        sub.assert_true(restored.len <= 500, "Output length must not exceed quota limit");
    };

    t.run("Gzip Quota Overflow Cutoff") { sub =>
        var bomb: u8[>..] = [];
        for i in 15000 {
            bomb.push(0x5A);
        }

        var wire: u8[>..] = [];
        core::gzip_compress(bomb[..], wire, 6);

        var restored: u8[>..] = [];
        let ok, err = core::gzip_decompress_with_limit(wire[..], restored, 400);
        sub.assert_true(!ok, "Gzip decompression exceeding quota must fail");
        sub.assert_eq(err, core::CompressError.OutputBufferOverflow, "Error must be OutputBufferOverflow");
        sub.assert_true(restored.len <= 400, "Output length must not exceed quota limit");
    };

    t.run("Zlib Quota Overflow Cutoff") { sub =>
        var bomb: u8[>..] = [];
        for i in 15000 {
            bomb.push(0x7F);
        }

        var wire: u8[>..] = [];
        core::zlib_compress(bomb[..], wire, 6);

        var restored: u8[>..] = [];
        let ok, err = core::zlib_decompress_with_limit(wire[..], restored, 350);
        sub.assert_true(!ok, "Zlib decompression exceeding quota must fail");
        sub.assert_eq(err, core::CompressError.OutputBufferOverflow, "Error must be OutputBufferOverflow");
        sub.assert_true(restored.len <= 350, "Output length must not exceed quota limit");
    };
}

fn test_resumable_streaming_chunk_by_chunk(t: core::T&) {
    t.run("ZStream 1-Byte Slices Feeding") { sub =>
        let message = "Resumable streaming decompressor feeding arbitrary tiny byte slices across network boundaries.";
        var wire: u8[>..] = [];
        core::zlib_compress(message, wire, 6);

        var decompressor = core::new_zstream_decompressor(core::ContainerFormat.Zlib);
        var restored: u8[>..] = [];

        // Feed byte by byte
        for i in wire.len {
            let single_byte = wire[i..i + 1];
            let err = decompressor.write(single_byte, restored);
            sub.assert_eq(err, core::CompressError.None, "Writing single byte slice must not return error");
        }

        sub.assert_eq(restored.len, message.len, "Restored length must match message length");
        sub.assert_eq(restored[..], message, "Restored payload from 1-byte chunks must match verbatim");
    };

    t.run("ZStream Variable Prime Slices Feeding") { sub =>
        let message = "Another streaming verification test using prime-sized slices (3, 7, 11 bytes) to simulate jitter.";
        var wire: u8[>..] = [];
        core::gzip_compress(message, wire, 6);

        var decompressor = core::new_zstream_decompressor(core::ContainerFormat.Gzip);
        var restored: u8[>..] = [];

        var offset: i64 = 0;
        var step: i64 = 3;
        while offset < wire.len {
            let rem = wire.len - offset;
            let take = if rem < step { rem } else { step };
            let chunk = wire[offset..offset + take];
            let err = decompressor.write(chunk, restored);
            sub.assert_eq(err, core::CompressError.None, "Writing variable chunk must succeed");
            offset += take;
            step = if step == 3 { 7 } else if step == 7 { 11 } else { 3 };
        }

        sub.assert_eq(restored.len, message.len, "Restored length must match message length");
        sub.assert_eq(restored[..], message, "Restored payload from prime chunks must match verbatim");
    };
}

// Reference test frames generated by official Zstandard library (v1.5.7)
const ZSTD_REF_EMPTY: u8[9] = [
    0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x00, 0x01, 0x00, 0x00,
];

const ZSTD_REF_SHORT_TEXT: u8[25] = [
    0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x10, 0x81, 0x00, 0x00, 0x48, 0x65, 0x6C,
    0x6C, 0x6F, 0x20, 0x5A, 0x73, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64,
    0x21,
];

const ZSTD_REF_RLE: u8[17] = [
    0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x40, 0x45, 0x00, 0x00, 0x10, 0x41, 0x41,
    0x01, 0x00, 0x93, 0x00, 0x16,
];

const ZSTD_REF_REPEATED_WORDS: u8[27] = [
    0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x37, 0x95, 0x00, 0x00, 0x60, 0x67, 0x6F,
    0x6F, 0x73, 0x65, 0x20, 0x77, 0x69, 0x6E, 0x67, 0x20, 0x21, 0x01, 0x00,
    0xD8, 0x2C, 0x5E,
];

const ZSTD_REF_FOX_PANGRAM: u8[63] = [
    0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x5A, 0xB5, 0x01, 0x00, 0xE4, 0x02, 0x54,
    0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6B, 0x20, 0x62, 0x72, 0x6F,
    0x77, 0x6E, 0x20, 0x66, 0x6F, 0x78, 0x20, 0x6A, 0x75, 0x6D, 0x70, 0x73,
    0x20, 0x6F, 0x76, 0x65, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6C, 0x61,
    0x7A, 0x79, 0x20, 0x64, 0x6F, 0x67, 0x2E, 0x20, 0x00, 0x01, 0x00, 0x0D,
    0x9A, 0xAA, 0x0C,
];

fn test_zstandard_rfc8878(t: core::T&) {
    t.run("Reference Zstd Empty Frame") { sub =>
        var decomp: u8[>..] = [];
        let ok, err = core::zstd_decompress(ZSTD_REF_EMPTY[..], decomp);
        sub.assert_true(ok, "Decompressing empty frame must succeed");
        sub.assert_eq(err, core::CompressError.None, "Empty frame error code must be None");
        sub.assert_eq(decomp.len, 0 as i64, "Decompressed length must be 0");
    };

    t.run("Reference Zstd Short Text (Raw Block)") { sub =>
        var decomp: u8[>..] = [];
        let ok, err = core::zstd_decompress(ZSTD_REF_SHORT_TEXT[..], decomp);
        sub.assert_true(ok, "Decompressing short text frame must succeed");
        sub.assert_eq(err, core::CompressError.None, "Short text error code must be None");
        sub.assert_eq(decomp[..], "Hello Zstandard!", "Decoded text must match verbatim");
    };

    t.run("Reference Zstd RLE Pattern (Compressed Block with RLE)") { sub =>
        var decomp: u8[>..] = [];
        let ok, err = core::zstd_decompress(ZSTD_REF_RLE[..], decomp);
        sub.assert_true(ok, "Decompressing RLE frame must succeed");
        sub.assert_eq(err, core::CompressError.None, "RLE error code must be None");
        sub.assert_eq(decomp.len, 64 as i64, "Decoded length must be 64");
        var all_a = true;
        for b in decomp {
            if b != 0x41 { all_a = false; }
        }
        sub.assert_true(all_a, "All decoded bytes must be 'A'");
    };

    t.run("Reference Zstd Sequences & Repeat Offsets") { sub =>
        var decomp: u8[>..] = [];
        let ok, err = core::zstd_decompress(ZSTD_REF_REPEATED_WORDS[..], decomp);
        sub.assert_true(ok, "Decompressing repeated words frame must succeed");
        sub.assert_eq(err, core::CompressError.None, "Repeated words error code must be None");
        sub.assert_eq(decomp[..], "goose wing goose wing goose wing goose wing goose wing!", "Restored repeated words must match verbatim");
    };

    t.run("Reference Zstd Fox Pangram (Compressed Block)") { sub =>
        var decomp: u8[>..] = [];
        let ok, err = core::zstd_decompress(ZSTD_REF_FOX_PANGRAM[..], decomp);
        sub.assert_true(ok, "Decompressing fox pangram frame must succeed");
        sub.assert_eq(err, core::CompressError.None, "Fox pangram error code must be None");
        let expected = "The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.\0";
        sub.assert_eq(decomp.len, expected.len, "Pangram length must match");
        sub.assert_eq(decomp[..], expected, "Decoded pangram must match verbatim");
    };

    t.run("Native Zstd Round-Trip (Small, Medium, Large)") { sub =>
        let samples: const u8[:][3] = [
            "Zstd clean room native Goose compressor test payload.",
            "High-performance systems programming in Goose: modern syntax, zero-heap memory model, C++ and Rust speed.",
            "1234567890",
        ];

        for sample in samples {
            var wire: u8[>..] = [];
            let ok_c = core::zstd_compress(sample, wire, true);
            sub.assert_true(ok_c, "Zstd compression must succeed");
            sub.assert_true(wire.len >= 4, "Compressed frame must contain at least magic");

            var restored: u8[>..] = [];
            let ok_d, err_d = core::zstd_decompress(wire[..], restored);
            sub.assert_true(ok_d, "Zstd decompression must succeed");
            sub.assert_eq(err_d, core::CompressError.None, "Error must be None");
            sub.assert_eq(restored[..], sample, "Restored slice must match original");
        }
    };

    t.run("Multi-Block Zstd Frame Round-Trip (> 128 KB)") { sub =>
        var large_input: u8[>..] = [];
        let pattern = "Goose Zstandard Multi-Block Verification Payload 1234567890! ";
        while large_input.len < 150000 {
            large_input.append(pattern);
        }

        var wire: u8[>..] = [];
        let ok_c = core::zstd_compress(large_input[..], wire, true);
        sub.assert_true(ok_c, "Multi-block Zstd compression must succeed");

        var restored: u8[>..] = [];
        let ok_d, err_d = core::zstd_decompress(wire[..], restored);
        sub.assert_true(ok_d, "Multi-block Zstd decompression must succeed");
        sub.assert_eq(err_d, core::CompressError.None, "Multi-block error must be None");
        sub.assert_eq(restored.len, large_input.len, "Restored length must match 150,000 bytes");
        sub.assert_eq(restored[..], large_input[..], "Restored payload must match verbatim across block boundaries");
    };

    t.run("Content Checksum Verification & Tamper Detection") { sub =>
        let message = "Tamper detection test payload with XXH64 content checksum.";
        var wire: u8[>..] = [];
        core::zstd_compress(message, wire, true);

        // Tamper with data payload
        var tampered: u8[>..] = [];
        tampered.append(wire[..]);
        let data_idx = 10;
        tampered[data_idx] = tampered[data_idx] ^ 0xFF;

        var restored: u8[>..] = [];
        let ok_d, err_d = core::zstd_decompress(tampered[..], restored);
        sub.assert_false(ok_d, "Decompressing tampered frame must fail");
        sub.assert_eq(err_d, core::CompressError.ChecksumMismatch, "Tampered payload must trigger ChecksumMismatch");
    };

    t.run("Decompression Bomb Quota Guards") { sub =>
        let message = "A somewhat long message intended to test quota limits on output buffer.";
        var wire: u8[>..] = [];
        core::zstd_compress(message, wire, false);

        var restored: u8[>..] = [];
        let quota: i64 = 20; // smaller than message length
        let ok_d, err_d = core::zstd_decompress_with_limit(wire[..], restored, quota);
        sub.assert_false(ok_d, "Decompressing beyond quota must fail");
        sub.assert_eq(err_d, core::CompressError.OutputBufferOverflow, "Must return OutputBufferOverflow");
    };

    t.run("Universal Auto-Detection for Zstandard") { sub =>
        let message = "Auto-detection test vector for RFC 8878 Zstandard magic.";
        var wire: u8[>..] = [];
        core::zstd_compress(message, wire, false);

        let fmt = core::detect_container_format(wire[..]);
        sub.assert_eq(fmt, core::ContainerFormat.Zstd, "detect_container_format must recognize ContainerFormat.Zstd");

        var restored: u8[>..] = [];
        let ok_d, err_d = core::decompress_auto(wire[..], restored);
        sub.assert_true(ok_d, "decompress_auto must succeed for Zstd frame");
        sub.assert_eq(err_d, core::CompressError.None, "Auto-decompress error must be None");
        sub.assert_eq(restored[..], message, "Auto-decompressed text must match verbatim");
    };

    t.run("HTTP Response Content-Encoding: zstd Integration") { sub =>
        let raw_payload = "HTTP/1.1 response body compressed with Zstandard content-encoding.";
        var wire: u8[>..] = [];
        core::zstd_compress(raw_payload, wire, true);

        var res = wing::new_response();
        res.status_code = 200;
        let h_enc = wing::make_header("Content-Encoding", "zstd");
        let h_type = wing::make_header("Content-Type", "text/plain");
        res.headers.push(h_enc);
        res.headers.push(h_type);
        res.body.append(wire[..]);

        let decoded = wing::decode_body(res);
        sub.assert_true(decoded, "decode_body must handle Content-Encoding: zstd");
        sub.assert_eq(res.body[..], raw_payload, "Decoded HTTP body must match original payload");
    };

    t.run("ZStreamDecompressor Chunked Streaming for Zstandard") { sub =>
        let message = "Chunked TCP slice streaming test vector for RFC 8878 Zstandard frames.";
        var wire: u8[>..] = [];
        core::zstd_compress(message, wire, true);

        // Feed arbitrary chunks (13 bytes at a time) to ZStreamDecompressor in Auto mode
        var dec = core::new_zstream_decompressor(core::ContainerFormat.Auto);
        var restored: u8[>..] = [];
        var offset: i64 = 0;
        let chunk_size: i64 = 13;

        while offset < wire.len {
            let rem = wire.len - offset;
            let take = if rem < chunk_size { rem } else { chunk_size };
            let err = core::zstream_decompress_write_limit(dec, wire[offset..offset + take], restored);
            sub.assert_eq(err, core::CompressError.None, "zstream_decompress_write_limit must succeed on chunk");
            offset += take;
        }

        sub.assert_true(dec.is_finished, "ZStreamDecompressor must be finished");
        sub.assert_eq(restored[..], message, "ZStream chunk-streamed Zstd must match original payload");
    };

    t.run("Zstandard Native Compressor Levels 0..3 Roundtrip Verification") { sub =>
        var payload_buf: u8[>..] = [];
        for i in 6 {
            payload_buf.append("{\"status\": \"success\", \"code\": 200, \"items\": [\"apple\", \"banana\", \"cherry\", \"date\"], \"extra\": \"high performance compression testing for goose-wing stdlib candidate\"}\n");
        }
        let payload = payload_buf[..];

        for lvl in 4 {
            let level = lvl as i32;
            var compressed: u8[>..] = [];
            let ok_c = core::zstd_compress_level(payload, compressed, level, true);
            sub.assert_true(ok_c, "compress_zstd_level must succeed");

            if level > 0 {
                sub.assert_true(compressed.len < payload.len, "Levels 1..3 must achieve positive compression ratio");
            }

            var decompressed: u8[>..] = [];
            let ok_d, err_d = core::zstd_decompress(compressed[..], decompressed);
            sub.assert_true(ok_d, "decompress_zstd must decompress native level output");
            sub.assert_eq(err_d, core::CompressError.None, "Decompress error must be None");
            sub.assert_eq(decompressed[..], payload, "Decompressed bytes must match original verbatim");
        }
    };

    t.run("RFC 8878 Block Header Validation & Return Code Conformance") { sub =>
        // Vector 1: Reserved block type (Block_Type = 3) must return InvalidBlockType
        let invalid_block_type_frame: u8[9] = [
            0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x00, 0x07, 0x00, 0x00,
        ];
        var out1: u8[>..] = [];
        let ok1, err1 = core::zstd_decompress(invalid_block_type_frame[..], out1);
        sub.assert_false(ok1, "Reserved block type 3 must be rejected");
        sub.assert_eq(err1, core::CompressError.InvalidBlockType, "Must return InvalidBlockType");

        // Vector 2: Block_Size exceeding Window_Size (RFC 8878 §3.1.1.2.4)
        // Multi-segment frame with Window_Size = 1 KB (WD = 0x00), but Block_Size = 2048
        var invalid_block_size_frame: u8[>..] = [];
        let prefix: u8[9] = [0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00, 0x01, 0x40, 0x00];
        invalid_block_size_frame.append(prefix[..]);
        for i in 2048 {
            invalid_block_size_frame.push(0x55);
        }
        var out2: u8[>..] = [];
        let ok2, err2 = core::zstd_decompress(invalid_block_size_frame[..], out2);
        sub.assert_false(ok2, "Block_Size exceeding Window_Size must be rejected");
        sub.assert_eq(err2, core::CompressError.CorruptedBitstream, "Must return CorruptedBitstream when Block_Size > Block_Maximum_Size");

        // Vector 3: Reserved bit in Frame_Header_Descriptor must return InvalidHeader
        let invalid_fhd_frame: u8[9] = [
            0x28, 0xB5, 0x2F, 0xFD, 0x28, 0x00, 0x01, 0x00, 0x00,
        ];
        var out3: u8[>..] = [];
        let ok3, err3 = core::zstd_decompress(invalid_fhd_frame[..], out3);
        sub.assert_false(ok3, "Reserved bit in FHD must be rejected");
        sub.assert_eq(err3, core::CompressError.InvalidHeader, "Must return InvalidHeader");
    };

    t.run("RFC 8878 Sliding Window, Quota Defense & Pre-existing Buffer Isolation") { sub =>
        // Vector 1: Relative quota enforcement with pre-existing buffer contents
        let message = "Testing relative quota calculation with pre-existing buffer content.";
        var wire: u8[>..] = [];
        core::zstd_compress(message, wire, false);

        var restored: u8[>..] = [];
        for i in 100 {
            restored.push(0xAA);
        }
        let quota = message.len as i64;
        let ok_d, err_d = core::zstd_decompress_with_limit(wire[..], restored, quota);
        sub.assert_true(ok_d, "Decompress with quota matching payload size must succeed even if out_buf already contains data");
        sub.assert_eq(err_d, core::CompressError.None, "Must succeed with None");
        sub.assert_eq(restored.len, 100 + message.len, "Length must be 100 + message.len");
        sub.assert_eq(restored[100..], message, "Appended data must match message");

        // Vector 2: RLE block exceeding output quota must return OutputBufferOverflow
        let rle_frame: u8[10] = [
            0x28, 0xB5, 0x2F, 0xFD,
            0x00,
            0x00,
            0xA3, 0x0F, 0x00,
            0x42,
        ];
        var out_rle: u8[>..] = [];
        let ok_rle, err_rle = core::zstd_decompress_with_limit(rle_frame[..], out_rle, 200);
        sub.assert_false(ok_rle, "RLE block exceeding quota must fail");
        sub.assert_eq(err_rle, core::CompressError.OutputBufferOverflow, "Must return OutputBufferOverflow");

        // Vector 3: Cross-frame / pre-existing buffer boundary isolation
        // Craft a 2-block frame: Block 1 is raw (100 bytes), Block 2 is compressed with 1 sequence referencing offset=2045
        var frame_leak: u8[>..] = [];
        let hdr_leak: u8[6] = [0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00];
        frame_leak.append(hdr_leak[..]);
        // Block 1 header: Last=0, Type=0 (Raw), Size=100 -> 0x20, 0x03, 0x00
        let blk1_hdr: u8[3] = [0x20, 0x03, 0x00];
        frame_leak.append(blk1_hdr[..]);
        for i in 100 {
            frame_leak.push(0x58);
        }
        // Block 2 header: Last=1, Type=2 (Compressed), Size=8 -> 0x45, 0x00, 0x00
        let blk2_hdr: u8[3] = [0x45, 0x00, 0x00];
        frame_leak.append(blk2_hdr[..]);
        // Block 2 payload: lit_hdr(0x00), nb_seq=1(0x01), modes=0x54, ll=0, of=11(0x0B), ml=0, seq_bits=[0x00, 0x80]
        let blk2_payload: u8[8] = [0x00, 0x01, 0x54, 0x00, 0x0B, 0x00, 0x00, 0x80];
        frame_leak.append(blk2_payload[..]);

        var pre_buf: u8[>..] = [];
        for i in 5000 {
            pre_buf.push(0x7F);
        }
        let ok_leak, err_leak = core::zstd_decompress(frame_leak[..], pre_buf);
        sub.assert_false(ok_leak, "Sequence offset pointing before frame_start_out into pre-existing buffer must be rejected");
        sub.assert_eq(err_leak, core::CompressError.DistanceOutOfBounds, "Must return DistanceOutOfBounds for pre-frame cross-boundary reference");
    };

    t.run("RFC 8878 Repeat Offset Edge Cases & 4-Stream Huffman Integrity") { sub =>
        // Vector 1: Repeat offset 3 when lit_len == 0 and rep0 == 1 evaluates to 0 (RFC 8878 §3.1.1.5)
        var frame_rep0: u8[>..] = [];
        let hdr_rep0: u8[6] = [0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00];
        frame_rep0.append(hdr_rep0[..]);
        // Block 1 header: Last=0, Type=0 (Raw), Size=50 -> 0x90, 0x01, 0x00
        let b1_hdr: u8[3] = [0x90, 0x01, 0x00];
        frame_rep0.append(b1_hdr[..]);
        for i in 50 {
            frame_rep0.push(0x41);
        }
        // Block 2 header: Last=1, Type=2 (Compressed), Size=8 -> 0x45, 0x00, 0x00
        let b2_hdr: u8[3] = [0x45, 0x00, 0x00];
        frame_rep0.append(b2_hdr[..]);
        // Block 2 payload: lit_hdr(0x00), nb_seq=1(0x01), modes=0x54, ll=0, of=1(base=2,eb=1), ml=0, seq_bits=[0x00, 0xC0] -> of_extra=1 -> offset_val=3
        let b2_payload: u8[8] = [0x00, 0x01, 0x54, 0x00, 0x01, 0x00, 0x00, 0xC0];
        frame_rep0.append(b2_payload[..]);

        var out_rep0: u8[>..] = [];
        let ok_rep0, err_rep0 = core::zstd_decompress(frame_rep0[..], out_rep0);
        sub.assert_false(ok_rep0, "Repeat offset evaluating to 0 must be rejected as corrupted");
        sub.assert_eq(err_rep0, core::CompressError.CorruptedBitstream, "Must return CorruptedBitstream for rep0 <= 1 when Offset_Value is 3 and lit_len is 0");

        // Vector 2: Treeless literals block without prior Huffman table (RFC 8878 §3.1.1.3.1.1)
        var frame_treeless: u8[>..] = [];
        let hdr_tree: u8[6] = [0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00];
        frame_treeless.append(hdr_tree[..]);
        // Block 1 header: Last=1, Type=2 (Compressed), Size=5 -> 0x2D, 0x00, 0x00
        let b_tree_hdr: u8[3] = [0x2D, 0x00, 0x00];
        frame_treeless.append(b_tree_hdr[..]);
        // Lit header: lit_type=3(Treeless), size_format=0, regen=5, comp=1 -> 0x53, 0x40, 0x00
        // Stream: 0x80, Sequences: 0x00
        let b_tree_payload: u8[5] = [0x53, 0x40, 0x00, 0x80, 0x00];
        frame_treeless.append(b_tree_payload[..]);

        var out_treeless: u8[>..] = [];
        let ok_treeless, err_treeless = core::zstd_decompress(frame_treeless[..], out_treeless);
        sub.assert_false(ok_treeless, "Treeless literals without prior table must be rejected");
        sub.assert_eq(err_treeless, core::CompressError.CorruptedBitstream, "Must return CorruptedBitstream for uninitialized Treeless table");

        // Vector 3: 4-stream Huffman jump table stream length 0 (RFC 8878 §3.1.1.3.1.2 & §4.2.2)
        var frame_4s_zero: u8[>..] = [];
        let hdr_4s: u8[6] = [0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00];
        frame_4s_zero.append(hdr_4s[..]);
        // Block 1 header: Last=1, Type=2 (Compressed), Size=12 -> 0x65, 0x00, 0x00
        let b_4s_hdr: u8[3] = [0x65, 0x00, 0x00];
        frame_4s_zero.append(b_4s_hdr[..]);
        let b_4s_payload: u8[12] = [
            0x87, 0x00, 0x02,
            0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
            0x80, 0x80, 0x00,
        ];
        frame_4s_zero.append(b_4s_payload[..]);

        var out_4s: u8[>..] = [];
        let ok_4s, err_4s = core::zstd_decompress(frame_4s_zero[..], out_4s);
        sub.assert_false(ok_4s, "4-stream Huffman with invalid size or zero-length stream must be rejected");
        sub.assert_eq(err_4s, core::CompressError.CorruptedBitstream, "Must return CorruptedBitstream for malformed 4-stream jump table");
    };
}

fn test_rfc1951_bounds_and_error_handling(t: core::T&) {
    t.run("Stored Block LEN/NLEN Mismatch Rejection") { sub =>
        // BFINAL=1, BTYPE=00 (stored), 5 zero padding bits -> byte 0 = 0x01
        // LEN = 4 (0x04, 0x00), Corrupted NLEN = 4 (0x04, 0x00) != ~4 (0xFB, 0xFF)
        let bad_stored: u8[9] = [
            0x01, 0x04, 0x00, 0x04, 0x00, 0x74, 0x65, 0x73, 0x74,
        ];
        var restored: u8[>..] = [];
        let ok, err = core::inflate(bad_stored[..], restored);
        sub.assert_false(ok, "Stored block with mismatched LEN/NLEN must fail");
        sub.assert_eq(err, core::CompressError.LengthMismatch, "Error must be LengthMismatch");
    };

    t.run("Dynamic Huffman HLIT Bound Rejection (HLIT > 29)") { sub =>
        // BFINAL=1 (1), BTYPE=2 (0b10), HLIT=30 (0b11110) -> 0xF5
        // HDIST=0 (0b00000), HCLEN low 3 bits=0 -> 0x00
        // HCLEN bit 3=0, padding -> 0x00
        let bad_hlit: u8[3] = [0xF5, 0x00, 0x00];
        var restored: u8[>..] = [];
        let ok, err = core::inflate(bad_hlit[..], restored);
        sub.assert_false(ok, "Dynamic block with HLIT > 29 must fail");
        sub.assert_eq(err, core::CompressError.TooManyLengthOrDistanceCodes, "Error must be TooManyLengthOrDistanceCodes");
    };

    t.run("Dynamic Huffman Incomplete Code Lengths Tree Rejection") { sub =>
        var wire: u8[>..] = [];
        var w = core::BitWriter { bit_buf: 0, bit_count: 0 };
        core::write_bits(w, 1, 1, wire);  // BFINAL=1
        core::write_bits(w, 2, 2, wire);  // BTYPE=2 (Dynamic)
        core::write_bits(w, 0, 5, wire);  // HLIT=0 (257)
        core::write_bits(w, 0, 5, wire);  // HDIST=0 (1)
        core::write_bits(w, 0, 4, wire);  // HCLEN=0 (4 codes: 16, 17, 18, 0)
        core::write_bits(w, 2, 3, wire);  // code 16 has length 2 (incomplete: sum=0.25 < 1)
        core::write_bits(w, 0, 3, wire);  // code 17 has length 0
        core::write_bits(w, 0, 3, wire);  // code 18 has length 0
        core::write_bits(w, 0, 3, wire);  // code 0 has length 0
        core::flush_bits(w, wire);

        var restored: u8[>..] = [];
        let ok, err = core::inflate(wire[..], restored);
        sub.assert_false(ok, "Incomplete code lengths tree must be rejected");
        sub.assert_eq(err, core::CompressError.CodeLengthsIncomplete, "Error must be CodeLengthsIncomplete");
    };

    t.run("Dynamic Huffman Incomplete Literal Tree Rejection") { sub =>
        var wire: u8[>..] = [];
        var w = core::BitWriter { bit_buf: 0, bit_count: 0 };
        core::write_bits(w, 1, 1, wire);   // BFINAL=1
        core::write_bits(w, 2, 2, wire);   // BTYPE=2 (Dynamic)
        core::write_bits(w, 0, 5, wire);   // HLIT=0 (nlen = 257)
        core::write_bits(w, 10, 5, wire);  // HDIST=10 (ndist = 11, total_codes = 268)
        core::write_bits(w, 14, 4, wire);  // HCLEN=14 (ncode = 18)

        // Code lengths for h_code:
        // Index 2 (sym 18) = 1, Index 17 (sym 1) = 1, all others 0 -> complete tree (0 and 1)
        for i in 18 {
            if i == 2 || i == 17 {
                core::write_bits(w, 1, 3, wire);
            } else {
                core::write_bits(w, 0, 3, wire);
            }
        }

        // Emit code lengths for lit_dist_lens:
        // Canonical codes: sym 1 gets code 0 (len 1), sym 18 gets code 1 (len 1)
        // 138 zeros via sym 18 (bit 1 + extra 127)
        core::write_bits(w, 1, 1, wire);
        core::write_bits(w, 127, 7, wire);

        // 118 zeros via sym 18 (bit 1 + extra 107) -> cur_idx = 256
        core::write_bits(w, 1, 1, wire);
        core::write_bits(w, 107, 7, wire);

        // Symbol 256: length 1 via sym 1 (bit 0) -> cur_idx = 257
        core::write_bits(w, 0, 1, wire);

        // 11 zeros for distance codes via sym 18 (bit 1 + extra 0) -> cur_idx = 268
        core::write_bits(w, 1, 1, wire);
        core::write_bits(w, 0, 7, wire);

        core::flush_bits(w, wire);

        var restored: u8[>..] = [];
        let ok, err = core::inflate(wire[..], restored);
        sub.assert_false(ok, "Incomplete literal/length tree must be rejected");
        sub.assert_eq(err, core::CompressError.CodeLengthsIncomplete, "Error must be CodeLengthsIncomplete");
    };

    t.run("Fixed Huffman Distance Out of Bounds (At Stream Start)") { sub =>
        var wire: u8[>..] = [];
        var w = core::BitWriter { bit_buf: 0, bit_count: 0 };
        core::write_bits(w, 1, 1, wire); // BFINAL=1
        core::write_bits(w, 1, 2, wire); // BTYPE=1 (Fixed Huffman)
        // Match len 3 (symbol 257, 7 bits)
        core::write_bits(w, core::FIXED_LIT_CODE[257] as u32, 7, wire);
        // Distance 1 (dist symbol 0, 5 bits) at curr_decoded = 0
        core::write_bits(w, core::FIXED_DIST_CODE[0] as u32, 5, wire);
        core::flush_bits(w, wire);

        var restored: u8[>..] = [];
        let ok, err = core::inflate(wire[..], restored);
        sub.assert_false(ok, "Distance referencing prior to stream start must fail");
        sub.assert_eq(err, core::CompressError.DistanceOutOfBounds, "Error must be DistanceOutOfBounds");
    };

    t.run("Preset Dictionary Distance Out of Bounds (Prior to Dict Start)") { sub =>
        var wire: u8[>..] = [];
        var w = core::BitWriter { bit_buf: 0, bit_count: 0 };
        core::write_bits(w, 1, 1, wire); // BFINAL=1
        core::write_bits(w, 1, 2, wire); // BTYPE=1 (Fixed Huffman)
        // Match len 3 (symbol 257, 7 bits)
        core::write_bits(w, core::FIXED_LIT_CODE[257] as u32, 7, wire);
        // Distance 4 (dist symbol 3, 5 bits, DISTS_BASE[3]=4, 0 extra bits) at curr_decoded = 0
        core::write_bits(w, core::FIXED_DIST_CODE[3] as u32, 5, wire);
        core::flush_bits(w, wire);

        // Dictionary has 3 bytes ("abc"), but distance is 4 (exceeds available history 0 + 3 = 3)
        var restored: u8[>..] = [];
        let ok, err = core::inflate_with_dict(wire[..], restored, "abc");
        sub.assert_false(ok, "Match referencing prior to dictionary start must fail");
        sub.assert_eq(err, core::CompressError.DistanceOutOfBounds, "Error must be DistanceOutOfBounds");
    };

    t.run("Preset Dictionary: Valid Match Spanning Dict and Output") { sub =>
        var wire: u8[>..] = [];
        var w = core::BitWriter { bit_buf: 0, bit_count: 0 };
        core::write_bits(w, 1, 1, wire); // BFINAL=1
        core::write_bits(w, 1, 2, wire); // BTYPE=1 (Fixed Huffman)
        // Match len 4 (symbol 258, 7 bits)
        core::write_bits(w, core::FIXED_LIT_CODE[258] as u32, 7, wire);
        // Distance 3 (dist symbol 2, 5 bits, DISTS_BASE[2]=3, 0 extra bits)
        core::write_bits(w, core::FIXED_DIST_CODE[2] as u32, 5, wire);
        // EOB symbol 256 (7 bits)
        core::write_bits(w, core::FIXED_LIT_CODE[256] as u32, 7, wire);
        core::flush_bits(w, wire);

        // Dict "ABC", match dist 3, len 4 -> produces "ABCA"
        var restored: u8[>..] = [];
        let ok, err = core::inflate_with_dict(wire[..], restored, "ABC");
        sub.assert_true(ok, "Valid match against preset dictionary must succeed");
        sub.assert_eq(err, core::CompressError.None, "Error must be None");
        sub.assert_eq(restored[..], "ABCA", "Decoded output must match 'ABCA'");
    };

    t.run("Preset Dictionary with Quota Guard (inflate_with_dict_limit)") { sub =>
        var wire: u8[>..] = [];
        var w = core::BitWriter { bit_buf: 0, bit_count: 0 };
        core::write_bits(w, 1, 1, wire); // BFINAL=1
        core::write_bits(w, 1, 2, wire); // BTYPE=1 (Fixed Huffman)
        // Match len 4 (symbol 258, 7 bits)
        core::write_bits(w, core::FIXED_LIT_CODE[258] as u32, 7, wire);
        // Distance 3 (dist symbol 2, 5 bits)
        core::write_bits(w, core::FIXED_DIST_CODE[2] as u32, 5, wire);
        // EOB symbol 256
        core::write_bits(w, core::FIXED_LIT_CODE[256] as u32, 7, wire);
        core::flush_bits(w, wire);

        // Quota = 2 bytes (smaller than match len 4) -> must fail with OutputBufferOverflow
        var restored_fail: u8[>..] = [];
        let ok_f, err_f = core::inflate_with_dict_limit(wire[..], restored_fail, "ABC", 2);
        sub.assert_false(ok_f, "inflate_with_dict_limit exceeding quota must fail");
        sub.assert_eq(err_f, core::CompressError.OutputBufferOverflow, "Error must be OutputBufferOverflow");

        // Quota = 10 bytes -> must succeed
        var restored_ok: u8[>..] = [];
        let ok_s, err_s = core::inflate_with_dict_limit(wire[..], restored_ok, "ABC", 10);
        sub.assert_true(ok_s, "inflate_with_dict_limit within quota must succeed");
        sub.assert_eq(err_s, core::CompressError.None, "Error must be None");
        sub.assert_eq(restored_ok[..], "ABCA", "Output must match 'ABCA'");
    };

    t.run("Concatenated Multi-Member Gzip Quota Defense") { sub =>
        let part1 = "12345678901234567890"; // 20 bytes
        let part2 = "abcdefghijklmnopqrst"; // 20 bytes
        var gz1: u8[>..] = [];
        var gz2: u8[>..] = [];
        core::gzip_compress(part1, gz1, 6);
        core::gzip_compress(part2, gz2, 6);

        var multi_gz: u8[>..] = [];
        multi_gz.append(gz1[..]);
        multi_gz.append(gz2[..]); // Total uncompressed: 40 bytes

        // Quota = 30 bytes (allows member 1 [20 bytes], but member 2 [20 bytes] would total 40 bytes)
        var restored: u8[>..] = [];
        let ok, err = core::gzip_decompress_with_limit(multi_gz[..], restored, 30);
        sub.assert_false(ok, "Multi-member Gzip exceeding cumulative quota must fail");
        sub.assert_eq(err, core::CompressError.OutputBufferOverflow, "Error must be OutputBufferOverflow");
        sub.assert_true(restored.len <= 30, "Restored length must not exceed quota limit of 30");
    };

    t.run("Chunked ZStream Streaming Quota Defense") { sub =>
        let message = "Chunked streaming decompressor quota verification across multiple TCP slices.";
        var zb: u8[>..] = [];
        core::zlib_compress(message, zb, 6);

        var decompressor = core::new_zstream_decompressor(core::ContainerFormat.Zlib);
        var restored: u8[>..] = [];
        let quota: i64 = 25; // Smaller than message.len

        var offset: i64 = 0;
        var hit_overflow = false;
        while offset < zb.len {
            let chunk_size = if zb.len - offset < 8 { zb.len - offset } else { 8 };
            let chunk = zb[offset..offset + chunk_size];
            let err = decompressor.write_with_limit(chunk, restored, quota);
            if err == core::CompressError.OutputBufferOverflow {
                hit_overflow = true;
                break;
            }
            offset += chunk_size;
        }

        sub.assert_true(hit_overflow, "Streaming decompression exceeding quota must trigger OutputBufferOverflow");
        sub.assert_true((restored.len as i64) <= quota, "Restored length must not exceed quota limit");
    };

    t.run("Dynamic Huffman HDIST Bound Rejection (HDIST > 29)") { sub =>
        // BFINAL=1, BTYPE=2 (Dynamic), HLIT=0 (257 codes), HDIST=30 (0b11110) > 29 -> illegal
        var wire: u8[>..] = [];
        var w = core::BitWriter { bit_buf: 0, bit_count: 0 };
        core::write_bits(w, 1, 1, wire);  // BFINAL=1
        core::write_bits(w, 2, 2, wire);  // BTYPE=2 (Dynamic)
        core::write_bits(w, 0, 5, wire);  // HLIT=0 (257)
        core::write_bits(w, 30, 5, wire); // HDIST=30 (> 29, illegal)
        core::write_bits(w, 0, 4, wire);  // HCLEN=0 (4 codes)
        core::flush_bits(w, wire);

        var restored: u8[>..] = [];
        let ok, err = core::inflate(wire[..], restored);
        sub.assert_false(ok, "Dynamic block with HDIST > 29 must fail");
        sub.assert_eq(err, core::CompressError.TooManyLengthOrDistanceCodes, "Error must be TooManyLengthOrDistanceCodes");
    };

    t.run("Dynamic Huffman Repeat Without Previous Length at Index 0") { sub =>
        var wire: u8[>..] = [];
        var w = core::BitWriter { bit_buf: 0, bit_count: 0 };
        core::write_bits(w, 1, 1, wire);   // BFINAL=1
        core::write_bits(w, 2, 2, wire);   // BTYPE=2 (Dynamic)
        core::write_bits(w, 0, 5, wire);   // HLIT=0 (257)
        core::write_bits(w, 0, 5, wire);   // HDIST=0 (1)
        core::write_bits(w, 14, 4, wire);  // HCLEN=14 (18 codes)

        // Code lengths: sym 16 (index 0) = 1, sym 1 (index 17) = 1, all others 0
        for i in 18 {
            if i == 0 || i == 17 {
                core::write_bits(w, 1, 3, wire);
            } else {
                core::write_bits(w, 0, 3, wire);
            }
        }

        // Canonical codes: sym 1 gets code 0, sym 16 gets code 1
        // Emit sym 16 at cur_idx = 0 (bit 1 + 2 bits repeat count: 0)
        core::write_bits(w, 1, 1, wire);
        core::write_bits(w, 0, 2, wire);
        core::flush_bits(w, wire);

        var restored: u8[>..] = [];
        let ok, err = core::inflate(wire[..], restored);
        sub.assert_false(ok, "Symbol 16 at index 0 must fail with RepeatWithoutPreviousLength");
        sub.assert_eq(err, core::CompressError.RepeatWithoutPreviousLength, "Error must be RepeatWithoutPreviousLength");
    };

    t.run("Dynamic Huffman RLE Sym 16 Repeat Overflow (cur_idx + count > total_codes)") { sub =>
        var wire: u8[>..] = [];
        var w = core::BitWriter { bit_buf: 0, bit_count: 0 };
        core::write_bits(w, 1, 1, wire);   // BFINAL=1
        core::write_bits(w, 2, 2, wire);   // BTYPE=2 (Dynamic)
        core::write_bits(w, 0, 5, wire);   // HLIT=0 (257)
        core::write_bits(w, 0, 5, wire);   // HDIST=0 (1, total_codes = 258)
        core::write_bits(w, 14, 4, wire);  // HCLEN=14 (18 codes)

        // Code lengths: sym 16 (index 0) = 1, sym 1 (index 17) = 1
        for i in 18 {
            if i == 0 || i == 17 {
                core::write_bits(w, 1, 3, wire);
            } else {
                core::write_bits(w, 0, 3, wire);
            }
        }

        // Canonical codes: sym 1 gets code 0, sym 16 gets code 1
        // Emit 256 lengths of 1 using sym 1 (code 0) -> cur_idx becomes 256
        for i in 256 {
            core::write_bits(w, 0, 1, wire);
        }

        // Now cur_idx = 256. total_codes = 258. Remaining codes = 2.
        // Emit sym 16 (code 1) with count = 3 (extra bits = 0) -> cur_idx + count = 259 > 258!
        core::write_bits(w, 1, 1, wire);
        core::write_bits(w, 0, 2, wire);
        core::flush_bits(w, wire);

        var restored: u8[>..] = [];
        let ok, err = core::inflate(wire[..], restored);
        sub.assert_false(ok, "Symbol 16 repeat exceeding total_codes must fail");
        sub.assert_eq(err, core::CompressError.TooManyLengthOrDistanceCodes, "Error must be TooManyLengthOrDistanceCodes");
    };

    t.run("Dynamic Huffman RLE Sym 17 Repeat Zeros Overflow (cur_idx + count > total_codes)") { sub =>
        var wire: u8[>..] = [];
        var w = core::BitWriter { bit_buf: 0, bit_count: 0 };
        core::write_bits(w, 1, 1, wire);   // BFINAL=1
        core::write_bits(w, 2, 2, wire);   // BTYPE=2 (Dynamic)
        core::write_bits(w, 0, 5, wire);   // HLIT=0 (257)
        core::write_bits(w, 0, 5, wire);   // HDIST=0 (1, total_codes = 258)
        core::write_bits(w, 14, 4, wire);  // HCLEN=14 (18 codes)

        // Code lengths: sym 17 (index 1) = 1, sym 1 (index 17) = 1
        for i in 18 {
            if i == 1 || i == 17 {
                core::write_bits(w, 1, 3, wire);
            } else {
                core::write_bits(w, 0, 3, wire);
            }
        }

        // Canonical codes: sym 1 gets code 0, sym 17 gets code 1
        // Emit 256 lengths of 1 using sym 1 (code 0) -> cur_idx becomes 256
        for i in 256 {
            core::write_bits(w, 0, 1, wire);
        }

        // Now cur_idx = 256. total_codes = 258. Remaining codes = 2.
        // Emit sym 17 (code 1) with count = 3 (extra bits = 0) -> cur_idx + count = 259 > 258!
        core::write_bits(w, 1, 1, wire);
        core::write_bits(w, 0, 3, wire);
        core::flush_bits(w, wire);

        var restored: u8[>..] = [];
        let ok, err = core::inflate(wire[..], restored);
        sub.assert_false(ok, "Symbol 17 repeat zeros exceeding total_codes must fail");
        sub.assert_eq(err, core::CompressError.TooManyLengthOrDistanceCodes, "Error must be TooManyLengthOrDistanceCodes");
    };

    t.run("Dynamic Huffman RLE Sym 18 Repeat Zeros Overflow (cur_idx + count > total_codes)") { sub =>
        var wire: u8[>..] = [];
        var w = core::BitWriter { bit_buf: 0, bit_count: 0 };
        core::write_bits(w, 1, 1, wire);   // BFINAL=1
        core::write_bits(w, 2, 2, wire);   // BTYPE=2 (Dynamic)
        core::write_bits(w, 0, 5, wire);   // HLIT=0 (257)
        core::write_bits(w, 0, 5, wire);   // HDIST=0 (1, total_codes = 258)
        core::write_bits(w, 14, 4, wire);  // HCLEN=14 (18 codes)

        // Code lengths: sym 18 (index 2) = 1, sym 1 (index 17) = 1
        for i in 18 {
            if i == 2 || i == 17 {
                core::write_bits(w, 1, 3, wire);
            } else {
                core::write_bits(w, 0, 3, wire);
            }
        }

        // Canonical codes: sym 1 gets code 0, sym 18 gets code 1
        // Emit 250 lengths of 1 using sym 1 (code 0) -> cur_idx becomes 250
        for i in 250 {
            core::write_bits(w, 0, 1, wire);
        }

        // Now cur_idx = 250. total_codes = 258. Remaining codes = 8.
        // Emit sym 18 (code 1) with count = 11 (extra bits = 0) -> cur_idx + count = 261 > 258!
        core::write_bits(w, 1, 1, wire);
        core::write_bits(w, 0, 7, wire);
        core::flush_bits(w, wire);

        var restored: u8[>..] = [];
        let ok, err = core::inflate(wire[..], restored);
        sub.assert_false(ok, "Symbol 18 repeat zeros exceeding total_codes must fail");
        sub.assert_eq(err, core::CompressError.TooManyLengthOrDistanceCodes, "Error must be TooManyLengthOrDistanceCodes");
    };
}

// --- Component: core_brotli ---
// Verification suite for RFC 7932 Brotli Compression & Decompression Engine:
// 1. Bit-level framing and empty stream handling
// 2. Uncompressed meta-blocks (Level 0 encoder & decoder) with roundtrip
// 3. Official Google Brotli compressed test vectors (uncompressed & compressed)
// 4. Repetitive LZ77 matching & backward copy decoding
// 5. Built-in Static Dictionary (122 KB) & Word Transformations (Appendix B)
// 6. Output limit protection (decompression bomb defense)
// 7. Error handling on corrupted/truncated bitstreams
// 8. HTTP Client Response auto-decompression (`Content-Encoding: br`)

// ---- Official Google Brotli Test Vectors -------------------------------------

// empty raw_len=0 c_len=1
const VEC_EMPTY_RAW: const u8[0] = [];
const VEC_EMPTY_COMP: const u8[1] = [59];

// hello raw_len=23 c_len=27
const VEC_HELLO_RAW: const u8[23] = [
    72, 101, 108, 108, 111, 44, 32, 66, 114, 111, 116, 108, 105, 32, 105, 110, 32, 71, 111, 111, 115, 101, 33,
];
const VEC_HELLO_COMP: const u8[27] = [
    11, 11, 128, 72, 101, 108, 108, 111, 44, 32, 66, 114, 111, 116, 108, 105, 32, 105, 110, 32, 71, 111, 111, 115, 101, 33, 3,
];

// json raw_len=26 c_len=30
const VEC_JSON_RAW: const u8[26] = [
    123, 34, 115, 116, 97, 116, 117, 115, 34, 58, 34, 111, 107, 34, 44, 34, 99, 111, 100, 101, 34, 58, 50, 48, 48, 125,
];
const VEC_JSON_COMP: const u8[30] = [
    139, 12, 128, 123, 34, 115, 116, 97, 116, 117, 115, 34, 58, 34, 111, 107, 34, 44, 34, 99, 111, 100, 101, 34, 58, 50, 48, 48, 125, 3,
];

// repeat raw_len=100 c_len=20 (LZ77 compressed)
const VEC_REPEAT_COMP: const u8[20] = [
    139, 49, 0, 0, 32, 130, 216, 0, 14, 92, 195, 9, 113, 54, 128, 11, 112, 88, 222, 6,
];

// ---- Test Cases -------------------------------------------------------------

fn test_brotli_empty_and_uncompressed(t: core::T&) {
    t.run("Empty stream and Google Brotli uncompressed vectors") { sub =>
        // 1. Empty stream: Google Brotli vector [59]
        var dec_empty: u8[>..] = [];
        let ok_e, err_e = core::brotli_decompress(VEC_EMPTY_COMP[..], dec_empty);
        sub.assert_true(ok_e, "Decompress empty vector succeeds");
        sub.assert_true(err_e == core::CompressError.None, "No error on empty vector");
        sub.assert_eq(dec_empty.len, 0, "Decoded empty length is 0");

        // 2. Hello World vector
        var dec_hello: u8[>..] = [];
        let ok_h, err_h = core::brotli_decompress(VEC_HELLO_COMP[..], dec_hello);
        sub.assert_true(ok_h, "Decompress hello vector succeeds");
        sub.assert_true(err_h == core::CompressError.None, "No error on hello vector");
        sub.assert_eq(dec_hello.len, VEC_HELLO_RAW.len, "Hello length matches");
        sub.assert_eq(dec_hello[..], VEC_HELLO_RAW[..], "Hello payload matches 100%");

        // 3. JSON vector
        var dec_json: u8[>..] = [];
        let ok_j, err_j = core::brotli_decompress(VEC_JSON_COMP[..], dec_json);
        sub.assert_true(ok_j, "Decompress JSON vector succeeds");
        sub.assert_true(err_j == core::CompressError.None, "No error on JSON vector");
        sub.assert_eq(dec_json.len, VEC_JSON_RAW.len, "JSON length matches");
        sub.assert_eq(dec_json[..], VEC_JSON_RAW[..], "JSON payload matches 100%");
    };
}

fn test_brotli_level0_roundtrip(t: core::T&) {
    t.run("Level 0 uncompressed encoder and decoder round-trip") { sub =>
        // 1. Short text roundtrip
        let text = "Brotli zero-heap compression running natively inside Goose-Wing!";
        var comp: u8[>..] = [];
        let ok_c = core::brotli_compress(text, comp, 0);
        sub.assert_true(ok_c, "Level 0 compression succeeds");
        sub.assert_true(comp.len > 0, "Compressed output not empty");

        var decomp: u8[>..] = [];
        let ok_d, err_d = core::brotli_decompress(comp[..], decomp);
        sub.assert_true(ok_d, "Decompression succeeds");
        sub.assert_true(err_d == core::CompressError.None, "No decompression error");
        sub.assert_eq(decomp.len, text.len, "Decompressed length matches original");
        sub.assert_eq(decomp[..], text, "Decompressed content matches exactly");

        // 2. Empty string roundtrip
        var comp_empty: u8[>..] = [];
        let ok_ce = core::brotli_compress("", comp_empty, 0);
        sub.assert_true(ok_ce, "Empty string compression succeeds");

        var decomp_empty: u8[>..] = [];
        let ok_de, err_de = core::brotli_decompress(comp_empty[..], decomp_empty);
        sub.assert_true(ok_de, "Empty string decompression succeeds");
        sub.assert_eq(decomp_empty.len, 0, "Empty string roundtrips to 0 bytes");
    };
}

fn test_brotli_compressed_meta_blocks(t: core::T&) {
    t.run("Google Brotli LZ77 compressed meta-block decoding") { sub =>
        // VEC_REPEAT_COMP compresses 100 'A's into 20 bytes
        var decomp: u8[>..] = [];
        let ok, err = core::brotli_decompress(VEC_REPEAT_COMP[..], decomp);
        sub.assert_true(ok, "Decompress LZ77 vector succeeds");
        sub.assert_true(err == core::CompressError.None, "No error on repeat vector");
        sub.assert_eq(decomp.len, 100, "Decompressed length is 100");

        var all_a = true;
        for b in decomp {
            if b != ('A' as u8) {
                all_a = false;
                break;
            }
        }
        sub.assert_true(all_a, "All 100 bytes are correctly decompressed 'A's");
    };
}

fn test_brotli_static_dictionary_transforms(t: core::T&) {
    t.run("Static built-in dictionary and word transformations") { sub =>
        // 1. Verify static dictionary is present and non-empty
        sub.assert_eq(core::BROTLI_DICTIONARY.len, 122784, "Dictionary size is exactly 122,784 bytes");

        // 2. Test word transformations directly
        var word_out1: u8[>..] = [];
        // Transform 0: Identity
        let ok1 = core::brotli_transform_word("world", 0, word_out1);
        sub.assert_true(ok1, "Transform 0 succeeds");
        sub.assert_eq(word_out1[..], "world", "Transform 0 is Identity");

        // Transform 1: Add trailing space
        var word_out2: u8[>..] = [];
        let ok2 = core::brotli_transform_word("hello", 1, word_out2);
        sub.assert_true(ok2, "Transform 1 succeeds");
        sub.assert_eq(word_out2[..], "hello ", "Transform 1 adds trailing space");

        // Transform 2: Add leading and trailing space
        var word_out3: u8[>..] = [];
        let ok3 = core::brotli_transform_word("test", 2, word_out3);
        sub.assert_true(ok3, "Transform 2 succeeds");
        sub.assert_eq(word_out3[..], " test ", "Transform 2 adds leading & trailing space");

        // Transform 4: Uppercase first and add space
        var word_out4: u8[>..] = [];
        let ok4 = core::brotli_transform_word("google", 4, word_out4);
        sub.assert_true(ok4, "Transform 4 succeeds");
        sub.assert_eq(word_out4[..], "Google ", "Transform 4 capitalizes first letter and adds space");

        // Transform 5: Add suffix " the "
        var word_out5: u8[>..] = [];
        let ok5 = core::brotli_transform_word("all", 5, word_out5);
        sub.assert_true(ok5, "Transform 5 succeeds");
        sub.assert_eq(word_out5[..], "all the ", "Transform 5 appends ' the '");

        // 3. Test static dictionary word lookup
        var dict_out: u8[>..] = [];
        // Look up 4-letter word at index 0 (distance = max_dist + 1)
        // Offset for length 4, index 0 is 0..4
        let ok_lookup = core::brotli_lookup_dictionary_word(1001, 1000, 4, dict_out);
        sub.assert_true(ok_lookup, "Dictionary lookup succeeds");
        sub.assert_true(dict_out.len >= 4, "Dictionary word length >= 4");
    };
}

fn test_brotli_quota_and_error_handling(t: core::T&) {
    t.run("Decompression bomb protection and corrupted streams") { sub =>
        // 1. Quota limit exceeded guard
        var out_limited: u8[>..] = [];
        // VEC_HELLO_COMP has 23 bytes uncompressed. Limit to 10 bytes:
        let ok_q, err_q = core::brotli_decompress_with_limit(VEC_HELLO_COMP[..], out_limited, 10);
        sub.assert_false(ok_q, "Decompression quota limit triggers failure");
        sub.assert_true(err_q == core::CompressError.OutputBufferOverflow, "Returns OutputBufferOverflow");

        // 2. Empty input buffer
        var out_empty: u8[>..] = [];
        let ok_trunc, err_trunc = core::brotli_decompress(VEC_EMPTY_RAW[..], out_empty);
        sub.assert_false(ok_trunc, "Empty buffer rejected");
        sub.assert_true(err_trunc == core::CompressError.InputBufferTruncated, "Returns InputBufferTruncated");

        // 3. Corrupted header
        var bad_bytes: u8[4] = [0xFF, 0xFF, 0xFF, 0xFF];
        var out_bad: u8[>..] = [];
        let ok_bad, _ = core::brotli_decompress(bad_bytes[..], out_bad);
        sub.assert_false(ok_bad, "Corrupted header is rejected");

        // 4. RFC 7932 Section 3.4: Duplicate symbols in simple prefix code must be rejected
        var dup_simple_bytes: u8[10] = [2, 0, 0, 0, 84, 80, 80, 32, 16, 0];
        var out_dup: u8[>..] = [];
        let ok_dup, err_dup = core::brotli_decompress(dup_simple_bytes[..], out_dup);
        sub.assert_false(ok_dup, "Simple prefix code with duplicate symbols is rejected");
        sub.assert_true(err_dup == core::CompressError.InvalidHuffmanCode, "Returns InvalidHuffmanCode");

        // 5. RFC 7932 Section 8 & Section 9.2: Static dictionary transformed word length exceeding MLEN must be rejected
        var dict_overflow_bytes: u8[10] = [98, 0, 0, 0, 4, 64, 8, 18, 32, 1];
        var out_dict_overflow: u8[>..] = [];
        let ok_do, err_do = core::brotli_decompress(dict_overflow_bytes[..], out_dict_overflow);
        sub.assert_false(ok_do, "Dictionary transformed word exceeding MLEN is rejected");
        sub.assert_true(err_do == core::CompressError.CorruptedBitstream, "Returns CorruptedBitstream on MLEN overflow");

        // 6. Decompression bomb quota: dictionary transform expansion exceeding max_output_bytes must be rejected
        var out_quota_dict: u8[>..] = [];
        let ok_qd, _ = core::brotli_decompress_with_limit(dict_overflow_bytes[..], out_quota_dict, 4);
        sub.assert_false(ok_qd, "Decompression quota defense rejects dictionary word exceeding limit");

        // 7. RFC 7932 Section 9.2: Metadata meta-blocks must be parsed and skipped cleanly without corrupting stream
        var metadata_stream: u8[15] = [172, 1, 77, 69, 84, 65, 32, 0, 8, 71, 111, 111, 115, 101, 3];
        var out_meta: u8[>..] = [];
        let ok_meta, err_meta = core::brotli_decompress(metadata_stream[..], out_meta);
        sub.assert_true(ok_meta, "Metadata meta-block decompress succeeded");
        sub.assert_eq(out_meta[..], "Goose", "Payload decompressed matches 'Goose'");
    };
}

fn test_brotli_http_client_integration(t: core::T&) {
    t.run("HTTP Client Response auto-decompression for Content-Encoding: br") { sub =>
        // 1. Compress payload with Level 0 Brotli
        let original_body = "{\"user\":\"admin\",\"authenticated\":true,\"stack\":\"wing-brotli\"}";
        var comp_body: u8[>..] = [];
        let ok_c = core::brotli_compress(original_body, comp_body, 0);
        sub.assert_true(ok_c, "Compressed test payload");

        // 2. Response with Content-Encoding: br
        var res = wing::new_response();
        res.status_code = 200;
        res.headers.push(wing::make_header("Content-Encoding", "br"));
        res.headers.push(wing::make_header("Content-Type", "application/json"));
        res.body.append(comp_body[..]);

        // 3. Transparent auto-decompression via wing::decode_body
        let ok_dec = wing::decode_body(res);
        sub.assert_true(ok_dec, "decode_body succeeded for Content-Encoding: br");
        sub.assert_eq(res.body[..], original_body, "Body was automatically decompressed from Brotli");
    };
}

// --- Component: core_compress_dict ---
// Verification suite for Compression Dictionary Transport (IETF / Chrome 123+ dcz/dcb):
// - `Use-As-Dictionary` response header parsing & dictionary caching
// - `Available-Dictionary` RFC 8941 Structured Fields byte sequence generation
// - `dcz` (Dictionary-Compressed Zstandard) frame encoding & decoding
// - Client automatic dictionary discovery, Available-Dictionary injection & transparent dcz decompression
// - Origin scoping, pattern matching, TTL expiration, and insecure HTTP rejection

fn test_dictionary_header_parsing_and_matching(t: core::T&) {
    t.run("Use-As-Dictionary Parser: match, id, ttl") { sub =>
        let raw = "match=\"/assets/*\", id=\"v1\", ttl=3600, type=\"raw\"";
        let p, ok = wing::parse_use_as_dictionary_header(raw);
        sub.assert_true(ok, "parse_use_as_dictionary_header succeeded");
        sub.assert_bytes_eq(p.match_pattern[..], "/assets/*", "match_pattern is /assets/*");
        sub.assert_bytes_eq(p.id[..], "v1", "id is v1");
        sub.assert_eq(p.ttl_sec, 3600, "ttl is 3600");
        sub.assert_bytes_eq(p.dict_type[..], "raw", "type is raw");

        // Semicolon separated format
        let raw_semi = "match=\"/api/*\"; ttl=7200";
        let p2, ok2 = wing::parse_use_as_dictionary_header(raw_semi);
        sub.assert_true(ok2, "semicolon format parsed");
        sub.assert_bytes_eq(p2.match_pattern[..], "/api/*", "match is /api/*");
        sub.assert_eq(p2.ttl_sec, 7200, "ttl is 7200");
    };

    t.run("URL Pattern Matching") { sub =>
        sub.assert_true(wing::url_path_matches_pattern("/assets/app.js", "/assets/*"), "/assets/app.js matches /assets/*");
        sub.assert_true(wing::url_path_matches_pattern("/assets/vendor/chunk.js", "/assets/*"), "subpath matches /assets/*");
        sub.assert_false(wing::url_path_matches_pattern("/api/users", "/assets/*"), "/api/users does NOT match /assets/*");
        sub.assert_true(wing::url_path_matches_pattern("/exact.js", "/exact.js"), "exact match works");
        sub.assert_false(wing::url_path_matches_pattern("/other.js", "/exact.js"), "mismatch works");
    };
}

fn test_dcz_frame_codec(t: core::T&) {
    t.run("DCZ Magic, 32-Byte Hash & Payload Codec") { sub =>
        let dict_data = "dictionary_shared_context_v1";
        let hash = core::sha256(dict_data);

        let uncompressed_target = "Hello World! This is target data to compress with dcz.";
        var dcz_wire: u8[>..] = [];
        let enc_ok = wing::encode_dcz_response(dcz_wire, hash, uncompressed_target);
        sub.assert_true(enc_ok, "encode_dcz_response ok");

        // Verify wire format:
        // Byte 0..3: 0xFF, 'D', 'C', 'Z'
        sub.assert_true(dcz_wire.len >= 36, "dcz frame is at least 36 bytes");
        sub.assert_eq(dcz_wire[0], 0xFF, "Magic byte 0 is 0xFF");
        sub.assert_eq(dcz_wire[1], 'D' as u8, "Magic byte 1 is 'D'");
        sub.assert_eq(dcz_wire[2], 'C' as u8, "Magic byte 2 is 'C'");
        sub.assert_eq(dcz_wire[3], 'Z' as u8, "Magic byte 3 is 'Z'");

        // Decode DCZ header
        var decoded_hash: u8[32] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let p_slice, dec_ok = wing::decode_dcz_header(dcz_wire[..], decoded_hash);
        sub.assert_true(dec_ok, "decode_dcz_header ok");
        sub.assert_bytes_eq(decoded_hash[..], hash[..], "Decoded 32-byte dict hash matches");

        // Decompress payload using dictionary
        var decompressed: u8[>..] = [];
        let dec_body_ok = wing::decompress_dcz_payload(p_slice, dict_data, decompressed);
        sub.assert_true(dec_body_ok, "decompress_dcz_payload ok");
        sub.assert_bytes_eq(decompressed[..], uncompressed_target, "Decompressed payload matches original target data!");
    };
}

fn test_client_dictionary_lifecycle(t: core::T&) {
    t.run("Request 1 Learns Dictionary, Request 2 Sends Available-Dictionary & Decodes dcz") { sub =>
        var client = wing::new_client();
        wing::set_clock_us(client, 1700000000000000); // t0

        let dict_body = "function sharedCommonUtils() { return 42; }";
        let dict_hash = core::sha256(dict_body);

        // 1. Mock dictionary endpoint returning Use-As-Dictionary header
        wing::mock_route(client, "GET", "https://cdn.site.com/assets/dict.js", 200, dict_body);
        wing::add_mock_header(client, "Use-As-Dictionary", "match=\"/assets/*\", id=\"v1\", ttl=86400");

        sub.assert_false(wing::has_dictionary_for(client, "https://cdn.site.com/assets/app.js"), "no dictionary before request");

        // Fetch dictionary
        let resp1, err1 = wing::get(client, "https://cdn.site.com/assets/dict.js");
        sub.assert_true(wing::ok(err1), "fetch dict ok");
        sub.assert_eq(wing::status(resp1), 200, "200 OK");

        // Client has now ingested dictionary
        sub.assert_true(wing::has_dictionary_for(client, "https://cdn.site.com/assets/app.js"), "dictionary available for /assets/app.js");
        sub.assert_false(wing::has_dictionary_for(client, "https://cdn.site.com/api/user"), "not available for non-matching path");
        sub.assert_false(wing::has_dictionary_for(client, "https://other.com/assets/app.js"), "not available for different origin");

        // 2. Mock app endpoint returning DCZ compressed response
        let original_app_js = "console.log('App started with shared utils'); sharedCommonUtils();";
        var dcz_payload: u8[>..] = [];
        wing::encode_dcz_response(dcz_payload, dict_hash, original_app_js);

        wing::mock_route(client, "GET", "https://cdn.site.com/assets/app.js", 200, dcz_payload[..]);
        wing::add_mock_header(client, "Content-Encoding", "dcz");

        // Fetch app.js: Client automatically adds Available-Dictionary and decompresses dcz!
        let resp2, err2 = wing::get(client, "https://cdn.site.com/assets/app.js");
        sub.assert_true(wing::ok(err2), "fetch app.js ok");
        sub.assert_eq(wing::status(resp2), 200, "200 OK");

        // Verify client sent Available-Dictionary header
        let sent_avail = wing::sent_header(resp2, "Available-Dictionary");
        sub.assert_true(sent_avail.len > 0, "Available-Dictionary sent in request");
        sub.assert_eq(sent_avail[0], ':' as u8, "Starts with colon (Structured Fields byte sequence)");
        sub.assert_eq(sent_avail[sent_avail.len - 1], ':' as u8, "Ends with colon");

        // Verify transparent dcz decompression!
        sub.assert_bytes_eq(resp2.body[..], original_app_js, "Body was transparently decompressed from dcz!");

        // 3. Mock app endpoint returning DCB (Dictionary-Compressed Brotli) response
        let original_app_css = "body { margin: 0; padding: 0; background: #fff; }";
        var dcb_payload: u8[>..] = [];
        wing::encode_dcb_response(dcb_payload, dict_hash, original_app_css);

        wing::mock_route(client, "GET", "https://cdn.site.com/assets/style.css", 200, dcb_payload[..]);
        wing::add_mock_header(client, "Content-Encoding", "dcb");

        let resp3, err3 = wing::get(client, "https://cdn.site.com/assets/style.css");
        sub.assert_true(wing::ok(err3), "fetch style.css ok");
        sub.assert_bytes_eq(resp3.body[..], original_app_css, "Body was transparently decompressed from dcb!");
    };

    t.run("Dictionary TTL Expiration") { sub =>
        var client = wing::new_client();
        wing::set_clock_us(client, 1700000000000000); // t0

        wing::mock_route(client, "GET", "https://api.site.com/dict", 200, "short_lived_dictionary");
        wing::add_mock_header(client, "Use-As-Dictionary", "match=\"/api/*\", id=\"temp\", ttl=3");

        let _, _ = wing::get(client, "https://api.site.com/dict");
        sub.assert_true(wing::has_dictionary_for(client, "https://api.site.com/api/v1"), "valid at t0");

        // Advance 2s: still valid
        wing::set_clock_us(client, 1700000002000000);
        sub.assert_true(wing::has_dictionary_for(client, "https://api.site.com/api/v1"), "valid at t0+2s (< 3s)");

        // Advance 4s: expired
        wing::set_clock_us(client, 1700000004000000);
        sub.assert_false(wing::has_dictionary_for(client, "https://api.site.com/api/v1"), "expired at t0+4s (>= 3s)");
    };

    t.run("Insecure Transport Security Invariant") { sub =>
        var client = wing::new_client();
        wing::set_clock_us(client, 1700000000000000);

        // Plain HTTP server tries to declare a dictionary
        wing::mock_route(client, "GET", "http://insecure.site.com/dict", 200, "insecure_dict");
        wing::add_mock_header(client, "Use-As-Dictionary", "match=\"/*\"");

        let _, _ = wing::get(client, "http://insecure.site.com/dict");
        sub.assert_false(wing::has_dictionary_for(client, "http://insecure.site.com/page"), "Use-As-Dictionary ignored over insecure HTTP");
    };
}

fn main() {
    var runner = core::new_runner("Core Compression Engine (Deflate, Brotli, Dictionaries) Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. IEEE 802.3 CRC-32 & RFC 1950 Adler-32 Checksums", test_checksums);
    core::run_case(runner, "2. RFC 1951 Deflate & Inflate (Stored and LZ77 + Fixed)", test_deflate_stored_and_fixed);
    core::run_case(runner, "3. RFC 1952 Gzip Container & Verification", test_gzip_container);
    core::run_case(runner, "4. RFC 1950 Zlib Container & Verification", test_zlib_container);
    core::run_case(runner, "5. Boundary & Sliding Window Wrap Vectors", test_boundary_and_large_buffers);
    core::run_case(runner, "6. Dynamic Huffman Coding & BTYPE Invariants", test_dynamic_huffman_and_btypes);
    core::run_case(runner, "7. Streaming State Machine & Flush Modes (ZStream)", test_streaming_and_flush_modes);
    core::run_case(runner, "8. Preset Dictionaries & RFC 1950 FDICT Handling", test_preset_dictionary_and_fdict);
    core::run_case(runner, "9. Universal Container Auto-Detection", test_universal_autodetect);
    core::run_case(runner, "10. Lazy Matching & Stored Block Cost Selection", test_lazy_matching_and_stored_cost_selection);
    core::run_case(runner, "11. Concatenated Gzip Members & FHCRC", test_concatenated_gzip_and_fhcrc);
    core::run_case(runner, "12. Decompression Bomb Quota Guards", test_zipbomb_quota_guards);
    core::run_case(runner, "13. Resumable Arbitrary-Chunk Streaming", test_resumable_streaming_chunk_by_chunk);
    core::run_case(runner, "14. RFC 8878 Zstandard Frame Decompression & Test Vectors", test_zstandard_rfc8878);
    core::run_case(runner, "15. RFC 1951 Stored Blocks & Huffman Header Bounds", test_rfc1951_bounds_and_error_handling);
    core::run_case(runner, "16. Empty Stream and Google Brotli Vectors", test_brotli_empty_and_uncompressed);
    core::run_case(runner, "17. Level 0 Uncompressed Round-Trip", test_brotli_level0_roundtrip);
    core::run_case(runner, "18. Compressed Meta-Block Decoding", test_brotli_compressed_meta_blocks);
    core::run_case(runner, "19. Static Built-in Dictionary and Word Transforms", test_brotli_static_dictionary_transforms);
    core::run_case(runner, "20. Decompression Bomb Quota Protection & Errors", test_brotli_quota_and_error_handling);
    core::run_case(runner, "21. HTTP Client Response Content-Encoding: br", test_brotli_http_client_integration);
    core::run_case(runner, "22. Dictionary Header Parsing & Pattern Matching", test_dictionary_header_parsing_and_matching);
    core::run_case(runner, "23. DCZ Wire Format Codec & Decompression", test_dcz_frame_codec);
    core::run_case(runner, "24. Client Dictionary Lifecycle & dcz Decompression", test_client_dictionary_lifecycle);

    let ok = core::finish(runner);
    assert(ok);
}
