// Comprehensive test suite for Goose native compression: candidate for `core::compress`.
//
// Verification Coverage:
// 1. RFC 1950 Adler-32 & IEEE 802.3 CRC-32 Checksum Standards
// 2. RFC 1951 Deflate & Inflate (Stored and LZ77 + Fixed Huffman)
// 3. RFC 1952 Gzip Container Round-Trip & Header/Footer Verification
// 4. RFC 1950 Zlib Container Round-Trip & Adler-32 Verification
// 5. Extreme & Boundary Vectors (Empty, 1-byte, 35KB Sliding Window Wrap)
// 6. Corrupt Bitstream & Tampering Defenses (Checksum/Size/Truncation detection)
import std;
import wing from "..";

fn test_checksums(t: wing::T&) {
    t.run("CRC-32 Known Test Vectors") { sub =>
        let empty_buf: u8[0] = [];
        sub.assert_eq(wing::crc32(empty_buf[..]), 0x00000000 as u32, "CRC-32 of empty buffer must be 0x00000000");

        let vec1 = "123456789";
        sub.assert_eq(wing::crc32(vec1), 0xCBF43926 as u32, "CRC-32 of 123456789 must match 0xCBF43926");

        let vec2 = "The quick brown fox jumps over the lazy dog";
        sub.assert_eq(wing::crc32(vec2), 0x414FA339 as u32, "CRC-32 of fox pangram must match 0x414FA339");

        // Incremental CRC-32
        let part1 = "12345";
        let part2 = "6789";
        let c1 = wing::crc32_update(0, part1);
        let c2 = wing::crc32_update(c1, part2);
        sub.assert_eq(c2, 0xCBF43926 as u32, "Incremental CRC-32 must match one-shot");
    };

    t.run("Adler-32 Known Test Vectors") { sub =>
        let empty_buf: u8[0] = [];
        sub.assert_eq(wing::adler32(empty_buf[..]), 0x00000001 as u32, "Adler-32 of empty buffer must be 1");

        let vec1 = "123456789";
        sub.assert_eq(wing::adler32(vec1), 0x091E01DE as u32, "Adler-32 of 123456789 must match 0x091E01DE");

        let vec2 = "The quick brown fox jumps over the lazy dog";
        sub.assert_eq(wing::adler32(vec2), 0x5BDC0FDA as u32, "Adler-32 of fox pangram must match 0x5BDC0FDA");

        // Incremental Adler-32
        let part1 = "12345";
        let part2 = "6789";
        let a1 = wing::adler32_update(1, part1);
        let a2 = wing::adler32_update(a1, part2);
        sub.assert_eq(a2, 0x091E01DE as u32, "Incremental Adler-32 must match one-shot");
    };

    t.run("XXH64 & RFC 8878 Content Checksum Known Vectors") { sub =>
        let empty_buf: u8[0] = [];
        sub.assert_eq(wing::xxh64(empty_buf[..], 0), 0xEF46DB3751D8E999 as u64, "XXH64 empty buffer");
        sub.assert_eq(wing::xxh64_digest_32(empty_buf[..]), 0x51D8E999 as u32, "RFC 8878 32-bit checksum of empty");

        let s1 = "a";
        sub.assert_eq(wing::xxh64(s1, 0), 0xD24EC4F1A98C6E5B as u64, "XXH64 'a'");
        sub.assert_eq(wing::xxh64_digest_32(s1), 0xA98C6E5B as u32, "RFC 8878 32-bit checksum of 'a'");

        let s5 = "hello";
        sub.assert_eq(wing::xxh64(s5, 0), 0x26C7827D889F6DA3 as u64, "XXH64 'hello'");
        sub.assert_eq(wing::xxh64_digest_32(s5), 0x889F6DA3 as u32, "RFC 8878 32-bit checksum of 'hello'");

        let s32 = "12345678901234567890123456789012";
        sub.assert_eq(wing::xxh64(s32, 0), 0x40FD1AA52D98274C as u64, "XXH64 32-byte string");
        sub.assert_eq(wing::xxh64_digest_32(s32), 0x2D98274C as u32, "RFC 8878 32-bit checksum of 32-byte string");
    };
}

fn test_deflate_stored_and_fixed(t: wing::T&) {
    t.run("Deflate Stored Blocks (Level 0)") { sub =>
        let msg = "Stored block mode test: no compression, verbatim payload framing.";
        var comp: u8[>..] = [];
        let ok_c = wing::compress_deflate(msg, comp, 0);
        sub.assert_true(ok_c, "Deflate level 0 must succeed");
        sub.assert_true(comp.len > msg.len, "Stored block contains 5-byte framing overhead");

        var decomp: u8[>..] = [];
        let ok_d, err = wing::decompress_deflate(comp[..], decomp);
        sub.assert_true(ok_d, "Decompress stored block must succeed");
        sub.assert_eq(err, wing::CompressError.None, "Error must be None");
        sub.assert_eq(decomp[..], msg, "Decompressed payload must match original");
    };

    t.run("Deflate LZ77 & Fixed Huffman (Level 6)") { sub =>
        let msg = "Hello, world! This is a test of Goose native compression. Hello, world! This is a test!";
        var comp: u8[>..] = [];
        let ok_c = wing::compress_deflate(msg, comp, 6);
        sub.assert_true(ok_c, "Deflate level 6 must succeed");

        var decomp: u8[>..] = [];
        let ok_d, err = wing::decompress_deflate(comp[..], decomp);
        sub.assert_true(ok_d, "Inflate level 6 output must succeed");
        sub.assert_eq(err, wing::CompressError.None, "Error must be None");
        sub.assert_eq(decomp[..], msg, "Decompressed payload must match original");
    };

    t.run("Repetitive Data Massive Compression Ratio") { sub =>
        var rep: u8[>..] = [];
        for i in 1000 {
            rep.append("ABCDEFGHIJ");
        }
        sub.assert_eq(rep.len, 10000, "Uncompressed payload is 10,000 bytes");

        var comp: u8[>..] = [];
        let ok_c = wing::compress_deflate(rep[..], comp, 6);
        sub.assert_true(ok_c, "Compression must succeed");
        sub.assert_true(comp.len < 150, "10,000 repetitive bytes must compress under 150 bytes");

        var decomp: u8[>..] = [];
        let ok_d, err = wing::decompress_deflate(comp[..], decomp);
        sub.assert_true(ok_d, "Decompression must succeed");
        sub.assert_eq(err, wing::CompressError.None, "Error must be None");
        sub.assert_eq(decomp.len, rep.len, "Length must match");
        sub.assert_eq(decomp[..], rep[..], "Decompressed bytes must match original");
    };
}

fn test_gzip_container(t: wing::T&) {
    t.run("Gzip Compression and Decompression Round-Trip") { sub =>
        let payload = "{\"status\":200,\"message\":\"Goose zero-heap compression is lightning fast!\",\"data\":[1,2,3,4,5]}";
        var gz: u8[>..] = [];
        let ok_c = wing::compress_gzip(payload, gz, 6);
        sub.assert_true(ok_c, "gzip_compress must succeed");

        // Verify standard Gzip magic bytes (0x1F, 0x8B) and deflate method (8)
        sub.assert_true(gz.len >= 18, "Gzip stream must have at least 18 bytes");
        sub.assert_eq(gz[0], 0x1F, "ID1 must be 0x1F");
        sub.assert_eq(gz[1], 0x8B, "ID2 must be 0x8B");
        sub.assert_eq(gz[2], 0x08, "CM must be 8 (deflate)");

        var restored: u8[>..] = [];
        let ok_d, err = wing::decompress_gzip(gz[..], restored);
        sub.assert_true(ok_d, "gzip_decompress must succeed");
        sub.assert_eq(err, wing::CompressError.None, "Error must be None");
        sub.assert_eq(restored[..], payload, "Restored content must match original");
    };

    t.run("Gzip Checksum Tampering Rejection") { sub =>
        let payload = "Sensitive banking payload requiring strict CRC-32 integrity.";
        var gz: u8[>..] = [];
        wing::compress_gzip(payload, gz, 6);

        // Corrupt trailer CRC32 (located at len - 8)
        let crc_idx = gz.len - 8;
        gz[crc_idx] ^= 0xFF;

        var restored: u8[>..] = [];
        let ok_d, err = wing::decompress_gzip(gz[..], restored);
        sub.assert_false(ok_d, "Tampered CRC-32 must be rejected");
        sub.assert_eq(err, wing::CompressError.ChecksumMismatch, "Error must be ChecksumMismatch");
    };

    t.run("Gzip Size Tampering Rejection") { sub =>
        let payload = "Testing uncompressed size validation.";
        var gz: u8[>..] = [];
        wing::compress_gzip(payload, gz, 6);

        // Corrupt trailer ISIZE (located at len - 4)
        let isize_idx = gz.len - 4;
        gz[isize_idx] ^= 0x01;

        var restored: u8[>..] = [];
        let ok_d, err = wing::decompress_gzip(gz[..], restored);
        sub.assert_false(ok_d, "Tampered ISIZE must be rejected");
        sub.assert_eq(err, wing::CompressError.SizeMismatch, "Error must be SizeMismatch");
    };

    t.run("Gzip Truncated Stream Rejection") { sub =>
        let payload = "Short payload to test truncated input handling.";
        var gz: u8[>..] = [];
        wing::compress_gzip(payload, gz, 6);

        // Truncate last 5 bytes
        let trunc_len = gz.len - 5;
        let trunc_slice = gz[..trunc_len];

        var restored: u8[>..] = [];
        let ok_d, err = wing::decompress_gzip(trunc_slice, restored);
        sub.assert_false(ok_d, "Truncated stream must fail");
        sub.assert_ne(err, wing::CompressError.None, "Error must not be None on truncated stream");
    };
}

fn test_zlib_container(t: wing::T&) {
    t.run("Zlib Compression and Decompression Round-Trip") { sub =>
        let payload = "Zlib RFC 1950 container format verification with Big-Endian Adler-32.";
        var zb: u8[>..] = [];
        let ok_c = wing::compress_zlib(payload, zb, 6);
        sub.assert_true(ok_c, "compress_zlib must succeed");

        // Verify CMF (0x78) and FCHECK modulo 31
        let cmf = zb[0] as u32;
        let flg = zb[1] as u32;
        sub.assert_eq(cmf, 0x78 as u32, "CMF must be 0x78 (deflate, 32K window)");
        sub.assert_eq((cmf * 256 + flg) % 31, 0 as u32, "Header checksum (CMF*256 + FLG) % 31 must be 0");

        var restored: u8[>..] = [];
        let ok_d, err = wing::decompress_zlib(zb[..], restored);
        sub.assert_true(ok_d, "decompress_zlib must succeed");
        sub.assert_eq(err, wing::CompressError.None, "Error must be None");
        sub.assert_eq(restored[..], payload, "Restored content must match original");
    };

    t.run("Zlib Adler-32 Tampering Rejection") { sub =>
        let payload = "Adler-32 tamper test payload.";
        var zb: u8[>..] = [];
        wing::compress_zlib(payload, zb, 6);

        // Corrupt Adler-32 (last byte)
        let last_idx = zb.len - 1;
        zb[last_idx] ^= 0x55;

        var restored: u8[>..] = [];
        let ok_d, err = wing::decompress_zlib(zb[..], restored);
        sub.assert_false(ok_d, "Tampered Adler-32 must be rejected");
        sub.assert_eq(err, wing::CompressError.ChecksumMismatch, "Error must be ChecksumMismatch");
    };

    t.run("Zlib Invalid Header Rejection") { sub =>
        let payload = "Invalid header test.";
        var zb: u8[>..] = [];
        wing::compress_zlib(payload, zb, 6);

        // Corrupt CMF
        zb[0] = 0xFF;

        var restored: u8[>..] = [];
        let ok_d, err = wing::decompress_zlib(zb[..], restored);
        sub.assert_false(ok_d, "Invalid header must be rejected");
        sub.assert_eq(err, wing::CompressError.InvalidHeader, "Error must be InvalidHeader");
    };
}

fn test_boundary_and_large_buffers(t: wing::T&) {
    t.run("Single Byte Round-Trip") { sub =>
        let single: u8[1] = [0x5A];
        var gz: u8[>..] = [];
        wing::compress_gzip(single[..], gz, 6);

        var restored: u8[>..] = [];
        let ok_d, err = wing::decompress_gzip(gz[..], restored);
        sub.assert_true(ok_d, "Single byte decompress must succeed");
        sub.assert_eq(restored.len, 1, "Length must be 1");
        sub.assert_eq(restored[0], 0x5A, "Byte value must match");
    };

    t.run("Two Identical Bytes Round-Trip") { sub =>
        let two: u8[2] = [0x42, 0x42];
        var gz: u8[>..] = [];
        wing::compress_gzip(two[..], gz, 6);

        var restored: u8[>..] = [];
        let ok_d, err = wing::decompress_gzip(gz[..], restored);
        sub.assert_true(ok_d, "Two bytes decompress must succeed");
        sub.assert_eq(restored.len, 2, "Length must be 2");
        sub.assert_eq(restored[0], 0x42, "Byte 0 must match");
        sub.assert_eq(restored[1], 0x42, "Byte 1 must match");
    };

    t.run("Empty Buffer Gzip Round-Trip") { sub =>
        let empty_buf: u8[0] = [];
        var gz: u8[>..] = [];
        wing::compress_gzip(empty_buf[..], gz, 6);

        var restored: u8[>..] = [];
        let ok_d, err = wing::decompress_gzip(gz[..], restored);
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
        let ok_c = wing::compress_gzip(large[..], comp, 6);
        sub.assert_true(ok_c, "Large gzip compression must succeed");

        var restored: u8[>..] = [];
        let ok_d, err = wing::decompress_gzip(comp[..], restored);
        sub.assert_true(ok_d, "Large gzip decompression must succeed");
        sub.assert_eq(err, wing::CompressError.None, "Error must be None");
        sub.assert_eq(restored.len, large.len, "Decompressed size must match 35,840 bytes");
        sub.assert_eq(restored[..], large[..], "Payload must match exactly byte-for-byte");
    };
}

fn test_dynamic_huffman_and_btypes(t: wing::T&) {
    t.run("BTYPE Bit Header Verification") { sub =>
        let payload = "Deflate block header specification requires bit 0 to be BFINAL, and bits 1-2 to be BTYPE. Level 0 produces stored blocks (BTYPE 00). Level 1-5 produces fixed Huffman (BTYPE 01). Level 6+ produces dynamic Huffman (BTYPE 10) with custom canonical prefix code trees. Deflate block header specification requires bit 0 to be BFINAL, and bits 1-2 to be BTYPE.";

        // Level 0 (Stored): BFINAL=1, BTYPE=00 -> lowest 3 bits are 0b001 = 1
        var c0: u8[>..] = [];
        wing::compress_deflate(payload, c0, 0);
        let btype0 = (c0[0] >> 1) & 0x03;
        sub.assert_eq(btype0, 0 as u8, "Level 0 must emit BTYPE 00 (Stored block)");

        // Level 1 (Fixed): BFINAL=1, BTYPE=01 -> lowest 3 bits are 0b011 = 3
        var c1: u8[>..] = [];
        wing::compress_deflate(payload, c1, 1);
        let btype1 = (c1[0] >> 1) & 0x03;
        sub.assert_eq(btype1, 1 as u8, "Level 1 must emit BTYPE 01 (Fixed Huffman block)");

        // Level 6 (Dynamic): BFINAL=1, BTYPE=10 -> lowest 3 bits are 0b101 = 5
        var c6: u8[>..] = [];
        wing::compress_deflate(payload, c6, 6);
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
        wing::compress_deflate(skewed[..], comp_fixed, 1);

        var comp_dyn: u8[>..] = [];
        wing::compress_deflate(skewed[..], comp_dyn, 6);

        sub.assert_true(comp_dyn.len > 0, "Dynamic compression must succeed");
        sub.assert_true(comp_dyn.len <= comp_fixed.len, "Dynamic Huffman must match or beat Fixed Huffman size");

        var restored: u8[>..] = [];
        let ok_d, err = wing::decompress_deflate(comp_dyn[..], restored);
        sub.assert_true(ok_d, "Dynamic Huffman decompression must succeed");
        sub.assert_eq(restored.len, skewed.len, "Restored length must match exactly");
        sub.assert_eq(restored[..], skewed[..], "Restored payload must match verbatim");
    };
}

fn test_streaming_and_flush_modes(t: wing::T&) {
    t.run("ZStream SyncFlush WebSockets Framing") { sub =>
        var stream = wing::new_zstream_compressor(wing::ContainerFormat.Raw, 6);
        var wire: u8[>..] = [];

        let msg1 = "First streaming message chunk over WebSocket connection. ";
        let ok1 = stream.write(msg1, wire, wing::FlushMode.SyncFlush);
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
        let ok2 = stream.write(msg2, wire, wing::FlushMode.Finish);
        sub.assert_true(ok2, "Second chunk write with Finish must succeed");

        var combined: u8[>..] = [];
        combined.append(msg1);
        combined.append(msg2);

        var restored: u8[>..] = [];
        let ok_d, err = wing::decompress_deflate(wire[..], restored);
        sub.assert_true(ok_d, "Decompressing SyncFlushed multi-block stream must succeed");
        sub.assert_eq(restored.len, combined.len, "Decompressed length must match sum of chunks");
        sub.assert_eq(restored[..], combined[..], "Decompressed stream payload must match verbatim");
    };

    t.run("ZStream FullFlush Archive Checkpoints") { sub =>
        var stream = wing::new_zstream_compressor(wing::ContainerFormat.Raw, 6);
        var wire: u8[>..] = [];

        let part1 = "Checkpoint block A: independent data partition. ";
        stream.write(part1, wire, wing::FlushMode.FullFlush);

        let part2 = "Checkpoint block B: second isolated data partition.";
        stream.write(part2, wire, wing::FlushMode.Finish);

        var combined: u8[>..] = [];
        combined.append(part1);
        combined.append(part2);

        var restored: u8[>..] = [];
        let ok_d, err = wing::decompress_deflate(wire[..], restored);
        sub.assert_true(err == wing::CompressError.None, "err must be None");
        sub.assert_true(err != wing::CompressError.DistanceOutOfBounds, "err is not DistanceOutOfBounds");
        sub.assert_true(err != wing::CompressError.InputBufferTruncated, "err is not InputBufferTruncated");
        sub.assert_true(err != wing::CompressError.InvalidBlockType, "err is not InvalidBlockType");
        sub.assert_true(err != wing::CompressError.InvalidHuffmanCode, "err is not InvalidHuffmanCode");
        sub.assert_true(ok_d, "Decompressing FullFlushed stream must succeed");
        sub.assert_eq(restored.len, combined.len, "Decompressed length must match combined");
        sub.assert_eq(restored[..], combined[..], "Decompressed payload must match verbatim");
    };
}

fn test_preset_dictionary_and_fdict(t: wing::T&) {
    t.run("RFC 1950 FDICT Zlib Compression & Verification") { sub =>
        let dict = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";
        let payload = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0 CustomRequestData/2.0";

        var comp: u8[>..] = [];
        let ok_c = wing::compress_zlib_dict(payload, comp, 6, dict);
        sub.assert_true(ok_c, "Zlib dictionary compression must succeed");

        // Verify FDICT bit (bit 5) in FLG byte (byte 1)
        let flg = comp[1] as u32;
        sub.assert_true((flg & 0x20) != 0, "FLG byte bit 5 (FDICT) must be set");

        // Verify 4-byte DICTID in bytes 2..6 matches adler32(dict)
        let expected_dict_id = wing::adler32(dict);
        let actual_dict_id = ((comp[2] as u32) << 24) |
                             ((comp[3] as u32) << 16) |
                             ((comp[4] as u32) << 8) |
                             (comp[5] as u32);
        sub.assert_eq(actual_dict_id, expected_dict_id, "DICTID must match Adler-32 of dictionary");

        // Decompress with missing dictionary must fail with NeedDictionary
        var bad1: u8[>..] = [];
        let ok_d1, err1 = wing::decompress_zlib_dict(comp[..], bad1, "");
        sub.assert_false(ok_d1, "Decompress without dictionary must fail");
        sub.assert_eq(err1, wing::CompressError.NeedDictionary, "Error must be NeedDictionary");

        // Decompress with wrong dictionary must fail with DictionaryMismatch
        var bad2: u8[>..] = [];
        let ok_d2, err2 = wing::decompress_zlib_dict(comp[..], bad2, "Wrong Dictionary Content Here");
        sub.assert_false(ok_d2, "Decompress with wrong dictionary must fail");
        sub.assert_eq(err2, wing::CompressError.DictionaryMismatch, "Error must be DictionaryMismatch");

        // Decompress with correct dictionary must succeed
        var restored: u8[>..] = [];
        let ok_d3, err3 = wing::decompress_zlib_dict(comp[..], restored, dict);
        sub.assert_true(ok_d3, "Decompress with correct dictionary must succeed");
        sub.assert_eq(err3, wing::CompressError.None, "Error must be None");
        sub.assert_eq(restored[..], payload, "Restored payload must match original");
    };

    t.run("Raw Deflate Preset Dictionary Round-Trip") { sub =>
        let dict = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nServer: Wing\r\n";
        let payload = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{\"success\":true}";

        var comp: u8[>..] = [];
        let ok_c = wing::compress_deflate_dict(payload, comp, 6, dict);
        sub.assert_true(ok_c, "Deflate dict compression must succeed");

        var restored: u8[>..] = [];
        let ok_d, err = wing::decompress_deflate_dict(comp[..], restored, dict);
        sub.assert_true(ok_d, "Deflate dict decompression must succeed");
        sub.assert_eq(err, wing::CompressError.None, "Error must be None");
        sub.assert_eq(restored[..], payload, "Restored text must match verbatim");
    };
}

fn test_universal_autodetect(t: wing::T&) {
    t.run("Auto-Detect Gzip, Zlib, and Raw Deflate") { sub =>
        let original = "Universal automatic decompressor test for Wing stdlib candidate.";

        // 1. Gzip
        var gz: u8[>..] = [];
        wing::compress_gzip(original, gz, 6);
        sub.assert_eq(wing::detect_container_format(gz[..]), wing::ContainerFormat.Gzip, "Format must be Gzip");

        var out_gz: u8[>..] = [];
        let ok_gz, err_gz = wing::decompress(gz[..], out_gz);
        sub.assert_true(ok_gz, "Auto-decompress Gzip must succeed");
        sub.assert_eq(err_gz, wing::CompressError.None, "Error must be None");
        sub.assert_eq(out_gz[..], original, "Gzip output must match original");

        // 2. Zlib
        var zb: u8[>..] = [];
        wing::compress_zlib(original, zb, 6);
        sub.assert_eq(wing::detect_container_format(zb[..]), wing::ContainerFormat.Zlib, "Format must be Zlib");

        var out_zb: u8[>..] = [];
        let ok_zb, err_zb = wing::decompress(zb[..], out_zb);
        sub.assert_true(ok_zb, "Auto-decompress Zlib must succeed");
        sub.assert_eq(err_zb, wing::CompressError.None, "Error must be None");
        sub.assert_eq(out_zb[..], original, "Zlib output must match original");

        // 3. Raw Deflate
        var df: u8[>..] = [];
        wing::compress_deflate(original, df, 6);
        sub.assert_eq(wing::detect_container_format(df[..]), wing::ContainerFormat.Raw, "Format must be Raw Deflate");

        var out_df: u8[>..] = [];
        let ok_df, err_df = wing::decompress(df[..], out_df);
        sub.assert_true(ok_df, "Auto-decompress Raw Deflate must succeed");
        sub.assert_eq(err_df, wing::CompressError.None, "Error must be None");
        sub.assert_eq(out_df[..], original, "Deflate output must match original");
    };
}

fn test_lazy_matching_and_stored_cost_selection(t: wing::T&) {
    t.run("Lazy Matching Ratio Advantage") { sub =>
        var src: u8[>..] = [];
        let pattern = "The quick brown fox jumps over the lazy dog repeatedly in structured sequences. ";
        for i in 25 {
            src.append(pattern);
        }

        var l1_out: u8[>..] = [];
        wing::compress_deflate(src[..], l1_out, 1);

        var l9_out: u8[>..] = [];
        wing::compress_deflate(src[..], l9_out, 9);

        sub.assert_true(l9_out.len <= l1_out.len, "Level 9 lazy matching must be equal or smaller than level 1 greedy");

        var restored: u8[>..] = [];
        let ok, err = wing::decompress_deflate(l9_out[..], restored);
        sub.assert_true(ok, "Decompressing level 9 must succeed");
        sub.assert_eq(err, wing::CompressError.None, "Error must be None");
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
        wing::compress_deflate(random_data[..], comp, 6);

        // Exact bit-cost selection guarantees stored block envelope overhead is <= 15 bytes
        sub.assert_true(comp.len <= (random_data.len + 15), "Deflate must never expand incompressible data beyond framing");

        var restored: u8[>..] = [];
        let ok, err = wing::decompress_deflate(comp[..], restored);
        sub.assert_true(ok, "Decompressing incompressible stored block must succeed");
        sub.assert_eq(err, wing::CompressError.None, "Error must be None");
        sub.assert_eq(restored[..], random_data[..], "Restored incompressible payload must match bit-for-bit");
    };
}

fn test_concatenated_gzip_and_fhcrc(t: wing::T&) {
    t.run("Concatenated Gzip Members (RFC 1952 multi-member)") { sub =>
        let part1 = "First concatenated gzip archive member. ";
        let part2 = "Second concatenated gzip archive member with independent payload.";

        var gz1: u8[>..] = [];
        wing::compress_gzip(part1, gz1, 6);

        var gz2: u8[>..] = [];
        wing::compress_gzip(part2, gz2, 6);

        var combined_gz: u8[>..] = [];
        combined_gz.append(gz1[..]);
        combined_gz.append(gz2[..]);

        var combined_text: u8[>..] = [];
        combined_text.append(part1);
        combined_text.append(part2);

        var restored: u8[>..] = [];
        let ok, err = wing::decompress_gzip(combined_gz[..], restored);
        sub.assert_true(ok, "Decompressing concatenated Gzip stream must succeed");
        sub.assert_eq(err, wing::CompressError.None, "Error must be None");
        sub.assert_eq(restored.len, combined_text.len, "Length must match combined length");
        sub.assert_eq(restored[..], combined_text[..], "Payload must match concatenation verbatim");
    };

    t.run("Gzip Header Metadata and FHCRC Verification") { sub =>
        let payload = "Config file with filename, comment, and 16-bit header CRC.";
        var gz: u8[>..] = [];
        let ok_c = wing::compress_gzip_with_header(payload, gz, 6, "config.ini", "production settings", true);
        sub.assert_true(ok_c, "Gzip compress with header and FHCRC must succeed");

        var restored: u8[>..] = [];
        let ok_d, err_d = wing::decompress_gzip(gz[..], restored);
        sub.assert_true(ok_d, "Decompressing Gzip with valid FHCRC must succeed");
        sub.assert_eq(err_d, wing::CompressError.None, "Error must be None");
        sub.assert_eq(restored[..], payload, "Restored payload must match");

        // Tamper with header byte to invalidate FHCRC
        var tampered: u8[>..] = [];
        tampered.append(gz[..]);
        tampered[10] ^= 0x55; // Tamper character in filename

        var restored_fail: u8[>..] = [];
        let ok_fail, err_fail = wing::decompress_gzip(tampered[..], restored_fail);
        sub.assert_true(!ok_fail, "Decompressing tampered header must fail");
        sub.assert_eq(err_fail, wing::CompressError.ChecksumMismatch, "Error must be ChecksumMismatch");
    };
}

fn test_zipbomb_quota_guards(t: wing::T&) {
    t.run("Deflate Quota Overflow Cutoff") { sub =>
        var bomb: u8[>..] = [];
        for i in 15000 {
            bomb.push(0x42);
        }

        var wire: u8[>..] = [];
        wing::compress_deflate(bomb[..], wire, 6);

        var restored: u8[>..] = [];
        let ok, err = wing::decompress_deflate_with_limit(wire[..], restored, 500);
        sub.assert_true(!ok, "Decompression exceeding quota must fail");
        sub.assert_eq(err, wing::CompressError.OutputBufferOverflow, "Error must be OutputBufferOverflow");
        sub.assert_true(restored.len <= 500, "Output length must not exceed quota limit");
    };

    t.run("Gzip Quota Overflow Cutoff") { sub =>
        var bomb: u8[>..] = [];
        for i in 15000 {
            bomb.push(0x5A);
        }

        var wire: u8[>..] = [];
        wing::compress_gzip(bomb[..], wire, 6);

        var restored: u8[>..] = [];
        let ok, err = wing::decompress_gzip_with_limit(wire[..], restored, 400);
        sub.assert_true(!ok, "Gzip decompression exceeding quota must fail");
        sub.assert_eq(err, wing::CompressError.OutputBufferOverflow, "Error must be OutputBufferOverflow");
        sub.assert_true(restored.len <= 400, "Output length must not exceed quota limit");
    };

    t.run("Zlib Quota Overflow Cutoff") { sub =>
        var bomb: u8[>..] = [];
        for i in 15000 {
            bomb.push(0x7F);
        }

        var wire: u8[>..] = [];
        wing::compress_zlib(bomb[..], wire, 6);

        var restored: u8[>..] = [];
        let ok, err = wing::decompress_zlib_with_limit(wire[..], restored, 350);
        sub.assert_true(!ok, "Zlib decompression exceeding quota must fail");
        sub.assert_eq(err, wing::CompressError.OutputBufferOverflow, "Error must be OutputBufferOverflow");
        sub.assert_true(restored.len <= 350, "Output length must not exceed quota limit");
    };
}

fn test_resumable_streaming_chunk_by_chunk(t: wing::T&) {
    t.run("ZStream 1-Byte Slices Feeding") { sub =>
        let message = "Resumable streaming decompressor feeding arbitrary tiny byte slices across network boundaries.";
        var wire: u8[>..] = [];
        wing::compress_zlib(message, wire, 6);

        var decompressor = wing::new_zstream_decompressor(wing::ContainerFormat.Zlib);
        var restored: u8[>..] = [];

        // Feed byte by byte
        for i in wire.len {
            let single_byte = wire[i..i + 1];
            let err = decompressor.write(single_byte, restored);
            sub.assert_eq(err, wing::CompressError.None, "Writing single byte slice must not return error");
        }

        sub.assert_eq(restored.len, message.len, "Restored length must match message length");
        sub.assert_eq(restored[..], message, "Restored payload from 1-byte chunks must match verbatim");
    };

    t.run("ZStream Variable Prime Slices Feeding") { sub =>
        let message = "Another streaming verification test using prime-sized slices (3, 7, 11 bytes) to simulate jitter.";
        var wire: u8[>..] = [];
        wing::compress_gzip(message, wire, 6);

        var decompressor = wing::new_zstream_decompressor(wing::ContainerFormat.Gzip);
        var restored: u8[>..] = [];

        var offset: i64 = 0;
        var step: i64 = 3;
        while offset < wire.len {
            let rem = wire.len - offset;
            let take = if rem < step { rem } else { step };
            let chunk = wire[offset..offset + take];
            let err = decompressor.write(chunk, restored);
            sub.assert_eq(err, wing::CompressError.None, "Writing variable chunk must succeed");
            offset += take;
            step = if step == 3 { 7 } else if step == 7 { 11 } else { 3 };
        }

        sub.assert_eq(restored.len, message.len, "Restored length must match message length");
        sub.assert_eq(restored[..], message, "Restored payload from prime chunks must match verbatim");
    };
}

// Reference test frames generated by official Zstandard library (v1.5.7)
const ZSTD_REF_EMPTY: u8[9] = [
    0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x00, 0x01, 0x00, 0x00
];

const ZSTD_REF_SHORT_TEXT: u8[25] = [
    0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x10, 0x81, 0x00, 0x00, 0x48, 0x65, 0x6C,
    0x6C, 0x6F, 0x20, 0x5A, 0x73, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64,
    0x21
];

const ZSTD_REF_RLE: u8[17] = [
    0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x40, 0x45, 0x00, 0x00, 0x10, 0x41, 0x41,
    0x01, 0x00, 0x93, 0x00, 0x16
];

const ZSTD_REF_REPEATED_WORDS: u8[27] = [
    0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x37, 0x95, 0x00, 0x00, 0x60, 0x67, 0x6F,
    0x6F, 0x73, 0x65, 0x20, 0x77, 0x69, 0x6E, 0x67, 0x20, 0x21, 0x01, 0x00,
    0xD8, 0x2C, 0x5E
];

const ZSTD_REF_FOX_PANGRAM: u8[63] = [
    0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x5A, 0xB5, 0x01, 0x00, 0xE4, 0x02, 0x54,
    0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6B, 0x20, 0x62, 0x72, 0x6F,
    0x77, 0x6E, 0x20, 0x66, 0x6F, 0x78, 0x20, 0x6A, 0x75, 0x6D, 0x70, 0x73,
    0x20, 0x6F, 0x76, 0x65, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6C, 0x61,
    0x7A, 0x79, 0x20, 0x64, 0x6F, 0x67, 0x2E, 0x20, 0x00, 0x01, 0x00, 0x0D,
    0x9A, 0xAA, 0x0C
];

fn test_zstandard_rfc8878(t: wing::T&) {
    t.run("Reference Zstd Empty Frame") { sub =>
        var decomp: u8[>..] = [];
        let ok, err = wing::decompress_zstd(ZSTD_REF_EMPTY[..], decomp);
        sub.assert_true(ok, "Decompressing empty frame must succeed");
        sub.assert_eq(err, wing::CompressError.None, "Empty frame error code must be None");
        sub.assert_eq(decomp.len, 0 as i64, "Decompressed length must be 0");
    };

    t.run("Reference Zstd Short Text (Raw Block)") { sub =>
        var decomp: u8[>..] = [];
        let ok, err = wing::decompress_zstd(ZSTD_REF_SHORT_TEXT[..], decomp);
        sub.assert_true(ok, "Decompressing short text frame must succeed");
        sub.assert_eq(err, wing::CompressError.None, "Short text error code must be None");
        sub.assert_eq(decomp[..], "Hello Zstandard!", "Decoded text must match verbatim");
    };

    t.run("Reference Zstd RLE Pattern (Compressed Block with RLE)") { sub =>
        var decomp: u8[>..] = [];
        let ok, err = wing::decompress_zstd(ZSTD_REF_RLE[..], decomp);
        sub.assert_true(ok, "Decompressing RLE frame must succeed");
        sub.assert_eq(err, wing::CompressError.None, "RLE error code must be None");
        sub.assert_eq(decomp.len, 64 as i64, "Decoded length must be 64");
        var all_a = true;
        for b in decomp {
            if b != 0x41 { all_a = false; }
        }
        sub.assert_true(all_a, "All decoded bytes must be 'A'");
    };

    t.run("Reference Zstd Sequences & Repeat Offsets") { sub =>
        var decomp: u8[>..] = [];
        let ok, err = wing::decompress_zstd(ZSTD_REF_REPEATED_WORDS[..], decomp);
        sub.assert_true(ok, "Decompressing repeated words frame must succeed");
        sub.assert_eq(err, wing::CompressError.None, "Repeated words error code must be None");
        sub.assert_eq(decomp[..], "goose wing goose wing goose wing goose wing goose wing!", "Restored repeated words must match verbatim");
    };

    t.run("Reference Zstd Fox Pangram (Compressed Block)") { sub =>
        var decomp: u8[>..] = [];
        let ok, err = wing::decompress_zstd(ZSTD_REF_FOX_PANGRAM[..], decomp);
        sub.assert_true(ok, "Decompressing fox pangram frame must succeed");
        sub.assert_eq(err, wing::CompressError.None, "Fox pangram error code must be None");
        let expected = "The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.\0";
        sub.assert_eq(decomp.len, expected.len, "Pangram length must match");
        sub.assert_eq(decomp[..], expected, "Decoded pangram must match verbatim");
    };

    t.run("Clean-Room Native Zstd Round-Trip (Small, Medium, Large)") { sub =>
        let samples: const u8[:][3] = [
            "Zstd clean room native Goose compressor test payload.",
            "High-performance systems programming in Goose: modern syntax, zero-heap memory model, C++ and Rust speed.",
            "1234567890"
        ];

        for sample in samples {
            var wire: u8[>..] = [];
            let ok_c = wing::compress_zstd(sample, wire, true);
            sub.assert_true(ok_c, "Zstd compression must succeed");
            sub.assert_true(wire.len >= 4, "Compressed frame must contain at least magic");

            var restored: u8[>..] = [];
            let ok_d, err_d = wing::decompress_zstd(wire[..], restored);
            sub.assert_true(ok_d, "Zstd decompression must succeed");
            sub.assert_eq(err_d, wing::CompressError.None, "Error must be None");
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
        let ok_c = wing::compress_zstd(large_input[..], wire, true);
        sub.assert_true(ok_c, "Multi-block Zstd compression must succeed");

        var restored: u8[>..] = [];
        let ok_d, err_d = wing::decompress_zstd(wire[..], restored);
        sub.assert_true(ok_d, "Multi-block Zstd decompression must succeed");
        sub.assert_eq(err_d, wing::CompressError.None, "Multi-block error must be None");
        sub.assert_eq(restored.len, large_input.len, "Restored length must match 150,000 bytes");
        sub.assert_eq(restored[..], large_input[..], "Restored payload must match verbatim across block boundaries");
    };

    t.run("Content Checksum Verification & Tamper Detection") { sub =>
        let message = "Tamper detection test payload with XXH64 content checksum.";
        var wire: u8[>..] = [];
        wing::compress_zstd(message, wire, true);

        // Tamper with data payload
        var tampered: u8[>..] = [];
        tampered.append(wire[..]);
        let data_idx = 10;
        tampered[data_idx] = tampered[data_idx] ^ 0xFF;

        var restored: u8[>..] = [];
        let ok_d, err_d = wing::decompress_zstd(tampered[..], restored);
        sub.assert_false(ok_d, "Decompressing tampered frame must fail");
        sub.assert_eq(err_d, wing::CompressError.ChecksumMismatch, "Tampered payload must trigger ChecksumMismatch");
    };

    t.run("Decompression Bomb Quota Guards") { sub =>
        let message = "A somewhat long message intended to test quota limits on output buffer.";
        var wire: u8[>..] = [];
        wing::compress_zstd(message, wire, false);

        var restored: u8[>..] = [];
        let quota: i64 = 20; // smaller than message length
        let ok_d, err_d = wing::decompress_zstd_with_limit(wire[..], restored, quota);
        sub.assert_false(ok_d, "Decompressing beyond quota must fail");
        sub.assert_eq(err_d, wing::CompressError.OutputBufferOverflow, "Must return OutputBufferOverflow");
    };

    t.run("Universal Auto-Detection for Zstandard") { sub =>
        let message = "Auto-detection test vector for RFC 8878 Zstandard magic.";
        var wire: u8[>..] = [];
        wing::compress_zstd(message, wire, false);

        let fmt = wing::detect_container_format(wire[..]);
        sub.assert_eq(fmt, wing::ContainerFormat.Zstd, "detect_container_format must recognize ContainerFormat.Zstd");

        var restored: u8[>..] = [];
        let ok_d, err_d = wing::decompress(wire[..], restored);
        sub.assert_true(ok_d, "decompress_auto must succeed for Zstd frame");
        sub.assert_eq(err_d, wing::CompressError.None, "Auto-decompress error must be None");
        sub.assert_eq(restored[..], message, "Auto-decompressed text must match verbatim");
    };

    t.run("HTTP Response Content-Encoding: zstd Integration") { sub =>
        let raw_payload = "HTTP/1.1 response body compressed with Zstandard content-encoding.";
        var wire: u8[>..] = [];
        wing::compress_zstd(raw_payload, wire, true);

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
        wing::compress_zstd(message, wire, true);

        // Feed arbitrary chunks (13 bytes at a time) to ZStreamDecompressor in Auto mode
        var dec = wing::new_zstream_decompressor(wing::ContainerFormat.Auto);
        var restored: u8[>..] = [];
        var offset: i64 = 0;
        let chunk_size: i64 = 13;

        while offset < wire.len {
            let rem = wire.len - offset;
            let take = if rem < chunk_size { rem } else { chunk_size };
            let err = wing::zstream_decompress_write_limit(dec, wire[offset .. offset + take], restored);
            sub.assert_eq(err, wing::CompressError.None, "zstream_decompress_write_limit must succeed on chunk");
            offset += take;
        }

        sub.assert_true(dec.is_finished, "ZStreamDecompressor must be finished");
        sub.assert_eq(restored[..], message, "ZStream chunk-streamed Zstd must match original payload");
    };
}

fn main() {
    var runner = wing::new_runner("Goose Native Compression Engine Verification Suite", wing::Verbosity.Verbose);
    wing::run_case(runner, "1. IEEE 802.3 CRC-32 & RFC 1950 Adler-32 Checksums", test_checksums);
    wing::run_case(runner, "2. RFC 1951 Deflate & Inflate (Stored and LZ77 + Fixed)", test_deflate_stored_and_fixed);
    wing::run_case(runner, "3. RFC 1952 Gzip Container & Verification", test_gzip_container);
    wing::run_case(runner, "4. RFC 1950 Zlib Container & Verification", test_zlib_container);
    wing::run_case(runner, "5. Boundary & Sliding Window Wrap Vectors", test_boundary_and_large_buffers);
    wing::run_case(runner, "6. Dynamic Huffman Coding & BTYPE Invariants", test_dynamic_huffman_and_btypes);
    wing::run_case(runner, "7. Streaming State Machine & Flush Modes (ZStream)", test_streaming_and_flush_modes);
    wing::run_case(runner, "8. Preset Dictionaries & RFC 1950 FDICT Handling", test_preset_dictionary_and_fdict);
    wing::run_case(runner, "9. Universal Container Auto-Detection", test_universal_autodetect);
    wing::run_case(runner, "10. Lazy Matching & Stored Block Cost Selection", test_lazy_matching_and_stored_cost_selection);
    wing::run_case(runner, "11. Concatenated Gzip Members & FHCRC", test_concatenated_gzip_and_fhcrc);
    wing::run_case(runner, "12. Decompression Bomb Quota Guards", test_zipbomb_quota_guards);
    wing::run_case(runner, "13. Resumable Arbitrary-Chunk Streaming", test_resumable_streaming_chunk_by_chunk);
    wing::run_case(runner, "14. RFC 8878 Zstandard Frame Decompression & Clean-Room Vectors", test_zstandard_rfc8878);
    let ok = wing::finish(runner);
    assert(ok);
}
