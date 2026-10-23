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
    let ok = wing::finish(runner);
    assert(ok);
}
