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

fn main() {
    var runner = wing::new_runner("Goose Native Compression Engine Verification Suite", wing::Verbosity.Verbose);
    wing::run_case(runner, "1. IEEE 802.3 CRC-32 & RFC 1950 Adler-32 Checksums", test_checksums);
    wing::run_case(runner, "2. RFC 1951 Deflate & Inflate (Stored and LZ77 + Fixed)", test_deflate_stored_and_fixed);
    wing::run_case(runner, "3. RFC 1952 Gzip Container & Verification", test_gzip_container);
    wing::run_case(runner, "4. RFC 1950 Zlib Container & Verification", test_zlib_container);
    wing::run_case(runner, "5. Boundary & Sliding Window Wrap Vectors", test_boundary_and_large_buffers);
    let ok = wing::finish(runner);
    assert(ok);
}
