// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Hardening & Security Invariants Suite for HPACK / RFC 7541 and RFC 9113:
// 1. Shift overflow & 31-bit integer boundary attacks (FIND-401).
// 2. Dynamic table LIFO index mapping, eviction to 0, and ring buffer wrap-around.
// 3. Dynamic table size update placement & bounds enforcement.
// 4. RFC 9113 pseudo-header ordering, duplicate checks, and connection header bans.
import std;
import core from "..";
import wing from "..";

fn test_hpack_integer_codec_overflows(t: core::T&) {
    t.run("HPACK-SEC-01: Prefix bits out of range and empty slice bounds") { sub =>
        let empty_buf: u8[0] = [];
        let _, _, ok_empty = wing::hpack_decode_int(empty_buf[..], 0, 7);
        sub.assert_false(ok_empty, "empty slice must fail integer decoding");

        let buf: u8[4] = [0xFF, 0xFF, 0xFF, 0x00];
        let _, _, ok_zero_pref = wing::hpack_decode_int(buf[..], 0, 0);
        sub.assert_false(ok_zero_pref, "prefix_bits = 0 is invalid per RFC 7541");

        let _, _, ok_nine_pref = wing::hpack_decode_int(buf[..], 0, 9);
        sub.assert_false(ok_nine_pref, "prefix_bits = 9 is invalid (> 8)");
    };

    t.run("HPACK-SEC-02: Multibyte Integer Decoding Correctness") { sub =>
        // 5-bit prefix: 31 + (26 + (10 << 7)) = 31 + 26 + 1280 = 1337
        let enc_1337: u8[3] = [0x1F, 0x9A, 0x0A];
        let val, next_off, ok = wing::hpack_decode_int(enc_1337[..], 0, 5);
        sub.assert_true(ok, "decoding 1337 succeeds");
        sub.assert_eq(val, 1337, "decoded integer matches 1337");
        sub.assert_eq(next_off, 3, "consumed 3 bytes");

        // Single-byte integer: 10 with 7-bit prefix
        let enc_single: u8[1] = [0x0A];
        let val_s, off_s, ok_s = wing::hpack_decode_int(enc_single[..], 0, 7);
        sub.assert_true(ok_s, "single-byte decode succeeds");
        sub.assert_eq(val_s, 10, "decoded value is 10");
        sub.assert_eq(off_s, 1, "consumed 1 byte");
    };

    t.run("HPACK-SEC-03: Truncated Continuation Sequence Detection") { sub =>
        // 7-bit prefix is 127 (0x7F), followed by 0x80 (continuation bit set) but stream ends
        let truncated: u8[2] = [0x7F, 0x80];
        let _, _, ok_trunc = wing::hpack_decode_int(truncated[..], 0, 7);
        sub.assert_false(ok_trunc, "truncated continuation must return false");
    };

    t.run("HPACK-SEC-04: Integer Shift Overflow Protection (FIND-401)") { sub =>
        // 10 continuation bytes of 0xFF (shift would exceed 28 and payload > 0x0F)
        let overflow_bytes: u8[11] = [
            0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
        ];
        let _, _, ok_ovf = wing::hpack_decode_int(overflow_bytes[..], 0, 7);
        sub.assert_false(ok_ovf, "chain of 0xFF continuation bytes must fail shift overflow");

        // Shift == 28 with payload > 0x0F (e.g. 0x10) must fail
        let overflow_28: u8[6] = [0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0x10];
        let _, _, ok_28 = wing::hpack_decode_int(overflow_28[..], 0, 7);
        sub.assert_false(ok_28, "shift 28 with payload 0x10 must fail 31-bit limit");
    };
}

fn test_hpack_dynamic_table_invariants(t: core::T&) {
    t.run("HPACK-SEC-05: Index 0 is strictly forbidden (RFC 7541 §6.1)") { sub =>
        let dt = wing::new_dynamic_table(4096);
        let _, _, ok_zero = wing::get_indexed_header_slices(dt, 0);
        sub.assert_false(ok_zero, "index 0 lookup must fail");
    };

    t.run("HPACK-SEC-06: Dynamic Table LIFO Order and Eviction to 0") { sub =>
        var dt = wing::new_dynamic_table(4096);
        wing::insert_header(dt, "custom-header-1", "value-1");
        wing::insert_header(dt, "custom-header-2", "value-2");

        sub.assert_eq(dt.count, 2, "2 active entries");

        // Most recent entry must be at index 62
        let n62, v62, ok62 = wing::get_indexed_header_slices(dt, 62);
        sub.assert_true(ok62, "index 62 exists");
        sub.assert_eq(n62, "custom-header-2", "index 62 is most recently added entry");
        sub.assert_eq(v62, "value-2", "index 62 value is value-2");

        // Preceding entry must be at index 63
        let n63, v63, ok63 = wing::get_indexed_header_slices(dt, 63);
        sub.assert_true(ok63, "index 63 exists");
        sub.assert_eq(n63, "custom-header-1", "index 63 is custom-header-1");

        // Out of bounds dynamic index
        let _, _, ok64 = wing::get_indexed_header_slices(dt, 64);
        sub.assert_false(ok64, "index 64 out of bounds must fail");

        // Evict until 0
        wing::evict_until(dt, 0);
        sub.assert_eq(dt.count, 0, "count is 0 after evicting to 0");
        sub.assert_eq(dt.used_bytes, 0, "used bytes is 0 after evicting to 0");

        let _, _, ok_after = wing::get_indexed_header_slices(dt, 62);
        sub.assert_false(ok_after, "lookup after evict_until(0) must fail");
    };

    t.run("HPACK-SEC-07: Dynamic Table Ring Wrap-Around without Leakage") { sub =>
        var dt = wing::new_dynamic_table(2048);
        // Insert 200 entries into 128-slot ring table
        for i in 200 {
            wing::insert_header(dt, "x-header", "x-value");
        }
        sub.assert_true(dt.count > 0, "table still holds entries");
        sub.assert_true(dt.count <= 128, "count cannot exceed 128 ring capacity");
        sub.assert_true(dt.used_bytes <= 2048, "used bytes stays within current max size");

        // Top entry must be valid
        let n_top, v_top, ok_top = wing::get_indexed_header_slices(dt, 62);
        sub.assert_true(ok_top, "top entry at 62 resolves cleanly after wrap-around");
        sub.assert_eq(n_top, "x-header", "name matches");
        sub.assert_eq(v_top, "x-value", "val matches");
    };
}

fn test_hpack_rfc9113_header_block_rules(t: core::T&) {
    t.run("HPACK-SEC-08: Dynamic Table Size Update in middle of Block Rejected") { sub =>
        var dt = wing::new_dynamic_table(4096);
        var out_list = wing::DecodedH2HeaderList { .. };

        // Header block:
        // 1. Static index 2 (:method: GET) -> 0x82
        // 2. Dynamic table size update: 001xxxxx -> 0x3F 0x00 (size = 31)
        let bad_block: u8[3] = [0x82, 0x3F, 0x00];
        let err = wing::decode_hpack_header_block(dt, bad_block[..], out_list);
        sub.assert_eq(err, wing::ERR_COMPRESSION_ERROR, "table size update after regular header must fail with COMPRESSION_ERROR per RFC 7541 §4.2");
    };

    t.run("HPACK-SEC-09: Table Size Update Exceeding SETTINGS Max Rejected") { sub =>
        var dt = wing::new_dynamic_table(1024); // max allowed size = 1024
        var out_list = wing::DecodedH2HeaderList { .. };

        // Table size update requesting 2048:
        // 001xxxxx prefix 5: 0x3F (31), followed by (2048 - 31) = 2017 -> 2017 = 0x7E1 -> 0xE1 0x0F
        let oversize_block: u8[3] = [0x3F, 0xE1, 0x0F];
        let err = wing::decode_hpack_header_block(dt, oversize_block[..], out_list);
        sub.assert_eq(err, wing::ERR_COMPRESSION_ERROR, "size update exceeding max_allowed_size must trigger COMPRESSION_ERROR");
    };

    t.run("HPACK-SEC-10: Pseudo-Header Ordering (Pseudo After Regular Rejected)") { sub =>
        var dt = wing::new_dynamic_table(4096);
        var out_list = wing::DecodedH2HeaderList { .. };

        // Header block:
        // 1. Static index 24 (cache-control: no-cache) -> 0x98 (regular header)
        // 2. Static index 2 (:method: GET) -> 0x82 (pseudo-header)
        let out_of_order_block: u8[2] = [0x98, 0x82];
        let err = wing::decode_hpack_header_block(dt, out_of_order_block[..], out_list);
        sub.assert_eq(err, wing::ERR_PROTOCOL_ERROR, "pseudo-header after regular header must trigger PROTOCOL_ERROR per RFC 9113 §8.3");
    };

    t.run("HPACK-SEC-11: Forbidden Connection Headers in HTTP/2 Rejected") { sub =>
        var dt = wing::new_dynamic_table(4096);
        var out_list = wing::DecodedH2HeaderList { .. };

        // Literal Header with Incremental Indexing (01000000 = 0x40):
        // Name: "connection" (raw, 10 bytes): 0x0A, "connection"
        // Val: "close" (raw, 5 bytes): 0x05, "close"
        var conn_block: u8[..64] = [];
        conn_block.push(0x82); // :method: GET (valid pseudo)
        conn_block.push(0x40); // Literal with indexing, new name
        conn_block.push(10);   // name len 10
        conn_block.append("connection");
        conn_block.push(5);    // val len 5
        conn_block.append("close");

        let err = wing::decode_hpack_header_block(dt, conn_block[..], out_list);
        sub.assert_eq(err, wing::ERR_PROTOCOL_ERROR, "Connection header must trigger PROTOCOL_ERROR per RFC 9113 §8.2.2");
    };

    t.run("HPACK-SEC-12: Disallowed TE Header Value Rejected") { sub =>
        var dt = wing::new_dynamic_table(4096);
        var out_list = wing::DecodedH2HeaderList { .. };

        // TE header with value other than "trailers" (e.g. "gzip") is illegal in HTTP/2
        var te_block: u8[..64] = [];
        te_block.push(0x82); // :method: GET
        te_block.push(0x40); // Literal with indexing
        te_block.push(2);    // "te"
        te_block.append("te");
        te_block.push(4);    // "gzip"
        te_block.append("gzip");

        let err = wing::decode_hpack_header_block(dt, te_block[..], out_list);
        sub.assert_eq(err, wing::ERR_PROTOCOL_ERROR, "TE header with value other than 'trailers' must trigger PROTOCOL_ERROR per RFC 9113 §8.2.2");
    };
}

fn main() {
    var runner = core::new_runner("HPACK & RFC 9113 Security Invariants Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. HPACK Variable-Length Integer Codec Overflows (FIND-401)", test_hpack_integer_codec_overflows);
    core::run_case(runner, "2. HPACK Dynamic Table Invariants, Eviction & Wrap-Around", test_hpack_dynamic_table_invariants);
    core::run_case(runner, "3. RFC 9113 Header Block Security Rules & Invariants", test_hpack_rfc9113_header_block_rules);

    let ok = core::finish(runner);
    assert(ok);
}
