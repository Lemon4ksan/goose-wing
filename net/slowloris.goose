// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// 4-tier Slowloris and Reverse-Slowloris tarpit defense.
// Tracks cumulative header deadlines, byte ceilings, minimum ingress rates, and line counts.
namespace wing;

import std;
import core from "..";

enum SlowlorisViolation {
    None,
    HeaderTimeoutExpired,
    ExpectContinueTimeoutExpired,
    MaxHeaderBytesExceeded,
    MinIngressRateViolated,
    MaxHeaderCountExceeded,
}

struct SlowlorisDefenseConfig {
    response_header_timeout_ns:  i64 = 10000000000, // 10 seconds monotonic cumulative deadline
    expect_continue_timeout_ns:  i64 = 1000000000,  // 1 second Expect: 100-continue ceiling
    max_response_header_bytes:   i64 = 65536,       // 64 KB hard memory ceiling
    min_header_ingress_rate_bps: i64 = 256,         // 256 B/s minimum streaming rate
    max_header_count:            i32 = 100,         // 100 header fields cap
}

struct HeaderReader {
    config:                  SlowlorisDefenseConfig = SlowlorisDefenseConfig { .. },
    header_read_start_ns:    i64                    = 0,
    cumulative_header_bytes: i64                    = 0,
    header_lines_count:      i32                    = 0,
    tail_bytes:              u8[..3]                = [],
    headers_complete:        bool                   = false,
    poison_connection:       bool                   = false,
}

fn new_header_reader(cfg: SlowlorisDefenseConfig, start_mono_ns: i64) -> HeaderReader {
    return HeaderReader {
        config:               cfg,
        header_read_start_ns: start_mono_ns,
        ..
    };
}

fn check_slowloris_deadlines(reader: HeaderReader&, elapsed_ns: i64) -> SlowlorisViolation {
    if elapsed_ns >= reader.config.response_header_timeout_ns {
        reader.poison_connection = true;
        return SlowlorisViolation.HeaderTimeoutExpired;
    }
    return SlowlorisViolation.None;
}

inline fn detect_header_end_across_chunks(reader: HeaderReader&, chunk: const u8[:]) -> bool {
    if core::find(chunk, "\r\n\r\n") >= 0 {
        return true;
    }
    var window: u8[..6] = [];
    window.append(reader.tail_bytes[..]);
    let take_head = min(chunk.len, 3);
    if take_head > 0 {
        window.append(chunk[..take_head]);
    }
    if core::find(window[..], "\r\n\r\n") >= 0 {
        return true;
    }
    var combined: u8[..6] = [];
    combined.append(reader.tail_bytes[..]);
    if chunk.len >= 3 {
        let _ = combined.try_set(chunk[^3..]);
    } else if chunk.len > 0 {
        combined.append(chunk);
    }
    let keep = min(combined.len, 3);
    if keep > 0 {
        let _ = reader.tail_bytes.try_set(combined[^keep..]);
    } else {
        reader.tail_bytes.clear();
    }
    return false;
}

// Feeds incoming header chunk and verifies all 4 Slowloris defense invariants.
fn feed_header_bytes(
    reader:      HeaderReader&,
    chunk:       const u8[:],
    now_mono_ns: i64,
) -> SlowlorisViolation {
    if reader.headers_complete { return SlowlorisViolation.None; }

    let elapsed_ns = core::ct_max_i64(0, core::sub_sat_i64(now_mono_ns, reader.header_read_start_ns));

    let v_deadline = check_slowloris_deadlines(reader, elapsed_ns);
    if v_deadline != SlowlorisViolation.None {
        return v_deadline;
    }

    reader.cumulative_header_bytes = core::add_sat_i64(reader.cumulative_header_bytes, chunk.len);

    // Barrier 3: Hard memory ceiling on header block
    if reader.cumulative_header_bytes > reader.config.max_response_header_bytes {
        reader.poison_connection = true;
        return SlowlorisViolation.MaxHeaderBytesExceeded;
    }

    // Barrier 4: Byte-Drip Gate (minimum ingress rate check on windows >= 1s)
    if elapsed_ns >= 1000000000 && reader.config.min_header_ingress_rate_bps > 0 {
        let lhs = core::mul_sat_u64(core::ct_max_i64(0, reader.cumulative_header_bytes) as u64, 1000000000);
        let rhs = core::mul_sat_u64(reader.config.min_header_ingress_rate_bps as u64, elapsed_ns as u64);
        if lhs < rhs {
            reader.poison_connection = true;
            return SlowlorisViolation.MinIngressRateViolated;
        }
    }

    // Count header lines and enforce ceiling
    let newlines = chunk.count_byte('\n') as i32;
    if newlines > 0 {
        reader.header_lines_count = core::add_sat_i64(reader.header_lines_count, newlines) as i32;
        if reader.header_lines_count > reader.config.max_header_count {
            reader.poison_connection = true;
            return SlowlorisViolation.MaxHeaderCountExceeded;
        }
    }

    if detect_header_end_across_chunks(reader, chunk) {
        reader.headers_complete = true;
    }

    return SlowlorisViolation.None;
}
