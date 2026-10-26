// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// W3C Trace Context (RFC 9239 / W3C Recommendation 23 November 2021).
// Provides zero-heap parsing, validation, and generation of `traceparent`
// and `tracestate` distributed tracing headers.
namespace wing;

import std;

// ---- 1. traceparent model & invariants -------------------------------------

struct Traceparent {
    version: u8 = 0,
    trace_id: u8[16] = [0; 16],
    parent_id: u8[8] = [0; 8],
    trace_flags: u8 = 1,
    valid: bool = false,
}

// Bitmask flags for trace_flags (Section 3.2.2)
const TRACE_FLAG_NONE: u8 = 0x00;
const TRACE_FLAG_SAMPLED: u8 = 0x01; // Bit 0: parent recorded / sampled

inline fn hex_val(c: u8) -> i32 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'f' { return c - 'a' + 10; }
    if c >= 'A' && c <= 'F' { return c - 'A' + 10; }
    return -1;
}

// Parses 2 hex characters into a u8
fn parse_hex_u8(src: const u8[:], offset: i64) -> u8, bool {
    guard offset + 2 <= src.len else { return 0, false; }
    let h0 = hex_val(src[offset]);
    let h1 = hex_val(src[offset + 1]);
    guard h0 >= 0 && h1 >= 0 else { return 0, false; }
    return ((h0 << 4) | h1) as u8, true;
}

// Formats a u8 into 2 lowercase hex characters
fn format_hex_u8<B>(val: u8, out: B&) {
    let hex_chars: const u8[16] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];
    out.push(hex_chars[(val >> 4) & 0x0F]);
    out.push(hex_chars[val & 0x0F]);
}

// Parses raw `traceparent` header string conforming to W3C Section 3.2:
// format: version(2)-traceid(32)-parentid(16)-traceflags(2)
// Example: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01 (55 chars)
fn parse_traceparent(raw: const u8[:]) -> Traceparent, bool {
    var tp = Traceparent { .. };
    guard raw.len >= 55 else { return tp, false; }

    // 1. Version (2 hex chars)
    let ver, ok_ver = parse_hex_u8(raw, 0);
    guard ok_ver else { return tp, false; }
    guard ver != 0xFF else { return tp, false; } // 0xFF is explicitly forbidden by W3C Section 3.2.1

    // If version is 0x00, length MUST be exactly 55 characters
    if ver == 0 {
        guard raw.len == 55 else { return tp, false; }
    }

    // Delimiter 1
    guard raw[2] == '-' else { return tp, false; }

    // 2. Trace ID (32 hex chars -> 16 bytes)
    var all_zero_trace = true;
    for i in 16 {
        let b, ok_b = parse_hex_u8(raw, 3 + i * 2);
        guard ok_b else { return tp, false; }
        if b != 0 { all_zero_trace = false; }
        tp.trace_id[i] = b;
    }
    // Trace ID all zeros is strictly invalid per W3C Section 3.2.2
    guard !all_zero_trace else { return tp, false; }

    // Delimiter 2
    guard raw[35] == '-' else { return tp, false; }

    // 3. Parent ID (16 hex chars -> 8 bytes)
    var all_zero_parent = true;
    for i in 8 {
        let b, ok_b = parse_hex_u8(raw, 36 + i * 2);
        guard ok_b else { return tp, false; }
        if b != 0 { all_zero_parent = false; }
        tp.parent_id[i] = b;
    }
    // Parent ID all zeros is strictly invalid per W3C Section 3.2.3
    guard !all_zero_parent else { return tp, false; }

    // Delimiter 3
    guard raw[52] == '-' else { return tp, false; }

    // 4. Trace Flags (2 hex chars -> 1 byte)
    let flags, ok_flags = parse_hex_u8(raw, 53);
    guard ok_flags else { return tp, false; }

    // Forward compatibility for future versions (ver > 0)
    if raw.len > 55 {
        guard ver > 0 else { return tp, false; }
        guard raw[55] == '-' else { return tp, false; }
    }

    tp.version = ver;
    tp.trace_flags = flags;
    tp.valid = true;
    return tp, true;
}

// Formats a Traceparent struct into the standard 55-byte wire string
fn format_traceparent<B>(tp: const Traceparent&, out: B&) {
    format_hex_u8(tp.version, out);
    out.push('-');
    for b in tp.trace_id {
        format_hex_u8(b, out);
    }
    out.push('-');
    for b in tp.parent_id {
        format_hex_u8(b, out);
    }
    out.push('-');
    format_hex_u8(tp.trace_flags, out);
}

// Constructs a new valid Traceparent
fn new_traceparent(trace_id: const u8[16]&, parent_id: const u8[8]&, sampled: bool = true) -> Traceparent {
    return Traceparent {
        version: 0,
        trace_id: trace_id,
        parent_id: parent_id,
        trace_flags: if sampled { TRACE_FLAG_SAMPLED } else { TRACE_FLAG_NONE },
        valid: true,
    };
}

inline fn traceparent_is_sampled(tp: const Traceparent&) -> bool {
    return (tp.trace_flags & TRACE_FLAG_SAMPLED) != 0;
}

// ---- 2. tracestate model & parsing -----------------------------------------

struct TracestateMember {
    key: u8[..64] = [],
    val: u8[..256] = [],
}

struct Tracestate {
    members: TracestateMember[..32] = [],
    valid: bool = true,
}

// Key validation conforming to W3C Section 3.3:
// simple key: [a-z0-9_*/-]{1,256}
// multi-tenant key: [a-z0-9_*/-]{1,241}@[a-z0-9_*/-]{1,14}
fn is_valid_tracestate_key(key: const u8[:]) -> bool {
    guard key.len >= 1 && key.len <= 256 else { return false; }
    var at_pos: i64 = -1;
    for i in key.len {
        let b = key[i];
        if b == '@' {
            guard at_pos < 0 else { return false; } // only one '@' allowed
            at_pos = i;
        } else {
            let valid_char = (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') ||
                             b == '_' || b == '-' || b == '*' || b == '/';
            guard valid_char else { return false; }
        }
    }
    if at_pos >= 0 {
        let tenant_len = at_pos;
        let system_len = key.len - at_pos - 1;
        guard tenant_len >= 1 && tenant_len <= 241 else { return false; }
        guard system_len >= 1 && system_len <= 14 else { return false; }
    }
    return true;
}

// Value validation conforming to W3C Section 3.3:
// 0..256 printable ASCII chars excluding comma ',' and equal '='
fn is_valid_tracestate_val(val: const u8[:]) -> bool {
    guard val.len <= 256 else { return false; }
    for b in val {
        guard b >= 0x20 && b <= 0x7E && b != ',' && b != '=' else { return false; }
    }
    return true;
}

// Parses W3C `tracestate` header: comma-separated list of key=val pairs
fn parse_tracestate(raw: const u8[:]) -> Tracestate, bool {
    var ts = Tracestate { .. };
    var cursor: i64 = 0;

    while cursor < raw.len {
        // Skip leading whitespace / OWS
        while cursor < raw.len && (raw[cursor] == ' ' || raw[cursor] == '\t') {
            cursor++;
        }
        if cursor == raw.len { break; }

        // Find end of entry or next comma
        var eq_pos: i64 = -1;
        var comma_pos: i64 = -1;
        var i = cursor;
        while i < raw.len {
            let b = raw[i];
            if b == '=' && eq_pos < 0 {
                eq_pos = i;
            } else if b == ',' {
                comma_pos = i;
                break;
            }
            i++;
        }

        let entry_end = if comma_pos >= 0 { comma_pos } else { raw.len };
        guard eq_pos > cursor && eq_pos < entry_end else { return ts, false; }

        let k_raw = raw[cursor..eq_pos];
        let v_raw = raw[eq_pos + 1..entry_end];

        guard is_valid_tracestate_key(k_raw) else { return ts, false; }
        guard is_valid_tracestate_val(v_raw) else { return ts, false; }

        if ts.members.len < 32 {
            var member = TracestateMember { .. };
            member.key.append(k_raw);
            member.val.append(v_raw);
            ts.members.push(member);
        }

        cursor = if comma_pos >= 0 { comma_pos + 1 } else { raw.len };
    }

    ts.valid = true;
    return ts, true;
}

// Formats a Tracestate into a comma-separated wire string
fn format_tracestate<B>(ts: const Tracestate&, out: B&) {
    for i in ts.members.len {
        if i > 0 {
            out.push(',');
        }
        out.append(ts.members[i].key[..]);
        out.push('=');
        out.append(ts.members[i].val[..]);
    }
}

// Looks up a value in Tracestate by key
fn tracestate_get(ts: const Tracestate&, key: const u8[:]) -> const u8[:] {
    for &m in ts.members {
        if m.key[..] == key {
            return m.val[..];
        }
    }
    return "";
}

// Updates or prepends a key-value pair per W3C Section 3.3 (most recent at the front)
fn tracestate_set(ts: Tracestate&, key: const u8[:], val: const u8[:]) -> bool {
    guard is_valid_tracestate_key(key) && is_valid_tracestate_val(val) else { return false; }

    // Find and remove existing key if present
    var existing_idx: i64 = -1;
    for i in ts.members.len {
        if ts.members[i].key[..] == key {
            existing_idx = i;
            break;
        }
    }

    var new_members: TracestateMember[..32] = [];
    var new_item = TracestateMember { .. };
    new_item.key.append(key);
    new_item.val.append(val);
    new_members.push(new_item);

    for i in ts.members.len {
        if i != existing_idx && new_members.len < 32 {
            new_members.push(ts.members[i]);
        }
    }

    ts.members = new_members;
    return true;
}
