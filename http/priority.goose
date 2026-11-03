// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9218 Extensible HTTP Priority.
// Defines structured priority parameters (urgency 0..7 and incremental boolean flag),
// structured field parsing/serialization, and priority update frame handling.
namespace wing;

import std;
import core from "..";
import .sfv;

// ---- Urgency Constants & Model -------------------------------------------

struct PriorityParam {
    urgency:     u8   = rfc::PRIORITY_URGENCY_DEFAULT,
    incremental: bool = false,
}

type HttpPriority = PriorityParam;

// Default priority instance per RFC 9218 Section 4.
fn priority_default(default_incremental: bool = false) -> HttpPriority {
    return HttpPriority {
        urgency:     rfc::PRIORITY_URGENCY_DEFAULT,
        incremental: default_incremental,
    };
}

// Checks if priority holds the standard default values (u=3, i=false).
fn priority_is_default(p: const HttpPriority&) -> bool {
    return p.urgency == rfc::PRIORITY_URGENCY_DEFAULT && !p.incremental;
}

// Validates whether urgency integer is within RFC 9218 bounds [0..7].
fn is_valid_urgency(u: i64) -> bool {
    return u >= 0 && u <= 7;
}

fn urgency_to_ascii(u: u8) -> u8 {
    match u {
        0 => '0',
        1 => '1',
        2 => '2',
        3 => '3',
        4 => '4',
        5 => '5',
        6 => '6',
        7 => '7',
        _ => '3',
    }
}

// ---- RFC 9218 Structured Field Parser ------------------------------------

fn apply_priority_u(dict_str: const u8[:], p: HttpPriority&) -> bool {
    let u_val = sf_dict_get_int(dict_str, "u", -1);
    guard is_valid_urgency(u_val) else { return false; }
    p.urgency = u_val as u8;
    return true;
}

fn apply_priority_i(dict_str: const u8[:], p: HttpPriority&) -> bool {
    var entries: SfDictEntry[..16] = [];
    guard parse_sf_dict(dict_str, entries) else { return false; }
    for &entry in entries {
        if entry.key == "i" {
            guard entry.item.kind == SfType.Boolean else { return false; }
            p.incremental = entry.item.bool_val;
            return true;
        }
    }
    return false;
}

// Parses RFC 9218 Priority header value: e.g. "u=0, i", "u=5", "i=?0, u=2".
// Ignores unknown parameters per RFC 9218 Section 4.
// Returns parsed HttpPriority and true if at least one recognized parameter was parsed.
//
// Example:
//   raw = "u=0, i"
//   returns: p with urgency=0, incremental=true, ok = true
fn parse_http_priority(raw: const u8[:], default_incremental: bool = false) -> HttpPriority, bool {
    var p = priority_default(default_incremental);
    let trimmed = core::trim_ascii_space(raw);
    if trimmed.len == 0 {
        return p, false;
    }

    var entries: SfDictEntry[..16] = [];
    if !parse_sf_dict(trimmed, entries) {
        return p, false;
    }

    let ok_u = apply_priority_u(trimmed, p);
    let ok_i = apply_priority_i(trimmed, p);
    return p, ok_u || ok_i;
}

// ---- RFC 9218 Structured Field Serializer --------------------------------

// Writes RFC 9218 Priority header value: e.g. "u=3", "u=0, i".
fn serialize_http_priority<B>(prio: const HttpPriority&, out: B&) {
    out.append("u=");
    out.push(urgency_to_ascii(prio.urgency));
    if prio.incremental {
        out.append(", i");
    }
}

// Backward-compatible alias for existing callers.
fn write_priority_param_rfc9218<B>(prio: const HttpPriority&, out: B&) {
    serialize_http_priority(prio, out);
}
