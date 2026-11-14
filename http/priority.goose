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

// Default priority instance per RFC 9218 Section 4.
fn priority_default(default_incremental: bool = false) -> PriorityParam {
    return PriorityParam {
        urgency:     rfc::PRIORITY_URGENCY_DEFAULT,
        incremental: default_incremental,
    };
}

// Checks if priority holds the standard default values (u=3, i=false).
fn priority_is_default(p: const PriorityParam&) -> bool {
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

// RFC 9218 Section 4: Priority Parameters - Parse SF Dictionary once and ignore out-of-range or unknown keys.
//
// Example:
//   raw = "u=0, i"
//   returns: p with urgency=0, incremental=true, ok = true
fn parse_http_priority(raw: const u8[:], default_incremental: bool = false) -> PriorityParam, bool {
    var p = priority_default(default_incremental);
    let trimmed = raw.trim_ascii_space();
    guard trimmed.len > 0 else { return p, false; }

    var entries: SfDictEntry[..16] = [];
    guard parse_sf_dict(trimmed, entries) && entries.len > 0 else { return p, false; }

    for &entry in entries {
        if entry.key == "u" {
            if !entry.is_inner_list && entry.item.kind == SfType.Integer && is_valid_urgency(entry.item.int_val) {
                p.urgency = entry.item.int_val as u8;
            }
        } else if entry.key == "i" {
            if !entry.is_inner_list && entry.item.kind == SfType.Boolean {
                p.incremental = entry.item.bool_val;
            }
        }
    }
    return p, true;
}

// ---- RFC 9218 Structured Field Serializer --------------------------------

// Writes RFC 9218 Priority header value: e.g. "u=3", "u=0, i".
fn serialize_http_priority<B>(prio: const PriorityParam&, out: B&) {
    out.append("u=");
    out.push(urgency_to_ascii(prio.urgency));
    if prio.incremental {
        out.append(", i");
    }
}
