// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Programmable zero-allocation L7 Edge Filter for Goose-Wing.
// Provides sandboxed L7 request inspection, rule evaluation,
// and path/header filtering without heap allocations.
namespace wing;

import std;
import core from "..";

enum EdgeFilterVerdict {
    Pass,
    BlockForbidden,
    ThrottleRate,
    DropConnection,
}

struct EdgeFilterRule {
    name: u8[..64] = [],
    path_prefix: u8[..64] = [],
    required_header: u8[..64] = [],
    verdict: EdgeFilterVerdict = EdgeFilterVerdict.Pass,
    enabled: bool = true,
}

struct EdgeFilter {
    rules: EdgeFilterRule[..16] = [],
    total_inspected: u64 = 0,
    total_blocked: u64 = 0,
    max_payload_bytes: i64 = 65536,
    enabled: bool = true,
}

fn add_edge_filter_rule(filter: EdgeFilter&, rule: EdgeFilterRule) -> bool {
    guard filter.rules.len < filter.rules.cap else { return false; }
    filter.rules.push(rule);
    return true;
}

fn make_edge_filter_rule(
    name: const u8[:],
    path_prefix: const u8[:],
    verdict: EdgeFilterVerdict,
) -> EdgeFilterRule {
    var r = EdgeFilterRule {
        name: [],
        path_prefix: [],
        required_header: [],
        verdict: verdict,
        enabled: true,
    };
    r.name.append(name);
    r.path_prefix.append(path_prefix);
    return r;
}

// Evaluates request path and headers against active edge filter rules.
// Returns EdgeFilterVerdict::Pass if allowed, or specific verdict on violation.
fn evaluate_edge_filter(
    filter: EdgeFilter&,
    method: const u8[:],
    path: const u8[:],
    headers: const HeaderItem[:],
) -> EdgeFilterVerdict {
    guard filter.enabled else { return EdgeFilterVerdict.Pass; }
    filter.total_inspected += 1;

    for &rule in filter.rules {
        guard rule.enabled else { continue; }

        let path_matched = if rule.path_prefix.len > 0 {
            core::starts_with(path, rule.path_prefix[..])
        } else {
            false
        };

        if path_matched {
            if rule.required_header.len > 0 {
                let has_hdr = headers.find_header(rule.required_header[..]).len > 0;
                if !has_hdr {
                    filter.total_blocked += 1;
                    return rule.verdict;
                }
            } else {
                filter.total_blocked += 1;
                return rule.verdict;
            }
        }
    }

    return EdgeFilterVerdict.Pass;
}
