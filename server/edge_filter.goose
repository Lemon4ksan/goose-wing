// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Programmable zero-allocation L7 Edge Filter for Goose-Wing.
// Provides sandboxed L7 request inspection, rule evaluation,
// and path/header filtering without heap allocations.
namespace server;

import std;
import core from "..";
import http.headers;
import .router;
import .internal;

enum EdgeFilterVerdict {
    Pass,
    BlockForbidden,
    ThrottleRate,
    DropConnection,
}

struct EdgeFilterRule {
    name:            u8[..64]          = [],
    path_prefix:     u8[..64]          = [],
    required_header: u8[..64]          = [],
    verdict:         EdgeFilterVerdict = EdgeFilterVerdict.Pass,
    enabled:         bool              = true,
}

struct EdgeFilter {
    rules:             EdgeFilterRule[..16] = [],
    total_inspected:   u64                  = 0,
    total_blocked:     u64                  = 0,
    max_payload_bytes: i64                  = 65536,
    enabled:           bool                 = true,
}

fn add_edge_filter_rule(filter: EdgeFilter&, rule: EdgeFilterRule) -> bool {
    guard rule.enabled && rule.path_prefix.len > 0 else { return false; }
    return filter.rules.try_push(rule);
}

fn make_edge_filter_rule(
    name:        const u8[:],
    path_prefix: const u8[:],
    verdict:     EdgeFilterVerdict,
) -> EdgeFilterRule {
    var r = EdgeFilterRule {
        name:            [],
        path_prefix:     [],
        required_header: [],
        verdict:         verdict,
        enabled:         true,
    };
    guard r.name.try_set(name) && r.path_prefix.try_set(path_prefix) else {
        r.name.clear();
        r.path_prefix.clear();
        r.enabled = false;
        return r;
    }
    return r;
}

fn edge_rule_matches(
    rule:    const EdgeFilterRule&,
    path:    const u8[:],
    headers: const http::HeaderMap&,
) -> bool {
    guard rule.enabled && rule.path_prefix.len > 0 else { return false; }
    var canon_path: u8[..2048] = [];
    guard canonicalize_route_path(path, canon_path) else {
        return rule.verdict != EdgeFilterVerdict.Pass;
    }
    let raw_pfx = rule.path_prefix[..];
    let pfx = if raw_pfx.len > 1 && raw_pfx[raw_pfx.len - 1] == '/' {
        raw_pfx[..^1]
    } else {
        raw_pfx
    };
    guard core::starts_with(canon_path[..], pfx)
        && (pfx == "/" || canon_path.len == pfx.len || canon_path[pfx.len] == '/') else {
        return false;
    }
    if rule.required_header.len > 0 {
        guard !server_internal::has_non_empty_header_value(headers, rule.required_header[..]) else { return false; }
    }
    return true;
}

// Evaluates request path and headers against active edge filter rules.
// Returns EdgeFilterVerdict::Pass if allowed, or specific verdict on violation.
fn evaluate_edge_filter(
    filter:  EdgeFilter&,
    method:  const u8[:],
    path:    const u8[:],
    headers: const http::HeaderMap&,
) -> EdgeFilterVerdict {
    guard filter.enabled else { return EdgeFilterVerdict.Pass; }
    filter.total_inspected = core::add_sat_u64(filter.total_inspected, 1);

    for &rule in filter.rules {
        guard edge_rule_matches(rule, path, headers) else { continue; }
        if rule.verdict != EdgeFilterVerdict.Pass {
            filter.total_blocked = core::add_sat_u64(filter.total_blocked, 1);
        }
        return rule.verdict;
    }

    return EdgeFilterVerdict.Pass;
}
