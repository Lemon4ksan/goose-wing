// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Programmable zero-allocation WebAssembly Edge Filter for Goose-Wing.
// Allows sandboxed L7 request and frame inspection, WAF rule evaluation,
// and path/header filtering compatible with Gosling Wasm VM and x86_64 JIT.
namespace wing;

import std;
import core from "..";

enum WasmFilterVerdict {
    Pass,
    BlockForbidden,
    ThrottleRate,
    DropConnection,
}

struct WasmFilterRule {
    name: u8[..64] = [],
    path_prefix: u8[..64] = [],
    required_header: u8[..64] = [],
    verdict: WasmFilterVerdict = WasmFilterVerdict.Pass,
    enabled: bool = true,
}

struct WasmEdgeFilter {
    rules: WasmFilterRule[..16] = [],
    total_inspected: u64 = 0,
    total_blocked: u64 = 0,
    max_payload_bytes: i64 = 65536,
    enabled: bool = true,
}

fn new_wasm_edge_filter() -> WasmEdgeFilter {
    return WasmEdgeFilter { .. };
}

fn add_wasm_filter_rule(filter: WasmEdgeFilter&, rule: WasmFilterRule) -> bool {
    guard filter.rules.len < filter.rules.cap else { return false; }
    filter.rules.push(rule);
    return true;
}

fn make_wasm_filter_rule(
    name: const u8[:],
    path_prefix: const u8[:],
    verdict: WasmFilterVerdict,
) -> WasmFilterRule {
    var r = WasmFilterRule {
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
// Returns WasmFilterVerdict::Pass if allowed, or specific verdict on violation.
fn evaluate_wasm_request_filter(
    filter: WasmEdgeFilter&,
    method: const u8[:],
    path: const u8[:],
    headers: const HeaderItem[:],
) -> WasmFilterVerdict {
    guard filter.enabled else { return WasmFilterVerdict.Pass; }
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

    return WasmFilterVerdict.Pass;
}
