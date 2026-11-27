// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal L0 SWAR register table matching, static route payload framing,
// and HTTP method tree / Allow header resolution.
namespace server_internal;

import std;
import core;
import rfc.http;
import http.headers;
import http.response;
import wire.pipeline;
import .router;
import .router_internal;

// Packs a 64-bit word lane (up to 8 bytes) starting at byte offset.
inline fn pack_word_lane(path: const u8[:], offset: i64) -> u64 {
    guard path.len > offset else { return 0; }
    let rem = core::sub_sat_i64(path.len, offset);
    let n = min(rem, 8);
    var w: u64 = 0;
    for i in n {
        let shift = core::mul_sat_u64(i as u64, 8) as u32;
        w |= core::shl_sat_u64(path[core::add_sat_i64(offset, i)], shift);
    }
    return w;
}

// Packs wire path slice of up to 16 bytes into two 64-bit integer words (RFC Little-Endian).
//
// Example:
//   path = "/plaintext" (len = 10)
//   returns: w0 = 0x747865746e69616c, w1 = 0x0000000000007478
inline fn pack_path_words(path: const u8[:]) -> u64, u64 {
    return pack_word_lane(path, 0), pack_word_lane(path, 8);
}

// Evaluates a path slice and HTTP method against the 16-slot L0 register table via scalar SWAR.
//
// Example:
//   path = "/json", method_id = 0 ("GET"), table contains "/json" in slot 2
//   returns: 2
inline fn match_l0_swar(
    path:      const u8[:],
    method_id: u8,
    table:     const server::L0RegisterTable&,
) -> i32 {
    guard path.len <= 16 && table.count > 0 else { return -1; }
    let w0, w1 = pack_path_words(path);
    let plen = path.len as u16;

    for i in (table.count as i64) {
        if table.len[i] == plen
            && table.method_id[i] == method_id
            && table.w0[i] == w0
            && table.w1[i] == w1 {
            return i as i32;
        }
    }
    return -1;
}

// Evaluates an HTTP request wire path against the L0 Register Table using scalar SWAR.
//
// Example:
//   path = "/plaintext", method_id = 0 ("GET"), table contains "/plaintext" in slot 0
//   returns: 0
inline fn match_l0(
    path:      const u8[:],
    method_id: u8,
    table:     const server::L0RegisterTable&,
) -> i32 {
    return match_l0_swar(path, method_id, table);
}

// Returns true if path contains no dynamic parameter or wildcard delimiters.
inline fn is_pure_static_path(path: const u8[:]) -> bool {
    for i in path.len {
        let b = path[i];
        if b == ':' || b == '{' || b == '*' {
            return false;
        }
    }
    return true;
}

// Registers a static route in L0 register table if path <= 16 bytes and table has space.
//
// Example:
//   path = "/plaintext", method_id = 0 ("GET"), handler_id = 1
//   returns: true (stored in slot 0)
fn register_l0_route(
    table:        server::L0RegisterTable&,
    method_id:    u8,
    path:         const u8[:],
    handler_id:   i32,
    entries_mask: u32 = 0,
    pso_mask:     u64 = server::DEFAULT_ROUTE_PSO_MASK,
    ingress_mask: u64 = wire::STAGE_SRV_IN_DEFAULT_MASK,
    egress_mask:  u64 = wire::STAGE_SRV_OUT_DEFAULT_MASK,
) -> bool {
    guard path.len <= 16 && (table.count as i64) < 16 else { return false; }
    guard is_pure_static_path(path) else { return false; }

    let existing = match_l0_swar(path, method_id, table);
    if existing >= 0 {
        let e = existing as i64;
        table.handler_id[e] = handler_id;
        table.entries_mask[e] = entries_mask;
        table.pso_mask[e] = pso_mask;
        table.ingress_mask[e] = ingress_mask;
        table.egress_mask[e] = egress_mask;
        return true;
    }

    let slot = table.count as i64;
    guard slot < 16 else { return false; }

    let w0, w1 = pack_path_words(path);
    table.w0[slot] = w0;
    table.w1[slot] = w1;
    table.len[slot] = path.len as u16;
    table.method_id[slot] = method_id;
    table.handler_id[slot] = handler_id;
    table.entries_mask[slot] = entries_mask;
    table.pso_mask[slot] = pso_mask;
    table.ingress_mask[slot] = ingress_mask;
    table.egress_mask[slot] = egress_mask;
    table.active_mask |= (core::shl_sat_u64(1, slot as u32) as u16);
    table.count = core::add_sat_u64(table.count, 1) as u16;
    return true;
}

inline fn build_custom_method_route_key<B>(
    method:     const u8[:],
    canon_path: const u8[:],
    out_key:    B&,
) -> bool {
    let needed = core::add_sat_i64(core::add_sat_i64(1, method.len), canon_path.len);
    guard needed <= out_key.cap else { return false; }
    out_key.clear();
    return out_key.try_push('/') && out_key.try_append(method) && out_key.try_append(canon_path);
}

// Registers a route pattern with explicit role-scoped ingress_mask and egress_mask.
fn add_route_masks(
    router:       server::RadixRouter&,
    method:       const u8[:],
    path:         const u8[:],
    handler_id:   i32,
    entries_mask: u32,
    pso_mask:     u64,
    ingress_mask: u64,
    egress_mask:  u64,
) -> bool {
    var canon_path: u8[..512] = [];
    guard server::canonicalize_route_path(path, canon_path) else { return false; }
    let idx = find_router_method_tree_index(router, method);
    guard idx >= 0 else { return false; }
    let tree_i = idx as i64;
    if idx == 8 {
        var custom_key: u8[..544] = [];
        guard build_custom_method_route_key(method, canon_path[..], custom_key) else { return false; }
        return server::insert_route(
            router.trees[tree_i].tree,
            custom_key[..],
            handler_id,
            entries_mask,
            pso_mask,
            ingress_mask,
            egress_mask,
        );
    }
    let ok = server::insert_route(
        router.trees[tree_i].tree,
        canon_path[..],
        handler_id,
        entries_mask,
        pso_mask,
        ingress_mask,
        egress_mask,
    );
    if ok {
        register_l0_route(
            router.l0_table,
            idx as u8,
            canon_path[..],
            handler_id,
            entries_mask,
            pso_mask,
            ingress_mask,
            egress_mask,
        );
    }
    return ok;
}

inline fn build_static_route_payload_frames(
    sp:           server::StaticRoutePayload&,
    content_type: const u8[:],
    body:         const u8[:],
) {
    var cl_buf: u8[..32] = [];
    body.len.format_i64_dec(cl_buf);

    sp.payload_keep.clear();
    sp.payload_keep.append("Content-Length: ");
    sp.payload_keep.append(cl_buf[..]);
    if content_type.len > 0 {
        sp.payload_keep.append("\r\nContent-Type: ");
        sp.payload_keep.append(content_type);
    }
    sp.payload_keep.append("\r\nConnection: keep-alive\r\n\r\n");
    sp.payload_keep.append(body);

    sp.payload_close.clear();
    sp.payload_close.append("Content-Length: ");
    sp.payload_close.append(cl_buf[..]);
    if content_type.len > 0 {
        sp.payload_close.append("\r\nContent-Type: ");
        sp.payload_close.append(content_type);
    }
    sp.payload_close.append("\r\nConnection: close\r\n\r\n");
    sp.payload_close.append(body);
}

const HASH_HDR_CONTENT_TYPE: u32 = 0xFCF70995; // "content-type"

inline fn set_static_response_content_type(res: http::Response&, ct: const u8[:]) {
    let ct_slot = http::well_known_to_slot(http::WellKnownHeader.ContentType);
    if res.headers.inline_slots[ct_slot] == 0xFF
        && res.headers.entries.len < 128
        && core::add_sat_i64(res.headers.raw_buf.len, core::add_sat_i64(12, ct.len)) <= 8192 {
        let n_begin = res.headers.raw_buf.len as u16;
        res.headers.raw_buf.append(rfc::HEADER_CONTENT_TYPE);
        let n_end = res.headers.raw_buf.len as u16;
        res.headers.raw_buf.append(ct);
        let v_end = res.headers.raw_buf.len as u16;
        let new_idx = res.headers.entries.len as u8;
        res.headers.inline_slots[ct_slot] = new_idx;
        res.headers.entries.push(http::HeaderEntry {
            name_begin:    n_begin,
            name_end:      n_end,
            values_begin:  n_end,
            values_end:    v_end,
            next_idx:      0xFF,
            flags:         0,
            well_known_id: ct_slot as u8,
            reserved:      0,
            name_hash:     HASH_HDR_CONTENT_TYPE,
        });
        res.headers.header_contains_comma.push(false);
        res.headers.bloom.add_header(rfc::HEADER_CONTENT_TYPE);
        res.presence_mask |= http::RES_PRESENCE_CONTENT_TYPE;
        return;
    }
    http::set_header(res, rfc::HEADER_CONTENT_TYPE, ct);
}

fn get_static_route_payload(
    router:     const server::RadixRouter&,
    handler_id: i32,
    res:        http::Response&,
) -> bool {
    for idx in router.static_payloads.len {
        if router.static_payloads[idx].handler_id == handler_id {
            if router.static_payloads[idx].content_type.len > 0 {
                set_static_response_content_type(res, router.static_payloads[idx].content_type[..]);
            }
            let _ = res.body.try_set(router.static_payloads[idx].body[..]);
            return true;
        }
    }
    return false;
}

inline fn find_static_payload_index(router: const server::RadixRouter&, handler_id: i32) -> i32 {
    for idx in router.static_payloads.len {
        if router.static_payloads[idx].handler_id == handler_id {
            return idx as i32;
        }
    }
    return -1;
}

inline fn method_tree_has_routes(tree: const server::RadixTree&) -> bool {
    guard tree.nodes.len > 0 else { return false; }
    if tree.nodes.len > 1 { return true; }
    let root = tree.nodes[0];
    return root.children.len > 0 || root.handler_id >= 0 || root.param_child >= 0 || root.catch_all_child >= 0;
}

inline fn record_allowed_method(
    m:             const u8[:],
    allow_buf:     u8[..64]&,
    matched_other: bool&,
    has_get:       bool&,
    has_head:      bool&,
    has_options:   bool&,
) {
    if m == "GET" { has_get = true; }
    if m == "HEAD" { has_head = true; }
    if m == "OPTIONS" { has_options = true; }
    if matched_other { allow_buf.append(", "); }
    allow_buf.append(m);
    matched_other = true;
}

fn build_allow_header(
    router:          const server::RadixRouter&,
    target_tree_idx: i32,
    method:          const u8[:],
    path:            const u8[:],
    allow_buf:       u8[..64]&,
) -> bool {
    var matched_other = false;
    var dummy_params = http::ZeroAllocParams { .. };
    var dummy_canon: u8[..512] = [];
    var has_get = false;
    var has_head = false;
    var has_options = false;

    let std_trees = min(router.trees.len, 8);
    let is_star = path == "*";
    for idx in std_trees {
        var hit = false;
        if is_star {
            hit = method_tree_has_routes(router.trees[idx].tree);
        } else if (idx as i32) != target_tree_idx {
            let res_other = server::match_path(router.trees[idx].tree, path, dummy_params, dummy_canon);
            hit = server::is_match_found(res_other);
        }
        if hit {
            record_allowed_method(
                router.trees[idx].method[..], allow_buf, matched_other, has_get, has_head, has_options,
            );
        }
    }

    guard matched_other else { return false; }
    // RFC 9110 Section 9.3.2: HEAD - Allow header MUST include HEAD if GET is supported.
    if has_get && !has_head { allow_buf.append(", HEAD"); }
    // RFC 9110 Section 9.3.7: OPTIONS - Allow header MUST include OPTIONS on capability probes.
    if (method == "OPTIONS" || is_star) && !has_options { allow_buf.append(", OPTIONS"); }
    return true;
}

inline fn is_valid_method_token(method: const u8[:]) -> bool {
    guard method.len > 0 else { return false; }
    for b in method {
        if !core::is_tchar(b) {
            return false;
        }
    }
    return true;
}

inline fn resolve_method_tree_index(method: const u8[:]) -> i32 {
    if method == "GET" { return 0; }
    if method == "POST" { return 1; }
    if method == "PUT" { return 2; }
    if method == "DELETE" { return 3; }
    if method == "PATCH" { return 4; }
    if method == "HEAD" { return 5; }
    if method == "OPTIONS" { return 6; }
    if method == "QUERY" { return 7; }
    return if is_valid_method_token(method) { 8 } else { -1 };
}

// Matches an HTTP request path against the L0 Register Table and returns RouteMatchResult if found.
inline fn try_match_l0_slot<B>(
    table:          const server::L0RegisterTable&,
    method_id:      u8,
    path:           const u8[:],
    params:         http::ZeroAllocParams&,
    out_canon_path: B&,
) -> server::RouteMatchResult {
    guard path.len <= 16 && table.count > 0 else { return server::RouteMatchResult.NotFound; }
    let slot = match_l0(path, method_id, table);
    guard slot >= 0 else { return server::RouteMatchResult.NotFound; }

    let s = slot as i64;
    params.clear();
    guard out_canon_path.try_set(path) else { return server::RouteMatchResult.NotFound; }
    return server::RouteMatchResult.Found {
        handler_id:   table.handler_id[s],
        entries_mask: table.entries_mask[s],
        pso_mask:     table.pso_mask[s],
        ingress_mask: table.ingress_mask[s],
        egress_mask:  table.egress_mask[s],
    };
}

inline fn find_router_method_tree_index(router: const server::RadixRouter&, method: const u8[:]) -> i32 {
    let idx = resolve_method_tree_index(method);
    if idx >= 0 && idx < router.trees.len {
        return idx;
    }
    for i in router.trees.len {
        if router.trees[i].method[..] == method {
            return i as i32;
        }
    }
    return -1;
}

inline fn match_custom_method_tree<B>(
    router:         const server::RadixRouter&,
    method:         const u8[:],
    clean_path:     const u8[:],
    params:         http::ZeroAllocParams&,
    out_canon_path: B&,
) -> server::RouteMatchResult {
    let eff_path, ok_path = resolve_effective_route_path(clean_path, out_canon_path);
    guard ok_path && eff_path.len > 0 else { return server::RouteMatchResult.NotFound; }
    var custom_key:  u8[..544] = [];
    var dummy_canon: u8[..544] = [];
    guard build_custom_method_route_key(method, eff_path, custom_key) else {
        return server::RouteMatchResult.NotFound;
    }
    let res = server::match_path(router.trees[8].tree, custom_key[..], params, dummy_canon);
    guard server::is_match_found(res) else { return res; }
    let shift = core::add_sat_u64(1, method.len as u64) as u16;
    for i in params.len {
        let sp .= params.spans[i];
        if sp.val_start >= shift && sp.val_end >= sp.val_start {
            sp.val_start -= shift;
            sp.val_end -= shift;
        } else {
            params.clear();
            break;
        }
    }
    return res;
}

inline fn match_tree_with_l0<B>(
    router:         const server::RadixRouter&,
    tree_idx:       i32,
    clean_path:     const u8[:],
    params:         http::ZeroAllocParams&,
    out_canon_path: B&,
) -> server::RouteMatchResult {
    let fast_res = try_match_l0_slot(router.l0_table, tree_idx as u8, clean_path, params, out_canon_path);
    if server::is_match_found(fast_res) {
        return fast_res;
    }
    return server::match_path(router.trees[tree_idx as i64].tree, clean_path, params, out_canon_path);
}

fn resolve_method_not_allowed_or_not_found(
    router:          const server::RadixRouter&,
    target_tree_idx: i32,
    method:          const u8[:],
    clean_path:      const u8[:],
) -> server::RouteMatchResult {
    var allow_buf: u8[..64] = [];
    if build_allow_header(router, target_tree_idx, method, clean_path, allow_buf) {
        return server::RouteMatchResult.MethodNotAllowed { allow_header: allow_buf };
    }
    return server::RouteMatchResult.NotFound;
}
