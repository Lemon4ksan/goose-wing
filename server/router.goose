// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Compressed radix trie router with parameter extraction and path canonicalization.
namespace server;

import std;
import core;
import http.bind;
import wire.pipeline;
import .router_internal;
import .router_l0_internal;

// Ingress Stages (Bits 0..31): Inbound filters executed prior to route handler
const STAGE_INGRESS_SLOWLORIS: u64 = (1 as u64) << 0; // RFC 9112 Connection liveliness timeout

const STAGE_INGRESS_EXPECT_100: u64 = (1 as u64) << 1; // RFC 9110 Section 10.1.1: Expect validation

const STAGE_INGRESS_IP_RATELIMIT: u64 = (1 as u64) << 2; // Global GCRA IP rate limiter

const STAGE_INGRESS_CORS_PREFLIGHT: u64 = (1 as u64) << 3; // W3C CORS preflight and header application

const STAGE_INGRESS_FETCH_CSRF: u64 = (1 as u64) << 4; // W3C Sec-Fetch-* isolation check

const STAGE_INGRESS_AUTH_COOKIE: u64 = (1 as u64) << 5; // PrivateJar cookie decryption

const STAGE_INGRESS_AUTH_JWT: u64 = (1 as u64) << 6; // RFC 7519 / RFC 9449 DPoP JWT validation

const STAGE_INGRESS_ROUTE_RATELIMIT: u64 = (1 as u64) << 7; // Per-route GCRA quota check

// Egress Stages (Bits 32..63): Outbound response transformations
const STAGE_EGRESS_COMPRESS_BROTLI: u64 = (1 as u64) << 32; // RFC 7932 Brotli body compression

const STAGE_EGRESS_COMPRESS_ZSTD: u64 = (1 as u64) << 33; // RFC 8878 Zstandard body compression

const STAGE_EGRESS_COMPRESS_GZIP: u64 = (1 as u64) << 34; // RFC 1952 Gzip body compression

const STAGE_EGRESS_ETAG: u64 = (1 as u64) << 35; // RFC 9110 Section 8.8.3: Entity Tag calculation

const STAGE_EGRESS_SECURITY_HEADERS: u64 = (1 as u64) << 36; // HSTS, CSP, X-Content-Type-Options

const STAGE_EGRESS_METRICS: u64 = (1 as u64) << 37; // Microsecond latency and status recording

const STAGE_EGRESS_ACCESS_LOG: u64 = (1 as u64) << 38; // Zero-allocation access log sink

const STAGE_INGRESS_ALL: u64 = 0x00000000FFFFFFFF;

const STAGE_EGRESS_ALL: u64 = 0xFFFFFFFF00000000;

const DEFAULT_ROUTE_PSO_MASK: u64 =
    STAGE_INGRESS_SLOWLORIS |
    STAGE_INGRESS_EXPECT_100 |
    STAGE_INGRESS_IP_RATELIMIT |
    STAGE_INGRESS_CORS_PREFLIGHT |
    STAGE_INGRESS_FETCH_CSRF |
    STAGE_INGRESS_AUTH_COOKIE;

// Flat Register Routing Table (16-slot Structure of Arrays).
// First 592 bytes match C wing_l0_table_t (w0.._pad2).
// Hardware registers: w0 (first 8 bytes) and w1 (next 8 bytes) of ASCII path.
struct L0RegisterTable {
    w0:           u64[16] = [0; 16],
    w1:           u64[16] = [0; 16],
    len:          u16[16] = [0; 16],
    method_id:    u8[16]  = [0; 16],
    _pad1:        u8[16]  = [0; 16],
    handler_id:   i32[16] = [-1; 16],
    entries_mask: u32[16] = [0; 16],
    pso_mask:     u64[16] = [0; 16],
    active_mask:  u16     = 0,
    count:        u16     = 0,
    _pad2:        u8[12]  = [0; 12],
    ingress_mask: u64[16] = [wire::STAGE_SRV_IN_DEFAULT_MASK; 16],
    egress_mask:  u64[16] = [wire::STAGE_SRV_OUT_DEFAULT_MASK; 16],
}

struct RadixTree {
    nodes:    server_internal::RadixNode[..128] = [],
    root_idx: i32                               = -1,
}

fn new_radix_tree() -> RadixTree {
    var tree = RadixTree { .. };
    var root_node = server_internal::RadixNode { node_type: server_internal::NodeType.Root, .. };
    tree.nodes.push(root_node);
    tree.root_idx = 0;
    return tree;
}

// insert_route inserts a route path into the RadixTree with automatic common-prefix compression.
//
// Supports:
// - Static routes: "/api/v1/users"
// - Named parameters: "/users/{id}" and suffix patterns "/files/{name}.png"
// - Greedy catch-alls: "/static/{*filepath}"
//
// Invariant: Insertion order does not alter matching precedence; static routes always precede dynamic parameters.
fn insert_route(
    tree:         RadixTree&,
    path:         const u8[:],
    handler_id:   i32,
    entries_mask: u32 = 0,
    pso_mask:     u64 = 0,
    ingress_mask: u64 = wire::STAGE_SRV_IN_DEFAULT_MASK,
    egress_mask:  u64 = wire::STAGE_SRV_OUT_DEFAULT_MASK,
) -> bool {
    guard path.len > 0 && path[0] == '/' && tree.root_idx >= 0
        && server_internal::has_valid_route_braces(path) else { return false; }
    var cur_idx = tree.root_idx;
    var rem = path;

    while rem.len > 0 {
        server_internal::inc_node_priority(tree, cur_idx);
        var param_start = -1;
        var param_end = -1;
        var is_catchall = false;
        var is_brace = false;
        server_internal::find_param_delimiter(rem, param_start, param_end, is_catchall, is_brace);

        if param_start < 0 {
            guard server_internal::traverse_or_insert_static(tree, cur_idx, rem) else { return false; }
            return server_internal::set_endpoint_handler(
                tree, cur_idx, handler_id, entries_mask, pso_mask, ingress_mask, egress_mask,
            );
        }
        guard param_end > param_start else { return false; }
        if param_start > 0 {
            guard server_internal::traverse_or_insert_static(tree, cur_idx, rem[..param_start]) else { return false; }
            rem = rem[param_start..];
            server_internal::sub_param_offset(param_end, param_start);
            param_start = 0;
        }

        let name_start = if is_brace && is_catchall { 2 } else { 1 };
        guard param_end > name_start else { return false; }
        let name = rem[name_start..param_end];
        let suffix_after = rem[if is_brace { server_internal::calc_next_char_pos(param_end) } else { param_end }..];

        if is_catchall {
            guard suffix_after.len == 0 else { return false; }
            return server_internal::insert_catch_all_child(
                tree, cur_idx, name, handler_id, entries_mask, pso_mask, ingress_mask, egress_mask,
            );
        }

        var param_node_idx: i32 = -1;
        guard server_internal::insert_or_update_param_child(
            tree, cur_idx, name, suffix_after, param_node_idx,
        ) else { return false; }
        if suffix_after.len > 0 {
            cur_idx = param_node_idx;
            rem = suffix_after;
            continue;
        }
        return server_internal::set_endpoint_handler(
            tree, param_node_idx, handler_id, entries_mask, pso_mask, ingress_mask, egress_mask,
        );
    }
    return true;
}

// Resolves dot-segments (. and ..), collapses duplicate slashes, and strips query strings and fragments.
// Output always begins with '/' and clamps at root boundary (RFC 3986 Section 5.2.4).
//
// Example:
//   raw_path = "/api/v1/../users//42?active=1"
//   returns: ok = true, out = "/api/users/42"
fn canonicalize_route_path<B>(raw_path: const u8[:], out: B&) -> bool {
    guard out.cap >= 1 else { return false; }
    guard raw_path.len > 0 else {
        return out.try_set("/");
    }
    out.clear();

    let s, ok_comp = server_internal::extract_valid_route_path_component(raw_path);
    guard ok_comp else { return false; }

    var scan_idx = 0;
    while scan_idx < s.len && s[scan_idx] == '/' {
        scan_idx += 1;
    }

    while scan_idx < s.len {
        let seg_start = scan_idx;
        while scan_idx < s.len && s[scan_idx] != '/' {
            scan_idx += 1;
        }
        let seg = s[seg_start..scan_idx];

        while scan_idx < s.len && s[scan_idx] == '/' {
            scan_idx += 1;
        }

        if seg == "." || seg.eq_ascii_fold("%2e") {
            continue;
        }

        if server_internal::is_dot_dot_segment(seg) {
            server_internal::pop_last_canonical_segment(out);
            continue;
        }

        guard out.try_push('/') && out.try_append(seg) else {
            out.clear();
            return false;
        }
    }

    if out.len == 0 {
        out.push('/');
    }
    return true;
}

enum RouteMatchResult {
    Found {
        handler_id:   i32,
        entries_mask: u32,
        pso_mask:     u64,
        ingress_mask: u64,
        egress_mask:  u64,
    },
    NotFound,
    MethodNotAllowed { allow_header: u8[..64] },
}

fn is_match_found(res: const RouteMatchResult&) -> bool {
    return match res {
        Found _ => true,
        _ => false,
    };
}

inline fn match_path_resolved(
    tree:     const RadixTree&,
    eff_path: const u8[:],
    params:   http::ZeroAllocParams&,
) -> RouteMatchResult {
    guard tree.root_idx >= 0 && eff_path.len > 0 else { return RouteMatchResult.NotFound; }
    params.clear();

    var cur_idx = tree.root_idx;
    var cursor:   u16                                        = 0;
    var bt_stack: server_internal::RouteBacktrackEntry[..32] = [];
    var skip_pfx = false;

    while cur_idx >= 0 {
        let pfx_ok = server_internal::check_node_prefix_advance(tree, eff_path, cur_idx, cursor, skip_pfx);
        let rem = eff_path[(cursor as i64)..];
        if pfx_ok && rem.len == 0 && tree.nodes[cur_idx as i64].handler_id >= 0 {
            return server_internal::make_found_route(tree.nodes[cur_idx as i64]);
        }
        if pfx_ok && rem.len > 0 &&
            server_internal::try_advance_static_or_param_node(tree, rem, cur_idx, cursor, skip_pfx, params, bt_stack) {
            continue;
        }

        var ca_res = RouteMatchResult.NotFound;
        let ok_bt, is_ca = server_internal::pop_route_backtrack(
            tree, eff_path, bt_stack, cur_idx, cursor, params, ca_res,
        );
        if !ok_bt { break; }
        if is_ca { return ca_res; }
        skip_pfx = true;
    }

    return RouteMatchResult.NotFound;
}

// Matches path against the RadixTree, recording parameter spans into params and writing `out_canon_path`.
fn match_path<B>(
    tree:           const RadixTree&,
    path:           const u8[:],
    params:         http::ZeroAllocParams&,
    out_canon_path: B&,
) -> RouteMatchResult {
    let eff_path, ok_path = server_internal::resolve_effective_route_path(path, out_canon_path);
    guard ok_path else { return RouteMatchResult.NotFound; }
    return match_path_resolved(tree, eff_path, params);
}

// Matches path against the RadixTree without copying already-canonical paths.
//
// Example:
//   path = "/users/42" -> returns Found with param "id"="42" without copying `path` into stack scratch
fn match_path(
    tree:   const RadixTree&,
    path:   const u8[:],
    params: http::ZeroAllocParams&,
) -> RouteMatchResult {
    var canon_path: u8[..2048] = [];
    let eff_path, ok_path = server_internal::resolve_effective_route_path_borrow(path, canon_path);
    guard ok_path else { return RouteMatchResult.NotFound; }
    let res = match_path_resolved(tree, eff_path, params);
    if canon_path.len > 0 && canon_path[..] != path {
        params.clear();
    }
    return res;
}

// Method-segregated radix routing table supporting static, parameterized, and wildcard routes.
struct MethodTree {
    method: u8[..8]   = "GET",
    tree:   RadixTree = RadixTree { .. },
}

struct StaticRoutePayload {
    handler_id:    i32       = 0,
    content_type:  u8[..64]  = [],
    body:          u8[..512] = [],
    payload_keep:  u8[..640] = [],
    payload_close: u8[..640] = [],
}

const DEFAULT_PLAINTEXT_PAYLOAD: const u8[:] = "Hello, World!";

const DEFAULT_JSON_PAYLOAD: const u8[:] = "{\"message\":\"Hello, World!\"}";

const DEFAULT_METRICS_PAYLOAD: const u8[:] =
    "{\"engine\":\"goose-wing\",\"memory_allocations\":0,\"heap_bytes\":0,\"architecture\":\"zero_alloc_stack\"}";

struct RadixRouter {
    trees:           MethodTree[..9]          = [],
    l0_table:        L0RegisterTable          = L0RegisterTable { .. },
    static_payloads: StaticRoutePayload[..32] = [],
}

// Populates standard built-in static payload slots (handler IDs 1001..1003) for
// health/plaintext checks, JSON probes, and zero-allocation engine telemetry metrics.
fn init_default_static_payloads(r: RadixRouter&) {
    let _ = set_static_route_payload(r, 1001, "text/plain", DEFAULT_PLAINTEXT_PAYLOAD);
    let _ = set_static_route_payload(r, 1002, "application/json", DEFAULT_JSON_PAYLOAD);
    let _ = set_static_route_payload(r, 1003, "application/json", DEFAULT_METRICS_PAYLOAD);
}

fn init_radix_router_inplace(r: RadixRouter&) {
    r.trees.clear();
    // RFC 9110 Section 9.3 & RFC 10008 Section 2 standard HTTP methods + slot 8 custom extension bucket
    let methods: const u8[:][9] = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "QUERY", "*"];
    for m in methods {
        var mt = MethodTree { method: [], tree: new_radix_tree() };
        mt.method.append(m);
        r.trees.push(mt);
    }
    init_default_static_payloads(r);
}

fn new_radix_router() -> RadixRouter {
    var r = RadixRouter { .. };
    init_radix_router_inplace(r);
    return r;
}

// Registers a route pattern for an HTTP method in the router.
// Supports static routes ("/users"), parameters ("/:id" or "/{id}"), and wildcards ("/*path").
// Route paths are canonicalized consistently with request matching (RFC 3986 §5.2.4).
fn add_route(
    router:       RadixRouter&,
    method:       const u8[:],
    path:         const u8[:],
    handler_id:   i32,
    entries_mask: u32 = 0,
    pso_mask:     u64 = DEFAULT_ROUTE_PSO_MASK,
) -> bool {
    let in_mask = server_internal::pso_mask_to_srv_ingress(pso_mask);
    let out_mask = server_internal::pso_mask_to_srv_egress(pso_mask);
    return server_internal::add_route_masks(
        router,
        method,
        path,
        handler_id,
        entries_mask,
        pso_mask,
        in_mask,
        out_mask,
    );
}

// Registers a route pattern with an explicit Pre-Baked Pipeline State Object (PSO) mask.
fn add_route_pso(
    router:     RadixRouter&,
    method:     const u8[:],
    path:       const u8[:],
    handler_id: i32,
    pso_mask:   u64,
) -> bool {
    return add_route(router, method, path, handler_id, 0, pso_mask);
}

// Registers a route pattern with explicit Server Ingress and Egress 64-bit stage masks.
fn add_route_pso(
    router:       RadixRouter&,
    method:       const u8[:],
    path:         const u8[:],
    handler_id:   i32,
    ingress_mask: u64,
    egress_mask:  u64,
) -> bool {
    let pso_mask = server_internal::srv_masks_to_pso_mask(ingress_mask, egress_mask);
    return server_internal::add_route_masks(router, method, path, handler_id, 0, pso_mask, ingress_mask, egress_mask);
}

// Attaches or updates a static payload for a given `handler_id` in `router.static_payloads`.
fn set_static_route_payload(
    router:       RadixRouter&,
    handler_id:   i32,
    content_type: const u8[:],
    body:         const u8[:],
) -> bool {
    for idx in router.static_payloads.len {
        if router.static_payloads[idx].handler_id == handler_id {
            guard router.static_payloads[idx].content_type.try_set(content_type)
                && router.static_payloads[idx].body.try_set(body) else {
                return false;
            }
            server_internal::build_static_route_payload_frames(router.static_payloads[idx], content_type, body);
            return true;
        }
    }
    var sp = StaticRoutePayload {
        handler_id:    handler_id,
        content_type:  [],
        body:          [],
        payload_keep:  [],
        payload_close: [],
    };
    guard sp.content_type.try_set(content_type) && sp.body.try_set(body) else { return false; }
    server_internal::build_static_route_payload_frames(sp, content_type, body);
    return router.static_payloads.try_push(sp);
}

fn add_static_route(
    router:       RadixRouter&,
    method:       const u8[:],
    path:         const u8[:],
    content_type: const u8[:],
    body:         const u8[:],
    handler_id:   i32 = 0,
) -> bool {
    guard content_type.len <= 64 && body.len <= 512 else { return false; }
    let eff_id = if handler_id != 0 { handler_id } else { 2048 | (router.static_payloads.len as i32) };
    var has_existing = false;
    for idx in router.static_payloads.len {
        if router.static_payloads[idx].handler_id == eff_id {
            has_existing = true;
            break;
        }
    }
    guard has_existing || router.static_payloads.len < router.static_payloads.cap else { return false; }
    guard add_route(router, method, path, eff_id, 0, DEFAULT_ROUTE_PSO_MASK) else { return false; }
    return set_static_route_payload(router, eff_id, content_type, body);
}

// Matches a request method and path against registered routes.
// Automatically canonicalizes path before matching.
// Automatic HEAD routing: if a route matches GET, HEAD requests route to GET handler (RFC 9110 §9.3.2).
// Returns RouteMatchResult: Found with handler_id, NotFound, or MethodNotAllowed with Allow header.
fn match_route<B>(
    router:         const RadixRouter&,
    method:         const u8[:],
    path:           const u8[:],
    params:         http::ZeroAllocParams&,
    out_canon_path: B&,
) -> RouteMatchResult {
    guard router.trees.len > 0 else { return RouteMatchResult.NotFound; }
    let clean_path = server_internal::strip_query_and_fragment(path);
    let target_tree_idx = server_internal::find_router_method_tree_index(router, method);

    if target_tree_idx >= 0 && clean_path != "*" {
        let res = if target_tree_idx == 8 {
            server_internal::match_custom_method_tree(router, method, clean_path, params, out_canon_path)
        } else {
            server_internal::match_tree_with_l0(router, target_tree_idx, clean_path, params, out_canon_path)
        };
        if is_match_found(res) { return res; }
    }

    // Automatic HEAD routing: if method is HEAD and no explicit HEAD route matched,
    // route to GET handler if a GET route matches (RFC 9110 §9.3.2).
    if method == "HEAD" && clean_path != "*" && router.trees[0].method[..] == "GET" {
        let res_get = server_internal::match_tree_with_l0(router, 0, clean_path, params, out_canon_path);
        if is_match_found(res_get) { return res_get; }
    }

    return server_internal::resolve_method_not_allowed_or_not_found(router, target_tree_idx, method, clean_path);
}

fn match_route(
    router: const RadixRouter&,
    method: const u8[:],
    path:   const u8[:],
    params: http::ZeroAllocParams&,
) -> RouteMatchResult {
    var canon_path: u8[..2048] = [];
    let res = match_route(router, method, path, params, canon_path);
    if canon_path.len > 0 && canon_path[..] != path {
        params.clear();
    }
    return res;
}

const ROUTE_ENTRY_CONN: u32 = 1 << 0;

const ROUTE_ENTRY_PARAMS: u32 = 1 << 1;

const ROUTE_ENTRY_COOKIES: u32 = 1 << 2;

const ROUTE_ENTRY_SECURITY: u32 = 1 << 3;

struct InferredRouteMasks {
    entries_mask: u32 = 0,
    pso_mask:     u64 = 0,
    ingress_mask: u64 = 0,
    egress_mask:  u64 = 0,
}

// Inspects fields of a user-defined request contract struct `T` at compile time
// (e.g. `params`, `cookies`, `session`, `claims`, `jwt`, `peer_ip`, `etag`) and
// computes narrow extractor (`entries_mask`) and PSO (`pso_mask`) bitmasks.
fn infer_contract_masks<T>(base_pso: u64 = DEFAULT_ROUTE_PSO_MASK) -> InferredRouteMasks {
    var entries: u32 = 0;
    var pso:     u64 = base_pso & ~(STAGE_INGRESS_AUTH_COOKIE | STAGE_INGRESS_AUTH_JWT);

    const for <Name, Acc> in fields<T> {
        if Name == "params" {
            entries |= ROUTE_ENTRY_PARAMS;
        } else if Name == "cookies" || Name == "session" {
            entries |= ROUTE_ENTRY_COOKIES;
            pso |= STAGE_INGRESS_AUTH_COOKIE;
        } else if Name == "claims" || Name == "jwt" {
            entries |= ROUTE_ENTRY_SECURITY;
            pso |= STAGE_INGRESS_AUTH_JWT;
        } else if Name == "peer_ip" {
            entries |= ROUTE_ENTRY_CONN;
        } else if Name == "etag" {
            pso |= STAGE_EGRESS_ETAG;
        }
    }

    let in_mask = server_internal::pso_mask_to_srv_ingress(pso);
    let out_mask = server_internal::pso_mask_to_srv_egress(pso);
    return InferredRouteMasks {
        entries_mask: entries,
        pso_mask:     pso,
        ingress_mask: in_mask,
        egress_mask:  out_mask,
    };
}

// Opt-in router registration overload combining inferred masks with explicit overrides.
fn add_route_for_contract<Contract>(
    router:     RadixRouter&,
    method:     const u8[:],
    path:       const u8[:],
    handler_id: i32,
    extra_pso:  u64 = 0,
) -> bool {
    let inferred = infer_contract_masks<Contract>();
    let merged_pso = inferred.pso_mask | extra_pso;
    return add_route(
        router,
        method,
        path,
        handler_id,
        inferred.entries_mask,
        merged_pso,
    );
}

// Lightweight, non-owning route registration group sharing a URL prefix and PSO stage masks.
struct RouteGroup {
    prefix:       u8[..128] = [],
    entries_mask: u32       = 0,
    pso_mask:     u64       = DEFAULT_ROUTE_PSO_MASK,
}

fn make_route_group(
    prefix:       const u8[:],
    pso_mask:     u64 = DEFAULT_ROUTE_PSO_MASK,
    entries_mask: u32 = 0,
) -> RouteGroup, bool {
    var grp = RouteGroup { entries_mask: entries_mask, pso_mask: pso_mask, .. };
    guard canonicalize_route_path(prefix, grp.prefix) else { return grp, false; }
    return grp, true;
}

// Joins a canonical group prefix ("/api/v1") and sub-path ("/users/:id") into `out`.
//
// Example:
//   prefix = "/api/v1", sub_path = "/users", out = []
//   out becomes "/api/v1/users", returns true
fn join_route_prefix<B>(prefix: const u8[:], sub_path: const u8[:], out: B&) -> bool {
    let saved_len = out.len;
    let last_idx = core::sub_sat_i64(prefix.len, 1);
    let pfx = if prefix.len > 1 && prefix[last_idx] == '/' {
        prefix[..^1]
    } else {
        prefix
    };
    if pfx.len > 0 && pfx != "/" {
        guard out.try_append(pfx) else { out.resize(saved_len); return false; }
    }
    if sub_path.len == 0 || sub_path == "/" {
        if out.len == saved_len {
            guard out.try_push('/') else { out.resize(saved_len); return false; }
        }
        return true;
    }
    if sub_path[0] != '/' {
        guard out.try_push('/') else { out.resize(saved_len); return false; }
    }
    guard out.try_append(sub_path) else { out.resize(saved_len); return false; }
    return true;
}

// Expands a trailing optional parameter ("/users/:id?" or "/users/{id?}") into
// its base path ("/users") and required-param path ("/users/:id").
//
// Example:
//   pattern = "/api/animals/:type?"
//   base_out = "/api/animals", full_out = "/api/animals/:type", returns true
fn split_trailing_optional_param<B>(
    pattern:  const u8[:],
    base_out: B&,
    full_out: B&,
) -> bool {
    let saved_base = base_out.len;
    let saved_full = full_out.len;
    let slash_idx = pattern.last_index_of_byte('/');
    guard slash_idx >= 0 && core::add_sat_i64(slash_idx, 2) < pattern.len else { return false; }
    let seg_start = core::add_sat_i64(slash_idx, 1);
    let seg = pattern[seg_start..];
    let seg_last = core::sub_sat_i64(seg.len, 1);
    let base_slice = if slash_idx == 0 { "/" } else { pattern[..slash_idx] };
    if seg[0] == ':' && seg.len >= 3 && seg[seg_last] == '?' {
        guard base_out.try_append(base_slice) && full_out.try_append(pattern[..^1]) else {
            base_out.resize(saved_base);
            full_out.resize(saved_full);
            return false;
        }
        return true;
    }
    let seg_penult = core::sub_sat_i64(seg.len, 2);
    if seg[0] == '{' && seg.len >= 4 && seg[seg_penult] == '?' && seg[seg_last] == '}' {
        guard base_out.try_append(base_slice)
            && full_out.try_append(pattern[..^2])
            && full_out.try_push('}') else {
            base_out.resize(saved_base);
            full_out.resize(saved_full);
            return false;
        }
        return true;
    }
    return false;
}

// Registers a route supporting an optional trailing parameter (`:param?` or `{param?}`).
fn add_optional_route(
    router:       RadixRouter&,
    method:       const u8[:],
    pattern:      const u8[:],
    handler_id:   i32,
    entries_mask: u32 = 0,
    pso_mask:     u64 = DEFAULT_ROUTE_PSO_MASK,
) -> bool {
    var base_path: u8[..512] = [];
    var full_path: u8[..512] = [];
    if split_trailing_optional_param(pattern, base_path, full_path) {
        guard base_path.len > 0 && full_path.len > 0 else { return false; }
        guard add_route(router, method, base_path[..], handler_id, entries_mask, pso_mask) else {
            return false;
        }
        return add_route(router, method, full_path[..], handler_id, entries_mask, pso_mask);
    }
    return add_route(router, method, pattern, handler_id, entries_mask, pso_mask);
}

// Registers a route within `group`, inheriting its prefix, `entries_mask`, and `pso_mask`.
fn add_group_route(
    router:     RadixRouter&,
    group:      const RouteGroup&,
    method:     const u8[:],
    sub_path:   const u8[:],
    handler_id: i32,
) -> bool {
    var merged: u8[..512] = [];
    guard join_route_prefix(group.prefix[..], sub_path, merged) else { return false; }
    return add_optional_route(
        router,
        method,
        merged[..],
        handler_id,
        group.entries_mask,
        group.pso_mask,
    );
}

// Registers `pattern` across an explicit list of HTTP methods (Hono `app.on(methods, path)`).
fn add_route_methods(
    router:       RadixRouter&,
    methods:      const (const u8[:])[:],
    pattern:      const u8[:],
    handler_id:   i32,
    entries_mask: u32 = 0,
    pso_mask:     u64 = DEFAULT_ROUTE_PSO_MASK,
) -> bool {
    guard methods.len > 0 else { return false; }
    for m in methods {
        guard add_optional_route(router, m, pattern, handler_id, entries_mask, pso_mask) else {
            return false;
        }
    }
    return true;
}
