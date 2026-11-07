// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Compressed radix trie router with parameter extraction and path canonicalization.
namespace wing;

import std;
import wire.pipeline;

// ---- pipeline stage bitmask constants (64-bit register layout) --------------

// Ingress Stages (Bits 0..31): Inbound filters executed prior to route handler
const STAGE_INGRESS_SLOWLORIS:       u64 = (1 as u64) << 0; // RFC 9112 Connection liveliness timeout
const STAGE_INGRESS_EXPECT_100:      u64 = (1 as u64) << 1; // RFC 9110 Section 10.1.1: Expect validation
const STAGE_INGRESS_IP_RATELIMIT:    u64 = (1 as u64) << 2; // Global GCRA IP rate limiter
const STAGE_INGRESS_CORS_PREFLIGHT:  u64 = (1 as u64) << 3; // W3C CORS preflight and header application
const STAGE_INGRESS_FETCH_CSRF:      u64 = (1 as u64) << 4; // W3C Sec-Fetch-* isolation check
const STAGE_INGRESS_AUTH_COOKIE:     u64 = (1 as u64) << 5; // PrivateJar cookie decryption
const STAGE_INGRESS_AUTH_JWT:        u64 = (1 as u64) << 6; // RFC 7519 / RFC 9449 DPoP JWT validation
const STAGE_INGRESS_ROUTE_RATELIMIT: u64 = (1 as u64) << 7; // Per-route GCRA quota check

// Egress Stages (Bits 32..63): Outbound response transformations
const STAGE_EGRESS_COMPRESS_BROTLI:  u64 = (1 as u64) << 32; // RFC 7932 Brotli body compression
const STAGE_EGRESS_COMPRESS_ZSTD:    u64 = (1 as u64) << 33; // RFC 8878 Zstandard body compression
const STAGE_EGRESS_COMPRESS_GZIP:    u64 = (1 as u64) << 34; // RFC 1952 Gzip body compression
const STAGE_EGRESS_ETAG:             u64 = (1 as u64) << 35; // RFC 9110 Section 8.8.3: Entity Tag calculation
const STAGE_EGRESS_SECURITY_HEADERS: u64 = (1 as u64) << 36; // HSTS, CSP, X-Content-Type-Options
const STAGE_EGRESS_METRICS:          u64 = (1 as u64) << 37; // Microsecond latency and status recording
const STAGE_EGRESS_ACCESS_LOG:       u64 = (1 as u64) << 38; // Zero-allocation access log sink

const STAGE_INGRESS_ALL: u64 = 0x00000000FFFFFFFF;
const STAGE_EGRESS_ALL:  u64 = 0xFFFFFFFF00000000;

const DEFAULT_ROUTE_PSO_MASK: u64 =
    STAGE_INGRESS_SLOWLORIS |
    STAGE_INGRESS_EXPECT_100 |
    STAGE_INGRESS_IP_RATELIMIT |
    STAGE_INGRESS_CORS_PREFLIGHT |
    STAGE_INGRESS_FETCH_CSRF |
    STAGE_INGRESS_AUTH_COOKIE;

// Maps a combined 64-bit PSO mask (bits 0..31 ingress, bits 32..63 egress) to role-scoped server ingress_mask.
inline fn pso_mask_to_srv_ingress(pso_mask: u64) -> u64 {
    if pso_mask == 0 {
        return wire::STAGE_SRV_IN_ROUTE_MATCH;
    }
    var m: u64 = wire::STAGE_SRV_IN_ROUTE_MATCH | wire::STAGE_SRV_IN_EDGE_FILTER;
    if (pso_mask & STAGE_INGRESS_SLOWLORIS) != 0 { m |= wire::STAGE_SRV_IN_SLOWLORIS; }
    if (pso_mask & STAGE_INGRESS_EXPECT_100) != 0 { m |= wire::STAGE_SRV_IN_EXPECT_100; }
    if (pso_mask & STAGE_INGRESS_IP_RATELIMIT) != 0 { m |= wire::STAGE_SRV_IN_RATELIMIT_IP; }
    if (pso_mask & STAGE_INGRESS_ROUTE_RATELIMIT) != 0 { m |= wire::STAGE_SRV_IN_RATELIMIT_ROUTE; }
    if (pso_mask & STAGE_INGRESS_CORS_PREFLIGHT) != 0 { m |= wire::STAGE_SRV_IN_CORS; }
    if (pso_mask & STAGE_INGRESS_FETCH_CSRF) != 0 { m |= wire::STAGE_SRV_IN_CSRF; }
    if (pso_mask & STAGE_INGRESS_AUTH_COOKIE) != 0 { m |= wire::STAGE_SRV_IN_AUTH_COOKIE; }
    if (pso_mask & STAGE_INGRESS_AUTH_JWT) != 0 { m |= wire::STAGE_SRV_IN_AUTH_JWT; }
    return m;
}

// Maps a combined 64-bit PSO mask (bits 0..31 ingress, bits 32..63 egress) to role-scoped server egress_mask.
inline fn pso_mask_to_srv_egress(pso_mask: u64) -> u64 {
    var m: u64 = 0;
    if (pso_mask & STAGE_EGRESS_ETAG) != 0 { m |= wire::STAGE_SRV_OUT_ETAG; }
    if (pso_mask & STAGE_EGRESS_COMPRESS_GZIP) != 0 { m |= wire::STAGE_SRV_OUT_COMPRESS_GZIP; }
    if (pso_mask & STAGE_EGRESS_COMPRESS_BROTLI) != 0 { m |= wire::STAGE_SRV_OUT_COMPRESS_BR; }
    if (pso_mask & STAGE_EGRESS_COMPRESS_ZSTD) != 0 { m |= wire::STAGE_SRV_OUT_COMPRESS_ZSTD; }
    if (pso_mask & STAGE_EGRESS_SECURITY_HEADERS) != 0 { m |= wire::STAGE_SRV_OUT_SECURITY_HEADERS; }
    if (pso_mask & STAGE_EGRESS_METRICS) != 0 { m |= wire::STAGE_SRV_OUT_METRICS; }
    if (pso_mask & STAGE_EGRESS_ACCESS_LOG) != 0 { m |= wire::STAGE_SRV_OUT_ACCESS_LOG; }
    return m;
}

// Maps role-scoped server ingress_mask and egress_mask to a combined 64-bit PSO mask.
inline fn srv_masks_to_pso_mask(ingress_mask: u64, egress_mask: u64) -> u64 {
    var pso: u64 = 0;
    if (ingress_mask & wire::STAGE_SRV_IN_SLOWLORIS) != 0 { pso |= STAGE_INGRESS_SLOWLORIS; }
    if (ingress_mask & wire::STAGE_SRV_IN_EXPECT_100) != 0 { pso |= STAGE_INGRESS_EXPECT_100; }
    if (ingress_mask & wire::STAGE_SRV_IN_RATELIMIT_IP) != 0 { pso |= STAGE_INGRESS_IP_RATELIMIT; }
    if (ingress_mask & wire::STAGE_SRV_IN_RATELIMIT_ROUTE) != 0 { pso |= STAGE_INGRESS_ROUTE_RATELIMIT; }
    if (ingress_mask & wire::STAGE_SRV_IN_CORS) != 0 { pso |= STAGE_INGRESS_CORS_PREFLIGHT; }
    if (ingress_mask & wire::STAGE_SRV_IN_CSRF) != 0 { pso |= STAGE_INGRESS_FETCH_CSRF; }
    if (ingress_mask & wire::STAGE_SRV_IN_AUTH_COOKIE) != 0 { pso |= STAGE_INGRESS_AUTH_COOKIE; }
    if (ingress_mask & wire::STAGE_SRV_IN_AUTH_JWT) != 0 { pso |= STAGE_INGRESS_AUTH_JWT; }
    if (egress_mask & wire::STAGE_SRV_OUT_ETAG) != 0 { pso |= STAGE_EGRESS_ETAG; }
    if (egress_mask & wire::STAGE_SRV_OUT_COMPRESS_GZIP) != 0 { pso |= STAGE_EGRESS_COMPRESS_GZIP; }
    if (egress_mask & wire::STAGE_SRV_OUT_COMPRESS_BR) != 0 { pso |= STAGE_EGRESS_COMPRESS_BROTLI; }
    if (egress_mask & wire::STAGE_SRV_OUT_COMPRESS_ZSTD) != 0 { pso |= STAGE_EGRESS_COMPRESS_ZSTD; }
    if (egress_mask & wire::STAGE_SRV_OUT_SECURITY_HEADERS) != 0 { pso |= STAGE_EGRESS_SECURITY_HEADERS; }
    if (egress_mask & wire::STAGE_SRV_OUT_METRICS) != 0 { pso |= STAGE_EGRESS_METRICS; }
    if (egress_mask & wire::STAGE_SRV_OUT_ACCESS_LOG) != 0 { pso |= STAGE_EGRESS_ACCESS_LOG; }
    return pso;
}

enum NodeType {
    Root,
    Static,
    Param { suffix: bool },
    CatchAll,
}

struct ParamSpan {
    name:      u8[..32] = [],
    key_start: u16      = 0,
    key_end:   u16      = 0,
    val_start: u16      = 0,
    val_end:   u16      = 0,
}

struct ZeroAllocParams {
    spans: ParamSpan[8] = [ParamSpan { .. }; 8],
    len:   i64          = 0,
}

fn clear(params: ZeroAllocParams&) {
    params.len = 0;
}

fn add_param(
    params:  ZeroAllocParams&,
    k_start: u16,
    k_end:   u16,
    v_start: u16,
    v_end:   u16,
) -> bool {
    guard params.len < params.spans.len else { return false; }
    params.spans[params.len] = ParamSpan {
        name:      [],
        key_start: k_start,
        key_end:   k_end,
        val_start: v_start,
        val_end:   v_end,
    };
    params.len += 1;
    return true;
}

fn add_param(
    params:  ZeroAllocParams&,
    name:    const u8[:],
    k_start: u16,
    k_end:   u16,
    v_start: u16,
    v_end:   u16,
) -> bool {
    guard params.len < params.spans.len else { return false; }
    let idx = params.len;
    guard name.len <= params.spans[idx].name.cap else { return false; }
    params.spans[idx].name.clear();
    params.spans[idx].name.append(name);
    params.spans[idx].key_start = k_start;
    params.spans[idx].key_end = k_end;
    params.spans[idx].val_start = v_start;
    params.spans[idx].val_end = v_end;
    params.len += 1;
    return true;
}

fn param_val(params: const ZeroAllocParams&, idx: i64, req_path: const u8[:]) -> const u8[:] {
    guard idx >= 0 && idx < params.len else { return ""; }
    let span = params.spans[idx];
    guard span.val_end <= req_path.len && span.val_start <= span.val_end else { return ""; }
    return req_path[(span.val_start as i64)..(span.val_end as i64)];
}

fn param_key(params: const ZeroAllocParams&, idx: i64, route_template: const u8[:]) -> const u8[:] {
    guard idx >= 0 && idx < params.len else { return ""; }
    let span = &params.spans[idx];
    if span.key_end <= route_template.len && span.key_start < span.key_end {
        return route_template[(span.key_start as i64)..(span.key_end as i64)];
    }
    if span.name.len > 0 {
        return span.name[..];
    }
    return "";
}

fn param_by_name(
    params:         const ZeroAllocParams&,
    name:           const u8[:],
    route_template: const u8[:],
    req_path:       const u8[:],
) -> const u8[:], bool {
    for idx in params.len {
        let k = params.param_key(idx, route_template);
        if k == name {
            return params.param_val(idx, req_path), true;
        }
    }
    return "", false;
}

fn param_by_name(
    params:   const ZeroAllocParams&,
    name:     const u8[:],
    req_path: const u8[:],
) -> const u8[:], bool {
    for idx in params.len {
        if params.spans[idx].name[..] == name {
            return params.param_val(idx, req_path), true;
        }
    }
    return "", false;
}

// ---- radix trie node & arena storage ---------------------------------------

struct RadixNode {
    prefix:          u8[..64]  = [],
    indices:         u8[..16]  = [],
    children:        i32[..16] = [],
    priority:        u32       = 0,
    wild_child:      bool      = false,
    param_child:     i32       = -1,
    catch_all_child: i32       = -1,
    node_type:       NodeType  = NodeType.Static,
    handler_id:      i32       = -1,
    entries_mask:    u32       = 0,
    pso_mask:        u64       = 0,
    ingress_mask:    u64       = wire::STAGE_SRV_IN_DEFAULT_MASK,
    egress_mask:     u64       = wire::STAGE_SRV_OUT_DEFAULT_MASK,
    param_name:      u8[..32]  = [],
    static_suffix:   u8[..32]  = [],
}

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
    nodes:    RadixNode[..128] = [],
    root_idx: i32              = -1,
}

fn new_radix_tree() -> RadixTree {
    var tree = RadixTree { .. };
    var root_node = RadixNode { node_type: NodeType.Root, .. };
    tree.nodes.push(root_node);
    tree.root_idx = 0;
    return tree;
}

// Allocates a new node in the arena pool
fn alloc_node(tree: RadixTree&, n_type: NodeType) -> i32 {
    guard tree.nodes.len < tree.nodes.cap else { return -1; }
    var n = RadixNode { node_type: n_type, .. };
    tree.nodes.push(n);
    return (tree.nodes.len - 1) as i32;
}

// Monotonic suffix preservation during node insertion/splitting (Fixes matchit Issue #83)
fn update_param_suffix_flag(existing_type: NodeType, new_suffix: const u8[:]) -> NodeType {
    let prev_has_suffix = match existing_type {
        Param p => p.suffix,
        _ => false,
    };
    let new_has_suffix = (new_suffix.len > 0 && new_suffix != "/") || prev_has_suffix;
    return NodeType.Param { suffix: new_has_suffix };
}

// Searches the static indices array of a node for a child matching first_byte.
fn find_child_by_byte(tree: const RadixTree&, cur_idx: i32, b: u8) -> i32 {
    let c_idx = cur_idx as i64;
    let idx = core::index_of_byte(tree.nodes[c_idx].indices[..], b);
    if idx >= 0 {
        return tree.nodes[c_idx].children[idx];
    }
    return -1;
}

// Splits an existing node at common_len, creating a child node with the remaining prefix and edges.
fn split_radix_node(
    tree:          RadixTree&,
    cur_idx:       i32,
    common_len:    i64,
    common_prefix: const u8[:],
) -> bool {
    let split_child_idx = alloc_node(tree, tree.nodes[cur_idx as i64].node_type);
    guard split_child_idx >= 0 else { return false; }

    let c_idx = cur_idx as i64;
    let s_idx = split_child_idx as i64;

    tree.nodes[s_idx].prefix.append(tree.nodes[c_idx].prefix[common_len..]);
    tree.nodes[s_idx].indices.append(tree.nodes[c_idx].indices[..]);
    for c in tree.nodes[c_idx].children { tree.nodes[s_idx].children.push(c); }
    tree.nodes[s_idx].wild_child = tree.nodes[c_idx].wild_child;
    tree.nodes[s_idx].param_child = tree.nodes[c_idx].param_child;
    tree.nodes[s_idx].catch_all_child = tree.nodes[c_idx].catch_all_child;
    tree.nodes[s_idx].handler_id = tree.nodes[c_idx].handler_id;
    tree.nodes[s_idx].entries_mask = tree.nodes[c_idx].entries_mask;
    tree.nodes[s_idx].pso_mask = tree.nodes[c_idx].pso_mask;
    tree.nodes[s_idx].ingress_mask = tree.nodes[c_idx].ingress_mask;
    tree.nodes[s_idx].egress_mask = tree.nodes[c_idx].egress_mask;
    tree.nodes[s_idx].param_name.append(tree.nodes[c_idx].param_name[..]);
    tree.nodes[s_idx].static_suffix.append(tree.nodes[c_idx].static_suffix[..]);
    tree.nodes[s_idx].priority = if tree.nodes[c_idx].priority > 0 { tree.nodes[c_idx].priority - 1 } else { 0 };

    let first_split_byte = tree.nodes[s_idx].prefix[0];
    tree.nodes[c_idx].prefix.clear();
    tree.nodes[c_idx].prefix.append(common_prefix);
    tree.nodes[c_idx].indices.clear();
    tree.nodes[c_idx].indices.push(first_split_byte);
    tree.nodes[c_idx].children.clear();
    tree.nodes[c_idx].children.push(split_child_idx);
    tree.nodes[c_idx].wild_child = false;
    tree.nodes[c_idx].param_child = -1;
    tree.nodes[c_idx].catch_all_child = -1;
    tree.nodes[c_idx].handler_id = -1;
    tree.nodes[c_idx].entries_mask = 0;
    tree.nodes[c_idx].pso_mask = 0;
    tree.nodes[c_idx].ingress_mask = wire::STAGE_SRV_IN_DEFAULT_MASK;
    tree.nodes[c_idx].egress_mask = wire::STAGE_SRV_OUT_DEFAULT_MASK;
    tree.nodes[c_idx].param_name.clear();
    tree.nodes[c_idx].static_suffix.clear();
    tree.nodes[c_idx].node_type = NodeType.Static;
    return true;
}

// Traverses or inserts a static path segment into the trie, updating cur_idx to the endpoint node.
fn traverse_or_insert_static(tree: RadixTree&, cur_idx: i32&, seg: const u8[:]) -> bool {
    var rem = seg;
    while rem.len > 0 {
        let c_idx = cur_idx as i64;
        let is_empty_root = tree.nodes[c_idx].prefix.len == 0 &&
            tree.nodes[c_idx].node_type == NodeType.Root &&
            tree.nodes[c_idx].indices.len == 0 &&
            tree.nodes[c_idx].children.len == 0 &&
            tree.nodes[c_idx].param_child < 0 &&
            tree.nodes[c_idx].catch_all_child < 0 &&
            tree.nodes[c_idx].handler_id < 0;
        if is_empty_root {
            let chunk_len = min(rem.len, 64);
            tree.nodes[c_idx].prefix.append(rem[..chunk_len]);
            if chunk_len == rem.len { return true; }
        }

        let updated_prefix = tree.nodes[c_idx].prefix[..];
        var common_len = 0;
        let max_c = min(rem.len, updated_prefix.len);
        while common_len < max_c && rem[common_len] == updated_prefix[common_len] {
            common_len += 1;
        }

        if common_len < updated_prefix.len {
            guard split_radix_node(tree, cur_idx, common_len, rem[..common_len]) else {
                return false;
            }
        }

        if common_len >= rem.len {
            return true;
        }

        let tail = rem[common_len..];
        let first_byte = tail[0];
        let child_idx = find_child_by_byte(tree, cur_idx, first_byte);

        if child_idx >= 0 {
            cur_idx = child_idx;
            inc_node_priority(tree, cur_idx);
            rem = tail;
        } else {
            guard tree.nodes[cur_idx as i64].children.len < tree.nodes[cur_idx as i64].children.cap else {
                return false;
            }
            let new_idx = alloc_node(tree, NodeType.Static);
            guard new_idx >= 0 else { return false; }
            let chunk_len = min(tail.len, 64);
            tree.nodes[new_idx as i64].prefix.append(tail[..chunk_len]);
            tree.nodes[new_idx as i64].priority = 1;
            tree.nodes[cur_idx as i64].indices.push(first_byte);
            tree.nodes[cur_idx as i64].children.push(new_idx);
            cur_idx = new_idx;
            if chunk_len == tail.len {
                return true;
            }
            rem = tail;
        }
    }
    return true;
}

// Validates that a route pattern has balanced, non-nested `{...}` delimiters without `/` inside parameter names.
fn has_valid_route_braces(path: const u8[:]) -> bool {
    var in_brace = false;
    for i in path.len {
        let b = path[i];
        if b == '{' {
            if in_brace { return false; }
            in_brace = true;
        } else if b == '}' {
            if !in_brace { return false; }
            in_brace = false;
        } else if in_brace && b == '/' {
            return false;
        }
    }
    return !in_brace;
}

// Locates the first parameter (`{param}` or `:param`) or catch-all (`{*param}` or `*param`) delimiter
// in the remaining route pattern.
//
// Example:
//   rem = "/users/:id/posts"
//   returns: param_start = 7, param_end = 10, is_catchall = false, is_brace = false
fn find_param_delimiter(
    rem:         const u8[:],
    param_start: i64&,
    param_end:   i64&,
    is_catchall: bool&,
    is_brace:    bool&,
) {
    param_start = -1;
    param_end = -1;
    is_catchall = false;
    is_brace = false;

    for i in rem.len {
        let b = rem[i];
        if b == '{' && param_start < 0 {
            param_start = i;
            is_brace = true;
            is_catchall = (i + 1 < rem.len && rem[i + 1] == '*');
        } else if b == '}' && param_start >= 0 && is_brace {
            param_end = i;
            return;
        } else if (b == ':' || b == '*') && param_start < 0 {
            param_start = i;
            is_brace = false;
            is_catchall = (b == '*');
            if is_catchall {
                param_end = rem.len;
                return;
            }
            var j = i + 1;
            while j < rem.len && rem[j] != '/' && rem[j] != '.' && rem[j] != ':' && rem[j] != '{' {
                j += 1;
            }
            param_end = j;
            return;
        }
    }
}

// Inserts a catch-all route node '{*param}', marking it as a wild child.
fn insert_catch_all_child(
    tree:         RadixTree&,
    cur_idx:      i32,
    name:         const u8[:],
    handler_id:   i32,
    entries_mask: u32,
    pso_mask:     u64 = 0,
    ingress_mask: u64 = wire::STAGE_SRV_IN_DEFAULT_MASK,
    egress_mask:  u64 = wire::STAGE_SRV_OUT_DEFAULT_MASK,
) -> bool {
    guard name.len > 0 && name.len <= 32 else { return false; }
    let ca_idx = alloc_node(tree, NodeType.CatchAll);
    guard ca_idx >= 0 else { return false; }
    let ca = ca_idx as i64;
    let cur = cur_idx as i64;
    tree.nodes[ca].param_name.append(name);
    tree.nodes[ca].handler_id = handler_id;
    tree.nodes[ca].entries_mask = entries_mask;
    tree.nodes[ca].pso_mask = pso_mask;
    tree.nodes[ca].ingress_mask = ingress_mask;
    tree.nodes[ca].egress_mask = egress_mask;

    tree.nodes[cur].catch_all_child = ca_idx;
    tree.nodes[cur].wild_child = true;
    return true;
}

// Inserts or updates a parameterized route node '{param}' with suffix preservation.
fn insert_or_update_param_child(
    tree:          RadixTree&,
    cur_idx:       i32,
    name:          const u8[:],
    suffix_after:  const u8[:],
    out_param_idx: i32&,
) -> bool {
    guard name.len > 0 && name.len <= 32 else { return false; }
    let has_suffix = (suffix_after.len > 0 && suffix_after != "/");
    var param_node_idx = tree.nodes[cur_idx as i64].param_child;

    if param_node_idx < 0 {
        param_node_idx = alloc_node(tree, NodeType.Param { suffix: has_suffix });
        guard param_node_idx >= 0 else { return false; }
        tree.nodes[param_node_idx as i64].param_name.append(name);
        tree.nodes[cur_idx as i64].param_child = param_node_idx;
        tree.nodes[cur_idx as i64].wild_child = true;
    } else {
        let updated_type = update_param_suffix_flag(tree.nodes[param_node_idx as i64].node_type, suffix_after);
        tree.nodes[param_node_idx as i64].node_type = updated_type;
    }

    out_param_idx = param_node_idx;
    return true;
}

inline fn inc_node_priority(tree: RadixTree&, cur_idx: i32) {
    tree.nodes[cur_idx as i64].priority += 1;
}

inline fn set_endpoint_handler(
    tree:         RadixTree&,
    node_idx:     i32,
    handler_id:   i32,
    entries_mask: u32,
    pso_mask:     u64,
    ingress_mask: u64 = wire::STAGE_SRV_IN_DEFAULT_MASK,
    egress_mask:  u64 = wire::STAGE_SRV_OUT_DEFAULT_MASK,
) {
    let n = node_idx as i64;
    tree.nodes[n].handler_id = handler_id;
    tree.nodes[n].entries_mask = entries_mask;
    tree.nodes[n].pso_mask = pso_mask;
    tree.nodes[n].ingress_mask = ingress_mask;
    tree.nodes[n].egress_mask = egress_mask;
}

inline fn sub_param_offset(param_end: i64&, param_start: i64) {
    param_end -= param_start;
}

inline fn calc_next_char_pos(pos: i64) -> i64 {
    return pos + 1;
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
    guard path.len > 0 && path[0] == '/' && has_valid_route_braces(path) && tree.root_idx >= 0 else { return false; }
    var cur_idx = tree.root_idx;
    var rem = path;

    while rem.len > 0 {
        inc_node_priority(tree, cur_idx);

        var param_start = -1;
        var param_end = -1;
        var is_catchall = false;
        var is_brace = false;
        find_param_delimiter(rem, param_start, param_end, is_catchall, is_brace);

        if param_start < 0 {
            guard traverse_or_insert_static(tree, cur_idx, rem) else { return false; }
            set_endpoint_handler(tree, cur_idx, handler_id, entries_mask, pso_mask, ingress_mask, egress_mask);
            return true;
        }

        guard param_end > param_start else { return false; }

        if param_start > 0 {
            guard traverse_or_insert_static(tree, cur_idx, rem[..param_start]) else { return false; }
            rem = rem[param_start..];
            sub_param_offset(param_end, param_start);
            param_start = 0;
        }

        let name_start = if is_brace && is_catchall { 2 } else { 1 };
        guard param_end > name_start else { return false; }
        let name = rem[name_start..param_end];
        let suffix_after = rem[if is_brace { calc_next_char_pos(param_end) } else { param_end }..];

        if is_catchall {
            guard suffix_after.len == 0 else { return false; }
            return insert_catch_all_child(
                tree, cur_idx, name, handler_id, entries_mask, pso_mask, ingress_mask, egress_mask,
            );
        }

        var param_node_idx: i32 = -1;
        guard insert_or_update_param_child(tree, cur_idx, name, suffix_after, param_node_idx) else { return false; }

        if suffix_after.len > 0 {
            cur_idx = param_node_idx;
            rem = suffix_after;
        } else {
            set_endpoint_handler(tree, param_node_idx, handler_id, entries_mask, pso_mask, ingress_mask, egress_mask);
            return true;
        }
    }
    return true;
}

// Strips query string '?' and fragment '#' from a path (RFC 3986 Section 3).
fn strip_query_and_fragment(path: const u8[:]) -> const u8[:] {
    for i in path.len {
        let b = path[i];
        if b == '?' || b == '#' {
            return path[..i];
        }
    }
    return path;
}

inline fn find_scheme_colon_slash(path: const u8[:]) -> i64 {
    for i in path.len {
        if path[i] == '/' {
            break;
        }
        if path[i] == ':' && i + 2 < path.len && path[i + 1] == '/' && path[i + 2] == '/' {
            return i;
        }
    }
    return -1;
}

// Strips absolute-URI scheme and authority if present (RFC 9112 Section 3.2.2).
fn strip_scheme_and_authority(path: const u8[:]) -> const u8[:] {
    let colon_slash = find_scheme_colon_slash(path);
    if colon_slash <= 0 {
        return path;
    }
    let after_scheme = path[colon_slash + 3..];
    for j in after_scheme.len {
        if after_scheme[j] == '/' {
            return after_scheme[j..];
        }
    }
    return "";
}

// Tests if a segment is a dot-dot segment (RFC 3986 Section 5.2.4).
fn is_dot_dot_segment(seg: const u8[:]) -> bool {
    return seg == ".." ||
           eq_ascii_fold(seg, ".%2e") ||
           eq_ascii_fold(seg, "%2e.") ||
           eq_ascii_fold(seg, "%2e%2e");
}

// Resolves dot-segments (. and ..), collapses duplicate slashes, and strips query strings and fragments.
// Output always begins with '/' and clamps at root boundary (RFC 3986 Section 5.2.4).
fn canonicalize_route_path<B>(raw_path: const u8[:], out: B&) -> bool {
    out.clear();
    guard raw_path.len > 0 else {
        out.push('/');
        return true;
    }

    var s = strip_query_and_fragment(raw_path);
    s = strip_scheme_and_authority(s);

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

        if seg == "." || eq_ascii_fold(seg, "%2e") {
            continue;
        }

        if is_dot_dot_segment(seg) {
            guard out.len > 0 else { continue; }
            var last_slash: i64 = out.len - 1;
            while last_slash > 0 && out[last_slash] != '/' {
                last_slash--;
            }
            out.resize(last_slash);
            continue;
        }

        guard out.len + seg.len + 1 <= out.cap else {
            out.clear();
            return false;
        }
        out.push('/');
        out.append(seg);
    }

    if out.len == 0 {
        out.push('/');
    }
    return true;
}

// ---- route matching --------------------------------------------------------

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

// Verifies that `rem_seg` matches a chain of static children starting at `child_idx`.
fn matches_static_suffix_chain(tree: const RadixTree&, child_idx: i32, rem_seg: const u8[:]) -> bool {
    var cur = child_idx;
    var off: i64 = 0;
    while off < rem_seg.len && cur >= 0 {
        let pfx = tree.nodes[cur as i64].prefix[..];
        let tail = rem_seg[off..];
        if tail.len <= pfx.len {
            return pfx[..tail.len] == tail;
        }
        guard tail[..pfx.len] == pfx else { return false; }
        off = core::add_sat_i64(off, pfx.len);
        guard off < rem_seg.len else { break; }
        cur = find_child_by_byte(tree, cur, rem_seg[off]);
    }
    return off >= rem_seg.len;
}

// Scans current path segment for a static child suffix attached to `p_idx`.
fn find_param_suffix_split(tree: const RadixTree&, p_idx: i32, rem: const u8[:], seg_end: i64) -> i64 {
    for i in seg_end {
        guard i > 0 else { continue; }
        let child_idx = find_child_by_byte(tree, p_idx, rem[i]);
        guard child_idx >= 0 else { continue; }
        if matches_static_suffix_chain(tree, child_idx, rem[i..seg_end]) {
            return i;
        }
    }
    return seg_end;
}

// Extracts a dynamic parameter segment and records its span into params.
fn match_param_child(
    tree:    const RadixTree&,
    p_idx:   i32,
    rem:     const u8[:],
    cursor:  u16,
    params:  ZeroAllocParams&,
    val_len: i64&,
) -> bool {
    let is_suffix = match tree.nodes[p_idx as i64].node_type {
        Param p => p.suffix,
        _ => false,
    };

    let slash_idx = core::index_of_byte(rem, '/');
    let seg_end = if slash_idx >= 0 { slash_idx } else { rem.len };
    let val_end = if is_suffix {
        find_param_suffix_split(tree, p_idx, rem, seg_end)
    } else {
        seg_end
    };

    guard val_end > 0 else { return false; }

    let pname = tree.nodes[p_idx as i64].param_name[..];
    guard add_param(params, pname, 0, 0, cursor, cursor + (val_end as u16)) else { return false; }
    val_len = val_end;
    return true;
}

// Captures remainder path into catch-all parameter and yields handler result.
fn match_catch_all_child(
    tree:   const RadixTree&,
    ca_idx: i32,
    rem:    const u8[:],
    cursor: u16,
    params: ZeroAllocParams&,
) -> RouteMatchResult {
    let catch_val = if rem[0] == '/' { rem[1..] } else { rem };
    guard catch_val.len > 0 else { return RouteMatchResult.NotFound; }

    let start_off = if rem[0] == '/' { cursor + 1 } else { cursor };
    let pname = tree.nodes[ca_idx as i64].param_name[..];
    guard add_param(params, pname, 0, 0, start_off, start_off + (catch_val.len as u16)) else {
        return RouteMatchResult.NotFound;
    }

    let hid = tree.nodes[ca_idx as i64].handler_id;
    if hid >= 0 {
        return RouteMatchResult.Found {
            handler_id:   hid,
            entries_mask: tree.nodes[ca_idx as i64].entries_mask,
            pso_mask:     tree.nodes[ca_idx as i64].pso_mask,
            ingress_mask: tree.nodes[ca_idx as i64].ingress_mask,
            egress_mask:  tree.nodes[ca_idx as i64].egress_mask,
        };
    }
    return RouteMatchResult.NotFound;
}

inline fn has_non_root_trailing_slash(path: const u8[:]) -> bool {
    return path.len > 1 && path[path.len - 1] == '/';
}

inline fn is_already_canonical_route_path(path: const u8[:]) -> bool {
    guard path.len > 0 && path[0] == '/' else { return false; }
    guard !has_non_root_trailing_slash(path) else { return false; }
    for i in path.len {
        let b = path[i];
        if b == '.' || b == '?' || b == '#' || b == '%' { return false; }
        if b == '/' && i > 0 && path[i - 1] == '/' { return false; }
    }
    return true;
}

inline fn resolve_effective_route_path<B>(path: const u8[:], out: B&) -> const u8[:], bool {
    if is_already_canonical_route_path(path) {
        guard out.try_set(path) else { return "", false; }
        return path, true;
    }
    out.clear();
    guard canonicalize_route_path(path, out) else { return "", false; }
    return out[..], true;
}

inline fn make_found_route(n: const RadixNode&) -> RouteMatchResult {
    return RouteMatchResult.Found {
        handler_id:   n.handler_id,
        entries_mask: n.entries_mask,
        pso_mask:     n.pso_mask,
        ingress_mask: n.ingress_mask,
        egress_mask:  n.egress_mask,
    };
}

struct RouteBacktrackEntry {
    node_idx:    i32  = -1,
    cursor:      u16  = 0,
    param_len:   i64  = 0,
    tried_param: bool = false,
}

inline fn try_backtrack_param_branch(
    tree:     const RadixTree&,
    rem:      const u8[:],
    bt:       const RouteBacktrackEntry&,
    top_i:    i64,
    bt_stack: RouteBacktrackEntry[..8]&,
    cur_idx:  i32&,
    cursor:   u16&,
    params:   ZeroAllocParams&,
) -> bool {
    guard !bt.tried_param else { return false; }
    bt_stack[top_i].tried_param = true;
    let p_idx = tree.nodes[bt.node_idx as i64].param_child;
    guard p_idx >= 0 else { return false; }
    var val_len: i64 = 0;
    guard match_param_child(tree, p_idx, rem, bt.cursor, params, val_len) else { return false; }
    if tree.nodes[bt.node_idx as i64].catch_all_child < 0 {
        bt_stack.resize(top_i);
    }
    cur_idx = p_idx;
    cursor = bt.cursor + (val_len as u16);
    return true;
}

inline fn pop_route_backtrack(
    tree:       const RadixTree&,
    eff_path:   const u8[:],
    bt_stack:   RouteBacktrackEntry[..8]&,
    cur_idx:    i32&,
    cursor:     u16&,
    params:     ZeroAllocParams&,
    out_ca_res: RouteMatchResult&,
) -> bool, bool {
    while bt_stack.len > 0 {
        let top_i = bt_stack.len - 1;
        let bt = bt_stack[top_i];
        params.len = bt.param_len;
        let rem = eff_path[(bt.cursor as i64)..];

        if try_backtrack_param_branch(tree, rem, bt, top_i, bt_stack, cur_idx, cursor, params) {
            return true, false;
        }

        bt_stack.resize(top_i);
        let ca_idx = tree.nodes[bt.node_idx as i64].catch_all_child;
        if ca_idx >= 0 {
            out_ca_res = match_catch_all_child(tree, ca_idx, rem, bt.cursor, params);
            if is_match_found(out_ca_res) {
                return true, true;
            }
        }
    }
    return false, false;
}

inline fn check_node_prefix_advance(
    tree:     const RadixTree&,
    eff_path: const u8[:],
    cur_idx:  i32,
    cursor:   u16&,
    skip_pfx: bool&,
) -> bool {
    if skip_pfx {
        skip_pfx = false;
        return true;
    }
    let prefix = tree.nodes[cur_idx as i64].prefix[..];
    guard prefix.len > 0 else { return true; }
    let rem_before = eff_path[(cursor as i64)..];
    guard rem_before.len >= prefix.len && rem_before[..prefix.len] == prefix else { return false; }
    cursor += prefix.len as u16;
    return true;
}

inline fn push_wildcard_backtrack_if_any(
    tree:      const RadixTree&,
    cur_idx:   i32,
    cursor:    u16,
    param_len: i64,
    bt_stack:  RouteBacktrackEntry[..8]&,
) {
    let has_wild = tree.nodes[cur_idx as i64].param_child >= 0
        || tree.nodes[cur_idx as i64].catch_all_child >= 0;
    if has_wild && bt_stack.len < 8 {
        bt_stack.push(RouteBacktrackEntry {
            node_idx:    cur_idx,
            cursor:      cursor,
            param_len:   param_len,
            tried_param: false,
        });
    }
}

// Matches path against the RadixTree, recording parameter spans into params.
fn match_path<B>(
    tree:           const RadixTree&,
    path:           const u8[:],
    params:         ZeroAllocParams&,
    out_canon_path: B&,
) -> RouteMatchResult {
    let eff_path, ok_path = resolve_effective_route_path(path, out_canon_path);
    guard ok_path && tree.root_idx >= 0 && eff_path.len > 0 else { return RouteMatchResult.NotFound; }
    params.clear();

    var cur_idx = tree.root_idx;
    var cursor:   u16                      = 0;
    var bt_stack: RouteBacktrackEntry[..8] = [];
    var skip_pfx = false;

    while cur_idx >= 0 {
        let pfx_ok = check_node_prefix_advance(tree, eff_path, cur_idx, cursor, skip_pfx);
        let rem = eff_path[(cursor as i64)..];
        if pfx_ok && rem.len == 0 && tree.nodes[cur_idx as i64].handler_id >= 0 {
            return make_found_route(tree.nodes[cur_idx as i64]);
        }
        if pfx_ok && rem.len > 0 {
            push_wildcard_backtrack_if_any(tree, cur_idx, cursor, params.len, bt_stack);
            let next_child = find_child_by_byte(tree, cur_idx, rem[0]);
            let next_pfx = if next_child >= 0 { tree.nodes[next_child as i64].prefix[..] } else { "" };
            if next_child >= 0 && rem.len >= next_pfx.len && rem[..next_pfx.len] == next_pfx {
                cur_idx = next_child;
                continue;
            }
        }

        var ca_res = RouteMatchResult.NotFound;
        let ok_bt, is_ca = pop_route_backtrack(
            tree, eff_path, bt_stack, cur_idx, cursor, params, ca_res,
        );
        if !ok_bt { break; }
        if is_ca { return ca_res; }
        skip_pfx = true;
    }

    return RouteMatchResult.NotFound;
}

fn match_path(
    tree:   const RadixTree&,
    path:   const u8[:],
    params: ZeroAllocParams&,
) -> RouteMatchResult {
    var canon_path: u8[..2048] = [];
    return match_path(tree, path, params, canon_path);
}

// Packs a 64-bit word lane (up to 8 bytes) starting at byte offset.
inline fn pack_word_lane(path: const u8[:], offset: i64) -> u64 {
    guard path.len > offset else { return 0; }
    let rem = path.len - offset;
    let n = if rem < 8 { rem } else { 8 };
    var w: u64 = 0;
    for i in n {
        w |= (path[offset + i] as u64) << ((i as u64) * 8);
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
    table:     const L0RegisterTable&,
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

extern fn native_simd_match_l0(
    path:      const u8[:],
    method_id: u8,
    table:     const L0RegisterTable&,
) -> i32 = "wing_simd_match_l0";

// Evaluates an HTTP request wire path against the L0 Register Table using SIMD vector acceleration.
//
// Example:
//   path = "/plaintext", method_id = 0 ("GET"), table contains "/plaintext" in slot 0
//   returns: 0
inline fn match_l0(
    path:      const u8[:],
    method_id: u8,
    table:     const L0RegisterTable&,
) -> i32 {
    guard path.len <= 16 && table.count > 0 else { return -1; }
    return native_simd_match_l0(path, method_id, table);
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
    table:        L0RegisterTable&,
    method_id:    u8,
    path:         const u8[:],
    handler_id:   i32,
    entries_mask: u32 = 0,
    pso_mask:     u64 = DEFAULT_ROUTE_PSO_MASK,
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
    table.active_mask |= ((1 as u16) << (slot as u16));
    table.count += 1;
    return true;
}

// ---- multi-method radix router ---------------------------------------------

// Method-segregated radix routing table supporting static, parameterized, and wildcard routes.
struct MethodTree {
    method: u8[..8]   = "GET",
    tree:   RadixTree = RadixTree { .. },
}

struct StaticRoutePayload {
    handler_id:   i32       = 0,
    content_type: u8[..64]  = [],
    body:         u8[..512] = [],
}

const DEFAULT_METRICS_PAYLOAD: const u8[:] =
    "{\"engine\":\"goose-wing\",\"memory_allocations\":0,\"heap_bytes\":0,\"architecture\":\"zero_alloc_stack\"}";

struct RadixRouter {
    trees:           MethodTree[..8]          = [],
    l0_table:        L0RegisterTable          = L0RegisterTable { .. },
    static_payloads: StaticRoutePayload[..32] = [],
}

fn new_radix_router() -> RadixRouter {
    var r = RadixRouter { .. };
    // RFC 9110 Section 9.3 & RFC 10008 Section 2 standard HTTP methods
    let methods: const u8[:][8] = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "QUERY"];
    for m in methods {
        var mt = MethodTree { method: [], tree: new_radix_tree() };
        mt.method.append(m);
        r.trees.push(mt);
    }
    let _ = set_static_route_payload(r, 1001, "text/plain", "Hello, World!");
    let _ = set_static_route_payload(r, 1002, "application/json", "{\"message\":\"Hello, World!\"}");
    let _ = set_static_route_payload(r, 1003, "application/json", DEFAULT_METRICS_PAYLOAD);
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
    let in_mask = pso_mask_to_srv_ingress(pso_mask);
    let out_mask = pso_mask_to_srv_egress(pso_mask);
    return add_route_masks(router, method, path, handler_id, entries_mask, pso_mask, in_mask, out_mask);
}

// Registers a route pattern with explicit role-scoped ingress_mask and egress_mask.
fn add_route_masks(
    router:       RadixRouter&,
    method:       const u8[:],
    path:         const u8[:],
    handler_id:   i32,
    entries_mask: u32,
    pso_mask:     u64,
    ingress_mask: u64,
    egress_mask:  u64,
) -> bool {
    var canon_path: u8[..512] = [];
    guard canonicalize_route_path(path, canon_path) else { return false; }
    for idx in router.trees.len {
        guard router.trees[idx].method[..] == method else { continue; }
        let ok = insert_route(
            router.trees[idx].tree,
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
    return false;
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
    let pso_mask = srv_masks_to_pso_mask(ingress_mask, egress_mask);
    return add_route_masks(router, method, path, handler_id, 0, pso_mask, ingress_mask, egress_mask);
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
            return true;
        }
    }
    guard router.static_payloads.len < router.static_payloads.cap else { return false; }
    var sp = StaticRoutePayload {
        handler_id:   handler_id,
        content_type: [],
        body:         [],
    };
    guard sp.content_type.try_set(content_type) && sp.body.try_set(body) else { return false; }
    router.static_payloads.push(sp);
    return true;
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

fn get_static_route_payload(
    router:     const RadixRouter&,
    handler_id: i32,
    res:        Response&,
) -> bool {
    for idx in router.static_payloads.len {
        if router.static_payloads[idx].handler_id == handler_id {
            if router.static_payloads[idx].content_type.len > 0 {
                set_header(res, "Content-Type", router.static_payloads[idx].content_type[..]);
            }
            res.body.clear();
            res.body.append(router.static_payloads[idx].body[..]);
            return true;
        }
    }
    return false;
}

inline fn method_tree_has_routes(tree: const RadixTree&) -> bool {
    guard tree.nodes.len > 0 else { return false; }
    if tree.nodes.len > 1 { return true; }
    let root = tree.nodes[0];
    return root.children.len > 0 || root.handler_id >= 0 || root.param_child >= 0 || root.catch_all_child >= 0;
}

fn build_allow_header(
    router:          const RadixRouter&,
    target_tree_idx: i32,
    method:          const u8[:],
    path:            const u8[:],
    allow_buf:       u8[..64]&,
) -> bool {
    var matched_other = false;
    var dummy_params = ZeroAllocParams { .. };
    var dummy_canon: u8[..512] = [];
    var has_get = false;
    var has_head = false;
    var has_options = false;

    if path == "*" {
        for idx in router.trees.len {
            if method_tree_has_routes(router.trees[idx].tree) {
                let m = router.trees[idx].method[..];
                if m == "GET" { has_get = true; }
                if m == "HEAD" { has_head = true; }
                if m == "OPTIONS" { has_options = true; }
                if matched_other { allow_buf.append(", "); }
                allow_buf.append(m);
                matched_other = true;
            }
        }
    } else {
        for idx in router.trees.len {
            guard (idx as i32) != target_tree_idx else { continue; }
            let res_other = match_path(router.trees[idx].tree, path, dummy_params, dummy_canon);
            guard is_match_found(res_other) else { continue; }
            let m = router.trees[idx].method[..];
            if m == "GET" { has_get = true; }
            if m == "HEAD" { has_head = true; }
            if m == "OPTIONS" { has_options = true; }
            if matched_other { allow_buf.append(", "); }
            allow_buf.append(m);
            matched_other = true;
        }
    }

    if matched_other {
        // RFC 9110 §9.3.2: Allow header MUST include HEAD if GET is supported
        if has_get && !has_head {
            allow_buf.append(", HEAD");
        }
        // RFC 9110 §9.3.7: Allow header MUST include OPTIONS if capability probe
        let is_capability_probe = (method == "OPTIONS" || path == "*");
        if is_capability_probe && !has_options {
            allow_buf.append(", OPTIONS");
        }
    }
    return matched_other;
}

inline fn resolve_method_tree_index(method: const u8[:]) -> i32 {
    guard method.len >= 3 else { return -1; }
    return match method[0] {
        'G' => if method == "GET" { 0 } else { -1 },
        'P' => if method == "POST" { 1 } else if method == "PUT" { 2 } else if method == "PATCH" { 4 } else { -1 },
        'D' => if method == "DELETE" { 3 } else { -1 },
        'H' => if method == "HEAD" { 5 } else { -1 },
        'O' => if method == "OPTIONS" { 6 } else { -1 },
        'Q' => if method == "QUERY" { 7 } else { -1 },
        _ => -1,
    };
}

// Matches an HTTP request path against the L0 Register Table and returns RouteMatchResult if found.
inline fn try_match_l0_slot<B>(
    table:          const L0RegisterTable&,
    method_id:      u8,
    path:           const u8[:],
    params:         ZeroAllocParams&,
    out_canon_path: B&,
) -> RouteMatchResult {
    guard path.len <= 16 && table.count > 0 else { return RouteMatchResult.NotFound; }
    let slot = match_l0(path, method_id, table);
    guard slot >= 0 else { return RouteMatchResult.NotFound; }

    let s = slot as i64;
    params.clear();
    guard out_canon_path.try_set(path) else { return RouteMatchResult.NotFound; }
    return RouteMatchResult.Found {
        handler_id:   table.handler_id[s],
        entries_mask: table.entries_mask[s],
        pso_mask:     table.pso_mask[s],
        ingress_mask: table.ingress_mask[s],
        egress_mask:  table.egress_mask[s],
    };
}

// Matches a request method and path against registered routes.
// Automatically canonicalizes path before matching.
// Automatic HEAD routing: if a route matches GET, HEAD requests route to GET handler (RFC 9110 §9.3.2).
// Returns RouteMatchResult: Found with handler_id, NotFound, or MethodNotAllowed with Allow header.
fn match_route<B>(
    router:         const RadixRouter&,
    method:         const u8[:],
    path:           const u8[:],
    params:         ZeroAllocParams&,
    out_canon_path: B&,
) -> RouteMatchResult {
    guard router.trees.len > 0 else { return RouteMatchResult.NotFound; }
    let clean_path = strip_query_and_fragment(path);
    var target_tree_idx: i32 = resolve_method_tree_index(method);
    if target_tree_idx < 0 || (target_tree_idx as i64) >= router.trees.len {
        target_tree_idx = -1;
        for idx in router.trees.len {
            if router.trees[idx].method[..] == method {
                target_tree_idx = idx as i32;
                break;
            }
        }
    }

    if target_tree_idx >= 0 && clean_path != "*" {
        let fast_res = try_match_l0_slot(router.l0_table, target_tree_idx as u8, clean_path, params, out_canon_path);
        if match fast_res { Found _ => true, _ => false } {
            return fast_res;
        }

        let res = match_path(router.trees[target_tree_idx as i64].tree, clean_path, params, out_canon_path);
        match res {
            Found _ => { return res; },
            _ => {},
        };
    }

    // Automatic HEAD routing: if method is HEAD and no explicit HEAD route matched,
    // route to GET handler if a GET route matches (RFC 9110 §9.3.2).
    if method == "HEAD" && clean_path != "*" && router.trees[0].method[..] == "GET" {
        let fast_head = try_match_l0_slot(router.l0_table, 0, clean_path, params, out_canon_path);
        if match fast_head { Found _ => true, _ => false } {
            return fast_head;
        }

        let res_get = match_path(router.trees[0].tree, clean_path, params, out_canon_path);
        match res_get {
            Found _ => { return res_get; },
            _ => {},
        };
    }

    var allow_buf: u8[..64] = [];
    if build_allow_header(router, target_tree_idx, method, clean_path, allow_buf) {
        return RouteMatchResult.MethodNotAllowed { allow_header: allow_buf };
    }

    return RouteMatchResult.NotFound;
}

fn match_route(
    router: const RadixRouter&,
    method: const u8[:],
    path:   const u8[:],
    params: ZeroAllocParams&,
) -> RouteMatchResult {
    var canon_path: u8[..2048] = [];
    return match_route(router, method, path, params, canon_path);
}
