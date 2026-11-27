// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal radix trie, L0 SWAR matching, and route canonicalization helpers for `server/router.goose`.
namespace server_internal;

import std;
import core;
import rfc.http;
import .router;
import .router_l0_internal;

// Maps a combined 64-bit PSO mask (bits 0..31 ingress, bits 32..63 egress) to role-scoped server ingress_mask.
inline fn pso_mask_to_srv_ingress(pso_mask: u64) -> u64 {
    if pso_mask == 0 {
        return wire::STAGE_SRV_IN_ROUTE_MATCH;
    }
    var m: u64 = wire::STAGE_SRV_IN_ROUTE_MATCH | wire::STAGE_SRV_IN_EDGE_FILTER;
    if (pso_mask & server::STAGE_INGRESS_SLOWLORIS) != 0 { m |= wire::STAGE_SRV_IN_SLOWLORIS; }
    if (pso_mask & server::STAGE_INGRESS_EXPECT_100) != 0 { m |= wire::STAGE_SRV_IN_EXPECT_100; }
    if (pso_mask & server::STAGE_INGRESS_IP_RATELIMIT) != 0 { m |= wire::STAGE_SRV_IN_RATELIMIT_IP; }
    if (pso_mask & server::STAGE_INGRESS_ROUTE_RATELIMIT) != 0 { m |= wire::STAGE_SRV_IN_RATELIMIT_ROUTE; }
    if (pso_mask & server::STAGE_INGRESS_CORS_PREFLIGHT) != 0 { m |= wire::STAGE_SRV_IN_CORS; }
    if (pso_mask & server::STAGE_INGRESS_FETCH_CSRF) != 0 { m |= wire::STAGE_SRV_IN_CSRF; }
    if (pso_mask & server::STAGE_INGRESS_AUTH_COOKIE) != 0 { m |= wire::STAGE_SRV_IN_AUTH_COOKIE; }
    if (pso_mask & server::STAGE_INGRESS_AUTH_JWT) != 0 { m |= wire::STAGE_SRV_IN_AUTH_JWT; }
    return m;
}

// Maps a combined 64-bit PSO mask (bits 0..31 ingress, bits 32..63 egress) to role-scoped server egress_mask.
inline fn pso_mask_to_srv_egress(pso_mask: u64) -> u64 {
    var m: u64 = 0;
    if (pso_mask & server::STAGE_EGRESS_ETAG) != 0 { m |= wire::STAGE_SRV_OUT_ETAG; }
    if (pso_mask & server::STAGE_EGRESS_COMPRESS_GZIP) != 0 { m |= wire::STAGE_SRV_OUT_COMPRESS_GZIP; }
    if (pso_mask & server::STAGE_EGRESS_COMPRESS_BROTLI) != 0 { m |= wire::STAGE_SRV_OUT_COMPRESS_BR; }
    if (pso_mask & server::STAGE_EGRESS_COMPRESS_ZSTD) != 0 { m |= wire::STAGE_SRV_OUT_COMPRESS_ZSTD; }
    if (pso_mask & server::STAGE_EGRESS_SECURITY_HEADERS) != 0 { m |= wire::STAGE_SRV_OUT_SECURITY_HEADERS; }
    if (pso_mask & server::STAGE_EGRESS_METRICS) != 0 { m |= wire::STAGE_SRV_OUT_METRICS; }
    if (pso_mask & server::STAGE_EGRESS_ACCESS_LOG) != 0 { m |= wire::STAGE_SRV_OUT_ACCESS_LOG; }
    return m;
}

// Maps role-scoped server ingress_mask and egress_mask to a combined 64-bit PSO mask.
inline fn srv_masks_to_pso_mask(ingress_mask: u64, egress_mask: u64) -> u64 {
    var pso: u64 = 0;
    if (ingress_mask & wire::STAGE_SRV_IN_SLOWLORIS) != 0 { pso |= server::STAGE_INGRESS_SLOWLORIS; }
    if (ingress_mask & wire::STAGE_SRV_IN_EXPECT_100) != 0 { pso |= server::STAGE_INGRESS_EXPECT_100; }
    if (ingress_mask & wire::STAGE_SRV_IN_RATELIMIT_IP) != 0 { pso |= server::STAGE_INGRESS_IP_RATELIMIT; }
    if (ingress_mask & wire::STAGE_SRV_IN_RATELIMIT_ROUTE) != 0 { pso |= server::STAGE_INGRESS_ROUTE_RATELIMIT; }
    if (ingress_mask & wire::STAGE_SRV_IN_CORS) != 0 { pso |= server::STAGE_INGRESS_CORS_PREFLIGHT; }
    if (ingress_mask & wire::STAGE_SRV_IN_CSRF) != 0 { pso |= server::STAGE_INGRESS_FETCH_CSRF; }
    if (ingress_mask & wire::STAGE_SRV_IN_AUTH_COOKIE) != 0 { pso |= server::STAGE_INGRESS_AUTH_COOKIE; }
    if (ingress_mask & wire::STAGE_SRV_IN_AUTH_JWT) != 0 { pso |= server::STAGE_INGRESS_AUTH_JWT; }
    if (egress_mask & wire::STAGE_SRV_OUT_ETAG) != 0 { pso |= server::STAGE_EGRESS_ETAG; }
    if (egress_mask & wire::STAGE_SRV_OUT_COMPRESS_GZIP) != 0 { pso |= server::STAGE_EGRESS_COMPRESS_GZIP; }
    if (egress_mask & wire::STAGE_SRV_OUT_COMPRESS_BR) != 0 { pso |= server::STAGE_EGRESS_COMPRESS_BROTLI; }
    if (egress_mask & wire::STAGE_SRV_OUT_COMPRESS_ZSTD) != 0 { pso |= server::STAGE_EGRESS_COMPRESS_ZSTD; }
    if (egress_mask & wire::STAGE_SRV_OUT_SECURITY_HEADERS) != 0 { pso |= server::STAGE_EGRESS_SECURITY_HEADERS; }
    if (egress_mask & wire::STAGE_SRV_OUT_METRICS) != 0 { pso |= server::STAGE_EGRESS_METRICS; }
    if (egress_mask & wire::STAGE_SRV_OUT_ACCESS_LOG) != 0 { pso |= server::STAGE_EGRESS_ACCESS_LOG; }
    return pso;
}

enum NodeType {
    Root,
    Static,
    Param { suffix: bool },
    CatchAll,
}

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

// Allocates a new node in the arena pool
fn alloc_node(tree: server::RadixTree&, n_type: NodeType) -> i32 {
    var n = RadixNode { node_type: n_type, .. };
    guard tree.nodes.try_push(n) else { return -1; }
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
fn find_child_by_byte(tree: const server::RadixTree&, cur_idx: i32, b: u8) -> i32 {
    let c_idx = cur_idx as i64;
    let idx = tree.nodes[c_idx].indices[..].index_of_byte(b);
    if idx >= 0 {
        return tree.nodes[c_idx].children[idx];
    }
    return -1;
}

// Splits an existing node at common_len, creating a child node with the remaining prefix and edges.
fn split_radix_node(
    tree:          server::RadixTree&,
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
    tree.nodes[s_idx].priority = max(tree.nodes[c_idx].priority, 1) - 1;

    let first_split_byte = tree.nodes[s_idx].prefix[0];
    let _ = tree.nodes[c_idx].prefix.try_set(common_prefix);
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
fn traverse_or_insert_static(tree: server::RadixTree&, cur_idx: i32&, seg: const u8[:]) -> bool {
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
    tree:         server::RadixTree&,
    cur_idx:      i32,
    name:         const u8[:],
    handler_id:   i32,
    entries_mask: u32,
    pso_mask:     u64 = 0,
    ingress_mask: u64 = wire::STAGE_SRV_IN_DEFAULT_MASK,
    egress_mask:  u64 = wire::STAGE_SRV_OUT_DEFAULT_MASK,
) -> bool {
    guard name.len > 0 && name.len <= 32 else { return false; }
    let cur = cur_idx as i64;
    let prev_ca = tree.nodes[cur].catch_all_child;
    if prev_ca >= 0 {
        let prev = prev_ca as i64;
        guard prev < tree.nodes.len else { return false; }
        let existing_h = tree.nodes[prev].handler_id;
        guard existing_h < 0 || (existing_h == handler_id && tree.nodes[prev].param_name[..] == name) else {
            return false;
        }
        tree.nodes[prev].handler_id = handler_id;
        tree.nodes[prev].entries_mask = entries_mask;
        tree.nodes[prev].pso_mask = pso_mask;
        tree.nodes[prev].ingress_mask = ingress_mask;
        tree.nodes[prev].egress_mask = egress_mask;
        return true;
    }

    let ca_idx = alloc_node(tree, NodeType.CatchAll);
    guard ca_idx >= 0 else { return false; }
    let ca = ca_idx as i64;
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
    tree:          server::RadixTree&,
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
        let p_i64 = param_node_idx as i64;
        guard p_i64 < tree.nodes.len && tree.nodes[p_i64].param_name[..] == name else {
            return false;
        }
        let updated_type = update_param_suffix_flag(tree.nodes[p_i64].node_type, suffix_after);
        tree.nodes[p_i64].node_type = updated_type;
    }

    out_param_idx = param_node_idx;
    return true;
}

inline fn inc_node_priority(tree: server::RadixTree&, cur_idx: i32) {
    tree.nodes[cur_idx as i64].priority += 1;
}

inline fn set_endpoint_handler(
    tree:         server::RadixTree&,
    node_idx:     i32,
    handler_id:   i32,
    entries_mask: u32,
    pso_mask:     u64,
    ingress_mask: u64 = wire::STAGE_SRV_IN_DEFAULT_MASK,
    egress_mask:  u64 = wire::STAGE_SRV_OUT_DEFAULT_MASK,
) -> bool {
    let n = node_idx as i64;
    let existing = tree.nodes[n].handler_id;
    guard existing < 0 || existing == handler_id else { return false; }
    tree.nodes[n].handler_id = handler_id;
    tree.nodes[n].entries_mask = entries_mask;
    tree.nodes[n].pso_mask = pso_mask;
    tree.nodes[n].ingress_mask = ingress_mask;
    tree.nodes[n].egress_mask = egress_mask;
    return true;
}

inline fn sub_param_offset(param_end: i64&, param_start: i64) {
    param_end -= param_start;
}

inline fn calc_next_char_pos(pos: i64) -> i64 {
    return pos + 1;
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
           seg.eq_ascii_fold(".%2e") ||
           seg.eq_ascii_fold("%2e.") ||
           seg.eq_ascii_fold("%2e%2e");
}

inline fn is_valid_suffix_segment_end(tree: const server::RadixTree&, node_idx: i32) -> bool {
    let n = tree.nodes[node_idx as i64];
    return n.handler_id >= 0 ||
        find_child_by_byte(tree, node_idx, '/') >= 0 ||
        n.param_child >= 0 ||
        n.catch_all_child >= 0;
}

// Verifies that `rem_seg` matches a chain of static children starting at `child_idx`.
fn matches_static_suffix_chain(tree: const server::RadixTree&, child_idx: i32, rem_seg: const u8[:]) -> bool {
    var cur = child_idx;
    var off: i64 = 0;
    while off < rem_seg.len && cur >= 0 {
        let pfx = tree.nodes[cur as i64].prefix[..];
        let tail = rem_seg[off..];
        if tail.len < pfx.len {
            return pfx[..tail.len] == tail && pfx[tail.len] == '/';
        }
        if tail.len == pfx.len {
            return pfx == tail && is_valid_suffix_segment_end(tree, cur);
        }
        guard tail[..pfx.len] == pfx else { return false; }
        off = core::add_sat_i64(off, pfx.len);
        guard off < rem_seg.len else { break; }
        cur = find_child_by_byte(tree, cur, rem_seg[off]);
    }
    return off >= rem_seg.len && cur >= 0 && is_valid_suffix_segment_end(tree, cur);
}

// Scans current path segment for a static child suffix attached to `p_idx`.
fn find_param_suffix_split(tree: const server::RadixTree&, p_idx: i32, rem: const u8[:], seg_end: i64) -> i64 {
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
    tree:    const server::RadixTree&,
    p_idx:   i32,
    rem:     const u8[:],
    cursor:  u16,
    params:  http::ZeroAllocParams&,
    val_len: i64&,
) -> bool {
    let is_suffix = match tree.nodes[p_idx as i64].node_type {
        Param p => p.suffix,
        _ => false,
    };

    let slash_idx = rem.index_of_byte('/');
    let seg_end = if slash_idx >= 0 { slash_idx } else { rem.len };
    let val_end = if is_suffix {
        find_param_suffix_split(tree, p_idx, rem, seg_end)
    } else {
        seg_end
    };

    guard val_end > 0 else { return false; }

    let pname = tree.nodes[p_idx as i64].param_name[..];
    guard http::add_param(params, pname, 0, 0, cursor, cursor + (val_end as u16)) else { return false; }
    val_len = val_end;
    return true;
}

// Captures remainder path into catch-all parameter and yields handler result.
fn match_catch_all_child(
    tree:   const server::RadixTree&,
    ca_idx: i32,
    rem:    const u8[:],
    cursor: u16,
    params: http::ZeroAllocParams&,
) -> server::RouteMatchResult {
    let catch_val = if rem[0] == '/' { rem[1..] } else { rem };
    guard catch_val.len > 0 else { return server::RouteMatchResult.NotFound; }

    let start_off = if rem[0] == '/' { cursor + 1 } else { cursor };
    let pname = tree.nodes[ca_idx as i64].param_name[..];
    guard http::add_param(params, pname, 0, 0, start_off, start_off + (catch_val.len as u16)) else {
        return server::RouteMatchResult.NotFound;
    }

    let hid = tree.nodes[ca_idx as i64].handler_id;
    if hid >= 0 {
        return server::RouteMatchResult.Found {
            handler_id:   hid,
            entries_mask: tree.nodes[ca_idx as i64].entries_mask,
            pso_mask:     tree.nodes[ca_idx as i64].pso_mask,
            ingress_mask: tree.nodes[ca_idx as i64].ingress_mask,
            egress_mask:  tree.nodes[ca_idx as i64].egress_mask,
        };
    }
    return server::RouteMatchResult.NotFound;
}

inline fn has_non_root_trailing_slash(path: const u8[:]) -> bool {
    return path.len > 1 && path[path.len - 1] == '/';
}

inline fn is_valid_route_pct_triplet(h1: u8, h2: u8) -> bool {
    guard core::is_ascii_hexdigit(h1) && core::is_ascii_hexdigit(h2) else {
        return false;
    }
    let lo1 = core::to_lower_ascii_byte(h1);
    let lo2 = core::to_lower_ascii_byte(h2);
    let bad = (lo1 == '5' && lo2 == 'c')
        || (lo1 == '2' && lo2 == 'f')
        || (lo1 == '3' && lo2 == 'b');
    return !bad;
}

inline fn is_valid_canonical_path_component(s: const u8[:]) -> bool {
    var i: i64 = 0;
    while i < s.len {
        let b = s[i];
        guard b >= 0x20 && b != 0x7F && b != '\\' && b != ';' else {
            return false;
        }
        if b == '%' {
            guard i + 2 < s.len && is_valid_route_pct_triplet(s[i + 1], s[i + 2]) else {
                return false;
            }
            i += 3;
            continue;
        }
        i += 1;
    }
    return true;
}

// Strips query/fragment and scheme/authority, rejecting raw CTLs, '\', ';',
// malformed %XX triplets, and encoded %5C/%2F/%3B in the path component.
//
// Example:
//   raw_path = "http://ex.com/a%20b?x=1"
//   returns: "/a%20b", ok = true
fn extract_valid_route_path_component(raw_path: const u8[:]) -> const u8[:], bool {
    var s = strip_query_and_fragment(raw_path);
    s = strip_scheme_and_authority(s);
    guard is_valid_canonical_path_component(s) else { return "", false; }
    return s, true;
}

inline fn pop_last_canonical_segment<B>(out: B&) {
    guard out.len > 0 else { return; }
    var last_slash: i64 = out.len - 1;
    while last_slash > 0 && out[last_slash] != '/' {
        last_slash--;
    }
    out.resize(last_slash);
}

inline fn is_already_canonical_route_path(path: const u8[:]) -> bool {
    guard path.len > 0 && path[0] == '/' else { return false; }
    guard !has_non_root_trailing_slash(path) else { return false; }
    for i in 1..path.len {
        let b = path[i];
        if b < 0x20 || b == 0x7F || b == '.' || b == '?' || b == '#' || b == '%'
            || b == '\\' || b == ';' {
            return false;
        }
        if b == '/' && path[i - 1] == '/' { return false; }
    }
    return true;
}

// Resolves canonical path into `out`, populating `out` even when `path` is already canonical.
//
// Example:
//   path = "/users/42", out = [] -> returns ("/users/42", true), out = "/users/42"
inline fn resolve_effective_route_path<B>(path: const u8[:], out: B&) -> const u8[:], bool {
    if is_already_canonical_route_path(path) {
        guard out.try_set(path) else { return "", false; }
        return path, true;
    }
    out.clear();
    guard server::canonicalize_route_path(path, out) else { return "", false; }
    return out[..], true;
}

// Borrows `path` directly with zero copy when already canonical; otherwise canonicalizes into `scratch`.
//
// Example:
//   path = "/users/42" -> returns ("/users/42", true) with untouched `scratch`
inline fn resolve_effective_route_path_borrow<B>(path: const u8[:], scratch: B&) -> const u8[:], bool {
    if is_already_canonical_route_path(path) {
        return path, true;
    }
    scratch.clear();
    guard server::canonicalize_route_path(path, scratch) else { return "", false; }
    return scratch[..], true;
}

inline fn make_found_route(n: const RadixNode&) -> server::RouteMatchResult {
    return server::RouteMatchResult.Found {
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
    tree:     const server::RadixTree&,
    rem:      const u8[:],
    bt:       const RouteBacktrackEntry&,
    top_i:    i64,
    bt_stack: RouteBacktrackEntry[..32]&,
    cur_idx:  i32&,
    cursor:   u16&,
    params:   http::ZeroAllocParams&,
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
    tree:       const server::RadixTree&,
    eff_path:   const u8[:],
    bt_stack:   RouteBacktrackEntry[..32]&,
    cur_idx:    i32&,
    cursor:     u16&,
    params:     http::ZeroAllocParams&,
    out_ca_res: server::RouteMatchResult&,
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
            if server::is_match_found(out_ca_res) {
                return true, true;
            }
        }
    }
    return false, false;
}

inline fn check_node_prefix_advance(
    tree:     const server::RadixTree&,
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
    tree:        const server::RadixTree&,
    cur_idx:     i32,
    cursor:      u16,
    param_len:   i64,
    bt_stack:    RouteBacktrackEntry[..32]&,
    tried_param: bool = false,
) {
    let has_wild = (!tried_param && tree.nodes[cur_idx as i64].param_child >= 0)
        || tree.nodes[cur_idx as i64].catch_all_child >= 0;
    if has_wild {
        let _ = bt_stack.try_push(RouteBacktrackEntry {
            node_idx:    cur_idx,
            cursor:      cursor,
            param_len:   param_len,
            tried_param: tried_param,
        });
    }
}

inline fn commit_matched_route_node(
    cur_idx:     i32&,
    cursor:      u16&,
    skip_pfx:    bool&,
    next_idx:    i32,
    advance_len: i64,
) {
    cur_idx = next_idx;
    cursor += advance_len as u16;
    skip_pfx = true;
}

inline fn try_advance_static_or_param_node(
    tree:     const server::RadixTree&,
    rem:      const u8[:],
    cur_idx:  i32&,
    cursor:   u16&,
    skip_pfx: bool&,
    params:   http::ZeroAllocParams&,
    bt_stack: RouteBacktrackEntry[..32]&,
) -> bool {
    let next_child = find_child_by_byte(tree, cur_idx, rem[0]);
    let next_pfx = if next_child >= 0 { tree.nodes[next_child as i64].prefix[..] } else { "" };
    if next_child >= 0 && rem.len >= next_pfx.len && rem[..next_pfx.len] == next_pfx {
        push_wildcard_backtrack_if_any(tree, cur_idx, cursor, params.len, bt_stack, false);
        commit_matched_route_node(cur_idx, cursor, skip_pfx, next_child, next_pfx.len);
        return true;
    }
    let p_idx = tree.nodes[cur_idx as i64].param_child;
    let saved_param_len = params.len;
    if p_idx >= 0 {
        var val_len: i64 = 0;
        if match_param_child(tree, p_idx, rem, cursor, params, val_len) {
            push_wildcard_backtrack_if_any(tree, cur_idx, cursor, saved_param_len, bt_stack, true);
            commit_matched_route_node(cur_idx, cursor, skip_pfx, p_idx, val_len);
            return true;
        }
    }
    push_wildcard_backtrack_if_any(tree, cur_idx, cursor, saved_param_len, bt_stack, true);
    return false;
}
