// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Goose-exclusive self-relative packed radix route tree (`PackedRoute..[>..]`).
// Compiles a builder `RadixTree` into a variable-size enum arena linked via varint relative
// offsets (`PackedRoute..&<varint>?`), supporting zero-copy `bytes_of` and verified `from_bytes`.
namespace server;

import std;
import core;
import http.bind;
import .router;
import .router_internal;

// Route endpoint dispatch metadata packed inside compiled `PackedRoute` nodes.
struct PackedRouteMeta {
    handler_id:   i32 = -1,
    entries_mask: u32 = 0,
    pso_mask:     u64 = 0,
    ingress_mask: u64 = 0,
    egress_mask:  u64 = 0,
}

// Variable-size self-relative radix route node stored sequentially inside `PackedRoute..[>..]`.
enum PackedRoute {
    Leaf {
        prefix: u8[varint],
        meta:   PackedRouteMeta,
    },
    Branch {
        prefix:          u8[varint],
        has_handler:     bool,
        meta:            PackedRouteMeta,
        first_child:     PackedRoute..&<varint>?,
        param_child:     PackedRoute..&<varint>?,
        catch_all_child: PackedRoute..&<varint>?,
    },
    Param {
        prefix:          u8[varint],
        param_name:      u8[varint],
        has_suffix:      bool,
        has_handler:     bool,
        meta:            PackedRouteMeta,
        first_child:     PackedRoute..&<varint>?,
        param_child:     PackedRoute..&<varint>?,
        catch_all_child: PackedRoute..&<varint>?,
    },
    CatchAll {
        prefix:     u8[varint],
        param_name: u8[varint],
        meta:       PackedRouteMeta,
    },
    Sib {
        first_byte: u8,
        child:      PackedRoute..&<varint>,
        next:       PackedRoute..&<varint>?,
    },
}

inline fn make_packed_meta(n: const server_internal::RadixNode&) -> PackedRouteMeta {
    return PackedRouteMeta {
        handler_id:   n.handler_id,
        entries_mask: n.entries_mask,
        pso_mask:     n.pso_mask,
        ingress_mask: n.ingress_mask,
        egress_mask:  n.egress_mask,
    };
}

inline fn make_packed_found(m: const PackedRouteMeta&) -> RouteMatchResult {
    return RouteMatchResult.Found {
        handler_id:   m.handler_id,
        entries_mask: m.entries_mask,
        pso_mask:     m.pso_mask,
        ingress_mask: m.ingress_mask,
        egress_mask:  m.egress_mask,
    };
}

recursive fn compile_packed_node(
    tree:     const RadixTree&,
    node_idx: i32,
    out:      PackedRoute..[>..]&,
) -> PackedRoute..& {
    let n .= tree.nodes[node_idx];
    var first_ch: PackedRoute..? = null;
    var i = core::sub_sat_i64(n.children.len, 1);
    while i >= 0 {
        let c_idx = n.children[i];
        let c_node .= tree.nodes[c_idx];
        let fb: u8 = if c_node.prefix.len > 0 { c_node.prefix[0] } else { 0 };
        let c_ref .= compile_packed_node(tree, c_idx, out);
        first_ch .= out.push(PackedRoute.Sib {
            first_byte: fb,
            child:      c_ref,
            next:       first_ch,
        });
        i = core::sub_sat_i64(i, 1);
    }

    var p_ch: PackedRoute..? = null;
    if n.param_child >= 0 {
        p_ch .= compile_packed_node(tree, n.param_child, out);
    }
    var ca_ch: PackedRoute..? = null;
    if n.catch_all_child >= 0 {
        ca_ch .= compile_packed_node(tree, n.catch_all_child, out);
    }

    let meta = make_packed_meta(n);
    let has_handler = n.handler_id >= 0;

    return match n.node_type {
        CatchAll => out.push(PackedRoute.CatchAll {
            prefix:     n.prefix[..],
            param_name: n.param_name[..],
            meta:       meta,
        }),
        Param p => out.push(PackedRoute.Param {
            prefix:          n.prefix[..],
            param_name:      n.param_name[..],
            has_suffix:      p.suffix,
            has_handler:     has_handler,
            meta:            meta,
            first_child:     first_ch,
            param_child:     p_ch,
            catch_all_child: ca_ch,
        }),
        _ => if has_handler && !first_ch && !p_ch && !ca_ch {
            out.push(PackedRoute.Leaf {
                prefix: n.prefix[..],
                meta:   meta,
            })
        } else {
            out.push(PackedRoute.Branch {
                prefix:          n.prefix[..],
                has_handler:     has_handler,
                meta:            meta,
                first_child:     first_ch,
                param_child:     p_ch,
                catch_all_child: ca_ch,
            })
        },
    };
}

// Compiles `tree` bottom-up into the self-relative `PackedRoute..[>..]` arena `out`.
// The root node is placed at the end of `out` so parent links become compact backward varint offsets.
//
// Example:
//   compile_packed_route_tree(tree, packed_arena) -> true (packed_arena ready for match_packed_route)
fn compile_packed_route_tree(tree: const RadixTree&, out: PackedRoute..[>..]&) -> bool {
    guard tree.root_idx >= 0 && tree.root_idx < tree.nodes.len else { return false; }
    out.clear();
    let _ = compile_packed_node(tree, tree.root_idx, out);
    return true;
}

// Returns the root node of a compiled or `from_bytes`-verified `PackedRoute..[>..]` arena.
fn find_packed_route_root(arena: const PackedRoute..[>..]&) -> const PackedRoute..? {
    var root: const PackedRoute..? = null;
    for n in arena {
        root .= n;
    }
    return root;
}

inline fn packed_node_prefix(n: const PackedRoute..&) -> const u8[:] {
    return match n {
        Leaf &l => l.prefix,
        Branch &b => b.prefix,
        Param &p => p.prefix,
        CatchAll &c => c.prefix,
        Sib &_ => "",
    };
}

inline fn packed_sib_next(n: const PackedRoute..&) -> const PackedRoute..? {
    return match n {
        Sib &s => s.next,
        _ => null,
    };
}

inline fn packed_node_static_child(first_child: const PackedRoute..?, b: u8) -> const PackedRoute..? {
    var cur = first_child;
    while cur {
        let hit: const PackedRoute..? = match cur {
            Sib &s => if s.first_byte == b { s.child } else { null },
            _ => null,
        };
        if hit {
            return hit;
        }
        cur .= packed_sib_next(cur);
    }
    return null;
}

inline fn packed_is_valid_suffix_end(n: const PackedRoute..&) -> bool {
    return match n {
        Leaf &_ => true,
        Branch &b => b.has_handler || b.param_child || b.catch_all_child ||
            packed_node_static_child(b.first_child, '/'),
        Param &p => p.has_handler || p.param_child || p.catch_all_child ||
            packed_node_static_child(p.first_child, '/'),
        CatchAll &_ => true,
        Sib &_ => false,
    };
}

fn packed_matches_suffix_chain(start: const PackedRoute..&, rem_seg: const u8[:]) -> bool {
    var cur: const PackedRoute..? = start;
    var off: i64                  = 0;
    while cur && off < rem_seg.len {
        let pfx = packed_node_prefix(cur);
        let tail = rem_seg[off..];
        if tail.len < pfx.len {
            return pfx[..tail.len] == tail && pfx[tail.len] == '/';
        }
        if tail.len == pfx.len {
            return pfx == tail && packed_is_valid_suffix_end(cur);
        }
        guard tail[..pfx.len] == pfx else { return false; }
        off = core::add_sat_i64(off, pfx.len);
        guard off < rem_seg.len else { break; }
        cur .= match cur {
            Branch &b => packed_node_static_child(b.first_child, rem_seg[off]),
            Param &p => packed_node_static_child(p.first_child, rem_seg[off]),
            _ => null,
        };
    }
    if cur && off >= rem_seg.len {
        return packed_is_valid_suffix_end(cur);
    }
    return false;
}

fn packed_find_param_suffix_split(
    p_first_child: const PackedRoute..?,
    rem:           const u8[:],
    seg_end:       i64,
) -> i64 {
    for i in seg_end {
        guard i > 0 else { continue; }
        let ch = packed_node_static_child(p_first_child, rem[i]);
        guard ch else { continue; }
        if packed_matches_suffix_chain(ch, rem[i..seg_end]) {
            return i;
        }
    }
    return seg_end;
}

inline fn add_u16_len(base: u16, delta: i64) -> u16 {
    return core::add_sat_u64(base, delta as u64) as u16;
}

inline fn match_packed_catchall(
    c_node: const PackedRoute..&,
    rem:    const u8[:],
    cursor: u16,
    params: http::ZeroAllocParams&,
) -> RouteMatchResult {
    return match c_node {
        CatchAll &c => {
            let skip_slash = rem[0] == '/';
            let catch_val = if skip_slash { rem[1..] } else { rem };
            guard catch_val.len > 0 else { return RouteMatchResult.NotFound; }
            let start_off = if skip_slash { add_u16_len(cursor, 1) } else { cursor };
            let end_off = add_u16_len(start_off, catch_val.len);
            guard http::add_param(params, c.param_name, 0, 0, start_off, end_off) else {
                return RouteMatchResult.NotFound;
            }
            if c.meta.handler_id >= 0 {
                return make_packed_found(c.meta);
            }
            return RouteMatchResult.NotFound;
        },
        _ => RouteMatchResult.NotFound,
    };
}

recursive fn match_packed_children(
    first_child:     const PackedRoute..?,
    param_child:     const PackedRoute..?,
    catch_all_child: const PackedRoute..?,
    eff_path:        const u8[:],
    cursor:          u16,
    params:          http::ZeroAllocParams&,
) -> RouteMatchResult {
    let rem = eff_path[cursor..];
    let saved_param_len = params.len;

    if first_child {
        let sc = packed_node_static_child(first_child, rem[0]);
        if sc {
            let s_pfx = packed_node_prefix(sc);
            if rem.len >= s_pfx.len && rem[..s_pfx.len] == s_pfx {
                let next_c = add_u16_len(cursor, s_pfx.len);
                let res = match_packed_node(sc, eff_path, next_c, true, params);
                if is_match_found(res) {
                    return res;
                }
                params.len = saved_param_len;
            }
        }
    }

    if param_child {
        let res = match_packed_param_node(param_child, eff_path, rem, cursor, params);
        if is_match_found(res) {
            return res;
        }
        params.len = saved_param_len;
    }

    if catch_all_child {
        return match_packed_catchall(catch_all_child, rem, cursor, params);
    }
    return RouteMatchResult.NotFound;
}

recursive fn match_packed_param_node(
    p_node:   const PackedRoute..&,
    eff_path: const u8[:],
    rem:      const u8[:],
    cursor:   u16,
    params:   http::ZeroAllocParams&,
) -> RouteMatchResult {
    return match p_node {
        Param &p => {
            let slash_idx = rem.index_of_byte('/');
            let seg_end = if slash_idx >= 0 { slash_idx } else { rem.len };
            let val_end = if p.has_suffix {
                packed_find_param_suffix_split(p.first_child, rem, seg_end)
            } else {
                seg_end
            };
            guard val_end > 0 else { return RouteMatchResult.NotFound; }
            let next_c = add_u16_len(cursor, val_end);
            guard http::add_param(params, p.param_name, 0, 0, cursor, next_c) else {
                return RouteMatchResult.NotFound;
            }
            return match_packed_node(p_node, eff_path, next_c, true, params);
        },
        _ => RouteMatchResult.NotFound,
    };
}

inline fn advance_packed_node_prefix(
    node:     const PackedRoute..&,
    eff_path: const u8[:],
    cursor:   u16&,
    skip_pfx: bool,
) -> bool {
    guard !skip_pfx else { return true; }
    let pfx = packed_node_prefix(node);
    guard pfx.len > 0 else { return true; }
    let rem_before = eff_path[cursor..];
    guard rem_before.len >= pfx.len && rem_before[..pfx.len] == pfx else {
        return false;
    }
    cursor = add_u16_len(cursor, pfx.len);
    return true;
}

recursive fn eval_packed_branch(
    at_end:          bool,
    has_handler:     bool,
    meta:            const PackedRouteMeta&,
    first_child:     const PackedRoute..?,
    param_child:     const PackedRoute..?,
    catch_all_child: const PackedRoute..?,
    eff_path:        const u8[:],
    cursor:          u16,
    params:          http::ZeroAllocParams&,
) -> RouteMatchResult {
    if at_end {
        if has_handler {
            return make_packed_found(meta);
        }
        return RouteMatchResult.NotFound;
    }
    return match_packed_children(first_child, param_child, catch_all_child, eff_path, cursor, params);
}

recursive fn match_packed_node(
    node:     const PackedRoute..&,
    eff_path: const u8[:],
    cursor:   u16,
    skip_pfx: bool,
    params:   http::ZeroAllocParams&,
) -> RouteMatchResult {
    var cur_cursor = cursor;
    guard advance_packed_node_prefix(node, eff_path, cur_cursor, skip_pfx) else {
        return RouteMatchResult.NotFound;
    }
    let at_end = eff_path[cur_cursor..].len == 0;
    return match node {
        Leaf &l => if at_end && l.meta.handler_id >= 0 {
            make_packed_found(l.meta)
        } else {
            RouteMatchResult.NotFound
        },
        Branch &b => eval_packed_branch(
            at_end,
            b.has_handler,
            b.meta,
            b.first_child,
            b.param_child,
            b.catch_all_child,
            eff_path,
            cur_cursor,
            params,
        ),
        Param &p => eval_packed_branch(
            at_end,
            p.has_handler,
            p.meta,
            p.first_child,
            p.param_child,
            p.catch_all_child,
            eff_path,
            cur_cursor,
            params,
        ),
        CatchAll &_ => RouteMatchResult.NotFound,
        Sib &_ => RouteMatchResult.NotFound,
    };
}

// Matches `path` against a compiled `PackedRoute..[>..]` arena without allocating or copying canonical paths.
//
// Example:
//   path = "/users/42" -> returns Found with param "id"="42"
fn match_packed_route(
    arena:  const PackedRoute..[>..]&,
    path:   const u8[:],
    params: http::ZeroAllocParams&,
) -> RouteMatchResult {
    var canon_scratch: u8[..2048] = [];
    let eff_path, ok_path = server_internal::resolve_effective_route_path_borrow(path, canon_scratch);
    guard ok_path && eff_path.len > 0 else { return RouteMatchResult.NotFound; }
    let root = find_packed_route_root(arena);
    guard root else { return RouteMatchResult.NotFound; }
    params.clear();
    let res = match_packed_node(root, eff_path, 0, false, params);
    if canon_scratch.len > 0 && canon_scratch[..] != path {
        params.clear();
    }
    return res;
}
