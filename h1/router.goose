// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Compact (~11 KB) zero-copy HTTP/1.1 router supporting static, parameterized, and wildcard routes.
// Insertion-order independent precedence (static > param > wildcard) with automatic HEAD->GET fallback.
namespace h1;

import std;
import core.bytes.case;
import core.bytes.split;
import core.math.arithmetic;
import .wire;

const MAX_H1_ROUTES:       i64 = 64;
const MAX_H1_ROUTE_PARAMS: i64 = 8;

const ROUTE_PRIO_WILDCARD: u8 = 1;
const ROUTE_PRIO_PARAM:    u8 = 2;
const ROUTE_PRIO_STATIC:   u8 = 3;

// Zero-copy parameter span referencing offsets inside the canonicalized request path.
struct RouteParamSpan {
    name:      u8[..24] = [],
    val_start: u16      = 0,
    val_end:   u16      = 0,
}

struct RouteParams {
    spans: RouteParamSpan[8] = [RouteParamSpan { .. }; 8],
    len:   i64               = 0,
}

// Looks up a captured route parameter by `name`, returning a zero-copy slice of `path`.
fn param_by_name(params: const RouteParams&, name: const u8[:], path: const u8[:]) -> const u8[:], bool {
    let limit = min(params.len, MAX_H1_ROUTE_PARAMS);
    for i in limit {
        if params.spans[i].name[..] == name {
            let s = params.spans[i].val_start as i64;
            let e = params.spans[i].val_end as i64;
            guard s <= e && e <= path.len else { return "", false; }
            return path[s..e], true;
        }
    }
    return "", false;
}

inline fn push_route_param(params: RouteParams&, name: const u8[:], val_start: i64, val_end: i64) -> bool {
    guard params.len >= 0 && params.len < MAX_H1_ROUTE_PARAMS else { return false; }
    guard val_start >= 0 && val_end >= val_start && val_end <= 65535 else { return false; }
    let idx = params.len;
    guard buf_set(params.spans[idx].name, name) else { return false; }
    params.spans[idx].val_start = val_start as u16;
    params.spans[idx].val_end = val_end as u16;
    params.len = core::add_sat_i64(idx, 1);
    return true;
}

struct RouteEntry {
    method:     u8[..8]   = [],
    pattern:    u8[..128] = [],
    handler_id: i32       = -1,
    stage_mask: u64       = 0,
    priority:   u8        = ROUTE_PRIO_STATIC,
}

// ~11 KB fixed-capacity HTTP/1.1 routing table (vs ~410 KB for server::RadixRouter).
struct Router {
    routes: RouteEntry[..64] = [],
}

enum RouteMatch {
    Found {
        handler_id: i32,
        stage_mask: u64,
    },
    NotFound,
    MethodNotAllowed {
        allow: u8[..64],
    },
}

// Applies one normalized path segment (skip `.`, pop on `..`, or append `/seg`) into `out`.
inline fn apply_canonical_segment<B>(seg: const u8[:], out: B&) -> bool {
    if seg == "." || core::eq_ascii_fold(seg, "%2e") {
        return true;
    }
    if seg == ".." || core::eq_ascii_fold(seg, "%2e%2e") {
        pop_last_path_segment(out);
        return true;
    }
    return buf_push(out, '/') && buf_append(out, seg);
}

// Resolves `.` and `..` dot-segments, collapses duplicate slashes, and strips query/fragment (RFC 3986 Section 5.2.4).
// Always produces a path starting with `/`. Rolls back `out` on capacity overflow.
//
// Example:
//   raw_path = "/api/v1/../users//42?active=1", out = []
//   returns: true, out = "/api/users/42"
fn canonicalize_path<B>(raw_path: const u8[:], out: B&) -> bool {
    var committed = false;
    defer if !committed { out.clear(); };
    out.clear();
    guard raw_path.len > 0 else {
        guard buf_push(out, '/') else { return false; }
        committed = true;
        return true;
    }

    let no_frag, _, _ = core::split_once_byte(raw_path, '#');
    let path_only, _, _ = core::split_once_byte(no_frag, '?');
    var idx: i64 = 0;
    while idx < path_only.len {
        let seg_start, seg_end = next_path_segment_bounds(path_only, idx);
        if seg_end > seg_start {
            guard apply_canonical_segment(path_only[seg_start..seg_end], out) else { return false; }
        }
    }
    if out.len == 0 {
        guard buf_push(out, '/') else { return false; }
    }
    committed = true;
    return true;
}

inline fn pop_last_path_segment<B>(out: B&) {
    guard out.len > 0 else { return; }
    var pos = core::sub_sat_i64(out.len, 1);
    while pos > 0 && out[pos] != '/' {
        pos = core::sub_sat_i64(pos, 1);
    }
    out.resize(pos);
}

// Classifies a route pattern segment: returns `(param_name, is_param, is_wildcard)`.
inline fn inspect_pattern_segment(seg: const u8[:]) -> const u8[:], bool, bool {
    guard seg.len >= 2 else { return "", false, false; }
    let last = core::sub_sat_i64(seg.len, 1);
    if seg[0] == ':' {
        return seg[1..], true, false;
    }
    if seg[0] == '*' {
        return seg[1..], false, true;
    }
    if seg[0] == '{' && seg[last] == '}' && seg.len >= 3 {
        if seg[1] == '*' && seg.len >= 4 {
            return seg[2..last], false, true;
        }
        return seg[1..last], true, false;
    }
    return "", false, false;
}

// Computes precedence tier (`ROUTE_PRIO_STATIC`, `ROUTE_PRIO_PARAM`, or `ROUTE_PRIO_WILDCARD`) for `pattern`.
fn classify_route_priority(pattern: const u8[:]) -> u8 {
    var prio: u8 = ROUTE_PRIO_STATIC;
    var rem = if pattern.len > 0 && pattern[0] == '/' { pattern[1..] } else { pattern };
    while rem.len > 0 {
        let seg, tail, has_slash = core::split_once_byte(rem, '/');
        let _, is_param, is_wild = inspect_pattern_segment(seg);
        if is_wild { return ROUTE_PRIO_WILDCARD; }
        if is_param { prio = ROUTE_PRIO_PARAM; }
        if !has_slash { break; }
        rem = tail;
    }
    return prio;
}

// Registers a route pattern (`method`, `pattern`, `handler_id`, optional per-route `stage_mask`).
fn add_route(
    router:     Router&,
    method:     const u8[:],
    pattern:    const u8[:],
    handler_id: i32,
    stage_mask: u64 = 0,
) -> bool {
    guard is_valid_token(method) && method.len <= 8 && pattern.len > 0 && pattern[0] == '/' else {
        return false;
    }
    guard router.routes.len < MAX_H1_ROUTES else { return false; }
    var canon: u8[..128] = [];
    guard canonicalize_path(pattern, canon) else { return false; }
    var entry = RouteEntry {
        handler_id: handler_id,
        stage_mask: stage_mask,
        priority:   classify_route_priority(canon[..]),
        ..
    };
    guard buf_set(entry.method, method) && buf_set(entry.pattern, canon[..]) else { return false; }
    router.routes.push(entry);
    return true;
}

// Advances one slash-delimited segment starting at `pos` inside `s`, returning `(seg_start, seg_end)`.
//
// Example:
//   s = "/users/42", pos = 0
//   returns: 1, 6 (segment "users"), pos = 6
inline fn next_path_segment_bounds(s: const u8[:], pos: i64&) -> i64, i64 {
    if pos < s.len && s[pos] == '/' {
        pos = core::add_sat_i64(pos, 1);
    }
    let start = pos;
    while pos < s.len && s[pos] != '/' {
        pos = core::add_sat_i64(pos, 1);
    }
    return start, pos;
}

inline fn match_wildcard_tail(path: const u8[:], r_cur: i64, pname: const u8[:], params: RouteParams&) -> bool {
    let tail_start = if r_cur < path.len && path[r_cur] == '/' {
        core::add_sat_i64(r_cur, 1)
    } else {
        r_cur
    };
    return push_route_param(params, pname, tail_start, path.len);
}

// Matches a canonicalized `path` against `pattern`, recording zero-copy param offsets into `params`.
fn match_pattern_segments(pattern: const u8[:], path: const u8[:], params: RouteParams&) -> bool {
    params.len = 0;
    if pattern == "/" {
        return path == "/";
    }
    var p_cur: i64 = 0;
    var r_cur: i64 = 0;
    while p_cur < pattern.len {
        let ps, pe = next_path_segment_bounds(pattern, p_cur);
        let p_seg = pattern[ps..pe];
        let pname, is_param, is_wild = inspect_pattern_segment(p_seg);
        if is_wild {
            return match_wildcard_tail(path, r_cur, pname, params);
        }
        guard r_cur < path.len else { return false; }
        let rs, re = next_path_segment_bounds(path, r_cur);
        if is_param {
            guard re > rs && push_route_param(params, pname, rs, re) else { return false; }
            continue;
        }
        guard path[rs..re] == p_seg else { return false; }
    }
    return r_cur >= path.len;
}

inline fn append_allow_method(allow: u8[..64]&, method: const u8[:]) {
    guard !header_value_has_token(allow[..], method) else { return; }
    if allow.len > 0 {
        let _ = buf_append(allow, ", ");
    }
    let _ = buf_append(allow, method);
}

// Ranks route candidates so exact methods beat HEAD->GET fallback and static > param > wildcard.
inline fn is_better_route_candidate(
    best_idx:  i64,
    best_prio: u8,
    best_head: bool,
    prio:      u8,
    exact_m:   bool,
) -> bool {
    if best_idx < 0 { return true; }
    if exact_m && best_head { return true; }
    return exact_m == !best_head && prio > best_prio;
}

// Matches `method` and `raw_path` against `router` with insertion-order independent precedence.
// Writes the canonicalized path into `out_canon` and zero-copy parameter spans into `params`.
fn match_route<B>(
    router:    const Router&,
    method:    const u8[:],
    raw_path:  const u8[:],
    params:    RouteParams&,
    out_canon: B&,
) -> RouteMatch {
    params.len = 0;
    guard canonicalize_path(raw_path, out_canon) else { return RouteMatch.NotFound; }
    let canon = out_canon[..];
    var best_idx:  i64      = -1;
    var best_prio: u8       = 0;
    var best_head: bool     = false;
    var allow:     u8[..64] = [];
    var tmp = RouteParams { .. };

    for i in router.routes.len {
        if !match_pattern_segments(router.routes[i].pattern[..], canon, tmp) { continue; }
        let r_meth = router.routes[i].method[..];
        append_allow_method(allow, r_meth);
        let exact_m = r_meth == method;
        let head_fb = !exact_m && method == "HEAD" && r_meth == "GET";
        if !exact_m && !head_fb { continue; }
        let prio = router.routes[i].priority;
        if is_better_route_candidate(best_idx, best_prio, best_head, prio, exact_m) {
            best_idx = i;
            best_prio = prio;
            best_head = head_fb;
            params = tmp;
        }
    }

    if best_idx >= 0 {
        return RouteMatch.Found {
            handler_id: router.routes[best_idx].handler_id,
            stage_mask: router.routes[best_idx].stage_mask,
        };
    }
    if allow.len > 0 {
        return RouteMatch.MethodNotAllowed { allow: allow };
    }
    return RouteMatch.NotFound;
}
