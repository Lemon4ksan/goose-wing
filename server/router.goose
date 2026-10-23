// Zero-Allocation Compressed Radix Trie Router with Parameter Suffix Splitting.
// Clean-Room Implementation conforming to matchit, httprouter, and Axum routing rules.
//
// Core Types:
//   NodeType        - Node classification enum (Root, Static, Param { suffix: bool }, CatchAll).
//   ParamSpan       - Byte offset index pair (u16) into URI buffer without string copying.
//   ZeroAllocParams - Fixed-capacity stack buffer for up to 8 matched route parameters.
//   RadixRouter     - Per-HTTP-method compressed prefix trie with automatic 405 Method Not Allowed.
//
// Critical Architectural Invariants:
//   - Zero heap allocations during route lookup (matchit / http.zig pattern).
//   - Monotonic Param suffix preservation (defending against matchit Issue #83 / commit f607f73).
//   - Static routes (/foo) take precedence over dynamic (/{id}) and greedy (/{*rest}).
//   - CatchAll (/{*rest}) captures path remainder without leading slash, rejecting empty matches.
namespace wing;

import std;

enum NodeType {
    Root,
    Static,
    Param { suffix: bool },
    CatchAll,
}

struct ParamSpan {
    key_start: u16 = 0,
    key_end: u16 = 0,
    val_start: u16 = 0,
    val_end: u16 = 0,
}

struct ZeroAllocParams {
    spans: ParamSpan[8] = [ParamSpan { .. }; 8],
    len: i64 = 0,
}

fn clear(params: ZeroAllocParams&) {
    params.len = 0;
}

fn add_param(params: ZeroAllocParams&, k_start: u16, k_end: u16, v_start: u16, v_end: u16) -> bool {
    guard params.len < params.spans.len else { return false; }
    params.spans[params.len] = ParamSpan {
        key_start: k_start,
        key_end: k_end,
        val_start: v_start,
        val_end: v_end,
    };
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
    let span = params.spans[idx];
    guard span.key_end <= route_template.len && span.key_start <= span.key_end else { return ""; }
    return route_template[(span.key_start as i64)..(span.key_end as i64)];
}

fn param_by_name(
    params: const ZeroAllocParams&,
    name: const u8[:],
    route_template: const u8[:],
    req_path: const u8[:],
) -> const u8[:], bool {
    for idx in params.len {
        let k = param_key(params, idx, route_template);
        if k == name {
            return param_val(params, idx, req_path), true;
        }
    }
    return "", false;
}

// ---- radix trie node & arena storage ---------------------------------------

struct RadixNode {
    prefix: u8[..64] = [],
    indices: u8[..16] = [],
    children: i32[..16] = [],
    priority: u32 = 0,
    wild_child: bool = false,
    param_child: i32 = -1,
    catch_all_child: i32 = -1,
    node_type: NodeType = NodeType.Static,
    handler_id: i32 = -1,
    entries_mask: u32 = 0,
    param_name: u8[..32] = [],
    static_suffix: u8[..32] = [],
}

struct RadixTree {
    nodes: RadixNode[..128] = [],
    root_idx: i32 = -1,
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

// Traverses or inserts a static path segment into the trie, updating cur_idx to the endpoint node.
fn traverse_or_insert_static(tree: RadixTree&, cur_idx: i32&, seg: const u8[:]) -> bool {
    var rem = seg;
    while rem.len > 0 {
        let cur_prefix = tree.nodes[cur_idx as i64].prefix[..];

        if cur_prefix.len == 0 && tree.nodes[cur_idx as i64].node_type == NodeType.Root {
            if tree.nodes[cur_idx as i64].indices.len == 0 &&
               tree.nodes[cur_idx as i64].children.len == 0 &&
               tree.nodes[cur_idx as i64].param_child < 0 &&
               tree.nodes[cur_idx as i64].catch_all_child < 0 &&
               tree.nodes[cur_idx as i64].handler_id < 0 {
                tree.nodes[cur_idx as i64].prefix.append(rem);
                return true;
            }
        }

        var common_len = 0;
        let max_c = if rem.len < cur_prefix.len { rem.len } else { cur_prefix.len };
        while common_len < max_c && rem[common_len] == cur_prefix[common_len] {
            common_len += 1;
        }

        if common_len < cur_prefix.len {
            let split_child_idx = alloc_node(tree, tree.nodes[cur_idx as i64].node_type);
            guard split_child_idx >= 0 else { return false; }

            let c_idx = cur_idx as i64;
            let s_idx = split_child_idx as i64;

            tree.nodes[s_idx].prefix.append(tree.nodes[c_idx].prefix[common_len..]);
            tree.nodes[s_idx].indices.append(tree.nodes[c_idx].indices[..]);
            for c in tree.nodes[c_idx].children { tree.nodes[s_idx].children.push(c); }
            tree.nodes[s_idx].param_child = tree.nodes[c_idx].param_child;
            tree.nodes[s_idx].catch_all_child = tree.nodes[c_idx].catch_all_child;
            tree.nodes[s_idx].handler_id = tree.nodes[c_idx].handler_id;
            tree.nodes[s_idx].entries_mask = tree.nodes[c_idx].entries_mask;
            tree.nodes[s_idx].priority = tree.nodes[c_idx].priority - 1;

            let first_split_byte = tree.nodes[s_idx].prefix[0];
            tree.nodes[c_idx].prefix.clear();
            tree.nodes[c_idx].prefix.append(rem[..common_len]);
            tree.nodes[c_idx].indices.clear();
            tree.nodes[c_idx].indices.push(first_split_byte);
            tree.nodes[c_idx].children.clear();
            tree.nodes[c_idx].children.push(split_child_idx);
            tree.nodes[c_idx].param_child = -1;
            tree.nodes[c_idx].catch_all_child = -1;
            tree.nodes[c_idx].handler_id = -1;
        }

        if common_len < rem.len {
            let tail = rem[common_len..];
            let first_byte = tail[0];

            var child_idx: i32 = -1;
            for i in tree.nodes[cur_idx as i64].indices.len {
                if tree.nodes[cur_idx as i64].indices[i] == first_byte {
                    child_idx = tree.nodes[cur_idx as i64].children[i];
                    break;
                }
            }

            if child_idx >= 0 {
                cur_idx = child_idx;
                rem = tail;
            } else {
                let new_idx = alloc_node(tree, NodeType.Static);
                guard new_idx >= 0 else { return false; }
                tree.nodes[new_idx as i64].prefix.append(tail);

                tree.nodes[cur_idx as i64].indices.push(first_byte);
                tree.nodes[cur_idx as i64].children.push(new_idx);
                cur_idx = new_idx;
                return true;
            }
        } else {
            return true;
        }
    }
    return true;
}

// Inserts a route into the Radix tree
fn insert_route(
    tree: RadixTree&,
    path: const u8[:],
    handler_id: i32,
    entries_mask: u32 = 0,
) -> bool {
    guard path.len > 0 && path[0] == '/' else { return false; }
    guard tree.root_idx >= 0 else { return false; }

    var cur_idx = tree.root_idx;
    var rem = path;

    while rem.len > 0 {
        tree.nodes[cur_idx as i64].priority += 1;

        // Check for parameter '{' or catchall '{*'
        var param_start = -1;
        var param_end = -1;
        var is_catchall = false;

        for i in rem.len {
            if rem[i] == '{' {
                param_start = i;
                if i + 1 < rem.len && rem[i + 1] == '*' {
                    is_catchall = true;
                }
            } else if rem[i] == '}' && param_start >= 0 {
                param_end = i;
                break;
            }
        }

        if param_start < 0 {
            // Pure static segment
            guard traverse_or_insert_static(tree, cur_idx, rem) else { return false; }
            tree.nodes[cur_idx as i64].handler_id = handler_id;
            tree.nodes[cur_idx as i64].entries_mask = entries_mask;
            return true;
        } else {
            // Dynamic parameter segment
            if param_start > 0 {
                let pre_param = rem[..param_start];
                guard traverse_or_insert_static(tree, cur_idx, pre_param) else { return false; }
                rem = rem[param_start..];
                param_end -= param_start;
                param_start = 0;
            }

            let name = if is_catchall { rem[2..param_end] } else { rem[1..param_end] };
            let suffix_after = rem[param_end + 1..];

            if is_catchall {
                let ca_idx = alloc_node(tree, NodeType.CatchAll);
                guard ca_idx >= 0 else { return false; }
                tree.nodes[ca_idx as i64].param_name.append(name);
                tree.nodes[ca_idx as i64].handler_id = handler_id;
                tree.nodes[ca_idx as i64].entries_mask = entries_mask;

                tree.nodes[cur_idx as i64].catch_all_child = ca_idx;
                tree.nodes[cur_idx as i64].wild_child = true;
                return true;
            } else {
                // Param node with suffix preservation
                let has_suffix = (suffix_after.len > 0 && suffix_after != "/");
                var param_node_idx = tree.nodes[cur_idx as i64].param_child;

                if param_node_idx < 0 {
                    param_node_idx = alloc_node(tree, NodeType.Param { suffix: has_suffix });
                    guard param_node_idx >= 0 else { return false; }
                    tree.nodes[param_node_idx as i64].param_name.append(name);
                    tree.nodes[cur_idx as i64].param_child = param_node_idx;
                    tree.nodes[cur_idx as i64].wild_child = true;
                } else {
                    // Update existing node with monotonic suffix preservation!
                    let updated_type = update_param_suffix_flag(tree.nodes[param_node_idx as i64].node_type, suffix_after);
                    tree.nodes[param_node_idx as i64].node_type = updated_type;
                }

                if suffix_after.len > 0 {
                    cur_idx = param_node_idx;
                    rem = suffix_after;
                } else {
                    tree.nodes[param_node_idx as i64].handler_id = handler_id;
                    tree.nodes[param_node_idx as i64].entries_mask = entries_mask;
                    return true;
                }
            }
        }
    }
    return true;
}

// ---- zero-allocation router lookup -----------------------------------------

enum RouteMatchResult {
    Found { handler_id: i32, entries_mask: u32 },
    NotFound,
    MethodNotAllowed { allow_header: u8[..64] },
}

// Matches a path against a single RadixTree without heap allocations
fn match_path(
    tree: const RadixTree&,
    path: const u8[:],
    params: ZeroAllocParams&,
) -> RouteMatchResult {
    guard tree.root_idx >= 0 && path.len > 0 else { return RouteMatchResult.NotFound; }
    params.clear();

    var cur_idx = tree.root_idx;
    var rem = path;
    var cursor: u16 = 0;

    while cur_idx >= 0 {
        let prefix = tree.nodes[cur_idx as i64].prefix[..];

        if prefix.len > 0 {
            guard rem.len >= prefix.len && rem[..prefix.len] == prefix else {
                return RouteMatchResult.NotFound;
            }
            cursor += prefix.len as u16;
            rem = rem[prefix.len..];
        }

        if rem.len == 0 {
            let hid = tree.nodes[cur_idx as i64].handler_id;
            if hid >= 0 {
                return RouteMatchResult.Found {
                    handler_id: hid,
                    entries_mask: tree.nodes[cur_idx as i64].entries_mask,
                };
            }
            return RouteMatchResult.NotFound;
        }

        // Try static children first (O(1) index lookup)
        let first_byte = rem[0];
        var next_child: i32 = -1;
        for i in tree.nodes[cur_idx as i64].indices.len {
            if tree.nodes[cur_idx as i64].indices[i] == first_byte {
                next_child = tree.nodes[cur_idx as i64].children[i];
                break;
            }
        }

        if next_child >= 0 {
            cur_idx = next_child;
            continue;
        }

        // Fall back to Param child
        if tree.nodes[cur_idx as i64].param_child >= 0 {
            let p_idx = tree.nodes[cur_idx as i64].param_child;
            let is_suffix = match tree.nodes[p_idx as i64].node_type {
                Param p => p.suffix,
                _ => false,
            };

            var val_end = -1;
            if is_suffix {
                // Find next '.' or '/'
                for i in rem.len {
                    if rem[i] == '.' || rem[i] == '/' { val_end = i; break; }
                }
            } else {
                // Find next '/'
                for i in rem.len {
                    if rem[i] == '/' { val_end = i; break; }
                }
            }

            if val_end < 0 { val_end = rem.len; }
            guard val_end > 0 else { return RouteMatchResult.NotFound; }

            add_param(params, 0, 0, cursor, cursor + (val_end as u16));
            cursor += val_end as u16;
            rem = rem[val_end..];
            cur_idx = p_idx;
            continue;
        }

        // Fall back to CatchAll child
        if tree.nodes[cur_idx as i64].catch_all_child >= 0 {
            let ca_idx = tree.nodes[cur_idx as i64].catch_all_child;
            // CatchAll captures remainder without leading slash
            let catch_val = if rem[0] == '/' { rem[1..] } else { rem };
            guard catch_val.len > 0 else { return RouteMatchResult.NotFound; }

            let start_off = if rem[0] == '/' { cursor + 1 } else { cursor };
            add_param(params, 0, 0, start_off, start_off + (catch_val.len as u16));

            let hid = tree.nodes[ca_idx as i64].handler_id;
            if hid >= 0 {
                return RouteMatchResult.Found {
                    handler_id: hid,
                    entries_mask: tree.nodes[ca_idx as i64].entries_mask,
                };
            }
            return RouteMatchResult.NotFound;
        }

        return RouteMatchResult.NotFound;
    }

    return RouteMatchResult.NotFound;
}

// ---- multi-method radix router ---------------------------------------------

struct MethodTree {
    method: u8[..8] = "GET",
    tree: RadixTree = RadixTree { .. },
}

struct RadixRouter {
    trees: MethodTree[..8] = [],
}

fn new_radix_router() -> RadixRouter {
    var r = RadixRouter { .. };
    let methods: const u8[:][7] = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
    for m in methods {
        var mt = MethodTree { method: [], tree: new_radix_tree() };
        mt.method.append(m);
        r.trees.push(mt);
    }
    return r;
}

fn add_route(
    router: RadixRouter&,
    method: const u8[:],
    path: const u8[:],
    handler_id: i32,
    entries_mask: u32 = 0,
) -> bool {
    for idx in router.trees.len {
        if router.trees[idx].method[..] == method {
            return insert_route(router.trees[idx].tree, path, handler_id, entries_mask);
        }
    }
    return false;
}

// Resolves a route for (method, path); returns Found, NotFound, or MethodNotAllowed with Allow header.
fn match_route(
    router: const RadixRouter&,
    method: const u8[:],
    path: const u8[:],
    params: ZeroAllocParams&,
) -> RouteMatchResult {
    var target_tree_idx: i32 = -1;
    for idx in router.trees.len {
        if router.trees[idx].method[..] == method {
            target_tree_idx = idx as i32;
            break;
        }
    }

    if target_tree_idx >= 0 {
        let res = match_path(router.trees[target_tree_idx as i64].tree, path, params);
        match res {
            Found _ => { return res; },
            _ => {},
        };
    }

    // Check if matched by another method (405 Method Not Allowed)
    var allow_buf: u8[..64] = [];
    var matched_other = false;
    var dummy_params = ZeroAllocParams { .. };

    for idx in router.trees.len {
        if (idx as i32) != target_tree_idx {
            let res_other = match_path(router.trees[idx].tree, path, dummy_params);
            match res_other {
                Found _ => {
                    if matched_other { allow_buf.append(", "); }
                    allow_buf.append(router.trees[idx].method[..]);
                    matched_other = true;
                },
                _ => {},
            };
        }
    }

    if matched_other {
        return RouteMatchResult.MethodNotAllowed { allow_header: allow_buf };
    }

    return RouteMatchResult.NotFound;
}
