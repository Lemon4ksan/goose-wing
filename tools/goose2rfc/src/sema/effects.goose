// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Call-graph entry-context synthesizer and 4-state parameter rollback analyzer.

import std;
import db from "../model";
import loader from "../config";

struct MutScanState {
    has_defer_restore:  bool = false,
    mutated_before_err: bool = false,
    has_err_after_mut:  bool = false,
    all_err_restored:   bool = true,
    defer_text:         Span,
    restore_text:       Span,
    effect_span:        Span,
}

fn strip_semi_eff(s: const u8[:]) -> const u8[:] {
    let t = trim_ascii_ws(s);
    guard slice_ends_with(t, ";") && t.len >= 1 else { return t; }
    return trim_ascii_ws(t[..dec_i64(t.len)]);
}

fn find_body_block_eff(db: const CompilerDb&, decl_node: i32) -> i32 {
    guard decl_node >= 0 && decl_node < db.nodes.len else { return -1; }
    var cur = db.nodes[decl_node].first;
    for step in db.nodes.len {
        guard cur >= 0 && cur < db.nodes.len else { return decl_node; }
        if db.nodes[cur].kind == AstKind.Block {
            return cur;
        }
        cur = db.nodes[cur].next;
    }
    return decl_node;
}

fn is_container_node_eff(k: AstKind) -> bool {
    return k == AstKind.Block
        || k == AstKind.IfStmt
        || k == AstKind.MatchStmt
        || k == AstKind.MatchArm
        || k == AstKind.ForStmt
        || k == AstKind.WhileStmt;
}

fn next_stmt_eff(db: const CompilerDb&, root: i32, cur: i32, descend: bool) -> i32 {
    guard cur >= 0 && cur < db.nodes.len else { return -1; }
    let first = db.nodes[cur].first;
    if descend && first >= 0 {
        return first;
    }
    var p = cur;
    for climb in db.nodes.len {
        if p == root || p < 0 || p >= db.nodes.len {
            return -1;
        }
        let nxt = db.nodes[p].next;
        if nxt >= 0 {
            return nxt;
        }
        p = db.nodes[p].parent;
    }
    return -1;
}

fn span_union_lines(start_sp: Span, end_sp: Span) -> Span {
    guard start_sp.file_id == end_sp.file_id && end_sp.at >= start_sp.at else {
        return end_sp;
    }
    let total_len = add_i32(sub_i32(end_sp.at, start_sp.at), end_sp.len);
    return Span {
        file_id: start_sp.file_id,
        at:      start_sp.at,
        len:     total_len,
        line:    start_sp.line,
        col:     start_sp.col,
    };
}

fn last_param_name_and_type(db: const CompilerDb&, spec: SpecFunction) -> const u8[:], const u8[:] {
    guard spec.param_count > 0 else { return "param", "parameter"; }
    for step in spec.param_count {
        let rev_i = sub_i32(dec_i32(spec.param_count), step);
        let idx = add_i32(spec.param_start, rev_i);
        if idx >= 0 && idx < db.symbols.len {
            let sym = db.symbols[idx];
            let pname = trim_ascii_ws(text_of(db, sym.name_span));
            let ptype = trim_ascii_ws(text_of(db, sym.type_span));
            if pname.len > 0 && ptype != "bool&" && ptype != "bool" {
                return pname, if ptype.len > 0 { ptype } else { "parameter" };
            }
        }
    }
    let last_idx = add_i32(spec.param_start, dec_i32(spec.param_count));
    guard last_idx >= 0 && last_idx < db.symbols.len else { return "param", "parameter"; }
    let sym = db.symbols[last_idx];
    let pname = trim_ascii_ws(text_of(db, sym.name_span));
    let ptype = trim_ascii_ws(text_of(db, sym.type_span));
    return if pname.len > 0 { pname } else { "param" }, if ptype.len > 0 { ptype } else { "parameter" };
}

fn param_name_and_type_at(db: const CompilerDb&, spec: SpecFunction, arg_idx: i32) -> const u8[:], const u8[:] {
    if arg_idx >= 0 && arg_idx < spec.param_count {
        let idx = add_i32(spec.param_start, arg_idx);
        if idx >= 0 && idx < db.symbols.len {
            let sym = db.symbols[idx];
            let pname = trim_ascii_ws(text_of(db, sym.name_span));
            let ptype = trim_ascii_ws(text_of(db, sym.type_span));
            if pname.len > 0 {
                return pname, if ptype.len > 0 { ptype } else { "parameter" };
            }
        }
    }
    return last_param_name_and_type(db, spec);
}

fn find_arg_index_in_call_eff(ctext: const u8[:], call_pat: const u8[:], recv_name: const u8[:]) -> i32 {
    let clean_recv = trim_ascii_ws(recv_name);
    guard clean_recv.len > 0 else { return -1; }
    let _, after_call, ok_c = split_at_str(ctext, call_pat);
    guard ok_c else { return -1; }
    let args_str, _, ok_rp = split_at_str(after_call, ")");
    guard ok_rp else { return -1; }
    var rest = trim_ascii_ws(args_str);
    for idx in 16 {
        guard rest.len > 0 else { return -1; }
        let head, tail, has_comma = split_at_str(rest, ",");
        let arg = trim_ascii_ws(if has_comma { head } else { rest });
        if arg == clean_recv {
            return idx as i32;
        }
        if !has_comma {
            return -1;
        }
        rest = trim_ascii_ws(tail);
    }
    return -1;
}

fn find_field_set_in_caller(
    db:         const CompilerDb&,
    caller_blk: i32,
    ctext:      const u8[:],
    call_pat:   const u8[:],
    call_at:    i32,
) -> i32, const u8[:], const u8[:], bool {
    guard caller_blk >= 0 && caller_blk < db.nodes.len else { return -1, "", "", false; }
    var cur = db.nodes[caller_blk].first;
    var last_assign_arg: i32 = -1;
    var last_node:       i32 = -1;
    var found_set = false;
    var had_intervening_branch = false;

    for step in db.nodes.len {
        guard cur >= 0 && cur < db.nodes.len else { break; }
        let node = db.nodes[cur];
        if call_at > 0 && node.span.at >= call_at {
            break;
        }
        let k = node.kind;
        if k == AstKind.IfStmt || k == AstKind.GuardStmt || k == AstKind.ReturnStmt || k == AstKind.ForStmt || k == AstKind.WhileStmt {
            had_intervening_branch = true;
            found_set = false;
        }
        if node.kind == AstKind.AssignStmt {
            let lhs = trim_ascii_ws(text_of(db, node.span));
            let rhs = strip_semi_eff(text_of(db, node.aux_span));
            let recv, field, has_dot = split_at_str(lhs, ".");
            if has_dot && field.len > 0 && rhs.len > 0 && slice_find(rhs, call_pat) < 0 {
                let arg_idx = find_arg_index_in_call_eff(ctext, call_pat, recv);
                if arg_idx >= 0 {
                    last_assign_arg = arg_idx;
                    last_node = cur;
                    found_set = true;
                    had_intervening_branch = false;
                }
            }
        }
        cur = db.nodes[cur].next;
    }
    if found_set && !had_intervening_branch && last_assign_arg >= 0 && last_node >= 0 {
        let node = db.nodes[last_node];
        let lhs = trim_ascii_ws(text_of(db, node.span));
        let rhs = strip_semi_eff(text_of(db, node.aux_span));
        let _, field, _ = split_at_str(lhs, ".");
        return last_assign_arg, trim_ascii_ws(field), rhs, true;
    }
    return -1, "", "", false;
}

fn find_match_prefix_for_call(
    db:          const CompilerDb&,
    caller_blk:  i32,
    callee_name: const u8[:],
) -> const u8[:], bool {
    guard caller_blk >= 0 && caller_blk < db.nodes.len else { return "", false; }
    var cur = db.nodes[caller_blk].first;
    for step in db.nodes.len {
        guard cur >= 0 && cur < db.nodes.len else { return "", false; }
        let node = db.nodes[cur];
        if node.kind == AstKind.MatchArm {
            let arm_body = text_of(db, node.aux_span);
            if slice_find(arm_body, callee_name) >= 0 {
                return trim_ascii_ws(text_of(db, node.span)), true;
            }
        }
        cur = next_stmt_eff(db, caller_blk, cur, is_container_node_eff(node.kind));
    }
    return "", false;
}

fn format_caller_sets_ctx(
    db:          CompilerDb&,
    caller_name: const u8[:],
    callee_name: const u8[:],
    param_name:  const u8[:],
    param_type:  const u8[:],
    field_name:  const u8[:],
    rhs_expr:    const u8[:],
) -> Span {
    var out: u8[>..] = [];
    out.append("Caller `");
    out.append(caller_name);
    out.append("` sets `");
    out.append(param_name);
    out.push('.');
    out.append(field_name);
    out.append(" = (");
    out.append(rhs_expr);
    out.append(")` before it calls `");
    out.append(callee_name);
    out.append("`. Direct callers of `");
    out.append(callee_name);
    out.append("` can pass any `");
    out.append(param_type);
    out.append("` value.");
    return put_text(db, out[..]);
}

fn try_caller_entry_ctx(
    db:          CompilerDb&,
    spec:        SpecFunction,
    sym:         Symbol,
    callee_name: const u8[:],
    call_pat:    const u8[:],
) -> Span, bool {
    let EmptySpan = Span { .. };
    let cblk = find_body_block_eff(db, sym.decl_node);
    let ctext = text_of(db, db.nodes[cblk].span);
    guard slice_find(ctext, call_pat) >= 0 else { return EmptySpan, false; }

    let caller_name = text_of(db, sym.name_span);
    let call_pos = slice_find(ctext, call_pat);
    let call_at = if call_pos >= 0 { db.nodes[cblk].span.at + (call_pos as i32) } else { 0 };
    let arg_idx, field, rhs, ok_set = find_field_set_in_caller(db, cblk, ctext, call_pat, call_at);
    if ok_set {
        let pname, ptype = param_name_and_type_at(db, spec, arg_idx);
        let sp = format_caller_sets_ctx(db, caller_name, callee_name, pname, ptype, field, rhs);
        return sp, true;
    }
    let pat, ok_arm = find_match_prefix_for_call(db, cblk, call_pat);
    if ok_arm && pat.len > 0 {
        var msg: u8[>..] = [];
        msg.append("Caller `");
        msg.append(caller_name);
        msg.append("` reads prefix `");
        msg.append(pat);
        msg.append("` before it calls `");
        msg.append(callee_name);
        msg.append("`.");
        return put_text(db, msg[..]), true;
    }
    return EmptySpan, false;
}

fn synthesize_entry_context(db: CompilerDb&, spec_idx: i32) {
    let spec = db.specs[spec_idx];
    guard spec.fn_sym >= 0 && spec.fn_sym < db.symbols.len else { return; }
    let callee_name = text_of(db, db.symbols[spec.fn_sym].name_span);
    guard callee_name.len > 0 else { return; }

    var call_pat: u8[>..] = [];
    call_pat.append(callee_name);
    call_pat.push('(');

    for i in db.symbols.len {
        let sym_id = i as i32;
        let sym = db.symbols[sym_id];
        if sym.kind == SymKind.FnSym && sym_id != spec.fn_sym && sym.decl_node >= 0 {
            let ctx_sp, found = try_caller_entry_ctx(
                db,
                spec,
                sym,
                callee_name,
                call_pat[..],
            );
            if found {
                db.specs[spec_idx].entry_ctx_text = ctx_sp;
                return;
            }
        }
    }

    var def_msg: u8[>..] = [];
    def_msg.append("Direct callers of `");
    def_msg.append(callee_name);
    def_msg.append("` can pass any parameter value.");
    db.specs[spec_idx].entry_ctx_text = put_text(db, def_msg[..]);
}

fn find_alias_for_param(
    db:         const CompilerDb&,
    body_node:  i32,
    param_name: const u8[:],
) -> const u8[:] {
    guard body_node >= 0 && body_node < db.nodes.len else { return ""; }
    var cur = db.nodes[body_node].first;
    for step in db.nodes.len {
        guard cur >= 0 && cur < db.nodes.len else { return ""; }
        let node = db.nodes[cur];
        if node.kind == AstKind.LetDecl && node.op_tok == TOK_REBIND {
            let rhs = strip_semi_eff(text_of(db, node.aux_span));
            if rhs == param_name {
                return trim_ascii_ws(text_of(db, node.span));
            }
        }
        cur = db.nodes[cur].next;
    }
    return "";
}

fn text_mentions_target(text: const u8[:], param_name: const u8[:], alias_name: const u8[:]) -> bool {
    if param_name.len > 0 && slice_find(text, param_name) >= 0 {
        return true;
    }
    if alias_name.len > 0 && slice_find(text, alias_name) >= 0 {
        return true;
    }
    return false;
}

fn text_restores_target(
    text:       const u8[:],
    param_name: const u8[:],
    alias_name: const u8[:],
) -> const u8[:], bool {
    guard text_mentions_target(text, param_name, alias_name) else { return "", false; }
    if slice_find(text, ".resize(") >= 0 || slice_find(text, ".clear(") >= 0 {
        let stmt_part, _, _ = split_at_str(text, ";");
        return trim_ascii_ws(stmt_part), true;
    }
    var assign_pat: u8[>..] = [];
    assign_pat.append(param_name);
    assign_pat.append(" = ");
    if slice_find(text, assign_pat[..]) >= 0 {
        let stmt_part2, _, _ = split_at_str(text, ";");
        return trim_ascii_ws(stmt_part2), true;
    }
    return "", false;
}

fn text_has_mutating_intrinsic(intrinsics: const IntrinsicTable&, text: const u8[:]) -> bool {
    for i in intrinsics.entries.len {
        let sym = strip_ns_prefix(intrinsics.entries[i].symbol[..]);
        if sym.len > 0 && slice_find(text, sym) >= 0 {
            let k = intrinsics.entries[i].kind;
            if k == IntrinsicKind.ReadKind || k == IntrinsicKind.WriteKind {
                return true;
            }
        }
    }
    return false;
}

fn text_mutates_target(
    intrinsics: const IntrinsicTable&,
    text:       const u8[:],
    param_name: const u8[:],
    alias_name: const u8[:],
) -> bool {
    guard text_mentions_target(text, param_name, alias_name) else { return false; }
    if slice_find(text, "+=") >= 0 || slice_find(text, "-=") >= 0 ||
       slice_find(text, ".push(") >= 0 || slice_find(text, ".try_push(") >= 0 ||
       slice_find(text, ".append(") >= 0 || slice_find(text, ".try_append(") >= 0 ||
       slice_find(text, ".try_set(") >= 0 || slice_find(text, ".clear(") >= 0 ||
       slice_find(text, ".resize(") >= 0 {
        return true;
    }
    if slice_find(text, "++") >= 0 || slice_find(text, "--") >= 0 {
        return true;
    }
    return text_has_mutating_intrinsic(intrinsics, text);
}

fn record_defer_stmt_eff(
    db:         CompilerDb&,
    state:      MutScanState&,
    cur:        i32,
    prev_stmt:  i32,
    param_name: const u8[:],
    alias_name: const u8[:],
) {
    let raw = strip_semi_eff(text_of(db, db.nodes[cur].span));
    guard text_mentions_target(raw, param_name, alias_name) else { return; }
    if slice_find(raw, ".resize(") >= 0 || slice_find(raw, ".clear(") >= 0 || slice_find(raw, " = ") >= 0 {
        state.has_defer_restore = true;
        var full_defer: u8[>..] = [];
        if !slice_starts_with(raw, "defer ") {
            full_defer.append("defer ");
        }
        full_defer.append(raw);
        state.defer_text = put_text(db, full_defer[..]);
        if prev_stmt >= 0 && prev_stmt < db.nodes.len {
            state.effect_span = span_union_lines(db.nodes[prev_stmt].span, db.nodes[cur].span);
        } else {
            state.effect_span = db.nodes[cur].span;
        }
    }
}

fn is_error_return_text_eff(txt: const u8[:]) -> bool {
    let raw = strip_semi_eff(txt);
    let t = trim_ascii_ws(if slice_ends_with(raw, "}") && raw.len > 0 { raw[..dec_i64(raw.len)] } else { raw });
    if t.len == 0 {
        return true;
    }
    if slice_find(t, "NO_ERROR") >= 0 || slice_find(t, "CloseNotify") >= 0 || slice_ends_with(t, ", true") {
        return false;
    }
    if slice_find(t, "false") >= 0 && slice_find(t, "true") < 0 {
        return true;
    }
    if slice_find(t, "-1") >= 0 {
        return true;
    }
    if slice_find(t, "Error.") >= 0 && slice_find(t, ".None") < 0 && slice_find(t, ".Ok") < 0 {
        return true;
    }
    if slice_find(t, "_err") >= 0 && slice_find(t, "==") < 0 {
        return true;
    }
    return t == "return";
}

fn inspect_guard_stmt_eff(
    db:         CompilerDb&,
    intrinsics: const IntrinsicTable&,
    state:      MutScanState&,
    cur:        i32,
    param_name: const u8[:],
    alias_name: const u8[:],
) {
    let node = db.nodes[cur];
    let cond_txt = trim_ascii_ws(text_of(db, node.span));
    let else_txt = trim_ascii_ws(text_of(db, node.aux_span));
    let returns_false = is_error_return_text_eff(else_txt);
    let rest_str, has_rest = text_restores_target(else_txt, param_name, alias_name);
    if has_rest {
        state.restore_text = put_text(db, rest_str);
    }

    let cond_muts = text_mutates_target(intrinsics, cond_txt, param_name, alias_name);
    let p_pos = slice_find(cond_txt, param_name);
    let muts_before_and = cond_muts && p_pos >= 0 && slice_find(cond_txt[p_pos..], "&&") >= 0;
    if returns_false && (state.mutated_before_err || muts_before_and) {
        state.has_err_after_mut = true;
        if !has_rest {
            state.all_err_restored = false;
        }
        if state.effect_span.line == 0 {
            state.effect_span = node.span;
        }
    }
    if cond_muts {
        state.mutated_before_err = true;
        if state.effect_span.line == 0 {
            state.effect_span = node.span;
        }
    }
}

fn mark_mutated_at(state: MutScanState&, span: Span) {
    state.mutated_before_err = true;
    if state.effect_span.line == 0 {
        state.effect_span = span;
    }
}

fn inspect_assign_or_let_eff(
    db:         const CompilerDb&,
    intrinsics: const IntrinsicTable&,
    state:      MutScanState&,
    node:       AstNode,
    param_name: const u8[:],
    alias_name: const u8[:],
) {
    if node.kind == AstKind.LetDecl {
        let rhs = text_of(db, node.aux_span);
        if text_mutates_target(intrinsics, rhs, param_name, alias_name) {
            mark_mutated_at(state, node.span);
        }
        return;
    }
    let lhs = trim_ascii_ws(text_of(db, node.span));
    let rhs = trim_ascii_ws(text_of(db, node.aux_span));
    if (lhs == param_name || lhs == alias_name) && (slice_find(rhs, "valid: false") >= 0 || slice_find(rhs, "default<") >= 0) {
        return;
    }
    if lhs == param_name || lhs == alias_name || slice_starts_with(lhs, param_name) {
        mark_mutated_at(state, node.span);
    }
}

fn if_stmt_returns_only_true_eff(db: const CompilerDb&, if_node: i32) -> bool {
    guard if_node >= 0 && if_node < db.nodes.len && db.nodes[if_node].kind == AstKind.IfStmt else {
        return false;
    }
    let cond_id = db.nodes[if_node].first;
    let then_blk = if cond_id >= 0 && cond_id < db.nodes.len { db.nodes[cond_id].next } else { -1 };
    guard then_blk >= 0 && then_blk < db.nodes.len && db.nodes[then_blk].next < 0 else { return false; }
    let then_txt = trim_ascii_ws(text_of(db, db.nodes[then_blk].span));
    return slice_ends_with(then_txt, "return true;") && slice_find(then_txt, "false") < 0;
}

fn inspect_leaf_stmt_eff(
    db:         CompilerDb&,
    intrinsics: const IntrinsicTable&,
    state:      MutScanState&,
    cur:        i32,
    prev_stmt:  i32,
    param_name: const u8[:],
    alias_name: const u8[:],
) {
    let node = db.nodes[cur];
    let k = node.kind;
    if k == AstKind.DeferStmt {
        record_defer_stmt_eff(db, state, cur, prev_stmt, param_name, alias_name);
        return;
    }
    if k == AstKind.GuardStmt {
        inspect_guard_stmt_eff(db, intrinsics, state, cur, param_name, alias_name);
        return;
    }
    if k == AstKind.LetDecl || k == AstKind.AssignStmt {
        inspect_assign_or_let_eff(db, intrinsics, state, node, param_name, alias_name);
        return;
    }
    if k == AstKind.CallExpr || k == AstKind.UfcsCallExpr {
        let ctxt = text_of(db, node.aux_span);
        let recv_txt = text_of(db, node.span);
        if text_mutates_target(intrinsics, ctxt, param_name, alias_name) || slice_starts_with(recv_txt, param_name) {
            mark_mutated_at(state, node.aux_span);
        }
        return;
    }
    if k == AstKind.ReturnStmt {
        let rtxt = text_of(db, node.span);
        if state.mutated_before_err && is_error_return_text_eff(rtxt) {
            state.has_err_after_mut = true;
            state.all_err_restored = false;
        }
    }
}

fn loop_contains_mut_and_err(
    db:         const CompilerDb&,
    intrinsics: const IntrinsicTable&,
    loop_node:  i32,
    param_name: const u8[:],
    alias_name: const u8[:],
) -> bool, Span {
    guard loop_node >= 0 && loop_node < db.nodes.len else { return false, Span {}; }
    var cur = db.nodes[loop_node].first;
    var has_mut = false;
    var has_err = false;
    var mut_span = Span {};
    for step in db.nodes.len {
        guard cur >= 0 && cur < db.nodes.len else { break; }
        let k = db.nodes[cur].kind;
        let is_cont = is_container_node_eff(k);
        if !is_cont {
            let txt = text_of(db, db.nodes[cur].span);
            if text_mutates_target(intrinsics, txt, param_name, alias_name) {
                has_mut = true;
                if mut_span.line == 0 { mut_span = db.nodes[cur].span; }
            }
            if k == AstKind.AssignStmt {
                let lhs = trim_ascii_ws(text_of(db, db.nodes[cur].span));
                if lhs == param_name || lhs == alias_name || slice_starts_with(lhs, param_name) {
                    has_mut = true;
                    if mut_span.line == 0 { mut_span = db.nodes[cur].span; }
                }
            }
            if k == AstKind.GuardStmt {
                let else_txt = text_of(db, db.nodes[cur].aux_span);
                if is_error_return_text_eff(else_txt) {
                    has_err = true;
                }
            }
            if k == AstKind.ReturnStmt {
                let ret_txt = text_of(db, db.nodes[cur].span);
                if is_error_return_text_eff(ret_txt) {
                    has_err = true;
                }
            }
        }
        cur = next_stmt_eff(db, loop_node, cur, is_cont);
    }
    return has_mut && has_err, mut_span;
}

// Scans all statements in a function body to classify mutations and rollbacks on `param_name`.
//
// Example:
//   param_name = "out", body_node = Block(defer if !committed { out.resize(orig_len, 0); })
//   returns: MutScanState { has_defer_restore: true, .. }
fn scan_param_mutations(
    db:         CompilerDb&,
    intrinsics: const IntrinsicTable&,
    body_node:  i32,
    param_name: const u8[:],
    alias_name: const u8[:],
    def_span:   Span,
) -> MutScanState {
    var state = MutScanState { effect_span: def_span, .. };
    guard body_node >= 0 && body_node < db.nodes.len else { return state; }
    var cur = db.nodes[body_node].first;
    var prev_let: i32 = -1;
    for step in db.nodes.len {
        guard cur >= 0 && cur < db.nodes.len else { return state; }
        let k = db.nodes[cur].kind;
        let container = is_container_node_eff(k);
        let descend = container && !if_stmt_returns_only_true_eff(db, cur);
        if k == AstKind.ForStmt || k == AstKind.WhileStmt {
            let loop_has_both, loop_span = loop_contains_mut_and_err(db, intrinsics, cur, param_name, alias_name);
            if loop_has_both {
                state.has_err_after_mut = true;
                state.mutated_before_err = true;
                if state.effect_span.line == 0 {
                    state.effect_span = loop_span;
                }
            }
        }
        if !container {
            inspect_leaf_stmt_eff(db, intrinsics, state, cur, prev_let, param_name, alias_name);
            if k == AstKind.LetDecl && prev_let < 0 {
                prev_let = cur;
            }
        }
        cur = next_stmt_eff(db, body_node, cur, descend);
    }
    return state;
}

fn find_restoring_caller(
    db:          const CompilerDb&,
    fn_sym:      i32,
    callee_name: const u8[:],
    param_name:  const u8[:],
) -> const u8[:], bool {
    guard callee_name.len > 0 else { return "", false; }
    var call_pat: u8[>..] = [];
    call_pat.append(callee_name);
    call_pat.push('(');
    for i in db.symbols.len {
        let sym_id = i as i32;
        let sym = db.symbols[sym_id];
        if sym.kind == SymKind.FnSym && sym_id != fn_sym && sym.decl_node >= 0 {
            let cblk = find_body_block_eff(db, sym.decl_node);
            let ctext = text_of(db, db.nodes[cblk].span);
            if slice_find(ctext, call_pat[..]) >= 0 {
                let _, ok_rest = text_restores_target(ctext, param_name, "");
                if ok_rest {
                    return text_of(db, sym.name_span), true;
                }
            }
        }
    }
    return "", false;
}

fn build_effect_for_param(
    db:         CompilerDb&,
    intrinsics: const IntrinsicTable&,
    spec:       SpecFunction,
    param_sym:  i32,
    body_node:  i32,
) -> ParamEffect {
    let fn_name = text_of(db, db.symbols[spec.fn_sym].name_span);
    let ret_str = trim_ascii_ws(text_of(db, spec.ret_type_text));
    let psym = db.symbols[param_sym];
    let param_name = text_of(db, psym.name_span);
    let alias_name = find_alias_for_param(db, body_node, param_name);
    let st = scan_param_mutations(db, intrinsics, body_node, param_name, alias_name, psym.span);

    if ret_str == "void" || ret_str.len == 0 {
        var mech_void: u8[>..] = [];
        mech_void.push('`');
        mech_void.append(fn_name);
        if st.mutated_before_err {
            mech_void.append("` changes `");
            mech_void.append(param_name);
            mech_void.append("` in place (infallible `void` function).");
        } else {
            mech_void.append("` does not change `");
            mech_void.append(param_name);
            mech_void.append("` (infallible `void` function).");
        }
        return ParamEffect {
            param_sym:      param_sym,
            state:          RollbackState.Unmodified,
            mechanism_text: put_text(db, mech_void[..]),
            span:           st.effect_span,
        };
    }

    if st.has_defer_restore {
        var mech: u8[>..] = [];
        mech.push('`');
        mech.append(text_of(db, st.defer_text));
        mech.append("` resets `");
        mech.append(param_name);
        if slice_find(text_of(db, st.defer_text), ".resize") >= 0 || slice_find(text_of(db, st.defer_text), ".clear") >= 0 {
            mech.append(".len");
        }
        mech.append("` on all `return false` paths.");
        return ParamEffect {
            param_sym:      param_sym,
            state:          RollbackState.TransactionalSelf,
            mechanism_text: put_text(db, mech[..]),
            span:           st.effect_span,
        };
    }

    if !st.has_err_after_mut {
        var mech_unmod: u8[>..] = [];
        mech_unmod.push('`');
        mech_unmod.append(fn_name);
        mech_unmod.append("` does not change `");
        mech_unmod.append(param_name);
        mech_unmod.append("` before any `return false` path.");
        return ParamEffect {
            param_sym:      param_sym,
            state:          RollbackState.Unmodified,
            mechanism_text: put_text(db, mech_unmod[..]),
            span:           psym.span,
        };
    }

    if st.all_err_restored && st.restore_text.len > 0 {
        var mech_rest: u8[>..] = [];
        mech_rest.push('`');
        mech_rest.append(text_of(db, st.restore_text));
        mech_rest.append("` resets `");
        mech_rest.append(param_name);
        if slice_find(text_of(db, st.restore_text), ".resize") >= 0 {
            mech_rest.append(".len");
        }
        mech_rest.append("` on all `return false` paths.");
        return ParamEffect {
            param_sym:      param_sym,
            state:          RollbackState.TransactionalSelf,
            mechanism_text: put_text(db, mech_rest[..]),
            span:           st.effect_span,
        };
    }

    let caller_name, has_caller_rest = find_restoring_caller(db, spec.fn_sym, fn_name, param_name);
    if has_caller_rest {
        var mech_caller: u8[>..] = [];
        mech_caller.push('`');
        mech_caller.append(fn_name);
        mech_caller.append("` leaves `");
        mech_caller.append(param_name);
        mech_caller.append("` changed, and caller `");
        mech_caller.append(caller_name);
        mech_caller.append("` restores `");
        mech_caller.append(param_name);
        mech_caller.append("` on `false`.");
        return ParamEffect {
            param_sym:      param_sym,
            state:          RollbackState.DirtySelfRestoredByCaller,
            mechanism_text: put_text(db, mech_caller[..]),
            span:           st.effect_span,
        };
    }

    var mech_dirty: u8[>..] = [];
    mech_dirty.push('`');
    mech_dirty.append(fn_name);
    mech_dirty.append("` changes `");
    mech_dirty.append(param_name);
    mech_dirty.append("` before `return false` without rollback.");
    return ParamEffect {
        param_sym:      param_sym,
        state:          RollbackState.DirtyExposed,
        mechanism_text: put_text(db, mech_dirty[..]),
        span:           st.effect_span,
    };
}

fn analyze_spec_effects(db: CompilerDb&, spec_idx: i32, intrinsics: const IntrinsicTable&) {
    let spec = db.specs[spec_idx];
    let eff_start = db.effects.len as i32;
    db.specs[spec_idx].effect_start = eff_start;
    db.specs[spec_idx].effect_count = 0;
    guard spec.fn_sym >= 0 && spec.fn_sym < db.symbols.len else { return; }

    let decl_node = db.symbols[spec.fn_sym].decl_node;
    let body_node = find_body_block_eff(db, decl_node);
    for i in spec.param_count {
        let param_sym = add_i32(spec.param_start, i);
        if param_sym >= 0 && param_sym < db.symbols.len {
            let psym = db.symbols[param_sym];
            let raw_t = trim_ascii_ws(text_of(db, psym.type_span));
            let is_flag_or_reader = raw_t == "bool&" || slice_find(raw_t, "Reader&") >= 0;
            let is_slice_array = slice_starts_with(raw_t, "const u8[:]") && slice_ends_with(raw_t, "&");
            let is_mut_ref = psym.is_ref_mut || is_slice_array || (slice_ends_with(raw_t, "&") && !slice_starts_with(raw_t, "const "));
            if !is_flag_or_reader && is_mut_ref {
                let eff = build_effect_for_param(db, intrinsics, spec, param_sym, body_node);
                db.effects.push(eff);
            }
        }
    }
    db.specs[spec_idx].effect_count = sub_i32(db.effects.len as i32, eff_start);
}

fn analyze_call_graph_and_effects(db: CompilerDb&, intrinsics: IntrinsicTable&) -> bool {
    for i in db.specs.len {
        let spec_idx = i as i32;
        synthesize_entry_context(db, spec_idx);
        analyze_spec_effects(db, spec_idx, intrinsics);
    }
    return true;
}
