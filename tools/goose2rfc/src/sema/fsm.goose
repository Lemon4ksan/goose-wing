// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Stage 2A state-machine transition table extractor.

import std;
import db from "../model";
import loader from "../config";
import sema.inliner;

struct FsmBind {
    name: u8[..64]  = [],
    expr: u8[..512] = [],
}

struct FsmBindTable {
    items: FsmBind[..32] = [],
    count: i32           = 0,
}

struct FsmScope {
    state_cond: u8[..160] = [],
    event_cond: u8[..256] = [],
    guard_cond: u8[..512] = [],
}

struct FsmTask {
    fn_sym:      i32      = -1,
    depth:       i32      = 0,
    state_param: u8[..64] = [],
    event_param: u8[..64] = [],
    init_scope:  FsmScope,
    binds:       FsmBindTable,
}

struct FsmContext {
    state_param: u8[..64] = [],
    event_param: u8[..64] = [],
    file_id:     i32      = 0,
    spec_id:     i32      = 0,
    depth:       i32      = 0,
    max_rows:    i32      = 128,
    max_depth:   i32      = 3,
}

fn fsm_add_bind(tbl: FsmBindTable&, name: const u8[:], expr: const u8[:]) {
    guard name.len > 0 && tbl.items.len < tbl.items.cap else { return; }
    for i in tbl.items.len {
        if tbl.items[i].name[..] == name {
            copy_bounded_str(tbl.items[i].expr, expr);
            return;
        }
    }
    var item = FsmBind { .. };
    copy_bounded_str(item.name, name);
    copy_bounded_str(item.expr, expr);
    tbl.items.push(item);
    tbl.count = tbl.items.len as i32;
}

fn fsm_is_ident_char(b: u8) -> bool {
    if b >= 'a' && b <= 'z' { return true; }
    if b >= 'A' && b <= 'Z' { return true; }
    if b >= '0' && b <= '9' { return true; }
    return b == '_' || b == ':';
}

fn fsm_boundary_ok(src: const u8[:], pos: i64, tok_len: i64) -> bool {
    if pos > 0 {
        let prev = src[dec_i64(pos)];
        if fsm_is_ident_char(prev) || prev == '.' {
            return false;
        }
    }
    let after = add_i64(pos, tok_len);
    if after < src.len {
        if fsm_is_ident_char(src[after]) {
            return false;
        }
    }
    return true;
}

// Substitutes standalone identifier occurrences of `old_tok` with `new_val` in `src`.
//
// Example:
//   src = "is_psk", old_tok = "is_psk", new_val = "mode == HandshakeMode.Psk"
//   appends: "mode == HandshakeMode.Psk" into `out`
fn fsm_replace_ident(src: const u8[:], old_tok: const u8[:], new_val: const u8[:], out: u8[>..]&) {
    out.clear();
    guard old_tok.len > 0 && src.len >= old_tok.len else {
        out.append(src);
        return;
    }
    var cursor: i64 = 0;
    for step in src.len {
        if cursor >= src.len { return; }
        let tail = src[cursor..];
        let rel = slice_find(tail, old_tok);
        if rel < 0 {
            out.append(tail);
            return;
        }
        let abs_pos = add_i64(cursor, rel);
        out.append(tail[..rel]);
        if fsm_boundary_ok(src, abs_pos, old_tok.len) {
            out.append(new_val);
        } else {
            out.append(old_tok);
        }
        cursor = add_i64(abs_pos, old_tok.len);
    }
}

fn fsm_apply_binds(src: const u8[:], binds: const FsmBindTable&, out: u8[>..]&) {
    out.clear();
    out.append(src);
    var tmp: u8[>..] = [];
    for i in binds.items.len {
        let nm = binds.items[i].name[..];
        let ex = binds.items[i].expr[..];
        if nm != ex && slice_find(out[..], nm) >= 0 {
            fsm_replace_ident(out[..], nm, ex, tmp);
            out.clear();
            out.append(tmp[..]);
        }
    }
}

fn fsm_strip_comment(line: const u8[:]) -> const u8[:] {
    let clean, _, has_c = split_at_str(line, "//");
    if has_c {
        return trim_ascii_ws(clean);
    }
    return trim_ascii_ws(line);
}

fn fsm_find_matching_rbrace(win: const u8[:], lbrace: i64, start_line: i32) -> i64, i32 {
    var depth: i32 = 0;
    var lines = start_line;
    for i in win.len {
        let b = win[i];
        if b == '\n' { lines = inc_i32(lines); }
        if i >= lbrace && b == '{' { depth = inc_i32(depth); }
        if i >= lbrace && b == '}' {
            depth = dec_i32(depth);
            if depth == 0 {
                return i, lines;
            }
        }
    }
    return dec_i64(win.len), lines;
}

// Extracts the function signature and `{ ... }` body slice along with start line and file_id.
//
// Example:
//   fn_sym = validate_client_handshake_transition
//   returns: sig_slice, body_slice, 126, file_id
fn fsm_extract_fn_slices(
    db:     const CompilerDb&,
    fn_sym: i32,
) -> const u8[:], const u8[:], i32, i32 {
    guard fn_sym >= 0 && fn_sym < db.symbols.len else { return "", "", 0, 0; }
    let sym = db.symbols[fn_sym];
    let fn_node = sym.decl_node;
    let base_span = if fn_node >= 0 && fn_node < db.nodes.len {
        db.nodes[fn_node].span
    } else {
        sym.span
    };
    guard base_span.at >= 0 && base_span.at < db.text.len else { return "", "", 0, 0; }
    let tail = db.text[base_span.at..];
    let win = tail[..min(tail.len, 16384)];
    let lbrace = slice_find(win, "{");
    guard lbrace >= 0 else { return "", "", base_span.line, base_span.file_id; }
    let rbrace, _ = fsm_find_matching_rbrace(win, lbrace, base_span.line);
    let body_start = inc_i64(lbrace);
    guard rbrace >= body_start else { return win[..lbrace], "", base_span.line, base_span.file_id; }
    let body_len = sub_i64(rbrace, body_start);
    return win[..lbrace], win[body_start..][..body_len], base_span.line, base_span.file_id;
}

fn fsm_is_enum_type_name(db: CompilerDb&, tname: const u8[:]) -> bool {
    let base_ref, _ = strip_ref_suffix(trim_ascii_ws(tname));
    let clean = if slice_starts_with(base_ref, "const ") {
        trim_ascii_ws(base_ref[6..])
    } else {
        trim_ascii_ws(base_ref)
    };
    guard clean.len > 0 else { return false; }
    var sym_id = find_symbol(db, clean);
    if sym_id < 0 {
        sym_id = find_symbol(db, strip_ns_prefix(clean));
    }
    return sym_id >= 0 && sym_id < db.symbols.len && db.symbols[sym_id].kind == SymKind.EnumSym;
}

fn fsm_is_state_type_name(db: CompilerDb&, tname: const u8[:]) -> bool {
    let _ = db.files.len;
    let s = trim_ascii_ws(tname);
    return slice_ends_with(s, "State") || slice_ends_with(s, "State&")
        || slice_ends_with(s, "Status") || slice_ends_with(s, "Status&")
        || slice_ends_with(s, "Phase") || slice_ends_with(s, "Phase&")
        || slice_ends_with(s, "Stage") || slice_ends_with(s, "Stage&");
}

// Detects whether a specification function represents a state-machine transition function.
//
// Example:
//   fn_name = "validate_client_handshake_transition", sig = "fn ...(current: HsState, ...)"
//   returns: true, state_param = "current", event_param = "incoming_msg_type"
fn fsm_detect_params(
    db:        CompilerDb&,
    fn_name:   const u8[:],
    sig:       const u8[:],
    state_out: u8[..64]&,
    event_out: u8[..64]&,
) -> bool {
    state_out.clear();
    event_out.clear();
    let _, after_lp, ok_lp = split_at_str(sig, "(");
    guard ok_lp else { return false; }
    let params_raw, ret_raw, _ = split_at_str(after_lp, ")");
    let is_fsm_named = slice_ends_with(fn_name, "_transition")
        || slice_find(fn_name, "_transition_") >= 0
        || slice_find(fn_name, "_fsm") >= 0
        || slice_starts_with(fn_name, "step_");
    var has_state_param = false;
    each_split(params_raw, ',') {
        let pname_raw, ptype_raw, has_col = split_at_str(trim_ascii_ws(it), ":");
        if has_col {
            let pname = trim_ascii_ws(pname_raw);
            let ptype, _, _ = split_at_str(trim_ascii_ws(ptype_raw), "=");
            let is_st = fsm_is_state_type_name(db, ptype) || (is_fsm_named && fsm_is_enum_type_name(db, ptype));
            if state_out.len == 0 && is_st {
                copy_bounded_str(state_out, pname);
                has_state_param = true;
            } else if event_out.len == 0 {
                copy_bounded_str(event_out, pname);
            }
        }
    };
    if slice_ends_with(fn_name, "_transition") || slice_find(fn_name, "_transition_") >= 0 {
        return true;
    }
    return has_state_param && slice_find(ret_raw, "->") >= 0;
}

fn fsm_bind_callee_args(
    sig:         const u8[:],
    args_txt:    const u8[:],
    caller_bind: const FsmBindTable&,
    callee_bind: FsmBindTable&,
) {
    let _, after_lp, ok_lp = split_at_str(sig, "(");
    guard ok_lp else { return; }
    let params_raw, _, _ = split_at_str(after_lp, ")");
    var pnames: const u8[:][>..] = [];
    var rem_p = trim_ascii_ws(params_raw);
    for step_p in 32 {
        if rem_p.len == 0 {
            break;
        }
        let head_p, tail_p, has_c_p = inl_split_top_level(rem_p, ",");
        let pdecl = trim_ascii_ws(if has_c_p { head_p } else { rem_p });
        let pname, _, has_col = split_at_str(pdecl, ":");
        if has_col {
            pnames.push(trim_ascii_ws(pname));
        }
        if !has_c_p {
            break;
        }
        rem_p = trim_ascii_ws(tail_p);
    }
    var args: const u8[:][>..] = [];
    var rem_a = trim_ascii_ws(args_txt);
    for step_a in 32 {
        if rem_a.len == 0 {
            break;
        }
        let head_a, tail_a, has_c_a = inl_split_top_level(rem_a, ",");
        args.push(trim_ascii_ws(if has_c_a { head_a } else { rem_a }));
        if !has_c_a {
            break;
        }
        rem_a = trim_ascii_ws(tail_a);
    }
    let n = min(pnames.len, args.len);
    var sub_arg: u8[>..] = [];
    for i in n {
        fsm_apply_binds(args[i], caller_bind, sub_arg);
        fsm_add_bind(callee_bind, pnames[i], sub_arg[..]);
    }
}

fn fsm_negate_atom(g: const u8[:], out: u8[>..]&) {
    let s = trim_ascii_ws(g);
    out.clear();
    guard s.len > 0 else { return; }
    let lhs_eq, rhs_eq, has_eq = split_at_str(s, " == ");
    if has_eq {
        out.append(lhs_eq);
        out.append(" != ");
        out.append(rhs_eq);
        return;
    }
    let lhs_ne, rhs_ne, has_ne = split_at_str(s, " != ");
    if has_ne {
        out.append(lhs_ne);
        out.append(" == ");
        out.append(rhs_ne);
        return;
    }
    let lhs_ge, rhs_ge, has_ge = split_at_str(s, " >= ");
    if has_ge {
        out.append(lhs_ge);
        out.append(" < ");
        out.append(rhs_ge);
        return;
    }
    let lhs_le, rhs_le, has_le = split_at_str(s, " <= ");
    if has_le {
        out.append(lhs_le);
        out.append(" > ");
        out.append(rhs_le);
        return;
    }
    let lhs_gt, rhs_gt, has_gt = split_at_str(s, " > ");
    if has_gt {
        out.append(lhs_gt);
        out.append(if trim_ascii_ws(rhs_gt) == "0" && slice_ends_with(trim_ascii_ws(lhs_gt), ".len") { " == 0" } else { " <= " });
        if !(trim_ascii_ws(rhs_gt) == "0" && slice_ends_with(trim_ascii_ws(lhs_gt), ".len")) {
            out.append(rhs_gt);
        }
        return;
    }
    let lhs_lt, rhs_lt, has_lt = split_at_str(s, " < ");
    if has_lt {
        out.append(lhs_lt);
        out.append(" >= ");
        out.append(rhs_lt);
        return;
    }
    if slice_starts_with(s, "!") {
        out.append(trim_ascii_ws(s[1..]));
        return;
    }
    if slice_find(s, " ") >= 0 {
        out.append("!(");
        out.append(s);
        out.append(")");
        return;
    }
    out.append("!");
    out.append(s);
}

fn fsm_negate_conj(g: const u8[:], out: u8[>..]&) {
    let s = trim_ascii_ws(g);
    out.clear();
    guard s.len > 0 else { return; }
    let _, _, has_and0 = inl_split_top_level(s, " && ");
    if !has_and0 {
        fsm_negate_atom(s, out);
        return;
    }
    out.push('(');
    var rest = s;
    var na: u8[>..] = [];
    for step in 8 {
        if rest.len == 0 {
            break;
        }
        let head, tail, has_and = inl_split_top_level(rest, " && ");
        let part = trim_ascii_ws(if has_and { head } else { rest });
        fsm_negate_atom(part, na);
        if step > 0 {
            out.append(" || ");
        }
        out.append(na[..]);
        if !has_and {
            break;
        }
        rest = trim_ascii_ws(tail);
    }
    out.push(')');
}

fn fsm_negate_guard(g: const u8[:], out: u8[>..]&) {
    let s = trim_ascii_ws(g);
    out.clear();
    guard s.len > 0 else { return; }
    let _, _, has_or0 = inl_split_top_level(s, " || ");
    if !has_or0 {
        fsm_negate_conj(s, out);
        return;
    }
    out.push('(');
    var rest = s;
    var nc: u8[>..] = [];
    for step in 8 {
        if rest.len == 0 {
            break;
        }
        let head, tail, has_or = inl_split_top_level(rest, " || ");
        let part = trim_ascii_ws(if has_or { head } else { rest });
        fsm_negate_conj(part, nc);
        if step > 0 {
            out.append(" && ");
        }
        out.append(nc[..]);
        if !has_or {
            break;
        }
        rest = trim_ascii_ws(tail);
    }
    out.push(')');
}

fn fsm_join_guard(a: const u8[:], b: const u8[:], out: u8[>..]&) {
    out.clear();
    let ta = trim_ascii_ws(a);
    let tb = trim_ascii_ws(b);
    if ta.len == 0 || ta == "always" {
        out.append(tb);
        return;
    }
    if tb.len == 0 || tb == "always" || ta == tb {
        out.append(ta);
        return;
    }
    out.append(ta);
    out.append(" && ");
    out.append(tb);
}

fn fsm_ensure_guards_at_tail(db: CompilerDb&, spec_id: i32) {
    let start = db.specs[spec_id].guard_start;
    let count = db.specs[spec_id].guard_count;
    if count == 0 {
        db.specs[spec_id].guard_start = db.guards.len as i32;
        return;
    }
    let end_idx = add_i32(start, count);
    if end_idx == (db.guards.len as i32) {
        return;
    }
    let new_start = db.guards.len as i32;
    for i in count {
        let old_idx = add_i32(start, i);
        if old_idx >= 0 && old_idx < db.guards.len {
            db.guards.push(db.guards[old_idx]);
        }
    }
    db.specs[spec_id].guard_start = new_start;
}

fn fsm_emit_backing_guard_if_needed(
    db:      CompilerDb&,
    spec_id: i32,
    req_id:  i32,
    st_txt:  const u8[:],
    ev_txt:  const u8[:],
    nx_txt:  const u8[:],
    rspan:   Span,
) {
    guard req_id > db.specs[spec_id].guard_count else { return; }
    fsm_ensure_guards_at_tail(db, spec_id);
    var lhs: u8[>..] = [];
    lhs.append(st_txt);
    lhs.append(" on ");
    lhs.append(ev_txt);
    db.guards.push(GuardRule {
        req_index:     req_id,
        template_id:   put_text(db, "REQ_EQ"),
        lhs_text:      put_text(db, lhs[..]),
        rhs_text:      put_text(db, nx_txt),
        else_ret_text: put_text(db, ""),
        inlined_from:  put_text(db, ""),
        span:          rspan,
    });
    db.specs[spec_id].guard_count = req_id;
}

fn fsm_append_single_row(
    db:      CompilerDb&,
    ctx:     const FsmContext&,
    st_txt:  const u8[:],
    ev_txt:  const u8[:],
    gd_txt:  const u8[:],
    nx_txt:  const u8[:],
    line_no: i32,
) {
    let cur_cnt = db.specs[ctx.spec_id].fsm_count;
    guard cur_cnt < ctx.max_rows else { return; }
    let req_id = inc_i32(cur_cnt);
    db.specs[ctx.spec_id].fsm_count = req_id;
    let fpath = file_path_of(db, ctx.file_id);
    var src_buf: u8[>..] = [];
    src_buf.append(fpath);
    src_buf.append(":");
    format_int(src_buf, line_no, 10, 0, ' ');
    let final_st = if st_txt.len > 0 { st_txt } else { "*" };
    let final_ev = if ev_txt.len > 0 { ev_txt } else { "*" };
    let final_gd = if gd_txt.len > 0 { gd_txt } else { "always" };
    let rspan = Span { file_id: ctx.file_id, at: 0, len: 0, line: line_no, col: 1 };
    db.fsm_rows.push(FsmRow {
        state_text:  put_text(db, final_st),
        event_text:  put_text(db, final_ev),
        guard_text:  put_text(db, final_gd),
        next_text:   put_text(db, nx_txt),
        req_id:      req_id,
        source_text: put_text(db, src_buf[..]),
        span:        rspan,
    });
    fsm_emit_backing_guard_if_needed(db, ctx.spec_id, req_id, final_st, final_ev, nx_txt, rspan);
}

fn fsm_extract_eq_rhs(clause: const u8[:], param_name: const u8[:]) -> const u8[:], bool {
    let lhs, rhs, has_eq = split_at_str(trim_ascii_ws(clause), "==");
    guard has_eq && trim_ascii_ws(lhs) == param_name else { return "", false; }
    return trim_ascii_ws(rhs), true;
}

// Emits one or more FSM transition rows (expanding `||` event disjunctions).
//
// Example:
//   ev_raw = "incoming_msg_type == rfc::TLS_HS_CERTIFICATE || incoming_msg_type == rfc::TLS_HS_COMPRESSED_CERTIFICATE"
//   emits 2 FsmRow entries
fn fsm_emit_rows_for_return(
    db:      CompilerDb&,
    ctx:     const FsmContext&,
    st_txt:  const u8[:],
    ev_raw:  const u8[:],
    gd_txt:  const u8[:],
    nx_txt:  const u8[:],
    line_no: i32,
) {
    if slice_find(ev_raw, "||") < 0 {
        let ev_val, ok_eq = fsm_extract_eq_rhs(ev_raw, ctx.event_param[..]);
        let ev_clean = if ok_eq { ev_val } else { ev_raw };
        fsm_append_single_row(db, ctx, st_txt, ev_clean, gd_txt, nx_txt, line_no);
        return;
    }
    each_split(ev_raw, '|') {
        let part = trim_ascii_ws(it);
        if part.len > 0 {
            let ev_val, ok_eq = fsm_extract_eq_rhs(part, ctx.event_param[..]);
            let ev_clean = if ok_eq { ev_val } else { part };
            fsm_append_single_row(db, ctx, st_txt, ev_clean, gd_txt, nx_txt, line_no);
        }
    };
}

// Classifies an `if` or `match` condition into state, event, or auxiliary guard components.
//
// Example:
//   cond = "current == HsState.ClientWaitSH && incoming_msg_type == rfc::TLS_HS_SERVER_HELLO"
//   populates `scope.state_cond` and `scope.event_cond`
fn fsm_classify_cond_clause(
    ctx:    const FsmContext&,
    clause: const u8[:],
    scope:  FsmScope&,
) {
    let c = trim_ascii_ws(clause);
    guard c.len > 0 else { return; }
    if slice_find(c, "||") >= 0 {
        if ctx.event_param.len > 0 && slice_find(c, ctx.event_param[..]) >= 0 {
            copy_bounded_str(scope.event_cond, c);
            return;
        }
        if ctx.state_param.len > 0 && slice_find(c, ctx.state_param[..]) >= 0 {
            return;
        }
    }
    let st_val, ok_st = fsm_extract_eq_rhs(c, ctx.state_param[..]);
    if ok_st {
        copy_bounded_str(scope.state_cond, st_val);
        return;
    }
    let ev_val, ok_ev = fsm_extract_eq_rhs(c, ctx.event_param[..]);
    if ok_ev {
        copy_bounded_str(scope.event_cond, ev_val);
        return;
    }
    var joined: u8[>..] = [];
    fsm_join_guard(scope.guard_cond[..], c, joined);
    copy_bounded_str(scope.guard_cond, joined[..]);
}

fn fsm_parse_if_cond(
    ctx:    const FsmContext&,
    raw_if: const u8[:],
    parent: const FsmScope&,
    binds:  const FsmBindTable&,
) -> FsmScope {
    var scope = parent;
    var sub_cond: u8[>..] = [];
    fsm_apply_binds(trim_ascii_ws(raw_if), binds, sub_cond);
    var rest: const u8[:] = sub_cond[..];
    for step in 8 {
        if rest.len == 0 {
            return scope;
        }
        let head, tail, has_and = split_at_str(rest, "&&");
        if has_and {
            fsm_classify_cond_clause(ctx, head, scope);
            rest = trim_ascii_ws(tail);
        } else {
            fsm_classify_cond_clause(ctx, rest, scope);
            return scope;
        }
    }
    return scope;
}

// Parses a `return ...;` value into a target state variant if it represents a valid transition.
//
// Example:
//   ret_raw = "HsState.ClientWaitEE, true"
//   returns: "HsState.ClientWaitEE", true
fn fsm_parse_transition_return(ret_raw: const u8[:]) -> const u8[:], bool {
    var s = trim_ascii_ws(ret_raw);
    if slice_starts_with(s, "(") && slice_ends_with(s, ")") {
        s = trim_ascii_ws(s[1..^1]);
    }
    let st_part, ok_part, has_comma = split_at_str(s, ",");
    if has_comma {
        guard trim_ascii_ws(ok_part) == "true" else { return "", false; }
        return trim_ascii_ws(st_part), true;
    }
    if slice_find(s, ".") >= 0 && slice_find(s, "(") < 0 && s != "false" && s != "true" {
        return s, true;
    }
    return "", false;
}

fn fsm_parse_call_expr(expr: const u8[:]) -> const u8[:], const u8[:], bool {
    let s = trim_ascii_ws(expr);
    guard slice_ends_with(s, ")") else { return "", "", false; }
    let fname, after_lp, has_lp = split_at_str(s, "(");
    guard has_lp && fname.len > 0 else { return "", "", false; }
    let clean_fn = trim_ascii_ws(fname);
    if slice_find(clean_fn, " ") >= 0 || slice_find(clean_fn, "=") >= 0 {
        return "", "", false;
    }
    return clean_fn, trim_ascii_ws(after_lp[..^1]), true;
}

fn fsm_enqueue_delegate_call(
    db:          CompilerDb&,
    ctx:         const FsmContext&,
    ret_expr:    const u8[:],
    cur_scope:   const FsmScope&,
    caller_bind: const FsmBindTable&,
    tasks:       FsmTask[..16]&,
) {
    guard ctx.depth < ctx.max_depth && tasks.len < tasks.cap else { return; }
    let fname, args_txt, is_call = fsm_parse_call_expr(ret_expr);
    guard is_call else { return; }
    var csym = find_symbol(db, fname);
    if csym < 0 { csym = find_symbol(db, strip_ns_prefix(fname)); }
    guard csym >= 0 && csym < db.symbols.len else { return; }
    guard db.symbols[csym].kind == SymKind.FnSym else { return; }
    let sig, cbody, _, _ = fsm_extract_fn_slices(db, csym);
    guard cbody.len > 0 else { return; }
    db.specs[ctx.spec_id].inlined_callees = inc_i32(db.specs[ctx.spec_id].inlined_callees);

    var task = FsmTask {
        fn_sym:     csym,
        depth:      inc_i32(ctx.depth),
        init_scope: cur_scope,
        ..
    };
    copy_bounded_str(task.state_param, ctx.state_param[..]);
    copy_bounded_str(task.event_param, ctx.event_param[..]);
    fsm_bind_callee_args(sig, args_txt, caller_bind, task.binds);
    let _, after_lp, ok_lp = split_at_str(sig, "(");
    if ok_lp {
        let p0, _, _ = split_at_str(after_lp, ",");
        let pn0, pt0, has_c = split_at_str(p0, ":");
        if has_c && fsm_is_state_type_name(db, pt0) {
            copy_bounded_str(task.state_param, trim_ascii_ws(pn0));
        } else if has_c {
            copy_bounded_str(task.event_param, trim_ascii_ws(pn0));
        }
    }
    tasks.push(task);
}

fn fsm_handle_complete_stmt(
    db:        CompilerDb&,
    ctx:       const FsmContext&,
    stmt:      const u8[:],
    line_no:   i32,
    cur_scope: const FsmScope&,
    binds:     FsmBindTable&,
    tasks:     FsmTask[..16]&,
) {
    if slice_starts_with(stmt, "let ") {
        let vname, rhs_raw, has_eq = split_at_str(trim_ascii_ws(stmt[4..]), "=");
        if has_eq {
            let rhs_clean, _, _ = split_at_str(rhs_raw, ";");
            var sub_rhs: u8[>..] = [];
            fsm_apply_binds(trim_ascii_ws(rhs_clean), binds, sub_rhs);
            fsm_add_bind(binds, trim_ascii_ws(vname), sub_rhs[..]);
        }
        return;
    }
    if slice_starts_with(stmt, "return ") {
        let r_clean, _, _ = split_at_str(stmt[7..], ";");
        let next_st, ok_tr = fsm_parse_transition_return(r_clean);
        if ok_tr {
            fsm_emit_rows_for_return(
                db, ctx, cur_scope.state_cond[..], cur_scope.event_cond[..],
                cur_scope.guard_cond[..], next_st, line_no,
            );
        } else {
            fsm_enqueue_delegate_call(db, ctx, r_clean, cur_scope, binds, tasks);
        }
    }
}

fn fsm_handle_inline_if_return(
    db:       CompilerDb&,
    ctx:      const FsmContext&,
    if_cond:  const u8[:],
    after_lb: const u8[:],
    line_no:  i32,
    stack:    FsmScope[..16]&,
    binds:    FsmBindTable&,
    tasks:    FsmTask[..16]&,
) {
    let top_idx = dec_i64(stack.len);
    let child_scope = fsm_parse_if_cond(ctx, if_cond, stack[top_idx], binds);
    let inner_stmt, _, _ = split_at_str(after_lb, "}");
    let prev_gd = stack[top_idx].guard_cond[..];
    fsm_handle_complete_stmt(db, ctx, trim_ascii_ws(inner_stmt), line_no, child_scope, binds, tasks);
    let new_gd = child_scope.guard_cond[..];
    let same_se = child_scope.state_cond[..] == stack[top_idx].state_cond[..]
        && child_scope.event_cond[..] == stack[top_idx].event_cond[..];
    let has_ret = slice_find(inner_stmt, "return ") >= 0 || slice_find(inner_stmt, "return;") >= 0;
    if (same_se && new_gd.len > 0 && new_gd != prev_gd) || (same_se && has_ret) {
        var neg: u8[>..] = [];
        fsm_negate_guard(if_cond, neg);
        var sub_neg: u8[>..] = [];
        fsm_apply_binds(neg[..], binds, sub_neg);
        var joined: u8[>..] = [];
        fsm_join_guard(prev_gd, sub_neg[..], joined);
        copy_bounded_str(stack[top_idx].guard_cond, joined[..]);
    }
}

fn fsm_step_match_arm(
    db:      CompilerDb&,
    ctx:     const FsmContext&,
    arm_lhs: const u8[:],
    arm_rhs: const u8[:],
    line_no: i32,
    stack:   FsmScope[..16]&,
    binds:   FsmBindTable&,
    tasks:   FsmTask[..16]&,
) {
    let top_idx = dec_i64(stack.len);
    var arm_scope = stack[top_idx];
    let pat = trim_ascii_ws(arm_lhs);
    if pat != "_" {
        if arm_scope.state_cond.len == 0 {
            copy_bounded_str(arm_scope.state_cond, pat);
        } else {
            copy_bounded_str(arm_scope.event_cond, pat);
        }
    }
    if slice_ends_with(trim_ascii_ws(arm_rhs), "{") && stack.len < stack.cap {
        stack.push(arm_scope);
        return;
    }
    let clean_rhs, _, _ = split_at_str(arm_rhs, ",");
    var synth: u8[>..] = [];
    if !slice_starts_with(trim_ascii_ws(arm_rhs), "return ") { synth.append("return "); }
    synth.append(trim_ascii_ws(clean_rhs));
    synth.append(";");
    fsm_handle_complete_stmt(db, ctx, synth[..], line_no, arm_scope, binds, tasks);
}

fn fsm_step_close_brace(line: const u8[:], ctx: const FsmContext&, binds: const FsmBindTable&, stack: FsmScope[..16]&) -> bool {
    if slice_starts_with(line, "} else if ") {
        if stack.len > 1 { stack.pop(); }
        let p_idx = dec_i64(stack.len);
        let cond_raw, _, has_lb = split_at_str(line[10..], "{");
        if has_lb && stack.len < stack.cap {
            stack.push(fsm_parse_if_cond(ctx, cond_raw, stack[p_idx], binds));
        }
        return true;
    }
    if slice_starts_with(line, "} else") && slice_find(line, "{") >= 0 {
        return true;
    }
    if slice_starts_with(line, "}") {
        if stack.len > 1 {
            let popped = stack.pop();
            let p_idx = dec_i64(stack.len);
            let prev_g = stack[p_idx].guard_cond[..];
            let pop_g = popped.guard_cond[..];
            let same_se = popped.state_cond[..] == stack[p_idx].state_cond[..]
                && popped.event_cond[..] == stack[p_idx].event_cond[..];
            if same_se && pop_g != prev_g {
                var delta: const u8[:] = pop_g;
                if prev_g.len > 0 && slice_starts_with(pop_g, prev_g) {
                    delta = trim_ascii_ws(pop_g[prev_g.len..]);
                    if slice_starts_with(delta, "&&") {
                        delta = trim_ascii_ws(delta[2..]);
                    }
                }
                var neg:    u8[>..] = [];
                var joined: u8[>..] = [];
                fsm_negate_guard(delta, neg);
                fsm_join_guard(prev_g, neg[..], joined);
                copy_bounded_str(stack[p_idx].guard_cond, joined[..]);
            }
        }
        return true;
    }
    return false;
}

fn fsm_step_body_line(
    db:      CompilerDb&,
    ctx:     const FsmContext&,
    line:    const u8[:],
    line_no: i32,
    stack:   FsmScope[..16]&,
    binds:   FsmBindTable&,
    tasks:   FsmTask[..16]&,
) {
    guard line.len > 0 && stack.len > 0 else { return; }
    if fsm_step_close_brace(line, ctx, binds, stack) {
        return;
    }
    let top_idx = dec_i64(stack.len);
    if slice_starts_with(line, "if ") {
        let cond_raw, after_lb, has_lb = split_at_str(line[3..], "{");
        if has_lb && slice_find(after_lb, "}") >= 0 {
            fsm_handle_inline_if_return(db, ctx, cond_raw, after_lb, line_no, stack, binds, tasks);
        } else if has_lb && stack.len < stack.cap {
            stack.push(fsm_parse_if_cond(ctx, cond_raw, stack[top_idx], binds));
        }
        return;
    }
    let arm_lhs, arm_rhs, has_arrow = split_at_str(line, "=>");
    if has_arrow {
        fsm_step_match_arm(db, ctx, arm_lhs, arm_rhs, line_no, stack, binds, tasks);
        return;
    }
    fsm_handle_complete_stmt(db, ctx, line, line_no, stack[top_idx], binds, tasks);
}

fn fsm_run_task(db: CompilerDb&, cfg: const Config&, spec_id: i32, task: FsmTask&, tasks: FsmTask[..16]&) {
    let _, body, sline, file_id = fsm_extract_fn_slices(db, task.fn_sym);
    guard body.len > 0 else { return; }
    var ctx = FsmContext {
        file_id:   file_id,
        spec_id:   spec_id,
        depth:     task.depth,
        max_rows:  cfg.max_fsm_rows,
        max_depth: cfg.max_inline_depth,
        ..
    };
    copy_bounded_str(ctx.state_param, task.state_param[..]);
    copy_bounded_str(ctx.event_param, task.event_param[..]);

    var stack: FsmScope[..16] = [];
    stack.push(task.init_scope);
    var cur_line = sline;
    var multi_stmt: u8[>..] = [];
    var multi_if:   u8[>..] = [];

    each_split(body, '\n') {
        let line = fsm_strip_comment(it);
        let top_idx = dec_i64(stack.len);
        let cur_scope = stack[top_idx];

        if multi_if.len > 0 {
            multi_if.append(" ");
            multi_if.append(line);
            if slice_find(line, "{") >= 0 {
                fsm_step_body_line(db, ctx, multi_if[..], cur_line, stack, task.binds, tasks);
                multi_if.clear();
            }
        } else if multi_stmt.len > 0 {
            multi_stmt.append(" ");
            multi_stmt.append(line);
            if slice_find(line, ";") >= 0 {
                fsm_handle_complete_stmt(db, ctx, multi_stmt[..], cur_line, cur_scope, task.binds, tasks);
                multi_stmt.clear();
            }
        } else if (slice_starts_with(line, "if ") || slice_starts_with(line, "} else if ")) && slice_find(line, "{") < 0 {
            multi_if.append(line);
        } else if (slice_starts_with(line, "let ") || slice_starts_with(line, "return ")) && slice_find(line, ";") < 0 {
            multi_stmt.append(line);
        } else {
            fsm_step_body_line(db, ctx, line, cur_line, stack, task.binds, tasks);
        }
        cur_line = inc_i32(cur_line);
    };
}

fn fsm_process_spec_function(db: CompilerDb&, cfg: const Config&, spec_id: i32) {
    let fn_sym = db.specs[spec_id].fn_sym;
    guard fn_sym >= 0 && fn_sym < db.symbols.len else { return; }
    let fn_name = text_of(db, db.symbols[fn_sym].name_span);
    let sig, body, _, _ = fsm_extract_fn_slices(db, fn_sym);
    guard body.len > 0 else { return; }

    var root_task = FsmTask { fn_sym: fn_sym, depth: 0, .. };
    guard fsm_detect_params(db, fn_name, sig, root_task.state_param, root_task.event_param) else {
        return;
    }
    db.specs[spec_id].fsm_start = db.fsm_rows.len as i32;
    db.specs[spec_id].fsm_count = 0;

    var tasks: FsmTask[..16] = [];
    tasks.push(root_task);
    var cursor: i64 = 0;
    for step in 16 {
        guard cursor < tasks.len else { return; }
        var cur_task = tasks[cursor];
        cursor = inc_i64(cursor);
        fsm_run_task(db, cfg, spec_id, cur_task, tasks);
    }
}

fn extract_state_machines(db: CompilerDb&, cfg: Config&) -> bool {
    for i in db.specs.len {
        let spec_id = i as i32;
        fsm_process_spec_function(db, cfg, spec_id);
    }
    return true;
}

fn extract_state_machines(db: CompilerDb&) -> bool {
    var cfg = default_config();
    return extract_state_machines(db, cfg);
}
