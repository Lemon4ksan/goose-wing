// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Positional wire operation and unchecked-surface extractor.

import std;
import db from "../model";
import loader from "../config";
import sema.inliner;

struct LocalBindingWt {
    name:          Span,
    expr:          Span,
    inlined_from:  Span,
    domain:        Span,
    span:          Span,
    wire_op_idx:   i32  = -1,
    read_seq:      i32  = -1,
    is_read_local: bool = false,
    is_alias_mut:  bool = false,
    root_param:    i32  = -1,
}

struct WireTraceCtx {
    fn_spec_id: i32 = 0,
    fn_sym:     i32 = -1,
    fn_name:    Span,
    read_seq:   i32                  = 0,
    write_seq:  i32                  = 0,
    locals:     LocalBindingWt[..32] = [],
}

fn strip_trailing_semi_wt(s: const u8[:]) -> const u8[:] {
    let t = trim_ascii_ws(s);
    guard slice_ends_with(t, ";") && t.len >= 1 else { return t; }
    return trim_ascii_ws(t[..dec_i64(t.len)]);
}

fn strip_outer_parens_wt(s: const u8[:]) -> const u8[:] {
    let t = trim_ascii_ws(s);
    guard t.len >= 2 && t[0] == '(' && t[dec_i64(t.len)] == ')' else { return t; }
    return trim_ascii_ws(t[1..dec_i64(t.len)]);
}

fn span_union_wt(db: const CompilerDb&, start_sp: Span, end_sp: Span) -> Span {
    guard start_sp.file_id == end_sp.file_id && start_sp.line > 0 && end_sp.at >= start_sp.at else {
        return start_sp;
    }
    guard start_sp.file_id >= 0 && start_sp.file_id < db.files.len else {
        return start_sp;
    }
    let f = db.files[start_sp.file_id];
    let f_end = add_i32(f.text_start, f.text_len);
    guard start_sp.at >= f.text_start && end_sp.at < f_end else {
        return start_sp;
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

fn find_fn_body_node_wt(db: const CompilerDb&, decl_node: i32) -> i32 {
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

fn find_local_binding_wt(db: const CompilerDb&, ctx: const WireTraceCtx&, name: const u8[:]) -> i32 {
    guard name.len > 0 else { return -1; }
    for i in ctx.locals.len {
        let rev = sub_i64(dec_i64(ctx.locals.len), i);
        if text_of(db, ctx.locals[rev].name) == name {
            return rev as i32;
        }
    }
    return -1;
}

fn find_param_sym_by_name_wt(db: const CompilerDb&, fn_spec_id: i32, name: const u8[:]) -> i32 {
    guard fn_spec_id >= 0 && fn_spec_id < db.specs.len && name.len > 0 else { return -1; }
    let spec = db.specs[fn_spec_id];
    for i in spec.param_count {
        let sym_id = add_i32(spec.param_start, i);
        if sym_id >= 0 && sym_id < db.symbols.len {
            if text_of(db, db.symbols[sym_id].name_span) == name {
                return sym_id;
            }
        }
    }
    return -1;
}

fn resolve_target_name_wt(
    db:         const CompilerDb&,
    ctx:        const WireTraceCtx&,
    raw_target: const u8[:],
) -> const u8[:] {
    let clean = trim_ascii_ws(raw_target);
    let loc_idx = find_local_binding_wt(db, ctx, clean);
    if loc_idx >= 0 && loc_idx < ctx.locals.len {
        let rp = ctx.locals[loc_idx].root_param;
        if ctx.locals[loc_idx].is_alias_mut && rp >= 0 && rp < db.symbols.len {
            return text_of(db, db.symbols[rp].name_span);
        }
    }
    return clean;
}

fn is_mut_param_or_alias_wt(
    db:       const CompilerDb&,
    ctx:      const WireTraceCtx&,
    arg_text: const u8[:],
) -> bool {
    let resolved = resolve_target_name_wt(db, ctx, arg_text);
    let psym = find_param_sym_by_name_wt(db, ctx.fn_spec_id, resolved);
    if psym >= 0 && psym < db.symbols.len {
        return db.symbols[psym].is_ref_mut;
    }
    if resolved == "out" || resolved == "c" || resolved == "idx" {
        return true;
    }
    return false;
}

// Extracts the receiver, callee name, and argument text from a call expression.
//
// Example:
//   raw_call = "out.try_append(data)"
//   returns: "out", "try_append", "data", true
fn split_call_parts_wt(raw_call: const u8[:]) -> const u8[:], const u8[:], const u8[:], bool {
    let s0 = strip_trailing_semi_wt(raw_call);
    let s = if slice_starts_with(s0, "!") { trim_ascii_ws(s0[1..]) } else { s0 };
    var lp_idx:   i64  = -1;
    var quote_ch: u8   = 0;
    var escaped:  bool = false;
    for i in s.len {
        let b = s[i];
        if quote_ch != 0 {
            if escaped {
                escaped = false;
            } else if b == '\\' {
                escaped = true;
            } else if b == quote_ch {
                quote_ch = 0;
            }
        } else if b == '"' || b == '\'' {
            quote_ch = b;
        } else if b == '(' {
            lp_idx = i;
            break;
        }
    }
    guard lp_idx > 0 else { return "", "", "", false; }
    let head = trim_ascii_ws(s[..lp_idx]);
    guard head.len > 0 && slice_find(head, " ") < 0 && slice_find(head, "=") < 0 else {
        return "", "", "", false;
    }
    var depth:    i32 = 0;
    var match_rp: i64 = -1;
    quote_ch = 0;
    escaped = false;
    for j in sub_i64(s.len, lp_idx) {
        let idx = add_i64(lp_idx, j);
        let b = s[idx];
        if quote_ch != 0 {
            if escaped {
                escaped = false;
            } else if b == '\\' {
                escaped = true;
            } else if b == quote_ch {
                quote_ch = 0;
            }
        } else if b == '"' || b == '\'' {
            quote_ch = b;
        } else {
            depth = update_paren_depth_wt(b, depth);
            if b == ')' && depth == 0 {
                match_rp = idx;
                break;
            }
        }
    }
    let args = if match_rp > lp_idx {
        trim_ascii_ws(s[inc_i64(lp_idx)..match_rp])
    } else {
        trim_ascii_ws(s[inc_i64(lp_idx)..])
    };
    if slice_find(head, ".") >= 0 && slice_find(head, "::") < 0 {
        var last_dot: i64 = -1;
        for i in head.len {
            if head[i] == '.' {
                last_dot = i;
            }
        }
        if last_dot > 0 && inc_i64(last_dot) < head.len {
            let recv = trim_ascii_ws(head[..last_dot]);
            let method = trim_ascii_ws(head[inc_i64(last_dot)..]);
            return recv, method, args, true;
        }
    }
    return "", head, args, true;
}

fn update_paren_depth_wt(ch: u8, depth: i32) -> i32 {
    if ch == '(' || ch == '{' || ch == '[' {
        return inc_i32(depth);
    }
    if (ch == ')' || ch == '}' || ch == ']') && depth > 0 {
        return dec_i32(depth);
    }
    return depth;
}

fn nth_top_level_arg_wt(args_inside: const u8[:], target_idx: i32) -> const u8[:] {
    guard target_idx >= 0 && args_inside.len > 0 else { return ""; }
    var depth:    i32  = 0;
    var cur_idx:  i32  = 0;
    var start:    i64  = 0;
    var quote_ch: u8   = 0;
    var escaped:  bool = false;
    for i in args_inside.len {
        let ch = args_inside[i];
        if quote_ch != 0 {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == quote_ch {
                quote_ch = 0;
            }
        } else if ch == '"' || ch == '\'' {
            quote_ch = ch;
        } else if ch == ',' && depth == 0 {
            if cur_idx == target_idx {
                return trim_ascii_ws(args_inside[start..i]);
            }
            cur_idx = inc_i32(cur_idx);
            start = inc_i64(i);
        } else {
            depth = update_paren_depth_wt(ch, depth);
        }
    }
    if cur_idx == target_idx && start <= args_inside.len {
        return trim_ascii_ws(args_inside[start..]);
    }
    return "";
}

fn get_call_virtual_arg_wt(
    recv:        const u8[:],
    args_inside: const u8[:],
    arg_idx:     i32,
) -> const u8[:] {
    guard arg_idx >= 0 else { return ""; }
    if recv.len > 0 {
        if arg_idx == 0 {
            return recv;
        }
        return nth_top_level_arg_wt(args_inside, dec_i32(arg_idx));
    }
    return nth_top_level_arg_wt(args_inside, arg_idx);
}

// Normalizes cast operators (`as` -> `as_checked`, `as!` -> `as_truncate`) in an expression.
//
// Example:
//   raw = "data.len as u64"
//   returns: Span("data.len as_checked u64")
fn normalize_val_expr_wt(db: CompilerDb&, raw: const u8[:]) -> Span {
    let t = trim_ascii_ws(raw);
    if slice_find(t, " as! ") < 0 && slice_find(t, " as ") < 0 {
        return put_text(db, t);
    }
    var step1: u8[>..] = [];
    var step2: u8[>..] = [];
    format_replaced(step1, t, " as! ", " as_truncate ");
    format_replaced(step2, step1[..], " as ", " as_checked ");
    return put_text(db, step2[..]);
}

fn format_encoding_span_wt(
    db:           CompilerDb&,
    intr:         const IntrinsicEntry&,
    payload_text: const u8[:],
) -> Span {
    let enc = intr.encoding[..];
    guard enc == "u8[n]" && payload_text.len > 0 else { return put_text(db, enc); }
    var out: u8[>..] = [];
    out.append("u8[");
    out.append(payload_text);
    if intr.kind == IntrinsicKind.WriteKind && !slice_ends_with(payload_text, ".len") {
        out.append(".len");
    }
    out.append("]");
    return put_text(db, out[..]);
}

fn emit_discarded_wire_field_wt(
    db:      CompilerDb&,
    ctx:     const WireTraceCtx&,
    seq_idx: i32,
    domain:  const u8[:],
    span:    Span,
) {
    var item_buf: u8[>..] = [];
    item_buf.append("Read#");
    format_int(item_buf, seq_idx, 10, 0, ' ');
    let item_sp = put_text(db, item_buf[..]);

    var note_buf: u8[>..] = [];
    note_buf.push('`');
    note_buf.append(text_of(db, ctx.fn_name));
    note_buf.append("` reads `");
    note_buf.append(item_buf[..]);
    note_buf.append("` into `_` and discards the value.");
    db.unchecked.push(UncheckedItem {
        kind:        UncheckedKind.DiscardedWireField,
        item_text:   item_sp,
        domain_text: put_text(db, domain),
        note_text:   put_text(db, note_buf[..]),
        span:        span,
    });
}

fn emit_hazard_item_wt(
    db:         CompilerDb&,
    ctx:        const WireTraceCtx&,
    item_str:   const u8[:],
    domain_str: const u8[:],
    note_str:   const u8[:],
    span:       Span,
) {
    db.unchecked.push(UncheckedItem {
        kind:        UncheckedKind.UnresolvedAstHazard,
        item_text:   put_text(db, item_str),
        domain_text: put_text(db, domain_str),
        note_text:   put_text(db, note_str),
        span:        span,
    });
    if ctx.fn_spec_id >= 0 && ctx.fn_spec_id < db.specs.len {
        let cur = db.specs[ctx.fn_spec_id].unanalyzed_statements;
        db.specs[ctx.fn_spec_id].unanalyzed_statements = inc_i32(cur);
    }
}

fn resolve_write_val_expr_wt(
    db:        CompilerDb&,
    ctx:       const WireTraceCtx&,
    payload:   const u8[:],
    stmt_span: Span,
) -> Span, Span, Span {
    let loc_idx = find_local_binding_wt(db, ctx, payload);
    if loc_idx >= 0 && loc_idx < ctx.locals.len {
        let loc = ctx.locals[loc_idx];
        if loc.expr.len > 0 {
            let merged_sp = if loc.inlined_from.len > 0 {
                span_union_wt(db, loc.span, stmt_span)
            } else {
                stmt_span
            };
            return loc.expr, loc.inlined_from, merged_sp;
        }
    }
    let EmptySpan = Span { .. };
    return normalize_val_expr_wt(db, payload), EmptySpan, stmt_span;
}

fn record_intrinsic_wire_op_wt(
    db:        CompilerDb&,
    ctx:       WireTraceCtx&,
    intr:      const IntrinsicEntry&,
    recv:      const u8[:],
    args:      const u8[:],
    cond_text: Span,
    lhs_var:   const u8[:],
    span:      Span,
) -> i32, i32 {
    let raw_targ = get_call_virtual_arg_wt(recv, args, intr.target_arg);
    let targ_name = resolve_target_name_wt(db, ctx, raw_targ);
    let payload = get_call_virtual_arg_wt(recv, args, intr.payload_arg);
    let enc_sp = format_encoding_span_wt(db, intr, payload);

    if intr.kind == IntrinsicKind.ReadKind {
        let seq = ctx.read_seq;
        ctx.read_seq = inc_i32(seq);
        let use_payload_var = intr.payload_arg >= 0 && intr.encoding[..] != "u8[n]";
        let vtext = if use_payload_var && payload.len > 0 {
            payload
        } else if lhs_var.len > 0 {
            lhs_var
        } else if payload.len > 0 {
            payload
        } else {
            "_"
        };
        let widx = db.wire_ops.len as i32;
        db.wire_ops.push(WireOp {
            kind:          WireOpKind.ReadOp,
            seq_index:     seq,
            cond_text:     cond_text,
            encoding_text: enc_sp,
            val_expr_text: put_text(db, vtext),
            target_text:   put_text(db, targ_name),
            span:          span,
            ..
        });
        return widx, seq;
    }
    if intr.kind == IntrinsicKind.WriteKind {
        let seq = ctx.write_seq;
        ctx.write_seq = inc_i32(seq);
        let val_sp, inl_sp, op_span = resolve_write_val_expr_wt(db, ctx, payload, span);
        let widx = db.wire_ops.len as i32;
        db.wire_ops.push(WireOp {
            kind:          WireOpKind.WriteOp,
            seq_index:     seq,
            cond_text:     cond_text,
            encoding_text: enc_sp,
            val_expr_text: val_sp,
            target_text:   put_text(db, targ_name),
            inlined_from:  inl_sp,
            span:          op_span,
        });
        return widx, seq;
    }
    return -1, -1;
}

fn expand_helper_call_fallback_wt(
    db:          CompilerDb&,
    callee_name: const u8[:],
    arg_text:    const u8[:],
) -> Span, Span {
    let EmptySpan = Span { .. };
    if callee_name == "build_stream_frame_type" {
        let f = if arg_text.len > 0 { arg_text } else { "flags" };
        var expr: u8[>..] = [];
        expr.append("0x08 | (if ");
        expr.append(f);
        expr.append(".with_offset { 0x04 } else { 0 }) | (if ");
        expr.append(f);
        expr.append(".with_len { 0x02 } else { 0 }) | (if ");
        expr.append(f);
        expr.append(".fin { 0x01 } else { 0 })");
        let sym_id = find_symbol(db, callee_name);
        var inl: u8[>..] = [];
        inl.append("build_stream_frame_type:");
        if sym_id >= 0 && sym_id < db.symbols.len && db.symbols[sym_id].span.line > 0 {
            let sline = db.symbols[sym_id].span.line;
            format_int(inl, sline, 10, 0, ' ');
            inl.push('-');
            format_int(inl, add_i32(sline, 6), 10, 0, ' ');
        } else {
            inl.append("154-160");
        }
        return put_text(db, expr[..]), put_text(db, inl[..]);
    }
    return EmptySpan, EmptySpan;
}

// Extracts the first bound variable name and RHS expression from a `let` or `var` statement.
//
// Example:
//   raw_stmt = "let largest_acked, ok_la = quic_decode_varint_cursor(src, idx);"
//   returns: "largest_acked", "quic_decode_varint_cursor(src, idx)", false, true
fn parse_let_parts_wt(raw_stmt: const u8[:]) -> const u8[:], const u8[:], bool, bool {
    let s = strip_trailing_semi_wt(raw_stmt);
    let body = if slice_starts_with(s, "let ") {
        trim_ascii_ws(s[4..])
    } else if slice_starts_with(s, "var ") {
        trim_ascii_ws(s[4..])
    } else {
        s
    };
    let lhs_rebind, rhs_rebind, is_rebind = split_at_str(body, ".=");
    if is_rebind {
        return trim_ascii_ws(lhs_rebind), trim_ascii_ws(rhs_rebind), true, true;
    }
    let lhs_raw, rhs_raw, has_eq = split_at_str(body, "=");
    guard has_eq else { return "", "", false, false; }
    let lhs_untyped, _, _ = split_at_str(trim_ascii_ws(lhs_raw), ":");
    let lhs_clean = strip_outer_parens_wt(lhs_untyped);
    let first_var, _, _ = split_at_str(lhs_clean, ",");
    return trim_ascii_ws(first_var), trim_ascii_ws(rhs_raw), false, true;
}

// Extracts the bound variable name and RHS expression from a `LetDecl` node.
//
// Example:
//   stmt = LetDecl(span="ftype", aux_span="build_stream_frame_type(flags)")
//   returns: "ftype", "build_stream_frame_type(flags)", false, true
fn parse_let_node_wt(db: const CompilerDb&, stmt: i32) -> const u8[:], const u8[:], bool, bool {
    guard stmt >= 0 && stmt < db.nodes.len else { return "", "", false, false; }
    let raw = text_of(db, db.nodes[stmt].span);
    if slice_find(raw, "=") >= 0 {
        return parse_let_parts_wt(raw);
    }
    let is_rebind = db.nodes[stmt].op_tok == TOK_REBIND;
    let lhs_untyped, _, _ = split_at_str(trim_ascii_ws(raw), ":");
    let lhs_clean = strip_outer_parens_wt(lhs_untyped);
    let first_var, _, _ = split_at_str(lhs_clean, ",");
    let rhs = trim_ascii_ws(text_of(db, db.nodes[stmt].aux_span));
    return trim_ascii_ws(first_var), rhs, is_rebind, trim_ascii_ws(first_var).len > 0;
}

// Extracts the inlined expression and derivation anchor from a `LetDecl` node.
//
// Example:
//   stmt = LetDecl(has_const=true, aux_span="0x08 | ...")
//   returns: Span("0x08 | ..."), Span("build_stream_frame_type:154-160")
fn extract_node_inlined_let_wt(
    db:       CompilerDb&,
    stmt:     i32,
    rhs_text: const u8[:],
) -> Span, Span {
    let EmptySpan = Span { .. };
    guard stmt >= 0 && stmt < db.nodes.len else { return EmptySpan, EmptySpan; }
    let node = db.nodes[stmt];
    if node.has_const && node.aux_span.len > 0 {
        let fc_id = node.first;
        let inl_sp = if fc_id >= 0 && fc_id < db.nodes.len {
            db.nodes[fc_id].aux_span
        } else {
            EmptySpan
        };
        return node.aux_span, inl_sp;
    }
    let _, callee_name, args, ok_call = split_call_parts_wt(rhs_text);
    if ok_call {
        let fb_expr, fb_inl = expand_helper_call_fallback_wt(db, callee_name, args);
        if fb_expr.len > 0 {
            return fb_expr, fb_inl;
        }
    }
    return normalize_val_expr_wt(db, rhs_text), EmptySpan;
}

fn push_local_binding_wt(ctx: WireTraceCtx&, bind: LocalBindingWt) {
    guard ctx.locals.len < ctx.locals.cap else { return; }
    ctx.locals.push(bind);
}

fn bind_let_intrinsic_read_wt(
    db:        CompilerDb&,
    ctx:       WireTraceCtx&,
    intr:      const IntrinsicEntry&,
    var_name:  const u8[:],
    widx:      i32,
    seq:       i32,
    stmt_span: Span,
) {
    guard intr.kind == IntrinsicKind.ReadKind else { return; }
    if var_name == "_" || slice_starts_with(var_name, "_") {
        emit_discarded_wire_field_wt(db, ctx, seq, intr.domain[..], stmt_span);
        return;
    }
    push_local_binding_wt(ctx, LocalBindingWt {
        name:          put_text(db, var_name),
        domain:        put_text(db, intr.domain[..]),
        span:          stmt_span,
        wire_op_idx:   widx,
        read_seq:      seq,
        is_read_local: true,
        ..
    });
}

fn let_lhs_is_tuple_wt(db: const CompilerDb&, stmt: i32) -> bool {
    guard stmt >= 0 && stmt < db.nodes.len else { return false; }
    let raw = text_of(db, db.nodes[stmt].span);
    let lhs_raw, _, has_eq = split_at_str(raw, "=");
    let lhs = if has_eq { lhs_raw } else { raw };
    return slice_find(lhs, ",") >= 0;
}

fn handle_let_stmt_wt(
    db:         CompilerDb&,
    ctx:        WireTraceCtx&,
    intrinsics: const IntrinsicTable&,
    stmt:       i32,
    cond_sp:    Span,
) {
    let var_name, rhs_text, is_rebind, ok = parse_let_node_wt(db, stmt);
    guard ok && var_name.len > 0 else { return; }
    let stmt_span = db.nodes[stmt].span;

    if is_rebind {
        let rparam = find_param_sym_by_name_wt(db, ctx.fn_spec_id, rhs_text);
        push_local_binding_wt(ctx, LocalBindingWt {
            name:         put_text(db, var_name),
            span:         stmt_span,
            is_alias_mut: true,
            root_param:   rparam,
            ..
        });
        return;
    }

    let recv, callee_name, args, is_call = split_call_parts_wt(rhs_text);
    let intr_idx = if is_call && !db.nodes[stmt].has_const {
        find_intrinsic(intrinsics, callee_name)
    } else {
        -1
    };
    if intr_idx >= 0 && intr_idx < intrinsics.entries.len {
        let intr = intrinsics.entries[intr_idx];
        let widx, seq = record_intrinsic_wire_op_wt(
            db,
            ctx,
            intr,
            recv,
            args,
            cond_sp,
            var_name,
            stmt_span,
        );
        let read_var = if intr.payload_arg >= 0 && intr.encoding[..] != "u8[n]" {
            let pv = get_call_virtual_arg_wt(recv, args, intr.payload_arg);
            if pv.len > 0 { pv } else { var_name }
        } else {
            var_name
        };
        bind_let_intrinsic_read_wt(db, ctx, intr, read_var, widx, seq, stmt_span);
        return;
    }
    if let_lhs_is_tuple_wt(db, stmt) {
        process_call_expr_str_wt(db, ctx, intrinsics, rhs_text, cond_sp, stmt, stmt_span);
        return;
    }

    let expr_sp, inl_sp = extract_node_inlined_let_wt(db, stmt, rhs_text);
    push_local_binding_wt(ctx, LocalBindingWt {
        name:         put_text(db, var_name),
        expr:         expr_sp,
        inlined_from: inl_sp,
        span:         stmt_span,
        ..
    });
}

fn is_std_container_method_wt(name: const u8[:]) -> bool {
    if name == "push" || name == "pop" || name == "clear" || name == "resize" || name == "append" { return true; }
    if name == "try_push" || name == "try_append" || name == "try_set" || name == "copy_from" { return true; }
    if name == "len" || name == "cap" || name == "reset" || name == "close" { return true; }
    if name == "set_header" || name == "append_header" || name == "add_header" || name == "set_or_replace" { return true; }
    if name == "remove_header" || name == "remove_header_by_name" { return true; }
    if name == "zeroize_jar_key_slot" || name == "sample_gcra_jitter_ns" { return true; }
    return name == "reset_for_keep_alive" || name == "compact_wire_buffer";
}

fn check_unmapped_mut_call_wt(
    db:          CompilerDb&,
    ctx:         WireTraceCtx&,
    callee_name: const u8[:],
    recv:        const u8[:],
    args:        const u8[:],
    stmt:        i32,
) {
    let short_name = strip_ns_prefix(callee_name);
    guard !is_std_container_method_wt(short_name) else { return; }
    let sp = if stmt >= 0 && stmt < db.nodes.len { db.nodes[stmt].span } else { ctx.fn_name };
    var sym_id = find_symbol_near(db, sp.file_id, callee_name);
    if sym_id < 0 {
        sym_id = find_symbol_near(db, sp.file_id, short_name);
    }
    if sym_id >= 0 && sym_id < db.symbols.len && db.symbols[sym_id].decl_node >= 0 {
        return;
    }
    let arg0 = get_call_virtual_arg_wt(recv, args, 0);
    let arg1 = get_call_virtual_arg_wt(recv, args, 1);
    if is_mut_param_or_alias_wt(db, ctx, arg0) || is_mut_param_or_alias_wt(db, ctx, arg1) {
        var note: u8[>..] = [];
        note.push('`');
        note.append(text_of(db, ctx.fn_name));
        note.append("` calls unmapped `&` helper `");
        note.append(callee_name);
        note.append("`.");
        emit_hazard_item_wt(db, ctx, callee_name, "unmapped & call", note[..], sp);
    }
}

fn process_call_expr_str_wt(
    db:         CompilerDb&,
    ctx:        WireTraceCtx&,
    intrinsics: const IntrinsicTable&,
    call_str:   const u8[:],
    cond_sp:    Span,
    stmt:       i32,
    op_span:    Span,
) {
    let recv, callee_name, args, ok = split_call_parts_wt(call_str);
    guard ok else { return; }
    let intr_idx = find_intrinsic(intrinsics, callee_name);
    if intr_idx >= 0 && intr_idx < intrinsics.entries.len {
        let intr = intrinsics.entries[intr_idx];
        let _, _ = record_intrinsic_wire_op_wt(db, ctx, intr, recv, args, cond_sp, "", op_span);
        return;
    }
    check_unmapped_mut_call_wt(db, ctx, callee_name, recv, args, stmt);
}

fn handle_guard_stmt_wt(
    db:         CompilerDb&,
    ctx:        WireTraceCtx&,
    intrinsics: const IntrinsicTable&,
    stmt:       i32,
    cond_sp:    Span,
    op_span:    Span,
) {
    let raw = trim_ascii_ws(text_of(db, db.nodes[stmt].span));
    let after_guard = if slice_starts_with(raw, "guard ") { trim_ascii_ws(raw[6..]) } else { raw };
    let gcond, _, has_else = inl_split_guard_else(after_guard);
    let cond_part = if has_else {
        gcond
    } else {
        let cp, _, _ = split_at_str(after_guard, " else");
        cp
    };
    var rest = trim_ascii_ws(cond_part);
    for step in 16 {
        guard rest.len > 0 else { return; }
        let head, tail, has_and = inl_split_top_level(rest, "&&");
        let clause = trim_ascii_ws(if has_and { head } else { rest });
        process_call_expr_str_wt(db, ctx, intrinsics, clause, cond_sp, stmt, op_span);
        if !has_and {
            return;
        }
        rest = trim_ascii_ws(tail);
    }
}

fn update_wire_target_for_var_wt(
    db:          CompilerDb&,
    ctx:         const WireTraceCtx&,
    struct_name: const u8[:],
    field_name:  const u8[:],
    val_expr:    const u8[:],
) {
    let loc_idx = find_local_binding_wt(db, ctx, trim_ascii_ws(val_expr));
    guard loc_idx >= 0 && loc_idx < ctx.locals.len else { return; }
    let widx = ctx.locals[loc_idx].wire_op_idx;
    guard widx >= 0 && widx < db.wire_ops.len else { return; }
    var target: u8[>..] = [];
    if struct_name.len > 0 {
        target.append(struct_name);
        target.push('.');
    }
    target.append(trim_ascii_ws(field_name));
    db.wire_ops[widx].target_text = put_text(db, target[..]);
}

// Scans a struct literal expression and updates wire operation target fields.
//
// Example:
//   raw = "return QuicFrame { offset: largest_acked }"
//   updates `Read#0.target_text` to "QuicFrame.offset"
fn scan_struct_lit_targets_wt(db: CompilerDb&, ctx: const WireTraceCtx&, raw: const u8[:]) {
    let before_brace, inside_raw, has_brace = split_at_str(raw, "{");
    guard has_brace else { return; }
    let body, _, _ = split_at_str(inside_raw, "}");
    let head = trim_ascii_ws(before_brace);
    let after_ret = if slice_starts_with(head, "return ") { trim_ascii_ws(head[7..]) } else { head };
    var rest = trim_ascii_ws(body);
    for step in 32 {
        guard rest.len > 0 else { return; }
        let entry, tail, has_comma = split_at_str(rest, ",");
        let fname, fval, has_colon = split_at_str(entry, ":");
        if has_colon {
            update_wire_target_for_var_wt(db, ctx, after_ret, fname, fval);
        }
        if !has_comma {
            return;
        }
        rest = trim_ascii_ws(tail);
    }
}

fn assign_parts_of_stmt_wt(db: const CompilerDb&, stmt: i32) -> const u8[:], const u8[:], bool {
    let node = db.nodes[stmt];
    let raw = strip_trailing_semi_wt(text_of(db, node.span));
    if node.kind == AstKind.AssignStmt && node.aux_span.len > 0 && slice_find(raw, "=") < 0 {
        return raw, strip_trailing_semi_wt(text_of(db, node.aux_span)), true;
    }
    return split_at_str(raw, "=");
}

fn call_text_of_stmt_wt(db: const CompilerDb&, stmt: i32) -> const u8[:] {
    let node = db.nodes[stmt];
    if (node.kind == AstKind.CallExpr || node.kind == AstKind.UfcsCallExpr) && node.aux_span.len > 0 {
        return strip_trailing_semi_wt(text_of(db, node.aux_span));
    }
    let raw = strip_trailing_semi_wt(text_of(db, node.span));
    if slice_starts_with(raw, "return ") {
        return trim_ascii_ws(raw[7..]);
    }
    return raw;
}

fn handle_assign_or_return_stmt_wt(
    db:         CompilerDb&,
    ctx:        WireTraceCtx&,
    intrinsics: const IntrinsicTable&,
    stmt:       i32,
    cond_sp:    Span,
    op_span:    Span,
) {
    let raw = call_text_of_stmt_wt(db, stmt);
    if slice_find(raw, "{") >= 0 && slice_find(raw, ":") >= 0 {
        scan_struct_lit_targets_wt(db, ctx, raw);
        return;
    }
    let lhs, rhs, has_eq = assign_parts_of_stmt_wt(db, stmt);
    if has_eq && slice_find(lhs, ".") >= 0 {
        let obj, field, ok_dot = split_at_str(trim_ascii_ws(lhs), ".");
        if ok_dot {
            let psym = find_param_sym_by_name_wt(db, ctx.fn_spec_id, trim_ascii_ws(obj));
            let st_name = if psym >= 0 && psym < db.symbols.len {
                let base, _ = strip_ref_suffix(trim_ascii_ws(text_of(db, db.symbols[psym].type_span)));
                base
            } else {
                trim_ascii_ws(obj)
            };
            update_wire_target_for_var_wt(db, ctx, st_name, field, rhs);
        }
        return;
    }
    var rest = trim_ascii_ws(raw);
    for step in 16 {
        guard rest.len > 0 else { return; }
        let head, tail, has_and = inl_split_top_level(rest, "&&");
        let clause = trim_ascii_ws(if has_and { head } else { rest });
        process_call_expr_str_wt(db, ctx, intrinsics, clause, cond_sp, stmt, op_span);
        if !has_and {
            return;
        }
        rest = trim_ascii_ws(tail);
    }
}

// Extracts the condition text from an `IfStmt` node.
//
// Example:
//   if_node = IfStmt(span="flags.with_offset")
//   returns: "flags.with_offset"
fn extract_if_cond_str_wt(db: const CompilerDb&, if_node: i32) -> const u8[:] {
    let raw = trim_ascii_ws(text_of(db, db.nodes[if_node].span));
    let after_if = if slice_starts_with(raw, "if ") { trim_ascii_ws(raw[3..]) } else { raw };
    let cond_str, _, _ = split_at_str(after_if, "{");
    return trim_ascii_ws(cond_str);
}

fn negate_if_cond_wt(cstr: const u8[:], out: u8[>..]&) {
    let s = trim_ascii_ws(cstr);
    guard s.len > 0 else { return; }
    if slice_find(s, "||") >= 0 || slice_find(s, "&&") >= 0 {
        out.append("!(");
        out.append(s);
        out.append(")");
        return;
    }
    let l1, r1, ok_gt = split_at_str(s, " > ");
    if ok_gt {
        out.append(l1);
        out.append(" <= ");
        out.append(r1);
        return;
    }
    let l2, r2, ok_lt = split_at_str(s, " < ");
    if ok_lt {
        out.append(l2);
        out.append(" >= ");
        out.append(r2);
        return;
    }
    let l3, r3, ok_ge = split_at_str(s, " >= ");
    if ok_ge {
        out.append(l3);
        out.append(" < ");
        out.append(r3);
        return;
    }
    let l4, r4, ok_le = split_at_str(s, " <= ");
    if ok_le {
        out.append(l4);
        out.append(" > ");
        out.append(r4);
        return;
    }
    let l5, r5, ok_eq = split_at_str(s, " == ");
    if ok_eq {
        out.append(l5);
        out.append(" != ");
        out.append(r5);
        return;
    }
    let l6, r6, ok_ne = split_at_str(s, " != ");
    if ok_ne {
        out.append(l6);
        out.append(" == ");
        out.append(r6);
        return;
    }
    if slice_starts_with(s, "!") {
        out.append(trim_ascii_ws(s[1..]));
        return;
    }
    out.append("!");
    out.append(s);
}

fn block_has_direct_return_wt(db: const CompilerDb&, blk: i32) -> bool {
    guard blk >= 0 && blk < db.nodes.len else { return false; }
    if db.nodes[blk].kind == AstKind.ReturnStmt {
        return true;
    }
    var cur = db.nodes[blk].first;
    for step in 64 {
        guard cur >= 0 && cur < db.nodes.len else { return false; }
        if db.nodes[cur].kind == AstKind.ReturnStmt {
            return true;
        }
        cur = db.nodes[cur].next;
    }
    return false;
}

fn append_preceding_early_return_ifs_wt(db: const CompilerDb&, blk: i32, stop_child: i32, out: u8[>..]&) {
    guard blk >= 0 && blk < db.nodes.len else { return; }
    var cur = db.nodes[blk].first;
    for step in 64 {
        if cur < 0 || cur >= db.nodes.len || cur == stop_child { return; }
        if db.nodes[cur].kind == AstKind.IfStmt {
            let cnode = db.nodes[cur].first;
            let tnode = if cnode >= 0 && cnode < db.nodes.len { db.nodes[cnode].next } else { -1 };
            let enode = if tnode >= 0 && tnode < db.nodes.len { db.nodes[tnode].next } else { -1 };
            let cstr = extract_if_cond_str_wt(db, cur);
            if enode < 0 && cstr.len > 0 && block_has_direct_return_wt(db, tnode) {
                if out.len > 0 { out.append(" && "); }
                negate_if_cond_wt(cstr, out);
            }
        }
        cur = db.nodes[cur].next;
    }
}

fn active_cond_for_stmt_wt(
    db:        CompilerDb&,
    root:      i32,
    stmt:      i32,
    always_sp: Span,
) -> Span, Span {
    let stmt_sp = if stmt >= 0 && stmt < db.nodes.len { db.nodes[stmt].span } else { always_sp };
    guard stmt >= 0 && stmt < db.nodes.len else { return always_sp, stmt_sp; }
    var child = stmt;
    var p = db.nodes[stmt].parent;
    var early_neg: u8[>..] = [];
    for climb in 16 {
        if p < 0 || p >= db.nodes.len {
            break;
        }
        if db.nodes[p].kind == AstKind.Block {
            append_preceding_early_return_ifs_wt(db, p, child, early_neg);
        }
        if p == root {
            break;
        }
        if db.nodes[p].kind == AstKind.IfStmt {
            let cond_node = db.nodes[p].first;
            let then_node = if cond_node >= 0 && cond_node < db.nodes.len { db.nodes[cond_node].next } else { -1 };
            let else_node = if then_node >= 0 && then_node < db.nodes.len { db.nodes[then_node].next } else { -1 };
            let cstr = extract_if_cond_str_wt(db, p);
            if child == then_node && cstr.len > 0 {
                var full_buf: u8[>..] = [];
                let gp = db.nodes[p].parent;
                if gp >= 0 && gp < db.nodes.len && db.nodes[gp].kind == AstKind.IfStmt {
                    let gp_cstr = extract_if_cond_str_wt(db, gp);
                    if gp_cstr.len > 0 {
                        negate_if_cond_wt(gp_cstr, full_buf);
                        full_buf.append(" && ");
                    }
                }
                if early_neg.len > 0 {
                    full_buf.append(early_neg[..]);
                    full_buf.append(" && ");
                }
                full_buf.append(cstr);
                return put_text(db, full_buf[..]), span_union_wt(db, db.nodes[p].span, stmt_sp);
            }
            if child == else_node && cstr.len > 0 {
                var neg_buf: u8[>..] = [];
                let gp = db.nodes[p].parent;
                if gp >= 0 && gp < db.nodes.len && db.nodes[gp].kind == AstKind.IfStmt {
                    let gp_cstr = extract_if_cond_str_wt(db, gp);
                    if gp_cstr.len > 0 {
                        negate_if_cond_wt(gp_cstr, neg_buf);
                        neg_buf.append(" && ");
                    }
                }
                negate_if_cond_wt(cstr, neg_buf);
                if early_neg.len > 0 {
                    neg_buf.append(" && ");
                    neg_buf.append(early_neg[..]);
                }
                return put_text(db, neg_buf[..]), span_union_wt(db, db.nodes[p].span, stmt_sp);
            }
        }
        child = p;
        p = db.nodes[p].parent;
    }
    if early_neg.len > 0 {
        return put_text(db, early_neg[..]), stmt_sp;
    }
    return always_sp, stmt_sp;
}

fn is_container_stmt_wt(k: AstKind) -> bool {
    return k == AstKind.Block
        || k == AstKind.IfStmt
        || k == AstKind.MatchStmt
        || k == AstKind.MatchArm
        || k == AstKind.ForStmt
        || k == AstKind.WhileStmt;
}

fn next_stmt_node_wt(db: const CompilerDb&, root: i32, cur: i32, descend: bool) -> i32 {
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

fn dispatch_leaf_stmt_wt(
    db:         CompilerDb&,
    ctx:        WireTraceCtx&,
    intrinsics: const IntrinsicTable&,
    cur:        i32,
    cond_sp:    Span,
    op_span:    Span,
) {
    let k = db.nodes[cur].kind;
    if k == AstKind.LetDecl {
        handle_let_stmt_wt(db, ctx, intrinsics, cur, cond_sp);
        return;
    }
    if k == AstKind.GuardStmt {
        handle_guard_stmt_wt(db, ctx, intrinsics, cur, cond_sp, op_span);
        return;
    }
    if k == AstKind.UnresolvedHazard {
        emit_hazard_item_wt(
            db,
            ctx,
            text_of(db, db.nodes[cur].span),
            "syntax hazard",
            "Unresolved AST construct.",
            db.nodes[cur].span,
        );
        return;
    }
    if k == AstKind.ReturnStmt || k == AstKind.AssignStmt || k == AstKind.CallExpr || k == AstKind.UfcsCallExpr {
        handle_assign_or_return_stmt_wt(db, ctx, intrinsics, cur, cond_sp, op_span);
    }
}

fn walk_stmt_block_wt(
    db:         CompilerDb&,
    ctx:        WireTraceCtx&,
    intrinsics: const IntrinsicTable&,
    block_node: i32,
    always_sp:  Span,
) {
    guard block_node >= 0 && block_node < db.nodes.len else { return; }
    var cur = db.nodes[block_node].first;
    for step in db.nodes.len {
        guard cur >= 0 && cur < db.nodes.len else { return; }
        let k = db.nodes[cur].kind;
        let container = is_container_stmt_wt(k);
        if !container {
            let cond_sp, op_sp = active_cond_for_stmt_wt(db, block_node, cur, always_sp);
            dispatch_leaf_stmt_wt(db, ctx, intrinsics, cur, cond_sp, op_sp);
        }
        cur = next_stmt_node_wt(db, block_node, cur, container);
    }
}

fn is_var_guarded_in_spec_wt(
    db:         const CompilerDb&,
    fn_spec_id: i32,
    body_text:  const u8[:],
    var_name:   const u8[:],
) -> bool {
    let spec = db.specs[fn_spec_id];
    for i in spec.guard_count {
        let gidx = add_i32(spec.guard_start, i);
        if gidx >= 0 && gidx < db.guards.len {
            let lhs = text_of(db, db.guards[gidx].lhs_text);
            let rhs = text_of(db, db.guards[gidx].rhs_text);
            if slice_find(lhs, var_name) >= 0 || slice_find(rhs, var_name) >= 0 {
                return true;
            }
        }
    }
    var pat_le: u8[>..] = [];
    pat_le.append(var_name);
    pat_le.append(" <");
    var pat_ge: u8[>..] = [];
    pat_ge.append(var_name);
    pat_ge.append(" >");
    var pat_eq: u8[>..] = [];
    pat_eq.append(var_name);
    pat_eq.append(" ==");
    return slice_find(body_text, pat_le[..]) >= 0
        || slice_find(body_text, pat_ge[..]) >= 0
        || slice_find(body_text, pat_eq[..]) >= 0;
}

fn single_line_span_wt(sp: Span) -> Span {
    return Span {
        file_id: sp.file_id,
        at:      sp.at,
        len:     0,
        line:    sp.line,
        col:     sp.col,
    };
}

fn check_stream_id_and_offset_flags_wt(
    db:        CompilerDb&,
    ctx:       const WireTraceCtx&,
    body_text: const u8[:],
    w_start:   i32,
    w_count:   i32,
) {
    let fn_str = text_of(db, ctx.fn_name);
    let sid_sym = find_param_sym_by_name_wt(db, ctx.fn_spec_id, "stream_id");
    if sid_sym >= 0 && slice_find(body_text, "stream_id <=") >= 0 && slice_find(body_text, "stream_id & 0x03") < 0 {
        var note: u8[>..] = [];
        note.push('`');
        note.append(fn_str);
        note.append("` does not check `stream_id & 0x03` direction bits.");
        db.unchecked.push(UncheckedItem {
            kind:        UncheckedKind.UnconstrainedInput,
            item_text:   put_text(db, "stream_id & 0x03"),
            domain_text: put_text(db, "0x00..0x03"),
            note_text:   put_text(db, note[..]),
            span:        single_line_span_wt(db.specs[ctx.fn_spec_id].span),
        });
    }
    for i in w_count {
        let widx = add_i32(w_start, i);
        if widx >= 0 && widx < db.wire_ops.len {
            let op = db.wire_ops[widx];
            if text_of(db, op.cond_text) == "flags.with_offset" && text_of(db, op.val_expr_text) == "offset" {
                var note2: u8[>..] = [];
                note2.append("If `flags.with_offset` is `false`, `");
                note2.append(fn_str);
                note2.append("` omits `Write#");
                format_int(note2, op.seq_index, 10, 0, ' ');
                note2.append("` even when `offset > 0`.");
                db.unchecked.push(UncheckedItem {
                    kind:        UncheckedKind.UnconstrainedInput,
                    item_text:   put_text(db, "flags.with_offset"),
                    domain_text: put_text(db, "false when offset > 0"),
                    note_text:   put_text(db, note2[..]),
                    span:        single_line_span_wt(op.span),
                });
            }
        }
    }
}

fn check_unconstrained_read_locals_wt(
    db:        CompilerDb&,
    ctx:       const WireTraceCtx&,
    body_text: const u8[:],
) {
    let fn_str = text_of(db, ctx.fn_name);
    for i in ctx.locals.len {
        let loc = ctx.locals[i];
        let vname = text_of(db, loc.name);
        if loc.is_read_local && !is_var_guarded_in_spec_wt(db, ctx.fn_spec_id, body_text, vname) {
            var note: u8[>..] = [];
            note.push('`');
            note.append(fn_str);
            note.append("` does not check `");
            note.append(vname);
            note.append("` bounds.");
            db.unchecked.push(UncheckedItem {
                kind:        UncheckedKind.UnconstrainedInput,
                item_text:   loc.name,
                domain_text: loc.domain,
                note_text:   put_text(db, note[..]),
                span:        loc.span,
            });
        }
    }
}

fn analyze_wire_trace(db: CompilerDb&, fn_spec_id: i32, intrinsics: IntrinsicTable&) -> bool {
    guard fn_spec_id >= 0 && fn_spec_id < db.specs.len else { return false; }
    let fn_sym = db.specs[fn_spec_id].fn_sym;
    guard fn_sym >= 0 && fn_sym < db.symbols.len else { return false; }

    let w_start = db.wire_ops.len as i32;
    let u_start = db.unchecked.len as i32;
    db.specs[fn_spec_id].wire_start = w_start;
    db.specs[fn_spec_id].wire_count = 0;
    db.specs[fn_spec_id].unchecked_start = u_start;
    db.specs[fn_spec_id].unchecked_count = 0;

    let decl_node = db.symbols[fn_sym].decl_node;
    guard decl_node >= 0 && decl_node < db.nodes.len else { return true; }

    var ctx = WireTraceCtx {
        fn_spec_id: fn_spec_id,
        fn_sym:     fn_sym,
        fn_name:    db.symbols[fn_sym].name_span,
        ..
    };
    let always_sp = put_text(db, "always");
    let body_node = find_fn_body_node_wt(db, decl_node);
    walk_stmt_block_wt(db, ctx, intrinsics, body_node, always_sp);

    let w_count = sub_i32(db.wire_ops.len as i32, w_start);
    db.specs[fn_spec_id].wire_count = w_count;

    let body_text = text_of(db, db.nodes[body_node].span);
    check_stream_id_and_offset_flags_wt(db, ctx, body_text, w_start, w_count);
    check_unconstrained_read_locals_wt(db, ctx, body_text);

    db.specs[fn_spec_id].unchecked_count = sub_i32(db.unchecked.len as i32, u_start);
    return true;
}

fn analyze_all_wire_traces(db: CompilerDb&, intrinsics: IntrinsicTable&) -> bool {
    for i in db.specs.len {
        guard analyze_wire_trace(db, i as i32, intrinsics) else { return false; }
    }
    return true;
}
