// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// ASD-STE100 Markdown and .sm.md specification emitter.

import std;
import db from "../model";
import loader from "../config";

fn utf8_col_count(s: const u8[:]) -> i64 {
    var n: i64 = 0;
    for c in s {
        if (c & 0xC0) != 0x80 {
            n = inc_i64(n);
        }
    }
    return n;
}

fn skip_spaces(s: const u8[:], from: i64) -> i64 {
    guard from >= 0 && from < s.len else { return s.len; }
    for c, idx in s[from..] {
        if c != ' ' && c != '\t' {
            return add_i64(from, idx);
        }
    }
    return s.len;
}

fn can_start_wrapped_line(rest: const u8[:]) -> bool {
    guard rest.len > 0 else { return false; }
    let c = rest[0];
    if c == '#' || c == '>' || c == '|' || c == '+' || c == '-' || c == '*' || c == '_' {
        return false;
    }
    return true;
}

// Finds the 80-column word-wrap split index outside backticked code spans.
//
// Example:
//   rem = "R1: `stream_id` must be at most `0x3fff`.", prefix_cols = 2
//   returns: -1, -1 when total columns <= 80
fn find_wrap_split(rem: const u8[:], prefix_cols: i64) -> i64, i64 {
    guard add_i64(prefix_cols, utf8_col_count(rem)) > 80 else { return -1, -1; }
    var code_ticks: i32  = 0;
    var skip_tick:  bool = false;
    var cols = prefix_cols;
    var best_k:  i64 = -1;
    var first_k: i64 = -1;
    for c, idx in rem {
        if skip_tick {
            skip_tick = false;
            cols = inc_i64(cols);
            continue;
        }
        let next_w = skip_spaces(rem, idx);
        if code_ticks == 0 && c == ' ' && can_start_wrapped_line(rem[next_w..]) {
            if cols <= 80 {
                best_k = idx;
            } else if first_k < 0 {
                first_k = idx;
                break;
            }
        }
        if c == '`' {
            let is_dbl = inc_i64(idx) < rem.len && rem[inc_i64(idx)] == '`';
            if is_dbl {
                skip_tick = true;
                if code_ticks == 0 {
                    code_ticks = 2;
                } else if code_ticks == 2 {
                    code_ticks = 0;
                }
            } else if code_ticks == 0 {
                code_ticks = 1;
            } else if code_ticks == 1 {
                code_ticks = 0;
            }
        }
        if (c & 0xC0) != 0x80 {
            cols = inc_i64(cols);
        }
    }
    let split_k = if best_k >= 0 { best_k } else { first_k };
    guard split_k >= 0 else { return -1, -1; }
    return split_k, skip_spaces(rem, split_k);
}

fn collapse_ws_to_single_line(raw: const u8[:], out: u8[>..]&) {
    out.clear();
    var prev_space = true;
    for c in raw {
        let is_ws = c == ' ' || c == '\t' || c == '\n' || c == '\r';
        if is_ws {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(c);
            prev_space = false;
        }
    }
    if out.len > 0 && out[dec_i64(out.len)] == ' ' {
        out.pop();
    }
}

fn emit_flow_wrapped(out: u8[>..]&, text: const u8[:], prefix1: const u8[:], prefix2: const u8[:]) {
    var single: u8[>..] = [];
    collapse_ws_to_single_line(text, single);
    let clean = trim_ascii_ws(single[..]);
    guard clean.len > 0 else { return; }
    var rem = clean;
    var is_first = true;
    for step in clean.len {
        let pfx = if is_first { prefix1 } else { prefix2 };
        let pfx_cols = utf8_col_count(pfx);
        let split_k, next_w = find_wrap_split(rem, pfx_cols);
        if split_k < 0 || split_k >= rem.len || next_w >= rem.len {
            out.append(pfx);
            out.append(trim_ascii_ws(rem));
            out.push('\n');
            return;
        }
        out.append(pfx);
        out.append(trim_ascii_ws(rem[..split_k]));
        out.push('\n');
        rem = rem[next_w..];
        is_first = false;
    }
}

fn primary_target_path(db: const CompilerDb&) -> const u8[:] {
    for i in db.files.len {
        if db.files[i].is_target {
            let p = file_path_of(db, i as i32);
            if p.len > 0 {
                return p;
            }
        }
    }
    if db.specs.len > 0 {
        let p = file_path_of(db, db.specs[0].span.file_id);
        if p.len > 0 {
            return p;
        }
    }
    if db.files.len > 0 {
        return file_path_of(db, 0);
    }
    return "module.goose";
}

fn spec_fn_name(db: const CompilerDb&, spec: SpecFunction) -> const u8[:] {
    if spec.fn_sym >= 0 && spec.fn_sym < db.symbols.len {
        let name = text_of(db, db.symbols[spec.fn_sym].name_span);
        if name.len > 0 {
            return name;
        }
    }
    let fallback = text_of(db, spec.span);
    if fallback.len > 0 {
        return fallback;
    }
    return "unknown_fn";
}

fn count_newlines(s: const u8[:]) -> i32 {
    var n: i32 = 0;
    for c in s {
        if c == '\n' {
            n = inc_i32(n);
        }
    }
    return n;
}

fn append_inlined_suffix<B>(db: const CompilerDb&, inlined_from: Span, out: B&) {
    let inl = trim_ascii_ws(text_of(db, inlined_from));
    guard inl.len > 0 else { return; }
    if slice_starts_with(inl, "(") {
        out.push(' ');
        out.append(inl);
        return;
    }
    out.append(" (inlined from ");
    out.append(inl);
    if slice_find(inl, ":") < 0 && inlined_from.line > 0 {
        out.push(':');
        format(out, inlined_from.line);
    }
    out.push(')');
}

fn format_source_anchor<B>(db: const CompilerDb&, span: Span, inlined_from: Span, out: B&) {
    out.clear();
    let raw = trim_ascii_ws(text_of(db, span));
    let fpath = file_path_of(db, span.file_id);
    if span.line <= 0 {
        out.append(if raw.len > 0 { raw } else { fpath });
        append_inlined_suffix(db, inlined_from, out);
        return;
    }
    if slice_starts_with(raw, fpath) && slice_find(raw, ":") >= 0 {
        out.append(raw);
        append_inlined_suffix(db, inlined_from, out);
        return;
    }
    out.append(fpath);
    out.push(':');
    format(out, span.line);
    let nl = count_newlines(raw);
    if nl > 0 {
        out.push('-');
        format(out, add_i32(span.line, nl));
    }
    append_inlined_suffix(db, inlined_from, out);
}

// Escapes unescaped table pipe characters (`|`) as `\|` and collapses newlines inside Markdown table cells.
//
// Example:
//   s = "0x08 | 0x04"
//   appends: "0x08 \| 0x04"
fn escape_table_pipes(out: u8[>..]&, s: const u8[:]) {
    var single: u8[>..] = [];
    collapse_ws_to_single_line(s, single);
    var prev_slash = false;
    for c in single[..] {
        if c == '|' && !prev_slash {
            out.append("\\|");
        } else {
            out.push(c);
        }
        prev_slash = c == '\\' && !prev_slash;
    }
}

fn append_code_cell(out: u8[>..]&, s: const u8[:], fallback: const u8[:]) {
    let clean = trim_ascii_ws(s);
    let body = if clean.len > 0 { clean } else { fallback };
    if slice_find(body, "`") >= 0 {
        if slice_find(body, "``") >= 0 {
            escape_table_pipes(out, body);
            return;
        }
        out.append("``");
        if body[0] == '`' {
            out.push(' ');
        }
        escape_table_pipes(out, body);
        if body[dec_i64(body.len)] == '`' {
            out.push(' ');
        }
        out.append("``");
        return;
    }
    out.push('`');
    escape_table_pipes(out, body);
    out.push('`');
}

fn emit_param_row(db: const CompilerDb&, sym: Symbol, out: u8[>..]&) {
    let pname = text_of(db, sym.name_span);
    let ptype = text_of(db, sym.type_span);
    let mode = if sym.is_ref_mut { "in_out" } else { "in" };
    let sclass = val_type_size_class(sym.val_type, sym.is_ref_mut, ptype);
    out.append("| ");
    append_code_cell(out, pname, "param");
    out.append(" | ");
    append_code_cell(out, ptype, "unknown");
    out.append(" | ");
    append_code_cell(out, mode, "in");
    out.append(" | ");
    escape_table_pipes(out, sclass);
    out.append(" |\n");
}

fn emit_signature_block(db: const CompilerDb&, spec: SpecFunction, fn_name: const u8[:], out: u8[>..]&) {
    format(out, "### 1. Signature of `", fn_name, "`\n\n");
    out.append("| parameter | type | mode | size class |\n");
    out.append("| --- | --- | --- | --- |\n");
    for i in spec.param_count {
        let idx = add_i32(spec.param_start, i);
        if idx >= 0 && idx < db.symbols.len {
            emit_param_row(db, db.symbols[idx], out);
        }
    }
    let ret_t = trim_ascii_ws(text_of(db, spec.ret_type_text));
    let ret_str = if ret_t.len > 0 { ret_t } else { "bool" };
    let ret_desc = if ret_str == "void" {
        "no return value"
    } else if slice_find(ret_str, "bool") >= 0 {
        "`true` on commit, `false` on reject"
    } else {
        "computed return value"
    };
    out.append("| `return` | ");
    append_code_cell(out, ret_str, "bool");
    out.append(" | `out` | ");
    out.append(ret_desc);
    out.append(" |\n\n");
}

fn wire_op_label(kind: WireOpKind) -> const u8[:] {
    return match kind {
        ReadOp => "Read#",
        WriteOp => "Write#",
        RollbackOp => "Rollback#",
        SatMathOp => "SatMath#",
    };
}

fn emit_wire_row(db: const CompilerDb&, op: WireOp, out: u8[>..]&) {
    var op_buf:  u8[..32] = [];
    var src_buf: u8[>..]  = [];
    format(op_buf, wire_op_label(op.kind), op.seq_index);
    format_source_anchor(db, op.span, op.inlined_from, src_buf);

    out.append("| ");
    append_code_cell(out, op_buf[..], "Read#0");
    out.append(" | ");
    append_code_cell(out, text_of(db, op.cond_text), "always");
    out.append(" | ");
    append_code_cell(out, text_of(db, op.encoding_text), "raw");
    out.append(" | ");
    append_code_cell(out, text_of(db, op.val_expr_text), "-");
    out.append(" | ");
    append_code_cell(out, text_of(db, op.target_text), "-");
    out.append(" | ");
    append_code_cell(out, src_buf[..], "-");
    out.append(" |\n");
}

fn emit_wire_block(db: const CompilerDb&, spec: SpecFunction, fn_name: const u8[:], out: u8[>..]&) {
    format(out, "### 2. Entry context and wire operations of `", fn_name, "`\n\n");
    var scratch: u8[>..] = [];
    let ctx = trim_ascii_ws(text_of(db, spec.entry_ctx_text));
    if ctx.len > 0 {
        emit_flow_wrapped(out, ctx, "", "");
    } else {
        format(scratch, "Direct callers of `", fn_name, "` can pass any parameter value.");
        emit_flow_wrapped(out, scratch[..], "", "");
    }
    out.push('\n');
    if spec.wire_count <= 0 {
        scratch.clear();
        format(scratch, "`", fn_name, "` does not read or write wire bytes directly.");
        emit_flow_wrapped(out, scratch[..], "", "");
        out.push('\n');
        return;
    }
    out.append("| wire op | condition | encoding | value expression | target | source |\n");
    out.append("| --- | --- | --- | --- | --- | --- |\n");
    for i in spec.wire_count {
        let idx = add_i32(spec.wire_start, i);
        if idx >= 0 && idx < db.wire_ops.len {
            emit_wire_row(db, db.wire_ops[idx], out);
        }
    }
    out.push('\n');
}

fn upgrade_backtick_span(expr: const u8[:], line_buf: u8[>..]&) {
    guard expr.len > 0 && slice_find(expr, "`") >= 0 && slice_find(expr, "``") < 0 else { return; }
    var old_sp: u8[>..] = [];
    old_sp.push('`');
    old_sp.append(expr);
    old_sp.push('`');
    var new_sp: u8[>..] = [];
    new_sp.append("``");
    if expr[0] == '`' {
        new_sp.push(' ');
    }
    new_sp.append(expr);
    if expr[dec_i64(expr.len)] == '`' {
        new_sp.push(' ');
    }
    new_sp.append("``");
    var out: u8[>..] = [];
    format_replaced(out, line_buf[..], old_sp[..], new_sp[..]);
    line_buf.clear();
    line_buf.append(out[..]);
}

fn render_guard_item(
    db:        const CompilerDb&,
    templates: const TemplateTable&,
    g:         GuardRule,
    fallback:  i32,
    fn_name:   const u8[:],
    line_buf:  u8[>..]&,
) {
    var src_buf: u8[>..] = [];
    format_source_anchor(db, g.span, g.inlined_from, src_buf);
    let req_no = if g.req_index > 0 { g.req_index } else { fallback };
    var num_buf: u8[..16] = [];
    format(num_buf, req_no);
    let raw_id = trim_ascii_ws(text_of(db, g.template_id));
    let lhs_raw = trim_ascii_ws(text_of(db, g.lhs_text));
    let rhs_raw = trim_ascii_ws(text_of(db, g.rhs_text));
    var lhs_buf: u8[>..] = [];
    if slice_find(lhs_raw, "(") >= 0 && slice_find(lhs_raw, ",") >= 0 && !slice_starts_with(lhs_raw, "(") {
        format(lhs_buf, "(", lhs_raw, ")");
    }
    let lhs = if lhs_buf.len > 0 { lhs_buf[..] } else if lhs_raw.len > 0 { lhs_raw } else { "cond" };
    let rhs = if rhs_raw.len > 0 { rhs_raw } else { "0" };
    let tmpl_id = if raw_id.len > 0 { raw_id } else if rhs_raw.len == 0 { "REQ_PRED" } else { "REQ_MAX" };
    let ok = if tmpl_id == "REQ_PRED" {
        render_template(templates, "REQ_PRED", num_buf[..], lhs, fn_name, src_buf[..], "", line_buf)
    } else {
        render_template(templates, tmpl_id, num_buf[..], lhs, rhs, fn_name, src_buf[..], line_buf)
    };
    if !ok {
        format(line_buf, "- R", num_buf[..], ": `", lhs, "` must be `true`. If it is `false`, `", fn_name, "` returns `false`. — ", src_buf[..]);
    }
    upgrade_backtick_span(lhs, line_buf);
    upgrade_backtick_span(rhs, line_buf);
}

fn adjust_guard_return_phrase(ret_t: const u8[:], else_ret: const u8[:], line_buf: u8[>..]&) {
    let rt = trim_ascii_ws(ret_t);
    guard rt.len > 0 && slice_find(rt, "bool") < 0 else { return; }
    let head, tail, found = split_at_str(line_buf[..], " returns `false`.");
    guard found else { return; }
    let er = trim_ascii_ws(else_ret);
    var rep_buf: u8[>..] = [];
    if rt == "void" {
        rep_buf.append(" returns early.");
    } else if er.len > 0 && slice_find(er, "`") < 0 {
        rep_buf.append(" returns `");
        rep_buf.append(er);
        rep_buf.append("`.");
    } else {
        let is_int = rt == "u64" || rt == "i64" || rt == "u32" || rt == "i32"
            || rt == "u16" || rt == "i16" || rt == "u8" || rt == "i8";
        rep_buf.append(if is_int { " returns `0`." } else { " returns an error." });
    }
    var rebuilt: u8[>..] = [];
    rebuilt.append(head);
    rebuilt.append(rep_buf[..]);
    rebuilt.append(tail);
    line_buf.clear();
    line_buf.append(rebuilt[..]);
}

fn emit_requirements_block(
    db:        const CompilerDb&,
    templates: const TemplateTable&,
    spec:      SpecFunction,
    fn_name:   const u8[:],
    out:       u8[>..]&,
) {
    format(out, "### 3. Requirements of `", fn_name, "`\n\n");
    if spec.guard_count <= 0 {
        var empty_buf: u8[>..] = [];
        format(empty_buf, "`", fn_name, "` has no guard requirements.");
        emit_flow_wrapped(out, empty_buf[..], "", "");
        out.push('\n');
        return;
    }
    let ret_t = text_of(db, spec.ret_type_text);
    var line_buf: u8[>..] = [];
    for i in spec.guard_count {
        let idx = add_i32(spec.guard_start, i);
        if idx >= 0 && idx < db.guards.len {
            line_buf.clear();
            let fallback = add_i32(i, 1);
            let g = db.guards[idx];
            render_guard_item(db, templates, g, fallback, fn_name, line_buf);
            adjust_guard_return_phrase(ret_t, text_of(db, g.else_ret_text), line_buf);
            let body = if slice_starts_with(line_buf[..], "- ") { line_buf[2..] } else { line_buf[..] };
            emit_flow_wrapped(out, body, "- ", "  ");
        }
    }
    out.push('\n');
}

fn unchecked_kind_label(kind: UncheckedKind) -> const u8[:] {
    return match kind {
        UnconstrainedInput => "`UNCONSTRAINED_INPUT`",
        DiscardedWireField => "`DISCARDED_WIRE_FIELD`",
        UnresolvedAstHazard => "`[UNRESOLVED_AST_HAZARD]`",
    };
}

fn emit_unchecked_row(db: const CompilerDb&, u: UncheckedItem, fn_name: const u8[:], out: u8[>..]&) {
    var src_buf: u8[>..] = [];
    format_source_anchor(db, u.span, Span { .. }, src_buf);
    let item = trim_ascii_ws(text_of(db, u.item_text));
    let item_str = if item.len > 0 { item } else { "-" };
    let note = trim_ascii_ws(text_of(db, u.note_text));

    out.append("| ");
    out.append(unchecked_kind_label(u.kind));
    out.append(" | ");
    append_code_cell(out, item_str, "-");
    out.append(" | ");
    append_code_cell(out, text_of(db, u.domain_text), "any");
    out.append(" | ");
    if note.len > 0 {
        escape_table_pipes(out, note);
    } else {
        format(out, "`", fn_name, "` does not check `", item_str, "` bits.");
    }
    out.append(" | ");
    append_code_cell(out, src_buf[..], "-");
    out.append(" |\n");
}

fn emit_unchecked_block(db: const CompilerDb&, spec: SpecFunction, fn_name: const u8[:], out: u8[>..]&) {
    format(out, "### 4. Unchecked surface of `", fn_name, "`\n\n");
    if spec.unchecked_count <= 0 {
        var scratch: u8[>..] = [];
        format(scratch, "`", fn_name, "` has no unchecked wire fields or unmapped mutable calls.");
        emit_flow_wrapped(out, scratch[..], "", "");
        out.push('\n');
        return;
    }
    out.append("| category | item | domain | note | source |\n");
    out.append("| --- | --- | --- | --- | --- |\n");
    for i in spec.unchecked_count {
        let idx = add_i32(spec.unchecked_start, i);
        if idx >= 0 && idx < db.unchecked.len {
            emit_unchecked_row(db, db.unchecked[idx], fn_name, out);
        }
    }
    out.push('\n');
}

fn rollback_state_label(state: RollbackState) -> const u8[:] {
    return match state {
        Unmodified => "`UNMODIFIED`",
        TransactionalSelf => "`TRANSACTIONAL_SELF`",
        DirtySelfRestoredByCaller => "`DIRTY_SELF_RESTORED_BY_CALLER`",
        DirtyExposed => "`DIRTY_EXPOSED`",
    };
}

fn emit_effect_row(db: const CompilerDb&, ef: ParamEffect, fn_name: const u8[:], out: u8[>..]&) {
    var src_buf: u8[>..] = [];
    format_source_anchor(db, ef.span, Span { .. }, src_buf);
    let pname = if ef.param_sym >= 0 && ef.param_sym < db.symbols.len {
        text_of(db, db.symbols[ef.param_sym].name_span)
    } else {
        "param"
    };
    let mech = trim_ascii_ws(text_of(db, ef.mechanism_text));

    out.append("| ");
    append_code_cell(out, pname, "param");
    out.append(" | ");
    out.append(rollback_state_label(ef.state));
    out.append(" | ");
    if mech.len > 0 {
        escape_table_pipes(out, mech);
    } else {
        format(out, "`", fn_name, "` does not change `", pname, "` before any `return false` path.");
    }
    out.append(" | ");
    append_code_cell(out, src_buf[..], "-");
    out.append(" |\n");
}

fn emit_effects_block(db: const CompilerDb&, spec: SpecFunction, fn_name: const u8[:], out: u8[>..]&) {
    format(out, "### 5. Error side effects of `", fn_name, "`\n\n");
    if spec.effect_count <= 0 {
        var scratch: u8[>..] = [];
        format(scratch, "`", fn_name, "` takes no mutable reference parameters.");
        emit_flow_wrapped(out, scratch[..], "", "");
        out.push('\n');
        return;
    }
    out.append("| parameter | classification | mechanism | source |\n");
    out.append("| --- | --- | --- | --- |\n");
    for i in spec.effect_count {
        let idx = add_i32(spec.effect_start, i);
        if idx >= 0 && idx < db.effects.len {
            emit_effect_row(db, db.effects[idx], fn_name, out);
        }
    }
    out.push('\n');
}

fn emit_fsm_row(db: const CompilerDb&, row: FsmRow, out: u8[>..]&) {
    var src_buf: u8[>..] = [];
    format_source_anchor(db, row.span, Span { .. }, src_buf);
    let src_raw = trim_ascii_ws(text_of(db, row.source_text));
    let src_cell = if src_raw.len > 0 { src_raw } else { src_buf[..] };
    var req_buf: u8[..16] = [];
    let req_no = if row.req_id > 0 { row.req_id } else { 1 };
    format(req_buf, "R", req_no);

    out.append("| ");
    append_code_cell(out, text_of(db, row.state_text), "init");
    out.append(" | ");
    append_code_cell(out, text_of(db, row.event_text), "step");
    out.append(" | ");
    append_code_cell(out, text_of(db, row.guard_text), "always");
    out.append(" | ");
    append_code_cell(out, text_of(db, row.next_text), "done");
    out.append(" | ");
    out.append(req_buf[..]);
    out.append(" | ");
    append_code_cell(out, src_cell, "-");
    out.append(" |\n");
}

fn emit_machine_block(db: const CompilerDb&, spec: SpecFunction, fn_name: const u8[:], out: u8[>..]&) {
    guard spec.fsm_count > 0 else { return; }
    let first_idx = spec.fsm_start;
    let last_idx = add_i32(spec.fsm_start, dec_i32(spec.fsm_count));
    let init_st = if first_idx >= 0 && first_idx < db.fsm_rows.len {
        trim_ascii_ws(text_of(db, db.fsm_rows[first_idx].state_text))
    } else {
        "init"
    };
    let fin_st = if last_idx >= 0 && last_idx < db.fsm_rows.len {
        trim_ascii_ws(text_of(db, db.fsm_rows[last_idx].next_text))
    } else {
        "done"
    };
    format(out, "## Machine `", fn_name, "`\n\n");
    format(out, "initial: `", if init_st.len > 0 { init_st } else { "init" }, "`\n");
    format(out, "final: `", if fin_st.len > 0 { fin_st } else { "done" }, "`\n\n");
    out.append("| state | event | guard | next | req | source |\n");
    out.append("| --- | --- | --- | --- | --- | --- |\n");
    for i in spec.fsm_count {
        let idx = add_i32(spec.fsm_start, i);
        if idx >= 0 && idx < db.fsm_rows.len {
            emit_fsm_row(db, db.fsm_rows[idx], out);
        }
    }
    out.push('\n');
}

fn has_duplicate_spec_fn_name(db: const CompilerDb&, target_name: const u8[:]) -> bool {
    var matches: i32 = 0;
    for i in db.specs.len {
        if spec_fn_name(db, db.specs[i]) == target_name {
            matches = inc_i32(matches);
            if matches > 1 {
                return true;
            }
        }
    }
    return false;
}

fn format_heading_fn_name(db: const CompilerDb&, spec: SpecFunction, out: u8[>..]&) {
    out.clear();
    let base_name = spec_fn_name(db, spec);
    out.append(base_name);
    if has_duplicate_spec_fn_name(db, base_name) {
        out.push(':');
        format(out, max(spec.span.line, 1));
    }
}

fn emit_spec_function(
    db:        const CompilerDb&,
    cfg:       const Config&,
    templates: const TemplateTable&,
    spec:      SpecFunction,
    out:       u8[>..]&,
) {
    let fn_name = spec_fn_name(db, spec);
    var h_name_buf: u8[>..] = [];
    format_heading_fn_name(db, spec, h_name_buf);
    let h_name = h_name_buf[..];
    let fpath = file_path_of(db, spec.span.file_id);
    let start_ln = max(spec.span.line, 1);
    let end_ln = max(spec.end_line, start_ln);

    format(out, "## Function `", h_name, "`\n\n");
    var meta: u8[>..] = [];
    format(
        meta,
        "Source: `", fpath, ":", start_ln, "-", end_ln, "`. Completeness: `resolved_constants=",
        spec.resolved_constants, "; inlined_callees=", spec.inlined_callees,
        "; unanalyzed_statements=", spec.unanalyzed_statements, "`.",
    );
    emit_flow_wrapped(out, meta[..], "", "");
    out.push('\n');

    if has_section(cfg, "signature") {
        emit_signature_block(db, spec, h_name, out);
    }
    if has_section(cfg, "entry_context") || has_section(cfg, "wire_ops") {
        emit_wire_block(db, spec, h_name, out);
    }
    if has_section(cfg, "requirements") {
        emit_requirements_block(db, templates, spec, h_name, out);
    }
    if has_section(cfg, "unchecked_surface") {
        emit_unchecked_block(db, spec, h_name, out);
    }
    if has_section(cfg, "error_side_effects") {
        emit_effects_block(db, spec, h_name, out);
    }
    if spec.fsm_count > 0 && has_section(cfg, "machines") {
        emit_machine_block(db, spec, h_name, out);
    }
}

fn trim_trailing_blank_lines(out: u8[>..]&) {
    for step in out.len {
        guard out.len >= 2 else { return; }
        let last = dec_i64(out.len);
        let prev = sub_i64(out.len, 2);
        guard prev >= 0 && prev < out.len && last >= 0 && last < out.len else { return; }
        if out[last] == '\n' && out[prev] == '\n' {
            out.pop();
        } else {
            return;
        }
    }
}

fn emit_markdown_ste(db: CompilerDb&, cfg: Config&, templates: TemplateTable&, out: u8[>..]&) -> bool {
    out.clear();
    let target = primary_target_path(db);
    format(out, "# Specification of `", target, "`\n\n");
    var intro: u8[>..] = [];
    format(intro, "Module `", target, "` defines `", db.specs.len, "` protocol functions.");
    emit_flow_wrapped(out, intro[..], "", "");
    out.push('\n');

    for i in db.specs.len {
        emit_spec_function(db, cfg, templates, db.specs[i], out);
    }
    trim_trailing_blank_lines(out);
    return out.len > 0;
}
