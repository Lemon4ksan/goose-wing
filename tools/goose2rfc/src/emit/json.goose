// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Machine-readable JSON Spec-IR emitter.

import std;
import db from "../model";
import loader from "../config";

// Escapes a raw UTF-8 slice as a JSON string literal with surrounding quotes.
//
// Example:
//   s = "a\"b\\c"
//   appends: "\"a\\\"b\\\\c\""
fn json_quote_str(out: u8[>..]&, s: const u8[:]) {
    out.push('"');
    for c in s {
        if c == '"' {
            out.append("\\\"");
        } else if c == '\\' {
            out.append("\\\\");
        } else if c == '\n' {
            out.append("\\n");
        } else if c == '\r' {
            out.append("\\r");
        } else if c == '\t' {
            out.append("\\t");
        } else {
            out.push(c);
        }
    }
    out.push('"');
}

fn json_kv_str(out: u8[>..]&, indent: const u8[:], key: const u8[:], val: const u8[:], comma: bool) {
    out.append(indent);
    json_quote_str(out, key);
    out.append(": ");
    json_quote_str(out, val);
    out.append(if comma { ",\n" } else { "\n" });
}

fn json_kv_i32(out: u8[>..]&, indent: const u8[:], key: const u8[:], val: i32, comma: bool) {
    out.append(indent);
    json_quote_str(out, key);
    out.append(": ");
    format(out, val);
    out.append(if comma { ",\n" } else { "\n" });
}

fn json_kv_bool(out: u8[>..]&, indent: const u8[:], key: const u8[:], val: bool, comma: bool) {
    out.append(indent);
    json_quote_str(out, key);
    out.append(": ");
    out.append(if val { "true" } else { "false" });
    out.append(if comma { ",\n" } else { "\n" });
}

fn json_count_newlines(s: const u8[:]) -> i32 {
    var n: i32 = 0;
    for c in s {
        if c == '\n' {
            n = inc_i32(n);
        }
    }
    return n;
}

fn json_inlined_suffix<B>(db: const CompilerDb&, inlined_from: Span, out: B&) {
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

fn json_source_anchor<B>(db: const CompilerDb&, span: Span, inlined_from: Span, out: B&) {
    out.clear();
    let raw = trim_ascii_ws(text_of(db, span));
    let fpath = file_path_of(db, span.file_id);
    if span.line <= 0 {
        out.append(if raw.len > 0 { raw } else { fpath });
        json_inlined_suffix(db, inlined_from, out);
        return;
    }
    if slice_starts_with(raw, fpath) && slice_find(raw, ":") >= 0 {
        out.append(raw);
        json_inlined_suffix(db, inlined_from, out);
        return;
    }
    out.append(fpath);
    out.push(':');
    format(out, span.line);
    let nl = json_count_newlines(raw);
    if nl > 0 {
        out.push('-');
        format(out, add_i32(span.line, nl));
    }
    json_inlined_suffix(db, inlined_from, out);
}

fn json_fn_name(db: const CompilerDb&, spec: SpecFunction) -> const u8[:] {
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

fn emit_json_files(db: const CompilerDb&, out: u8[>..]&) {
    out.append("  \"files\": [\n");
    for i in db.files.len {
        let f = db.files[i];
        let fpath = file_path_of(db, i as i32);
        let ns = text_of(db, f.ns_span);
        let has_more = inc_i64(i) < db.files.len;
        out.append("    {\n");
        json_kv_str(out, "      ", "path", fpath, true);
        json_kv_str(out, "      ", "namespace", ns, true);
        json_kv_bool(out, "      ", "is_target", f.is_target, false);
        out.append(if has_more { "    },\n" } else { "    }\n" });
    }
    out.append("  ],\n");
}

fn emit_json_param(db: const CompilerDb&, sym: Symbol, has_more: bool, out: u8[>..]&) {
    let pname = text_of(db, sym.name_span);
    let ptype = text_of(db, sym.type_span);
    let mode = if sym.is_ref_mut { "in_out" } else { "in" };
    let sclass = val_type_size_class(sym.val_type, sym.is_ref_mut, ptype);
    out.append("        {\n");
    json_kv_str(out, "          ", "name", pname, true);
    json_kv_str(out, "          ", "type", ptype, true);
    json_kv_str(out, "          ", "mode", mode, true);
    json_kv_str(out, "          ", "size_class", sclass, false);
    out.append(if has_more { "        },\n" } else { "        }\n" });
}

fn emit_json_signature(db: const CompilerDb&, spec: SpecFunction, out: u8[>..]&) {
    out.append("      \"signature\": [\n");
    for i in spec.param_count {
        let idx = add_i32(spec.param_start, i);
        let has_more = inc_i32(i) < spec.param_count;
        if idx >= 0 && idx < db.symbols.len {
            emit_json_param(db, db.symbols[idx], has_more, out);
        }
    }
    out.append("      ],\n");
}

fn json_wire_kind_str(kind: WireOpKind) -> const u8[:] {
    return match kind {
        ReadOp => "READ",
        WriteOp => "WRITE",
        RollbackOp => "ROLLBACK",
        SatMathOp => "SAT_OP",
    };
}

fn json_wire_prefix(kind: WireOpKind) -> const u8[:] {
    return match kind {
        ReadOp => "Read#",
        WriteOp => "Write#",
        RollbackOp => "Rollback#",
        SatMathOp => "SatMath#",
    };
}

fn emit_json_wire_item(db: const CompilerDb&, op: WireOp, has_more: bool, out: u8[>..]&) {
    var op_buf:  u8[..32] = [];
    var src_buf: u8[>..]  = [];
    format(op_buf, json_wire_prefix(op.kind), op.seq_index);
    json_source_anchor(db, op.span, op.inlined_from, src_buf);
    let cond = trim_ascii_ws(text_of(db, op.cond_text));
    let enc = trim_ascii_ws(text_of(db, op.encoding_text));
    let val = trim_ascii_ws(text_of(db, op.val_expr_text));
    let targ = trim_ascii_ws(text_of(db, op.target_text));

    out.append("        {\n");
    json_kv_str(out, "          ", "op", op_buf[..], true);
    json_kv_str(out, "          ", "kind", json_wire_kind_str(op.kind), true);
    json_kv_i32(out, "          ", "seq_index", op.seq_index, true);
    json_kv_str(out, "          ", "condition", if cond.len > 0 { cond } else { "always" }, true);
    json_kv_str(out, "          ", "encoding", if enc.len > 0 { enc } else { "raw" }, true);
    json_kv_str(out, "          ", "value_expression", val, true);
    json_kv_str(out, "          ", "target", targ, true);
    json_kv_str(out, "          ", "source", src_buf[..], false);
    out.append(if has_more { "        },\n" } else { "        }\n" });
}

fn emit_json_wire_ops(db: const CompilerDb&, spec: SpecFunction, out: u8[>..]&) {
    out.append("      \"wire_ops\": [\n");
    for i in spec.wire_count {
        let idx = add_i32(spec.wire_start, i);
        let has_more = inc_i32(i) < spec.wire_count;
        if idx >= 0 && idx < db.wire_ops.len {
            emit_json_wire_item(db, db.wire_ops[idx], has_more, out);
        }
    }
    out.append("      ],\n");
}

fn emit_json_req_item(db: const CompilerDb&, g: GuardRule, fallback: i32, has_more: bool, out: u8[>..]&) {
    var id_buf:  u8[..16] = [];
    var src_buf: u8[>..]  = [];
    let req_no = if g.req_index > 0 { g.req_index } else { fallback };
    format(id_buf, "R", req_no);
    json_source_anchor(db, g.span, g.inlined_from, src_buf);
    let tmpl = trim_ascii_ws(text_of(db, g.template_id));

    out.append("        {\n");
    json_kv_str(out, "          ", "id", id_buf[..], true);
    json_kv_i32(out, "          ", "req_index", req_no, true);
    json_kv_str(out, "          ", "template_id", if tmpl.len > 0 { tmpl } else { "REQ_PRED" }, true);
    json_kv_str(out, "          ", "lhs", trim_ascii_ws(text_of(db, g.lhs_text)), true);
    json_kv_str(out, "          ", "rhs", trim_ascii_ws(text_of(db, g.rhs_text)), true);
    json_kv_str(out, "          ", "source", src_buf[..], false);
    out.append(if has_more { "        },\n" } else { "        }\n" });
}

fn emit_json_requirements(db: const CompilerDb&, spec: SpecFunction, out: u8[>..]&) {
    out.append("      \"requirements\": [\n");
    for i in spec.guard_count {
        let idx = add_i32(spec.guard_start, i);
        let has_more = inc_i32(i) < spec.guard_count;
        if idx >= 0 && idx < db.guards.len {
            emit_json_req_item(db, db.guards[idx], add_i32(i, 1), has_more, out);
        }
    }
    out.append("      ],\n");
}

fn json_unchecked_cat(kind: UncheckedKind) -> const u8[:] {
    return match kind {
        UnconstrainedInput => "UNCONSTRAINED_INPUT",
        DiscardedWireField => "DISCARDED_WIRE_FIELD",
        UnresolvedAstHazard => "[UNRESOLVED_AST_HAZARD]",
    };
}

fn emit_json_unchecked_item(db: const CompilerDb&, u: UncheckedItem, has_more: bool, out: u8[>..]&) {
    var src_buf: u8[>..] = [];
    json_source_anchor(db, u.span, Span { .. }, src_buf);
    out.append("        {\n");
    json_kv_str(out, "          ", "category", json_unchecked_cat(u.kind), true);
    json_kv_str(out, "          ", "item", trim_ascii_ws(text_of(db, u.item_text)), true);
    json_kv_str(out, "          ", "domain", trim_ascii_ws(text_of(db, u.domain_text)), true);
    json_kv_str(out, "          ", "note", trim_ascii_ws(text_of(db, u.note_text)), true);
    json_kv_str(out, "          ", "source", src_buf[..], false);
    out.append(if has_more { "        },\n" } else { "        }\n" });
}

fn emit_json_unchecked(db: const CompilerDb&, spec: SpecFunction, out: u8[>..]&) {
    out.append("      \"unchecked_surface\": [\n");
    for i in spec.unchecked_count {
        let idx = add_i32(spec.unchecked_start, i);
        let has_more = inc_i32(i) < spec.unchecked_count;
        if idx >= 0 && idx < db.unchecked.len {
            emit_json_unchecked_item(db, db.unchecked[idx], has_more, out);
        }
    }
    out.append("      ],\n");
}

fn json_rollback_str(state: RollbackState) -> const u8[:] {
    return match state {
        Unmodified => "UNMODIFIED",
        TransactionalSelf => "TRANSACTIONAL_SELF",
        DirtySelfRestoredByCaller => "DIRTY_SELF_RESTORED_BY_CALLER",
        DirtyExposed => "DIRTY_EXPOSED",
    };
}

fn emit_json_effect_item(db: const CompilerDb&, ef: ParamEffect, has_more: bool, out: u8[>..]&) {
    var src_buf: u8[>..] = [];
    json_source_anchor(db, ef.span, Span { .. }, src_buf);
    let pname = if ef.param_sym >= 0 && ef.param_sym < db.symbols.len {
        text_of(db, db.symbols[ef.param_sym].name_span)
    } else {
        "param"
    };
    out.append("        {\n");
    json_kv_str(out, "          ", "parameter", pname, true);
    json_kv_str(out, "          ", "classification", json_rollback_str(ef.state), true);
    json_kv_str(out, "          ", "mechanism", trim_ascii_ws(text_of(db, ef.mechanism_text)), true);
    json_kv_str(out, "          ", "source", src_buf[..], false);
    out.append(if has_more { "        },\n" } else { "        }\n" });
}

fn emit_json_effects(db: const CompilerDb&, spec: SpecFunction, out: u8[>..]&) {
    out.append("      \"error_side_effects\": [\n");
    for i in spec.effect_count {
        let idx = add_i32(spec.effect_start, i);
        let has_more = inc_i32(i) < spec.effect_count;
        if idx >= 0 && idx < db.effects.len {
            emit_json_effect_item(db, db.effects[idx], has_more, out);
        }
    }
    out.append("      ],\n");
}

fn emit_json_fsm_item(db: const CompilerDb&, row: FsmRow, has_more: bool, out: u8[>..]&) {
    var src_buf: u8[>..] = [];
    json_source_anchor(db, row.span, Span { .. }, src_buf);
    let src_raw = trim_ascii_ws(text_of(db, row.source_text));
    let src_val = if src_raw.len > 0 { src_raw } else { src_buf[..] };

    out.append("        {\n");
    json_kv_str(out, "          ", "state", trim_ascii_ws(text_of(db, row.state_text)), true);
    json_kv_str(out, "          ", "event", trim_ascii_ws(text_of(db, row.event_text)), true);
    json_kv_str(out, "          ", "guard", trim_ascii_ws(text_of(db, row.guard_text)), true);
    json_kv_str(out, "          ", "next", trim_ascii_ws(text_of(db, row.next_text)), true);
    json_kv_i32(out, "          ", "req_id", row.req_id, true);
    json_kv_str(out, "          ", "source", src_val, false);
    out.append(if has_more { "        },\n" } else { "        }\n" });
}

fn emit_json_fsm(db: const CompilerDb&, spec: SpecFunction, out: u8[>..]&) {
    out.append("      \"fsm_rows\": [\n");
    for i in spec.fsm_count {
        let idx = add_i32(spec.fsm_start, i);
        let has_more = inc_i32(i) < spec.fsm_count;
        if idx >= 0 && idx < db.fsm_rows.len {
            emit_json_fsm_item(db, db.fsm_rows[idx], has_more, out);
        }
    }
    out.append("      ]\n");
}

fn emit_json_function(db: const CompilerDb&, spec: SpecFunction, has_more: bool, out: u8[>..]&) {
    let fn_name = json_fn_name(db, spec);
    let fpath = file_path_of(db, spec.span.file_id);
    let start_ln = max(spec.span.line, 1);
    let end_ln = max(spec.end_line, start_ln);
    var src_anchor: u8[>..] = [];
    format(src_anchor, fpath, ":", start_ln, "-", end_ln);
    let ret_raw = trim_ascii_ws(text_of(db, spec.ret_type_text));
    let ret_type = if ret_raw.len > 0 { ret_raw } else { "bool" };

    out.append("    {\n");
    json_kv_str(out, "      ", "name", fn_name, true);
    json_kv_str(out, "      ", "source", src_anchor[..], true);
    json_kv_str(out, "      ", "return_type", ret_type, true);
    json_kv_i32(out, "      ", "resolved_constants", spec.resolved_constants, true);
    json_kv_i32(out, "      ", "inlined_callees", spec.inlined_callees, true);
    json_kv_i32(out, "      ", "unanalyzed_statements", spec.unanalyzed_statements, true);
    json_kv_str(out, "      ", "entry_context", trim_ascii_ws(text_of(db, spec.entry_ctx_text)), true);
    emit_json_signature(db, spec, out);
    emit_json_wire_ops(db, spec, out);
    emit_json_requirements(db, spec, out);
    emit_json_unchecked(db, spec, out);
    emit_json_effects(db, spec, out);
    emit_json_fsm(db, spec, out);
    out.append(if has_more { "    },\n" } else { "    }\n" });
}

fn emit_spec_json(db: CompilerDb&, cfg: Config&, out: u8[>..]&) -> bool {
    out.clear();
    out.append("{\n");
    json_kv_str(out, "  ", "schema_version", "1.0", true);
    json_kv_bool(out, "  ", "strict", cfg.strict, true);
    emit_json_files(db, out);
    out.append("  \"functions\": [\n");
    for i in db.specs.len {
        let has_more = inc_i64(i) < db.specs.len;
        emit_json_function(db, db.specs[i], has_more, out);
    }
    out.append("  ]\n");
    out.append("}\n");
    return out.len > 0;
}
