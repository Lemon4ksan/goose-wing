// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Stage 2A configurable predicate and pure-helper inliner.

import std;
import db from "../model";
import loader from "../config";

struct InlBinding {
    name:         u8[..64]   = [],
    expr:         u8[..1024] = [],
    inlined_from: u8[..96]   = [],
    line:         i32        = 0,
}

struct InlBindTable {
    items: InlBinding[..32] = [],
    count: i32              = 0,
}

fn inl_add_binding(
    tbl:          InlBindTable&,
    name:         const u8[:],
    expr:         const u8[:],
    inlined_from: const u8[:],
    line:         i32,
) {
    let clean_name = trim_ascii_ws(name);
    guard clean_name.len > 0 else { return; }
    for i in tbl.items.len {
        if tbl.items[i].name[..] == clean_name {
            copy_bounded_str(tbl.items[i].expr, expr);
            if inlined_from.len > 0 {
                copy_bounded_str(tbl.items[i].inlined_from, inlined_from);
            }
            tbl.items[i].line = line;
            return;
        }
    }
    guard tbl.items.len < tbl.items.cap else { return; }
    var item = InlBinding { line: line, .. };
    copy_bounded_str(item.name, clean_name);
    copy_bounded_str(item.expr, expr);
    copy_bounded_str(item.inlined_from, inlined_from);
    tbl.items.push(item);
    tbl.count = tbl.items.len as i32;
}

fn inl_find_binding(tbl: const InlBindTable&, name: const u8[:]) -> i32 {
    let s = trim_ascii_ws(name);
    for i in tbl.items.len {
        if tbl.items[i].name[..] == s {
            return i as i32;
        }
    }
    return -1;
}

fn inl_digit_val(b: u8) -> u64, bool {
    if b >= '0' && b <= '9' { return sub_u64(b, '0'), true; }
    if b >= 'a' && b <= 'f' { return add_u64(sub_u64(b, 'a'), 10), true; }
    if b >= 'A' && b <= 'F' { return add_u64(sub_u64(b, 'A'), 10), true; }
    return 0, false;
}

fn inl_parse_u64_radix(s: const u8[:], radix: u64) -> u64, bool {
    guard s.len > 0 else { return 0, false; }
    var acc:    u64 = 0;
    var digits: i32 = 0;
    for i in s.len {
        let b = s[i];
        if b != '_' {
            let d, ok = inl_digit_val(b);
            guard ok && d < radix else { return 0, false; }
            acc = add_u64(mul_u64(acc, radix), d);
            digits = inc_i32(digits);
        }
    }
    return acc, digits > 0;
}

fn inl_parse_literal(raw: const u8[:]) -> u64, bool {
    let s = trim_ascii_ws(raw);
    guard s.len > 0 else { return 0, false; }
    if s.len > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
        return inl_parse_u64_radix(s[2..], 16);
    }
    if s.len > 2 && s[0] == '0' && (s[1] == 'b' || s[1] == 'B') {
        return inl_parse_u64_radix(s[2..], 2);
    }
    return inl_parse_u64_radix(s, 10);
}

fn inl_builtin_const(short_name: const u8[:]) -> u64, bool {
    if short_name == "QUIC_VARINT_MAX" { return 0x3fffffffffffffff, true; }
    if short_name == "QUIC_FRAME_PADDING" { return 0x00, true; }
    if short_name == "QUIC_FRAME_PING" { return 0x01, true; }
    if short_name == "QUIC_FRAME_RESET_STREAM" { return 0x04, true; }
    if short_name == "QUIC_FRAME_STOP_SENDING" { return 0x05, true; }
    if short_name == "QUIC_FRAME_CRYPTO" { return 0x06, true; }
    if short_name == "QUIC_FRAME_STREAM_BASE" { return 0x08, true; }
    if short_name == "QUIC_STREAM_FLAG_FIN" { return 0x01, true; }
    if short_name == "QUIC_STREAM_FLAG_LEN" { return 0x02, true; }
    if short_name == "QUIC_STREAM_FLAG_OFF" { return 0x04, true; }
    if short_name == "TLS_HS_MESSAGE_HASH" { return 254, true; }
    return 0, false;
}

fn inl_resolve_const_sym(db: CompilerDb&, token: const u8[:]) -> u64, bool {
    let s = trim_ascii_ws(token);
    guard s.len > 0 else { return 0, false; }
    let id = find_symbol(db, s);
    if id >= 0 && id < db.symbols.len && db.symbols[id].has_const {
        return db.symbols[id].const_val, true;
    }
    let short_name = strip_ns_prefix(s);
    let sid = find_symbol(db, short_name);
    if sid >= 0 && sid < db.symbols.len && db.symbols[sid].has_const {
        return db.symbols[sid].const_val, true;
    }
    return inl_builtin_const(short_name);
}

fn inl_inc_resolved_consts(db: CompilerDb&, spec_id: i32) {
    guard spec_id >= 0 && spec_id < db.specs.len else { return; }
    db.specs[spec_id].resolved_constants = inc_i32(db.specs[spec_id].resolved_constants);
}

fn inl_inc_inlined_callees(db: CompilerDb&, spec_id: i32) {
    guard spec_id >= 0 && spec_id < db.specs.len else { return; }
    db.specs[spec_id].inlined_callees = inc_i32(db.specs[spec_id].inlined_callees);
}

fn inl_strip_line_comment(line: const u8[:]) -> const u8[:] {
    var quote_ch: u8   = 0;
    var escaped:  bool = false;
    for i in line.len {
        let b = line[i];
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
        } else if b == '/' && inc_i64(i) < line.len && line[inc_i64(i)] == '/' {
            return trim_ascii_ws(line[..i]);
        }
    }
    return trim_ascii_ws(line);
}

fn inl_is_ident_char(b: u8) -> bool {
    if b >= 'a' && b <= 'z' { return true; }
    if b >= 'A' && b <= 'Z' { return true; }
    if b >= '0' && b <= '9' { return true; }
    return b == '_' || b == ':';
}

fn inl_boundary_ok(src: const u8[:], pos: i64, tok_len: i64) -> bool {
    if pos > 0 {
        let prev = src[dec_i64(pos)];
        if inl_is_ident_char(prev) || prev == '.' {
            return false;
        }
    }
    let after = add_i64(pos, tok_len);
    if after < src.len {
        let nxt = src[after];
        if inl_is_ident_char(nxt) {
            return false;
        }
    }
    return true;
}

fn inl_needs_parens(s: const u8[:]) -> bool {
    let t = trim_ascii_ws(s);
    if slice_starts_with(t, "(") && slice_ends_with(t, ")") {
        return false;
    }
    if slice_starts_with(t, "if ") || slice_starts_with(t, "match ") {
        return true;
    }
    return slice_find(t, " | ") >= 0
        || slice_find(t, " & ") >= 0
        || slice_find(t, " ^ ") >= 0
        || slice_find(t, " + ") >= 0
        || slice_find(t, " - ") >= 0
        || slice_find(t, " << ") >= 0
        || slice_find(t, " >> ") >= 0
        || slice_find(t, " == ") >= 0
        || slice_find(t, " != ") >= 0
        || slice_find(t, " <= ") >= 0
        || slice_find(t, " >= ") >= 0
        || slice_find(t, " < ") >= 0
        || slice_find(t, " > ") >= 0
        || slice_find(t, " && ") >= 0
        || slice_find(t, " || ") >= 0;
}

// Substitutes standalone identifier occurrences of `old_tok` with `new_val` in `src` outside literals.
//
// Example:
//   src = "rem >= len", old_tok = "len", new_val = "data.len as u64"
//   appends: "rem >= data.len as u64" into `out`
fn inl_replace_ident(src: const u8[:], old_tok: const u8[:], new_val: const u8[:], out: u8[>..]&) {
    out.clear();
    guard old_tok.len > 0 && src.len >= old_tok.len else {
        out.append(src);
        return;
    }
    let wrap_parens = trim_ascii_ws(src) != old_tok && inl_needs_parens(new_val);
    var cursor:   i64  = 0;
    var quote_ch: u8   = 0;
    var escaped:  bool = false;
    for step in src.len {
        if cursor >= src.len {
            return;
        }
        let b = src[cursor];
        if quote_ch != 0 {
            out.push(b);
            if escaped {
                escaped = false;
            } else if b == '\\' {
                escaped = true;
            } else if b == quote_ch {
                quote_ch = 0;
            }
            cursor = inc_i64(cursor);
        } else if b == '"' || b == '\'' {
            quote_ch = b;
            out.push(b);
            cursor = inc_i64(cursor);
        } else if slice_starts_with(src[cursor..], old_tok) && inl_boundary_ok(src, cursor, old_tok.len) {
            if wrap_parens { out.push('('); }
            out.append(new_val);
            if wrap_parens { out.push(')'); }
            cursor = add_i64(cursor, old_tok.len);
        } else {
            out.push(b);
            cursor = inc_i64(cursor);
        }
    }
}

fn inl_apply_bindings(src: const u8[:], binds: const InlBindTable&, out: u8[>..]&) -> i32 {
    out.clear();
    out.append(src);
    var used_line: i32     = 0;
    var tmp:       u8[>..] = [];
    for i in binds.items.len {
        let name = binds.items[i].name[..];
        let expr = binds.items[i].expr[..];
        if name != "__branch__" && slice_find(out[..], name) >= 0 {
            inl_replace_ident(out[..], name, expr, tmp);
            if tmp[..] != out[..] && binds.items[i].line > 0 {
                used_line = binds.items[i].line;
            }
            out.clear();
            out.append(tmp[..]);
        }
    }
    return used_line;
}

fn inl_normalize_casts(src: const u8[:], out: u8[>..]&) {
    var tmp: u8[>..] = [];
    format_replaced(tmp, src, " as! ", " as_truncate ");
    out.clear();
    format_replaced(out, tmp[..], " as ", " as_checked ");
}

fn inl_resolve_inline_token(db: CompilerDb&, spec_id: i32, tok: const u8[:], out: u8[>..]&) {
    let s = trim_ascii_ws(tok);
    let lit, ok_lit = inl_parse_literal(s);
    if ok_lit {
        format_u64_hex_lit(out, lit);
        return;
    }
    let cv, ok_c = inl_resolve_const_sym(db, s);
    if ok_c {
        inl_inc_resolved_consts(db, spec_id);
        format_u64_hex_lit(out, cv);
        return;
    }
    out.append(s);
}

// Normalizes casts, resolves constants in arithmetic sub-terms, and annotates wrap operators.
//
// Example:
//   raw = "rfc::QUIC_VARINT_MAX - offset"
//   appends: "0x3fff_ffff_ffff_ffff -_u64_wrap offset" into `out`
fn inl_normalize_arith_expr(db: CompilerDb&, spec_id: i32, raw: const u8[:], out: u8[>..]&) {
    var casted: u8[>..] = [];
    inl_normalize_casts(trim_ascii_ws(raw), casted);
    let s = casted[..];
    out.clear();
    let lhs_sub, rhs_sub, has_sub = split_at_str(s, " - ");
    if has_sub {
        inl_resolve_inline_token(db, spec_id, lhs_sub, out);
        out.append(" -_u64_wrap ");
        inl_resolve_inline_token(db, spec_id, rhs_sub, out);
        return;
    }
    let lhs_add, rhs_add, has_add = split_at_str(s, " + ");
    if has_add {
        inl_resolve_inline_token(db, spec_id, lhs_add, out);
        out.append(" +_u64_wrap ");
        inl_resolve_inline_token(db, spec_id, rhs_add, out);
        return;
    }
    let lhs_shl, rhs_shl, has_shl = split_at_str(s, " << ");
    if has_shl {
        inl_resolve_inline_token(db, spec_id, lhs_shl, out);
        out.append(" <<_u64_wrap ");
        inl_resolve_inline_token(db, spec_id, rhs_shl, out);
        return;
    }
    out.append(s);
}

// Formats a comparison bound with dual constant notation when the bound is a known constant symbol.
//
// Example:
//   raw = "rfc::QUIC_VARINT_MAX"
//   appends: "0x3fff_ffff_ffff_ffff` (`2^62 - 1`, `rfc::QUIC_VARINT_MAX" into `out`
fn inl_format_bound_expr(db: CompilerDb&, spec_id: i32, raw: const u8[:], out: u8[>..]&) {
    let s = trim_ascii_ws(raw);
    out.clear();
    let lit, ok_lit = inl_parse_literal(s);
    if ok_lit {
        if lit == 0x3fffffffffffffff {
            out.append("0x3fff_ffff_ffff_ffff");
        } else {
            out.append(s);
        }
        return;
    }
    let cv, ok_c = inl_resolve_const_sym(db, s);
    if ok_c {
        inl_inc_resolved_consts(db, spec_id);
        format_u64_hex_lit(out, cv);
        return;
    }
    inl_normalize_arith_expr(db, spec_id, s, out);
}

fn inl_find_matching_rbrace(win: const u8[:], lbrace: i64, start_line: i32) -> i64, i32 {
    var depth: i32 = 0;
    var lines = start_line;
    var in_comment: bool = false;
    var quote_ch:   u8   = 0;
    var escaped:    bool = false;
    for i in win.len {
        let b = win[i];
        if b == '\n' {
            lines = inc_i32(lines);
            in_comment = false;
            escaped = false;
        } else if in_comment {
            escaped = false;
        } else if quote_ch != 0 {
            if escaped {
                escaped = false;
            } else if b == '\\' {
                escaped = true;
            } else if b == quote_ch {
                quote_ch = 0;
            }
        } else if b == '/' && inc_i64(i) < win.len && win[inc_i64(i)] == '/' {
            in_comment = true;
        } else if b == '"' || b == '\'' {
            quote_ch = b;
        } else if i >= lbrace && b == '{' {
            depth = inc_i32(depth);
        } else if i >= lbrace && b == '}' {
            depth = dec_i32(depth);
            if depth == 0 {
                return i, lines;
            }
        }
    }
    return dec_i64(win.len), lines;
}

// Extracts the function signature and `{ ... }` body slice along with start and end lines.
//
// Example:
//   fn_node = FnDecl at line 154
//   returns: sig_slice, body_slice, 154, 160
fn inl_extract_fn_slices(
    db:      const CompilerDb&,
    fn_node: i32,
    fn_sym:  i32,
) -> const u8[:], const u8[:], i32, i32 {
    var base_span = Span { .. };
    if fn_node >= 0 && fn_node < db.nodes.len {
        base_span = db.nodes[fn_node].span;
    } else if fn_sym >= 0 && fn_sym < db.symbols.len {
        base_span = db.symbols[fn_sym].span;
    }
    guard base_span.at >= 0 && base_span.at < db.text.len else { return "", "", 0, 0; }
    let tail = db.text[base_span.at..];
    let win = tail[..min(tail.len, 16384)];
    let lbrace = slice_find(win, "{");
    guard lbrace >= 0 else { return "", "", base_span.line, base_span.line; }
    let rbrace, end_line = inl_find_matching_rbrace(win, lbrace, base_span.line);
    let body_start = inc_i64(lbrace);
    guard rbrace >= body_start else { return win[..lbrace], "", base_span.line, end_line; }
    let body_len = sub_i64(rbrace, body_start);
    return win[..lbrace], win[body_start..][..body_len], base_span.line, end_line;
}

// Parses formal parameter names from a function signature and binds them to caller arguments.
//
// Example:
//   sig = "fn foo(offset: u64, len: u64) -> bool", args_txt = "offset, data.len as u64"
//   populates `binds` with offset -> "offset", len -> "data.len as u64"
fn inl_bind_call_params(sig: const u8[:], args_txt: const u8[:], binds: InlBindTable&) -> bool {
    let _, after_lp, ok_lp = split_at_str(sig, "(");
    guard ok_lp else { return false; }
    let params_raw, _, _ = split_at_str(after_lp, ")");
    var pnames: const u8[:][>..] = [];
    var rem_params = trim_ascii_ws(params_raw);
    for step_p in 32 {
        if rem_params.len == 0 {
            break;
        }
        let head_p, tail_p, has_comma_p = inl_split_top_level(rem_params, ",");
        let pdecl = trim_ascii_ws(if has_comma_p { head_p } else { rem_params });
        let pname, _, has_col = split_at_str(pdecl, ":");
        if has_col {
            pnames.push(trim_ascii_ws(pname));
        }
        if !has_comma_p {
            break;
        }
        rem_params = trim_ascii_ws(tail_p);
    }
    var args: const u8[:][>..] = [];
    var rem_args = trim_ascii_ws(args_txt);
    for step_a in 32 {
        if rem_args.len == 0 {
            break;
        }
        let head_a, tail_a, has_comma_a = inl_split_top_level(rem_args, ",");
        let a = trim_ascii_ws(if has_comma_a { head_a } else { rem_args });
        if a.len > 0 {
            args.push(a);
        }
        if !has_comma_a {
            break;
        }
        rem_args = trim_ascii_ws(tail_a);
    }
    let has_default = slice_find(params_raw, "=") >= 0;
    guard args.len == pnames.len || (has_default && args.len < pnames.len) else { return false; }
    let n = min(pnames.len, args.len);
    for i in n {
        inl_add_binding(binds, pnames[i], args[i], "", 0);
    }
    return true;
}

fn inl_format_source_range(name: const u8[:], start_line: i32, end_line: i32, out: u8[>..]&) {
    out.clear();
    out.append(strip_ns_prefix(name));
    out.append(":");
    format_int(out, start_line, 10, 0, ' ');
    if end_line > start_line {
        out.append("-");
        format_int(out, end_line, 10, 0, ' ');
    }
}

fn inl_extract_bit_rhs(body_raw: const u8[:]) -> const u8[:], bool {
    let _, rhs_pipe_eq, has_peq = split_at_str(body_raw, "|=");
    if has_peq {
        let b1, _, _ = split_at_str(rhs_pipe_eq, ";");
        return trim_ascii_ws(b1), true;
    }
    let _, rhs_pipe, has_p = split_at_str(body_raw, "|");
    guard has_p else { return body_raw[..0], false; }
    let b2, _, _ = split_at_str(rhs_pipe, ";");
    return trim_ascii_ws(b2), true;
}

fn inl_parse_bitflag_if_line(
    db:       CompilerDb&,
    spec_id:  i32,
    line:     const u8[:],
    acc_name: const u8[:],
    binds:    const InlBindTable&,
    out:      u8[>..]&,
) -> bool {
    guard slice_starts_with(line, "if ") && slice_find(line, acc_name) >= 0 else { return false; }
    let after_if = trim_ascii_ws(line[3..]);
    let cond_raw, body_raw, has_lbrace = split_at_str(after_if, "{");
    guard has_lbrace else { return false; }
    var cond_sub: u8[>..] = [];
    inl_apply_bindings(trim_ascii_ws(cond_raw), binds, cond_sub);
    let bit_raw, ok_bit = inl_extract_bit_rhs(body_raw);
    guard ok_bit else { return false; }
    var bit_hex: u8[>..] = [];
    inl_resolve_inline_token(db, spec_id, bit_raw, bit_hex);
    out.append(" | (if ");
    out.append(cond_sub[..]);
    out.append(" { ");
    out.append(bit_hex[..]);
    out.append(" } else { 0 })");
    return true;
}

// Expands a pure helper function body into a single inline expression string.
//
// Example:
//   callee = build_stream_frame_type, args_txt = "flags"
//   appends: "0x08 | (if flags.with_offset { 0x04 } else { 0 }) | ..." into `out_expr`
fn inl_expand_pure_callee(
    db:          CompilerDb&,
    spec_id:     i32,
    callee_sym:  i32,
    args_txt:    const u8[:],
    out_expr:    u8[>..]&,
    out_inlined: u8[>..]&,
) -> bool {
    out_expr.clear();
    out_inlined.clear();
    guard callee_sym >= 0 && callee_sym < db.symbols.len else { return false; }
    let sym = db.symbols[callee_sym];
    let sig, body, sline, eline = inl_extract_fn_slices(db, sym.decl_node, callee_sym);
    guard body.len > 0 && slice_find(sig, "&") < 0 else { return false; }
    guard slice_find(body, "while ") < 0 && slice_find(body, "for ") < 0 && slice_find(body, "guard ") < 0 else {
        return false;
    }
    var binds = InlBindTable { .. };
    guard inl_bind_call_params(sig, args_txt, binds) else { return false; }
    var acc_name:    u8[..64] = [];
    var ret_buf:     u8[>..]  = [];
    var has_bitflag: bool     = false;
    var in_ret:      bool     = false;
    var ret_count:   i32      = 0;
    var non_bit_ifs: i32      = 0;
    each_split(body, '\n') {
        let line = inl_strip_line_comment(it);
        if in_ret {
            ret_buf.push(' ');
            let r_part, _, has_semi = split_at_str(line, ";");
            ret_buf.append(trim_ascii_ws(r_part));
            if has_semi {
                in_ret = false;
            }
        } else if slice_starts_with(line, "var ") {
            let vname_part, init_part, has_eq = split_at_str(trim_ascii_ws(line[4..]), "=");
            if has_eq {
                let vn, _, _ = split_at_str(vname_part, ":");
                let init_clean, _, _ = split_at_str(init_part, ";");
                copy_bounded_str(acc_name, trim_ascii_ws(vn));
                inl_resolve_inline_token(db, spec_id, trim_ascii_ws(init_clean), out_expr);
            }
        } else if slice_starts_with(line, "let ") {
            let vname_raw, rhs_raw, has_eq = split_at_str(trim_ascii_ws(line[4..]), "=");
            if has_eq && slice_find(rhs_raw, ";") >= 0 {
                let vn, _, _ = split_at_str(vname_raw, ":");
                let rhs_clean, _, _ = split_at_str(rhs_raw, ";");
                var sub_rhs: u8[>..] = [];
                inl_apply_bindings(trim_ascii_ws(rhs_clean), binds, sub_rhs);
                inl_add_binding(binds, trim_ascii_ws(vn), sub_rhs[..], "", 0);
            } else {
                non_bit_ifs = inc_i32(non_bit_ifs);
            }
        } else if slice_starts_with(line, "if ") || slice_starts_with(line, "match ") {
            if acc_name.len > 0 && slice_starts_with(line, "if ") && inl_parse_bitflag_if_line(db, spec_id, line, acc_name[..], binds, out_expr) {
                has_bitflag = true;
            } else {
                non_bit_ifs = inc_i32(non_bit_ifs);
            }
        } else if slice_starts_with(line, "return ") {
            ret_count = inc_i32(ret_count);
            let r_clean, _, has_semi = split_at_str(line[7..], ";");
            ret_buf.clear();
            ret_buf.append(trim_ascii_ws(r_clean));
            in_ret = !has_semi;
        }
    };
    if non_bit_ifs > 0 || ret_count != 1 {
        return false;
    }
    if acc_name.len > 0 && !has_bitflag {
        out_expr.clear();
    }
    if out_expr.len == 0 && ret_buf.len > 0 {
        var sub_ret: u8[>..] = [];
        inl_apply_bindings(ret_buf[..], binds, sub_ret);
        inl_normalize_arith_expr(db, spec_id, sub_ret[..], out_expr);
    }
    guard out_expr.len > 0 else { return false; }
    inl_format_source_range(text_of(db, sym.name_span), sline, eline, out_inlined);
    return true;
}

// Splits a single function call expression `name(args)` into callee name and argument slice.
//
// Example:
//   expr = "build_stream_frame_type(flags)"
//   returns: "build_stream_frame_type", "flags", true
fn inl_parse_call_text(expr: const u8[:]) -> const u8[:], const u8[:], bool {
    let s = trim_ascii_ws(expr);
    guard slice_ends_with(s, ")") else { return "", "", false; }
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
    guard lp_idx > 0 else { return "", "", false; }
    let clean_fn = trim_ascii_ws(s[..lp_idx]);
    if slice_find(clean_fn, " ") >= 0 || slice_find(clean_fn, "=") >= 0 || slice_find(clean_fn, "<") >= 0 || slice_starts_with(clean_fn, "!") {
        return "", "", false;
    }
    var depth: i32 = 0;
    quote_ch = 0;
    escaped = false;
    var match_rp: i64 = -1;
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
        } else if b == '(' || b == '[' || b == '{' {
            depth = inc_i32(depth);
        } else if b == ')' || b == ']' || b == '}' {
            depth = dec_i32(depth);
            if depth == 0 {
                match_rp = idx;
                break;
            }
        }
    }
    guard match_rp == dec_i64(s.len) else { return "", "", false; }
    let args_start = inc_i64(lp_idx);
    return clean_fn, trim_ascii_ws(s[args_start..match_rp]), true;
}

fn inl_is_wire_ok_ident(clause: const u8[:]) -> bool {
    let s = trim_ascii_ws(clause);
    if s == "ok" || s == "ok1" || s == "ok2" || s == "ok3" {
        return true;
    }
    return slice_starts_with(s, "ok_");
}

fn inl_is_intrinsic_call_clause(intrinsics: const IntrinsicTable&, clause: const u8[:]) -> bool {
    let fname, _, is_call = inl_parse_call_text(clause);
    guard is_call else { return false; }
    if find_intrinsic(intrinsics, fname) >= 0 {
        return true;
    }
    let _, method, has_dot = split_at_str(fname, ".");
    if has_dot && find_intrinsic(intrinsics, method) >= 0 {
        return true;
    }
    return false;
}

// Negates a failure condition from an `if <fail_cond> { return false; }` statement.
//
// Example:
//   cond = "offset > rfc::QUIC_VARINT_MAX"
//   appends: "offset <= rfc::QUIC_VARINT_MAX" into `out`
fn inl_negate_fail_cond(cond: const u8[:], out: u8[>..]&) {
    let s = trim_ascii_ws(cond);
    out.clear();
    if slice_find(s, "||") >= 0 || slice_find(s, "&&") >= 0 {
        out.append("!(");
        out.append(s);
        out.append(")");
        return;
    }
    let l1, r1, ok_ge = split_at_str(s, " >= ");
    if ok_ge {
        out.append(l1);
        out.append(" < ");
        out.append(r1);
        return;
    }
    let l2, r2, ok_le = split_at_str(s, " <= ");
    if ok_le {
        out.append(l2);
        out.append(" > ");
        out.append(r2);
        return;
    }
    let l3, r3, ok_gt = split_at_str(s, " > ");
    if ok_gt {
        out.append(l3);
        out.append(" <= ");
        out.append(r3);
        return;
    }
    let l4, r4, ok_lt = split_at_str(s, " < ");
    if ok_lt {
        out.append(l4);
        out.append(" >= ");
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

fn inl_split_top_level(s: const u8[:], sep: const u8[:]) -> const u8[:], const u8[:], bool {
    guard sep.len > 0 && s.len >= sep.len else { return s, "", false; }
    var depth:    i32  = 0;
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
        } else if b == '(' || b == '[' || b == '{' {
            depth = inc_i32(depth);
        } else if (b == ')' || b == ']' || b == '}') && depth > 0 {
            depth = dec_i32(depth);
        } else if depth == 0 && slice_starts_with(s[i..], sep) {
            let after = add_i64(i, sep.len);
            return s[..i], s[after..], true;
        }
    }
    return s, "", false;
}

fn inl_is_float_literal(s: const u8[:]) -> bool {
    let t = trim_ascii_ws(s);
    guard t.len >= 3 else { return false; }
    let head, tail, has_dot = split_at_str(t, ".");
    guard has_dot && head.len > 0 && tail.len > 0 else { return false; }
    let last_h = head[dec_i64(head.len)];
    let first_t = tail[0];
    return last_h >= '0' && last_h <= '9' && first_t >= '0' && first_t <= '9';
}

fn inl_has_balanced_braces(s: const u8[:]) -> bool {
    let t = trim_ascii_ws(s);
    guard slice_starts_with(t, "{") && slice_ends_with(t, "}") else { return false; }
    var depth:    i32  = 0;
    var quote_ch: u8   = 0;
    var escaped:  bool = false;
    for i in t.len {
        let b = t[i];
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
        } else if b == '{' {
            depth = inc_i32(depth);
        } else if b == '}' {
            depth = dec_i32(depth);
            if depth == 0 && i < dec_i64(t.len) {
                return false;
            }
        }
    }
    return depth == 0;
}

// Splits `after_guard` at its diverging top-level `else { ... }` block, ignoring inline `if ... else` values.
//
// Example:
//   s = "x == if c { 1 } else { 0 } else { return -1; }"
//   returns: "x == if c { 1 } else { 0 }", "{ return -1; }", true
fn inl_split_guard_else(s: const u8[:]) -> const u8[:], const u8[:], bool {
    guard s.len >= 6 else { return s, "", false; }
    var depth:     i32  = 0;
    var quote_ch:  u8   = 0;
    var escaped:   bool = false;
    var last_else: i64  = -1;
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
        } else if b == '(' || b == '[' || b == '{' {
            depth = inc_i32(depth);
        } else if (b == ')' || b == ']' || b == '}') && depth > 0 {
            depth = dec_i32(depth);
        } else if depth == 0 && slice_starts_with(s[i..], "else") && inl_boundary_ok(s, i, 4) {
            let tail = trim_ascii_ws(s[add_i64(i, 4)..]);
            let diverges = slice_find(tail, "return") >= 0
                || slice_find(tail, "break") >= 0
                || slice_find(tail, "continue") >= 0;
            if slice_starts_with(tail, "{") && diverges && inl_has_balanced_braces(tail) {
                last_else = i;
            }
        }
    }
    guard last_else >= 0 else { return s, "", false; }
    return trim_ascii_ws(s[..last_else]), trim_ascii_ws(s[add_i64(last_else, 4)..]), true;
}

fn inl_extract_else_return_expr(else_part: const u8[:]) -> const u8[:] {
    let _, after_ret, has_ret = split_at_str(else_part, "return");
    guard has_ret else { return ""; }
    let expr_raw, _, _ = split_at_str(after_ret, ";");
    let expr_clean, _, _ = split_at_str(expr_raw, "}");
    let t = trim_ascii_ws(expr_clean);
    if t.len == 0 || t == "false" {
        return "";
    }
    return t;
}

fn inl_is_loop_skip_else(else_part: const u8[:]) -> bool {
    if slice_find(else_part, "continue") >= 0 || slice_find(else_part, "break") >= 0 {
        return true;
    }
    let t = trim_ascii_ws(else_part);
    if slice_find(t, "return true") >= 0 ||
       slice_find(t, "return rfc::H2_ERR_NO_ERROR") >= 0 ||
       slice_find(t, "return rfc::H3_ERR_NO_ERROR") >= 0 ||
       slice_find(t, "return ERR_NO_ERROR") >= 0 ||
       slice_find(t, "return TlsAlert.CloseNotify") >= 0 {
        return true;
    }
    let ret_expr = inl_extract_else_return_expr(t);
    if ret_expr.len > 0 && (slice_ends_with(ret_expr, ", true") || slice_ends_with(ret_expr, ".None") || slice_ends_with(ret_expr, ".Ok")) {
        return true;
    }
    return false;
}

fn inl_conjoin_branch_cond(binds: InlBindTable&, cond_raw: const u8[:]) {
    var sub_c: u8[>..] = [];
    inl_apply_bindings(trim_ascii_ws(cond_raw), binds, sub_c);
    guard sub_c.len > 0 else { return; }
    let idx = inl_find_binding(binds, "__branch__");
    if idx >= 0 && binds.items[idx].expr.len > 0 {
        var joined: u8[>..] = [];
        joined.append(binds.items[idx].expr[..]);
        joined.append(" && ");
        joined.append(sub_c[..]);
        inl_add_binding(binds, "__branch__", joined[..], "", 0);
    } else {
        inl_add_binding(binds, "__branch__", sub_c[..], "", 0);
    }
}

fn inl_emit_single_guard_rule(
    db:           CompilerDb&,
    spec_id:      i32,
    clause:       const u8[:],
    inlined_from: const u8[:],
    else_ret:     const u8[:],
    guard_span:   Span,
) {
    let s = trim_ascii_ws(clause);
    guard s.len > 0 && !inl_is_wire_ok_ident(s) else { return; }
    var tmpl:    const u8[:] = "REQ_PRED";
    var lhs_buf: u8[>..]     = [];
    var rhs_buf: u8[>..]     = [];

    let _, _, has_or = inl_split_top_level(s, "||");
    let _, _, has_and = inl_split_top_level(s, "&&");
    let has_disj = has_or || has_and;
    let l_le, r_le, ok_le = inl_split_top_level(s, "<=");
    let l_ge, r_ge, ok_ge = inl_split_top_level(s, ">=");
    let l_ne, r_ne, ok_ne = inl_split_top_level(s, "!=");
    let l_eq, r_eq, ok_eq = inl_split_top_level(s, "==");
    if has_disj {
        inl_normalize_arith_expr(db, spec_id, s, lhs_buf);
    } else if ok_le {
        tmpl = "REQ_MAX";
        inl_normalize_arith_expr(db, spec_id, l_le, lhs_buf);
        inl_format_bound_expr(db, spec_id, r_le, rhs_buf);
    } else if ok_ge {
        tmpl = "REQ_MIN";
        inl_normalize_arith_expr(db, spec_id, l_ge, lhs_buf);
        inl_format_bound_expr(db, spec_id, r_ge, rhs_buf);
    } else if ok_ne {
        tmpl = "REQ_NE";
        inl_normalize_arith_expr(db, spec_id, l_ne, lhs_buf);
        inl_format_bound_expr(db, spec_id, r_ne, rhs_buf);
    } else if ok_eq {
        tmpl = "REQ_EQ";
        inl_normalize_arith_expr(db, spec_id, l_eq, lhs_buf);
        inl_format_bound_expr(db, spec_id, r_eq, rhs_buf);
    } else {
        let l_lt, r_lt, ok_lt = inl_split_top_level(s, " < ");
        let l_gt, r_gt, ok_gt = inl_split_top_level(s, " > ");
        if ok_lt && !inl_is_float_literal(r_lt) {
            tmpl = "REQ_MAX";
            inl_normalize_arith_expr(db, spec_id, l_lt, lhs_buf);
            inl_format_bound_expr(db, spec_id, r_lt, rhs_buf);
            rhs_buf.append(" - 1");
        } else if ok_gt && !inl_is_float_literal(r_gt) {
            tmpl = "REQ_MIN";
            inl_normalize_arith_expr(db, spec_id, l_gt, lhs_buf);
            if trim_ascii_ws(r_gt) == "0" {
                rhs_buf.append("1");
            } else {
                inl_format_bound_expr(db, spec_id, r_gt, rhs_buf);
                rhs_buf.append(" + 1");
            }
        } else {
            inl_normalize_arith_expr(db, spec_id, s, lhs_buf);
        }
    }
    let req_idx = inc_i32(db.specs[spec_id].guard_count);
    db.specs[spec_id].guard_count = req_idx;
    db.guards.push(GuardRule {
        req_index:     req_idx,
        template_id:   put_text(db, tmpl),
        lhs_text:      put_text(db, lhs_buf[..]),
        rhs_text:      put_text(db, rhs_buf[..]),
        else_ret_text: put_text(db, else_ret),
        inlined_from:  put_text(db, inlined_from),
        span:          guard_span,
    });
}

fn inl_format_branch_inlined(binds: const InlBindTable&, base_inl: const u8[:], out: u8[>..]&) {
    out.clear();
    let br_idx = inl_find_binding(binds, "__branch__");
    if br_idx >= 0 && binds.items[br_idx].expr.len > 0 {
        out.append("(when `");
        out.append(binds.items[br_idx].expr[..]);
        out.push('`');
        if base_inl.len > 0 {
            out.append(", inlined from ");
            out.append(base_inl);
        }
        out.push(')');
        return;
    }
    out.append(base_inl);
}

fn inl_emit_bound_callee_clause(
    db:         CompilerDb&,
    spec_id:    i32,
    callee_nm:  const u8[:],
    raw_cond:   const u8[:],
    line_no:    i32,
    binds:      const InlBindTable&,
    else_ret:   const u8[:],
    guard_span: Span,
) {
    let trimmed = trim_ascii_ws(raw_cond);
    let _, _, has_or = inl_split_top_level(trimmed, "||");
    let _, _, has_and_top = inl_split_top_level(trimmed, "&&");
    if !slice_starts_with(trimmed, "!(") && !has_or && has_and_top {
        var rest: const u8[:] = trimmed;
        for step in 16 {
            guard rest.len > 0 else { return; }
            let head, tail, has_and = inl_split_top_level(rest, "&&");
            let part = trim_ascii_ws(if has_and { head } else { rest });
            if part.len > 0 {
                var sub_p: u8[>..] = [];
                let l_p = inl_apply_bindings(part, binds, sub_p);
                let s_p = if l_p > 0 { l_p } else { line_no };
                var src_p: u8[>..] = [];
                inl_format_source_range(callee_nm, s_p, line_no, src_p);
                var full_p: u8[>..] = [];
                inl_format_branch_inlined(binds, src_p[..], full_p);
                inl_emit_single_guard_rule(db, spec_id, sub_p[..], full_p[..], else_ret, guard_span);
            }
            if !has_and { return; }
            rest = trim_ascii_ws(tail);
        }
        return;
    }
    var sub_c: u8[>..] = [];
    let l_start = inl_apply_bindings(trimmed, binds, sub_c);
    let s_line = if l_start > 0 { l_start } else { line_no };
    var inl_src: u8[>..] = [];
    inl_format_source_range(callee_nm, s_line, line_no, inl_src);
    var full_inl: u8[>..] = [];
    inl_format_branch_inlined(binds, inl_src[..], full_inl);
    inl_emit_single_guard_rule(db, spec_id, sub_c[..], full_inl[..], else_ret, guard_span);
}

fn inl_process_callee_line(
    db:         CompilerDb&,
    spec_id:    i32,
    callee_nm:  const u8[:],
    line_raw:   const u8[:],
    line_no:    i32,
    binds:      InlBindTable&,
    else_ret:   const u8[:],
    guard_span: Span,
) {
    let line = inl_strip_line_comment(line_raw);
    guard line.len > 0 else { return; }
    if slice_starts_with(line, "let ") {
        let vname_raw, rhs_raw, has_eq = split_at_str(trim_ascii_ws(line[4..]), "=");
        if has_eq {
            let vname_untyped, _, _ = split_at_str(vname_raw, ":");
            let vname = trim_ascii_ws(vname_untyped);
            let rhs_clean, _, _ = split_at_str(rhs_raw, ";");
            var sub_rhs: u8[>..] = [];
            inl_apply_bindings(trim_ascii_ws(rhs_clean), binds, sub_rhs);
            let is_len_snap = slice_ends_with(sub_rhs[..], ".len")
                && (slice_find(vname, "start") >= 0
                    || slice_find(vname, "saved") >= 0
                    || slice_find(vname, "orig") >= 0
                    || slice_find(vname, "mark") >= 0);
            if !is_len_snap && slice_find(vname, ",") < 0 {
                inl_add_binding(binds, vname, sub_rhs[..], "", line_no);
            }
        }
        return;
    }
    let is_true_if = slice_starts_with(line, "if ")
        && slice_find(line, "{") >= 0
        && slice_find(line, "}") >= 0
        && slice_find(line, "return true") >= 0;
    if is_true_if {
        let cond_true, _, has_lb_t = split_at_str(line[3..], "{");
        if has_lb_t {
            var neg_true: u8[>..] = [];
            inl_negate_fail_cond(cond_true, neg_true);
            inl_conjoin_branch_cond(binds, neg_true[..]);
        }
        return;
    }
    let is_err_if = slice_starts_with(line, "if ")
        && (slice_find(line, "return false") >= 0
            || slice_find(line, "return -1") >= 0
            || (slice_find(line, "return ") >= 0 && slice_find(line, "Error.") >= 0 && slice_find(line, ".None") < 0));
    if is_err_if {
        let cond_raw, _, has_lb = split_at_str(line[3..], "{");
        if has_lb {
            var neg: u8[>..] = [];
            inl_negate_fail_cond(cond_raw, neg);
            inl_emit_bound_callee_clause(db, spec_id, callee_nm, neg[..], line_no, binds, else_ret, guard_span);
        }
        return;
    }
    if slice_starts_with(line, "guard ") {
        let gcond, else_part, has_else = inl_split_guard_else(line[6..]);
        if has_else {
            if !inl_is_loop_skip_else(else_part) {
                inl_emit_bound_callee_clause(db, spec_id, callee_nm, gcond, line_no, binds, else_ret, guard_span);
            } else if slice_find(else_part, "return ") >= 0 {
                inl_conjoin_branch_cond(binds, gcond);
            }
        }
        return;
    }
    if slice_starts_with(line, "return ") {
        let r_expr, _, _ = split_at_str(line[7..], ";");
        let r_trim = trim_ascii_ws(r_expr);
        let is_ctrl = slice_starts_with(r_trim, "if ")
            || slice_starts_with(r_trim, "match ")
            || slice_ends_with(r_trim, "{");
        if r_trim != "true" && r_trim != "false" && !is_ctrl && slice_find(r_trim, ",") < 0 {
            inl_emit_bound_callee_clause(db, spec_id, callee_nm, r_trim, line_no, binds, else_ret, guard_span);
        }
    }
}

fn inl_update_branch_state(line: const u8[:], binds: InlBindTable&, brace_depth: i32&) {
    let prev_depth = brace_depth;
    if brace_depth == 0 && slice_starts_with(line, "if ") && slice_find(line, "{") >= 0 && slice_find(line, "}") < 0 {
        let cond, _, _ = split_at_str(line[3..], "{");
        var sub_cond: u8[>..] = [];
        inl_apply_bindings(trim_ascii_ws(cond), binds, sub_cond);
        inl_add_binding(binds, "__branch__", sub_cond[..], "", 0);
    } else if brace_depth == 1 && slice_starts_with(line, "} else if ") && slice_find(line, "{") >= 0 {
        let cond, _, _ = split_at_str(line[10..], "{");
        var sub_cond: u8[>..] = [];
        inl_apply_bindings(trim_ascii_ws(cond), binds, sub_cond);
        inl_add_binding(binds, "__branch__", sub_cond[..], "", 0);
    } else if brace_depth == 1 && slice_starts_with(line, "} else") && slice_find(line, "{") >= 0 {
        inl_add_binding(binds, "__branch__", "else", "", 0);
    }
    for b in line {
        if b == '{' { brace_depth = inc_i32(brace_depth); }
        if b == '}' && brace_depth > 0 { brace_depth = dec_i32(brace_depth); }
    }
    if prev_depth > 0 && brace_depth == 0 {
        inl_add_binding(binds, "__branch__", "", "", 0);
    }
}

fn inl_resolve_callee_sym(db: CompilerDb&, file_id: i32, fname: const u8[:]) -> i32 {
    var csym = find_symbol_near(db, file_id, fname);
    if csym < 0 && !slice_starts_with(fname, "json::") && !slice_starts_with(fname, "std::") {
        csym = find_symbol_near(db, file_id, strip_ns_prefix(fname));
    }
    return csym;
}

fn inl_try_inline_guard_call(
    db:         CompilerDb&,
    cfg:        const Config&,
    intrinsics: const IntrinsicTable&,
    spec_id:    i32,
    clause:     const u8[:],
    else_ret:   const u8[:],
    guard_span: Span,
) -> bool {
    guard cfg.max_inline_depth >= 1 else { return false; }
    let trimmed = trim_ascii_ws(clause);
    let is_neg = slice_starts_with(trimmed, "!");
    let call_cand = if is_neg { trim_ascii_ws(trimmed[1..]) } else { trimmed };
    let fname, args_txt, is_call = inl_parse_call_text(call_cand);
    guard is_call && find_intrinsic(intrinsics, fname) < 0 else { return false; }
    let csym = inl_resolve_callee_sym(db, guard_span.file_id, fname);
    guard csym >= 0 && csym < db.symbols.len else { return false; }
    let sym = db.symbols[csym];
    guard sym.kind == SymKind.FnSym && sym.visit_state != VisitState.Active else { return false; }
    if sym.decl_node >= 0 && subtree_node_count(db, sym.decl_node) > cfg.inline_max_nodes {
        return false;
    }
    if is_neg {
        var expr_buf: u8[>..] = [];
        var inl_buf:  u8[>..] = [];
        db.symbols[csym].visit_state = VisitState.Active;
        let ok_pure = inl_expand_pure_callee(db, spec_id, csym, args_txt, expr_buf, inl_buf);
        db.symbols[csym].visit_state = VisitState.Done;
        guard ok_pure else { return false; }
        inl_inc_inlined_callees(db, spec_id);
        var neg_expr: u8[>..] = [];
        inl_negate_fail_cond(expr_buf[..], neg_expr);
        inl_emit_single_guard_rule(db, spec_id, neg_expr[..], inl_buf[..], else_ret, guard_span);
        return true;
    }
    let sig, body, sline, _ = inl_extract_fn_slices(db, sym.decl_node, csym);
    guard body.len > 0 else { return false; }
    var binds = InlBindTable { .. };
    guard inl_bind_call_params(sig, args_txt, binds) else { return false; }
    db.symbols[csym].visit_state = VisitState.Active;
    inl_inc_inlined_callees(db, spec_id);
    var cur_line = sline;
    var brace_depth:   i32     = 0;
    var pending_cstmt: u8[>..] = [];
    var cstmt_line:    i32     = 0;
    each_split(body, '\n') {
        let clean_it = inl_strip_line_comment(it);
        inl_update_branch_state(clean_it, binds, brace_depth);
        if pending_cstmt.len > 0 {
            pending_cstmt.push(' ');
            pending_cstmt.append(clean_it);
            let done_guard = slice_starts_with(pending_cstmt[..], "guard ") && slice_find(pending_cstmt[..], "}") >= 0;
            let done_semi = !slice_starts_with(pending_cstmt[..], "guard ") && slice_find(clean_it, ";") >= 0;
            if done_guard || done_semi {
                inl_process_callee_line(db, spec_id, fname, pending_cstmt[..], cstmt_line, binds, else_ret, guard_span);
                pending_cstmt.clear();
            }
        } else if slice_starts_with(clean_it, "guard ") && slice_find(clean_it, "}") < 0 {
            pending_cstmt.append(clean_it);
            cstmt_line = cur_line;
        } else if (slice_starts_with(clean_it, "let ") || slice_starts_with(clean_it, "return ")) && slice_find(clean_it, ";") < 0 {
            pending_cstmt.append(clean_it);
            cstmt_line = cur_line;
        } else {
            inl_process_callee_line(db, spec_id, fname, clean_it, cur_line, binds, else_ret, guard_span);
        }
        cur_line = inc_i32(cur_line);
    };
    db.symbols[csym].visit_state = VisitState.Done;
    return true;
}

fn inl_handle_guard_clause(
    db:         CompilerDb&,
    cfg:        const Config&,
    intrinsics: const IntrinsicTable&,
    spec_id:    i32,
    raw_clause: const u8[:],
    local_lets: const InlBindTable&,
    else_ret:   const u8[:],
    guard_span: Span,
) {
    let c = trim_ascii_ws(raw_clause);
    guard c.len > 0 && !inl_is_wire_ok_ident(c) else { return; }
    guard !inl_is_intrinsic_call_clause(intrinsics, c) else { return; }
    let prev_g = db.guards.len;
    if inl_try_inline_guard_call(db, cfg, intrinsics, spec_id, c, else_ret, guard_span) {
        let br_idx = inl_find_binding(local_lets, "__branch__");
        if br_idx >= 0 && local_lets.items[br_idx].expr.len > 0 {
            var wrap_inl: u8[>..] = [];
            for gi in sub_i64(db.guards.len, prev_g) {
                let g_idx = add_i64(prev_g, gi);
                let cur_inl = text_of(db, db.guards[g_idx].inlined_from);
                if !slice_starts_with(cur_inl, "(") {
                    inl_format_branch_inlined(local_lets, cur_inl, wrap_inl);
                    db.guards[g_idx].inlined_from = put_text(db, wrap_inl[..]);
                }
            }
        }
        return;
    }
    var sub_c:    u8[>..] = [];
    var full_inl: u8[>..] = [];
    inl_apply_bindings(c, local_lets, sub_c);
    let b_idx = inl_find_binding(local_lets, c);
    if b_idx >= 0 {
        inl_format_branch_inlined(local_lets, local_lets.items[b_idx].inlined_from[..], full_inl);
        inl_emit_single_guard_rule(
            db,
            spec_id,
            sub_c[..],
            full_inl[..],
            else_ret,
            guard_span,
        );
        return;
    }
    inl_format_branch_inlined(local_lets, "", full_inl);
    inl_emit_single_guard_rule(db, spec_id, sub_c[..], full_inl[..], else_ret, guard_span);
}

fn inl_process_guard_cond(
    db:         CompilerDb&,
    cfg:        const Config&,
    intrinsics: const IntrinsicTable&,
    spec_id:    i32,
    cond_txt:   const u8[:],
    local_lets: const InlBindTable&,
    else_ret:   const u8[:],
    guard_span: Span,
) {
    var rest: const u8[:] = trim_ascii_ws(cond_txt);
    for step in 16 {
        guard rest.len > 0 else { return; }
        let head, tail, has_and = inl_split_top_level(rest, "&&");
        if has_and {
            inl_handle_guard_clause(db, cfg, intrinsics, spec_id, head, local_lets, else_ret, guard_span);
            rest = trim_ascii_ws(tail);
        } else {
            inl_handle_guard_clause(db, cfg, intrinsics, spec_id, rest, local_lets, else_ret, guard_span);
            return;
        }
    }
}

fn inl_record_let_node_inline(
    db:        CompilerDb&,
    let_node:  i32,
    callee_id: i32,
    expr_txt:  const u8[:],
    inl_txt:   const u8[:],
) {
    guard let_node >= 0 && let_node < db.nodes.len else { return; }
    let nspan = db.nodes[let_node].span;
    let espan = put_text_at(db, expr_txt, nspan.file_id, nspan.line, nspan.col);
    let ispan = put_text_at(db, inl_txt, nspan.file_id, nspan.line, nspan.col);
    db.nodes[let_node].aux_span = espan;
    db.nodes[let_node].const_val = add_u64(shl_u64(ispan.at as u64, 32), ispan.len as u64);
    db.nodes[let_node].has_const = true;
    let rsym = db.nodes[let_node].ref_sym;
    if rsym >= 0 && rsym < db.symbols.len {
        db.symbols[rsym].type_span = espan;
        db.symbols[rsym].qual_span = ispan;
    } else {
        db.nodes[let_node].ref_sym = callee_id;
    }
    let first_child = db.nodes[let_node].first;
    if first_child >= 0 && first_child < db.nodes.len {
        db.nodes[first_child].aux_span = ispan;
    }
}

fn inl_try_inline_let_stmt(
    db:         CompilerDb&,
    cfg:        const Config&,
    intrinsics: const IntrinsicTable&,
    spec_id:    i32,
    let_node:   i32,
    stmt_txt:   const u8[:],
    line_no:    i32,
    local_lets: InlBindTable&,
) {
    guard cfg.max_inline_depth >= 1 else { return; }
    let lhs_part, rhs_part, has_eq = split_at_str(stmt_txt, "=");
    guard has_eq else { return; }
    var vname = trim_ascii_ws(lhs_part);
    if slice_starts_with(vname, "let ") { vname = trim_ascii_ws(vname[4..]); }
    let vname_clean, _, _ = split_at_str(vname, ":");
    vname = trim_ascii_ws(vname_clean);
    let rhs_clean, _, _ = split_at_str(rhs_part, ";");
    let fname, args_txt, is_call = inl_parse_call_text(rhs_clean);
    guard is_call && find_intrinsic(intrinsics, fname) < 0 else { return; }
    let file_id = db.specs[spec_id].span.file_id;
    let csym = inl_resolve_callee_sym(db, file_id, fname);
    guard csym >= 0 && csym < db.symbols.len else { return; }
    let sym = db.symbols[csym];
    guard sym.kind == SymKind.FnSym && !sym.is_ref_mut else { return; }
    if sym.decl_node >= 0 && subtree_node_count(db, sym.decl_node) > cfg.inline_max_nodes {
        return;
    }
    var expr_buf: u8[>..] = [];
    var inl_buf:  u8[>..] = [];
    if inl_expand_pure_callee(db, spec_id, csym, args_txt, expr_buf, inl_buf) {
        inl_inc_inlined_callees(db, spec_id);
        inl_add_binding(local_lets, vname, expr_buf[..], inl_buf[..], line_no);
        inl_record_let_node_inline(db, let_node, csym, expr_buf[..], inl_buf[..]);
    }
}

fn inl_find_let_node_at_line(db: const CompilerDb&, fn_node: i32, line_no: i32) -> i32 {
    guard fn_node >= 0 && fn_node < db.nodes.len else { return -1; }
    var cur = fn_node;
    for step in db.nodes.len {
        guard cur >= 0 && cur < db.nodes.len else { return -1; }
        let node = db.nodes[cur];
        if node.kind == AstKind.LetDecl && node.span.line == line_no {
            return cur;
        }
        cur = advance_preorder(db, fn_node, cur);
    }
    return -1;
}

fn inl_emit_spec_return_stmt(
    db:         CompilerDb&,
    cfg:        const Config&,
    intrinsics: const IntrinsicTable&,
    spec_id:    i32,
    base_span:  Span,
    stmt_txt:   const u8[:],
    line_no:    i32,
    local_lets: const InlBindTable&,
) {
    let ret_t = trim_ascii_ws(text_of(db, db.specs[spec_id].ret_type_text));
    guard ret_t == "bool" && slice_starts_with(stmt_txt, "return ") else { return; }
    let r_expr, _, _ = split_at_str(stmt_txt[7..], ";");
    let r_trim = trim_ascii_ws(r_expr);
    let is_ctrl = slice_starts_with(r_trim, "if ")
        || slice_starts_with(r_trim, "match ")
        || slice_ends_with(r_trim, "{");
    if slice_find(r_trim, ",") < 0 && r_trim != "true" && r_trim != "false" && !is_ctrl {
        let gspan = Span { file_id: base_span.file_id, at: base_span.at, len: 0, line: line_no, col: 1 };
        inl_process_guard_cond(db, cfg, intrinsics, spec_id, r_trim, local_lets, "", gspan);
    }
}

fn inl_step_spec_line(
    db:            CompilerDb&,
    cfg:           const Config&,
    intrinsics:    const IntrinsicTable&,
    spec_id:       i32,
    fn_node:       i32,
    base_span:     Span,
    line:          const u8[:],
    cur_line:      i32,
    local_lets:    InlBindTable&,
    pending_guard: u8[>..]&,
    guard_line:    i32&,
    pending_stmt:  u8[>..]&,
    stmt_line:     i32&,
) {
    if pending_stmt.len > 0 {
        pending_stmt.push(' ');
        pending_stmt.append(line);
        if slice_find(line, ";") >= 0 {
            if slice_starts_with(pending_stmt[..], "let ") {
                let lnode = inl_find_let_node_at_line(db, fn_node, stmt_line);
                inl_try_inline_let_stmt(db, cfg, intrinsics, spec_id, lnode, pending_stmt[..], stmt_line, local_lets);
            } else {
                inl_emit_spec_return_stmt(db, cfg, intrinsics, spec_id, base_span, pending_stmt[..], stmt_line, local_lets);
            }
            pending_stmt.clear();
        }
        return;
    }
    if pending_guard.len > 0 {
        pending_guard.append(" ");
        pending_guard.append(line);
        let gcond, else_part, has_else = inl_split_guard_else(pending_guard[..]);
        if has_else {
            if !inl_is_loop_skip_else(else_part) {
                let eret = inl_extract_else_return_expr(else_part);
                let gspan = Span { file_id: base_span.file_id, at: base_span.at, len: 0, line: guard_line, col: 1 };
                inl_process_guard_cond(db, cfg, intrinsics, spec_id, gcond, local_lets, eret, gspan);
            } else if slice_find(else_part, "return ") >= 0 {
                inl_conjoin_branch_cond(local_lets, gcond);
            }
            pending_guard.clear();
        }
        return;
    }
    let is_true_if = slice_starts_with(line, "if ")
        && slice_find(line, "{") >= 0
        && slice_find(line, "}") >= 0
        && slice_find(line, "return true") >= 0;
    if is_true_if {
        let cond_true, _, has_lb_t = split_at_str(line[3..], "{");
        if has_lb_t {
            var neg_true: u8[>..] = [];
            inl_negate_fail_cond(cond_true, neg_true);
            inl_conjoin_branch_cond(local_lets, neg_true[..]);
        }
        return;
    }
    if slice_starts_with(line, "let ") {
        if slice_find(line, ";") >= 0 {
            let lnode = inl_find_let_node_at_line(db, fn_node, cur_line);
            inl_try_inline_let_stmt(db, cfg, intrinsics, spec_id, lnode, line, cur_line, local_lets);
        } else {
            pending_stmt.clear();
            pending_stmt.append(line);
            stmt_line = cur_line;
        }
        return;
    }
    if slice_starts_with(line, "guard ") {
        let after_g = line[6..];
        let gcond, else_part, has_else = inl_split_guard_else(after_g);
        if has_else {
            if !inl_is_loop_skip_else(else_part) {
                let eret = inl_extract_else_return_expr(else_part);
                let gspan = Span { file_id: base_span.file_id, at: base_span.at, len: 0, line: cur_line, col: 1 };
                inl_process_guard_cond(db, cfg, intrinsics, spec_id, gcond, local_lets, eret, gspan);
            } else if slice_find(else_part, "return ") >= 0 {
                inl_conjoin_branch_cond(local_lets, gcond);
            }
        } else {
            pending_guard.clear();
            pending_guard.append(after_g);
            guard_line = cur_line;
        }
        return;
    }
    if slice_starts_with(line, "return ") {
        if slice_find(line, ";") >= 0 {
            inl_emit_spec_return_stmt(db, cfg, intrinsics, spec_id, base_span, line, cur_line, local_lets);
        } else {
            pending_stmt.clear();
            pending_stmt.append(line);
            stmt_line = cur_line;
        }
        return;
    }
}

fn inl_process_spec_function(
    db:         CompilerDb&,
    cfg:        const Config&,
    intrinsics: const IntrinsicTable&,
    spec_id:    i32,
) {
    let fn_sym = db.specs[spec_id].fn_sym;
    guard fn_sym >= 0 && fn_sym < db.symbols.len else { return; }
    let fn_node = db.symbols[fn_sym].decl_node;
    let base_span = if fn_node >= 0 && fn_node < db.nodes.len {
        db.nodes[fn_node].span
    } else {
        db.symbols[fn_sym].span
    };
    db.specs[spec_id].guard_start = db.guards.len as i32;
    db.specs[spec_id].guard_count = 0;

    let _, body, sline, _ = inl_extract_fn_slices(db, fn_node, fn_sym);
    guard body.len > 0 else { return; }
    db.symbols[fn_sym].visit_state = VisitState.Active;
    var local_lets = InlBindTable { .. };
    var cur_line = sline;
    var pending_guard: u8[>..] = [];
    var guard_line:    i32     = 0;
    var pending_let:   u8[>..] = [];
    var let_line:      i32     = 0;
    var brace_depth:   i32     = 0;

    each_split(body, '\n') {
        let line = inl_strip_line_comment(it);
        inl_update_branch_state(line, local_lets, brace_depth);
        inl_step_spec_line(
            db, cfg, intrinsics, spec_id, fn_node, base_span,
            line, cur_line, local_lets, pending_guard, guard_line, pending_let, let_line,
        );
        cur_line = inc_i32(cur_line);
    };
    db.symbols[fn_sym].visit_state = VisitState.Done;
}

fn inline_predicates(db: CompilerDb&, cfg: Config&, intrinsics: IntrinsicTable&) -> bool {
    for i in db.specs.len {
        let spec_id = i as i32;
        inl_process_spec_function(db, cfg, intrinsics, spec_id);
    }
    return true;
}

fn inline_predicates(db: CompilerDb&, cfg: Config&) -> bool {
    var intrinsics = IntrinsicTable { .. };
    load_default_intrinsics(intrinsics);
    return inline_predicates(db, cfg, intrinsics);
}
