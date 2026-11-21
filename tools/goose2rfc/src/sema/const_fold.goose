// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Stage 2A constant evaluator and 256-entry lookup-table range compactor.

import std;
import db from "../model";
import loader from "../config";

fn cf_digit_val(b: u8) -> u64, bool {
    if b >= '0' && b <= '9' {
        return sub_u64(b, '0'), true;
    }
    if b >= 'a' && b <= 'f' {
        return add_u64(sub_u64(b, 'a'), 10), true;
    }
    if b >= 'A' && b <= 'F' {
        return add_u64(sub_u64(b, 'A'), 10), true;
    }
    return 0, false;
}

fn cf_parse_u64_radix(s: const u8[:], radix: u64) -> u64, bool {
    guard s.len > 0 else { return 0, false; }
    var acc:    u64 = 0;
    var digits: i32 = 0;
    for i in s.len {
        let b = s[i];
        if b != '_' {
            let d, ok = cf_digit_val(b);
            guard ok && d < radix else { return 0, false; }
            acc = add_u64(mul_u64(acc, radix), d);
            digits = inc_i32(digits);
        }
    }
    return acc, digits > 0;
}

fn parse_prefixed_uint(s: const u8[:]) -> u64, bool {
    guard s.len > 2 && s[0] == '0' else {
        return cf_parse_u64_radix(s, 10);
    }
    let p = s[1];
    if p == 'x' || p == 'X' {
        return cf_parse_u64_radix(s[2..], 16);
    }
    if p == 'b' || p == 'B' {
        return cf_parse_u64_radix(s[2..], 2);
    }
    return cf_parse_u64_radix(s, 10);
}

// Parses a numeric, boolean, or character literal into a 64-bit unsigned value.
//
// Example:
//   raw = "0x3fff_ffff_ffff_ffff"
//   returns: 0x3fffffffffffffff, true
fn parse_const_literal(raw: const u8[:]) -> u64, bool {
    let s = trim_ascii_ws(raw);
    guard s.len > 0 else { return 0, false; }
    if s == "true" { return 1, true; }
    if s == "false" { return 0, true; }
    if s.len == 3 && s[0] == '\'' && s[2] == '\'' {
        return s[1], true;
    }
    return parse_prefixed_uint(s);
}

fn builtin_quic_const(short_name: const u8[:]) -> u64, bool {
    if short_name == "QUIC_VARINT_MAX" { return 0x3fffffffffffffff, true; }
    if short_name == "QUIC_FRAME_PADDING" { return 0x00, true; }
    if short_name == "QUIC_FRAME_PING" { return 0x01, true; }
    if short_name == "QUIC_FRAME_ACK" { return 0x02, true; }
    if short_name == "QUIC_FRAME_ACK_ECN" { return 0x03, true; }
    if short_name == "QUIC_FRAME_RESET_STREAM" { return 0x04, true; }
    if short_name == "QUIC_FRAME_STOP_SENDING" { return 0x05, true; }
    if short_name == "QUIC_FRAME_CRYPTO" { return 0x06, true; }
    if short_name == "QUIC_FRAME_NEW_TOKEN" { return 0x07, true; }
    if short_name == "QUIC_FRAME_STREAM_BASE" { return 0x08, true; }
    if short_name == "QUIC_STREAM_FLAG_FIN" { return 0x01, true; }
    if short_name == "QUIC_STREAM_FLAG_LEN" { return 0x02, true; }
    if short_name == "QUIC_STREAM_FLAG_OFF" { return 0x04, true; }
    return 0, false;
}

fn builtin_tls_const(short_name: const u8[:]) -> u64, bool {
    if short_name == "TLS_HS_CLIENT_HELLO" { return 1, true; }
    if short_name == "TLS_HS_SERVER_HELLO" { return 2, true; }
    if short_name == "TLS_HS_NEW_SESSION_TICKET" { return 4, true; }
    if short_name == "TLS_HS_END_OF_EARLY_DATA" { return 5, true; }
    if short_name == "TLS_HS_ENCRYPTED_EXTENSIONS" { return 8, true; }
    if short_name == "TLS_HS_CERTIFICATE" { return 11, true; }
    if short_name == "TLS_HS_CERTIFICATE_REQUEST" { return 13, true; }
    if short_name == "TLS_HS_CERTIFICATE_VERIFY" { return 15, true; }
    if short_name == "TLS_HS_FINISHED" { return 20, true; }
    if short_name == "TLS_HS_KEY_UPDATE" { return 24, true; }
    if short_name == "TLS_HS_COMPRESSED_CERTIFICATE" { return 25, true; }
    if short_name == "TLS_HS_MESSAGE_HASH" { return 254, true; }
    return 0, false;
}

fn lookup_const_value(db: CompilerDb&, name: const u8[:]) -> u64, bool {
    let s = trim_ascii_ws(name);
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
    let qv, qok = builtin_quic_const(short_name);
    if qok { return qv, true; }
    return builtin_tls_const(short_name);
}

fn is_wrapped_in_parens(s: const u8[:]) -> bool {
    guard s.len >= 2 && slice_starts_with(s, "(") && slice_ends_with(s, ")") else { return false; }
    var depth: i32 = 0;
    let last_idx = dec_i64(s.len);
    for i in s.len {
        let b = s[i];
        if b == '(' { depth = inc_i32(depth); }
        if b == ')' { depth = dec_i32(depth); }
        if depth == 0 && i < last_idx {
            return false;
        }
    }
    return depth == 0;
}

fn cf_strip_outer_parens(raw: const u8[:]) -> const u8[:] {
    var s = trim_ascii_ws(raw);
    for step in 8 {
        if !is_wrapped_in_parens(s) {
            return s;
        }
        s = trim_ascii_ws(s[1..^1]);
    }
    return s;
}

fn strip_cast_suffix(raw: const u8[:]) -> const u8[:] {
    let s = cf_strip_outer_parens(raw);
    let lhs_bang, _, ok_bang = split_at_str(s, " as! ");
    if ok_bang && slice_find(lhs_bang, "(") < 0 {
        return cf_strip_outer_parens(lhs_bang);
    }
    let lhs_as, _, ok_as = split_at_str(s, " as ");
    if ok_as && slice_find(lhs_as, "(") < 0 {
        return cf_strip_outer_parens(lhs_as);
    }
    return s;
}

fn eval_const_atom(db: CompilerDb&, raw: const u8[:]) -> u64, bool {
    var s = strip_cast_suffix(raw);
    guard s.len > 0 else { return 0, false; }
    var invert = false;
    if s[0] == '~' {
        invert = true;
        s = strip_cast_suffix(s[1..]);
    }
    let lit, ok_lit = parse_const_literal(s);
    if ok_lit {
        return if invert { ~lit } else { lit }, true;
    }
    let sv, ok_sym = lookup_const_value(db, s);
    return if invert { ~sv } else { sv }, ok_sym;
}

fn find_top_level_op(s: const u8[:], op: const u8[:]) -> i64 {
    guard op.len > 0 && s.len > op.len else { return -1; }
    var depth: i32 = 0;
    for i in s.len {
        let b = s[i];
        if b == '(' { depth = inc_i32(depth); }
        if b == ')' { depth = dec_i32(depth); }
        let tail = s[i..];
        if depth == 0 && slice_starts_with(tail, op) {
            return i;
        }
    }
    return -1;
}

fn eval_const_shift_or_mul(db: CompilerDb&, raw: const u8[:]) -> u64, bool {
    let s = cf_strip_outer_parens(raw);
    let shl_idx = find_top_level_op(s, "<<");
    if shl_idx > 0 {
        let lv, lok = eval_const_atom(db, s[..shl_idx]);
        let rv, rok = eval_const_atom(db, s[shl_idx..][2..]);
        guard lok && rok && rv < 64 else { return 0, false; }
        return shl_u64(lv, rv), true;
    }
    let shr_idx = find_top_level_op(s, ">>");
    if shr_idx > 0 {
        let lv, lok = eval_const_atom(db, s[..shr_idx]);
        let rv, rok = eval_const_atom(db, s[shr_idx..][2..]);
        guard lok && rok && rv < 64 else { return 0, false; }
        return lv >> rv, true;
    }
    let mul_idx = find_top_level_op(s, "*");
    if mul_idx > 0 {
        let lv, lok = eval_const_atom(db, s[..mul_idx]);
        let rv, rok = eval_const_atom(db, s[mul_idx..][1..]);
        guard lok && rok else { return 0, false; }
        return mul_u64(lv, rv), true;
    }
    return eval_const_atom(db, s);
}

fn eval_const_add_sub(db: CompilerDb&, raw: const u8[:]) -> u64, bool {
    let s = cf_strip_outer_parens(raw);
    let plus_idx = find_top_level_op(s, " + ");
    if plus_idx > 0 {
        let lv, lok = eval_const_shift_or_mul(db, s[..plus_idx]);
        let rv, rok = eval_const_shift_or_mul(db, s[plus_idx..][3..]);
        guard lok && rok else { return 0, false; }
        return add_u64(lv, rv), true;
    }
    let sub_idx = find_top_level_op(s, " - ");
    if sub_idx > 0 {
        let lv, lok = eval_const_shift_or_mul(db, s[..sub_idx]);
        let rv, rok = eval_const_shift_or_mul(db, s[sub_idx..][3..]);
        guard lok && rok else { return 0, false; }
        return sub_u64(lv, rv), true;
    }
    return eval_const_shift_or_mul(db, s);
}

// Evaluates a constant integer expression (literals, shifts, masks, add/sub, symbols).
//
// Example:
//   raw = "((1 as u64) << 62) - 1"
//   returns: 0x3fffffffffffffff, true
fn eval_const_expr(db: CompilerDb&, raw: const u8[:]) -> u64, bool {
    let s = cf_strip_outer_parens(raw);
    guard s.len > 0 else { return 0, false; }
    if find_top_level_op(s, "|") > 0 {
        var acc: u64 = 0;
        var ok_all = true;
        each_split(s, '|') {
            let v, ok = eval_const_add_sub(db, it);
            if ok { acc = acc | v; } else { ok_all = false; }
        };
        return acc, ok_all;
    }
    let xor_idx = find_top_level_op(s, "^");
    if xor_idx > 0 {
        let lv, lok = eval_const_add_sub(db, s[..xor_idx]);
        let rv, rok = eval_const_add_sub(db, s[xor_idx..][1..]);
        guard lok && rok else { return 0, false; }
        return lv ^ rv, true;
    }
    let and_idx = find_top_level_op(s, "&");
    if and_idx > 0 {
        let lv, lok = eval_const_add_sub(db, s[..and_idx]);
        let rv, rok = eval_const_add_sub(db, s[and_idx..][1..]);
        guard lok && rok else { return 0, false; }
        return lv & rv, true;
    }
    return eval_const_add_sub(db, s);
}

fn scan_stmt_from_offset(db: const CompilerDb&, at: i32) -> const u8[:] {
    guard at >= 0 && at < db.text.len else { return ""; }
    let tail = db.text[at..];
    let limit = min(tail.len, 8192);
    let window = tail[..limit];
    let semi = slice_find(window, ";");
    guard semi > 0 else { return window; }
    return window[..semi];
}

// Extracts the right-hand side initializer expression text of a const/let declaration.
//
// Example:
//   stmt = "const QUIC_VARINT_MAX: u64 = 0x3fff_ffff_ffff_ffff"
//   returns: "0x3fff_ffff_ffff_ffff"
fn extract_decl_init_text(db: const CompilerDb&, decl_node: i32, fallback: Span) -> const u8[:] {
    if decl_node >= 0 && decl_node < db.nodes.len {
        let node = db.nodes[decl_node];
        let span_txt = text_of(db, node.span);
        let _, rhs, has_eq = split_at_str(span_txt, "=");
        if has_eq {
            let clean, _, _ = split_at_str(rhs, ";");
            return trim_ascii_ws(clean);
        }
        if node.last >= 0 && node.last < db.nodes.len {
            let child_txt = trim_ascii_ws(text_of(db, db.nodes[node.last].span));
            if child_txt.len > 0 {
                return child_txt;
            }
        }
        let scanned = scan_stmt_from_offset(db, node.span.at);
        let _, srhs, sok = split_at_str(scanned, "=");
        if sok {
            return trim_ascii_ws(srhs);
        }
    }
    let scanned_fb = scan_stmt_from_offset(db, fallback.at);
    let _, frhs, fok = split_at_str(scanned_fb, "=");
    if fok {
        return trim_ascii_ws(frhs);
    }
    return "";
}

fn eval_ast_const_node(db: CompilerDb&, node_id: i32) -> u64, bool {
    guard node_id >= 0 && node_id < db.nodes.len else { return 0, false; }
    let node = db.nodes[node_id];
    if node.has_const {
        return node.const_val, true;
    }
    return eval_const_expr(db, text_of(db, node.span));
}

fn is_lookup_table_type(type_txt: const u8[:], stmt_txt: const u8[:]) -> bool {
    if slice_find(type_txt, "bool[256]") >= 0 || slice_find(type_txt, "u8[256]") >= 0 {
        return true;
    }
    return slice_find(stmt_txt, "bool[256]") >= 0 || slice_find(stmt_txt, "u8[256]") >= 0;
}

fn append_hex_byte_range(out: u8[>..]&, start_idx: i32, end_idx: i32) {
    if out.len > 0 {
        out.append(", ");
    }
    format_u64_hex_lit(out, start_idx as u64);
    if end_idx > start_idx {
        out.append("..");
        format_u64_hex_lit(out, end_idx as u64);
    }
}

fn is_active_table_entry(db: CompilerDb&, elem: const u8[:]) -> bool {
    let s = trim_ascii_ws(elem);
    guard s.len > 0 && s != "false" && s != "0" && s != "0x00" else { return false; }
    if s == "true" {
        return true;
    }
    let v, ok = eval_const_expr(db, s);
    return ok && v != 0;
}

// Compacts a 256-entry array initializer into contiguous hex byte intervals (e.g. `0x21..0x7e`).
//
// Example:
//   init_txt = "[false, true, true, false]"
//   appends: "0x01..0x02" into `out`
fn compact_table_initializer(db: CompilerDb&, init_txt: const u8[:], out: u8[>..]&) -> bool {
    let _, after_lbrack, ok_l = split_at_str(init_txt, "[");
    guard ok_l else { return false; }
    let body, _, _ = split_at_str(after_lbrack, "]");
    out.clear();
    var idx:       i32 = 0;
    var run_start: i32 = -1;
    var run_end:   i32 = -1;
    each_split(body, ',') {
        let item = trim_ascii_ws(it);
        if item.len > 0 && idx < 256 {
            if is_active_table_entry(db, item) {
                if run_start < 0 { run_start = idx; }
                run_end = idx;
            } else if run_start >= 0 {
                append_hex_byte_range(out, run_start, run_end);
                run_start = -1;
            }
            idx = inc_i32(idx);
        }
    };
    if run_start >= 0 {
        append_hex_byte_range(out, run_start, run_end);
    }
    return out.len > 0;
}

fn try_fold_symbol_table(db: CompilerDb&, sym_id: i32) {
    guard sym_id >= 0 && sym_id < db.symbols.len else { return; }
    let sym = db.symbols[sym_id];
    let decl = sym.decl_node;
    let type_txt = text_of(db, sym.type_span);
    let stmt_txt = scan_stmt_from_offset(db, sym.span.at);
    guard is_lookup_table_type(type_txt, stmt_txt) else { return; }
    let init_txt = extract_decl_init_text(db, decl, sym.span);
    var compacted: u8[>..] = [];
    guard compact_table_initializer(db, init_txt, compacted) else { return; }
    let cspan = put_text_at(db, compacted[..], sym.span.file_id, sym.span.line, sym.span.col);
    if decl >= 0 && decl < db.nodes.len {
        db.nodes[decl].aux_span = cspan;
    }
    db.symbols[sym_id].type_span = cspan;
}

fn fold_single_symbol(db: CompilerDb&, sym_id: i32) -> bool {
    guard sym_id >= 0 && sym_id < db.symbols.len else { return false; }
    let sym = db.symbols[sym_id];
    guard sym.kind == SymKind.ConstSym else { return false; }
    if sym.has_const && sym.visit_state == VisitState.Done {
        return true;
    }
    guard sym.visit_state != VisitState.Active else { return false; }
    db.symbols[sym_id].visit_state = VisitState.Active;
    let decl = sym.decl_node;
    let init_txt = extract_decl_init_text(db, decl, sym.span);
    var val, ok = eval_const_expr(db, init_txt);
    if !ok && decl >= 0 && decl < db.nodes.len {
        let last_child = db.nodes[decl].last;
        val, ok = eval_ast_const_node(db, last_child);
    }
    if ok {
        db.symbols[sym_id].const_val = val;
        db.symbols[sym_id].has_const = true;
        db.symbols[sym_id].visit_state = VisitState.Done;
        if decl >= 0 && decl < db.nodes.len {
            db.nodes[decl].const_val = val;
            db.nodes[decl].has_const = true;
        }
        return true;
    }
    db.symbols[sym_id].visit_state = VisitState.Unvisited;
    return false;
}

fn propagate_single_node(db: CompilerDb&, nid: i32, fold_tables: bool) {
    guard nid >= 0 && nid < db.nodes.len else { return; }
    let node = db.nodes[nid];
    let rsym = node.ref_sym;
    if rsym >= 0 && rsym < db.symbols.len && db.symbols[rsym].has_const {
        db.nodes[nid].const_val = db.symbols[rsym].const_val;
        db.nodes[nid].has_const = true;
    }
    guard node.kind == AstKind.ConstDecl && !db.nodes[nid].has_const else { return; }
    let init_txt = extract_decl_init_text(db, nid, node.span);
    let v, ok = eval_const_expr(db, init_txt);
    if ok {
        db.nodes[nid].const_val = v;
        db.nodes[nid].has_const = true;
    }
    if fold_tables && is_lookup_table_type(text_of(db, node.aux_span), text_of(db, node.span)) {
        var comp: u8[>..] = [];
        if compact_table_initializer(db, init_txt, comp) {
            db.nodes[nid].aux_span = put_text_at(db, comp[..], node.span.file_id, node.span.line, node.span.col);
        }
    }
}

fn propagate_const_to_nodes(db: CompilerDb&, fold_tables: bool) {
    for i in db.nodes.len {
        let nid = i as i32;
        propagate_single_node(db, nid, fold_tables);
    }
}

fn fold_constants(db: CompilerDb&, cfg: Config&) -> bool {
    for pass in 4 {
        for i in db.symbols.len {
            let sym_id = i as i32;
            fold_single_symbol(db, sym_id);
        }
    }
    for i in db.symbols.len {
        let sym_id = i as i32;
        if db.symbols[sym_id].kind == SymKind.ConstSym {
            db.symbols[sym_id].visit_state = VisitState.Done;
            if cfg.fold_lookup_tables {
                try_fold_symbol_table(db, sym_id);
            }
        }
    }
    propagate_const_to_nodes(db, cfg.fold_lookup_tables);
    return true;
}

fn fold_constants(db: CompilerDb&) -> bool {
    var cfg = default_config();
    return fold_constants(db, cfg);
}
