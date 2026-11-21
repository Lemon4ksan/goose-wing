// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Syntax-directed symbol, UFCS, cast-mode, and root-parameter alias resolver.

import std;
import db from "../model";
import loader from "../config";

fn digit_val(b: u8) -> u64, bool {
    if b >= '0' && b <= '9' { return sub_u64(b, '0'), true; }
    if b >= 'a' && b <= 'f' { return add_u64(10, sub_u64(b, 'a')), true; }
    if b >= 'A' && b <= 'F' { return add_u64(10, sub_u64(b, 'A')), true; }
    return 0, false;
}

fn parse_u64_radix(s: const u8[:], base: u64) -> u64, bool {
    var acc:    u64 = 0;
    var digits: i32 = 0;
    for i in s.len {
        let b = s[i];
        if b == '_' { continue; }
        let d, ok = digit_val(b);
        guard ok && d < base else { return 0, false; }
        acc = add_u64(mul_u64(acc, base), d);
        digits = inc_i32(digits);
    }
    return acc, digits > 0;
}

fn eval_int_literal_str(raw: const u8[:]) -> u64, bool {
    let s = trim_ascii_ws(raw);
    guard s.len > 0 else { return 0, false; }
    if s.len > 2 && (slice_starts_with(s, "0x") || slice_starts_with(s, "0X")) {
        return parse_u64_radix(s[2..], 16);
    }
    if s.len > 2 && (slice_starts_with(s, "0b") || slice_starts_with(s, "0B")) {
        return parse_u64_radix(s[2..], 2);
    }
    return parse_u64_radix(s, 10);
}

fn eval_const_bin_op(op: u8, lv: u64, rv: u64) -> u64, bool {
    if op == TOK_SHL { return shl_u64(lv, rv), true; }
    if op == TOK_SHR { return lv >> rv, true; }
    if op == TOK_PIPE { return lv | rv, true; }
    if op == TOK_AMP { return lv & rv, true; }
    if op == TOK_CARET { return lv ^ rv, true; }
    if op == TOK_PLUS { return add_u64(lv, rv), true; }
    if op == TOK_MINUS { return sub_u64(lv, rv), true; }
    if op == TOK_MUL { return mul_u64(lv, rv), true; }
    return 0, false;
}

fn eval_const_leaf(db: CompilerDb&, node_id: i32) -> u64, bool {
    let kind = db.nodes[node_id].kind;
    if kind == AstKind.IntLit {
        let v, ok = eval_int_literal_str(text_of(db, db.nodes[node_id].span));
        if ok {
            db.nodes[node_id].const_val = v;
            db.nodes[node_id].has_const = true;
        }
        return v, ok;
    }
    if kind == AstKind.Ident {
        let sym_id = find_symbol(db, trim_ascii_ws(text_of(db, db.nodes[node_id].span)));
        if sym_id >= 0 && sym_id < db.symbols.len && db.symbols[sym_id].has_const {
            return db.symbols[sym_id].const_val, true;
        }
    }
    return 0, false;
}

recursive fn eval_simple_const_node(db: CompilerDb&, node_id: i32) -> u64, bool {
    guard node_id >= 0 && node_id < db.nodes.len else { return 0, false; }
    if db.nodes[node_id].has_const {
        return db.nodes[node_id].const_val, true;
    }
    let kind = db.nodes[node_id].kind;
    if kind == AstKind.CastExpr {
        return eval_simple_const_node(db, db.nodes[node_id].first);
    }
    if kind == AstKind.BinaryExpr {
        let c0 = db.nodes[node_id].first;
        let c1 = if c0 >= 0 && c0 < db.nodes.len { db.nodes[c0].next } else { -1 };
        let lv, ok_l = eval_simple_const_node(db, c0);
        let rv, ok_r = eval_simple_const_node(db, c1);
        guard ok_l && ok_r else { return 0, false; }
        return eval_const_bin_op(db.nodes[node_id].op_tok, lv, rv);
    }
    return eval_const_leaf(db, node_id);
}

fn make_qualified_span(db: CompilerDb&, ns: const u8[:], name_span: Span) -> Span {
    let name = trim_ascii_ws(text_of(db, name_span));
    let eff_ns = if ns.len > 0 && ns != "internal" {
        ns
    } else if slice_starts_with(name, "QUIC_") || slice_starts_with(name, "H3_") {
        "rfc"
    } else {
        ""
    };
    guard eff_ns.len > 0 else { return name_span; }
    var qbuf: u8[>..] = [];
    qbuf.append(eff_ns);
    qbuf.append("::");
    qbuf.append(name);
    return put_text_at(db, qbuf[..], name_span.file_id, name_span.line, name_span.col);
}

fn resolve_type_with_enums(db: CompilerDb&, raw_type: const u8[:]) -> ValType, bool {
    let vt, is_ref = classify_val_type(raw_type);
    if vt == ValType.StructVal {
        let base_raw, _ = strip_ref_suffix(trim_ascii_ws(raw_type));
        let base = if slice_starts_with(base_raw, "const ") {
            trim_ascii_ws(base_raw[6..])
        } else {
            base_raw
        };
        let sym_id = find_symbol(db, base);
        if sym_id >= 0 && sym_id < db.symbols.len && db.symbols[sym_id].kind == SymKind.EnumSym {
            return ValType.EnumVal, is_ref;
        }
    }
    return vt, is_ref;
}

fn register_const_or_let_top(db: CompilerDb&, ns: const u8[:], node_id: i32) {
    let name_sp = db.nodes[node_id].span;
    let qual_sp = make_qualified_span(db, ns, name_sp);
    let type_sp = db.nodes[node_id].aux_span;
    let vt, is_ref = resolve_type_with_enums(db, text_of(db, type_sp));
    let val, has_c = eval_simple_const_node(db, db.nodes[node_id].first);
    db.nodes[node_id].val_type = vt;
    db.nodes[node_id].const_val = val;
    db.nodes[node_id].has_const = has_c;
    let sym_id = add_symbol(db, Symbol {
        kind:       SymKind.ConstSym,
        name_span:  name_sp,
        qual_span:  qual_sp,
        type_span:  type_sp,
        decl_node:  node_id,
        val_type:   vt,
        is_ref_mut: is_ref,
        const_val:  val,
        has_const:  has_c,
        span:       name_sp,
        ..
    });
    db.nodes[node_id].ref_sym = sym_id;
}

fn register_type_decl_top(db: CompilerDb&, ns: const u8[:], node_id: i32, sk: SymKind, vt: ValType) {
    let name_sp = db.nodes[node_id].span;
    let qual_sp = make_qualified_span(db, ns, name_sp);
    let sym_id = add_symbol(db, Symbol {
        kind:      sk,
        name_span: name_sp,
        qual_span: qual_sp,
        decl_node: node_id,
        val_type:  vt,
        span:      name_sp,
        ..
    });
    db.nodes[node_id].ref_sym = sym_id;
    db.nodes[node_id].val_type = vt;
    if sk == SymKind.StructSym {
        var f = db.nodes[node_id].first;
        for step in db.nodes.len {
            guard f >= 0 && f < db.nodes.len else { break; }
            let f_vt, _ = resolve_type_with_enums(db, text_of(db, db.nodes[f].aux_span));
            db.nodes[f].val_type = f_vt;
            f = db.nodes[f].next;
        }
    }
}

fn register_module_items(db: CompilerDb&, file_id: i32) {
    guard file_id >= 0 && file_id < db.files.len else { return; }
    let mod_id = db.files[file_id].root_node;
    guard mod_id >= 0 && mod_id < db.nodes.len else { return; }
    let ns = trim_ascii_ws(text_of(db, db.files[file_id].ns_span));
    var cur = db.nodes[mod_id].first;
    for step in db.nodes.len {
        guard cur >= 0 && cur < db.nodes.len else { break; }
        let k = db.nodes[cur].kind;
        if k == AstKind.ConstDecl || k == AstKind.LetDecl {
            register_const_or_let_top(db, ns, cur);
        } else if k == AstKind.EnumDecl {
            register_type_decl_top(db, ns, cur, SymKind.EnumSym, ValType.EnumVal);
        } else if k == AstKind.StructDecl {
            register_type_decl_top(db, ns, cur, SymKind.StructSym, ValType.StructVal);
        } else if k == AstKind.FnDecl {
            let name_sp = db.nodes[cur].span;
            let qual_sp = make_qualified_span(db, ns, name_sp);
            let sym_id = add_symbol(db, Symbol {
                kind:      SymKind.FnSym,
                name_span: name_sp,
                qual_span: qual_sp,
                type_span: db.nodes[cur].aux_span,
                decl_node: cur,
                span:      name_sp,
                ..
            });
            db.nodes[cur].ref_sym = sym_id;
        }
        cur = db.nodes[cur].next;
    }
}

fn find_scoped_symbol(db: CompilerDb&, scope_start: i32, name: const u8[:]) -> i32 {
    guard name.len > 0 && scope_start >= 0 && scope_start <= db.symbols.len else {
        return find_symbol(db, name);
    }
    let count = sub_i32(db.symbols.len as i32, scope_start);
    for step in count {
        let idx = sub_i32(dec_i32(db.symbols.len as i32), step);
        if sym_matches_name(db, idx, name) {
            return idx;
        }
    }
    return find_symbol(db, name);
}

fn resolve_root_param_from_rhs(db: CompilerDb&, scope_start: i32, rhs_id: i32) -> i32 {
    guard rhs_id >= 0 && rhs_id < db.nodes.len else { return -1; }
    let rk = db.nodes[rhs_id].kind;
    let base_id = if rk == AstKind.SliceExpr || rk == AstKind.IndexExpr || rk == AstKind.FieldExpr {
        db.nodes[rhs_id].first
    } else {
        rhs_id
    };
    guard base_id >= 0 && base_id < db.nodes.len else { return -1; }
    let base_name = trim_ascii_ws(text_of(db, db.nodes[base_id].span));
    let sym_id = find_scoped_symbol(db, scope_start, base_name);
    guard sym_id >= scope_start && sym_id < db.symbols.len else { return -1; }
    if db.symbols[sym_id].kind == SymKind.ParamSym {
        return sym_id;
    }
    return db.symbols[sym_id].root_param;
}

fn primary_let_name_span(db: const CompilerDb&, lhs_span: Span) -> Span {
    let raw = text_of(db, lhs_span);
    let comma_idx = slice_find(raw, ",");
    guard comma_idx > 0 else { return lhs_span; }
    return Span {
        file_id: lhs_span.file_id,
        at:      lhs_span.at,
        len:     comma_idx as i32,
        line:    lhs_span.line,
        col:     lhs_span.col,
    };
}

fn resolve_ufcs_or_call(db: CompilerDb&, intrinsics: const IntrinsicTable&, node_id: i32) {
    let name = trim_ascii_ws(text_of(db, db.nodes[node_id].span));
    let intr_idx = find_intrinsic(intrinsics, name);
    if intr_idx >= 0 && intr_idx < intrinsics.entries.len {
        db.nodes[node_id].const_val = add_u64(intr_idx as u64, 1);
        if db.nodes[node_id].kind == AstKind.UfcsCallExpr {
            let sp = db.nodes[node_id].span;
            let canon = intrinsics.entries[intr_idx].symbol[..];
            db.nodes[node_id].span = put_text_at(db, canon, sp.file_id, sp.line, sp.col);
        }
    }
    let sym_id = find_symbol(db, name);
    if sym_id >= 0 {
        db.nodes[node_id].ref_sym = sym_id;
    }
}

fn normalize_cast_node(db: CompilerDb&, node_id: i32) {
    let raw_ty = trim_ascii_ws(text_of(db, db.nodes[node_id].aux_span));
    let vt, _ = resolve_type_with_enums(db, raw_ty);
    db.nodes[node_id].val_type = vt;
    let lhs_id = db.nodes[node_id].first;
    guard lhs_id >= 0 && lhs_id < db.nodes.len else { return; }
    let lhs_str = trim_ascii_ws(text_of(db, db.nodes[lhs_id].span));
    let mode = db.nodes[node_id].cast_mode;
    let op_str = if mode == CastMode.TruncateAsBang { " as_truncate " } else { " as_checked " };
    var norm: u8[>..] = [];
    norm.append(lhs_str);
    norm.append(op_str);
    norm.append(raw_ty);
    let sp = db.nodes[node_id].span;
    db.nodes[node_id].aux_span = put_text_at(db, norm[..], sp.file_id, sp.line, sp.col);
}

fn resolve_let_node(db: CompilerDb&, scope_start: i32, cur: i32) {
    let rhs_id = db.nodes[cur].first;
    let is_rebind = db.nodes[cur].op_tok == TOK_REBIND;
    let rhs_k = if rhs_id >= 0 && rhs_id < db.nodes.len { db.nodes[rhs_id].kind } else { AstKind.Ident };
    let root_p = if is_rebind || rhs_k == AstKind.SliceExpr || rhs_k == AstKind.IndexExpr {
        resolve_root_param_from_rhs(db, scope_start, rhs_id)
    } else {
        -1
    };
    let p_span = primary_let_name_span(db, db.nodes[cur].span);
    let lsym = add_symbol(db, Symbol {
        kind:       SymKind.LocalSym,
        name_span:  p_span,
        qual_span:  p_span,
        decl_node:  cur,
        val_type:   db.nodes[cur].val_type,
        is_ref_mut: is_rebind,
        root_param: root_p,
        span:       p_span,
        ..
    });
    db.nodes[cur].ref_sym = lsym;
}

fn resolve_ident_node(db: CompilerDb&, scope_start: i32, cur: i32) {
    let name = trim_ascii_ws(text_of(db, db.nodes[cur].span));
    let sym_id = find_scoped_symbol(db, scope_start, name);
    guard sym_id >= 0 && sym_id < db.symbols.len else { return; }
    db.nodes[cur].ref_sym = sym_id;
    db.nodes[cur].val_type = db.symbols[sym_id].val_type;
    if db.symbols[sym_id].has_const {
        db.nodes[cur].const_val = db.symbols[sym_id].const_val;
        db.nodes[cur].has_const = true;
    }
}

fn resolve_body_node(
    db:          CompilerDb&,
    intrinsics:  const IntrinsicTable&,
    scope_start: i32,
    cur:         i32,
) {
    let k = db.nodes[cur].kind;
    if k == AstKind.LetDecl {
        resolve_let_node(db, scope_start, cur);
    } else if k == AstKind.UfcsCallExpr || k == AstKind.CallExpr {
        resolve_ufcs_or_call(db, intrinsics, cur);
    } else if k == AstKind.CastExpr {
        normalize_cast_node(db, cur);
    } else if k == AstKind.Ident {
        resolve_ident_node(db, scope_start, cur);
    }
}

fn register_fn_params(db: CompilerDb&, fn_id: i32) -> i32, i32, i32 {
    let param_start = db.symbols.len as i32;
    var param_count: i32 = 0;
    var body_id:     i32 = -1;
    var child = db.nodes[fn_id].first;
    for step in db.nodes.len {
        guard child >= 0 && child < db.nodes.len else { break; }
        if db.nodes[child].kind == AstKind.ParamDecl {
            let p_sp = db.nodes[child].span;
            let ty_sp = db.nodes[child].aux_span;
            let vt, is_ref = resolve_type_with_enums(db, text_of(db, ty_sp));
            let psym = add_symbol(db, Symbol {
                kind:       SymKind.ParamSym,
                name_span:  p_sp,
                qual_span:  p_sp,
                type_span:  ty_sp,
                decl_node:  child,
                val_type:   vt,
                is_ref_mut: is_ref,
                span:       p_sp,
                ..
            });
            db.nodes[child].val_type = vt;
            db.nodes[child].ref_sym = psym;
            param_count = inc_i32(param_count);
        } else if db.nodes[child].kind == AstKind.Block {
            body_id = child;
        }
        child = db.nodes[child].next;
    }
    return param_start, param_count, body_id;
}

fn fn_matches_config(cfg: const Config&, fn_name: const u8[:]) -> bool {
    for e_idx in cfg.exclude.len {
        let ex = cfg.exclude[e_idx][..];
        if ex.len > 0 && glob_match(ex, fn_name) {
            return false;
        }
    }
    guard cfg.functions.len > 0 else { return true; }
    for f_idx in cfg.functions.len {
        let pat = cfg.functions[f_idx][..];
        if pat.len > 0 && glob_match(pat, fn_name) {
            return true;
        }
    }
    return false;
}

fn file_has_matching_fn(db: const CompilerDb&, cfg: const Config&, mod_id: i32) -> bool {
    guard mod_id >= 0 && mod_id < db.nodes.len else { return false; }
    var child = db.nodes[mod_id].first;
    for step in db.nodes.len {
        guard child >= 0 && child < db.nodes.len else { break; }
        if db.nodes[child].kind == AstKind.FnDecl {
            let name = trim_ascii_ws(text_of(db, db.nodes[child].span));
            if fn_matches_config(cfg, name) {
                return true;
            }
        }
        child = db.nodes[child].next;
    }
    return false;
}

fn process_fn_decl(
    db:         CompilerDb&,
    intrinsics: const IntrinsicTable&,
    fn_id:      i32,
    emit_spec:  bool,
) {
    let p_start, p_count, body_id = register_fn_params(db, fn_id);
    if body_id >= 0 && body_id < db.nodes.len {
        var cur = body_id;
        for step in db.nodes.len {
            guard cur >= 0 && cur < db.nodes.len else { break; }
            resolve_body_node(db, intrinsics, p_start, cur);
            cur = advance_preorder(db, body_id, cur);
        }
    }
    if emit_spec {
        db.specs.push(SpecFunction {
            fn_sym:        db.nodes[fn_id].ref_sym,
            ret_type_text: db.nodes[fn_id].aux_span,
            param_start:   p_start,
            param_count:   p_count,
            end_line:      db.nodes[fn_id].const_val as i32,
            span:          db.nodes[fn_id].span,
            ..
        });
    }
}

fn process_file_functions(
    db:         CompilerDb&,
    cfg:        const Config&,
    intrinsics: const IntrinsicTable&,
    file_id:    i32,
    any_target: bool,
) {
    let mod_id = db.files[file_id].root_node;
    guard mod_id >= 0 && mod_id < db.nodes.len else { return; }
    let is_targ = if any_target { db.files[file_id].is_target } else { true };
    let has_match = file_has_matching_fn(db, cfg, mod_id);
    var child = db.nodes[mod_id].first;
    for step in db.nodes.len {
        guard child >= 0 && child < db.nodes.len else { break; }
        if db.nodes[child].kind == AstKind.FnDecl {
            let fn_name = trim_ascii_ws(text_of(db, db.nodes[child].span));
            let emit = is_targ && (if has_match { fn_matches_config(cfg, fn_name) } else { true });
            process_fn_decl(db, intrinsics, child, emit);
        }
        child = db.nodes[child].next;
    }
}

fn build_hir(db: CompilerDb&, cfg: Config&, intrinsics: IntrinsicTable&) -> bool {
    var any_target = false;
    for i in db.files.len {
        if db.files[i].is_target {
            any_target = true;
        }
        register_module_items(db, i as i32);
    }
    for j in db.files.len {
        process_file_functions(db, cfg, intrinsics, j as i32, any_target);
    }
    return true;
}

fn build_hir(db: CompilerDb&, intrinsics: IntrinsicTable&) -> bool {
    var cfg = default_config();
    return build_hir(db, cfg, intrinsics);
}
