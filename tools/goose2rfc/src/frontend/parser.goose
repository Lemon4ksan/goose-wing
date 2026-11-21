// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Flat index-tree CST/AST token-range parser for Goose modules.

import std;
import db from "../model";
import loader from "../config";

fn tok_at(db: const CompilerDb&, idx: i32) -> Token {
    guard idx >= 0 && idx < db.tokens.len else { return Token { kind: TOK_EOF, .. }; }
    return db.tokens[idx];
}

fn tok_kind(db: const CompilerDb&, idx: i32) -> u8 {
    return tok_at(db, idx).kind;
}

fn span_of_range(db: const CompilerDb&, start_tok: i32, end_tok: i32) -> Span {
    guard start_tok >= 0 && end_tok > start_tok && start_tok < db.tokens.len else {
        return Span { .. };
    }
    let last_idx = min(dec_i32(end_tok) as i64, dec_i64(db.tokens.len)) as i32;
    let t0 = tok_at(db, start_tok).span;
    let t1 = tok_at(db, last_idx).span;
    let end_at = add_i32(t1.at, t1.len);
    return Span {
        file_id: t0.file_id,
        at:      t0.at,
        len:     max(0, sub_i32(end_at, t0.at)),
        line:    t0.line,
        col:     t0.col,
    };
}

fn unquote_span(s: Span) -> Span {
    guard s.len >= 2 else { return s; }
    return Span {
        file_id: s.file_id,
        at:      inc_i32(s.at),
        len:     sub_i32(s.len, 2),
        line:    s.line,
        col:     inc_i32(s.col),
    };
}

fn is_open_delim(k: u8) -> bool {
    return k == TOK_LPAREN || k == TOK_LBRACKET || k == TOK_LCURLY;
}

fn is_close_delim(k: u8) -> bool {
    return k == TOK_RPAREN || k == TOK_RBRACKET || k == TOK_RCURLY;
}

fn step_delim_depth(k: u8, depth: i32) -> i32 {
    if is_open_delim(k) { return inc_i32(depth); }
    if is_close_delim(k) { return max(0, dec_i32(depth)); }
    return depth;
}

fn find_matching_delim(db: const CompilerDb&, open_tok: i32, limit_tok: i32) -> i32 {
    let count = sub_i32(limit_tok, open_tok);
    guard count > 0 else { return open_tok; }
    var depth: i32 = 0;
    for step in count {
        let idx = add_i32(open_tok, step);
        let k = tok_kind(db, idx);
        depth = step_delim_depth(k, depth);
        if depth == 0 {
            return idx;
        }
    }
    return dec_i32(limit_tok);
}

fn find_matching_open_backward(db: const CompilerDb&, start_tok: i32, close_tok: i32) -> i32 {
    let count = inc_i32(sub_i32(close_tok, start_tok));
    guard count > 0 else { return start_tok; }
    var depth: i32 = 0;
    for step in count {
        let idx = sub_i32(close_tok, step);
        let k = tok_kind(db, idx);
        if is_close_delim(k) {
            depth = inc_i32(depth);
        } else if is_open_delim(k) {
            depth = dec_i32(depth);
            if depth == 0 {
                return idx;
            }
        }
    }
    return -1;
}

fn find_top_level_tok(db: const CompilerDb&, start_tok: i32, limit_tok: i32, target: u8) -> i32 {
    let count = sub_i32(limit_tok, start_tok);
    guard count > 0 else { return -1; }
    var depth: i32 = 0;
    for step in count {
        let idx = add_i32(start_tok, step);
        let k = tok_kind(db, idx);
        if depth == 0 && k == target {
            return idx;
        }
        depth = step_delim_depth(k, depth);
    }
    return -1;
}

fn find_stmt_semi_or_sync(db: const CompilerDb&, start_tok: i32, limit_tok: i32) -> i32 {
    let count = sub_i32(limit_tok, start_tok);
    guard count > 0 else { return start_tok; }
    var depth: i32 = 0;
    for step in count {
        let idx = add_i32(start_tok, step);
        let k = tok_kind(db, idx);
        if depth == 0 && (k == TOK_SEMI || k == TOK_RCURLY) {
            return idx;
        }
        depth = step_delim_depth(k, depth);
    }
    return limit_tok;
}

fn strip_outer_parens(db: const CompilerDb&, start_tok: i32, end_tok: i32) -> i32, i32 {
    var s = start_tok;
    var e = end_tok;
    let bound = sub_i32(e, s);
    for step in bound {
        guard inc_i32(s) < e && tok_kind(db, s) == TOK_LPAREN else { break; }
        let close_idx = find_matching_delim(db, s, e);
        guard close_idx == dec_i32(e) else { break; }
        s = inc_i32(s);
        e = dec_i32(e);
    }
    return s, e;
}

fn is_assign_tok(k: u8) -> bool {
    if k == TOK_ASSIGN || k == TOK_REBIND || k == TOK_PLUSEQ || k == TOK_MINUSEQ { return true; }
    if k == TOK_MULEQ || k == TOK_DIVEQ || k == TOK_MODEQ || k == TOK_OREQ { return true; }
    if k == TOK_INC || k == TOK_DEC { return true; }
    return k == TOK_ANDEQ || k == TOK_XOREQ || k == TOK_SHLEQ || k == TOK_SHREQ;
}

fn is_operand_end_tok(k: u8) -> bool {
    if k == TOK_IDENT || k == TOK_NUMBER || k == TOK_STRING || k == TOK_CHAR { return true; }
    if k == TOK_TRUE || k == TOK_FALSE || k == TOK_RPAREN { return true; }
    return k == TOK_RBRACKET || k == TOK_RCURLY;
}

fn bin_op_prec(k: u8) -> i32 {
    if k == TOK_OROR { return 1; }
    if k == TOK_ANDAND { return 2; }
    if k == TOK_EQ || k == TOK_NE || k == TOK_REF_EQ || k == TOK_REF_NE || k == TOK_TILDE_EQ {
        return 3;
    }
    if k == TOK_LT || k == TOK_LE || k == TOK_GT || k == TOK_GE { return 3; }
    if k == TOK_PIPE || k == TOK_CARET || k == TOK_AMP || k == TOK_SHL || k == TOK_SHR {
        return 4;
    }
    if k == TOK_PLUS || k == TOK_MINUS { return 5; }
    if k == TOK_MUL || k == TOK_DIV || k == TOK_MOD { return 6; }
    return 0;
}

fn find_lowest_bin_op(db: const CompilerDb&, start_tok: i32, end_tok: i32) -> i32 {
    let count = sub_i32(end_tok, start_tok);
    guard count > 1 else { return -1; }
    var depth:     i32 = 0;
    var best_idx:  i32 = -1;
    var best_prec: i32 = 100;
    for step in count {
        let idx = add_i32(start_tok, step);
        let k = tok_kind(db, idx);
        let prev_k = if idx > start_tok { tok_kind(db, dec_i32(idx)) } else { 0 };
        let prec = bin_op_prec(k);
        if depth == 0 && idx > start_tok && prec > 0 && is_operand_end_tok(prev_k) {
            if prec <= best_prec {
                best_prec = prec;
                best_idx = idx;
            }
        }
        depth = step_delim_depth(k, depth);
    }
    return best_idx;
}

fn find_top_cast_op(db: const CompilerDb&, start_tok: i32, end_tok: i32) -> i32 {
    let count = sub_i32(end_tok, start_tok);
    guard count > 1 else { return -1; }
    var depth: i32 = 0;
    for step in count {
        let idx = add_i32(start_tok, step);
        let k = tok_kind(db, idx);
        if depth == 0 && idx > start_tok && (k == TOK_AS || k == TOK_AS_BANG) {
            return idx;
        }
        depth = step_delim_depth(k, depth);
    }
    return -1;
}

fn find_last_top_dot(db: const CompilerDb&, start_tok: i32, end_tok: i32) -> i32 {
    let count = sub_i32(end_tok, start_tok);
    guard count > 1 else { return -1; }
    var depth:    i32 = 0;
    var last_dot: i32 = -1;
    for step in count {
        let idx = add_i32(start_tok, step);
        let k = tok_kind(db, idx);
        if depth == 0 && idx > start_tok && inc_i32(idx) < end_tok && k == TOK_DOT {
            last_dot = idx;
        }
        depth = step_delim_depth(k, depth);
    }
    return last_dot;
}

fn strip_generic_suffix(db: const CompilerDb&, start_tok: i32, end_tok: i32) -> i32 {
    guard end_tok > start_tok && tok_kind(db, dec_i32(end_tok)) == TOK_GT else { return end_tok; }
    let lt_idx = find_top_level_tok(db, start_tok, end_tok, TOK_LT);
    if lt_idx > start_tok {
        return lt_idx;
    }
    return end_tok;
}

recursive fn parse_arg_list(db: CompilerDb&, parent_id: i32, start_tok: i32, end_tok: i32) {
    let count = sub_i32(end_tok, start_tok);
    guard count > 0 else { return; }
    var depth: i32 = 0;
    var seg_start = start_tok;
    for step in count {
        let idx = add_i32(start_tok, step);
        let k = tok_kind(db, idx);
        if depth == 0 && k == TOK_COMMA {
            if idx > seg_start {
                let arg_id = parse_expr(db, seg_start, idx);
                append_child(db, parent_id, arg_id);
            }
            seg_start = inc_i32(idx);
        } else {
            depth = step_delim_depth(k, depth);
        }
    }
    if end_tok > seg_start {
        let last_arg = parse_expr(db, seg_start, end_tok);
        append_child(db, parent_id, last_arg);
    }
}

recursive fn parse_call_or_ufcs(db: CompilerDb&, s: i32, lparen: i32, e: i32) -> i32 {
    let full_span = span_of_range(db, s, e);
    let args_start = inc_i32(lparen);
    let args_end = dec_i32(e);
    let pre_dot = sub_i32(lparen, 2);
    if pre_dot >= s && tok_kind(db, pre_dot) == TOK_DOT && tok_kind(db, dec_i32(lparen)) == TOK_IDENT {
        let m_span = tok_at(db, dec_i32(lparen)).span;
        let id = new_node(db, AstKind.UfcsCallExpr, m_span);
        db.nodes[id].aux_span = full_span;
        let recv_id = parse_expr(db, s, pre_dot);
        append_child(db, id, recv_id);
        parse_arg_list(db, id, args_start, args_end);
        return id;
    }
    let callee_end = strip_generic_suffix(db, s, lparen);
    let callee_span = span_of_range(db, s, callee_end);
    let id = new_node(db, AstKind.CallExpr, callee_span);
    db.nodes[id].aux_span = full_span;
    parse_arg_list(db, id, args_start, args_end);
    return id;
}

recursive fn parse_struct_lit_fields(db: CompilerDb&, lit_id: i32, start_tok: i32, end_tok: i32) {
    var cur = start_tok;
    let bound = sub_i32(end_tok, start_tok);
    for step in bound {
        guard cur < end_tok else { break; }
        let comma = find_top_level_tok(db, cur, end_tok, TOK_COMMA);
        let seg_end = if comma >= 0 { comma } else { end_tok };
        let colon = find_top_level_tok(db, cur, seg_end, TOK_COLON);
        if colon > cur && inc_i32(colon) < seg_end {
            let f_span = span_of_range(db, cur, colon);
            let v_span = span_of_range(db, inc_i32(colon), seg_end);
            let fid = new_node(db, AstKind.FieldDecl, f_span);
            db.nodes[fid].aux_span = v_span;
            let val_id = parse_expr(db, inc_i32(colon), seg_end);
            append_child(db, fid, val_id);
            append_child(db, lit_id, fid);
        }
        cur = if comma >= 0 { inc_i32(comma) } else { end_tok };
    }
}

recursive fn parse_bracket_postfix(db: CompilerDb&, s: i32, lbrack: i32, e: i32) -> i32 {
    let full_span = span_of_range(db, s, e);
    let inner_start = inc_i32(lbrack);
    let inner_end = dec_i32(e);
    let has_dots = find_top_level_tok(db, inner_start, inner_end, TOK_DOTDOT) >= 0;
    let has_col = find_top_level_tok(db, inner_start, inner_end, TOK_COLON) >= 0;
    let kind = if has_dots || has_col { AstKind.SliceExpr } else { AstKind.IndexExpr };
    let id = new_node(db, kind, full_span);
    db.nodes[id].aux_span = span_of_range(db, inner_start, inner_end);
    append_child(db, id, parse_expr(db, s, lbrack));
    return id;
}

fn parse_leaf_atom(db: CompilerDb&, s: i32, e: i32, full_span: Span) -> i32 {
    let k0 = tok_kind(db, s);
    if inc_i32(s) == e && k0 == TOK_NUMBER {
        return new_node(db, AstKind.IntLit, full_span);
    }
    if inc_i32(s) == e && (k0 == TOK_TRUE || k0 == TOK_FALSE) {
        let id = new_node(db, AstKind.BoolLit, full_span);
        db.nodes[id].const_val = if k0 == TOK_TRUE { 1 } else { 0 };
        db.nodes[id].has_const = true;
        return id;
    }
    return new_node(db, AstKind.Ident, full_span);
}

recursive fn parse_postfix_or_leaf(db: CompilerDb&, s: i32, e: i32) -> i32 {
    let full_span = span_of_range(db, s, e);
    let last_k = tok_kind(db, dec_i32(e));
    if last_k == TOK_RPAREN {
        let lparen = find_matching_open_backward(db, s, dec_i32(e));
        if lparen > s { return parse_call_or_ufcs(db, s, lparen, e); }
    }
    if last_k == TOK_RBRACKET {
        let lbrack = find_matching_open_backward(db, s, dec_i32(e));
        if lbrack > s { return parse_bracket_postfix(db, s, lbrack, e); }
    }
    if last_k == TOK_RCURLY {
        let lcurly = find_matching_open_backward(db, s, dec_i32(e));
        if lcurly > s {
            let id = new_node(db, AstKind.StructLit, span_of_range(db, s, lcurly));
            db.nodes[id].aux_span = full_span;
            parse_struct_lit_fields(db, id, inc_i32(lcurly), dec_i32(e));
            return id;
        }
    }
    let dot_idx = find_last_top_dot(db, s, e);
    if dot_idx > s {
        let id = new_node(db, AstKind.FieldExpr, full_span);
        db.nodes[id].aux_span = span_of_range(db, inc_i32(dot_idx), e);
        append_child(db, id, parse_expr(db, s, dot_idx));
        return id;
    }
    return parse_leaf_atom(db, s, e, full_span);
}

recursive fn parse_if_expr(db: CompilerDb&, s: i32, e: i32, full_span: Span) -> i32 {
    let lcurly = find_top_level_tok(db, inc_i32(s), e, TOK_LCURLY);
    guard lcurly > s else { return new_node(db, AstKind.Ident, full_span); }
    let rcurly = find_matching_delim(db, lcurly, e);
    let id = new_node(db, AstKind.IfStmt, full_span);
    db.nodes[id].aux_span = span_of_range(db, inc_i32(s), lcurly);
    append_child(db, id, parse_expr(db, inc_i32(s), lcurly));
    append_child(db, id, parse_expr(db, inc_i32(lcurly), rcurly));
    let else_tok = inc_i32(rcurly);
    if else_tok < e && tok_kind(db, else_tok) == TOK_ELSE {
        let after_else = inc_i32(else_tok);
        if after_else < e && tok_kind(db, after_else) == TOK_LCURLY {
            let else_end = find_matching_delim(db, after_else, e);
            append_child(db, id, parse_expr(db, inc_i32(after_else), else_end));
        } else if after_else < e {
            append_child(db, id, parse_expr(db, after_else, e));
        }
    }
    return id;
}

recursive fn parse_expr(db: CompilerDb&, start_tok: i32, end_tok: i32) -> i32 {
    let s, e = strip_outer_parens(db, start_tok, end_tok);
    guard s < e else { return new_node(db, AstKind.Ident, Span { .. }); }
    let full_span = span_of_range(db, s, e);

    let bin_idx = find_lowest_bin_op(db, s, e);
    if bin_idx > s && inc_i32(bin_idx) < e {
        let id = new_node(db, AstKind.BinaryExpr, full_span);
        db.nodes[id].op_tok = tok_kind(db, bin_idx);
        db.nodes[id].aux_span = tok_at(db, bin_idx).span;
        let lhs = parse_expr(db, s, bin_idx);
        let rhs = parse_expr(db, inc_i32(bin_idx), e);
        append_child(db, id, lhs);
        append_child(db, id, rhs);
        return id;
    }

    let cast_idx = find_top_cast_op(db, s, e);
    if cast_idx > s && inc_i32(cast_idx) < e {
        let ck = tok_kind(db, cast_idx);
        let id = new_node(db, AstKind.CastExpr, full_span);
        db.nodes[id].op_tok = ck;
        db.nodes[id].cast_mode = if ck == TOK_AS_BANG { CastMode.TruncateAsBang } else { CastMode.CheckedAs };
        db.nodes[id].aux_span = span_of_range(db, inc_i32(cast_idx), e);
        let lhs = parse_expr(db, s, cast_idx);
        append_child(db, id, lhs);
        return id;
    }

    let k0 = tok_kind(db, s);
    if k0 == TOK_IF { return parse_if_expr(db, s, e, full_span); }
    if (k0 == TOK_BANG || k0 == TOK_MINUS || k0 == TOK_TILDE) && inc_i32(s) < e {
        let id = new_node(db, AstKind.UnaryExpr, full_span);
        db.nodes[id].op_tok = k0;
        let sub = parse_expr(db, inc_i32(s), e);
        append_child(db, id, sub);
        return id;
    }
    return parse_postfix_or_leaf(db, s, e);
}

fn find_top_assign_op(db: const CompilerDb&, start_tok: i32, end_tok: i32) -> i32 {
    let count = sub_i32(end_tok, start_tok);
    guard count > 0 else { return -1; }
    var depth: i32 = 0;
    for step in count {
        let idx = add_i32(start_tok, step);
        let k = tok_kind(db, idx);
        if depth == 0 && is_assign_tok(k) {
            return idx;
        }
        depth = step_delim_depth(k, depth);
    }
    return -1;
}

fn has_hazard_tokens(db: const CompilerDb&, start_tok: i32, end_tok: i32) -> bool {
    let count = sub_i32(end_tok, start_tok);
    guard count > 0 else { return true; }
    for step in count {
        let idx = add_i32(start_tok, step);
        if tok_kind(db, idx) == TOK_OTHER {
            return true;
        }
    }
    return false;
}

fn parse_let_or_var_stmt(db: CompilerDb&, block_id: i32, cur: i32, limit_tok: i32) -> i32 {
    let kw_tok = tok_kind(db, cur);
    let semi_idx = find_stmt_semi_or_sync(db, cur, limit_tok);
    let assign_idx = find_top_assign_op(db, inc_i32(cur), semi_idx);
    if assign_idx < 0 {
        let haz = new_node(db, AstKind.UnresolvedHazard, span_of_range(db, cur, semi_idx));
        db.nodes[haz].aux_span = put_text(db, "unrecognized statement syntax");
        append_child(db, block_id, haz);
        return if tok_kind(db, semi_idx) == TOK_SEMI { inc_i32(semi_idx) } else { semi_idx };
    }
    let colon_idx = find_top_level_tok(db, inc_i32(cur), assign_idx, TOK_COLON);
    let name_end = if colon_idx > inc_i32(cur) { colon_idx } else { assign_idx };
    let lhs_span = span_of_range(db, inc_i32(cur), name_end);
    let rhs_span = span_of_range(db, inc_i32(assign_idx), semi_idx);
    let id = new_node(db, AstKind.LetDecl, lhs_span);
    let assign_k = tok_kind(db, assign_idx);
    db.nodes[id].op_tok = if assign_k == TOK_REBIND { TOK_REBIND } else { kw_tok };
    db.nodes[id].aux_span = rhs_span;
    if colon_idx > inc_i32(cur) {
        let vt, _ = classify_val_type(text_of(db, span_of_range(db, inc_i32(colon_idx), assign_idx)));
        db.nodes[id].val_type = vt;
    }
    let rhs_node = parse_expr(db, inc_i32(assign_idx), semi_idx);
    append_child(db, id, rhs_node);
    append_child(db, block_id, id);
    return if tok_kind(db, semi_idx) == TOK_SEMI { inc_i32(semi_idx) } else { semi_idx };
}

recursive fn parse_guard_stmt(db: CompilerDb&, block_id: i32, cur: i32, limit_tok: i32) -> i32 {
    let else_idx = find_top_level_tok(db, inc_i32(cur), limit_tok, TOK_ELSE);
    guard else_idx > cur && inc_i32(else_idx) < limit_tok else {
        let sync = find_stmt_semi_or_sync(db, cur, limit_tok);
        return inc_i32(sync);
    }
    let lcurly = inc_i32(else_idx);
    let rcurly = find_matching_delim(db, lcurly, limit_tok);
    let cond_span = span_of_range(db, inc_i32(cur), else_idx);
    let else_span = span_of_range(db, inc_i32(lcurly), rcurly);
    let id = new_node(db, AstKind.GuardStmt, cond_span);
    db.nodes[id].aux_span = else_span;
    let cond_id = parse_expr(db, inc_i32(cur), else_idx);
    append_child(db, id, cond_id);
    let else_blk = parse_block_range(db, inc_i32(lcurly), rcurly);
    append_child(db, id, else_blk);
    append_child(db, block_id, id);
    return inc_i32(rcurly);
}

recursive fn parse_defer_stmt(db: CompilerDb&, block_id: i32, cur: i32, limit_tok: i32) -> i32 {
    let semi_idx = find_stmt_semi_or_sync(db, inc_i32(cur), limit_tok);
    let id = new_node(db, AstKind.DeferStmt, span_of_range(db, inc_i32(cur), semi_idx));
    let inner_blk = parse_block_range(db, inc_i32(cur), semi_idx);
    append_child(db, id, inner_blk);
    append_child(db, block_id, id);
    return if tok_kind(db, semi_idx) == TOK_SEMI { inc_i32(semi_idx) } else { semi_idx };
}

recursive fn parse_if_stmt(db: CompilerDb&, block_id: i32, cur: i32, limit_tok: i32) -> i32 {
    let lcurly = find_top_level_tok(db, inc_i32(cur), limit_tok, TOK_LCURLY);
    guard lcurly > cur else { return limit_tok; }
    let rcurly = find_matching_delim(db, lcurly, limit_tok);
    let cond_span = span_of_range(db, inc_i32(cur), lcurly);
    let id = new_node(db, AstKind.IfStmt, cond_span);
    append_child(db, id, parse_expr(db, inc_i32(cur), lcurly));
    append_child(db, id, parse_block_range(db, inc_i32(lcurly), rcurly));
    var next_pos = inc_i32(rcurly);
    if next_pos < limit_tok && tok_kind(db, next_pos) == TOK_ELSE {
        let after_else = inc_i32(next_pos);
        if after_else < limit_tok && tok_kind(db, after_else) == TOK_IF {
            next_pos = parse_if_stmt(db, id, after_else, limit_tok);
        } else if after_else < limit_tok && tok_kind(db, after_else) == TOK_LCURLY {
            let else_end = find_matching_delim(db, after_else, limit_tok);
            append_child(db, id, parse_block_range(db, inc_i32(after_else), else_end));
            next_pos = inc_i32(else_end);
        }
    }
    append_child(db, block_id, id);
    return next_pos;
}

recursive fn parse_one_match_arm(db: CompilerDb&, match_id: i32, cur: i32, end_tok: i32) -> i32 {
    let arrow = find_top_level_tok(db, cur, end_tok, TOK_FATARROW);
    guard arrow >= cur && inc_i32(arrow) < end_tok else { return end_tok; }
    let pat_span = span_of_range(db, cur, arrow);
    let body_start = inc_i32(arrow);
    if tok_kind(db, body_start) == TOK_LCURLY {
        let body_end = find_matching_delim(db, body_start, end_tok);
        let arm = new_node(db, AstKind.MatchArm, pat_span);
        db.nodes[arm].aux_span = span_of_range(db, inc_i32(body_start), body_end);
        append_child(db, arm, parse_block_range(db, inc_i32(body_start), body_end));
        append_child(db, match_id, arm);
        return inc_i32(body_end);
    }
    let comma = find_top_level_tok(db, body_start, end_tok, TOK_COMMA);
    let body_end = if comma >= 0 { comma } else { end_tok };
    let arm = new_node(db, AstKind.MatchArm, pat_span);
    db.nodes[arm].aux_span = span_of_range(db, body_start, body_end);
    append_child(db, arm, parse_expr(db, body_start, body_end));
    append_child(db, match_id, arm);
    return if comma >= 0 { inc_i32(comma) } else { end_tok };
}

recursive fn parse_match_arms(db: CompilerDb&, match_id: i32, start_tok: i32, end_tok: i32) {
    var cur = start_tok;
    let bound = sub_i32(end_tok, start_tok);
    for step in bound {
        guard cur < end_tok else { break; }
        let k = tok_kind(db, cur);
        if k == TOK_COMMA || k == TOK_SEMI {
            cur = inc_i32(cur);
        } else {
            cur = max(inc_i32(cur), parse_one_match_arm(db, match_id, cur, end_tok));
        }
    }
}

recursive fn parse_match_stmt(db: CompilerDb&, block_id: i32, cur: i32, limit_tok: i32) -> i32 {
    let lcurly = find_top_level_tok(db, inc_i32(cur), limit_tok, TOK_LCURLY);
    guard lcurly > cur else { return limit_tok; }
    let rcurly = find_matching_delim(db, lcurly, limit_tok);
    let id = new_node(db, AstKind.MatchStmt, span_of_range(db, inc_i32(cur), lcurly));
    append_child(db, id, parse_expr(db, inc_i32(cur), lcurly));
    parse_match_arms(db, id, inc_i32(lcurly), rcurly);
    append_child(db, block_id, id);
    return inc_i32(rcurly);
}

recursive fn parse_loop_stmt(db: CompilerDb&, block_id: i32, cur: i32, limit_tok: i32, kind: AstKind) -> i32 {
    let lcurly = find_top_level_tok(db, inc_i32(cur), limit_tok, TOK_LCURLY);
    guard lcurly >= inc_i32(cur) else { return limit_tok; }
    let rcurly = find_matching_delim(db, lcurly, limit_tok);
    let id = new_node(db, kind, span_of_range(db, inc_i32(cur), lcurly));
    append_child(db, id, parse_block_range(db, inc_i32(lcurly), rcurly));
    append_child(db, block_id, id);
    return inc_i32(rcurly);
}

fn parse_return_stmt(db: CompilerDb&, block_id: i32, cur: i32, limit_tok: i32) -> i32 {
    let semi_idx = find_stmt_semi_or_sync(db, inc_i32(cur), limit_tok);
    let id = new_node(db, AstKind.ReturnStmt, span_of_range(db, inc_i32(cur), semi_idx));
    if semi_idx > inc_i32(cur) {
        parse_arg_list(db, id, inc_i32(cur), semi_idx);
    }
    append_child(db, block_id, id);
    return if tok_kind(db, semi_idx) == TOK_SEMI { inc_i32(semi_idx) } else { semi_idx };
}

recursive fn parse_assign_or_expr_stmt(db: CompilerDb&, block_id: i32, cur: i32, limit_tok: i32) -> i32 {
    let semi_idx = find_stmt_semi_or_sync(db, cur, limit_tok);
    let next_pos = if tok_kind(db, semi_idx) == TOK_SEMI { inc_i32(semi_idx) } else { semi_idx };
    if semi_idx > inc_i32(cur) && tok_kind(db, dec_i32(semi_idx)) == TOK_RCURLY {
        let lcurly = find_matching_open_backward(db, cur, dec_i32(semi_idx));
        if lcurly > cur && tok_kind(db, dec_i32(lcurly)) == TOK_RPAREN {
            let body_start = if add_i32(lcurly, 2) < dec_i32(semi_idx) && tok_kind(db, add_i32(lcurly, 2)) == TOK_FATARROW {
                add_i32(lcurly, 3)
            } else {
                inc_i32(lcurly)
            };
            let loop_id = new_node(db, AstKind.ForStmt, span_of_range(db, cur, lcurly));
            append_child(db, loop_id, parse_block_range(db, body_start, dec_i32(semi_idx)));
            append_child(db, block_id, loop_id);
            return next_pos;
        }
    }
    if has_hazard_tokens(db, cur, semi_idx) {
        let haz = new_node(db, AstKind.UnresolvedHazard, span_of_range(db, cur, semi_idx));
        db.nodes[haz].aux_span = put_text(db, "unrecognized statement syntax");
        append_child(db, block_id, haz);
        return max(inc_i32(cur), next_pos);
    }
    let assign_idx = find_top_assign_op(db, cur, semi_idx);
    if assign_idx > cur && inc_i32(assign_idx) <= semi_idx {
        let id = new_node(db, AstKind.AssignStmt, span_of_range(db, cur, assign_idx));
        db.nodes[id].op_tok = tok_kind(db, assign_idx);
        if inc_i32(assign_idx) < semi_idx {
            db.nodes[id].aux_span = span_of_range(db, inc_i32(assign_idx), semi_idx);
            append_child(db, id, parse_expr(db, inc_i32(assign_idx), semi_idx));
        } else {
            db.nodes[id].aux_span = put_text(db, "1");
        }
        append_child(db, block_id, id);
        return next_pos;
    }
    let expr_id = parse_expr(db, cur, semi_idx);
    let ek = db.nodes[expr_id].kind;
    if ek == AstKind.CallExpr || ek == AstKind.UfcsCallExpr {
        append_child(db, block_id, expr_id);
        return next_pos;
    }
    let haz = new_node(db, AstKind.UnresolvedHazard, span_of_range(db, cur, semi_idx));
    db.nodes[haz].aux_span = put_text(db, "unrecognized statement syntax");
    append_child(db, block_id, haz);
    return max(inc_i32(cur), next_pos);
}

recursive fn parse_ctrl_stmt(db: CompilerDb&, block_id: i32, cur: i32, limit_tok: i32) -> i32 {
    let k = tok_kind(db, cur);
    if k == TOK_IF { return parse_if_stmt(db, block_id, cur, limit_tok); }
    if k == TOK_MATCH { return parse_match_stmt(db, block_id, cur, limit_tok); }
    if k == TOK_CONST && tok_kind(db, inc_i32(cur)) == TOK_FOR {
        return parse_loop_stmt(db, block_id, inc_i32(cur), limit_tok, AstKind.ForStmt);
    }
    if k == TOK_FOR || k == TOK_LOOP { return parse_loop_stmt(db, block_id, cur, limit_tok, AstKind.ForStmt); }
    if k == TOK_WHILE { return parse_loop_stmt(db, block_id, cur, limit_tok, AstKind.WhileStmt); }
    if k == TOK_RETURN { return parse_return_stmt(db, block_id, cur, limit_tok); }
    if k == TOK_BREAK || k == TOK_CONTINUE {
        let semi = find_stmt_semi_or_sync(db, cur, limit_tok);
        return if tok_kind(db, semi) == TOK_SEMI { inc_i32(semi) } else { semi };
    }
    return parse_assign_or_expr_stmt(db, block_id, cur, limit_tok);
}

recursive fn parse_one_stmt(db: CompilerDb&, block_id: i32, cur: i32, limit_tok: i32) -> i32 {
    let k = tok_kind(db, cur);
    if k == TOK_SEMI { return inc_i32(cur); }
    if k == TOK_LET || k == TOK_VAR { return parse_let_or_var_stmt(db, block_id, cur, limit_tok); }
    if k == TOK_GUARD { return parse_guard_stmt(db, block_id, cur, limit_tok); }
    if k == TOK_DEFER { return parse_defer_stmt(db, block_id, cur, limit_tok); }
    return parse_ctrl_stmt(db, block_id, cur, limit_tok);
}

recursive fn parse_block_range(db: CompilerDb&, start_tok: i32, end_tok: i32) -> i32 {
    let blk = new_node(db, AstKind.Block, span_of_range(db, start_tok, end_tok));
    var cur = start_tok;
    let bound = inc_i32(sub_i32(end_tok, start_tok));
    for step in bound {
        guard cur < end_tok else { break; }
        if tok_kind(db, cur) == TOK_RCURLY {
            cur = inc_i32(cur);
            continue;
        }
        let next_cur = parse_one_stmt(db, blk, cur, end_tok);
        cur = max(inc_i32(cur), next_cur);
    }
    return blk;
}

fn parse_top_import(db: CompilerDb&, mod_id: i32, cur: i32, limit_tok: i32) -> i32 {
    let semi = find_stmt_semi_or_sync(db, inc_i32(cur), limit_tok);
    let from_idx = find_top_level_tok(db, inc_i32(cur), semi, TOK_FROM);
    if from_idx > cur && inc_i32(from_idx) < semi {
        let pkg_span = span_of_range(db, inc_i32(cur), from_idx);
        let dir_span = unquote_span(tok_at(db, inc_i32(from_idx)).span);
        let id = new_node(db, AstKind.Import, pkg_span);
        db.nodes[id].aux_span = dir_span;
        append_child(db, mod_id, id);
    } else {
        let imp_span = span_of_range(db, inc_i32(cur), semi);
        let id = new_node(db, AstKind.Import, imp_span);
        append_child(db, mod_id, id);
    }
    return inc_i32(semi);
}

fn parse_top_const_or_let(db: CompilerDb&, mod_id: i32, cur: i32, limit_tok: i32) -> i32 {
    let kw = tok_kind(db, cur);
    let semi = find_stmt_semi_or_sync(db, inc_i32(cur), limit_tok);
    let assign_idx = find_top_assign_op(db, inc_i32(cur), semi);
    let name_span = tok_at(db, inc_i32(cur)).span;
    let kind = if kw == TOK_CONST { AstKind.ConstDecl } else { AstKind.LetDecl };
    let id = new_node(db, kind, name_span);
    if assign_idx > inc_i32(cur) {
        let colon_idx = find_top_level_tok(db, inc_i32(cur), assign_idx, TOK_COLON);
        if colon_idx > inc_i32(cur) && inc_i32(colon_idx) < assign_idx {
            db.nodes[id].aux_span = span_of_range(db, inc_i32(colon_idx), assign_idx);
        }
        let rhs_id = parse_expr(db, inc_i32(assign_idx), semi);
        append_child(db, id, rhs_id);
    }
    append_child(db, mod_id, id);
    return inc_i32(semi);
}

fn parse_top_enum(db: CompilerDb&, mod_id: i32, cur: i32, limit_tok: i32) -> i32 {
    let name_span = tok_at(db, inc_i32(cur)).span;
    let lcurly = find_top_level_tok(db, inc_i32(cur), limit_tok, TOK_LCURLY);
    guard lcurly > cur else { return limit_tok; }
    let rcurly = find_matching_delim(db, lcurly, limit_tok);
    let id = new_node(db, AstKind.EnumDecl, name_span);
    var p = inc_i32(lcurly);
    let bound = sub_i32(rcurly, p);
    for step in bound {
        guard p < rcurly else { break; }
        if tok_kind(db, p) == TOK_IDENT {
            let v_id = new_node(db, AstKind.FieldDecl, tok_at(db, p).span);
            append_child(db, id, v_id);
        }
        let comma = find_top_level_tok(db, p, rcurly, TOK_COMMA);
        p = if comma >= 0 { inc_i32(comma) } else { rcurly };
    }
    append_child(db, mod_id, id);
    return inc_i32(rcurly);
}

fn find_top_level_type_tok(db: const CompilerDb&, start_tok: i32, limit_tok: i32, target: u8) -> i32 {
    let count = sub_i32(limit_tok, start_tok);
    guard count > 0 else { return -1; }
    var depth: i32 = 0;
    var angle: i32 = 0;
    for step in count {
        let idx = add_i32(start_tok, step);
        let k = tok_kind(db, idx);
        if depth == 0 && angle == 0 && k == target {
            return idx;
        }
        if k == TOK_ASSIGN && depth == 0 {
            angle = 0;
        } else if k == TOK_LT && depth == 0 {
            angle = inc_i32(angle);
        } else if k == TOK_GT && depth == 0 && angle > 0 {
            angle = dec_i32(angle);
        } else if k == TOK_SHR && depth == 0 && angle > 0 {
            angle = max(0, sub_i32(angle, 2));
        }
        depth = step_delim_depth(k, depth);
    }
    return -1;
}

fn skip_generic_params_tok(db: const CompilerDb&, after_name_tok: i32, limit_tok: i32) -> i32 {
    guard after_name_tok < limit_tok && tok_kind(db, after_name_tok) == TOK_LT else {
        return after_name_tok;
    }
    let count = sub_i32(limit_tok, after_name_tok);
    var angle: i32 = 0;
    for step in count {
        let idx = add_i32(after_name_tok, step);
        let k = tok_kind(db, idx);
        if k == TOK_LT {
            angle = inc_i32(angle);
        } else if k == TOK_GT {
            angle = dec_i32(angle);
            if angle <= 0 {
                return inc_i32(idx);
            }
        } else if k == TOK_SHR {
            angle = sub_i32(angle, 2);
            if angle <= 0 {
                return inc_i32(idx);
            }
        } else if k == TOK_LCURLY && angle > 0 {
            return after_name_tok;
        }
    }
    return after_name_tok;
}

fn parse_one_typed_member(db: CompilerDb&, parent_id: i32, kind: AstKind, p: i32, end_tok: i32) -> i32 {
    let eq_first = find_top_level_tok(db, p, end_tok, TOK_ASSIGN);
    let comma = if eq_first >= 0 {
        let c_before = find_top_level_type_tok(db, p, eq_first, TOK_COMMA);
        if c_before >= 0 { c_before } else { find_top_level_tok(db, inc_i32(eq_first), end_tok, TOK_COMMA) }
    } else {
        find_top_level_type_tok(db, p, end_tok, TOK_COMMA)
    };
    let seg_end = if comma >= 0 { comma } else { end_tok };
    let colon = find_top_level_tok(db, p, seg_end, TOK_COLON);
    if colon > p && inc_i32(colon) < seg_end {
        let eq_idx = find_top_level_tok(db, inc_i32(colon), seg_end, TOK_ASSIGN);
        let ty_end = if eq_idx > colon { eq_idx } else { seg_end };
        let mid = new_node(db, kind, tok_at(db, p).span);
        db.nodes[mid].aux_span = span_of_range(db, inc_i32(colon), ty_end);
        append_child(db, parent_id, mid);
    }
    return if comma >= 0 { inc_i32(comma) } else { end_tok };
}

fn parse_typed_member_list(db: CompilerDb&, parent_id: i32, kind: AstKind, start_tok: i32, end_tok: i32) {
    var p = start_tok;
    let bound = sub_i32(end_tok, start_tok);
    for step in bound {
        guard p < end_tok else { break; }
        p = max(inc_i32(p), parse_one_typed_member(db, parent_id, kind, p, end_tok));
    }
}

fn parse_top_struct(db: CompilerDb&, mod_id: i32, cur: i32, limit_tok: i32) -> i32 {
    let s_tok = if tok_kind(db, cur) == TOK_ROOT { inc_i32(cur) } else { cur };
    let name_span = tok_at(db, inc_i32(s_tok)).span;
    let after_gen = skip_generic_params_tok(db, add_i32(s_tok, 2), limit_tok);
    let lcurly = find_top_level_tok(db, after_gen, limit_tok, TOK_LCURLY);
    guard lcurly > s_tok else { return limit_tok; }
    let rcurly = find_matching_delim(db, lcurly, limit_tok);
    let id = new_node(db, AstKind.StructDecl, name_span);
    parse_typed_member_list(db, id, AstKind.FieldDecl, inc_i32(lcurly), rcurly);
    append_child(db, mod_id, id);
    return inc_i32(rcurly);
}

fn parse_top_fn(db: CompilerDb&, mod_id: i32, fn_kw_tok: i32, limit_tok: i32) -> i32 {
    let raw_name_tok = inc_i32(fn_kw_tok);
    let name_tok = if tok_kind(db, raw_name_tok) == TOK_COLONCOLON {
        inc_i32(raw_name_tok)
    } else {
        raw_name_tok
    };
    let name_span = tok_at(db, name_tok).span;
    let after_gen = skip_generic_params_tok(db, inc_i32(name_tok), limit_tok);
    let lparen = find_top_level_tok(db, after_gen, limit_tok, TOK_LPAREN);
    guard lparen > name_tok else { return limit_tok; }
    let rparen = find_matching_delim(db, lparen, limit_tok);
    let lcurly = find_top_level_tok(db, inc_i32(rparen), limit_tok, TOK_LCURLY);
    guard lcurly > rparen else {
        let semi = find_stmt_semi_or_sync(db, inc_i32(rparen), limit_tok);
        return inc_i32(semi);
    }
    let rcurly = find_matching_delim(db, lcurly, limit_tok);
    let arrow = find_top_level_tok(db, inc_i32(rparen), lcurly, TOK_ARROW);
    let ret_span = if arrow >= 0 && inc_i32(arrow) < lcurly {
        span_of_range(db, inc_i32(arrow), lcurly)
    } else {
        put_text(db, "void")
    };
    let fn_id = new_node(db, AstKind.FnDecl, name_span);
    db.nodes[fn_id].aux_span = ret_span;
    db.nodes[fn_id].const_val = tok_at(db, rcurly).span.line as u64;
    parse_typed_member_list(db, fn_id, AstKind.ParamDecl, inc_i32(lparen), rparen);
    let body_id = parse_block_range(db, inc_i32(lcurly), rcurly);
    append_child(db, fn_id, body_id);
    append_child(db, mod_id, fn_id);
    return inc_i32(rcurly);
}

fn is_fn_modifier(k: u8) -> bool {
    return k == TOK_INLINE || k == TOK_CHECKFREE || k == TOK_RECURSIVE || k == TOK_EXPORT;
}

fn parse_top_item(db: CompilerDb&, file_id: i32, mod_id: i32, cur: i32, limit_tok: i32) -> i32 {
    let k = tok_kind(db, cur);
    if k == TOK_NAMESPACE {
        let semi = find_stmt_semi_or_sync(db, inc_i32(cur), limit_tok);
        let ns_span = tok_at(db, inc_i32(cur)).span;
        db.files[file_id].ns_span = ns_span;
        append_child(db, mod_id, new_node(db, AstKind.Namespace, ns_span));
        return inc_i32(semi);
    }
    if k == TOK_IMPORT { return parse_top_import(db, mod_id, cur, limit_tok); }
    if k == TOK_CONST || k == TOK_LET || k == TOK_VAR {
        return parse_top_const_or_let(db, mod_id, cur, limit_tok);
    }
    if k == TOK_ENUM { return parse_top_enum(db, mod_id, cur, limit_tok); }
    if k == TOK_STRUCT || (k == TOK_ROOT && tok_kind(db, inc_i32(cur)) == TOK_STRUCT) {
        return parse_top_struct(db, mod_id, cur, limit_tok);
    }
    if k == TOK_FN || is_fn_modifier(k) {
        let fn_tok = if k == TOK_FN { cur } else { find_top_level_tok(db, cur, limit_tok, TOK_FN) };
        if fn_tok >= cur {
            return parse_top_fn(db, mod_id, fn_tok, limit_tok);
        }
    }
    let semi = find_stmt_semi_or_sync(db, cur, limit_tok);
    return max(inc_i32(cur), inc_i32(semi));
}

fn parse_module(db: CompilerDb&, file_id: i32) -> bool {
    guard file_id >= 0 && file_id < db.files.len else { return false; }
    let tok_start = db.files[file_id].tok_start;
    let tok_count = db.files[file_id].tok_count;
    let limit_tok = add_i32(tok_start, tok_count);
    let mod_span = span_of_range(db, tok_start, limit_tok);
    let mod_id = new_node(db, AstKind.Module, mod_span);
    db.files[file_id].root_node = mod_id;

    var cur = tok_start;
    let bound = inc_i32(tok_count);
    for step in bound {
        guard cur < limit_tok else { break; }
        let next_cur = parse_top_item(db, file_id, mod_id, cur, limit_tok);
        cur = max(inc_i32(cur), next_cur);
    }
    return true;
}
