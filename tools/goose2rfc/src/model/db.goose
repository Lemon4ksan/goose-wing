// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Core AST, HIR, and Spec-IR fixed-size arena structures and index-tree helpers.

import std;
import dictionary;

let TOK_EOF:    u8 = 0;
let TOK_IDENT:  u8 = 1;
let TOK_NUMBER: u8 = 2;
let TOK_STRING: u8 = 3;
let TOK_CHAR:   u8 = 4;

let TOK_NAMESPACE: u8 = 10;
let TOK_IMPORT:    u8 = 11;
let TOK_FROM:      u8 = 12;
let TOK_CONST:     u8 = 13;
let TOK_LET:       u8 = 14;
let TOK_VAR:       u8 = 15;
let TOK_FN:        u8 = 16;
let TOK_INLINE:    u8 = 17;
let TOK_CHECKFREE: u8 = 18;
let TOK_RECURSIVE: u8 = 19;
let TOK_STRUCT:    u8 = 20;
let TOK_ROOT:      u8 = 21;
let TOK_ENUM:      u8 = 22;
let TOK_TYPE:      u8 = 23;
let TOK_GUARD:     u8 = 24;
let TOK_ELSE:      u8 = 25;
let TOK_DEFER:     u8 = 26;
let TOK_IF:        u8 = 27;
let TOK_MATCH:     u8 = 28;
let TOK_FOR:       u8 = 29;
let TOK_IN:        u8 = 30;
let TOK_WHILE:     u8 = 31;
let TOK_LOOP:      u8 = 32;
let TOK_RETURN:    u8 = 33;
let TOK_BREAK:     u8 = 34;
let TOK_CONTINUE:  u8 = 35;
let TOK_AS:        u8 = 36;
let TOK_TRUE:      u8 = 37;
let TOK_FALSE:     u8 = 38;
let TOK_EXTERN:    u8 = 39;
let TOK_EXPORT:    u8 = 40;

let TOK_LPAREN:     u8 = 41;
let TOK_RPAREN:     u8 = 42;
let TOK_LBRACKET:   u8 = 43;
let TOK_RBRACKET:   u8 = 44;
let TOK_LCURLY:     u8 = 45;
let TOK_RCURLY:     u8 = 46;
let TOK_SEMI:       u8 = 47;
let TOK_COMMA:      u8 = 48;
let TOK_COLON:      u8 = 49;
let TOK_COLONCOLON: u8 = 50;
let TOK_DOT:        u8 = 51;
let TOK_DOTDOT:     u8 = 52;
let TOK_GROW:       u8 = 53;
let TOK_GROWSHRINK: u8 = 54;
let TOK_ARROW:      u8 = 55;
let TOK_FATARROW:   u8 = 56;

let TOK_AS_BANG:  u8 = 60;
let TOK_REBIND:   u8 = 61;
let TOK_REF_EQ:   u8 = 62;
let TOK_REF_NE:   u8 = 63;
let TOK_TILDE_EQ: u8 = 64;
let TOK_SHL:      u8 = 65;
let TOK_SHR:      u8 = 66;
let TOK_LE:       u8 = 67;
let TOK_GE:       u8 = 68;
let TOK_EQ:       u8 = 69;
let TOK_NE:       u8 = 70;
let TOK_ANDAND:   u8 = 71;
let TOK_OROR:     u8 = 72;
let TOK_LT:       u8 = 73;
let TOK_GT:       u8 = 74;
let TOK_ASSIGN:   u8 = 75;
let TOK_PLUSEQ:   u8 = 76;
let TOK_MINUSEQ:  u8 = 77;
let TOK_MULEQ:    u8 = 78;
let TOK_DIVEQ:    u8 = 79;
let TOK_MODEQ:    u8 = 80;
let TOK_OREQ:     u8 = 81;
let TOK_ANDEQ:    u8 = 82;
let TOK_XOREQ:    u8 = 83;
let TOK_SHLEQ:    u8 = 84;
let TOK_SHREQ:    u8 = 85;
let TOK_INC:      u8 = 86;
let TOK_DEC:      u8 = 87;
let TOK_PLUS:     u8 = 88;
let TOK_MINUS:    u8 = 89;
let TOK_MUL:      u8 = 90;
let TOK_DIV:      u8 = 91;
let TOK_MOD:      u8 = 92;
let TOK_AMP:      u8 = 93;
let TOK_PIPE:     u8 = 94;
let TOK_CARET:    u8 = 95;
let TOK_BANG:     u8 = 96;
let TOK_TILDE:    u8 = 97;
let TOK_QUESTION: u8 = 98;
let TOK_OTHER:    u8 = 99;

enum VisitState {
    Unvisited,
    Active,
    Done,
}

struct Span {
    file_id: i32 = 0,
    at:      i32 = 0,
    len:     i32 = 0,
    line:    i32 = 0,
    col:     i32 = 0,
}

struct SourceFile {
    path_span:   Span,
    disk_span:   Span,
    ns_span:     Span,
    text_start:  i32        = 0,
    text_len:    i32        = 0,
    tok_start:   i32        = 0,
    tok_count:   i32        = 0,
    root_node:   i32        = -1,
    is_target:   bool       = false,
    visit_state: VisitState = VisitState.Unvisited,
}

struct Token {
    kind: u8 = 0,
    span: Span,
}

enum AstKind {
    Module,
    Namespace,
    Import,
    ConstDecl,
    LetDecl,
    EnumDecl,
    StructDecl,
    FieldDecl,
    FnDecl,
    ParamDecl,
    Block,
    GuardStmt,
    DeferStmt,
    IfStmt,
    MatchStmt,
    MatchArm,
    ForStmt,
    WhileStmt,
    ReturnStmt,
    AssignStmt,
    BinaryExpr,
    UnaryExpr,
    CastExpr,
    CallExpr,
    UfcsCallExpr,
    FieldExpr,
    IndexExpr,
    SliceExpr,
    StructLit,
    Ident,
    IntLit,
    BoolLit,
    UnresolvedHazard,
}

enum ValType {
    Unknown,
    Bool,
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
    SliceU8,
    FixedArray,
    BoundedVec,
    GrowVec,
    StructVal,
    EnumVal,
    RefParam,
}

enum CastMode {
    None,
    CheckedAs,
    TruncateAsBang,
}

struct AstNode {
    kind:      AstKind  = AstKind.Ident,
    val_type:  ValType  = ValType.Unknown,
    cast_mode: CastMode = CastMode.None,
    op_tok:    u8       = 0,
    parent:    i32      = -1,
    first:     i32      = -1,
    last:      i32      = -1,
    prev:      i32      = -1,
    next:      i32      = -1,
    ref_sym:   i32      = -1,
    const_val: u64      = 0,
    has_const: bool     = false,
    aux_span:  Span,
    span:      Span,
}

enum SymKind {
    ConstSym,
    FnSym,
    StructSym,
    EnumSym,
    ParamSym,
    LocalSym,
}

struct Symbol {
    kind:        SymKind = SymKind.ConstSym,
    name_span:   Span,
    qual_span:   Span,
    type_span:   Span,
    decl_node:   i32        = -1,
    val_type:    ValType    = ValType.Unknown,
    is_ref_mut:  bool       = false,
    root_param:  i32        = -1,
    const_val:   u64        = 0,
    has_const:   bool       = false,
    visit_state: VisitState = VisitState.Unvisited,
    span:        Span,
}

enum WireOpKind {
    ReadOp,
    WriteOp,
    RollbackOp,
    SatMathOp,
}

struct WireOp {
    kind:          WireOpKind = WireOpKind.ReadOp,
    seq_index:     i32        = 0,
    cond_text:     Span,
    encoding_text: Span,
    val_expr_text: Span,
    target_text:   Span,
    inlined_from:  Span,
    span:          Span,
}

struct GuardRule {
    req_index:     i32 = 0,
    template_id:   Span,
    lhs_text:      Span,
    rhs_text:      Span,
    else_ret_text: Span,
    inlined_from:  Span,
    span:          Span,
}

enum UncheckedKind {
    UnconstrainedInput,
    DiscardedWireField,
    UnresolvedAstHazard,
}

struct UncheckedItem {
    kind:        UncheckedKind = UncheckedKind.UnconstrainedInput,
    item_text:   Span,
    domain_text: Span,
    note_text:   Span,
    span:        Span,
}

enum RollbackState {
    Unmodified,
    TransactionalSelf,
    DirtySelfRestoredByCaller,
    DirtyExposed,
}

struct ParamEffect {
    param_sym:      i32           = -1,
    state:          RollbackState = RollbackState.Unmodified,
    mechanism_text: Span,
    span:           Span,
}

struct FsmRow {
    state_text:  Span,
    event_text:  Span,
    guard_text:  Span,
    next_text:   Span,
    req_id:      i32 = 0,
    source_text: Span,
    span:        Span,
}

struct SpecFunction {
    fn_sym:                i32 = -1,
    entry_ctx_text:        Span,
    ret_type_text:         Span,
    param_start:           i32 = 0,
    param_count:           i32 = 0,
    wire_start:            i32 = 0,
    wire_count:            i32 = 0,
    guard_start:           i32 = 0,
    guard_count:           i32 = 0,
    unchecked_start:       i32 = 0,
    unchecked_count:       i32 = 0,
    effect_start:          i32 = 0,
    effect_count:          i32 = 0,
    fsm_start:             i32 = 0,
    fsm_count:             i32 = 0,
    resolved_constants:    i32 = 0,
    inlined_callees:       i32 = 0,
    unanalyzed_statements: i32 = 0,
    end_line:              i32 = 0,
    span:                  Span,
}

struct CompilerDb {
    files:     SourceFile[>..]&,
    text:      u8[>..]&,
    tokens:    Token[>..]&,
    nodes:     AstNode[>..]&,
    symbols:   Symbol[>..]&,
    wire_ops:  WireOp[>..]&,
    guards:    GuardRule[>..]&,
    unchecked: UncheckedItem[>..]&,
    effects:   ParamEffect[>..]&,
    fsm_rows:  FsmRow[>..]&,
    specs:     SpecFunction[>..]&,
    sym_index: dictionary<u64, i32>&,
    work:      i32[>..<]&,
}

fn fnv1a_hash(s: const u8[:]) -> u64 {
    return hash(s);
}

fn inc_i32(x: i32) -> i32 {
    return x + 1;
}

fn dec_i32(x: i32) -> i32 {
    return x - 1;
}

fn add_i32(a: i32, b: i32) -> i32 {
    return a + b;
}

fn sub_i32(a: i32, b: i32) -> i32 {
    return a - b;
}

fn inc_i64(x: i64) -> i64 {
    return x + 1;
}

fn dec_i64(x: i64) -> i64 {
    return x - 1;
}

fn add_i64(a: i64, b: i64) -> i64 {
    return a + b;
}

fn sub_i64(a: i64, b: i64) -> i64 {
    return a - b;
}

fn add_u64(a: u64, b: u64) -> u64 {
    return a + b;
}

fn sub_u64(a: u64, b: u64) -> u64 {
    return a - b;
}

fn mul_u64(a: u64, b: u64) -> u64 {
    return a * b;
}

fn shl_u64(a: u64, b: u64) -> u64 {
    return a << b;
}

fn put_text(db: CompilerDb&, s: const u8[:]) -> Span {
    let at = db.text.len as i32;
    db.text.append(s);
    return Span { file_id: 0, at: at, len: s.len as i32, line: 0, col: 0 };
}

fn put_text_at(db: CompilerDb&, s: const u8[:], file_id: i32, line: i32, col: i32) -> Span {
    let at = db.text.len as i32;
    db.text.append(s);
    return Span { file_id: file_id, at: at, len: s.len as i32, line: line, col: col };
}

fn text_of(db: const CompilerDb&, s: Span) -> const u8[:] {
    let at:   i64 = s.at;
    let slen: i64 = s.len;
    guard at >= 0 && slen >= 0 && at <= db.text.len else { return ""; }
    let tail = db.text[at..];
    guard slen <= tail.len else { return ""; }
    return tail[..slen];
}

fn file_path_of(db: const CompilerDb&, file_id: i32) -> const u8[:] {
    guard file_id >= 0 && file_id < db.files.len else { return "<unknown>"; }
    return text_of(db, db.files[file_id].path_span);
}

fn new_node(db: CompilerDb&, kind: AstKind, span: Span) -> i32 {
    let id = db.nodes.len as i32;
    db.nodes.push(AstNode { kind: kind, span: span, .. });
    return id;
}

fn append_child(db: CompilerDb&, parent: i32, child: i32) {
    guard parent >= 0 && parent < db.nodes.len && child >= 0 && child < db.nodes.len else { return; }
    let last = db.nodes[parent].last;
    db.nodes[child].parent = parent;
    db.nodes[child].prev = last;
    db.nodes[child].next = -1;
    if last >= 0 && last < db.nodes.len {
        db.nodes[last].next = child;
    } else {
        db.nodes[parent].first = child;
    }
    db.nodes[parent].last = child;
}

fn child_count(db: const CompilerDb&, parent: i32) -> i32 {
    guard parent >= 0 && parent < db.nodes.len else { return 0; }
    var cur = db.nodes[parent].first;
    for step in db.nodes.len {
        if cur < 0 || cur >= db.nodes.len {
            return step as i32;
        }
        cur = db.nodes[cur].next;
    }
    return 0;
}

fn nth_child(db: const CompilerDb&, parent: i32, idx: i32) -> i32 {
    guard parent >= 0 && parent < db.nodes.len && idx >= 0 else { return -1; }
    var cur = db.nodes[parent].first;
    for step in idx {
        guard cur >= 0 && cur < db.nodes.len else { return -1; }
        cur = db.nodes[cur].next;
    }
    return cur;
}

fn advance_preorder(db: const CompilerDb&, root: i32, cur: i32) -> i32 {
    guard cur >= 0 && cur < db.nodes.len else { return -1; }
    let first = db.nodes[cur].first;
    if first >= 0 {
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

fn subtree_node_count(db: const CompilerDb&, root: i32) -> i32 {
    guard root >= 0 && root < db.nodes.len else { return 0; }
    if db.nodes[root].kind == AstKind.FnDecl {
        let body = db.nodes[root].last;
        if body >= 0 && body < db.nodes.len {
            return child_count(db, body);
        }
    }
    var cur = root;
    for step in db.nodes.len {
        if cur < 0 {
            return step as i32;
        }
        cur = advance_preorder(db, root, cur);
    }
    return db.nodes.len as i32;
}

fn add_symbol(db: CompilerDb&, sym: Symbol) -> i32 {
    let id = db.symbols.len as i32;
    db.symbols.push(sym);
    return id;
}

fn sym_matches_name(db: const CompilerDb&, id: i32, name: const u8[:]) -> bool {
    guard id >= 0 && id < db.symbols.len else { return false; }
    let sym = db.symbols[id];
    return text_of(db, sym.qual_span) == name || text_of(db, sym.name_span) == name;
}

fn find_symbol(db: CompilerDb&, name: const u8[:]) -> i32 {
    guard name.len > 0 else { return -1; }
    for i in db.symbols.len {
        let idx = i as i32;
        if sym_matches_name(db, idx, name) {
            return idx;
        }
    }
    return -1;
}

fn find_symbol_near(db: CompilerDb&, file_id: i32, name: const u8[:]) -> i32 {
    guard name.len > 0 else { return -1; }
    for i in db.symbols.len {
        let idx = i as i32;
        if db.symbols[idx].span.file_id == file_id && sym_matches_name(db, idx, name) {
            return idx;
        }
    }
    if file_id >= 0 && file_id < db.files.len {
        let cur_ns = trim_ascii_ws(text_of(db, db.files[file_id].ns_span));
        if cur_ns.len > 0 {
            for i in db.symbols.len {
                let idx = i as i32;
                let sfid = db.symbols[idx].span.file_id;
                let sns = if sfid >= 0 && sfid < db.files.len {
                    trim_ascii_ws(text_of(db, db.files[sfid].ns_span))
                } else {
                    ""
                };
                if sns == cur_ns && sym_matches_name(db, idx, name) {
                    return idx;
                }
            }
        }
    }
    return find_symbol(db, name);
}

fn is_ws_char(b: u8) -> bool {
    return b == ' ' || b == '\t' || b == '\r' || b == '\n';
}

fn trim_ascii_ws(s: const u8[:]) -> const u8[:] {
    var cur = s;
    for step in s.len {
        guard cur.len > 0 && is_ws_char(cur[0]) else { break; }
        cur = cur[1..];
    }
    for step in s.len {
        let last = dec_i64(cur.len);
        guard last >= 0 && last < cur.len && is_ws_char(cur[last]) else { break; }
        cur = cur[..last];
    }
    return cur;
}

fn slice_starts_with(s: const u8[:], p: const u8[:]) -> bool {
    guard p.len >= 0 && p.len <= s.len else { return false; }
    return s[..p.len] == p;
}

fn slice_ends_with(s: const u8[:], sfx: const u8[:]) -> bool {
    guard sfx.len >= 0 && sfx.len <= s.len else { return false; }
    let off = sub_i64(s.len, sfx.len);
    guard off >= 0 && off <= s.len else { return false; }
    return s[off..] == sfx;
}

fn slice_find(s: const u8[:], sub: const u8[:]) -> i64 {
    if sub.len == 0 {
        return 0;
    }
    guard sub.len > 0 && sub.len <= s.len else { return -1; }
    for i in s.len {
        let tail = s[i..];
        guard sub.len <= tail.len else { return -1; }
        if tail[..sub.len] == sub {
            return i;
        }
    }
    return -1;
}

fn primitive_val_type(base: const u8[:]) -> ValType {
    if base == "bool" { return ValType.Bool; }
    if base == "u8" { return ValType.U8; }
    if base == "u16" { return ValType.U16; }
    if base == "u32" { return ValType.U32; }
    if base == "u64" { return ValType.U64; }
    if base == "i8" { return ValType.I8; }
    if base == "i16" { return ValType.I16; }
    if base == "i32" { return ValType.I32; }
    if base == "i64" { return ValType.I64; }
    if base == "f32" { return ValType.F32; }
    if base == "f64" { return ValType.F64; }
    return ValType.Unknown;
}

fn container_val_type(base: const u8[:], is_ref: bool) -> ValType {
    if slice_find(base, "u8[:]") >= 0 { return ValType.SliceU8; }
    if slice_find(base, "[>..") >= 0 { return ValType.GrowVec; }
    if slice_find(base, "[..") >= 0 { return ValType.BoundedVec; }
    if slice_find(base, "[") >= 0 && slice_ends_with(base, "]") { return ValType.FixedArray; }
    if is_ref { return ValType.RefParam; }
    return ValType.StructVal;
}

fn split_at_str(s: const u8[:], sub: const u8[:]) -> const u8[:], const u8[:], bool {
    let idx = slice_find(s, sub);
    guard idx >= 0 && idx <= s.len else { return s, "", false; }
    let tail = s[idx..];
    guard sub.len >= 0 && sub.len <= tail.len else { return s[..idx], "", true; }
    return s[..idx], tail[sub.len..], true;
}

fn strip_ref_suffix(t: const u8[:]) -> const u8[:], bool {
    guard slice_ends_with(t, "&") else { return t, false; }
    let prefix, _, ok = split_at_str(t, "&");
    if ok && prefix.len > 0 {
        return trim_ascii_ws(prefix), true;
    }
    return t, true;
}

fn classify_val_type(raw_type: const u8[:]) -> ValType, bool {
    let trimmed = trim_ascii_ws(raw_type);
    let is_slice_array = slice_find(trimmed, "[:][..") >= 0;
    let is_const = slice_starts_with(trimmed, "const ") && !is_slice_array;
    let base_raw, is_ref = strip_ref_suffix(trimmed);
    let is_mut_slice_view = !is_ref && !is_const && slice_ends_with(base_raw, "[:]");
    let is_ref_mut = (is_ref && !is_const) || is_mut_slice_view;
    let base = if slice_starts_with(base_raw, "const ") {
        trim_ascii_ws(base_raw[6..])
    } else {
        base_raw
    };
    let prim = primitive_val_type(base);
    if prim != ValType.Unknown {
        return prim, is_ref_mut;
    }
    return container_val_type(base, is_ref_mut), is_ref_mut;
}

fn val_type_size_class(vt: ValType, is_ref_mut: bool, raw_type: const u8[:]) -> const u8[:] {
    let t = trim_ascii_ws(raw_type);
    if is_ref_mut && !slice_ends_with(t, "&") && slice_ends_with(t, "[:]") {
        return "mutable slice view (`0..2^63-1`)";
    }
    if is_ref_mut && (t == "B&" || slice_find(t, "ByteBuilder") >= 0 || slice_find(t, "[..") >= 0) {
        return "generic buffer reference";
    }
    if is_ref_mut && slice_find(t, "ByteCursor") >= 0 {
        return "mutable cursor reference";
    }
    if is_ref_mut {
        return "mutable reference";
    }
    if slice_ends_with(t, "&") {
        return "const reference";
    }
    return match vt {
        Bool => "fixed 8-bit boolean",
        U8 => "fixed 8-bit unsigned",
        U16 => "fixed 16-bit unsigned",
        U32 => "fixed 32-bit unsigned",
        U64 => "fixed 64-bit unsigned",
        I8 => "fixed 8-bit signed",
        I16 => "fixed 16-bit signed",
        I32 => "fixed 32-bit signed",
        I64 => "fixed 64-bit signed",
        F32 => "fixed 32-bit float",
        F64 => "fixed 64-bit float",
        SliceU8 => "byte slice view (`0..2^63-1`)",
        FixedArray => "fixed array",
        BoundedVec => "bounded inline buffer",
        GrowVec => "resizable data-stack vector",
        EnumVal => "fixed enum",
        StructVal => "fixed struct",
        RefParam => "generic buffer reference",
        Unknown => "fixed value",
    };
}

fn format_u64_hex_lit(out: u8[>..]&, val: u64) {
    if val == 0 {
        out.append("0");
        return;
    }
    if val == 0x3fffffffffffffff {
        out.append("0x3fff_ffff_ffff_ffff");
        return;
    }
    out.append("0x");
    let width: i64 = if val <= 0xff { 2 } else { 0 };
    format_uint(out, val, 16, width, '0');
}

fn glob_match(pattern: const u8[:], text: const u8[:]) -> bool {
    if pattern == "*" {
        return true;
    }
    let prefix, rest, has_star = split_at_str(pattern, "*");
    if !has_star {
        return pattern == text;
    }
    guard slice_starts_with(text, prefix) && prefix.len <= text.len else { return false; }
    let tail = text[prefix.len..];
    let mid, suffix, has_second = split_at_str(rest, "*");
    if !has_second {
        return slice_ends_with(tail, rest);
    }
    return slice_ends_with(tail, suffix) && slice_find(tail, mid) >= 0;
}
