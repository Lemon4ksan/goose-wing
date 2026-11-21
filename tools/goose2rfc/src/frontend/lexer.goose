// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Comment-stripping Goose lexer with 1-based line and column tracking.

import std;
import db from "../model";
import loader from "../config";

struct LexCursor {
    file_id: i32 = 0,
    base_at: i32 = 0,
    pos:     i64 = 0,
    line:    i32 = 1,
    col:     i32 = 1,
}

fn lex_byte_at(src: const u8[:], pos: i64) -> u8 {
    guard pos >= 0 && pos < src.len else { return 0; }
    return src[pos];
}

fn lex_slice(src: const u8[:], start: i64, end: i64) -> const u8[:] {
    guard start >= 0 && end >= start && start <= src.len else { return ""; }
    let tail = src[start..];
    let n = sub_i64(end, start);
    guard n >= 0 && n <= tail.len else { return ""; }
    return tail[..n];
}

fn is_ident_start(b: u8) -> bool {
    return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '_';
}

fn is_ident_cont(b: u8) -> bool {
    return is_ident_start(b) || (b >= '0' && b <= '9');
}

fn is_digit_byte(b: u8) -> bool {
    return b >= '0' && b <= '9';
}

fn lex_step_one(src: const u8[:], c: LexCursor&) {
    let b = lex_byte_at(src, c.pos);
    c.pos = inc_i64(c.pos);
    if b == '\n' {
        c.line = inc_i32(c.line);
        c.col = 1;
    } else {
        c.col = inc_i32(c.col);
    }
}

fn lex_step_n(src: const u8[:], c: LexCursor&, count: i64) {
    for i in count {
        lex_step_one(src, c);
    }
}

fn skip_line_comment(src: const u8[:], c: LexCursor&) {
    lex_step_n(src, c, 2);
    let rem = sub_i64(src.len, c.pos);
    for step in rem {
        let b = lex_byte_at(src, c.pos);
        if b == 0 || b == '\n' {
            return;
        }
        lex_step_one(src, c);
    }
}

fn skip_block_comment(src: const u8[:], c: LexCursor&) {
    lex_step_n(src, c, 2);
    let rem = sub_i64(src.len, c.pos);
    for step in rem {
        guard c.pos < src.len else { return; }
        let b0 = lex_byte_at(src, c.pos);
        let b1 = lex_byte_at(src, inc_i64(c.pos));
        if b0 == '*' && b1 == '/' {
            lex_step_n(src, c, 2);
            return;
        }
        lex_step_one(src, c);
    }
}

fn skip_ws_and_comments(src: const u8[:], c: LexCursor&) {
    let rem = sub_i64(src.len, c.pos);
    for step in rem {
        guard c.pos < src.len else { return; }
        let b0 = lex_byte_at(src, c.pos);
        let b1 = lex_byte_at(src, inc_i64(c.pos));
        if b0 == ' ' || b0 == '\t' || b0 == '\r' || b0 == '\n' {
            lex_step_one(src, c);
        } else if b0 == '/' && b1 == '/' {
            skip_line_comment(src, c);
        } else if b0 == '/' && b1 == '*' {
            skip_block_comment(src, c);
        } else {
            return;
        }
    }
}

fn classify_keyword_a(word: const u8[:]) -> u8 {
    if word == "namespace" { return TOK_NAMESPACE; }
    if word == "import" { return TOK_IMPORT; }
    if word == "from" { return TOK_FROM; }
    if word == "const" { return TOK_CONST; }
    if word == "let" { return TOK_LET; }
    if word == "var" { return TOK_VAR; }
    if word == "fn" { return TOK_FN; }
    if word == "inline" { return TOK_INLINE; }
    if word == "checkfree" { return TOK_CHECKFREE; }
    if word == "recursive" { return TOK_RECURSIVE; }
    if word == "struct" { return TOK_STRUCT; }
    return TOK_IDENT;
}

fn classify_keyword_b(word: const u8[:]) -> u8 {
    if word == "root" { return TOK_ROOT; }
    if word == "enum" { return TOK_ENUM; }
    if word == "type" { return TOK_TYPE; }
    if word == "guard" { return TOK_GUARD; }
    if word == "else" { return TOK_ELSE; }
    if word == "defer" { return TOK_DEFER; }
    if word == "if" { return TOK_IF; }
    if word == "match" { return TOK_MATCH; }
    if word == "for" { return TOK_FOR; }
    if word == "in" { return TOK_IN; }
    return TOK_IDENT;
}

fn classify_keyword(word: const u8[:]) -> u8 {
    let ka = classify_keyword_a(word);
    if ka != TOK_IDENT { return ka; }
    let kb = classify_keyword_b(word);
    if kb != TOK_IDENT { return kb; }
    if word == "while" { return TOK_WHILE; }
    if word == "loop" { return TOK_LOOP; }
    if word == "return" { return TOK_RETURN; }
    if word == "break" { return TOK_BREAK; }
    if word == "continue" { return TOK_CONTINUE; }
    if word == "as" { return TOK_AS; }
    if word == "true" { return TOK_TRUE; }
    if word == "false" { return TOK_FALSE; }
    if word == "extern" { return TOK_EXTERN; }
    if word == "export" { return TOK_EXPORT; }
    return TOK_IDENT;
}

fn make_lex_span(c: const LexCursor&, start_pos: i64, start_line: i32, start_col: i32) -> Span {
    let offset = start_pos as i32;
    let length = sub_i64(c.pos, start_pos) as i32;
    return Span {
        file_id: c.file_id,
        at:      add_i32(c.base_at, offset),
        len:     length,
        line:    start_line,
        col:     start_col,
    };
}

fn scan_ident_or_kw(src: const u8[:], c: LexCursor&) -> Token {
    let start_pos = c.pos;
    let start_line = c.line;
    let start_col = c.col;
    let rem = sub_i64(src.len, c.pos);
    for step in rem {
        let b = lex_byte_at(src, c.pos);
        if !is_ident_cont(b) {
            break;
        }
        lex_step_one(src, c);
    }
    let word = lex_slice(src, start_pos, c.pos);
    var kind = classify_keyword(word);
    if kind == TOK_AS && lex_byte_at(src, c.pos) == '!' && lex_byte_at(src, inc_i64(c.pos)) != '=' {
        lex_step_one(src, c);
        kind = TOK_AS_BANG;
    }
    return Token { kind: kind, span: make_lex_span(c, start_pos, start_line, start_col) };
}

fn scan_number(src: const u8[:], c: LexCursor&) -> Token {
    let start_pos = c.pos;
    let start_line = c.line;
    let start_col = c.col;
    let rem = sub_i64(src.len, c.pos);
    for step in rem {
        let b = lex_byte_at(src, c.pos);
        if !is_ident_cont(b) {
            break;
        }
        lex_step_one(src, c);
    }
    return Token { kind: TOK_NUMBER, span: make_lex_span(c, start_pos, start_line, start_col) };
}

fn scan_quoted(src: const u8[:], c: LexCursor&, quote: u8, kind: u8) -> Token {
    let start_pos = c.pos;
    let start_line = c.line;
    let start_col = c.col;
    lex_step_one(src, c);
    let rem = sub_i64(src.len, c.pos);
    for step in rem {
        guard c.pos < src.len else { break; }
        let b = lex_byte_at(src, c.pos);
        lex_step_one(src, c);
        if b == '\\' && c.pos < src.len {
            lex_step_one(src, c);
        } else if b == quote {
            break;
        }
    }
    return Token { kind: kind, span: make_lex_span(c, start_pos, start_line, start_col) };
}

fn match_multi_op_long(s4: const u8[:], s3: const u8[:]) -> u8, i64 {
    if s4 == ">..<" { return TOK_GROWSHRINK, 4; }
    if s3 == ">.." { return TOK_GROW, 3; }
    if s3 == ".==" { return TOK_REF_EQ, 3; }
    if s3 == ".!=" { return TOK_REF_NE, 3; }
    if s3 == "<<=" { return TOK_SHLEQ, 3; }
    if s3 == ">>=" { return TOK_SHREQ, 3; }
    return 0, 0;
}

fn match_multi_op_pair_a(s2: const u8[:]) -> u8 {
    if s2 == ".=" { return TOK_REBIND; }
    if s2 == "~=" { return TOK_TILDE_EQ; }
    if s2 == ".." { return TOK_DOTDOT; }
    if s2 == "::" { return TOK_COLONCOLON; }
    if s2 == "->" { return TOK_ARROW; }
    if s2 == "=>" { return TOK_FATARROW; }
    if s2 == "<<" { return TOK_SHL; }
    if s2 == ">>" { return TOK_SHR; }
    if s2 == "<=" { return TOK_LE; }
    if s2 == ">=" { return TOK_GE; }
    if s2 == "==" { return TOK_EQ; }
    if s2 == "!=" { return TOK_NE; }
    return 0;
}

fn match_multi_op_pair_b(s2: const u8[:]) -> u8 {
    if s2 == "&&" { return TOK_ANDAND; }
    if s2 == "||" { return TOK_OROR; }
    if s2 == "+=" { return TOK_PLUSEQ; }
    if s2 == "-=" { return TOK_MINUSEQ; }
    if s2 == "*=" { return TOK_MULEQ; }
    if s2 == "/=" { return TOK_DIVEQ; }
    if s2 == "%=" { return TOK_MODEQ; }
    if s2 == "|=" { return TOK_OREQ; }
    if s2 == "&=" { return TOK_ANDEQ; }
    if s2 == "^=" { return TOK_XOREQ; }
    if s2 == "++" { return TOK_INC; }
    if s2 == "--" { return TOK_DEC; }
    return 0;
}

fn match_single_punct(b: u8) -> u8 {
    if b == '(' { return TOK_LPAREN; }
    if b == ')' { return TOK_RPAREN; }
    if b == '[' { return TOK_LBRACKET; }
    if b == ']' { return TOK_RBRACKET; }
    if b == '{' { return TOK_LCURLY; }
    if b == '}' { return TOK_RCURLY; }
    if b == ';' { return TOK_SEMI; }
    if b == ',' { return TOK_COMMA; }
    if b == ':' { return TOK_COLON; }
    if b == '.' { return TOK_DOT; }
    if b == '<' { return TOK_LT; }
    if b == '>' { return TOK_GT; }
    return 0;
}

fn match_single_op(b: u8) -> u8 {
    let p = match_single_punct(b);
    if p != 0 { return p; }
    if b == '=' { return TOK_ASSIGN; }
    if b == '+' { return TOK_PLUS; }
    if b == '-' { return TOK_MINUS; }
    if b == '*' { return TOK_MUL; }
    if b == '/' { return TOK_DIV; }
    if b == '%' { return TOK_MOD; }
    if b == '&' { return TOK_AMP; }
    if b == '|' { return TOK_PIPE; }
    if b == '^' { return TOK_CARET; }
    if b == '!' { return TOK_BANG; }
    if b == '~' { return TOK_TILDE; }
    if b == '?' { return TOK_QUESTION; }
    return TOK_OTHER;
}

fn scan_operator(src: const u8[:], c: LexCursor&) -> Token {
    let start_pos = c.pos;
    let start_line = c.line;
    let start_col = c.col;
    let s4 = lex_slice(src, c.pos, add_i64(c.pos, 4));
    let s3 = lex_slice(src, c.pos, add_i64(c.pos, 3));
    let s2 = lex_slice(src, c.pos, add_i64(c.pos, 2));

    let k_long, n_long = match_multi_op_long(s4, s3);
    if n_long > 0 {
        lex_step_n(src, c, n_long);
        return Token { kind: k_long, span: make_lex_span(c, start_pos, start_line, start_col) };
    }
    let ka = match_multi_op_pair_a(s2);
    let kb = if ka != 0 { ka } else { match_multi_op_pair_b(s2) };
    if kb != 0 {
        lex_step_n(src, c, 2);
        return Token { kind: kb, span: make_lex_span(c, start_pos, start_line, start_col) };
    }
    let ks = match_single_op(lex_byte_at(src, c.pos));
    lex_step_one(src, c);
    return Token { kind: ks, span: make_lex_span(c, start_pos, start_line, start_col) };
}

fn scan_next_token(src: const u8[:], c: LexCursor&) -> Token {
    let b = lex_byte_at(src, c.pos);
    if is_ident_start(b) {
        return scan_ident_or_kw(src, c);
    }
    if is_digit_byte(b) {
        return scan_number(src, c);
    }
    if b == '"' {
        return scan_quoted(src, c, '"', TOK_STRING);
    }
    if b == '\'' {
        return scan_quoted(src, c, '\'', TOK_CHAR);
    }
    return scan_operator(src, c);
}

fn tokenize_file(db: CompilerDb&, file_id: i32) -> bool {
    guard file_id >= 0 && file_id < db.files.len else { return false; }
    let text_start = db.files[file_id].text_start;
    let text_len = db.files[file_id].text_len;
    let src = text_of(db, Span { file_id: file_id, at: text_start, len: text_len, line: 1, col: 1 });
    let tok_start = db.tokens.len as i32;
    db.files[file_id].tok_start = tok_start;

    var c = LexCursor { file_id: file_id, base_at: text_start, pos: 0, line: 1, col: 1 };
    let max_steps = inc_i64(src.len);
    for step in max_steps {
        skip_ws_and_comments(src, c);
        if c.pos >= src.len {
            break;
        }
        let tok = scan_next_token(src, c);
        db.tokens.push(tok);
    }
    db.files[file_id].tok_count = sub_i32(db.tokens.len as i32, tok_start);
    return true;
}
