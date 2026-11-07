// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yujie Teo (yujieteo)
// Copyright (c) 2026 Lemon4ksan

import std;
import md.node;
import lint.context;
import lint.md_base;

let BR_SPACES = 2;
let MAX_BLANK_LINES = 1;
let MAX_LINE_LENGTH = 80;

fn check_trailing_spaces(L: Lint&, ln: i64) {
    guard L.kinds[ln] != LINE_CODE;
    let t = line_text(L, ln);
    let kept = trim_end(t);
    let n = t.len - kept.len;
    guard n > 0 && n != BR_SPACES;
    report(L, L.lines[ln] + kept.len, "MD009", str(n, " trailing spaces: delete them, or use ", BR_SPACES, " for a line break"));
}

fn check_hard_tabs(L: Lint&, ln: i64) {
    let t = line_text(L, ln);
    var i = 0;
    while i < t.len {
        if t[i] == '\t' {
            report(L, L.lines[ln] + i, "MD010", "hard tab: use spaces");
            while i < t.len && t[i] == '\t' { i++; }
        } else {
            i++;
        }
    }
}

fn check_blank_runs(L: Lint&) {
    var run = 0;
    for ln in 1..last_line(L) + 1 {
        guard L.kinds[ln] != LINE_FRONT;
        run = if is_code_line(L, ln) || trim(line_text(L, ln)).len > 0 { 0 } else { run + 1 };
        if run > MAX_BLANK_LINES { report_at(L, ln, 1, "MD012", str(run, " blank lines in a row: use ", MAX_BLANK_LINES)); }
    }
}

fn hash_run(t: const u8[:]) -> i64 {
    var n = 0;
    while n < t.len && t[n] == '#' { n++; }
    return n;
}

fn check_missing_space_atx(L: Lint&, ln: i64) {
    let t = line_text(L, ln);
    let h = hash_run(t);
    guard h > 0 && h < t.len && t[h] != ' ' && t[h] != '\t';
    guard !ends_with(trim_end(t), "#") && !starts_with(t, "#\xEF\xB8\x8F\xE2\x83\xA3");
    report_at(L, ln, 1, "MD018", "no space after the hash of a heading: add a space");
}

struct ClosedAtx { left: i64, right: i64, escape: bool, close_at: i64 }

fn parse_closed_atx(t: const u8[:]) -> ClosedAtx {
    let none = ClosedAtx { left: -1, right: -1, escape: false, close_at: -1 };
    let h = hash_run(t);
    guard h > 0 else { return none; }
    var i = h;
    while i < t.len && (t[i] == ' ' || t[i] == '\t') { i++; }
    let e = trim_end(t).len;
    var k = e;
    while k > i && t[k - 1] == '#' { k--; }
    guard k < e && k > i else { return none; }
    let escape = t[k - 1] == '\\' && e - k >= 2;
    let close = if escape { k + 1 } else { k };
    var c = if escape { k - 1 } else { k };
    var j = c;
    while j > i && (t[j - 1] == ' ' || t[j - 1] == '\t') { j--; }
    guard j > i && position(t[i..j], '#') < 0 && t[j - 1] != '\\' else { return none; }
    return ClosedAtx { left: i - h, right: c - j, escape: escape, close_at: close };
}

fn check_closed_atx_space(L: Lint&, ln: i64) {
    let m = parse_closed_atx(line_text(L, ln));
    guard m.left >= 0;
    if m.left == 0 {
        report_at(L, ln, 1, "MD020", "no space after the opening hashes of a closed heading: add a space");
    } else if m.right == 0 || m.escape {
        report(L, L.lines[ln] + m.close_at, "MD020", "no space before the closing hashes of a closed heading: add a space");
    }
}

fn reversed_link_end(t: const u8[:], i: i64) -> i64 {
    guard t[i] == '(' && (i == 0 || t[i - 1] != '\\') else { return -1; }
    var j = i + 1;
    while j < t.len && t[j] != '(' && t[j] != ')' { j++; }
    guard j > i + 1 && j + 2 < t.len && t[j] == ')' && t[j + 1] == '[' && t[j - 1] != '\\' else { return -1; }
    guard t[j + 2] != ']' && t[j + 2] != '^' else { return -1; }
    let close = position(t[j + 2..], ']');
    guard close >= 0 else { return -1; }
    let end = j + 2 + close + 1;
    guard t[end - 2] != '\\' && (end >= t.len || t[end] != '(') else { return -1; }
    return end;
}

fn check_reversed_links(L: Lint&, ln: i64) {
    let t = line_text(L, ln);
    var i = 0;
    while i < t.len {
        let end = reversed_link_end(t, i);
        if end > 0 && !in_code_span(t, i) {
            report(L, L.lines[ln] + i, "MD011", str("reversed link ", t[i..end], ": write [text](url)"));
            i = end;
        } else {
            i++;
        }
    }
}

fn in_code_span(t: const u8[:], at: i64) -> bool {
    let ticks = count(t[..at]) { it == '`' };
    return ticks % 2 == 1;
}

fn has_breakable_space(t: const u8[:]) -> bool {
    var i = 0;
    while i < t.len {
        let c = t[i];
        if c == ' ' || c == '\t' || c == '>' {
            i++;
        } else if (c == '-' || c == '*' || c == '+') && i + 1 < t.len && (t[i + 1] == ' ' || t[i + 1] == '\t') {
            i += 2;
        } else if c >= '0' && c <= '9' {
            var j = i;
            while j < t.len && t[j] >= '0' && t[j] <= '9' { j++; }
            if j < t.len && (t[j] == '.' || t[j] == ')') && j + 1 < t.len && (t[j + 1] == ' ' || t[j + 1] == '\t') {
                i = j + 2;
            } else {
                break;
            }
        } else {
            break;
        }
    }
    let body = trim_end(t[i..]);
    var ticks = 0;
    var in_dest = false;
    for ch, idx in body {
        if ch == '`' { ticks++; }
        if ticks % 2 == 0 {
            if idx > 0 && body[idx - 1] == ']' && ch == '(' { in_dest = true; }
            if in_dest && ch == ')' && (idx == 0 || body[idx - 1] != '\\') { in_dest = false; }
            if !in_dest && (ch == ' ' || ch == '\t') { return true; }
        }
    }
    return false;
}

fn check_line_length(L: Lint&, ln: i64) {
    guard L.kinds[ln] == LINE_TEXT;
    let t = trim_end(line_text(L, ln));
    guard !starts_with(trim_start(t), "<!--") && !starts_with(trim_start(t), "[");
    var cols = 0;
    for c in t { if (c & 0xC0) != 0x80 { cols++; } }
    guard cols > MAX_LINE_LENGTH && has_breakable_space(t);
    report_at(L, ln, MAX_LINE_LENGTH + 1, "MD013", str("line length ", cols, " exceeds ", MAX_LINE_LENGTH, " columns: wrap the line"));
}

fn check_final_newline(L: Lint&) {
    let n = last_line(L);
    guard !blank_at(L, n);
    report(L, L.lines[n] + max(line_text(L, n).len - 1, 0), "MD047", "file does not end with a newline: add one");
}

fn check_lines(L: Lint&) {
    for ln in 1..last_line(L) + 1 {
        guard L.kinds[ln] != LINE_FRONT;
        check_trailing_spaces(L, ln);
        check_hard_tabs(L, ln);
        guard is_markdown_line(L, ln);
        check_missing_space_atx(L, ln);
        check_closed_atx_space(L, ln);
        check_reversed_links(L, ln);
        check_line_length(L, ln);
    }
    check_blank_runs(L);
    check_final_newline(L);
}
