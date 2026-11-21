// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// JSON configuration and TSV intrinsics/template loader.

import std;
import os;
import json;
import db from "../model";

let DEFAULT_INTRINSICS = embed_file("../../data/intrinsics.tsv");
let DEFAULT_TEMPLATES = embed_file("../../data/ste_templates.tsv");

enum IntrinsicKind {
    ReadKind,
    WriteKind,
    RollbackKind,
    SatOpKind,
}

struct IntrinsicEntry {
    symbol:            u8[..64]      = [],
    kind:              IntrinsicKind = IntrinsicKind.ReadKind,
    target_arg:        i32           = 0,
    payload_arg:       i32           = -1,
    encoding:          u8[..32]      = [],
    domain:            u8[..48]      = [],
    rollback_on_false: bool          = true,
}

struct IntrinsicTable {
    entries: IntrinsicEntry[..128] = [],
    count:   i32                   = 0,
}

struct TemplateEntry {
    template_id: u8[..32]  = [],
    block_name:  u8[..32]  = [],
    pattern:     u8[..160] = [],
}

struct TemplateTable {
    entries: TemplateEntry[..32] = [],
    count:   i32                 = 0,
}

struct Config {
    roots:               u8[..128][..16] = [],
    include:             u8[..128][..32] = [],
    exclude:             u8[..128][..32] = [],
    functions:           u8[..128][..32] = [],
    max_inline_depth:    i32             = 3,
    inline_max_nodes:    i32             = 24,
    max_fsm_rows:        i32             = 128,
    fold_lookup_tables:  bool            = true,
    formats:             u8[..32][..8]   = [],
    out_dir:             u8[..256]       = [],
    strict:              bool            = true,
    sections:            u8[..32][..16]  = [],
    intrinsics_manifest: u8[..256]       = [],
}

fn copy_bounded_str<B>(dst: B&, src: const u8[:]) {
    dst.clear();
    for b in src {
        if dst.len < dst.cap {
            dst.push(b);
        }
    }
}

fn push_bounded_str<A>(arr: A&, val: const u8[:]) {
    guard arr.len < arr.cap else { return; }
    var item: u8[..128] = [];
    copy_bounded_str(item, val);
    arr.push(item);
}

fn push_bounded_short<A>(arr: A&, val: const u8[:]) {
    guard arr.len < arr.cap else { return; }
    var item: u8[..32] = [];
    copy_bounded_str(item, val);
    arr.push(item);
}

fn default_config() -> Config {
    var cfg = Config { .. };
    push_bounded_str(cfg.roots, "wing.goose");
    push_bounded_str(cfg.roots, "core.goose");
    push_bounded_str(cfg.include, "quic/*");
    push_bounded_str(cfg.include, "tls/*");
    push_bounded_str(cfg.include, "http/*");
    push_bounded_str(cfg.exclude, "core/bytes/swar_*");
    push_bounded_str(cfg.exclude, "*::bloom_*");
    push_bounded_str(cfg.functions, "decode_*");
    push_bounded_str(cfg.functions, "encode_*");
    push_bounded_str(cfg.functions, "parse_*");
    push_bounded_str(cfg.functions, "validate_*");
    push_bounded_str(cfg.functions, "handle_*");
    push_bounded_str(cfg.functions, "process_*");
    push_bounded_str(cfg.functions, "on_*");
    push_bounded_str(cfg.functions, "apply_*");
    push_bounded_str(cfg.functions, "verify_*");
    push_bounded_str(cfg.functions, "check_*");
    push_bounded_str(cfg.functions, "recv_*");
    push_bounded_str(cfg.functions, "send_*");
    push_bounded_str(cfg.functions, "extract_*");
    push_bounded_str(cfg.functions, "demux_*");
    push_bounded_str(cfg.functions, "open_*");
    push_bounded_str(cfg.functions, "*_open_*");
    push_bounded_str(cfg.functions, "seal_*");
    push_bounded_str(cfg.functions, "*_seal_*");
    push_bounded_str(cfg.functions, "sign_*");
    push_bounded_str(cfg.functions, "*_sign_*");
    push_bounded_str(cfg.functions, "format_*");
    push_bounded_str(cfg.functions, "serialize_*");
    push_bounded_str(cfg.functions, "scan_*");
    push_bounded_str(cfg.functions, "pack_*");
    push_bounded_str(cfg.functions, "unpack_*");
    push_bounded_str(cfg.functions, "escape_*");
    push_bounded_str(cfg.functions, "unescape_*");
    push_bounded_str(cfg.functions, "sanitize_*");
    push_bounded_str(cfg.functions, "resolve_*");
    push_bounded_short(cfg.formats, "sm.md");
    push_bounded_short(cfg.formats, "json");
    copy_bounded_str(cfg.out_dir, "out/spec");
    push_bounded_short(cfg.sections, "manifest");
    push_bounded_short(cfg.sections, "structures");
    push_bounded_short(cfg.sections, "signature");
    push_bounded_short(cfg.sections, "entry_context");
    push_bounded_short(cfg.sections, "wire_ops");
    push_bounded_short(cfg.sections, "requirements");
    push_bounded_short(cfg.sections, "unchecked_surface");
    push_bounded_short(cfg.sections, "error_side_effects");
    push_bounded_short(cfg.sections, "machines");
    copy_bounded_str(cfg.intrinsics_manifest, "data/intrinsics.tsv");
    return cfg;
}

fn load_json_str_array_128<A>(node: json::Node?, dst: A&) -> bool {
    guard node else { return true; }
    match node.val { Arr => {}, _ => { return false; } }
    dst.clear();
    var item = node.first;
    while item {
        let s, ok = json::as_string(item);
        guard ok else { return false; }
        push_bounded_str(dst, s);
        item .= item.next;
    }
    return true;
}

fn load_json_str_array_32<A>(node: json::Node?, dst: A&) -> bool {
    guard node else { return true; }
    match node.val { Arr => {}, _ => { return false; } }
    dst.clear();
    var item = node.first;
    while item {
        let s, ok = json::as_string(item);
        guard ok else { return false; }
        push_bounded_short(dst, s);
        item .= item.next;
    }
    return true;
}

fn read_json_i32(root: json::Node?, key: const u8[:], lo: i64, hi: i64, dst: i32&) -> bool {
    let n = json::member(root, key);
    guard n else { return true; }
    let v, ok = json::as_i64(n);
    guard ok && v >= lo && v <= hi else { return false; }
    dst = v as i32;
    return true;
}

fn read_json_bool(root: json::Node?, key: const u8[:], dst: bool&) -> bool {
    let n = json::member(root, key);
    guard n else { return true; }
    let b, ok = json::as_bool(n);
    guard ok else { return false; }
    dst = b;
    return true;
}

fn apply_json_scalars(root: json::Node?, cfg: Config&) -> bool {
    guard read_json_i32(root, "max_inline_depth", 0, 64, cfg.max_inline_depth) else { return false; }
    guard read_json_i32(root, "inline_max_nodes", 1, 4096, cfg.inline_max_nodes) else { return false; }
    guard read_json_i32(root, "max_fsm_rows", 1, 4096, cfg.max_fsm_rows) else { return false; }
    guard read_json_bool(root, "fold_lookup_tables", cfg.fold_lookup_tables) else { return false; }
    guard read_json_bool(root, "strict", cfg.strict) else { return false; }
    return true;
}

fn apply_json_paths(root: json::Node?, cfg: Config&) -> bool {
    let out_node = json::member(root, "out_dir");
    if out_node {
        let s, ok = json::as_string(out_node);
        guard ok && s.len > 0 else { return false; }
        copy_bounded_str(cfg.out_dir, s);
    }
    let man_node = json::member(root, "intrinsics_manifest");
    if man_node {
        let s, ok = json::as_string(man_node);
        guard ok && s.len > 0 else { return false; }
        copy_bounded_str(cfg.intrinsics_manifest, s);
    }
    return true;
}

fn apply_json_arrays(root: json::Node?, cfg: Config&) -> bool {
    guard load_json_str_array_128(json::member(root, "roots"), cfg.roots) else { return false; }
    guard load_json_str_array_128(json::member(root, "include"), cfg.include) else { return false; }
    guard load_json_str_array_128(json::member(root, "exclude"), cfg.exclude) else { return false; }
    guard load_json_str_array_128(json::member(root, "functions"), cfg.functions) else { return false; }
    guard load_json_str_array_32(json::member(root, "formats"), cfg.formats) else { return false; }
    guard load_json_str_array_32(json::member(root, "sections"), cfg.sections) else { return false; }
    return true;
}

fn load_config_json(raw: const u8[:], cfg: Config&) -> bool {
    var copy_buf: u8[>..] = [];
    copy_buf.append(raw);
    var doc:     json::Node[>..] = [];
    var decoded: u8[>..]         = [];
    let root, err = json::parse(copy_buf, doc, decoded);
    guard root && err.len == 0 else { return false; }
    match root.val { Obj => {}, _ => { return false; } }

    guard apply_json_arrays(root, cfg) else { return false; }
    guard apply_json_scalars(root, cfg) else { return false; }
    return apply_json_paths(root, cfg);
}

fn parse_intrinsic_kind(s: const u8[:]) -> IntrinsicKind, bool {
    if s == "READ" { return IntrinsicKind.ReadKind, true; }
    if s == "WRITE" { return IntrinsicKind.WriteKind, true; }
    if s == "ROLLBACK" { return IntrinsicKind.RollbackKind, true; }
    if s == "SAT_OP" { return IntrinsicKind.SatOpKind, true; }
    return IntrinsicKind.ReadKind, false;
}

fn parse_intrinsic_line(line: const u8[:], tbl: IntrinsicTable&) -> bool {
    guard tbl.entries.len < tbl.entries.cap else { return false; }
    let p0, r0, ok0 = split_at_str(line, "\t");
    let p1, r1, ok1 = split_at_str(r0, "\t");
    let p2, r2, ok2 = split_at_str(r1, "\t");
    let p3, r3, ok3 = split_at_str(r2, "\t");
    let p4, r4, ok4 = split_at_str(r3, "\t");
    let p5, p6, ok5 = split_at_str(r4, "\t");
    guard ok0 && ok1 && ok2 && ok3 && ok4 && ok5 else { return false; }

    let k, ok_k = parse_intrinsic_kind(trim_ascii_ws(p1));
    let targ, ok_t = parse_int(trim_ascii_ws(p2), 10);
    let parg, ok_p = parse_int(trim_ascii_ws(p3), 10);
    guard ok_k && ok_t && ok_p else { return false; }

    var entry = IntrinsicEntry {
        kind:              k,
        target_arg:        targ as i32,
        payload_arg:       parg as i32,
        rollback_on_false: trim_ascii_ws(p6) == "true",
        ..
    };
    copy_bounded_str(entry.symbol, trim_ascii_ws(p0));
    copy_bounded_str(entry.encoding, trim_ascii_ws(p4));
    copy_bounded_str(entry.domain, trim_ascii_ws(p5));
    tbl.entries.push(entry);
    tbl.count = tbl.entries.len as i32;
    return true;
}

fn parse_intrinsics_tsv(raw: const u8[:], tbl: IntrinsicTable&) -> bool {
    tbl.entries.clear();
    tbl.count = 0;
    var ok = true;
    var rest = raw;
    for step in 256 {
        guard rest.len > 0 else { break; }
        let raw_line, tail, has_nl = split_at_str(rest, "\n");
        let line = trim_ascii_ws(raw_line);
        if line.len > 0 && line[0] != '#' {
            if !parse_intrinsic_line(line, tbl) {
                ok = false;
            }
        }
        if !has_nl { break; }
        rest = tail;
    }
    return ok && tbl.count > 0;
}

fn load_default_intrinsics(tbl: IntrinsicTable&) -> bool {
    return parse_intrinsics_tsv(DEFAULT_INTRINSICS, tbl);
}

fn strip_ns_prefix(sym: const u8[:]) -> const u8[:] {
    let _, tail, ok = split_at_str(sym, "::");
    if ok {
        return tail;
    }
    return sym;
}

fn find_intrinsic(tbl: const IntrinsicTable&, name: const u8[:]) -> i32 {
    guard name.len > 0 else { return -1; }
    let short_name = strip_ns_prefix(name);
    for &entry, i in tbl.entries {
        let sym = entry.symbol[..];
        if sym == name || strip_ns_prefix(sym) == short_name {
            return i as i32;
        }
    }
    return -1;
}

fn parse_template_line(line: const u8[:], tbl: TemplateTable&) -> bool {
    guard tbl.entries.len < tbl.entries.cap else { return false; }
    let p0, r0, ok0 = split_at_str(line, "\t");
    let p1, p2, ok1 = split_at_str(r0, "\t");
    guard ok0 && ok1 else { return false; }

    var entry = TemplateEntry { .. };
    copy_bounded_str(entry.template_id, trim_ascii_ws(p0));
    copy_bounded_str(entry.block_name, trim_ascii_ws(p1));
    copy_bounded_str(entry.pattern, trim_ascii_ws(p2));
    tbl.entries.push(entry);
    tbl.count = tbl.entries.len as i32;
    return true;
}

fn parse_templates_tsv(raw: const u8[:], tbl: TemplateTable&) -> bool {
    tbl.entries.clear();
    tbl.count = 0;
    var ok = true;
    var rest = raw;
    for step in 128 {
        guard rest.len > 0 else { break; }
        let raw_line, tail, has_nl = split_at_str(rest, "\n");
        let line = trim_ascii_ws(raw_line);
        if line.len > 0 && line[0] != '#' {
            if !parse_template_line(line, tbl) {
                ok = false;
            }
        }
        if !has_nl { break; }
        rest = tail;
    }
    return ok && tbl.count > 0;
}

fn load_default_templates(tbl: TemplateTable&) -> bool {
    return parse_templates_tsv(DEFAULT_TEMPLATES, tbl);
}

fn find_template(tbl: const TemplateTable&, id: const u8[:]) -> const u8[:] {
    for &entry in tbl.entries {
        if entry.template_id[..] == id {
            return entry.pattern[..];
        }
    }
    return "";
}

fn replace_slot(src: const u8[:], tag: const u8[:], val: const u8[:], dst: u8[>..]&) {
    dst.clear();
    let h1, t1, ok1 = split_at_str(src, tag);
    if !ok1 {
        dst.append(src);
        return;
    }
    dst.append(h1);
    dst.append(val);
    let h2, t2, ok2 = split_at_str(t1, tag);
    if !ok2 {
        dst.append(t1);
        return;
    }
    dst.append(h2);
    dst.append(val);
    dst.append(t2);
}

fn render_template(
    tbl:  const TemplateTable&,
    id:   const u8[:],
    arg0: const u8[:],
    arg1: const u8[:],
    arg2: const u8[:],
    arg3: const u8[:],
    arg4: const u8[:],
    out:  u8[>..]&,
) -> bool {
    let pat = find_template(tbl, id);
    guard pat.len > 0 else { return false; }
    var a: u8[>..] = [];
    var b: u8[>..] = [];
    replace_slot(pat, "{0}", arg0, a);
    replace_slot(a[..], "{1}", arg1, b);
    replace_slot(b[..], "{2}", arg2, a);
    replace_slot(a[..], "{3}", arg3, b);
    replace_slot(b[..], "{4}", arg4, out);
    return true;
}

fn has_section(cfg: const Config&, sec: const u8[:]) -> bool {
    guard cfg.sections.len > 0 else { return true; }
    for &item in cfg.sections {
        if item[..] == sec {
            return true;
        }
    }
    return false;
}

fn has_format(cfg: const Config&, fmt: const u8[:]) -> bool {
    guard cfg.formats.len > 0 else { return fmt == "sm.md"; }
    for &item in cfg.formats {
        if item[..] == fmt {
            return true;
        }
    }
    return false;
}
