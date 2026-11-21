// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// goose2rfc CLI entrypoint and top-level data-stack arena owner.

import std;
import os;
import dictionary;
import db from "./model";
import loader from "./config";
import frontend.lexer;
import frontend.parser;
import frontend.imports;
import frontend.hir;
import sema.const_fold;
import sema.inliner;
import sema.wire_trace;
import sema.effects;
import sema.fsm;
import emit.md_ste;
import emit.json;

struct CliOptions {
    cmd:           u8[..16]        = [],
    config_path:   u8[..256]       = [],
    root_override: u8[..256]       = [],
    fn_glob:       u8[..128]       = [],
    format_arg:    u8[..32]        = [],
    out_path:      u8[..256]       = [],
    diag_mode:     u8[..16]        = [],
    depth_arg:     i32             = -1,
    has_strict:    bool            = false,
    targets:       u8[..256][..16] = [],
}

fn push_target_path(opts: CliOptions&, val: const u8[:]) {
    guard opts.targets.len < opts.targets.cap else { return; }
    var item: u8[..256] = [];
    copy_bounded_str(item, val);
    opts.targets.push(item);
}

fn parse_str_flag(flag: const u8[:], val: const u8[:], opts: CliOptions&) -> bool {
    if flag == "--config" {
        copy_bounded_str(opts.config_path, val);
        return true;
    }
    if flag == "--root" {
        copy_bounded_str(opts.root_override, val);
        return true;
    }
    if flag == "--fn" {
        copy_bounded_str(opts.fn_glob, val);
        return true;
    }
    if flag == "--format" {
        copy_bounded_str(opts.format_arg, val);
        return true;
    }
    if flag == "-o" || flag == "--out" {
        copy_bounded_str(opts.out_path, val);
        return true;
    }
    if flag == "--diagnostics" {
        copy_bounded_str(opts.diag_mode, val);
        return true;
    }
    return false;
}

fn parse_flag_pair(flag: const u8[:], val: const u8[:], opts: CliOptions&) -> bool {
    if parse_str_flag(flag, val, opts) {
        return true;
    }
    if flag == "--max-inline-depth" {
        let d, ok = parse_int(val, 10);
        guard ok && d >= 0 && d <= 64 else { return false; }
        opts.depth_arg = d as i32;
        return true;
    }
    return false;
}

fn step_cli_arg(
    raw_args:  const u8[:][:],
    idx:       i64,
    opts:      CliOptions&,
    skip_next: bool&,
) -> bool {
    guard idx >= 0 && idx < raw_args.len else { return false; }
    let a = raw_args[idx];
    if a == "--" { return true; }
    if a == "--version" || a == "-v" {
        copy_bounded_str(opts.cmd, "version");
        return true;
    }
    if a == "--strict" {
        opts.has_strict = true;
        return true;
    }
    if a.len > 0 && a[0] == '-' {
        let nxt = inc_i64(idx);
        guard nxt >= 0 && nxt < raw_args.len else { return false; }
        skip_next = true;
        return parse_flag_pair(a, raw_args[nxt], opts);
    }
    if opts.cmd.len == 0 && (a == "compile" || a == "check") {
        copy_bounded_str(opts.cmd, a);
    } else {
        push_target_path(opts, a);
    }
    return true;
}

fn parse_cli_args(raw_args: const u8[:][:], opts: CliOptions&) -> bool {
    copy_bounded_str(opts.diag_mode, "text");
    var skip_next = false;
    for i in raw_args.len {
        if i == 0 { continue; }
        if skip_next {
            skip_next = false;
            continue;
        }
        guard step_cli_arg(raw_args, i, opts, skip_next) else { return false; }
        if opts.cmd[..] == "version" {
            return true;
        }
    }
    return opts.cmd.len > 0;
}

fn apply_config_file(opts: const CliOptions&, cfg: Config&) -> bool {
    if opts.config_path.len > 0 {
        var raw: u8[>..] = [];
        guard read_file(opts.config_path[..], raw) else { return false; }
        return load_config_json(raw[..], cfg);
    }
    if opts.targets.len == 0 {
        var raw: u8[>..] = [];
        if read_file("goose2rfc.json", raw) {
            load_config_json(raw[..], cfg);
        }
    }
    return true;
}

fn apply_cli_overrides(opts: const CliOptions&, cfg: Config&) -> bool {
    guard apply_config_file(opts, cfg) else { return false; }
    if opts.root_override.len > 0 {
        cfg.roots.clear();
        push_bounded_str(cfg.roots, opts.root_override[..]);
    } else if opts.targets.len > 0 && opts.config_path.len == 0 {
        cfg.roots.clear();
    }
    if opts.fn_glob.len > 0 {
        cfg.functions.clear();
        push_bounded_str(cfg.functions, opts.fn_glob[..]);
    }
    if opts.depth_arg >= 0 {
        cfg.max_inline_depth = opts.depth_arg;
    }
    if opts.format_arg.len > 0 {
        cfg.formats.clear();
        push_bounded_short(cfg.formats, opts.format_arg[..]);
    }
    if opts.has_strict {
        cfg.strict = true;
    }
    return true;
}

fn last_dir_sep(s: const u8[:]) -> i64 {
    var found: i64 = -1;
    for i in s.len {
        let b = s[i];
        if b == '/' || b == '\\' {
            found = i;
        }
    }
    return found;
}

fn infer_root_dir(opts: const CliOptions&) -> const u8[:] {
    let r = opts.root_override[..];
    let sep = last_dir_sep(r);
    if sep > 0 && sep <= r.len {
        return r[..sep];
    }
    return ".";
}

fn format_intrinsic_kind_tag(k: IntrinsicKind) -> const u8[:] {
    return match k {
        ReadKind => "READ",
        WriteKind => "WRITE",
        RollbackKind => "ROLLBACK",
        SatOpKind => "SAT_OP",
    };
}

fn emit_single_check_symbol(db: const CompilerDb&, sym: Symbol, out: u8[>..]&) {
    guard sym.kind == SymKind.ConstSym && sym.has_const else { return; }
    let name = text_of(db, sym.name_span);
    let qname = text_of(db, sym.qual_span);
    let _, _, has_ns = split_at_str(qname, "::");
    out.append("resolved_symbol: ");
    if has_ns {
        out.append(qname);
    } else if name == "QUIC_VARINT_MAX" {
        out.append("rfc::QUIC_VARINT_MAX");
    } else {
        out.append(name);
    }
    out.append(" = 0x");
    format_uint(out, sym.const_val, 16, 0, '0');
    out.push('\n');
}

fn emit_check_symbols(db: const CompilerDb&, out: u8[>..]&) {
    for i in db.symbols.len {
        emit_single_check_symbol(db, db.symbols[i], out);
    }
}

fn emit_ufcs_check_node(
    db:         const CompilerDb&,
    n:          AstNode,
    intrinsics: const IntrinsicTable&,
    out:        u8[>..]&,
) {
    let intr_idx = dec_i32(n.const_val as i32);
    guard intr_idx >= 0 && intr_idx < intrinsics.entries.len else { return; }
    let entry = intrinsics.entries[intr_idx];
    let recv_id = n.first;
    out.append("ufcs_desugar: ");
    out.append(entry.symbol[..]);
    out.push('(');
    if recv_id >= 0 && recv_id < db.nodes.len {
        out.append(text_of(db, db.nodes[recv_id].span));
    }
    out.append(") [");
    out.append(format_intrinsic_kind_tag(entry.kind));
    out.push(' ');
    out.append(entry.encoding[..]);
    out.append("]\n");
}

fn emit_check_ast_items(db: const CompilerDb&, intrinsics: const IntrinsicTable&, out: u8[>..]&) {
    for i in db.nodes.len {
        let n = db.nodes[i];
        if n.kind == AstKind.UfcsCallExpr && n.const_val > 0 {
            emit_ufcs_check_node(db, n, intrinsics, out);
        }
    }
    for i in db.nodes.len {
        let n = db.nodes[i];
        if n.kind == AstKind.CastExpr {
            let ctxt = text_of(db, n.aux_span);
            if ctxt.len > 0 {
                out.append("cast_expr: ");
                out.append(ctxt);
                out.push('\n');
            }
        }
    }
}

fn format_dirty_violation(db: const CompilerDb&, eff: ParamEffect, diag_mode: const u8[:], out: u8[>..]&) {
    if diag_mode == "json" {
        out.append("{\"rule\":\"dirty-exposed\",\"message\":\"");
        out.append(text_of(db, eff.mechanism_text));
        out.append("\"}\n");
        return;
    }
    out.append(file_path_of(db, eff.span.file_id));
    out.push(':');
    format_int(out, eff.span.line, 10, 0, ' ');
    out.append(":1: dirty-exposed: ");
    out.append(text_of(db, eff.mechanism_text));
    out.push('\n');
}

fn count_spec_dirty_effects(
    db:        const CompilerDb&,
    spec:      SpecFunction,
    diag_mode: const u8[:],
    out:       u8[>..]&,
) -> i32 {
    var count: i32 = 0;
    for e in spec.effect_count {
        let eff_idx = add_i32(spec.effect_start, e);
        if eff_idx >= 0 && eff_idx < db.effects.len {
            let eff = db.effects[eff_idx];
            if eff.state == RollbackState.DirtyExposed {
                count = inc_i32(count);
                format_dirty_violation(db, eff, diag_mode, out);
            }
        }
    }
    return count;
}

fn count_strict_violations(db: const CompilerDb&, diag_mode: const u8[:], out: u8[>..]&) -> i32 {
    var violations: i32 = 0;
    for i in db.specs.len {
        let spec = db.specs[i];
        violations = add_i32(violations, spec.unanalyzed_statements);
        violations = add_i32(violations, count_spec_dirty_effects(db, spec, diag_mode, out));
    }
    return violations;
}

fn ensure_parent_dir(path: const u8[:]) {
    let sep = last_dir_sep(path);
    guard sep > 0 && sep <= path.len else { return; }
    for i in sep {
        let b = path[i];
        if (b == '/' || b == '\\') && i > 0 {
            make_dir(path[..i]);
        }
    }
    make_dir(path[..sep]);
}

fn has_file_ext(path: const u8[:], ext: const u8[:]) -> bool {
    return glob_match(ext, path);
}

fn write_or_print_output(opts: const CliOptions&, cfg: const Config&, md_buf: const u8[:], json_buf: const u8[:]) -> bool {
    let out_p = opts.out_path[..];
    if out_p.len == 0 {
        if has_format(cfg, "json") && !has_format(cfg, "sm.md") && !has_format(cfg, "md") {
            write_stdout(json_buf);
        } else {
            write_stdout(md_buf);
        }
        return true;
    }
    ensure_parent_dir(out_p);
    if has_file_ext(out_p, "*.json") {
        return write_file(out_p, json_buf);
    }
    if has_file_ext(out_p, "*.md") {
        return write_file(out_p, md_buf);
    }
    make_dir(out_p);
    var fpath: u8[>..] = [];
    fpath.append(out_p);
    fpath.append("/spec.sm.md");
    return write_file(fpath[..], md_buf);
}

fn run_sema_passes(db: CompilerDb&, cfg: Config&, intrinsics: IntrinsicTable&) -> bool {
    guard build_hir(db, cfg, intrinsics) else { return false; }
    guard fold_constants(db, cfg) else { return false; }
    guard inline_predicates(db, cfg, intrinsics) else { return false; }
    guard analyze_all_wire_traces(db, intrinsics) else { return false; }
    guard analyze_call_graph_and_effects(db, intrinsics) else { return false; }
    return extract_state_machines(db, cfg);
}

fn collect_target_slices(opts: const CliOptions&, out: const u8[:][>..]&) -> bool {
    for &item in opts.targets {
        let t = item[..];
        var probe: u8[>..] = [];
        guard read_file(t, probe) else {
            write_stderr("error: input file not found\n");
            return false;
        }
        out.push(t);
    }
    return true;
}

fn emit_compile_outputs(
    db:        CompilerDb&,
    cfg:       Config&,
    templates: TemplateTable&,
    opts:      const CliOptions&,
) -> bool {
    var md_out:   u8[>..] = [];
    var json_out: u8[>..] = [];
    if has_format(cfg, "sm.md") || has_format(cfg, "md") {
        guard emit_markdown_ste(db, cfg, templates, md_out) else { return false; }
    }
    if has_format(cfg, "json") {
        guard emit_spec_json(db, cfg, json_out) else { return false; }
    }
    return write_or_print_output(opts, cfg, md_out[..], json_out[..]);
}

fn run_pipeline(
    db:         CompilerDb&,
    cfg:        Config&,
    intrinsics: IntrinsicTable&,
    templates:  TemplateTable&,
    opts:       const CliOptions&,
) -> i64 {
    var target_slices: const u8[:][>..] = [];
    guard collect_target_slices(opts, target_slices) else { return 2; }
    let root_dir = infer_root_dir(opts);
    guard resolve_import_graph(db, cfg, root_dir, target_slices[..]) else { return 2; }
    guard run_sema_passes(db, cfg, intrinsics) else { return 2; }

    var diag_out: u8[>..] = [];
    if opts.cmd[..] == "check" {
        emit_check_symbols(db, diag_out);
        emit_check_ast_items(db, intrinsics, diag_out);
        let v = count_strict_violations(db, opts.diag_mode[..], diag_out);
        write_stdout(diag_out[..]);
        return if cfg.strict && v > 0 { 1 } else { 0 };
    }

    guard emit_compile_outputs(db, cfg, templates, opts) else { return 2; }
    let strict_v = count_strict_violations(db, opts.diag_mode[..], diag_out);
    return if opts.has_strict && strict_v > 0 { 1 } else { 0 };
}

fn execute_with_opts(opts: const CliOptions&) -> i64 {
    if opts.cmd[..] == "version" {
        write_stdout("goose2rfc 0.1.0\n");
        return 0;
    }
    var cfg = default_config();
    guard apply_cli_overrides(opts, cfg) else { return 2; }

    var intrinsics = IntrinsicTable { .. };
    var templates = TemplateTable { .. };
    guard load_default_intrinsics(intrinsics) && load_default_templates(templates) else { return 2; }

    var files:     SourceFile[>..]    = [];
    var text:      u8[>..]            = [];
    var tokens:    Token[>..]         = [];
    var nodes:     AstNode[>..]       = [];
    var symbols:   Symbol[>..]        = [];
    var wire_ops:  WireOp[>..]        = [];
    var guards:    GuardRule[>..]     = [];
    var unchecked: UncheckedItem[>..] = [];
    var effects:   ParamEffect[>..]   = [];
    var fsm_rows:  FsmRow[>..]        = [];
    var specs:     SpecFunction[>..]  = [];
    var sym_index = dictionary<u64, i32> {};
    var work: i32[>..<] = [];

    var db = CompilerDb {
        files:     files,
        text:      text,
        tokens:    tokens,
        nodes:     nodes,
        symbols:   symbols,
        wire_ops:  wire_ops,
        guards:    guards,
        unchecked: unchecked,
        effects:   effects,
        fsm_rows:  fsm_rows,
        specs:     specs,
        sym_index: sym_index,
        work:      work,
    };
    return run_pipeline(db, cfg, intrinsics, templates, opts);
}

fn run_cli() -> i64 {
    let n = arg_count();
    var arg_pool:  u8[..256][..32]  = [];
    var arg_views: const u8[:][>..] = [];
    var buf:       u8[>..]          = [];
    for i in n {
        guard arg_pool.len < arg_pool.cap else { break; }
        buf.clear();
        arg(i, buf);
        var item: u8[..256] = [];
        copy_bounded_str(item, buf[..]);
        arg_pool.push(item);
    }
    for &item in arg_pool {
        arg_views.push(item[..]);
    }
    var opts = CliOptions { .. };
    guard parse_cli_args(arg_views[..], opts) else {
        write_stderr("usage: goose2rfc <compile|check|--version> [options] <files...>\n");
        return 2;
    }
    return execute_with_opts(opts);
}

fn main() {
    let code = run_cli();
    if code != 0 {
        exit(code);
    }
}
