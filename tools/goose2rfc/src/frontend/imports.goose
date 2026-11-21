// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Multi-root namespace and import graph resolver with 3-state cycle detection.

import std;
import os;
import db from "../model";
import loader from "../config";
import .lexer;
import .parser;

fn is_stdlib_import(name: const u8[:]) -> bool {
    if name == "std" || name == "os" || name == "json" { return true; }
    return name == "dictionary" || name == "slot_pool" || name == "slice_pool";
}

fn norm_slashes(raw: const u8[:], out: u8[>..]&) {
    out.clear();
    for i in raw.len {
        let b = raw[i];
        out.push(if b == '\\' { '/' } else { b });
    }
}

fn strip_after_marker(s: const u8[:], marker: const u8[:]) -> const u8[:] {
    let idx = slice_find(s, marker);
    guard idx >= 0 && idx <= s.len else { return s; }
    let tail = s[idx..];
    guard marker.len < tail.len else { return s; }
    return tail[marker.len..];
}

fn clean_display_path(raw: const u8[:], root_dir: const u8[:], out: u8[>..]&) {
    var norm: u8[>..] = [];
    norm_slashes(raw, norm);
    var s: const u8[:] = norm[..];
    if slice_starts_with(s, "./") { s = s[2..]; }
    s = strip_after_marker(s, "goose-wing/");
    s = strip_after_marker(s, "goose2rfc/");
    if root_dir.len > 0 && root_dir != "." {
        var rbuf: u8[>..] = [];
        norm_slashes(root_dir, rbuf);
        if slice_starts_with(s, rbuf[..]) && s.len > rbuf.len && s[rbuf.len] == '/' {
            s = s[inc_i64(rbuf.len)..];
        }
    }
    for step in 4 {
        if slice_starts_with(s, "../") {
            s = s[3..];
        } else if slice_starts_with(s, "./") {
            s = s[2..];
        } else {
            break;
        }
    }
    out.clear();
    out.append(s);
}

fn dir_of_path(path: const u8[:]) -> const u8[:] {
    var last_slash: i64 = -1;
    for i in path.len {
        if path[i] == '/' || path[i] == '\\' {
            last_slash = i;
        }
    }
    guard last_slash > 0 && last_slash <= path.len else { return "."; }
    return path[..last_slash];
}

fn parent_of_dir(dir: const u8[:]) -> const u8[:] {
    if dir == "." || dir.len == 0 { return ".."; }
    if slice_ends_with(dir, "/..") || dir == ".." { return "../.."; }
    let parent = dir_of_path(dir);
    return if parent == dir { ".." } else { parent };
}

fn join_path_2(dir: const u8[:], rel: const u8[:], out: u8[>..]&) {
    out.clear();
    if dir.len == 0 || dir == "." {
        norm_slashes(rel, out);
        return;
    }
    norm_slashes(dir, out);
    if out.len > 0 && out[dec_i64(out.len)] != '/' {
        out.push('/');
    }
    var r: u8[>..] = [];
    norm_slashes(rel, r);
    let rs: const u8[:] = if slice_starts_with(r[..], "./") { r[2..] } else { r[..] };
    out.append(rs);
}

fn find_existing_file(db: const CompilerDb&, disp_path: const u8[:], disk_path: const u8[:]) -> i32 {
    for i in db.files.len {
        let fid = i as i32;
        if text_of(db, db.files[fid].path_span) == disp_path {
            return fid;
        }
        if text_of(db, db.files[fid].disk_span) == disk_path {
            return fid;
        }
    }
    return -1;
}

fn load_and_parse_file(
    db:        CompilerDb&,
    root_dir:  const u8[:],
    disk_path: const u8[:],
    is_target: bool,
) -> i32 {
    var disp: u8[>..] = [];
    clean_display_path(disk_path, root_dir, disp);
    let existing = find_existing_file(db, disp[..], disk_path);
    if existing >= 0 {
        if is_target { db.files[existing].is_target = true; }
        return existing;
    }
    let text_start = db.text.len as i32;
    guard read_file(disk_path, db.text) else { return -1; }
    let text_len = sub_i32(db.text.len as i32, text_start);
    let path_sp = put_text(db, disp[..]);
    let disk_sp = put_text(db, disk_path);

    let fid = db.files.len as i32;
    db.files.push(SourceFile {
        path_span:   path_sp,
        disk_span:   disk_sp,
        text_start:  text_start,
        text_len:    text_len,
        is_target:   is_target,
        visit_state: VisitState.Unvisited,
        ..
    });
    tokenize_file(db, fid);
    parse_module(db, fid);
    return fid;
}

fn try_pkg_candidates(base_dir: const u8[:], pkg: const u8[:], out: u8[>..]&) -> bool {
    var rel1: u8[>..] = [];
    rel1.append(pkg);
    rel1.append(".goose");
    join_path_2(base_dir, rel1[..], out);
    if file_exists(out[..]) { return true; }

    var rel2: u8[>..] = [];
    rel2.append(pkg);
    rel2.push('/');
    rel2.append(pkg);
    rel2.append(".goose");
    join_path_2(base_dir, rel2[..], out);
    return file_exists(out[..]);
}

fn dotted_to_slash(dotted: const u8[:], slash_out: u8[>..]&, last_out: u8[>..]&) {
    slash_out.clear();
    last_out.clear();
    var last_dot: i64 = -1;
    for i in dotted.len {
        let b = dotted[i];
        if b == '.' {
            slash_out.push('/');
            last_dot = i;
        } else {
            slash_out.push(b);
        }
    }
    let tail_start = inc_i64(last_dot);
    if tail_start >= 0 && tail_start <= dotted.len {
        last_out.append(dotted[tail_start..]);
    }
}

fn try_dotted_in_base(base_dir: const u8[:], slash_rel: const u8[:], last_seg: const u8[:], out: u8[>..]&) -> bool {
    var c1: u8[>..] = [];
    c1.append(slash_rel);
    c1.append(".goose");
    join_path_2(base_dir, c1[..], out);
    if file_exists(out[..]) { return true; }

    var c2: u8[>..] = [];
    c2.append(slash_rel);
    c2.push('/');
    c2.append(last_seg);
    c2.append(".goose");
    join_path_2(base_dir, c2[..], out);
    if file_exists(out[..]) { return true; }

    var c3: u8[>..] = [];
    c3.append(slash_rel);
    c3.append("/mod.goose");
    join_path_2(base_dir, c3[..], out);
    return file_exists(out[..]);
}

fn resolve_import_disk_path(
    cur_dir:   const u8[:],
    root_dir:  const u8[:],
    imp_text:  const u8[:],
    from_text: const u8[:],
    out:       u8[>..]&,
) -> bool {
    if from_text.len > 0 {
        let base = if from_text == "." {
            cur_dir
        } else if from_text == ".." {
            parent_of_dir(cur_dir)
        } else {
            from_text
        };
        if try_pkg_candidates(base, imp_text, out) { return true; }
        return try_pkg_candidates(root_dir, imp_text, out);
    }
    if slice_starts_with(imp_text, ".") {
        let sib = imp_text[1..];
        return try_pkg_candidates(cur_dir, sib, out);
    }
    var slash_rel: u8[>..] = [];
    var last_seg:  u8[>..] = [];
    dotted_to_slash(imp_text, slash_rel, last_seg);
    if try_dotted_in_base(cur_dir, slash_rel[..], last_seg[..], out) { return true; }
    if try_dotted_in_base(root_dir, slash_rel[..], last_seg[..], out) { return true; }
    return try_dotted_in_base("../..", slash_rel[..], last_seg[..], out);
}

fn target_pkg_matches_import(db: const CompilerDb&, imp_text: const u8[:]) -> bool {
    for i in db.files.len {
        if db.files[i].is_target {
            let t_disp = text_of(db, db.files[i].path_span);
            let pkg, _, has_slash = split_at_str(t_disp, "/");
            if has_slash && pkg.len > 0 {
                if imp_text == pkg {
                    return true;
                }
                if slice_starts_with(imp_text, pkg) && imp_text.len > pkg.len && imp_text[pkg.len] == '.' {
                    return true;
                }
            }
        }
    }
    return false;
}

fn should_follow_import(
    db:         const CompilerDb&,
    cfg:        const Config&,
    parent_fid: i32,
    imp_text:   const u8[:],
) -> bool {
    if is_stdlib_import(imp_text) { return false; }
    if db.files[parent_fid].is_target { return true; }
    if slice_starts_with(imp_text, "rfc.") || imp_text == "rfc" || imp_text == "core" { return true; }
    if slice_starts_with(imp_text, "core.") || slice_starts_with(imp_text, ".") { return true; }
    let p_disp = text_of(db, db.files[parent_fid].path_span);
    if slice_starts_with(p_disp, "core/") || slice_starts_with(p_disp, "rfc/") { return true; }
    if p_disp == "wing.goose" || p_disp == "core.goose" {
        return target_pkg_matches_import(db, imp_text);
    }
    if target_pkg_matches_import(db, imp_text) { return true; }
    for i in db.files.len {
        if db.files[i].is_target {
            return false;
        }
    }
    for j in cfg.include.len {
        let pat = cfg.include[j][..];
        if pat.len > 0 && glob_match(pat, imp_text) {
            return true;
        }
    }
    return false;
}

fn resolve_and_load_dep(
    db:       CompilerDb&,
    cfg:      const Config&,
    root_dir: const u8[:],
    file_id:  i32,
    child:    i32,
) -> i32 {
    let imp_text = trim_ascii_ws(text_of(db, db.nodes[child].span));
    let from_text = trim_ascii_ws(text_of(db, db.nodes[child].aux_span));
    guard should_follow_import(db, cfg, file_id, imp_text) else { return -1; }
    let disk_str = text_of(db, db.files[file_id].disk_span);
    var cur_dir_buf: u8[>..] = [];
    cur_dir_buf.append(dir_of_path(disk_str));
    var cand: u8[>..] = [];
    guard resolve_import_disk_path(cur_dir_buf[..], root_dir, imp_text, from_text, cand) else {
        return -1;
    }
    return load_and_parse_file(db, root_dir, cand[..], false);
}

recursive fn handle_import_child(
    db:       CompilerDb&,
    cfg:      const Config&,
    root_dir: const u8[:],
    file_id:  i32,
    mod_id:   i32,
    child:    i32,
) {
    let dep_id = resolve_and_load_dep(db, cfg, root_dir, file_id, child);
    guard dep_id >= 0 && dep_id < db.files.len else { return; }
    if db.files[dep_id].visit_state == VisitState.Active {
        let haz = new_node(db, AstKind.UnresolvedHazard, db.nodes[child].span);
        db.nodes[haz].aux_span = put_text(db, "circular import cycle detected");
        append_child(db, mod_id, haz);
    } else if db.files[dep_id].visit_state == VisitState.Unvisited {
        visit_file_imports(db, cfg, root_dir, dep_id);
    }
}

recursive fn visit_file_imports(
    db:       CompilerDb&,
    cfg:      const Config&,
    root_dir: const u8[:],
    file_id:  i32,
) {
    guard file_id >= 0 && file_id < db.files.len else { return; }
    guard db.files[file_id].visit_state == VisitState.Unvisited else { return; }
    db.files[file_id].visit_state = VisitState.Active;

    let mod_id = db.files[file_id].root_node;
    var child = if mod_id >= 0 && mod_id < db.nodes.len { db.nodes[mod_id].first } else { -1 };
    let max_nodes = db.nodes.len;
    for step in max_nodes {
        guard child >= 0 && child < db.nodes.len else { break; }
        let next_child = db.nodes[child].next;
        if db.nodes[child].kind == AstKind.Import {
            handle_import_child(db, cfg, root_dir, file_id, mod_id, child);
        }
        child = next_child;
    }
    db.files[file_id].visit_state = VisitState.Done;
}

fn locate_seed_path(root_dir: const u8[:], raw_path: const u8[:], out: u8[>..]&) -> bool {
    norm_slashes(raw_path, out);
    if file_exists(out[..]) { return true; }
    if root_dir.len > 0 && root_dir != "." {
        join_path_2(root_dir, raw_path, out);
        if file_exists(out[..]) { return true; }
    }
    join_path_2("../..", raw_path, out);
    return file_exists(out[..]);
}

fn preload_target_pkg_aggregators(db: CompilerDb&, root_dir: const u8[:], t_disk: const u8[:]) {
    let cur_dir = dir_of_path(t_disk);
    if cur_dir.len > 0 && cur_dir != "." {
        var dir_mod: u8[>..] = [];
        dir_mod.append(cur_dir);
        dir_mod.append(".goose");
        if file_exists(dir_mod[..]) {
            load_and_parse_file(db, root_dir, dir_mod[..], false);
        }
    }
    var wing_root: u8[>..] = [];
    join_path_2(root_dir, "wing.goose", wing_root);
    if file_exists(wing_root[..]) {
        load_and_parse_file(db, root_dir, wing_root[..], false);
    }
}

fn resolve_import_graph(
    db:       CompilerDb&,
    cfg:      Config&,
    root_dir: const u8[:],
    targets:  const u8[:][:],
) -> bool {
    for t_idx in targets.len {
        let t_raw = targets[t_idx];
        var t_disk: u8[>..] = [];
        guard locate_seed_path(root_dir, t_raw, t_disk) else { return false; }
        let fid = load_and_parse_file(db, root_dir, t_disk[..], true);
        guard fid >= 0 else { return false; }
        preload_target_pkg_aggregators(db, root_dir, t_disk[..]);
    }
    for r_idx in cfg.roots.len {
        let r_raw = cfg.roots[r_idx][..];
        if r_raw.len > 0 {
            var r_disk: u8[>..] = [];
            if locate_seed_path(root_dir, r_raw, r_disk) {
                load_and_parse_file(db, root_dir, r_disk[..], false);
            }
        }
    }
    let initial_count = db.files.len;
    for i in initial_count {
        visit_file_imports(db, cfg, root_dir, i as i32);
    }
    return true;
}

fn resolve_import_graph(db: CompilerDb&, cfg: Config&, root_dir: const u8[:]) -> bool {
    var empty: const u8[:][..1] = [];
    return resolve_import_graph(db, cfg, root_dir, empty[..]);
}
