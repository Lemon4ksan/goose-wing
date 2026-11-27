// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Cookie persistence, SQLite schema generation, batching, and file formats
// (RFC 6265bis Section 5.4, Netscape cookies.txt).
namespace cookie;

import std;
import core;
import json;
import .constants;
import .limits;
import .canonical;
import .psl;
import .engine;

// ---- chromium sqlite v24 query generator -----------------------------------

// Serializes a CanonicalCookie into a SQLite V24 INSERT OR REPLACE statement.
// Rejects NUL bytes in string fields without mutating `out`.
fn generate_sqlite_insert_sql<B>(cookie_val: const CanonicalCookie&, out: B&) -> bool {
    guard cookie_internal::has_valid_sqlite_cookie_fields(cookie_val) else { return false; }
    out.append("INSERT OR REPLACE INTO cookies (creation_utc, top_frame_site_key, host_key, name, ");
    out.append("value, encrypted_value, path, expires_utc, is_secure, is_httponly, ");
    out.append("last_access_utc, has_expires, is_persistent, priority, samesite, source_scheme, ");
    out.append("source_port, last_update_utc, source_type, has_cross_site_ancestor) VALUES (");
    cookie_val.creation_utc.format_i64_dec(out);
    out.append(", ");
    let _ = cookie_internal::append_sql_escaped_string(cookie_val.partition_key[..], out);
    out.append(", ");
    let _ = cookie_internal::append_sqlite_host_key(cookie_val, out);
    out.append(", ");
    let _ = cookie_internal::append_sql_escaped_string(cookie_val.name[..], out);
    out.append(", ");
    let _ = cookie_internal::append_sql_escaped_string(cookie_val.value[..], out);
    out.append(", '', ");
    let _ = cookie_internal::append_sql_escaped_string(cookie_val.path[..], out);
    out.append(", ");
    cookie_val.expires_utc.format_i64_dec(out);
    cookie_internal::append_sqlite_insert_tail(cookie_val, out);
    return true;
}

// Serializes a CanonicalCookie deletion into a SQLite V24 DELETE statement.
// Rejects NUL bytes in string fields without mutating `out`.
fn generate_sqlite_delete_sql<B>(cookie_val: const CanonicalCookie&, out: B&) -> bool {
    guard cookie_internal::has_valid_sqlite_cookie_fields(cookie_val) else { return false; }
    out.append("DELETE FROM cookies WHERE top_frame_site_key = ");
    let _ = cookie_internal::append_sql_escaped_string(cookie_val.partition_key[..], out);
    out.append(" AND host_key = ");
    let _ = cookie_internal::append_sqlite_host_key(cookie_val, out);
    out.append(" AND name = ");
    let _ = cookie_internal::append_sql_escaped_string(cookie_val.name[..], out);
    out.append(" AND path = ");
    let _ = cookie_internal::append_sql_escaped_string(cookie_val.path[..], out);
    out.append(" AND source_scheme = ");
    cookie_internal::source_scheme_sqlite_code(cookie_val.source_scheme).format_i64_dec(out);
    out.append(" AND source_port = ");
    (cookie_val.source_port as i64).format_i64_dec(out);
    out.append(";\n");
    return true;
}

// ---- write-back mutation batcher -------------------------------------------

enum StoreOpType {
    InsertOrUpdate,
    Delete,
}

struct PendingStoreOp {
    op_type: StoreOpType     = StoreOpType.InsertOrUpdate,
    cookie:  CanonicalCookie = CanonicalCookie { .. },
}

// Asynchronous mutation batcher with queue coalescing and commit thresholds.
struct WriteBackBatcher {
    max_batch_size:      i64 = cookie_internal::K_COMMIT_AFTER_BATCH_SIZE, // 512
    commit_interval_ms:  i64 = cookie_internal::K_COMMIT_INTERVAL_MS,      // 30000
    last_commit_ms:      i64 = 0,
    total_committed_ops: i64 = 0,
    total_coalesced_ops: i64 = 0,

    // Fixed-capacity queue to avoid heap allocations.
    ops: PendingStoreOp[..256] = [],
}

// Constructs a WriteBackBatcher initialized at now_ms.
fn new_write_back_batcher(now_ms: i64 = 0) -> WriteBackBatcher {
    return WriteBackBatcher {
        max_batch_size:      cookie_internal::K_COMMIT_AFTER_BATCH_SIZE,
        commit_interval_ms:  cookie_internal::K_COMMIT_INTERVAL_MS,
        last_commit_ms:      now_ms,
        total_committed_ops: 0,
        total_coalesced_ops: 0,
        ops:                 [],
    };
}

fn cookie_internal::queue_store_mutation(
    batcher:        cookie::WriteBackBatcher&,
    operation_type: cookie::StoreOpType,
    cookie_val:     const cookie::CanonicalCookie&,
) -> bool {
    for op_idx in batcher.ops.len {
        if cookie_internal::are_cookies_store_identical(batcher.ops[op_idx].cookie, cookie_val)
            && cookie_internal::coalesce_store_mutation(batcher, op_idx, operation_type, cookie_val) {
            return true;
        }
    }

    var pending = cookie::PendingStoreOp { op_type: operation_type, cookie: cookie_val };
    return batcher.ops.try_push(pending);
}

// Enqueues a cookie insert or update into batcher, coalescing duplicate keys.
fn queue_insert(batcher: WriteBackBatcher&, cookie_val: const CanonicalCookie&) -> bool {
    return cookie_internal::queue_store_mutation(batcher, StoreOpType.InsertOrUpdate, cookie_val);
}

// Enqueues a cookie delete into batcher, coalescing with queued mutations.
fn queue_delete(batcher: WriteBackBatcher&, cookie_val: const CanonicalCookie&) -> bool {
    return cookie_internal::queue_store_mutation(batcher, StoreOpType.Delete, cookie_val);
}

// ---- outgoing header value formatting & ingestion --------------------------

const cookie_internal::MAX_COOKIE_HEADER_LEN: i64 = 8192;

fn cookie_internal::try_append_cookie_pair<B>(
    out:        B&,
    cookie_val: const cookie::CanonicalCookie&,
    with_delim: bool,
) -> bool {
    guard cookie_val.name.len > 0 || cookie_val.value.len > 0 else {
        return true;
    }
    let delim_len: i64 = if with_delim { 2 } else { 0 };
    let eq_len:    i64 = if cookie_val.name.len > 0 { 1 } else { 0 };
    let pair_len = core::add_sat_i64(cookie_val.name.len, core::add_sat_i64(eq_len, cookie_val.value.len));
    let needed = core::add_sat_i64(delim_len, pair_len);
    guard core::add_sat_i64(out.len, needed) <= cookie_internal::MAX_COOKIE_HEADER_LEN else {
        return false;
    }

    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };

    if with_delim {
        guard out.try_append("; ") else { return false; }
    }
    if cookie_val.name.len > 0 {
        guard out.try_append(cookie_val.name[..]) && out.try_push('=' as u8) else { return false; }
    }
    guard out.try_append(cookie_val.value[..]) else { return false; }
    committed = true;
    return true;
}

fn cookie_internal::format_cookie_header_from_indices<B>(
    jar:     const cookie::CanonicalCookieJar&,
    indices: const u16[:],
    out:     B&,
) {
    for i in indices.len {
        let idx = indices[i] as i64;
        guard idx >= 0 && idx < jar.cookies.len else { continue; }
        guard cookie_internal::try_append_cookie_pair(out, jar.cookies[idx], out.len > 0) else {
            return;
        }
    }
}

// Formats cookies into an outgoing HTTP Cookie header value per RFC 6265 Section 5.4.
// Stops cleanly before exceeding the 8192-byte limit or buffer capacity.
fn format_cookie_header_value<B>(cookies: const CanonicalCookie[:], out: B&) {
    for &cookie_val in cookies {
        guard cookie_internal::try_append_cookie_pair(out, cookie_val, out.len > 0) else {
            return;
        }
    }
}

// Parses an incoming Cookie header on the server side into distinct name-value pairs.
// Preserves the first occurrence on duplicate names (RFC 6265bis Section 5.4) and caps at max_cookies.
//
// Example:
//   raw_header = "a=1; b=2", now_us = 1000
//   appends: CanonicalCookie{name="a", value="1"}, CanonicalCookie{name="b", value="2"}
fn parse_server_cookie_header<C>(
    raw_header:  const u8[:],
    now_us:      i64,
    out:         C&,
    max_cookies: i64 = 100,
) {
    guard raw_header.len > 0 else { return; }

    var tok = core::make_byte_tokenizer(raw_header, ';');
    loop {
        let pair_slice, ok = core::token_next(tok);
        guard ok && out.len < max_cookies else { break; }
        cookie_internal::parse_single_server_cookie_pair(pair_slice, now_us, out);
    }
}

// Parses an incoming Cookie header on the server side with default now_us = 0.
//
// Example:
//   raw_header = "session=xyz"
//   appends: CanonicalCookie{name="session", value="xyz"}
fn parse_server_cookie_header<C>(
    raw_header:  const u8[:],
    out:         C&,
    max_cookies: i64 = 100,
) {
    parse_server_cookie_header(raw_header, 0, out, max_cookies);
}

// Parses an incoming Cookie header into a growable array of CanonicalCookie.
//
// Example:
//   raw_header = "sid=xyz"
//   returns: [CanonicalCookie{name="sid", value="xyz"}]
fn parse_server_cookie_header(raw_header: const u8[:]) -> CanonicalCookie[>..] {
    var out: CanonicalCookie[>..] = [];
    parse_server_cookie_header(raw_header, 0, out);
    return out;
}

// Returns the value of the first cookie matching name, or "" if absent.
fn get_server_cookie(cookies: const CanonicalCookie[:], name: const u8[:]) -> const u8[:] {
    for &cookie_val in cookies {
        if cookie_val.name[..] == name {
            return cookie_val.value[..];
        }
    }
    return "";
}

// ---- netscape cookies.txt format interop -----------------------------------

// Exports cookies formatted as a standard Netscape cookies.txt file.
fn export_netscape<B>(jar: const CanonicalCookieJar&, out: B&) {
    out.append("# Netscape HTTP Cookie File\n");
    out.append("# https://curl.se/docs/http-cookies.html\n");
    out.append("# This file was generated by goose-wing CanonicalCookieJar\n\n");

    for &cookie_val in jar.cookies {
        if cookie_val.httponly {
            out.append("#HttpOnly_");
        }
        out.append(cookie_val.domain[..]);
        out.push('\t');
        out.append(if !cookie_val.host_only { "TRUE" } else { "FALSE" });
        out.push('\t');
        out.append(cookie_val.path[..]);
        out.push('\t');
        out.append(if cookie_val.secure { "TRUE" } else { "FALSE" });
        out.push('\t');
        let expires_sec = if cookie_val.persistent { cookie_val.expires_utc / 1000000 } else { 0 as i64 };
        expires_sec.format_i64_dec(out);
        out.push('\t');
        out.append(cookie_val.name[..]);
        out.push('\t');
        out.append(cookie_val.value[..]);
        out.push('\n');
    }
}

inline fn cookie_internal::is_netscape_eol(b: u8) -> bool {
    return b == '\n' || b == '\r';
}

// Finds the exclusive line end and the start of the following line after EOL bytes.
//
// Example:
//   content = "a\r\nb", start = 0 -> returns: line_end = 1, next_start = 3
fn cookie_internal::find_netscape_line_range(content: const u8[:], start: i64) -> i64, i64 {
    var line_end = start;
    while line_end < content.len && !cookie_internal::is_netscape_eol(content[line_end]) {
        line_end = core::add_sat_i64(line_end, 1);
    }
    var next_start = line_end;
    while next_start < content.len && cookie_internal::is_netscape_eol(content[next_start]) {
        next_start = core::add_sat_i64(next_start, 1);
    }
    return line_end, next_start;
}

inline fn cookie_internal::try_import_netscape_cookie(
    jar:      cookie::CanonicalCookieJar&,
    raw_line: const u8[:],
    now_us:   i64,
) -> bool {
    var parsed_cookie, ok = cookie::try_parse_netscape_cookie_line(raw_line);
    guard ok else { return false; }
    let src_opts = cookie::SourceOptions { is_http_api: true, url_is_secure: parsed_cookie.secure };
    return jar.set_canonical_cookie(parsed_cookie, src_opts, now_us);
}

// Imports cookies from Netscape cookies.txt format into CanonicalCookieJar.
fn import_netscape(jar: CanonicalCookieJar&, content: const u8[:], now_us: i64) -> i64 {
    guard content.len > 0 else { return 0; }

    var imported_count: i64 = 0;
    var line_start:     i64 = 0;

    while line_start < content.len {
        guard imported_count < cookie_internal::K_MAX_COOKIES else { break; }

        let line_end, next_start = cookie_internal::find_netscape_line_range(content, line_start);
        if cookie_internal::try_import_netscape_cookie(jar, content[line_start..line_end], now_us) {
            imported_count = core::add_sat_i64(imported_count, 1);
        }

        line_start = next_start;
    }

    return imported_count;
}

// Parses a single line from Netscape cookies.txt format into a CanonicalCookie.
// Rejects control characters, public suffixes, and payloads exceeding 4096 bytes.
//
// Example:
//   raw_line = ".example.com\tTRUE\t/\tTRUE\t2147483647\tsid\tabc"
//   returns: CanonicalCookie{domain=".example.com", name="sid", value="abc"}, ok = true
fn try_parse_netscape_cookie_line(raw_line: const u8[:]) -> CanonicalCookie, bool {
    var result = CanonicalCookie { .. };
    var line = raw_line;
    guard line.len > 0 else { return result, false; }
    if cookie_internal::has_prohibited_ctl(line) { return result, false; }

    var is_httponly = false;
    let stripped, has_http_only = line.strip_prefix("#HttpOnly_");
    if has_http_only {
        is_httponly = true;
        line = stripped;
    }
    guard line.len > 0 && line[0] != '#' else { return result, false; }

    var tab_positions: i64[..8] = [];
    for char_idx in line.len {
        if line[char_idx] == '\t' {
            guard tab_positions.try_push(char_idx) else { return result, false; }
        }
    }
    guard tab_positions.len >= 6 else { return result, false; }

    let d_part = line[..tab_positions[0]];
    let subdom_part = line[core::add_sat_i64(tab_positions[0], 1)..tab_positions[1]];
    let p_part = line[core::add_sat_i64(tab_positions[1], 1)..tab_positions[2]];
    let sec_part = line[core::add_sat_i64(tab_positions[2], 1)..tab_positions[3]];
    let exp_part = line[core::add_sat_i64(tab_positions[3], 1)..tab_positions[4]];
    let n_part = line[core::add_sat_i64(tab_positions[4], 1)..tab_positions[5]];
    let v_part = line[core::add_sat_i64(tab_positions[5], 1)..];

    let clean_dom = if d_part.len > 0 && d_part[0] == '.' { d_part[1..] } else { d_part };
    guard clean_dom.len > 0 && clean_dom[0] != '.' && cookie_internal::is_valid_domain_attr(clean_dom) else {
        return result, false;
    }
    guard cookie_internal::is_valid_cookie_name(n_part) && cookie_internal::is_valid_cookie_val(v_part) else {
        return result, false;
    }
    guard core::add_sat_i64(n_part.len, v_part.len) <= cookie_internal::K_MAX_COOKIE_NAME_VAL_LEN else {
        return result, false;
    }

    guard result.domain.try_set(d_part)
        && result.path.try_set(p_part)
        && result.name.try_set(n_part)
        && result.value.try_set(v_part) else {
        return CanonicalCookie { .. }, false;
    }

    cookie_internal::populate_netscape_cookie_fields(
        result, subdom_part, p_part, sec_part, exp_part, is_httponly,
    );
    core::make_ascii_lowercase(result.domain[..]);

    let psl_check_dom = if result.domain.len > 0 && result.domain[0] == '.' {
        result.domain[1..]
    } else {
        result.domain[..]
    };
    if !result.host_only && is_public_suffix_domain(psl_check_dom) {
        return CanonicalCookie { .. }, false;
    }
    return result, true;
}

// ---- structured chromium v24 json interop ----------------------------------

inline fn cookie_internal::append_json_bool_field<B>(out: B&, key: const u8[:], val: bool) {
    core::format_json_key(out, key);
    out.append(if val { "true" } else { "false" });
    out.push(',');
}

inline fn cookie_internal::append_json_str_field<B>(out: B&, key: const u8[:], val: const u8[:]) {
    core::format_json_key(out, key);
    core::format_json_string(out, val);
    out.push(',');
}

inline fn cookie_internal::append_json_i64_field<B>(out: B&, key: const u8[:], val: i64) {
    core::format_json_key(out, key);
    val.format_i64_dec(out);
    out.push(',');
}

fn cookie_internal::format_json_cookie_object<B>(cookie_val: const cookie::CanonicalCookie&, out: B&) {
    out.push('{');
    cookie_internal::append_json_str_field(out, "name", cookie_val.name[..]);
    cookie_internal::append_json_str_field(out, "value", cookie_val.value[..]);
    cookie_internal::append_json_str_field(out, "domain", cookie_val.domain[..]);
    cookie_internal::append_json_str_field(out, "path", cookie_val.path[..]);
    cookie_internal::append_json_i64_field(out, "creation_utc", cookie_val.creation_utc);
    cookie_internal::append_json_i64_field(out, "last_access_utc", cookie_val.last_access_utc);
    cookie_internal::append_json_i64_field(out, "last_update_utc", cookie_val.last_update_utc);
    cookie_internal::append_json_i64_field(out, "expires_utc", cookie_val.expires_utc);
    cookie_internal::append_json_bool_field(out, "host_only", cookie_val.host_only);
    cookie_internal::append_json_bool_field(out, "has_path_attr", cookie_val.has_path_attr);
    cookie_internal::append_json_bool_field(out, "has_domain_attr", cookie_val.has_domain_attr);
    cookie_internal::append_json_bool_field(out, "persistent", cookie_val.persistent);
    cookie_internal::append_json_bool_field(out, "secure", cookie_val.secure);
    cookie_internal::append_json_bool_field(out, "httponly", cookie_val.httponly);
    cookie_internal::append_json_bool_field(out, "partitioned", cookie_val.partitioned);
    cookie_internal::append_json_str_field(out, "partition_key", cookie_val.partition_key[..]);
    cookie_internal::append_json_str_field(
        out, "same_site", cookie_internal::same_site_to_string(cookie_val.same_site),
    );
    cookie_internal::append_json_str_field(
        out, "priority", cookie_internal::priority_to_string(cookie_val.priority),
    );
    cookie_internal::append_json_str_field(
        out, "source_scheme", cookie_internal::source_scheme_to_string(cookie_val.source_scheme),
    );
    core::format_json_key(out, "source_port");
    (cookie_val.source_port as i64).format_i64_dec(out);
    out.push('}');
}

// Exports the CanonicalCookieJar to structured Chromium V24 JSON format.
fn export_json<B>(jar: const CanonicalCookieJar&, out: B&) {
    out.push('[');
    var first = true;
    for &cookie_val in jar.cookies {
        if !first { out.push(','); }
        first = false;
        cookie_internal::format_json_cookie_object(cookie_val, out);
    }
    out.push(']');
}

// Imports cookies from structured Chromium V24 JSON into CanonicalCookieJar.
fn import_json(jar: CanonicalCookieJar&, json_text: const u8[:], now_us: i64) -> i64 {
    guard json_text.len > 0 else { return 0; }
    var json_reader = json::reader(json_text);
    var imported_count: i64 = 0;

    json::each_element(json_reader) {
        guard imported_count < cookie_internal::K_MAX_COOKIES else { return imported_count; }
        var parsed_cookie = CanonicalCookie { .. };
        let read_ok = cookie_internal::read_canonical_cookie_json_object(json_reader, parsed_cookie);

        let has_ctl = cookie_internal::has_prohibited_ctl(parsed_cookie.name[..])
            || cookie_internal::has_prohibited_ctl(parsed_cookie.value[..])
            || cookie_internal::has_prohibited_ctl(parsed_cookie.path[..]);
        let has_payload = parsed_cookie.name.len > 0 || parsed_cookie.value.len > 0;
        let both_encrypted_and_plain = parsed_cookie.value.len > 0 && parsed_cookie.encrypted_value.len > 0;

        let is_valid = read_ok && !has_ctl && has_payload && !both_encrypted_and_plain;
        let src_opts = SourceOptions { is_http_api: true, url_is_secure: parsed_cookie.secure };
        if is_valid && jar.set_canonical_cookie(parsed_cookie, src_opts, now_us) {
            imported_count = core::add_sat_i64(imported_count, 1);
        }
    };

    return imported_count;
}

// ---- internal implementation helpers ---------------------------------------

fn cookie_internal::same_site_sqlite_code(same_site: cookie::SameSite) -> i64 {
    return match same_site {
        Lax => 1,
        Strict => 2,
        None => 3,
        _ => 0,
    };
}

fn cookie_internal::source_scheme_sqlite_code(scheme: cookie::SourceScheme) -> i64 {
    return match scheme {
        Unset => 0,
        NonSecure => 1,
        Secure => 2,
        Unknown => 0,
    };
}

fn cookie_internal::append_sqlite_insert_tail<B>(
    cookie_val: const cookie::CanonicalCookie&,
    out:        B&,
) {
    out.append(", ");
    let sec_flag: i64 = if cookie_val.secure { 1 } else { 0 };
    sec_flag.format_i64_dec(out);
    out.append(", ");
    let http_flag: i64 = if cookie_val.httponly { 1 } else { 0 };
    http_flag.format_i64_dec(out);
    out.append(", ");
    cookie_val.last_access_utc.format_i64_dec(out);
    out.append(", ");
    let persist_flag: i64 = if cookie_val.persistent { 1 } else { 0 };
    persist_flag.format_i64_dec(out);
    out.append(", ");
    persist_flag.format_i64_dec(out);
    out.append(", ");
    (cookie_internal::priority_rank(cookie_val.priority) as i64).format_i64_dec(out);
    out.append(", ");
    cookie_internal::same_site_sqlite_code(cookie_val.same_site).format_i64_dec(out);
    out.append(", ");
    cookie_internal::source_scheme_sqlite_code(cookie_val.source_scheme).format_i64_dec(out);
    out.append(", ");
    (cookie_val.source_port as i64).format_i64_dec(out);
    out.append(", ");
    cookie_val.last_update_utc.format_i64_dec(out);
    out.append(", 0, 0);\n");
}

inline fn cookie_internal::has_valid_sqlite_cookie_fields(c: const cookie::CanonicalCookie&) -> bool {
    return !c.partition_key[..].contains_byte(0) && !c.domain[..].contains_byte(0)
        && !c.name[..].contains_byte(0) && !c.value[..].contains_byte(0) && !c.path[..].contains_byte(0);
}

inline fn cookie_internal::append_sql_escaped_body<B>(sql_str: const u8[:], out: B&) -> bool {
    guard !sql_str.contains_byte(0) else { return false; }
    for char_byte in sql_str {
        if char_byte == '\'' {
            out.append("''");
        } else {
            out.push(char_byte);
        }
    }
    return true;
}

fn cookie_internal::append_sql_escaped_string<B>(sql_str: const u8[:], out: B&) -> bool {
    guard !sql_str.contains_byte(0) else { return false; }
    out.push('\'');
    guard cookie_internal::append_sql_escaped_body(sql_str, out) else { return false; }
    out.push('\'');
    return true;
}

fn cookie_internal::append_sqlite_host_key<B>(
    cookie_val: const cookie::CanonicalCookie&,
    out:        B&,
) -> bool {
    guard !cookie_val.domain[..].contains_byte(0) else { return false; }
    out.push('\'');
    if !cookie_val.host_only && (cookie_val.domain.len == 0 || cookie_val.domain[0] != '.') {
        out.push('.');
    }
    guard cookie_internal::append_sql_escaped_body(cookie_val.domain[..], out) else { return false; }
    out.push('\'');
    return true;
}

fn cookie_internal::coalesce_store_mutation(
    batcher:        cookie::WriteBackBatcher&,
    op_idx:         i64,
    operation_type: cookie::StoreOpType,
    cookie_val:     const cookie::CanonicalCookie&,
) -> bool {
    let existing_op = batcher.ops[op_idx].op_type;
    if existing_op == cookie::StoreOpType.InsertOrUpdate && operation_type == cookie::StoreOpType.InsertOrUpdate {
        let orig_creation = batcher.ops[op_idx].cookie.creation_utc;
        let orig_seq = batcher.ops[op_idx].cookie.creation_seq;
        batcher.ops[op_idx].cookie = cookie_val;
        batcher.ops[op_idx].cookie.creation_utc = orig_creation;
        batcher.ops[op_idx].cookie.creation_seq = orig_seq;
        batcher.total_coalesced_ops = core::add_sat_i64(batcher.total_coalesced_ops, 1);
        return true;
    }
    if existing_op == cookie::StoreOpType.InsertOrUpdate && operation_type == cookie::StoreOpType.Delete {
        remove_at(batcher.ops, op_idx);
        batcher.total_coalesced_ops = core::add_sat_i64(batcher.total_coalesced_ops, 1);
        return true;
    }
    if existing_op == cookie::StoreOpType.Delete && operation_type == cookie::StoreOpType.InsertOrUpdate {
        batcher.ops[op_idx].op_type = cookie::StoreOpType.InsertOrUpdate;
        batcher.ops[op_idx].cookie = cookie_val;
        batcher.total_coalesced_ops = core::add_sat_i64(batcher.total_coalesced_ops, 1);
        return true;
    }
    if existing_op == cookie::StoreOpType.Delete && operation_type == cookie::StoreOpType.Delete {
        batcher.total_coalesced_ops = core::add_sat_i64(batcher.total_coalesced_ops, 1);
        return true;
    }
    return false;
}

fn cookie_internal::are_cookies_store_identical(
    cookie_a: const cookie::CanonicalCookie&,
    cookie_b: const cookie::CanonicalCookie&,
) -> bool {
    if cookie_a.name[..] != cookie_b.name[..] { return false; }
    if cookie_a.host_only != cookie_b.host_only { return false; }
    if cookie_a.path[..] != cookie_b.path[..] { return false; }
    if cookie_a.partition_key[..] != cookie_b.partition_key[..] { return false; }

    let port_match = cookie_a.source_port == -1 || cookie_b.source_port == -1
        || cookie_a.source_port == cookie_b.source_port;
    let scheme_match = cookie_a.source_scheme == cookie::SourceScheme.Unset
        || cookie_b.source_scheme == cookie::SourceScheme.Unset
        || cookie_a.source_scheme == cookie_b.source_scheme;
    if !port_match || !scheme_match { return false; }

    let clean_dom_a = cookie_a.domain[..].trim_byte('.');
    let clean_dom_b = cookie_b.domain[..].trim_byte('.');
    return clean_dom_a.eq_ascii_fold(clean_dom_b);
}

// Parses a single name=value cookie pair into out if valid and not already present.
//
// Example:
//   pair_slice = "user=alice", now_us = 1000
//   appends: CanonicalCookie{name="user", value="alice"}
fn cookie_internal::parse_single_server_cookie_pair<C>(
    pair_slice: const u8[:],
    now_us:     i64,
    out:        C&,
) {
    if cookie_internal::has_prohibited_ctl(pair_slice) { return; }
    let clean_pair = pair_slice.trim_lws();
    guard clean_pair.len > 0 else { return; }

    let lhs, rhs, has_eq = clean_pair.split_once_byte('=');
    guard has_eq else { return; }
    let cookie_name = lhs.trim_lws();
    let cookie_val = rhs.trim_lws();
    guard cookie_name.len > 0 else { return; }
    if core::add_sat_i64(cookie_name.len, cookie_val.len) > cookie_internal::K_MAX_COOKIE_NAME_VAL_LEN {
        return;
    }
    guard cookie_internal::is_valid_cookie_name(cookie_name)
        && cookie_internal::is_valid_cookie_val(cookie_val) else {
        return;
    }

    for &existing in out {
        if existing.name[..] == cookie_name {
            return;
        }
    }

    var new_cookie = cookie::CanonicalCookie { .. };
    guard new_cookie.name.try_set(cookie_name) && new_cookie.value.try_set(cookie_val) else { return; }
    new_cookie.creation_utc = now_us;
    new_cookie.last_access_utc = now_us;
    new_cookie.last_update_utc = now_us;
    out.push(new_cookie);
}

fn cookie_internal::populate_netscape_cookie_fields(
    cookie_ref:  cookie::CanonicalCookie&,
    subdom_flag: const u8[:],
    path_val:    const u8[:],
    secure_flag: const u8[:],
    expires_str: const u8[:],
    is_httponly: bool,
) {
    if path_val.len > 0 {
        cookie_ref.has_path_attr = true;
    }
    cookie_ref.has_domain_attr = !subdom_flag.eq_ascii_fold("false");
    cookie_ref.host_only = subdom_flag.eq_ascii_fold("false");
    cookie_ref.secure = secure_flag.eq_ascii_fold("true");
    cookie_ref.httponly = is_httponly;
    cookie_ref.source_scheme = if cookie_ref.secure {
        cookie::SourceScheme.Secure
    } else {
        cookie::SourceScheme.NonSecure
    };
    cookie_ref.source_port = if cookie_ref.secure { 443 } else { 80 };

    let expires_sec, parse_ok = expires_str.parse_i64_dec();
    if parse_ok && expires_sec > 0 {
        let safe_sec = min(expires_sec, 9000000000000);
        cookie_ref.expires_utc = core::mul_sat_i64(safe_sec, 1000000);
        cookie_ref.persistent = true;
    }
}

fn cookie_internal::read_canonical_cookie_json_object(
    json_reader:   json::Reader&,
    parsed_cookie: cookie::CanonicalCookie&,
) -> bool {
    var enum_scratch: u8[..256] = [];
    var ok = true;
    json::each_member(json_reader) { key =>
        cookie_internal::read_json_cookie_member(json_reader, key, parsed_cookie, enum_scratch, ok);
    };
    return ok;
}

fn cookie_internal::read_json_cookie_string_member(
    json_reader:  json::Reader&,
    key:          const u8[:],
    cookie_ref:   cookie::CanonicalCookie&,
    enum_scratch: u8[..256]&,
    ok:           bool&,
) -> bool {
    if key == "name" {
        if !core::read_json_string_into(json_reader, cookie_ref.name) { ok = false; }
        return true;
    }
    if key == "value" {
        if !core::read_json_string_into(json_reader, cookie_ref.value) { ok = false; }
        return true;
    }
    if key == "encrypted_value" {
        if !core::read_json_string_into(json_reader, cookie_ref.encrypted_value) { ok = false; }
        return true;
    }
    if key == "domain" {
        if !core::read_json_string_into(json_reader, cookie_ref.domain) { ok = false; }
        return true;
    }
    if key == "path" {
        if !core::read_json_string_into(json_reader, cookie_ref.path) { ok = false; return true; }
        if cookie_ref.path.len > 0 { cookie_ref.has_path_attr = true; }
        return true;
    }
    if key == "partition_key" {
        if !core::read_json_string_into(json_reader, cookie_ref.partition_key) { ok = false; }
        return true;
    }
    if key == "same_site" {
        guard core::read_json_string_into(json_reader, enum_scratch) else { ok = false; return true; }
        cookie_ref.same_site = if enum_scratch[..].eq_ascii_fold("default") {
            cookie::SameSite.Default
        } else {
            cookie::parse_same_site(enum_scratch[..])
        };
        return true;
    }
    if key == "priority" {
        guard core::read_json_string_into(json_reader, enum_scratch) else { ok = false; return true; }
        cookie_ref.priority = cookie::parse_priority(enum_scratch[..]);
        return true;
    }
    if key == "source_scheme" {
        guard core::read_json_string_into(json_reader, enum_scratch) else { ok = false; return true; }
        cookie_ref.source_scheme = cookie_internal::parse_source_scheme(enum_scratch[..]);
        return true;
    }
    return false;
}

fn cookie_internal::read_json_cookie_scalar_member(
    json_reader: json::Reader&,
    key:         const u8[:],
    cookie_ref:  cookie::CanonicalCookie&,
) -> bool {
    if key == "has_path_attr" { cookie_ref.has_path_attr = json::read_bool(json_reader); return true; }
    if key == "has_domain_attr" { cookie_ref.has_domain_attr = json::read_bool(json_reader); return true; }
    if key == "creation_utc" { cookie_ref.creation_utc = json::read_int(json_reader); return true; }
    if key == "last_access_utc" { cookie_ref.last_access_utc = json::read_int(json_reader); return true; }
    if key == "last_update_utc" { cookie_ref.last_update_utc = json::read_int(json_reader); return true; }
    if key == "expires_utc" { cookie_ref.expires_utc = json::read_int(json_reader); return true; }
    if key == "host_only" { cookie_ref.host_only = json::read_bool(json_reader); return true; }
    if key == "persistent" { cookie_ref.persistent = json::read_bool(json_reader); return true; }
    if key == "secure" { cookie_ref.secure = json::read_bool(json_reader); return true; }
    if key == "httponly" { cookie_ref.httponly = json::read_bool(json_reader); return true; }
    if key == "partitioned" { cookie_ref.partitioned = json::read_bool(json_reader); return true; }
    if key == "source_port" { cookie_ref.source_port = json::read_int(json_reader) as i32; return true; }
    return false;
}

fn cookie_internal::read_json_cookie_member(
    json_reader:  json::Reader&,
    key:          const u8[:],
    cookie_ref:   cookie::CanonicalCookie&,
    enum_scratch: u8[..256]&,
    ok:           bool&,
) {
    if cookie_internal::read_json_cookie_string_member(json_reader, key, cookie_ref, enum_scratch, ok) {
        return;
    }
    if !cookie_internal::read_json_cookie_scalar_member(json_reader, key, cookie_ref) {
        json::skip(json_reader);
    }
}
