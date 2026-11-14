// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Cookie persistence, SQLite schema generation, batching, and file formats
// (RFC 6265bis Section 5.4, Netscape cookies.txt).
namespace wing;

import std;
import core from "..";
import json;
import .constants;
import .limits;
import .canonical;
import .psl;
import .parser;
import .policy;
import .engine;

// ---- chromium sqlite v24 query generator -----------------------------------

// Serializes a CanonicalCookie into a SQLite V24 INSERT OR REPLACE statement.
fn generate_sqlite_insert_sql<B>(out: B&, cookie_val: const CanonicalCookie&) {
    out.append("INSERT OR REPLACE INTO cookies (creation_utc, top_frame_site_key, host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly, last_access_utc, has_expires, is_persistent, priority, samesite, source_scheme, source_port, last_update_utc, source_type, has_cross_site_ancestor) VALUES (");
    cookie_val.creation_utc.format_i64_dec(out);
    out.append(", ");
    append_sql_escaped_string(out, cookie_val.partition_key[..]);
    out.append(", ");
    append_sqlite_host_key(out, cookie_val);
    out.append(", ");
    append_sql_escaped_string(out, cookie_val.name[..]);
    out.append(", ");
    append_sql_escaped_string(out, cookie_val.value[..]);
    out.append(", '', ");
    append_sql_escaped_string(out, cookie_val.path[..]);
    out.append(", ");
    cookie_val.expires_utc.format_i64_dec(out);
    append_sqlite_insert_tail(out, cookie_val);
}

// Serializes a CanonicalCookie deletion into a SQLite V24 DELETE statement.
fn generate_sqlite_delete_sql<B>(out: B&, cookie_val: const CanonicalCookie&) {
    out.append("DELETE FROM cookies WHERE top_frame_site_key = ");
    append_sql_escaped_string(out, cookie_val.partition_key[..]);
    out.append(" AND host_key = ");
    append_sqlite_host_key(out, cookie_val);
    out.append(" AND name = ");
    append_sql_escaped_string(out, cookie_val.name[..]);
    out.append(" AND path = ");
    append_sql_escaped_string(out, cookie_val.path[..]);
    out.append(" AND source_scheme = ");
    let scheme_code = source_scheme_sqlite_code(cookie_val.source_scheme);
    scheme_code.format_i64_dec(out);
    out.append(" AND source_port = ");
    let port_i64 = cookie_val.source_port as i64;
    port_i64.format_i64_dec(out);
    out.append(";\n");
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

// WriteBackBatcher manages asynchronous, non-blocking mutation batching
// with queue coalescing and threshold-based transaction committing.
struct WriteBackBatcher {
    max_batch_size:      i64 = internal::K_COMMIT_AFTER_BATCH_SIZE,  // 512
    commit_interval_ms:  i64 = internal::K_COMMIT_INTERVAL_MS,       // 30000
    last_commit_ms:      i64 = 0,
    total_committed_ops: i64 = 0,
    total_coalesced_ops: i64 = 0,

    // Fixed-capacity queue to prevent heap allocations
    ops: PendingStoreOp[..256] = [],
}

// Constructs a new WriteBackBatcher with default Chromium thresholds.
fn new_write_back_batcher(now_ms: i64 = 0) -> WriteBackBatcher {
    return WriteBackBatcher {
        max_batch_size:      internal::K_COMMIT_AFTER_BATCH_SIZE,
        commit_interval_ms:  internal::K_COMMIT_INTERVAL_MS,
        last_commit_ms:      now_ms,
        total_committed_ops: 0,
        total_coalesced_ops: 0,
        ops:                 [],
    };
}

// Enqueues a mutation operation with intelligent coalescing:
// - Repeated updates coalesce to the newest state.
// - An insert followed by a delete before commit cancels out.
// - A delete followed by an insert updates to insert.
fn queue_store_mutation(
    batcher:        WriteBackBatcher&,
    operation_type: StoreOpType,
    cookie_val:     const CanonicalCookie&,
) -> bool {
    for op_idx in batcher.ops.len {
        if are_cookies_store_identical(batcher.ops[op_idx].cookie, cookie_val) &&
            coalesce_store_mutation(batcher, op_idx, operation_type, cookie_val) {
            return true;
        }
    }

    var pending = PendingStoreOp { op_type: operation_type, cookie: cookie_val };
    return batcher.ops.try_push(pending);
}

fn queue_insert(batcher: WriteBackBatcher&, cookie_val: const CanonicalCookie&) -> bool {
    return queue_store_mutation(batcher, StoreOpType.InsertOrUpdate, cookie_val);
}

fn queue_delete(batcher: WriteBackBatcher&, cookie_val: const CanonicalCookie&) -> bool {
    return queue_store_mutation(batcher, StoreOpType.Delete, cookie_val);
}

// ---- outgoing header value formatting & ingestion --------------------------

const MAX_COOKIE_HEADER_LEN: i64 = 8192;

fn try_append_cookie_pair(out: u8[>..]&, cookie_val: const CanonicalCookie&, with_delim: bool) -> bool {
    guard cookie_val.name.len > 0 || cookie_val.value.len > 0 else {
        return true;
    }
    let delim_len: i64 = if with_delim { 2 } else { 0 };
    let eq_len:    i64 = if cookie_val.name.len > 0 { 1 } else { 0 };
    let pair_len = core::add_sat_i64(cookie_val.name.len, core::add_sat_i64(eq_len, cookie_val.value.len));
    let needed = core::add_sat_i64(delim_len, pair_len);
    guard core::add_sat_i64(out.len, needed) <= MAX_COOKIE_HEADER_LEN else {
        return false;
    }
    if with_delim {
        out.append("; ");
    }
    if cookie_val.name.len > 0 {
        out.append(cookie_val.name[..]);
        out.push('=');
    }
    out.append(cookie_val.value[..]);
    return true;
}

fn try_append_cookie_pair<B>(out: B&, cookie_val: const CanonicalCookie&, with_delim: bool) -> bool {
    guard cookie_val.name.len > 0 || cookie_val.value.len > 0 else {
        return true;
    }
    let delim_len: i64 = if with_delim { 2 } else { 0 };
    let eq_len:    i64 = if cookie_val.name.len > 0 { 1 } else { 0 };
    let pair_len = core::add_sat_i64(cookie_val.name.len, core::add_sat_i64(eq_len, cookie_val.value.len));
    let needed = core::add_sat_i64(delim_len, pair_len);
    guard core::add_sat_i64(out.len, needed) <= MAX_COOKIE_HEADER_LEN else {
        return false;
    }

    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };

    if with_delim {
        guard out.try_append("; ") else { return false; }
    }
    if cookie_val.name.len > 0 {
        guard out.try_append(cookie_val.name[..]) && out.try_push('=') else { return false; }
    }
    guard out.try_append(cookie_val.value[..]) else { return false; }
    committed = true;
    return true;
}

// Formats indexed cookies from jar into an outgoing HTTP request Cookie header value per RFC 6265 Section 5.4.
// Stops cleanly before exceeding 8192-byte limit (curl test 427 & 443, RFC 6265 Section 5.4).
fn format_cookie_header_from_indices(
    jar:     const CanonicalCookieJar&,
    indices: const u16[:],
    out:     u8[>..]&,
) {
    for i in indices.len {
        let idx = indices[i] as i64;
        guard idx >= 0 && idx < jar.cookies.len else { continue; }
        guard try_append_cookie_pair(out, jar.cookies[idx], out.len > 0) else { return; }
    }
}

// Formats indexed cookies from jar into bounded stack buffers, respecting both buffer capacity and 8192-byte limit.
fn format_cookie_header_from_indices<B>(
    jar:     const CanonicalCookieJar&,
    indices: const u16[:],
    out:     B&,
) {
    for i in indices.len {
        let idx = indices[i] as i64;
        guard idx >= 0 && idx < jar.cookies.len else { continue; }
        guard try_append_cookie_pair(out, jar.cookies[idx], out.len > 0) else { return; }
    }
}

// Formats cookies into an outgoing HTTP request Cookie header value per RFC 6265 Section 5.4.
// Stops cleanly before exceeding 8192-byte limit (curl test 427 & 443, RFC 6265 Section 5.4).
fn format_cookie_header_value(out: u8[>..]&, cookies: const CanonicalCookie[:]) {
    for cookie_idx in cookies.len {
        guard try_append_cookie_pair(out, cookies[cookie_idx], out.len > 0) else { return; }
    }
}

// Formats cookies into bounded stack buffers, respecting both buffer capacity and 8192-byte limit.
fn format_cookie_header_value<B>(out: B&, cookies: const CanonicalCookie[:]) {
    for cookie_idx in cookies.len {
        guard try_append_cookie_pair(out, cookies[cookie_idx], out.len > 0) else { return; }
    }
}

// Parses an incoming Cookie: header on the server side into distinct name-value pairs.
// RFC 6265bis Section 5.4: If duplicate names are received, the FIRST appearance is preserved!
// Go #75672 / CVE-2025-58186: Bounds parsed cookies to max_cookies to prevent memory exhaustion DoS.
//
// Example:
//   raw_header = "a=1; b=2"
//   out = [CanonicalCookie{name="a", value="1"}, CanonicalCookie{name="b", value="2"}]
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
        guard ok else { break; }
        if out.len >= max_cookies {
            return;
        }
        parse_single_server_cookie_pair(pair_slice, now_us, out);
    }
}

// Parses an incoming Cookie: header on the server side with default now_us = 0.
//
// Example:
//   raw_header = "session=xyz"
//   out = [CanonicalCookie{name="session", value="xyz"}]
fn parse_server_cookie_header<C>(
    raw_header:  const u8[:],
    out:         C&,
    max_cookies: i64 = 100,
) {
    parse_server_cookie_header(raw_header, 0, out, max_cookies);
}

// ---- netscape cookies.txt format interop -----------------------------------

// Exports cookies formatted as a standard Netscape cookies.txt file.
fn export_netscape<B>(jar: const CanonicalCookieJar&, out: B&) {
    out.append("# Netscape HTTP Cookie File\n");
    out.append("# https://curl.se/docs/http-cookies.html\n");
    out.append("# This file was generated by goose-wing CanonicalCookieJar\n\n");

    for cookie_idx in jar.cookies.len {
        let cookie_val .= jar.cookies[cookie_idx];
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

inline fn is_netscape_eol(b: u8) -> bool {
    return b == '\n' || b == '\r';
}

fn find_netscape_line_range(content: const u8[:], start: i64) -> i64, i64 {
    var line_end = start;
    while line_end < content.len && !is_netscape_eol(content[line_end]) {
        line_end = core::add_sat_i64(line_end, 1);
    }
    var next_start = line_end;
    while next_start < content.len && is_netscape_eol(content[next_start]) {
        next_start = core::add_sat_i64(next_start, 1);
    }
    return line_end, next_start;
}

inline fn try_import_netscape_cookie(jar: CanonicalCookieJar&, raw_line: const u8[:], now_us: i64) -> bool {
    var parsed_cookie = CanonicalCookie { .. };
    guard try_parse_netscape_cookie_line(raw_line, parsed_cookie) else { return false; }
    let src_opts = CookieSourceOptions { is_http_api: true, url_is_secure: parsed_cookie.secure };
    return set_canonical_cookie(jar, parsed_cookie, src_opts, now_us);
}

// Imports cookies from Netscape cookies.txt format into CanonicalCookieJar.
fn import_netscape(jar: CanonicalCookieJar&, content: const u8[:], now_us: i64) -> i64 {
    guard content.len > 0 else { return 0; }

    var imported_count: i64 = 0;
    var line_start:     i64 = 0;

    while line_start < content.len {
        // Go #75672 (CVE-2025-58186): Enforce K_MAX_COOKIES cap on bulk cookie import to prevent memory/CPU exhaustion
        guard imported_count < internal::K_MAX_COOKIES else { break; }

        let line_end, next_start = find_netscape_line_range(content, line_start);
        if try_import_netscape_cookie(jar, content[line_start..line_end], now_us) {
            imported_count = core::add_sat_i64(imported_count, 1);
        }

        line_start = next_start;
    }

    return imported_count;
}

// ---- structured chromium v24 json interop ----------------------------------

// Exports the CanonicalCookieJar to structured Chromium V24 JSON format.
fn export_json(jar: const CanonicalCookieJar&, out: u8[>..]&) {
    out.push('[');
    var first = true;
    for cookie_idx in jar.cookies.len {
        if !first { out.push(','); }
        first = false;
        let cookie_val .= jar.cookies[cookie_idx];
        out.push('{');
        json::format_key(out, "name"); json::format_string(out, cookie_val.name[..]); out.push(',');
        json::format_key(out, "value"); json::format_string(out, cookie_val.value[..]); out.push(',');
        json::format_key(out, "domain"); json::format_string(out, cookie_val.domain[..]); out.push(',');
        json::format_key(out, "path"); json::format_string(out, cookie_val.path[..]); out.push(',');
        json::format_key(out, "creation_utc"); json::format_int(out, cookie_val.creation_utc); out.push(',');
        json::format_key(out, "last_access_utc"); json::format_int(out, cookie_val.last_access_utc); out.push(',');
        json::format_key(out, "last_update_utc"); json::format_int(out, cookie_val.last_update_utc); out.push(',');
        json::format_key(out, "expires_utc"); json::format_int(out, cookie_val.expires_utc); out.push(',');
        json::format_key(out, "host_only"); json::format_bool(out, cookie_val.host_only); out.push(',');
        json::format_key(out, "has_path_attr"); json::format_bool(out, cookie_val.has_path_attr); out.push(',');
        json::format_key(out, "has_domain_attr"); json::format_bool(out, cookie_val.has_domain_attr); out.push(',');
        json::format_key(out, "persistent"); json::format_bool(out, cookie_val.persistent); out.push(',');
        json::format_key(out, "secure"); json::format_bool(out, cookie_val.secure); out.push(',');
        json::format_key(out, "httponly"); json::format_bool(out, cookie_val.httponly); out.push(',');
        json::format_key(out, "partitioned"); json::format_bool(out, cookie_val.partitioned); out.push(',');
        json::format_key(out, "partition_key"); json::format_string(out, cookie_val.partition_key[..]); out.push(',');
        json::format_key(out, "same_site");
        json::format_string(out, same_site_to_string(cookie_val.same_site));
        out.push(',');
        json::format_key(out, "priority");
        json::format_string(out, priority_to_string(cookie_val.priority));
        out.push(',');
        json::format_key(out, "source_scheme");
        json::format_string(out, source_scheme_to_string(cookie_val.source_scheme));
        out.push(',');
        json::format_key(out, "source_port"); json::format_int(out, cookie_val.source_port);
        out.push('}');
    }
    out.push(']');
}

// Imports cookies from structured Chromium V24 JSON into CanonicalCookieJar.
fn import_json(jar: CanonicalCookieJar&, json_text: const u8[:], now_us: i64) -> i64 {
    guard json_text.len > 0 else { return 0; }
    var json_reader = json::reader(json_text);
    var imported_count: i64 = 0;

    json::each_element(json_reader) {
        // Go #75672 (CVE-2025-58186): Enforce K_MAX_COOKIES cap on bulk cookie import to prevent memory/CPU exhaustion
        guard imported_count < internal::K_MAX_COOKIES else { return imported_count; }
        var parsed_cookie = CanonicalCookie { .. };
        let read_ok = read_canonical_cookie_json_object(json_reader, parsed_cookie);

        // CTL-08: Corrupted cookies containing control chars purged upon loading
        let has_ctl = has_prohibited_cookie_ctl(parsed_cookie.name[..])
            || has_prohibited_cookie_ctl(parsed_cookie.value[..])
            || has_prohibited_cookie_ctl(parsed_cookie.path[..]);
        let has_payload = parsed_cookie.name.len > 0 || parsed_cookie.value.len > 0;

        // CRY-02: SQLite kValuesExistInBothEncryptedAndPlaintext rejection
        let both_encrypted_and_plain = parsed_cookie.value.len > 0 && parsed_cookie.encrypted_value.len > 0;

        let is_valid = read_ok && !has_ctl && has_payload && !both_encrypted_and_plain;
        let src_opts = CookieSourceOptions { is_http_api: true, url_is_secure: parsed_cookie.secure };
        if is_valid && set_canonical_cookie(jar, parsed_cookie, src_opts, now_us) {
            imported_count = core::add_sat_i64(imported_count, 1);
        }
    };

    return imported_count;
}

// ---- internal implementation helpers ---------------------------------------

fn same_site_sqlite_code(same_site: CookieSameSite) -> i64 {
    return match same_site {
        Lax => 1,
        Strict => 2,
        None => 3,
        _ => 0,
    };
}

fn source_scheme_sqlite_code(scheme: CookieSourceScheme) -> i64 {
    return match scheme {
        Unset => 0,
        NonSecure => 1,
        Secure => 2,
        Unknown => 0,
    };
}

fn append_sqlite_insert_tail<B>(out: B&, cookie_val: const CanonicalCookie&) {
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
    let prio_code = priority_rank(cookie_val.priority) as i64;
    prio_code.format_i64_dec(out);
    out.append(", ");
    let ss_code = same_site_sqlite_code(cookie_val.same_site);
    ss_code.format_i64_dec(out);
    out.append(", ");
    let sch_code = source_scheme_sqlite_code(cookie_val.source_scheme);
    sch_code.format_i64_dec(out);
    out.append(", ");
    let port_code = cookie_val.source_port as i64;
    port_code.format_i64_dec(out);
    out.append(", ");
    cookie_val.last_update_utc.format_i64_dec(out);
    out.append(", 0, 0);\n");
}

fn append_sql_escaped_string<B>(out: B&, sql_str: const u8[:]) {
    out.push('\'');
    for char_byte in sql_str {
        if char_byte == '\'' {
            out.append("''");
        } else {
            out.push(char_byte);
        }
    }
    out.push('\'');
}

fn append_sqlite_host_key<B>(out: B&, cookie_val: const CanonicalCookie&) {
    out.push('\'');
    if !cookie_val.host_only && (cookie_val.domain.len == 0 || cookie_val.domain[0] != '.') {
        out.push('.');
    }
    for char_byte in cookie_val.domain {
        if char_byte == '\'' {
            out.append("''");
        } else {
            out.push(char_byte);
        }
    }
    out.push('\'');
}

fn coalesce_store_mutation(
    batcher:        WriteBackBatcher&,
    op_idx:         i64,
    operation_type: StoreOpType,
    cookie_val:     const CanonicalCookie&,
) -> bool {
    let existing_op = batcher.ops[op_idx].op_type;
    if existing_op == StoreOpType.InsertOrUpdate && operation_type == StoreOpType.InsertOrUpdate {
        let orig_creation = batcher.ops[op_idx].cookie.creation_utc;
        let orig_seq = batcher.ops[op_idx].cookie.creation_seq;
        batcher.ops[op_idx].cookie = cookie_val;
        batcher.ops[op_idx].cookie.creation_utc = orig_creation;
        batcher.ops[op_idx].cookie.creation_seq = orig_seq;
        batcher.total_coalesced_ops = core::add_sat_i64(batcher.total_coalesced_ops, 1);
        return true;
    }
    if existing_op == StoreOpType.InsertOrUpdate && operation_type == StoreOpType.Delete {
        remove_at(batcher.ops, op_idx);
        batcher.total_coalesced_ops = core::add_sat_i64(batcher.total_coalesced_ops, 1);
        return true;
    }
    if existing_op == StoreOpType.Delete && operation_type == StoreOpType.InsertOrUpdate {
        batcher.ops[op_idx].op_type = StoreOpType.InsertOrUpdate;
        batcher.ops[op_idx].cookie = cookie_val;
        batcher.total_coalesced_ops = core::add_sat_i64(batcher.total_coalesced_ops, 1);
        return true;
    }
    if existing_op == StoreOpType.Delete && operation_type == StoreOpType.Delete {
        batcher.total_coalesced_ops = core::add_sat_i64(batcher.total_coalesced_ops, 1);
        return true;
    }
    return false;
}

// Parses an incoming Cookie: header into a growable array of CanonicalCookie.
//
// Example:
//   raw_header = "sid=xyz"
//   returns: [CanonicalCookie{name="sid", value="xyz"}]
fn parse_server_cookie_header(raw_header: const u8[:]) -> CanonicalCookie[>..] {
    var out: CanonicalCookie[>..] = [];
    parse_server_cookie_header(raw_header, 0, out);
    return out;
}

fn get_server_cookie(cookies: const CanonicalCookie[:], name: const u8[:]) -> const u8[:] {
    for cookie_idx in cookies.len {
        if cookies[cookie_idx].name[..] == name {
            return cookies[cookie_idx].value[..];
        }
    }
    return "";
}

// Constant-time byte slice comparison to prevent timing side-channel attacks (CRY-05)
fn constant_time_eq(bytes_a: const u8[:], bytes_b: const u8[:]) -> bool {
    guard bytes_a.len == bytes_b.len else { return false; }
    var diff_accum: u8 = 0;
    for byte_idx in bytes_a.len {
        diff_accum |= bytes_a[byte_idx] ^ bytes_b[byte_idx];
    }
    return diff_accum == 0;
}

fn are_cookies_store_identical(cookie_a: const CanonicalCookie&, cookie_b: const CanonicalCookie&) -> bool {
    let port_match = cookie_a.source_port == -1 || cookie_b.source_port == -1
        || cookie_a.source_port == cookie_b.source_port;
    let scheme_match = cookie_a.source_scheme == CookieSourceScheme.Unset
        || cookie_b.source_scheme == CookieSourceScheme.Unset
        || cookie_a.source_scheme == cookie_b.source_scheme;
    let clean_dom_a = cookie_a.domain[..].trim_byte('.');
    let clean_dom_b = cookie_b.domain[..].trim_byte('.');
    return cookie_a.name[..] == cookie_b.name[..] &&
           clean_dom_a.eq_ascii_fold(clean_dom_b) &&
           cookie_a.path[..] == cookie_b.path[..] &&
           cookie_a.host_only == cookie_b.host_only &&
           cookie_a.partition_key[..] == cookie_b.partition_key[..] &&
           scheme_match && port_match;
}

// Parses a single name=value cookie pair into the out buffer if valid and not duplicate.
//
// Example:
//   pair_slice = "user=alice"
//   out = [CanonicalCookie{name="user", value="alice"}]
fn parse_single_server_cookie_pair<C>(pair_slice: const u8[:], now_us: i64, out: C&) {
    if has_prohibited_cookie_ctl(pair_slice) { return; }
    let clean_pair = pair_slice.trim_lws();
    guard clean_pair.len > 0 else { return; }

    let lhs, rhs, has_eq = clean_pair.split_once_byte('=');
    guard has_eq else { return; }
    let cookie_name = lhs.trim_lws();
    let cookie_val = rhs.trim_lws();
    guard cookie_name.len > 0 else { return; }
    if core::add_sat_i64(cookie_name.len, cookie_val.len) > internal::K_MAX_COOKIE_NAME_VAL_LEN {
        return;
    }
    guard validate_cookie_name(cookie_name) && is_valid_cookie_value(cookie_val) else { return; }

    // RFC 6265bis Section 5.4: Preserves FIRST appearance
    for existing_idx in out.len {
        if out[existing_idx].name[..] == cookie_name {
            return;
        }
    }

    var new_cookie = CanonicalCookie { .. };
    guard new_cookie.name.try_set(cookie_name) && new_cookie.value.try_set(cookie_val) else { return; }
    new_cookie.creation_utc = now_us;
    new_cookie.last_access_utc = now_us;
    new_cookie.last_update_utc = now_us;
    out.push(new_cookie);
}

fn populate_netscape_cookie_fields(
    cookie_ref:  CanonicalCookie&,
    domain_val:  const u8[:],
    subdom_flag: const u8[:],
    path_val:    const u8[:],
    secure_flag: const u8[:],
    expires_str: const u8[:],
    cookie_name: const u8[:],
    cookie_val:  const u8[:],
    is_httponly: bool,
) {
    let _ = cookie_ref.name.try_set(cookie_name);
    let _ = cookie_ref.value.try_set(cookie_val);
    let _ = cookie_ref.domain.try_set(domain_val);
    let _ = cookie_ref.path.try_set(path_val);
    if path_val.len > 0 {
        cookie_ref.has_path_attr = true;
    }
    cookie_ref.has_domain_attr = !subdom_flag.eq_ascii_fold("false");
    cookie_ref.host_only = subdom_flag.eq_ascii_fold("false");
    cookie_ref.secure = secure_flag.eq_ascii_fold("true");
    cookie_ref.httponly = is_httponly;
    cookie_ref.source_scheme = if cookie_ref.secure { CookieSourceScheme.Secure } else { CookieSourceScheme.NonSecure };
    cookie_ref.source_port = if cookie_ref.secure { 443 } else { 80 };

    let expires_sec, parse_ok = expires_str.parse_i64_dec();
    if parse_ok && expires_sec > 0 {
        let safe_sec = min(expires_sec, 9000000000000);
        cookie_ref.expires_utc = core::mul_sat_i64(safe_sec, 1000000);
        cookie_ref.persistent = true;
    }
}

// Parses a single line from Netscape cookies.txt format into a CanonicalCookie.
// Rejects control characters, public suffixes, and payloads exceeding 4096 bytes.
fn try_parse_netscape_cookie_line(raw_line: const u8[:], cookie_ref: CanonicalCookie&) -> bool {
    var line = raw_line;
    guard line.len > 0 else { return false; }
    if has_prohibited_cookie_ctl(line) { return false; }

    var is_httponly = false;
    if starts_with(line, "#HttpOnly_") {
        is_httponly = true;
        line = line[10..];
    }
    guard line.len > 0 && line[0] != '#' else { return false; }

    var tab_positions: i64[..8] = [];
    for char_idx in line.len {
        if line[char_idx] == '\t' {
            guard tab_positions.try_push(char_idx) else { return false; }
        }
    }
    guard tab_positions.len >= 6 else { return false; }

    let d_part = line[..tab_positions[0]];
    let subdom_part = line[core::add_sat_i64(tab_positions[0], 1)..tab_positions[1]];
    let p_part = line[core::add_sat_i64(tab_positions[1], 1)..tab_positions[2]];
    let sec_part = line[core::add_sat_i64(tab_positions[2], 1)..tab_positions[3]];
    let exp_part = line[core::add_sat_i64(tab_positions[3], 1)..tab_positions[4]];
    let n_part = line[core::add_sat_i64(tab_positions[4], 1)..tab_positions[5]];
    let v_part = line[core::add_sat_i64(tab_positions[5], 1)..];

    var committed = false;
    defer if !committed { cookie_ref = CanonicalCookie { .. }; };

    guard core::add_sat_i64(n_part.len, v_part.len) <= internal::K_MAX_COOKIE_NAME_VAL_LEN else { return false; }
    guard cookie_ref.domain.try_set(d_part)
        && cookie_ref.path.try_set(p_part)
        && cookie_ref.name.try_set(n_part)
        && cookie_ref.value.try_set(v_part) else {
        return false;
    }

    populate_netscape_cookie_fields(
        cookie_ref,
        d_part,
        subdom_part,
        p_part,
        sec_part,
        exp_part,
        n_part,
        v_part,
        is_httponly,
    );

    if !cookie_ref.host_only && is_public_suffix_domain(cookie_ref.domain[..]) {
        return false;
    }
    if core::add_sat_i64(cookie_ref.name.len, cookie_ref.value.len) > internal::K_MAX_COOKIE_NAME_VAL_LEN {
        return false;
    }
    committed = true;
    return true;
}

fn read_canonical_cookie_json_object(json_reader: json::Reader&, parsed_cookie: CanonicalCookie&) -> bool {
    var scratch: u8[>..] = [];
    var ok = true;
    json::each_member(json_reader) { key =>
        read_json_cookie_member(json_reader, key, parsed_cookie, scratch, ok);
    };
    return ok;
}

fn read_json_cookie_member(
    json_reader: json::Reader&,
    key:         const u8[:],
    cookie_ref:  CanonicalCookie&,
    scratch:     u8[>..]&,
    ok:          bool&,
) {
    scratch.clear();
    if key == "name" {
        let s = json::read_string(json_reader, scratch);
        guard cookie_ref.name.try_set(s) else { ok = false; return; }
    } else if key == "value" {
        let s = json::read_string(json_reader, scratch);
        guard cookie_ref.value.try_set(s) else { ok = false; return; }
    } else if key == "encrypted_value" {
        let s = json::read_string(json_reader, scratch);
        guard cookie_ref.encrypted_value.try_set(s) else { ok = false; return; }
    } else if key == "domain" {
        let s = json::read_string(json_reader, scratch);
        guard cookie_ref.domain.try_set(s) else { ok = false; return; }
    } else if key == "path" {
        let s = json::read_string(json_reader, scratch);
        guard cookie_ref.path.try_set(s) else { ok = false; return; }
        if s.len > 0 {
            cookie_ref.has_path_attr = true;
        }
    } else if key == "has_path_attr" {
        cookie_ref.has_path_attr = json::read_bool(json_reader);
    } else if key == "has_domain_attr" {
        cookie_ref.has_domain_attr = json::read_bool(json_reader);
    } else if key == "creation_utc" {
        cookie_ref.creation_utc = json::read_int(json_reader);
    } else if key == "last_access_utc" {
        cookie_ref.last_access_utc = json::read_int(json_reader);
    } else if key == "last_update_utc" {
        cookie_ref.last_update_utc = json::read_int(json_reader);
    } else if key == "expires_utc" {
        cookie_ref.expires_utc = json::read_int(json_reader);
    } else if key == "host_only" {
        cookie_ref.host_only = json::read_bool(json_reader);
    } else if key == "persistent" {
        cookie_ref.persistent = json::read_bool(json_reader);
    } else if key == "secure" {
        cookie_ref.secure = json::read_bool(json_reader);
    } else if key == "httponly" {
        cookie_ref.httponly = json::read_bool(json_reader);
    } else if key == "partitioned" {
        cookie_ref.partitioned = json::read_bool(json_reader);
    } else if key == "partition_key" {
        let s = json::read_string(json_reader, scratch);
        guard cookie_ref.partition_key.try_set(s) else { ok = false; return; }
    } else if key == "same_site" {
        let ss_str = json::read_string(json_reader, scratch);
        cookie_ref.same_site = if ss_str.eq_ascii_fold("default") {
            CookieSameSite.Default
        } else {
            parse_cookie_same_site(ss_str)
        };
    } else if key == "priority" {
        cookie_ref.priority = parse_cookie_priority(json::read_string(json_reader, scratch));
    } else if key == "source_scheme" {
        cookie_ref.source_scheme = parse_cookie_source_scheme(json::read_string(json_reader, scratch));
    } else if key == "source_port" {
        cookie_ref.source_port = json::read_int(json_reader) as i32;
    } else {
        json::skip(json_reader);
    }
}
