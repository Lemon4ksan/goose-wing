// Persistence Engine, Chromium SQLite V24 Schema, Write-Back Batcher & Formats
// Clean Room Implementation conforming to Chromium SQLitePersistentCookieStore and RFC 6265bis §5.4.
namespace wing;

import std;
import json;
import cookie.constants;
import cookie.canonical;
import cookie.psl;
import cookie.parser;
import cookie.policy;
import cookie.engine;

// ---- sqlite v24 schema ddl ----

// Generates the official Chromium SQLite V24 schema DDL and indices.
fn generate_sqlite_v24_schema<B>(out: B&) {
    out.append("CREATE TABLE meta (key TEXT NOT NULL UNIQUE PRIMARY KEY, value INTEGER NOT NULL);\n");
    out.append("INSERT INTO meta (key, value) VALUES ('version', 24);\n");
    out.append("INSERT INTO meta (key, value) VALUES ('last_compatible_version', 24);\n\n");
    out.append("CREATE TABLE cookies (\n");
    out.append("    creation_utc INTEGER NOT NULL,\n");
    out.append("    top_frame_site_key TEXT NOT NULL,\n");
    out.append("    host_key TEXT NOT NULL,\n");
    out.append("    name TEXT NOT NULL,\n");
    out.append("    value TEXT NOT NULL,\n");
    out.append("    encrypted_value BLOB DEFAULT '',\n");
    out.append("    path TEXT NOT NULL,\n");
    out.append("    expires_utc INTEGER NOT NULL,\n");
    out.append("    is_secure INTEGER NOT NULL,\n");
    out.append("    is_httponly INTEGER NOT NULL,\n");
    out.append("    last_access_utc INTEGER NOT NULL,\n");
    out.append("    has_expires INTEGER NOT NULL,\n");
    out.append("    is_persistent INTEGER NOT NULL,\n");
    out.append("    priority INTEGER NOT NULL,\n");
    out.append("    samesite INTEGER NOT NULL,\n");
    out.append("    source_scheme INTEGER NOT NULL,\n");
    out.append("    source_port INTEGER NOT NULL,\n");
    out.append("    last_update_utc INTEGER NOT NULL,\n");
    out.append("    source_type INTEGER NOT NULL DEFAULT 0,\n");
    out.append("    has_cross_site_ancestor INTEGER NOT NULL DEFAULT 0,\n");
    out.append("    PRIMARY KEY (top_frame_site_key, host_key, name, path, source_scheme, source_port)\n");
    out.append(");\n\n");
    out.append("CREATE INDEX domain ON cookies(host_key);\n");
    out.append("CREATE INDEX cookie_times ON cookies(creation_utc);\n");
    out.append("CREATE INDEX is_transient ON cookies(is_persistent) WHERE is_persistent = 0;\n");
}

// ---- sqlite v24 dml serialization ----

// Safely appends an SQL single-quoted string with internal quote doubling.
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

// Formats host_key per Chromium SQLitePersistentCookieStore convention:
// - Host-only cookies (host_only = true) store plain host e.g. 'example.com'
// - Domain cookies (host_only = false) store leading dot e.g. '.example.com'
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

// Serializes a CanonicalCookie into a SQLite V24 INSERT OR REPLACE statement.
fn generate_sqlite_insert_sql<B>(out: B&, cookie_val: const CanonicalCookie&) {
    out.append("INSERT OR REPLACE INTO cookies (creation_utc, top_frame_site_key, host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly, last_access_utc, has_expires, is_persistent, priority, samesite, source_scheme, source_port, last_update_utc, source_type, has_cross_site_ancestor) VALUES (");
    format(out, cookie_val.creation_utc);
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
    format(out, cookie_val.expires_utc);
    out.append(", ");
    format(out, if cookie_val.secure { 1 as i64 } else { 0 as i64 });
    out.append(", ");
    format(out, if cookie_val.httponly { 1 as i64 } else { 0 as i64 });
    out.append(", ");
    format(out, cookie_val.last_access_utc);
    out.append(", ");
    format(out, if cookie_val.persistent { 1 as i64 } else { 0 as i64 });
    out.append(", ");
    format(out, if cookie_val.persistent { 1 as i64 } else { 0 as i64 });
    out.append(", ");
    format(out, priority_rank(cookie_val.priority) as i64);
    out.append(", ");
    let same_site_code = match cookie_val.same_site {
        Default => 0,
        Lax => 1,
        Strict => 2,
        None => 3,
    };
    format(out, same_site_code as i64);
    out.append(", ");
    let source_scheme_code = match cookie_val.source_scheme {
        Unset => 0,
        NonSecure => 1,
        Secure => 2,
    };
    format(out, source_scheme_code as i64);
    out.append(", ");
    format(out, cookie_val.source_port as i64);
    out.append(", ");
    format(out, cookie_val.last_update_utc);
    out.append(", 0, 0);\n");
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
    let source_scheme_code = match cookie_val.source_scheme {
        Unset => 0,
        NonSecure => 1,
        Secure => 2,
    };
    format(out, source_scheme_code as i64);
    out.append(" AND source_port = ");
    format(out, cookie_val.source_port as i64);
    out.append(";\n");
}

// Generates the SQL statement for closing transient / session cookies on exit.
fn generate_sqlite_session_cleanup_sql<B>(out: B&) {
    out.append("DELETE FROM cookies WHERE is_persistent = 0;\n");
}

// ---- write-back batcher & queue coalescing ----

// Mutation operation type for write-back queue.
enum StoreOpType {
    InsertOrUpdate,
    Delete,
}

// Pending operation in the asynchronous write-back batch queue.
struct PendingStoreOp {
    op_type: StoreOpType = StoreOpType.InsertOrUpdate,
    cookie: CanonicalCookie = CanonicalCookie { .. },
}

// WriteBackBatcher manages asynchronous, non-blocking mutation batching
// with queue coalescing and threshold-based transaction committing.
struct WriteBackBatcher {
    max_batch_size: i64 = 512,       // K_COMMIT_AFTER_BATCH_SIZE
    commit_interval_ms: i64 = 30000,  // K_COMMIT_INTERVAL_MS
    last_commit_ms: i64 = 0,
    total_committed_ops: i64 = 0,
    total_coalesced_ops: i64 = 0,

    // Resizable queue must be the final field
    pending_ops: PendingStoreOp[>..] = [],
}

// Constructs a new WriteBackBatcher with default Chromium thresholds.
fn new_write_back_batcher() -> WriteBackBatcher {
    return WriteBackBatcher {
        max_batch_size: K_COMMIT_AFTER_BATCH_SIZE,
        commit_interval_ms: K_COMMIT_INTERVAL_MS,
        last_commit_ms: 0,
        total_committed_ops: 0,
        total_coalesced_ops: 0,
        pending_ops: [],
    };
}

// Enqueues a mutation operation with intelligent coalescing:
// - Repeated updates coalesce to the newest state.
// - An insert followed by a delete before commit cancels out.
// - A delete followed by an insert updates to insert.
fn queue_store_mutation(
    batcher: WriteBackBatcher&,
    operation_type: StoreOpType,
    cookie_val: const CanonicalCookie&,
) {
    for op_idx in batcher.pending_ops.len {
        if are_cookies_store_identical(batcher.pending_ops[op_idx].cookie, cookie_val) {
            let existing_op = batcher.pending_ops[op_idx].op_type;
            if existing_op == StoreOpType.InsertOrUpdate && operation_type == StoreOpType.InsertOrUpdate {
                batcher.pending_ops[op_idx].cookie = cookie_val;
                batcher.total_coalesced_ops += 1;
                return;
            }
            if existing_op == StoreOpType.InsertOrUpdate && operation_type == StoreOpType.Delete {
                remove_at(batcher.pending_ops, op_idx);
                batcher.total_coalesced_ops += 1;
                return;
            }
            if existing_op == StoreOpType.Delete && operation_type == StoreOpType.InsertOrUpdate {
                batcher.pending_ops[op_idx].op_type = StoreOpType.InsertOrUpdate;
                batcher.pending_ops[op_idx].cookie = cookie_val;
                batcher.total_coalesced_ops += 1;
                return;
            }
            if existing_op == StoreOpType.Delete && operation_type == StoreOpType.Delete {
                batcher.total_coalesced_ops += 1;
                return;
            }
        }
    }

    var pending = PendingStoreOp { .. };
    pending.op_type = operation_type;
    pending.cookie = cookie_val;
    batcher.pending_ops.push(pending);
}

// Checks if the write-back batcher needs to commit based on batch size or time.
fn should_commit_batch(batcher: const WriteBackBatcher&, now_ms: i64) -> bool {
    if batcher.pending_ops.len >= batcher.max_batch_size {
        return true;
    }
    if batcher.pending_ops.len > 0 && (now_ms - batcher.last_commit_ms) >= batcher.commit_interval_ms {
        return true;
    }
    return false;
}

// Flushes pending operations into an atomic SQL transaction block and clears the queue.
fn flush_store_batch<B>(
    batcher: WriteBackBatcher&,
    out_sql: B&,
    now_ms: i64,
) -> i64 {
    guard batcher.pending_ops.len > 0 else { return 0; }

    out_sql.append("BEGIN TRANSACTION;\n");
    let total_operations = batcher.pending_ops.len;

    for op_idx in batcher.pending_ops.len {
        let pending_op = batcher.pending_ops[op_idx];
        if pending_op.op_type == StoreOpType.InsertOrUpdate {
            generate_sqlite_insert_sql(out_sql, pending_op.cookie);
        } else {
            generate_sqlite_delete_sql(out_sql, pending_op.cookie);
        }
    }

    out_sql.append("COMMIT;\n");

    batcher.total_committed_ops += total_operations;
    batcher.pending_ops.clear();
    batcher.last_commit_ms = now_ms;
    return total_operations;
}

// ---- http cookie header formatting & parsing (§5.4) ----

// Serializes a slice of CanonicalCookies into an outgoing HTTP "Cookie: name=value; name2=value2" header.
fn format_cookie_header_value<B>(out: B&, cookies: const CanonicalCookie[:]) {
    for cookie_idx in cookies.len {
        if cookie_idx > 0 {
            out.append("; ");
        }
        out.append(cookies[cookie_idx].name[..]);
        out.push('=');
        out.append(cookies[cookie_idx].value[..]);
    }
}

// Parses an incoming server-side "Cookie" header string.
// Conforming to RFC 6265bis §5.4: if multiple cookies with the same name are present,
// the server MUST take the FIRST occurrence and ignore duplicate names.
fn parse_server_cookie_header(
    header_raw: const u8[:],
    now_us: i64,
    out: CanonicalCookie[>..]&,
) {
    guard header_raw.len > 0 else { return; }

    var scan_start = 0;
    while scan_start < header_raw.len {
        var scan_end = scan_start;
        while scan_end < header_raw.len && header_raw[scan_end] != ';' {
            scan_end += 1;
        }

        let raw_pair = trim(header_raw[scan_start..scan_end]);
        if raw_pair.len > 0 && !has_prohibited_cookie_ctl(raw_pair) {
            parse_single_server_cookie_pair(raw_pair, now_us, out);
        }

        scan_start = scan_end + 1;
    }
}

// ---- netscape format interop ----

// Exports the CanonicalCookieJar to standard Netscape cookies.txt format.
fn export_canonical_netscape<B>(jar: const CanonicalCookieJar&, out: B&) {
    out.append("# Netscape HTTP Cookie File\n");
    out.append("# Generated by goose-wing Chromium CookieMonster\n\n");

    for cookie_idx in jar.cookies.len {
        let cookie_val = jar.cookies[cookie_idx];
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
        format(out, cookie_val.expires_utc / 1000000);
        out.push('\t');
        out.append(cookie_val.name[..]);
        out.push('\t');
        out.append(cookie_val.value[..]);
        out.push('\n');
    }
}

// Imports cookies from Netscape cookies.txt format into CanonicalCookieJar.
fn import_canonical_netscape(jar: CanonicalCookieJar&, content: const u8[:], now_us: i64) -> i64 {
    guard content.len > 0 else { return 0; }

    var imported_count: i64 = 0;
    var line_start = 0;

    while line_start < content.len {
        var line_end = line_start;
        while line_end < content.len && content[line_end] != '\n' && content[line_end] != '\r' {
            line_end += 1;
        }

        let raw_line = content[line_start..line_end];
        var parsed_cookie = CanonicalCookie { .. };
        if try_parse_netscape_cookie_line(raw_line, parsed_cookie) {
            let ok = set_canonical_cookie(jar, parsed_cookie, true, parsed_cookie.secure, now_us);
            if ok {
                imported_count += 1;
            }
        }

        line_start = line_end;
        while line_start < content.len && (content[line_start] == '\n' || content[line_start] == '\r') {
            line_start += 1;
        }
    }

    return imported_count;
}

// ---- json serialization & deserialization ----

// Exports the CanonicalCookieJar to structured Chromium V24 JSON format.
fn export_canonical_json<B>(jar: const CanonicalCookieJar&, out: B&) {
    out.push('[');
    for cookie_idx in jar.cookies.len {
        let cookie_val = jar.cookies[cookie_idx];
        if cookie_idx > 0 { out.push(','); }
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
        json::format_key(out, "persistent"); json::format_bool(out, cookie_val.persistent); out.push(',');
        json::format_key(out, "secure"); json::format_bool(out, cookie_val.secure); out.push(',');
        json::format_key(out, "httponly"); json::format_bool(out, cookie_val.httponly); out.push(',');
        json::format_key(out, "partitioned"); json::format_bool(out, cookie_val.partitioned); out.push(',');
        json::format_key(out, "partition_key"); json::format_string(out, cookie_val.partition_key[..]); out.push(',');
        json::format_key(out, "same_site"); json::format_string(out, same_site_to_string(cookie_val.same_site)); out.push(',');
        json::format_key(out, "priority"); json::format_string(out, priority_to_string(cookie_val.priority)); out.push(',');
        json::format_key(out, "source_scheme"); json::format_string(out, source_scheme_to_string(cookie_val.source_scheme)); out.push(',');
        json::format_key(out, "source_port"); json::format_int(out, cookie_val.source_port as i64);
        out.push('}');
    }
    out.push(']');
}

// Imports cookies from structured Chromium V24 JSON format into CanonicalCookieJar.
fn import_canonical_json(jar: CanonicalCookieJar&, json_text: const u8[:], now_us: i64) -> i64 {
    guard json_text.len > 0 else { return 0; }
    var json_reader = json::reader(json_text);
    var imported_count: i64 = 0;

    json::each_element(json_reader) {
        var parsed_cookie = CanonicalCookie { .. };
        json::each_member(json_reader) { key =>
            read_json_cookie_member(json_reader, key, parsed_cookie);
        };

        if parsed_cookie.name.len > 0 {
            let is_sec_url = parsed_cookie.secure || (parsed_cookie.source_scheme == CookieSourceScheme.Secure);
            let ok = set_canonical_cookie(jar, parsed_cookie, true, is_sec_url, now_us);
            if ok { imported_count += 1; }
        }
    };

    return imported_count;
}

// ---- internal implementation helpers ----

// Tests if two cookies have identical canonical primary key in storage.
fn are_cookies_store_identical(cookie_a: const CanonicalCookie&, cookie_b: const CanonicalCookie&) -> bool {
    return cookie_a.name[..] == cookie_b.name[..] &&
           eq_ascii_fold(cookie_a.domain[..], cookie_b.domain[..]) &&
           cookie_a.path[..] == cookie_b.path[..] &&
           cookie_a.host_only == cookie_b.host_only &&
           cookie_a.partition_key[..] == cookie_b.partition_key[..] &&
           cookie_a.source_port == cookie_b.source_port &&
           cookie_a.source_scheme == cookie_b.source_scheme;
}

fn parse_single_server_cookie_pair(
    raw_pair: const u8[:],
    now_us: i64,
    out: CanonicalCookie[>..]&,
) {
    var eq_idx = -1;
    for char_idx in raw_pair.len {
        if raw_pair[char_idx] == '=' {
            eq_idx = char_idx;
            break;
        }
    }
    guard eq_idx >= 0 else { return; }

    let cookie_name = trim(raw_pair[..eq_idx]);
    let cookie_val = trim(raw_pair[eq_idx + 1..]);
    guard cookie_name.len > 0 else { return; }

    // RFC 6265bis §5.4: first occurrence invariant (do not overwrite)
    for existing_idx in out.len {
        if out[existing_idx].name[..] == cookie_name {
            return;
        }
    }

    var new_cookie = CanonicalCookie { .. };
    new_cookie.name.append(cookie_name);
    new_cookie.value.append(cookie_val);
    new_cookie.creation_utc = now_us;
    new_cookie.last_access_utc = now_us;
    new_cookie.last_update_utc = now_us;
    out.push(new_cookie);
}

fn try_parse_netscape_cookie_line(raw_line: const u8[:], cookie_ref: CanonicalCookie&) -> bool {
    var line = raw_line;
    guard line.len > 0 else { return false; }

    var is_httponly = false;
    if starts_with(line, "#HttpOnly_") {
        is_httponly = true;
        line = line[10..];
    }
    guard line.len > 0 && line[0] != '#' else { return false; }

    var tab_positions: i64[>..] = [];
    for char_idx in line.len {
        if line[char_idx] == '\t' {
            tab_positions.push(char_idx);
        }
    }
    guard tab_positions.len >= 6 else { return false; }

    let domain_val = line[..tab_positions[0]];
    let subdom_flag = line[tab_positions[0] + 1..tab_positions[1]];
    let path_val = line[tab_positions[1] + 1..tab_positions[2]];
    let secure_flag = line[tab_positions[2] + 1..tab_positions[3]];
    let expires_str = line[tab_positions[3] + 1..tab_positions[4]];
    let cookie_name = line[tab_positions[4] + 1..tab_positions[5]];
    let cookie_val = line[tab_positions[5] + 1..];

    cookie_ref.name.append(cookie_name);
    cookie_ref.value.append(cookie_val);
    cookie_ref.domain.append(domain_val);
    cookie_ref.path.clear();
    cookie_ref.path.append(path_val);
    cookie_ref.host_only = eq_ascii_fold(subdom_flag, "false");
    cookie_ref.secure = eq_ascii_fold(secure_flag, "true");
    cookie_ref.httponly = is_httponly;
    cookie_ref.source_scheme = if cookie_ref.secure { CookieSourceScheme.Secure } else { CookieSourceScheme.NonSecure };
    cookie_ref.source_port = if cookie_ref.secure { 443 } else { 80 };

    let expires_sec, parse_ok = parse_int(expires_str);
    if parse_ok && expires_sec > 0 {
        cookie_ref.expires_utc = expires_sec * 1000000;
        cookie_ref.persistent = true;
    }
    return true;
}

fn read_json_cookie_member(json_reader: json::Reader&, key: const u8[:], cookie_ref: CanonicalCookie&) {
    var scratch: u8[>..] = [];
    if key == "name" { cookie_ref.name.clear(); cookie_ref.name.append(json::read_string(json_reader, scratch)); }
    else if key == "value" { cookie_ref.value.clear(); cookie_ref.value.append(json::read_string(json_reader, scratch)); }
    else if key == "domain" { cookie_ref.domain.clear(); cookie_ref.domain.append(json::read_string(json_reader, scratch)); }
    else if key == "path" { cookie_ref.path.clear(); cookie_ref.path.append(json::read_string(json_reader, scratch)); }
    else if key == "creation_utc" { cookie_ref.creation_utc = json::read_int(json_reader); }
    else if key == "last_access_utc" { cookie_ref.last_access_utc = json::read_int(json_reader); }
    else if key == "last_update_utc" { cookie_ref.last_update_utc = json::read_int(json_reader); }
    else if key == "expires_utc" { cookie_ref.expires_utc = json::read_int(json_reader); }
    else if key == "host_only" { cookie_ref.host_only = json::read_bool(json_reader); }
    else if key == "persistent" { cookie_ref.persistent = json::read_bool(json_reader); }
    else if key == "secure" { cookie_ref.secure = json::read_bool(json_reader); }
    else if key == "httponly" { cookie_ref.httponly = json::read_bool(json_reader); }
    else if key == "partitioned" { cookie_ref.partitioned = json::read_bool(json_reader); }
    else if key == "partition_key" { cookie_ref.partition_key.clear(); cookie_ref.partition_key.append(json::read_string(json_reader, scratch)); }
    else if key == "same_site" { cookie_ref.same_site = parse_cookie_same_site(json::read_string(json_reader, scratch)); }
    else if key == "priority" { cookie_ref.priority = parse_cookie_priority(json::read_string(json_reader, scratch)); }
    else if key == "source_scheme" {
        let scheme_str = json::read_string(json_reader, scratch);
        cookie_ref.source_scheme = if eq_ascii_fold(scheme_str, "secure") {
            CookieSourceScheme.Secure
        } else if eq_ascii_fold(scheme_str, "nonsecure") {
            CookieSourceScheme.NonSecure
        } else {
            CookieSourceScheme.Unset
        };
    }
    else if key == "source_port" { cookie_ref.source_port = json::read_int(json_reader) as i32; }
    else { json::skip(json_reader); }
}
