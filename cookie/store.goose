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

// Safely appends an SQL single-quoted string with internal quote doubling.
fn append_sql_escaped_string<B>(out: B&, s: const u8[:]) {
    out.push('\'');
    for b in s {
        if b == '\'' {
            out.append("''");
        } else {
            out.push(b);
        }
    }
    out.push('\'');
}

// Serializes a CanonicalCookie into a SQLite V24 INSERT OR REPLACE statement.
fn generate_sqlite_insert_sql<B>(out: B&, c: const CanonicalCookie&) {
    out.append("INSERT OR REPLACE INTO cookies (creation_utc, top_frame_site_key, host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly, last_access_utc, has_expires, is_persistent, priority, samesite, source_scheme, source_port, last_update_utc, source_type, has_cross_site_ancestor) VALUES (");
    format(out, c.creation_utc);
    out.append(", ");
    append_sql_escaped_string(out, c.partition_key[..]);
    out.append(", ");
    append_sql_escaped_string(out, c.domain[..]);
    out.append(", ");
    append_sql_escaped_string(out, c.name[..]);
    out.append(", ");
    append_sql_escaped_string(out, c.value[..]);
    out.append(", '', ");
    append_sql_escaped_string(out, c.path[..]);
    out.append(", ");
    format(out, c.expires_utc);
    out.append(", ");
    format(out, if c.secure { 1 as i64 } else { 0 as i64 });
    out.append(", ");
    format(out, if c.httponly { 1 as i64 } else { 0 as i64 });
    out.append(", ");
    format(out, c.last_access_utc);
    out.append(", ");
    format(out, if c.persistent { 1 as i64 } else { 0 as i64 });
    out.append(", ");
    format(out, if c.persistent { 1 as i64 } else { 0 as i64 });
    out.append(", ");
    format(out, priority_rank(c.priority) as i64);
    out.append(", ");
    let ss_val = match c.same_site {
        Default => 0,
        Lax => 1,
        Strict => 2,
        None => 3,
    };
    format(out, ss_val as i64);
    out.append(", ");
    let sc_val = match c.source_scheme {
        Unset => 0,
        NonSecure => 1,
        Secure => 2,
    };
    format(out, sc_val as i64);
    out.append(", ");
    format(out, c.source_port as i64);
    out.append(", ");
    format(out, c.last_update_utc);
    out.append(", 0, 0);\n");
}

// Serializes a CanonicalCookie deletion into a SQLite V24 DELETE statement.
fn generate_sqlite_delete_sql<B>(out: B&, c: const CanonicalCookie&) {
    out.append("DELETE FROM cookies WHERE top_frame_site_key = ");
    append_sql_escaped_string(out, c.partition_key[..]);
    out.append(" AND host_key = ");
    append_sql_escaped_string(out, c.domain[..]);
    out.append(" AND name = ");
    append_sql_escaped_string(out, c.name[..]);
    out.append(" AND path = ");
    append_sql_escaped_string(out, c.path[..]);
    out.append(" AND source_scheme = ");
    let sc_val = match c.source_scheme {
        Unset => 0,
        NonSecure => 1,
        Secure => 2,
    };
    format(out, sc_val as i64);
    out.append(" AND source_port = ");
    format(out, c.source_port as i64);
    out.append(";\n");
}

// Generates the SQL statement for closing transient / session cookies on exit.
fn generate_sqlite_session_cleanup_sql<B>(out: B&) {
    out.append("DELETE FROM cookies WHERE is_persistent = 0;\n");
}

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

// Tests if two cookies have identical canonical primary key in storage.
fn are_cookies_store_identical(a: const CanonicalCookie&, b: const CanonicalCookie&) -> bool {
    return a.name[..] == b.name[..] &&
           eq_ascii_fold(a.domain[..], b.domain[..]) &&
           a.path[..] == b.path[..] &&
           a.host_only == b.host_only &&
           a.partition_key[..] == b.partition_key[..] &&
           a.source_port == b.source_port &&
           a.source_scheme == b.source_scheme;
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
    op: StoreOpType,
    c: const CanonicalCookie&
) {
    for i in batcher.pending_ops.len {
        if are_cookies_store_identical(batcher.pending_ops[i].cookie, c) {
            let existing_op = batcher.pending_ops[i].op_type;
            if existing_op == StoreOpType.InsertOrUpdate && op == StoreOpType.InsertOrUpdate {
                batcher.pending_ops[i].cookie = c;
                batcher.total_coalesced_ops += 1;
                return;
            }
            if existing_op == StoreOpType.InsertOrUpdate && op == StoreOpType.Delete {
                remove_at(batcher.pending_ops, i);
                batcher.total_coalesced_ops += 1;
                return;
            }
            if existing_op == StoreOpType.Delete && op == StoreOpType.InsertOrUpdate {
                batcher.pending_ops[i].op_type = StoreOpType.InsertOrUpdate;
                batcher.pending_ops[i].cookie = c;
                batcher.total_coalesced_ops += 1;
                return;
            }
            if existing_op == StoreOpType.Delete && op == StoreOpType.Delete {
                batcher.total_coalesced_ops += 1;
                return;
            }
        }
    }

    var pending = PendingStoreOp { .. };
    pending.op_type = op;
    pending.cookie = c;
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
    now_ms: i64
) -> i64 {
    if batcher.pending_ops.len == 0 {
        return 0;
    }

    out_sql.append("BEGIN TRANSACTION;\n");
    let count = batcher.pending_ops.len;

    for i in batcher.pending_ops.len {
        let op = batcher.pending_ops[i];
        if op.op_type == StoreOpType.InsertOrUpdate {
            generate_sqlite_insert_sql(out_sql, op.cookie);
        } else {
            generate_sqlite_delete_sql(out_sql, op.cookie);
        }
    }

    out_sql.append("COMMIT;\n");

    batcher.total_committed_ops += count;
    batcher.pending_ops.clear();
    batcher.last_commit_ms = now_ms;
    return count;
}

// --- Outgoing & Ingoing HTTP Cookie Headers (§5.4) ---

// Serializes a slice of CanonicalCookies into an outgoing HTTP "Cookie: name=value; name2=value2" header.
fn format_cookie_header_value<B>(out: B&, cookies: const CanonicalCookie[:]) {
    for i in cookies.len {
        if i > 0 {
            out.append("; ");
        }
        out.append(cookies[i].name[..]);
        out.push('=');
        out.append(cookies[i].value[..]);
    }
}

// Parses an incoming server-side "Cookie" header string.
// Conforming to RFC 6265bis §5.4: if multiple cookies with the same name are present,
// the server MUST take the FIRST occurrence and ignore duplicate names.
fn parse_server_cookie_header(
    header_raw: const u8[:],
    now_us: i64,
    out: CanonicalCookie[>..]&
) {
    guard header_raw.len > 0 else { return; }

    var start = 0;
    while start < header_raw.len {
        // Find next ';' delimiter
        var end = start;
        while end < header_raw.len && header_raw[end] != ';' {
            end += 1;
        }

        let pair = trim(header_raw[start..end]);
        if pair.len > 0 {
            var eq_idx = -1;
            for i in pair.len {
                if pair[i] == '=' {
                    eq_idx = i;
                    break;
                }
            }

            if eq_idx >= 0 {
                let name = trim(pair[..eq_idx]);
                let val = trim(pair[eq_idx + 1..]);

                // Check for first occurrence invariant (do not overwrite)
                var already_present = false;
                for j in out.len {
                    if out[j].name[..] == name {
                        already_present = true;
                        break;
                    }
                }

                if !already_present && name.len > 0 {
                    var c = CanonicalCookie { .. };
                    c.name.append(name);
                    c.value.append(val);
                    c.creation_utc = now_us;
                    c.last_access_utc = now_us;
                    c.last_update_utc = now_us;
                    out.push(c);
                }
            }
        }

        start = end + 1;
    }
}

// --- Netscape & JSON Export / Import ---

// Exports the CanonicalCookieJar to standard Netscape cookies.txt format.
fn export_canonical_netscape<B>(jar: const CanonicalCookieJar&, out: B&) {
    out.append("# Netscape HTTP Cookie File\n");
    out.append("# Generated by goose-wing Chromium CookieMonster\n\n");

    for i in jar.cookies.len {
        let c = jar.cookies[i];
        if c.httponly {
            out.append("#HttpOnly_");
        }
        out.append(c.domain[..]);
        out.push('\t');
        out.append(if !c.host_only { "TRUE" } else { "FALSE" });
        out.push('\t');
        out.append(c.path[..]);
        out.push('\t');
        out.append(if c.secure { "TRUE" } else { "FALSE" });
        out.push('\t');
        format(out, c.expires_utc / 1000000);
        out.push('\t');
        out.append(c.name[..]);
        out.push('\t');
        out.append(c.value[..]);
        out.push('\n');
    }
}

// Imports cookies from Netscape cookies.txt format into CanonicalCookieJar.
fn import_canonical_netscape(jar: CanonicalCookieJar&, content: const u8[:], now_us: i64) -> i64 {
    guard content.len > 0 else { return 0; }

    var imported: i64 = 0;
    var line_start = 0;

    while line_start < content.len {
        var line_end = line_start;
        while line_end < content.len && content[line_end] != '\n' && content[line_end] != '\r' {
            line_end += 1;
        }

        var line = content[line_start..line_end];
        if line.len > 0 {
            var is_httponly = false;
            if starts_with(line, "#HttpOnly_") {
                is_httponly = true;
                line = line[10..];
            }

            if line.len > 0 && line[0] != '#' {
                // Parse 7 tab-separated columns
                var tabs: i64[>..] = [];
                for i in line.len {
                    if line[i] == '\t' {
                        tabs.push(i);
                    }
                }

                if tabs.len >= 6 {
                    let dom = line[..tabs[0]];
                    let subdom_flag = line[tabs[0] + 1..tabs[1]];
                    let path = line[tabs[1] + 1..tabs[2]];
                    let sec_flag = line[tabs[2] + 1..tabs[3]];
                    let exp_str = line[tabs[3] + 1..tabs[4]];
                    let name = line[tabs[4] + 1..tabs[5]];
                    let val = line[tabs[5] + 1..];

                    var c = CanonicalCookie { .. };
                    c.name.append(name);
                    c.value.append(val);
                    c.domain.append(dom);
                    c.path.clear();
                    c.path.append(path);
                    c.host_only = eq_ascii_fold(subdom_flag, "false");
                    c.secure = eq_ascii_fold(sec_flag, "true");
                    c.httponly = is_httponly;
                    c.source_scheme = if c.secure { CookieSourceScheme.Secure } else { CookieSourceScheme.NonSecure };
                    c.source_port = if c.secure { 443 } else { 80 };

                    let exp_sec, parse_ok = parse_int(exp_str);
                    if parse_ok && exp_sec > 0 {
                        c.expires_utc = exp_sec * 1000000;
                        c.persistent = true;
                    }

                    let ok = set_canonical_cookie(jar, c, true, c.secure, now_us);
                    if ok {
                        imported += 1;
                    }
                }
            }
        }

        // Advance past newline
        line_start = line_end;
        while line_start < content.len && (content[line_start] == '\n' || content[line_start] == '\r') {
            line_start += 1;
        }
    }

    return imported;
}

// Exports the CanonicalCookieJar to structured Chromium V24 JSON format.
fn export_canonical_json<B>(jar: const CanonicalCookieJar&, out: B&) {
    out.push('[');
    for i in jar.cookies.len {
        let c = jar.cookies[i];
        if i > 0 { out.push(','); }
        out.push('{');
        json::format_key(out, "name"); json::format_string(out, c.name[..]); out.push(',');
        json::format_key(out, "value"); json::format_string(out, c.value[..]); out.push(',');
        json::format_key(out, "domain"); json::format_string(out, c.domain[..]); out.push(',');
        json::format_key(out, "path"); json::format_string(out, c.path[..]); out.push(',');
        json::format_key(out, "creation_utc"); json::format_int(out, c.creation_utc); out.push(',');
        json::format_key(out, "last_access_utc"); json::format_int(out, c.last_access_utc); out.push(',');
        json::format_key(out, "last_update_utc"); json::format_int(out, c.last_update_utc); out.push(',');
        json::format_key(out, "expires_utc"); json::format_int(out, c.expires_utc); out.push(',');
        json::format_key(out, "host_only"); json::format_bool(out, c.host_only); out.push(',');
        json::format_key(out, "persistent"); json::format_bool(out, c.persistent); out.push(',');
        json::format_key(out, "secure"); json::format_bool(out, c.secure); out.push(',');
        json::format_key(out, "httponly"); json::format_bool(out, c.httponly); out.push(',');
        json::format_key(out, "partitioned"); json::format_bool(out, c.partitioned); out.push(',');
        json::format_key(out, "partition_key"); json::format_string(out, c.partition_key[..]); out.push(',');
        json::format_key(out, "same_site"); json::format_string(out, same_site_to_string(c.same_site)); out.push(',');
        json::format_key(out, "priority"); json::format_string(out, priority_to_string(c.priority)); out.push(',');
        json::format_key(out, "source_scheme"); json::format_string(out, source_scheme_to_string(c.source_scheme)); out.push(',');
        json::format_key(out, "source_port"); json::format_int(out, c.source_port as i64);
        out.push('}');
    }
    out.push(']');
}

// Imports cookies from structured Chromium V24 JSON format into CanonicalCookieJar.
fn import_canonical_json(jar: CanonicalCookieJar&, json_text: const u8[:], now_us: i64) -> i64 {
    guard json_text.len > 0 else { return 0; }
    var r = json::reader(json_text);
    var imported: i64 = 0;

    json::each_element(r) {
        var c = CanonicalCookie { .. };
        json::each_member(r) { key =>
            var scratch: u8[>..] = [];
            if key == "name" { c.name.clear(); c.name.append(json::read_string(r, scratch)); }
            else if key == "value" { c.value.clear(); c.value.append(json::read_string(r, scratch)); }
            else if key == "domain" { c.domain.clear(); c.domain.append(json::read_string(r, scratch)); }
            else if key == "path" { c.path.clear(); c.path.append(json::read_string(r, scratch)); }
            else if key == "creation_utc" { c.creation_utc = json::read_int(r); }
            else if key == "last_access_utc" { c.last_access_utc = json::read_int(r); }
            else if key == "last_update_utc" { c.last_update_utc = json::read_int(r); }
            else if key == "expires_utc" { c.expires_utc = json::read_int(r); }
            else if key == "host_only" { c.host_only = json::read_bool(r); }
            else if key == "persistent" { c.persistent = json::read_bool(r); }
            else if key == "secure" { c.secure = json::read_bool(r); }
            else if key == "httponly" { c.httponly = json::read_bool(r); }
            else if key == "partitioned" { c.partitioned = json::read_bool(r); }
            else if key == "partition_key" { c.partition_key.clear(); c.partition_key.append(json::read_string(r, scratch)); }
            else if key == "same_site" { c.same_site = parse_cookie_same_site(json::read_string(r, scratch)); }
            else if key == "priority" { c.priority = parse_cookie_priority(json::read_string(r, scratch)); }
            else if key == "source_scheme" {
                let s = json::read_string(r, scratch);
                c.source_scheme = if eq_ascii_fold(s, "secure") { CookieSourceScheme.Secure } else if eq_ascii_fold(s, "nonsecure") { CookieSourceScheme.NonSecure } else { CookieSourceScheme.Unset };
            }
            else if key == "source_port" { c.source_port = json::read_int(r) as i32; }
            else { json::skip(r); }
        };

        if c.name.len > 0 {
            let is_sec_url = c.secure;
            let ok = set_canonical_cookie(jar, c, true, is_sec_url, now_us);
            if ok { imported += 1; }
        }
    };

    return imported;
}
