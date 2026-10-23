// RFC 9111 Section 5.2: Cache-Control and Pragma zero-heap parser.
// Compresses directives into a 16-bit bitmask and handles delta-seconds overflow clamping.
namespace wing;

import std;
import app.profile;
import http.headers;

// ---- cache-control bitmask flags -------------------------------------------

const CC_FLAG_NONE: u16               = 0x0000;
const CC_NO_STORE: u16                = 0x0001; // no-store
const CC_NO_CACHE: u16                = 0x0002; // no-cache (unqualified or qualified)
const CC_MUST_REVALIDATE: u16         = 0x0004; // must-revalidate
const CC_PROXY_REVALIDATE: u16        = 0x0008; // proxy-revalidate
const CC_MUST_UNDERSTAND: u16         = 0x0010; // must-understand (RFC 9111 Section 5.2.2.3)
const CC_PRIVATE: u16                 = 0x0020; // private (unqualified or qualified)
const CC_PUBLIC: u16                  = 0x0040; // public
const CC_IMMUTABLE: u16               = 0x0080; // immutable (RFC 8246)
const CC_ONLY_IF_CACHED: u16          = 0x0100; // only-if-cached (RFC 9111 Section 5.2.1.7)
const CC_NO_TRANSFORM: u16            = 0x0200; // no-transform
const CC_INVALID_FRESHNESS: u16       = 0x0400; // corrupted/non-digit max-age/s-maxage/min-fresh -> lifetime = 0
const CC_HAS_MAX_AGE: u16             = 0x0800; // max-age=delta-seconds
const CC_HAS_S_MAXAGE: u16            = 0x1000; // s-maxage=delta-seconds
const CC_HAS_MAX_STALE: u16           = 0x2000; // max-stale[=delta-seconds]
const CC_HAS_MIN_FRESH: u16           = 0x4000; // min-fresh=delta-seconds
const CC_STALE_WHILE_REVALIDATE: u16  = 0x8000; // stale-while-revalidate=delta-seconds (RFC 5861)

const MAX_DELTA_SECONDS: i32 = 2147483647; // i32::MAX overflow clamp per RFC 9111 Section 1.2.2

// ---- cache-control structure -----------------------------------------------

struct CacheControl {
    flags: u16 = 0,
    max_age: i32 = -1,
    s_maxage: i32 = -1,
    max_stale: i32 = -1, // -1 with CC_HAS_MAX_STALE means unbounded max-stale
    min_fresh: i32 = -1,
    stale_while_revalidate: i32 = -1,
    private_fields: u8[..64][..8] = [],
    no_cache_fields: u8[..64][..8] = [],
}

fn new_cache_control() -> CacheControl {
    return CacheControl { .. };
}

// Flag inspectors

fn has_flag(cc: const CacheControl&, flag: u16) -> bool {
    return (cc.flags & flag) == flag;
}

fn is_no_store(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_NO_STORE) != 0;
}

fn is_no_cache(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_NO_CACHE) != 0;
}

fn is_must_revalidate(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_MUST_REVALIDATE) != 0;
}

fn is_proxy_revalidate(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_PROXY_REVALIDATE) != 0;
}

fn is_must_understand(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_MUST_UNDERSTAND) != 0;
}

fn is_private(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_PRIVATE) != 0;
}

fn is_public(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_PUBLIC) != 0;
}

fn is_immutable(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_IMMUTABLE) != 0;
}

fn is_only_if_cached(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_ONLY_IF_CACHED) != 0;
}

fn is_no_transform(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_NO_TRANSFORM) != 0;
}

fn has_invalid_freshness(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_INVALID_FRESHNESS) != 0;
}

fn has_max_age(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_HAS_MAX_AGE) != 0;
}

fn has_s_maxage(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_HAS_S_MAXAGE) != 0;
}

fn has_max_stale(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_HAS_MAX_STALE) != 0;
}

fn has_min_fresh(cc: const CacheControl&) -> bool {
    return (cc.flags & CC_HAS_MIN_FRESH) != 0;
}

// Checks if a given field name is covered by qualified private="..."
fn is_private_field(cc: const CacheControl&, field_name: const u8[:]) -> bool {
    guard (cc.flags & CC_PRIVATE) != 0 else { return false; }
    if cc.private_fields.len == 0 {
        return true; // unqualified private applies to entire response
    }
    for &f in cc.private_fields {
        if eq_ascii_fold(f[..], field_name) {
            return true;
        }
    }
    return false;
}

// Checks if a given field name is covered by qualified no-cache="..."
fn is_no_cache_field(cc: const CacheControl&, field_name: const u8[:]) -> bool {
    guard (cc.flags & CC_NO_CACHE) != 0 else { return false; }
    if cc.no_cache_fields.len == 0 {
        return true; // unqualified no-cache applies to entire response
    }
    for &f in cc.no_cache_fields {
        if eq_ascii_fold(f[..], field_name) {
            return true;
        }
    }
    return false;
}

// ---- delta-seconds parsing with overflow clamp ------------------------------

// RFC 9111 Section 1.2.2: delta-seconds = 1*DIGIT
// Clamps values exceeding 2147483647 (i32::MAX) to MAX_DELTA_SECONDS.
// Strips optional surrounding quotes (e.g. "3600").
// Returns val, ok.
fn parse_delta_seconds(raw_val: const u8[:]) -> i32, bool {
    var s = trim_lws(raw_val);
    if s.len >= 2 && s[0] == '"' && s[s.len - 1] == '"' {
        s = trim_lws(s[1..s.len - 1]);
    }
    guard s.len > 0 else { return 0, false; }

    var acc: i64 = 0;
    var overflow = false;
    for b in s {
        guard b >= '0' && b <= '9' else {
            return 0, false;
        }
        let digit = (b - '0');
        acc = acc * 10 + digit;
        if acc > MAX_DELTA_SECONDS {
            overflow = true;
            acc = MAX_DELTA_SECONDS;
        }
    }
    return acc as i32, true;
}

// Extracts comma-separated or quoted field names into a fixed-capacity list
fn parse_field_names(raw_val: const u8[:], out_fields: u8[..64][..8]&) {
    var s = trim_lws(raw_val);
    if s.len >= 2 && s[0] == '"' && s[s.len - 1] == '"' {
        s = trim_lws(s[1..s.len - 1]);
    }
    guard s.len > 0 else { return; }

    var cursor: i64 = 0;
    while cursor < s.len {
        var end_idx = cursor;
        while end_idx < s.len && s[end_idx] != ',' {
            end_idx++;
        }
        let name_tok = trim_lws(s[cursor..end_idx]);
        if name_tok.len > 0 && out_fields.len < 8 {
            var buf: u8[..64] = [];
            buf.append(name_tok);
            out_fields.push(buf);
        }
        cursor = end_idx + 1;
    }
}

// ---- cache-control string parser -------------------------------------------

// Parses a single Cache-Control header line or comma-separated token stream.
fn parse_cache_control_str(raw: const u8[:], cc: CacheControl&, ignore_cargo_cult: bool = true) {
    var cursor: i64 = 0;
    let len = raw.len;

    while cursor < len {
        // Skip leading whitespace or commas
        while cursor < len && (raw[cursor] == ' ' || raw[cursor] == '\t' || raw[cursor] == ',') {
            cursor++;
        }
        guard cursor < len else { break; }

        // Find token end (either ',' or end of string, taking care of quoted strings)
        var token_end = cursor;
        var in_quotes = false;
        while token_end < len {
            let b = raw[token_end];
            if b == '"' {
                in_quotes = !in_quotes;
            } else if b == ',' && !in_quotes {
                break;
            }
            token_end++;
        }

        let directive_slice = trim_lws(raw[cursor..token_end]);
        cursor = token_end + 1;
        guard directive_slice.len > 0 else { continue; }

        // Split into name and optional value around '='
        var equal_idx: i64 = -1;
        for i in directive_slice.len {
            if directive_slice[i] == '=' {
                equal_idx = i;
                break;
            }
        }

        let name = if equal_idx >= 0 {
            trim_lws(directive_slice[..equal_idx])
        } else {
            directive_slice
        };

        let val = if equal_idx >= 0 {
            trim_lws(directive_slice[equal_idx + 1..])
        } else {
            ""
        };

        // Match directives case-insensitively (RFC 9111 Section 5.2)
        if eq_ascii_fold(name, "no-store") {
            cc.flags |= CC_NO_STORE;
        } else if eq_ascii_fold(name, "no-cache") {
            cc.flags |= CC_NO_CACHE;
            if val.len > 0 {
                parse_field_names(val, cc.no_cache_fields);
            }
        } else if eq_ascii_fold(name, "must-revalidate") {
            cc.flags |= CC_MUST_REVALIDATE;
        } else if eq_ascii_fold(name, "proxy-revalidate") {
            cc.flags |= CC_PROXY_REVALIDATE;
        } else if eq_ascii_fold(name, "must-understand") {
            cc.flags |= CC_MUST_UNDERSTAND;
        } else if eq_ascii_fold(name, "public") {
            cc.flags |= CC_PUBLIC;
        } else if eq_ascii_fold(name, "private") {
            cc.flags |= CC_PRIVATE;
            if val.len > 0 {
                parse_field_names(val, cc.private_fields);
            }
        } else if eq_ascii_fold(name, "immutable") {
            cc.flags |= CC_IMMUTABLE;
        } else if eq_ascii_fold(name, "only-if-cached") {
            cc.flags |= CC_ONLY_IF_CACHED;
        } else if eq_ascii_fold(name, "no-transform") {
            cc.flags |= CC_NO_TRANSFORM;
        } else if eq_ascii_fold(name, "max-age") {
            let secs, ok = parse_delta_seconds(val);
            if ok {
                cc.flags |= CC_HAS_MAX_AGE;
                cc.max_age = secs;
            } else {
                // Non-digit/corrupted delta-seconds: mark invalid freshness (RFC 9111 Section 4.2.1)
                cc.flags |= CC_INVALID_FRESHNESS;
            }
        } else if eq_ascii_fold(name, "s-maxage") {
            let secs, ok = parse_delta_seconds(val);
            if ok {
                cc.flags |= CC_HAS_S_MAXAGE;
                cc.s_maxage = secs;
            } else {
                cc.flags |= CC_INVALID_FRESHNESS;
            }
        } else if eq_ascii_fold(name, "max-stale") {
            cc.flags |= CC_HAS_MAX_STALE;
            if val.len > 0 {
                let secs, ok = parse_delta_seconds(val);
                if ok {
                    cc.max_stale = secs;
                } else {
                    // Invalid max-stale value: treat as unbounded or ignore corrupted value
                    cc.max_stale = -1;
                }
            } else {
                cc.max_stale = -1; // Unbounded max-stale
            }
        } else if eq_ascii_fold(name, "min-fresh") {
            let secs, ok = parse_delta_seconds(val);
            if ok {
                cc.flags |= CC_HAS_MIN_FRESH;
                cc.min_fresh = secs;
            } else {
                cc.flags |= CC_INVALID_FRESHNESS;
            }
        } else if eq_ascii_fold(name, "stale-while-revalidate") {
            let secs, ok = parse_delta_seconds(val);
            if ok {
                cc.flags |= CC_STALE_WHILE_REVALIDATE;
                cc.stale_while_revalidate = secs;
            }
        } else if ignore_cargo_cult && (eq_ascii_fold(name, "pre-check") || eq_ascii_fold(name, "post-check")) {
            // Legacy IE directives (e.g. pre-check=0, post-check=0) ignored safely
        }
    }
}

// Parses all Cache-Control (and optional Pragma fallback) headers from HeaderMap
fn parse_cache_control_headers(map: const HeaderMap&, is_request: bool = false, ignore_cargo_cult: bool = true) -> CacheControl {
    var cc = new_cache_control();
    var has_cc_header = false;

    // Scan all Cache-Control header entries in map
    for entry in map.entries {
        let name = map.raw_buf[entry.name_begin..entry.name_end];
        if eq_ascii_fold(name, "cache-control") {
            has_cc_header = true;
            let val = map.raw_buf[entry.values_begin..entry.values_end];
            parse_cache_control_str(val, cc, ignore_cargo_cult);
        }
    }

    // RFC 9111 Section 5.4: Pragma: no-cache fallback
    // When Cache-Control is absent, "Pragma: no-cache" is treated as "Cache-Control: no-cache".
    if !has_cc_header {
        let pragma_val = get_header(map, "pragma");
        if pragma_val.len > 0 {
            // Check if pragma contains no-cache
            var cursor: i64 = 0;
            while cursor < pragma_val.len {
                var end_idx = cursor;
                while end_idx < pragma_val.len && pragma_val[end_idx] != ',' {
                    end_idx++;
                }
                let tok = trim_lws(pragma_val[cursor..end_idx]);
                if eq_ascii_fold(tok, "no-cache") {
                    cc.flags |= CC_NO_CACHE;
                    break;
                }
                cursor = end_idx + 1;
            }
        }
    }

    return cc;
}
