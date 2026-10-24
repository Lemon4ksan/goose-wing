// HTTP Alternative Services (RFC 7838 Alt-Svc) Engine.
// Zero-heap parser, cache, and automatic HTTP/3 connection promotion manager.
// - Supports `h3=":443"; ma=86400; persist=1`, `clear`, multiple alternative entries
// - Manages per-origin alternative service mapping with TTL (`ma`) and failure backoff
// - Seamlessly promotes TCP (H1/H2) connections to UDP (HTTP/3 / QUIC)
namespace wing;

import std;
import http.headers;

// ---- 1. Alt-Svc Models & Constants -----------------------------------------

struct AltSvcEndpoint {
    proto: u8[..16] = [],           // e.g. "h3", "h2"
    host: u8[..128] = [],           // Alternate host (empty if same as origin)
    port: u16 = 443,
    max_age_sec: u32 = 86400,       // Default 24 hours per RFC 7838 Section 3.1
    persist: bool = false,          // Survives network change if true
}

struct AltSvcOriginEntry {
    origin: u8[..128] = [],         // e.g. "example.com:443"
    endpoints: AltSvcEndpoint[..4] = [],
    inserted_at_sec: i64 = 0,
    failed_attempts: u8 = 0,        // Consecutive connection failures for backoff
    broken_until_sec: i64 = 0,      // Exponential backoff timestamp
    valid: bool = false,
}

struct AltSvcCache {
    entries: AltSvcOriginEntry[..64] = [],
}

fn new_altsvc_cache() -> AltSvcCache {
    return AltSvcCache { .. };
}

// ---- 2. RFC 7838 Header Parser ---------------------------------------------

// Parses single parameter token: e.g. `ma=86400` or `persist=1`
fn parse_altsvc_param(param_str: const u8[:], ep: AltSvcEndpoint&) {
    var eq_pos: i64 = -1;
    for i in param_str.len {
        if param_str[i] == '=' {
            eq_pos = i;
            break;
        }
    }
    guard eq_pos > 0 else { return; }

    let p_name = trim_lws(param_str[..eq_pos]);
    var p_val = trim_lws(param_str[eq_pos + 1..]);

    if p_val.len >= 2 && p_val[0] == '"' && p_val[p_val.len - 1] == '"' {
        p_val = p_val[1..p_val.len - 1];
    }

    if p_name == "ma" {
        var num: u32 = 0;
        var ok = p_val.len > 0;
        for b in p_val {
            if b >= '0' && b <= '9' {
                num = num * 10 + (b - '0');
            } else {
                ok = false;
                break;
            }
        }
        if ok { ep.max_age_sec = num; }
    } else if p_name == "persist" {
        if p_val == "1" {
            ep.persist = true;
        }
    }
}

// Parses `Alt-Svc` header value (RFC 7838 Section 3):
// e.g. `h3=":443"; ma=86400; persist=1, h2="alt.example.com:8443"`
// or `clear`
fn parse_altsvc_header<E>(raw: const u8[:], out_endpoints: E&) -> bool, bool {
    let trimmed = trim_lws(raw);
    if trimmed == "clear" {
        return true, true; // is_clear = true
    }

    var cursor: i64 = 0;
    while cursor < trimmed.len {
        while cursor < trimmed.len && (trimmed[cursor] == ' ' || trimmed[cursor] == '\t' || trimmed[cursor] == ',') {
            cursor++;
        }
        if cursor == trimmed.len { break; }

        // Find end of current alternative service (next unquoted comma or end of string)
        var entry_end = trimmed.len;
        var in_quotes = false;
        var i = cursor;
        while i < trimmed.len {
            let b = trimmed[i];
            if b == '"' {
                in_quotes = !in_quotes;
            } else if b == ',' && !in_quotes {
                entry_end = i;
                break;
            }
            i++;
        }

        let entry_str = trim_lws(trimmed[cursor..entry_end]);
        cursor = if entry_end < trimmed.len { entry_end + 1 } else { trimmed.len };
        if entry_str.len == 0 { continue; }

        // Format of entry: proto="host:port" *( ";" param )
        var eq_pos: i64 = -1;
        for idx in entry_str.len {
            if entry_str[idx] == '=' {
                eq_pos = idx;
                break;
            }
        }
        guard eq_pos > 0 else { continue; }

        let proto_token = trim_lws(entry_str[..eq_pos]);
        let rem_entry = trim_lws(entry_str[eq_pos + 1..]);

        var ep = AltSvcEndpoint { .. };
        ep.proto.append(proto_token);

        // Find authority inside quotes: "host:port"
        guard rem_entry.len >= 2 && rem_entry[0] == '"' else { continue; }
        var quote_end: i64 = -1;
        for idx in 1..rem_entry.len {
            if rem_entry[idx] == '"' {
                quote_end = idx;
                break;
            }
        }
        guard quote_end > 0 else { continue; }

        let authority = rem_entry[1..quote_end];
        let params_part = rem_entry[quote_end + 1..];

        // Parse host:port in authority
        var colon_pos: i64 = -1;
        for idx in authority.len {
            if authority[idx] == ':' {
                colon_pos = idx;
                break;
            }
        }
        guard colon_pos >= 0 else { continue; }

        let host_part = authority[..colon_pos];
        let port_part = authority[colon_pos + 1..];

        if host_part.len > 0 {
            ep.host.append(host_part);
        }

        var port_num: u16 = 0;
        var port_ok = port_part.len > 0;
        for b in port_part {
            if b >= '0' && b <= '9' {
                port_num = port_num * 10 + ((b - '0') as u16);
            } else {
                port_ok = false;
                break;
            }
        }
        guard port_ok && port_num > 0 else { continue; }
        ep.port = port_num;

        // Parse parameters: ; ma=...; persist=...
        var p_cursor: i64 = 0;
        while p_cursor < params_part.len {
            while p_cursor < params_part.len && (params_part[p_cursor] == ' ' || params_part[p_cursor] == '\t' || params_part[p_cursor] == ';') {
                p_cursor++;
            }
            if p_cursor == params_part.len { break; }

            var next_semi = params_part.len;
            for p_idx in p_cursor..params_part.len {
                if params_part[p_idx] == ';' {
                    next_semi = p_idx;
                    break;
                }
            }

            let param_token = trim_lws(params_part[p_cursor..next_semi]);
            parse_altsvc_param(param_token, ep);
            p_cursor = if next_semi < params_part.len { next_semi + 1 } else { params_part.len };
        }

        out_endpoints.push(ep);
    }

    return true, false;
}

// ---- 3. Alt-Svc Cache Operations -------------------------------------------

// Inserts or updates an Alt-Svc mapping for an origin (RFC 7838 Section 3)
fn altsvc_cache_update(
    cache: AltSvcCache&,
    origin: const u8[:],
    raw_altsvc: const u8[:],
    now_sec: i64
) {
    var endpoints: AltSvcEndpoint[..4] = [];
    let ok, is_clear = parse_altsvc_header(raw_altsvc, endpoints);
    guard ok else { return; }

    // If "clear", invalidate origin entry
    if is_clear {
        for i in cache.entries.len {
            if cache.entries[i].valid && cache.entries[i].origin[..] == origin {
                cache.entries[i].valid = false;
                return;
            }
        }
        return;
    }

    guard endpoints.len > 0 else { return; }

    // Update existing origin
    for i in cache.entries.len {
        if cache.entries[i].valid && cache.entries[i].origin[..] == origin {
            cache.entries[i].endpoints.clear();
            for ep in endpoints { cache.entries[i].endpoints.push(ep); }
            cache.entries[i].inserted_at_sec = now_sec;
            // RFC 7838 Section 2.4 & Chromium HttpServerProperties:
            // Receiving an Alt-Svc header advertisement MUST NOT clear an active broken-backoff state!
            if now_sec >= cache.entries[i].broken_until_sec {
                cache.entries[i].failed_attempts = 0;
                cache.entries[i].broken_until_sec = 0;
            }
            return;
        }
    }

    // Insert new origin
    var entry = AltSvcOriginEntry {
        inserted_at_sec: now_sec,
        valid: true,
        ..
    };
    entry.origin.append(origin);
    for ep in endpoints { entry.endpoints.push(ep); }

    if cache.entries.len < 64 {
        cache.entries.push(entry);
    } else {
        // Evict oldest or invalid entry
        var oldest_idx: i64 = 0;
        var oldest_time = cache.entries[0].inserted_at_sec;
        for i in cache.entries.len {
            if !cache.entries[i].valid {
                oldest_idx = i;
                break;
            }
            if cache.entries[i].inserted_at_sec < oldest_time {
                oldest_time = cache.entries[i].inserted_at_sec;
                oldest_idx = i;
            }
        }
        cache.entries[oldest_idx] = entry;
    }
}

// Queries Alt-Svc cache for HTTP/3 ("h3") endpoint promotion
fn altsvc_lookup_h3(
    cache: const AltSvcCache&,
    origin: const u8[:],
    now_sec: i64,
    out_ep: AltSvcEndpoint&
) -> bool {
    for &entry in cache.entries {
        if entry.valid && entry.origin[..] == origin {
            // Check if marked broken (failure backoff)
            if now_sec < entry.broken_until_sec {
                return false;
            }

            for &ep in entry.endpoints {
                if ep.proto[..] == "h3" {
                    let elapsed = now_sec - entry.inserted_at_sec;
                    if elapsed < ep.max_age_sec {
                        out_ep = ep;
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

// Records an alternative service connection failure with exponential backoff (Chromium/Mach model)
fn altsvc_record_failure(cache: AltSvcCache&, origin: const u8[:], now_sec: i64) {
    for i in cache.entries.len {
        if cache.entries[i].valid && cache.entries[i].origin[..] == origin {
            cache.entries[i].failed_attempts++;
            let shift = if cache.entries[i].failed_attempts > 6 { 6 } else { cache.entries[i].failed_attempts };
            // Backoff: 5s, 10s, 20s, 40s, 80s, 160s, max 320s
            let backoff_sec: i64 = 5 * (1 << (shift - 1));
            cache.entries[i].broken_until_sec = now_sec + backoff_sec;
            return;
        }
    }
}

// Records an alternative service connection success, resetting consecutive failures and clearing broken status.
fn altsvc_record_success(cache: AltSvcCache&, origin: const u8[:]) {
    for i in cache.entries.len {
        if cache.entries[i].valid && cache.entries[i].origin[..] == origin {
            cache.entries[i].failed_attempts = 0;
            cache.entries[i].broken_until_sec = 0;
            return;
        }
    }
}

// Checks if an origin's alternative service is currently marked broken (within exponential backoff).
fn altsvc_is_broken(cache: const AltSvcCache&, origin: const u8[:], now_sec: i64) -> bool {
    for &entry in cache.entries {
        if entry.valid && entry.origin[..] == origin {
            return now_sec < entry.broken_until_sec;
        }
    }
    return false;
}

// Returns the number of consecutive failure attempts recorded for an origin.
fn altsvc_failed_attempts(cache: const AltSvcCache&, origin: const u8[:]) -> u8 {
    for &entry in cache.entries {
        if entry.valid && entry.origin[..] == origin {
            return entry.failed_attempts;
        }
    }
    return 0;
}

// ---- 4. Server-Side Serializer ---------------------------------------------

// Formats standard Alt-Svc header string: e.g. `h3=":443"; ma=86400; persist=1`
fn format_altsvc_header<B>(out: B&, proto: const u8[:], port: u16, max_age_sec: u32 = 86400, persist: bool = true) {
    out.append(proto);
    out.append("=\":");
    format(out, port);
    out.append("\"; ma=");
    format(out, max_age_sec);
    if persist {
        out.append("; persist=1");
    }
}
