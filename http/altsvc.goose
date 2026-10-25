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
    let p_name_raw, p_val_raw, ok = param_str.split_once_byte('=');
    guard ok else { return; }

    let p_name = p_name_raw.trim_lws();
    var p_val = p_val_raw.trim_lws().trim_byte('"');

    if p_name == "ma" {
        let num, num_ok = p_val.parse_u32_dec();
        if num_ok { ep.max_age_sec = num; }
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

        let proto_token_raw, rem_entry_raw, has_eq = entry_str.split_once_byte('=');
        guard has_eq && proto_token_raw.len > 0 else { continue; }

        let proto_token = proto_token_raw.trim_lws();
        let rem_entry = rem_entry_raw.trim_lws();

        var ep = AltSvcEndpoint { .. };
        ep.proto.append(proto_token);

        // Find authority inside quotes: "host:port"
        guard rem_entry.len >= 2 && rem_entry[0] == '"' else { continue; }
        let quote_end = rem_entry[1..].index_of_byte('"');
        guard quote_end >= 0 else { continue; }

        let authority = rem_entry[1..quote_end + 1];
        let params_part = rem_entry[quote_end + 2..];

        // Parse host:port in authority
        let host_part, port_part, has_colon = authority.rsplit_once_byte(':');
        guard has_colon else { continue; }

        if host_part.len > 0 {
            ep.host.append(host_part);
        }

        let port_num, port_ok = port_part.parse_u32_dec();
        guard port_ok && port_num > 0 && port_num <= 65535 else { continue; }
        ep.port = port_num as! u16;

        // Parse parameters: ; ma=...; persist=...
        var p_tok = make_byte_tokenizer(params_part, ';');
        while true {
            let param_token, tok_ok = p_tok.token_next();
            guard tok_ok else { break; }
            let p_trim = param_token.trim_lws();
            if p_trim.len > 0 {
                parse_altsvc_param(p_trim, ep);
            }
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
