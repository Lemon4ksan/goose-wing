// Lexical Analyzer, Set-Cookie Parser & RFC 6265 §5.1.1 Date Tokenizer.
// Clean Room Implementation for goose-wing conforming to Chromium CookieMonster and RFC 6265bis.
namespace wing;

import std;
import core.time;
import cookie.constants;
import cookie.canonical;
import cookie.psl;

// Checks whether s contains prohibited ASCII Control Characters (CTLs: %x00-08 / %x0A-1F / %x7F).
// RFC 6265bis §5.5 Step 1 & §5.7 Step 3 / Chromium Issue #1420 & #1531.
// Note: HTAB (%x09) is non-prohibited horizontal whitespace.
fn has_prohibited_cookie_ctl(s: const u8[:]) -> bool {
    for b in s {
        if (b <= 0x08) || (b >= 0x0A && b <= 0x1F) || b == 0x7F {
            return true;
        }
    }
    return false;
}

// RFC 6265 §5.1.1: delimiter characters for cookie-date tokenization.
// delimiter = %x09 / %x20-2F / %x3B-40 / %x5B-60 / %x7B-7E
fn is_cookie_date_delimiter(b: u8) -> bool {
    return b == 0x09 || (b >= 0x20 && b <= 0x2F) || (b >= 0x3B && b <= 0x40) ||
           (b >= 0x5B && b <= 0x60) || (b >= 0x7B && b <= 0x7E);
}

// Converts a 3-letter month prefix to a 1-based month number [1..12].
fn parse_cookie_month_name(tok: const u8[:]) -> i64 {
    guard tok.len >= 3 else { return 0; }
    var b0 = if tok[0] >= 'A' && tok[0] <= 'Z' { tok[0] + 32 } else { tok[0] };
    var b1 = if tok[1] >= 'A' && tok[1] <= 'Z' { tok[1] + 32 } else { tok[1] };
    var b2 = if tok[2] >= 'A' && tok[2] <= 'Z' { tok[2] + 32 } else { tok[2] };

    if b0 == 'j' && b1 == 'a' && b2 == 'n' { return 1; }
    if b0 == 'f' && b1 == 'e' && b2 == 'b' { return 2; }
    if b0 == 'm' && b1 == 'a' && b2 == 'r' { return 3; }
    if b0 == 'a' && b1 == 'p' && b2 == 'r' { return 4; }
    if b0 == 'm' && b1 == 'a' && b2 == 'y' { return 5; }
    if b0 == 'j' && b1 == 'u' && b2 == 'n' { return 6; }
    if b0 == 'j' && b1 == 'u' && b2 == 'l' { return 7; }
    if b0 == 'a' && b1 == 'u' && b2 == 'g' { return 8; }
    if b0 == 's' && b1 == 'e' && b2 == 'p' { return 9; }
    if b0 == 'o' && b1 == 'c' && b2 == 't' { return 10; }
    if b0 == 'n' && b1 == 'o' && b2 == 'v' { return 11; }
    if b0 == 'd' && b1 == 'e' && b2 == 'c' { return 12; }
    return 0;
}

// Parses an RFC 6265 §5.1.1 cookie date string, returning microsecond UTC timestamp.
// Implements 4-flag greedy token parsing, 2-digit year normalization, leap year checks,
// and 1601 minimum year bound (Windows FILETIME base).
fn parse_cookie_date_us(raw: const u8[:]) -> i64, bool {
    guard raw.len > 0 else { return 0, false; }

    var found_time = false;
    var found_dom = false;
    var found_month = false;
    var found_year = false;

    var hour: i64 = 0;
    var minute: i64 = 0;
    var second: i64 = 0;
    var day: i64 = 0;
    var month: i64 = 0;
    var year: i64 = 0;

    var at = 0;
    while at < raw.len {
        while at < raw.len && is_cookie_date_delimiter(raw[at]) { at++; }
        if at >= raw.len { break; }
        let tok_start = at;
        while at < raw.len && !is_cookie_date_delimiter(raw[at]) { at++; }
        let tok = raw[tok_start..at];

        // 1. Time token: 1*2DIGIT ":" 1*2DIGIT ":" 1*2DIGIT
        if !found_time && tok.len >= 5 {
            var c1 = -1;
            var c2 = -1;
            for i in tok.len {
                if tok[i] == ':' {
                    if c1 < 0 { c1 = i; } else if c2 < 0 { c2 = i; break; }
                }
            }
            if c1 > 0 && c2 > c1 {
                let h_val, h_ok = parse_int(tok[..c1]);
                let m_val, m_ok = parse_int(tok[c1 + 1..c2]);
                let s_val, s_ok = parse_int(tok[c2 + 1..]);
                if h_ok && m_ok && s_ok {
                    hour = h_val;
                    minute = m_val;
                    second = s_val;
                    found_time = true;
                    continue;
                }
            }
        }

        // 2. Day of month token: 1*2DIGIT
        if !found_dom {
            var all_digits = true;
            for b in tok {
                if b < '0' || b > '9' { all_digits = false; break; }
            }
            if all_digits && (tok.len == 1 || tok.len == 2) {
                let d_val, d_ok = parse_int(tok);
                if d_ok && d_val >= 1 && d_val <= 31 {
                    day = d_val;
                    found_dom = true;
                    continue;
                }
            }
        }

        // 3. Month token: 3+ alphabetic characters
        if !found_month {
            let m_val = parse_cookie_month_name(tok);
            if m_val > 0 {
                month = m_val;
                found_month = true;
                continue;
            }
        }

        // 4. Year token: 2*4DIGIT
        if !found_year {
            var all_digits = true;
            for b in tok {
                if b < '0' || b > '9' { all_digits = false; break; }
            }
            if all_digits && (tok.len == 2 || tok.len == 4) {
                let y_val, y_ok = parse_int(tok);
                if y_ok {
                    year = y_val;
                    found_year = true;
                    continue;
                }
            }
        }
    }

    // Step 3: 2-digit year normalization per RFC 6265 §5.1.1
    if year >= 70 && year <= 99 {
        year += 1900;
    } else if year >= 0 && year <= 69 {
        year += 2000;
    }

    // Step 5: Calendar boundaries validation
    guard found_time && found_dom && found_month && found_year else { return 0, false; }
    guard month >= 1 && month <= 12 else { return 0, false; }
    guard day >= 1 && day <= days_in_month(year, month) else { return 0, false; }
    guard year >= 1601 else { return 0, false; }
    guard hour <= 23 && minute <= 59 && second <= 59 else { return 0, false; }

    let total_days = civil_to_days(year, month, day);
    let total_sec = total_days * 86400 + hour * 3600 + minute * 60 + second;
    return total_sec * 1000000, true; // Return microseconds UTC
}

// Ingestion Pipeline: Parses a Set-Cookie header field into CanonicalCookie.
// Implements:
// 1. Strict CTL validation (DELETE_COOKIE_CONTROL_CHAR = 11).
// 2. Separate payload (name+value <= 4096) and attribute (<= 1024) limits.
// 3. DQUOTE preservation in cookie-value.
// 4. Max-Age priority over Expires, with 400-day TTL cap.
// 5. Attribute parsing for HttpOnly, Secure, SameSite, Priority, Partitioned, Domain, Path.
fn parse_canonical_set_cookie(
    header_val: const u8[:],
    default_domain: const u8[:],
    default_path: const u8[:],
    now_us: i64
) -> CanonicalCookie, CookieDeleteCause, bool {
    var c = CanonicalCookie { .. };

    // Step 1: Reject empty header or presence of prohibited CTLs
    if header_val.len == 0 {
        return c, CookieDeleteCause.UNKNOWN, false;
    }
    if has_prohibited_cookie_ctl(header_val) {
        return c, CookieDeleteCause.CONTROL_CHAR, false;
    }

    // Step 2: Separate name-value-pair from unparsed-attributes
    var semi_pos = -1;
    for i in header_val.len {
        if header_val[i] == ';' { semi_pos = i; break; }
    }
    let name_val_part = if semi_pos >= 0 { header_val[..semi_pos] } else { header_val };
    let unparsed_attrs = if semi_pos >= 0 { header_val[semi_pos + 1..] } else { "" };

    // Step 3: Split name and value by first '='
    var eq_pos = -1;
    for i in name_val_part.len {
        if name_val_part[i] == '=' { eq_pos = i; break; }
    }
    guard eq_pos >= 0 else { return c, CookieDeleteCause.UNKNOWN, false; }

    let raw_name = trim(name_val_part[..eq_pos]);
    let raw_val = trim(name_val_part[eq_pos + 1..]);

    guard raw_name.len > 0 else { return c, CookieDeleteCause.UNKNOWN, false; }

    // Unified payload size limit (Issue #1340: name + value <= 4096 bytes)
    if raw_name.len + raw_val.len > K_MAX_COOKIE_NAME_VAL_LEN {
        return c, CookieDeleteCause.UNKNOWN, false;
    }

    c.name.append(raw_name);

    // DQUOTE handling: quotes are PRESERVED in cookie-value per RFC 6265bis §5.6
    c.value.append(raw_val);

    c.domain.append(default_domain);
    to_lower(c.domain[..]);
    c.path.clear();
    c.path.append(default_path);
    c.host_only = true;
    c.creation_utc = now_us;
    c.last_access_utc = now_us;
    c.last_update_utc = now_us;

    var has_max_age = false;

    // Step 4: Iterative unparsed-attributes loop
    if unparsed_attrs.len > 0 {
        each_split(unparsed_attrs, ';') { raw_av =>
            let av = trim(raw_av);
            if av.len > 0 {
                var attr_eq = -1;
                for i in av.len {
                    if av[i] == '=' { attr_eq = i; break; }
                }
                let a_name = if attr_eq >= 0 { trim(av[..attr_eq]) } else { av };
                let a_val = if attr_eq >= 0 { trim(av[attr_eq + 1..]) } else { "" };

                // Attribute value length limit: if > 1024, IGNORE this attribute only!
                if a_val.len <= K_MAX_COOKIE_ATTR_VAL_LEN {
                    if eq_ascii_fold(a_name, "httponly") {
                        c.httponly = true;
                    } else if eq_ascii_fold(a_name, "secure") {
                        c.secure = true;
                    } else if eq_ascii_fold(a_name, "partitioned") {
                        c.partitioned = true;
                    } else if eq_ascii_fold(a_name, "samesite") {
                        c.same_site = parse_cookie_same_site(a_val);
                    } else if eq_ascii_fold(a_name, "priority") {
                        c.priority = parse_cookie_priority(a_val);
                    } else if eq_ascii_fold(a_name, "domain") {
                        if a_val.len > 0 && a_val[a_val.len - 1] != '.' {
                            let clean_dom = if a_val[0] == '.' { a_val[1..] } else { a_val };
                            c.domain.clear();
                            c.domain.append(clean_dom);
                            to_lower(c.domain[..]);
                            c.host_only = false;
                        }
                    } else if eq_ascii_fold(a_name, "path") {
                        if a_val.len > 0 && a_val[0] == '/' {
                            c.path.clear();
                            c.path.append(a_val);
                        }
                    } else if eq_ascii_fold(a_name, "max-age") {
                        let ma_val, ma_ok = parse_int(a_val);
                        if ma_ok {
                            has_max_age = true;
                            c.persistent = true;
                            if ma_val <= 0 {
                                // Expired overwrite
                                c.expires_utc = now_us - 1000000;
                            } else {
                                var delta_us = ma_val * 1000000;
                                if delta_us > K_MAX_COOKIE_AGE_US {
                                    delta_us = K_MAX_COOKIE_AGE_US; // 400 days cap
                                }
                                c.expires_utc = now_us + delta_us;
                            }
                        }
                    } else if eq_ascii_fold(a_name, "expires") {
                        // Max-Age has absolute priority over Expires per RFC 6265 §5.3 Step 3
                        if !has_max_age {
                            let exp_us, exp_ok = parse_cookie_date_us(a_val);
                            if exp_ok {
                                c.persistent = true;
                                if exp_us > now_us && (exp_us - now_us > K_MAX_COOKIE_AGE_US) {
                                    c.expires_utc = now_us + K_MAX_COOKIE_AGE_US; // 400 days cap
                                } else {
                                    c.expires_utc = exp_us;
                                }
                            }
                        }
                    }
                }
            }
        };
    }

    // Step 5: RFC 6265 §5.3 Step 5 & 6 Domain-attribute validation & PSL rejection
    if !c.host_only {
        // Step 5.1: If domain attribute value is a public suffix
        if is_public_suffix_domain(c.domain[..]) {
            if default_domain.len > 0 && eq_ascii_fold(c.domain[..], default_domain) {
                // If domain attribute value matches the canonicalized request-host, convert to host-only
                c.host_only = true;
            } else {
                // Ignore cookie entirely per RFC 6265 §5.3 Step 5
                return c, CookieDeleteCause.UNKNOWN, false;
            }
        }

        // Step 5.2: If canonicalized request-host does not domain-match domain-attribute-value
        if !c.host_only && default_domain.len > 0 {
            if !cookie_domain_match(default_domain, c.domain[..]) {
                // Reject: host is not authorized to set cookie for this domain
                return c, CookieDeleteCause.UNKNOWN, false;
            }
        }
    }

    return c, CookieDeleteCause.UNKNOWN, true;
}

// CanonicalCookieURL represents a dissected URL for cookie routing and origin binding.
struct CanonicalCookieURL {
    scheme: u8[..16] = [],
    host: u8[..256] = [],
    path: u8[..256] = "/",
    port: i32 = 80,
    is_secure: bool = false,
}

// Parses an arbitrary HTTP/HTTPS URL into its CanonicalCookieURL components.
fn parse_canonical_cookie_url(raw_url: const u8[:]) -> CanonicalCookieURL {
    var u = CanonicalCookieURL { .. };
    var rest = raw_url;
    if starts_with(rest, "https://") {
        u.scheme.append("https");
        u.is_secure = true;
        u.port = 443;
        rest = rest[8..];
    } else if starts_with(rest, "http://") {
        u.scheme.append("http");
        u.is_secure = false;
        u.port = 80;
        rest = rest[7..];
    }

    // Split host and path
    var slash_idx = -1;
    for i in rest.len {
        if rest[i] == '/' || rest[i] == '?' {
            slash_idx = i;
            break;
        }
    }
    let host_part = if slash_idx >= 0 { rest[..slash_idx] } else { rest };
    let path_part = if slash_idx >= 0 && rest[slash_idx] == '/' {
        var q_idx = -1;
        for j in slash_idx..rest.len {
            if rest[j] == '?' { q_idx = j; break; }
        }
        if q_idx >= 0 { rest[slash_idx..q_idx] } else { rest[slash_idx..] }
    } else {
        "/"
    };

    // Strip port if present from host, handling IPv6 literals "[::1]:port"
    var bare_host = host_part;
    if host_part.len > 0 && host_part[0] == '[' {
        var close_bracket = -1;
        for i in host_part.len {
            if host_part[i] == ']' { close_bracket = i; break; }
        }
        if close_bracket > 0 {
            bare_host = host_part[1..close_bracket];
            if close_bracket + 1 < host_part.len && host_part[close_bracket + 1] == ':' {
                let p_val, p_ok = parse_int(host_part[close_bracket + 2..]);
                if p_ok && p_val > 0 && p_val <= 65535 {
                    u.port = p_val as i32;
                }
            }
        }
    } else {
        var colon_idx = -1;
        for i in host_part.len {
            if host_part[i] == ':' { colon_idx = i; break; }
        }
        if colon_idx >= 0 {
            bare_host = host_part[..colon_idx];
            let p_val, p_ok = parse_int(host_part[colon_idx + 1..]);
            if p_ok && p_val > 0 && p_val <= 65535 {
                u.port = p_val as i32;
            }
        }
    }

    u.host.append(bare_host);
    to_lower(u.host[..]);

    u.path.clear();
    u.path.append(path_part);
    return u;
}

