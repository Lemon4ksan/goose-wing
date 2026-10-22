// Test Suite for Industrial HTTP Cookie Jar
// Combining Steps 1 through 6 into a single unified verification suite
// Conforming to Chromium CookieMonster & IETF RFC 6265 / RFC 6265bis specifications.
import std;
import wing from "..";

fn assert(cond: bool, msg: const u8[:]) {
    if !cond {
        print("FAIL: ", msg);
        abort(msg);
    } else {
        print("  PASS: ", msg);
    }
}

fn contains_substr(haystack: const u8[:], needle: const u8[:]) -> bool {
    if needle.len == 0 { return true; }
    if haystack.len < needle.len { return false; }
    for i in (haystack.len - needle.len + 1) {
        if haystack[i..i + needle.len] == needle {
            return true;
        }
    }
    return false;
}

fn make_test_cookie(
    name: const u8[:],
    val: const u8[:],
    domain: const u8[:],
    path: const u8[:],
    host_only: bool,
    secure: bool,
    prio: wing::CookiePriority
) -> wing::CanonicalCookie {
    var c = wing::CanonicalCookie { .. };
    c.name.append(name);
    c.value.append(val);
    c.domain.append(domain);
    c.path.clear();
    c.path.append(path);
    c.host_only = host_only;
    c.secure = secure;
    c.priority = prio;
    c.source_scheme = if secure { wing::CookieSourceScheme.Secure } else { wing::CookieSourceScheme.NonSecure };
    c.source_port = if secure { 443 } else { 80 };
    return c;
}

// =====================================================================================
// STEP 1: Canonical Cookie Model & Architectural Invariants
// =====================================================================================
fn test_step1_canonical_model() {
    print("=== Step 1: Canonical Cookie Model & Architectural Invariants ===");

    // 1. Constants verification
    assert(wing::K_MINUTES_IN_400_DAYS == 576000, "kMinutesIn400Days is 576000 minutes");
    assert(wing::K_MAX_COOKIE_AGE_US == 34560000000000, "400 days in microseconds is 34,560,000,000,000 us");
    assert(wing::K_MAX_COOKIE_NAME_VAL_LEN == 4096, "Payload limit is 4096 bytes");
    assert(wing::K_MAX_COOKIE_ATTR_VAL_LEN == 1024, "Attribute limit is 1024 bytes");
    assert(wing::K_DOMAIN_MAX_COOKIES == 180, "Domain max cookies is 180");
    assert(wing::K_DOMAIN_PURGE_COOKIES == 30, "Domain purge count is 30");
    assert(wing::K_DOMAIN_COOKIES_QUOTA_LOW == 30, "Low priority domain quota is 30");
    assert(wing::K_DOMAIN_COOKIES_QUOTA_MEDIUM == 50, "Medium priority domain quota is 50");
    assert(wing::K_DOMAIN_COOKIES_QUOTA_HIGH == 70, "High priority domain quota is 70");
    assert(wing::K_MAX_COOKIES == 3300, "Global max cookies is 3300");
    assert(wing::K_PURGE_COOKIES == 300, "Global purge count is 300");
    assert(wing::K_SAFE_FROM_GLOBAL_PURGE_DAYS == 30, "Safe from global purge is 30 days");
    assert(wing::K_LAX_ALLOWING_UNSAFE_WINDOW_US == 120000000, "Lax-allowing-unsafe window is 120 seconds (120,000,000 us)");
    assert(wing::K_PER_PARTITION_DOMAIN_MAX_COOKIE_BYTES == 10240, "CHIPS partition domain quota is 10240 bytes (10KB)");

    // 2. CanonicalCookie creation and default values
    var c = wing::CanonicalCookie { .. };
    c.name.append("__Host-id");
    c.value.append("12345");
    c.domain.append("example.com");
    c.path.clear();
    c.path.append("/");
    c.host_only = true;
    c.creation_utc = 1000000;
    c.last_access_utc = 1000000;
    c.last_update_utc = 1000000;
    c.expires_utc = 1000000 + wing::K_MAX_COOKIE_AGE_US;
    c.persistent = true;
    c.secure = true;
    c.httponly = true;
    c.same_site = wing::CookieSameSite.Strict;
    c.priority = wing::CookiePriority.High;
    c.source_scheme = wing::CookieSourceScheme.Secure;
    c.source_port = 443;

    assert(c.name[..] == "__Host-id", "Name preserved");
    assert(c.value[..] == "12345", "Value preserved");
    assert(c.host_only == true, "host_only is true");
    assert(c.secure == true, "secure is true");
    assert(c.httponly == true, "httponly is true");
    assert(c.same_site == wing::CookieSameSite.Strict, "same_site is Strict");
    assert(c.priority == wing::CookiePriority.High, "priority is High");
    assert(c.source_port == 443, "source_port is 443");

    // 3. Serialization
    var s_buf: u8[..256] = [];
    wing::format(s_buf, c);
    assert(find(s_buf[..], "__Host-id=12345") >= 0, "Contains name=value");
    assert(find(s_buf[..], "Secure") >= 0, "Contains Secure");
    assert(find(s_buf[..], "HttpOnly") >= 0, "Contains HttpOnly");
    assert(find(s_buf[..], "SameSite=Strict") >= 0, "Contains SameSite=Strict");
    assert(find(s_buf[..], "Priority=High") >= 0, "Contains Priority=High");

    // 4. Delete cause codes
    assert(wing::delete_cause_code(wing::CookieDeleteCause.EXPIRED_OVERWRITE) == 10, "EXPIRED_OVERWRITE code is 10");
    assert(wing::delete_cause_code(wing::CookieDeleteCause.CONTROL_CHAR) == 11, "CONTROL_CHAR code is 11");
    assert(wing::delete_cause_code(wing::CookieDeleteCause.NON_SECURE) == 12, "NON_SECURE code is 12");

    print("  -> Step 1 Complete: Model & Invariants Verified!\n");
}

// =====================================================================================
// STEP 2: Public Suffix List (PSL), eTLD+1 & Scope Matching
// =====================================================================================
fn test_step2_psl_and_matching() {
    print("=== Step 2: Public Suffix List (PSL), eTLD+1 & Matching Engine ===");

    // 1. IP address detection
    assert(wing::is_ip_address_literal("127.0.0.1"), "IPv4 127.0.0.1 detected");
    assert(wing::is_ip_address_literal("192.168.1.1"), "IPv4 192.168.1.1 detected");
    assert(!wing::is_ip_address_literal("256.1.1.1"), "IPv4 octet > 255 rejected");
    assert(!wing::is_ip_address_literal("1.2.3.4.5"), "IPv4 with 5 octets rejected");
    assert(wing::is_ip_address_literal("::1"), "IPv6 loopback ::1 detected");
    assert(wing::is_ip_address_literal("2001:db8::1"), "IPv6 address detected");
    assert(!wing::is_ip_address_literal("example.com"), "Domain name is not IP");

    // 2. Public Suffix detection
    assert(wing::is_public_suffix_domain("com"), ".com is public suffix");
    assert(wing::is_public_suffix_domain(".com"), ".com with leading dot is public suffix");
    assert(wing::is_public_suffix_domain("co.uk"), ".co.uk is 2-level public suffix");
    assert(wing::is_public_suffix_domain("com.ru"), ".com.ru is 2-level public suffix");
    assert(wing::is_public_suffix_domain("spb.ru"), ".spb.ru is 2-level public suffix");
    assert(!wing::is_public_suffix_domain("example.com"), "example.com is NOT a public suffix");

    // 3. eTLD+1 extraction
    var etld_buf: u8[..128] = [];

    wing::extract_etld_plus_one("example.com", etld_buf);
    assert(etld_buf[..] == "example.com", "eTLD+1 for example.com == example.com");

    wing::extract_etld_plus_one("sub.example.com", etld_buf);
    assert(etld_buf[..] == "example.com", "eTLD+1 for sub.example.com == example.com");

    wing::extract_etld_plus_one("deep.sub.example.com", etld_buf);
    assert(etld_buf[..] == "example.com", "eTLD+1 for deep.sub.example.com == example.com");

    wing::extract_etld_plus_one("service.co.uk", etld_buf);
    assert(etld_buf[..] == "service.co.uk", "eTLD+1 for service.co.uk == service.co.uk");

    wing::extract_etld_plus_one("app.service.co.uk", etld_buf);
    assert(etld_buf[..] == "service.co.uk", "eTLD+1 for app.service.co.uk == service.co.uk");

    wing::extract_etld_plus_one("portal.spb.ru", etld_buf);
    assert(etld_buf[..] == "portal.spb.ru", "eTLD+1 for portal.spb.ru == portal.spb.ru");

    wing::extract_etld_plus_one("sub.portal.spb.ru", etld_buf);
    assert(etld_buf[..] == "portal.spb.ru", "eTLD+1 for sub.portal.spb.ru == portal.spb.ru");

    wing::extract_etld_plus_one("localhost", etld_buf);
    assert(etld_buf[..] == "localhost", "eTLD+1 for intranet localhost == localhost");

    wing::extract_etld_plus_one("192.168.1.10", etld_buf);
    assert(etld_buf[..] == "192.168.1.10", "eTLD+1 for IPv4 literal == 192.168.1.10");

    // 4. Domain-Match (RFC 6265 §5.1.3)
    assert(wing::cookie_domain_match("example.com", "example.com"), "Identical domain matches");
    assert(wing::cookie_domain_match("sub.example.com", "example.com"), "Subdomain matches domain");
    assert(wing::cookie_domain_match("sub.example.com", ".example.com"), "Matches with leading dot stripped");
    assert(!wing::cookie_domain_match("example.com", "sub.example.com"), "Parent domain cannot match child domain");
    assert(!wing::cookie_domain_match("notexample.com", "example.com"), "Substring without dot does NOT match");
    assert(!wing::cookie_domain_match("192.168.1.1", "168.1.1"), "IP literal suffix match blocked");

    // 5. Default-Path (RFC 6265 §5.1.4)
    var p_buf: u8[..128] = [];
    wing::default_cookie_path_calc("/v1/users/42", p_buf);
    assert(p_buf[..] == "/v1/users", "Default-path for /v1/users/42 is /v1/users");

    wing::default_cookie_path_calc("/v1/users", p_buf);
    assert(p_buf[..] == "/v1", "Default-path for /v1/users is /v1");

    wing::default_cookie_path_calc("/file", p_buf);
    assert(p_buf[..] == "/", "Default-path for /file is /");

    wing::default_cookie_path_calc("/", p_buf);
    assert(p_buf[..] == "/", "Default-path for / is /");

    // 6. Path-Match (RFC 6265 §5.1.4)
    assert(wing::cookie_path_match("/foo", "/foo"), "/foo matches /foo");
    assert(wing::cookie_path_match("/foo/bar", "/foo"), "/foo/bar matches /foo");
    assert(wing::cookie_path_match("/foo/bar", "/foo/"), "/foo/bar matches /foo/");
    assert(!wing::cookie_path_match("/foobar", "/foo"), "/foobar does NOT match /foo (slash boundary enforced)");
    assert(!wing::cookie_path_match("/bar", "/foo"), "/bar does not match /foo");

    print("  -> Step 2 Complete: PSL, eTLD+1 & Scoping Verified!\n");
}

// =====================================================================================
// STEP 3: Ingestion Pipeline, Limits & RFC 6265 Date Parser
// =====================================================================================
fn test_step3_parser_and_dates() {
    print("=== Step 3: Ingestion Pipeline, Size Limits & RFC 6265 Date Parser ===");

    let now_us: i64 = 1700000000 * 1000000; // Reference timestamp: ~2023-11-14 22:13:20 UTC

    // 1. Control character rejection (RFC 6265bis §5.5 & Chromium Issue #1420)
    let c1, cause1, ok1 = wing::parse_canonical_set_cookie("session=bad\r\nval; Path=/", "example.com", "/", now_us);
    assert(!ok1, "CRLF in Set-Cookie rejected");
    assert(cause1 == wing::CookieDeleteCause.CONTROL_CHAR, "Delete cause is CONTROL_CHAR (11)");

    let c_null, cause_null, ok_null = wing::parse_canonical_set_cookie("session=bad\x00val", "example.com", "/", now_us);
    assert(!ok_null, "Null byte %x00 in Set-Cookie rejected");
    assert(cause_null == wing::CookieDeleteCause.CONTROL_CHAR, "Delete cause is CONTROL_CHAR (11)");

    let c_del, cause_del, ok_del = wing::parse_canonical_set_cookie("session=bad\x7Fval", "example.com", "/", now_us);
    assert(!ok_del, "Delete char %x7F in Set-Cookie rejected");
    assert(cause_del == wing::CookieDeleteCause.CONTROL_CHAR, "Delete cause is CONTROL_CHAR (11)");

    // Horizontal Tab (%x09) is permitted whitespace
    let c_tab, cause_tab, ok_tab = wing::parse_canonical_set_cookie("session=good\tval; Path=/", "example.com", "/", now_us);
    assert(ok_tab, "Horizontal tab HTAB (%x09) is accepted");

    // 2. Payload size limit (Issue #1340 / M95+: name + value <= 4096 bytes)
    var huge_val: u8[..4200] = [];
    for i in 4100 { huge_val.push('a'); }
    var huge_cookie: u8[..4300] = [];
    huge_cookie.append("key=");
    huge_cookie.append(huge_val[..]);
    huge_cookie.append("; Path=/");

    let c_huge, cause_huge, ok_huge = wing::parse_canonical_set_cookie(huge_cookie[..], "example.com", "/", now_us);
    assert(!ok_huge, "Payload exceeding 4096 bytes is rejected");

    // 3. Attribute size limit (M95+: attr <= 1024 bytes; if exceeded, ignore attribute only)
    var huge_path_val: u8[..1200] = [];
    huge_path_val.push('/');
    for i in 1100 { huge_path_val.push('x'); }

    var cookie_huge_attr: u8[..1400] = [];
    cookie_huge_attr.append("test=val; Path=");
    cookie_huge_attr.append(huge_path_val[..]);

    let c_attr, cause_attr, ok_attr = wing::parse_canonical_set_cookie(cookie_huge_attr[..], "example.com", "/default", now_us);
    assert(ok_attr, "Cookie with > 1024 byte attribute is NOT rejected");
    assert(c_attr.value[..] == "val", "Cookie payload preserved");
    assert(c_attr.path[..] == "/default", "Excessive Path attribute was ignored, fell back to default_path");

    // 4. DQUOTE preservation (RFC 6265bis §5.6)
    let c_quote, _, ok_quote = wing::parse_canonical_set_cookie("token=\"jwt-secret-xyz-123\"; Path=/", "example.com", "/", now_us);
    assert(ok_quote, "Quoted cookie parsed successfully");
    assert(c_quote.value[..] == "\"jwt-secret-xyz-123\"", "DQUOTEs are PRESERVED in value");

    // 5. RFC 6265 §5.1.1 Date Tokenizer
    let t_rfc1123, ok_r1123 = wing::parse_cookie_date_us("Wed, 09 Jun 2021 10:18:14 GMT");
    assert(ok_r1123, "RFC 1123 date parsed");
    assert(t_rfc1123 == 1623233894 * 1000000, "RFC 1123 timestamp in microseconds verified");

    // 2-digit year normalization: 21 -> 2021, 75 -> 1975
    let t_rfc850, ok_r850 = wing::parse_cookie_date_us("Wednesday, 09-Jun-21 10:18:14 GMT");
    assert(ok_r850, "RFC 850 2-digit year parsed");
    assert(t_rfc850 == t_rfc1123, "Year 21 correctly normalized to 2021");

    let t_70s, ok_70s = wing::parse_cookie_date_us("Monday, 09-Jun-75 10:18:14 GMT");
    assert(ok_70s, "2-digit year 75 parsed");
    let t_70s_expected, _ = wing::parse_cookie_date_us("Monday, 09-Jun-1975 10:18:14 GMT");
    assert(t_70s == t_70s_expected, "Year 75 normalized to 1975");

    // Leap year verification
    let _, ok_leap = wing::parse_cookie_date_us("Sun, 29 Feb 2004 12:00:00 GMT");
    assert(ok_leap, "Feb 29 on leap year 2004 is valid");

    let _, ok_nonleap = wing::parse_cookie_date_us("Mon, 29 Feb 2005 12:00:00 GMT");
    assert(!ok_nonleap, "Feb 29 on non-leap year 2005 is invalid and rejected");

    // Year before 1601 is rejected
    let _, ok_old = wing::parse_cookie_date_us("Mon, 01 Jan 1500 00:00:00 GMT");
    assert(!ok_old, "Year < 1601 rejected");

    // 6. Max-Age priority and 400-day TTL cap
    let c_ma, _, ok_ma = wing::parse_canonical_set_cookie(
        "auth=token; Max-Age=3600; Expires=Wed, 09 Jun 2021 10:18:14 GMT; Path=/",
        "example.com",
        "/",
        now_us
    );
    assert(ok_ma, "Parsed cookie with both Max-Age and Expires");
    assert(c_ma.expires_utc == now_us + 3600 * 1000000, "Max-Age took precedence over past Expires date");

    // Max-Age <= 0 expired overwrite
    let c_exp_ma, _, ok_exp_ma = wing::parse_canonical_set_cookie("auth=del; Max-Age=0; Path=/", "example.com", "/", now_us);
    assert(ok_exp_ma, "Max-Age=0 parsed");
    assert(c_exp_ma.expires_utc < now_us, "Max-Age=0 marks cookie expired in past");

    // 400-day cap on Max-Age
    let c_cap_ma, _, ok_cap_ma = wing::parse_canonical_set_cookie("long=term; Max-Age=100000000; Path=/", "example.com", "/", now_us);
    assert(ok_cap_ma, "Huge Max-Age parsed");
    assert(c_cap_ma.expires_utc == now_us + wing::K_MAX_COOKIE_AGE_US, "Max-Age capped at 400 days (576,000 minutes)");

    // 7. SameSite & Priority attributes
    let c_attrs, _, ok_attrs = wing::parse_canonical_set_cookie(
        "sec=1; SameSite=Strict; Priority=High; Secure; HttpOnly; Partitioned",
        "example.com",
        "/",
        now_us
    );
    assert(ok_attrs, "Parsed full security attributes");
    assert(c_attrs.same_site == wing::CookieSameSite.Strict, "SameSite is Strict");
    assert(c_attrs.priority == wing::CookiePriority.High, "Priority is High");
    assert(c_attrs.secure == true, "Secure is true");
    assert(c_attrs.httponly == true, "HttpOnly is true");
    assert(c_attrs.partitioned == true, "Partitioned is true");

    print("  -> Step 3 Complete: Ingestion & Date Parser Verified!\n");
}

// =====================================================================================
// STEP 4: Multi-tier Isolation, Prefixes, SameSite & OBC Policy
// =====================================================================================
fn test_step4_policy_and_isolation() {
    print("=== Step 4: Multi-tier Isolation, Prefixes, SameSite & OBC Policy ===");

    let now_us: i64 = 1700000000 * 1000000;

    // 1. Prefix: __Secure-
    var c_sec = wing::CanonicalCookie { .. };
    c_sec.name.append("__Secure-token");
    c_sec.value.append("123");
    c_sec.secure = false; // Missing secure
    assert(!wing::validate_canonical_cookie_security(c_sec, true, true), "__Secure- rejected without Secure flag");

    c_sec.secure = true;
    assert(!wing::validate_canonical_cookie_security(c_sec, false, true), "__Secure- rejected over insecure HTTP");
    assert(wing::validate_canonical_cookie_security(c_sec, true, true), "__Secure- accepted on HTTPS with Secure");

    // 2. Prefix: __Host-
    var c_host = wing::CanonicalCookie { .. };
    c_host.name.append("__Host-token");
    c_host.value.append("123");
    c_host.secure = true;
    c_host.host_only = false; // Has Domain
    c_host.path.clear(); c_host.path.append("/");
    assert(!wing::validate_canonical_cookie_security(c_host, true, true), "__Host- rejected with Domain attribute");

    c_host.host_only = true;
    c_host.path.clear(); c_host.path.append("/api");
    assert(!wing::validate_canonical_cookie_security(c_host, true, true), "__Host- rejected with Path != /");

    c_host.path.clear(); c_host.path.append("/");
    assert(wing::validate_canonical_cookie_security(c_host, true, true), "__Host- accepted with Secure, host_only, Path=/");

    // 3. Prefixes: __Http- and __Host-Http- (draft-ietf-httpbis-layered-cookies)
    var c_http = wing::CanonicalCookie { .. };
    c_http.name.append("__Http-session");
    c_http.value.append("secret");
    c_http.secure = true;
    c_http.httponly = false; // Missing HttpOnly
    assert(!wing::validate_canonical_cookie_security(c_http, true, true), "__Http- rejected without HttpOnly");

    c_http.httponly = true;
    assert(!wing::validate_canonical_cookie_security(c_http, true, false), "__Http- rejected when written from non-HTTP script API");
    assert(wing::validate_canonical_cookie_security(c_http, true, true), "__Http- accepted over HTTP with Secure + HttpOnly");

    var c_host_http = wing::CanonicalCookie { .. };
    c_host_http.name.append("__Host-Http-session");
    c_host_http.value.append("max_isolated");
    c_host_http.secure = true;
    c_host_http.httponly = true;
    c_host_http.host_only = true;
    c_host_http.path.clear(); c_host_http.path.append("/");
    assert(!wing::validate_canonical_cookie_security(c_host_http, true, false), "__Host-Http- rejected from script API");
    assert(wing::validate_canonical_cookie_security(c_host_http, true, true), "__Host-Http- accepted on HTTP with full isolation");

    // Case-insensitivity rejection in script API
    assert(!wing::validate_script_cookie_name("__HTTP-evil"), "__HTTP- uppercase blocked in script API");
    assert(!wing::validate_script_cookie_name("__HOST-HTTP-evil"), "__HOST-HTTP- uppercase blocked in script API");
    assert(wing::validate_script_cookie_name("custom_cookie"), "Normal cookie name allowed in script API");

    // 4. SameSite Incrementalism & Lax-allowing-unsafe (2-minute window)
    var c_lax_def = wing::CanonicalCookie { .. };
    c_lax_def.name.append("sso_login");
    c_lax_def.same_site = wing::CookieSameSite.Default;
    c_lax_def.creation_utc = now_us;

    // Inside 2-minute window:
    let now_plus_1min = now_us + 60 * 1000000;
    assert(
        wing::is_cookie_sendable_for_samesite(c_lax_def, false, true, false, now_plus_1min),
        "SameSite=Default allowed in top-level cross-site POST inside 2-minute Lax+POST window"
    );

    // Outside 2-minute window (3 minutes after creation):
    let now_plus_3min = now_us + 180 * 1000000;
    assert(
        !wing::is_cookie_sendable_for_samesite(c_lax_def, false, true, false, now_plus_3min),
        "SameSite=Default BLOCKED in top-level cross-site POST after 2-minute window elapsed"
    );
    assert(
        wing::is_cookie_sendable_for_samesite(c_lax_def, false, true, true, now_plus_3min),
        "SameSite=Default still allowed for safe GET navigation after 2 minutes (standard Lax)"
    );

    // SameSite=None strictly requires Secure
    var c_none = wing::CanonicalCookie { .. };
    c_none.name.append("cross_embed");
    c_none.same_site = wing::CookieSameSite.None;
    c_none.secure = false;
    assert(!wing::validate_canonical_cookie_security(c_none, true, true), "SameSite=None rejected without Secure flag");
    c_none.secure = true;
    assert(wing::validate_canonical_cookie_security(c_none, true, true), "SameSite=None accepted with Secure flag");

    // 5. Schemeful Same-Site (scheme, eTLD+1)
    assert(
        wing::is_schemeful_same_site("https", "sub.example.com", "https", "example.com"),
        "https://sub.example.com and https://example.com are same-site"
    );
    assert(
        !wing::is_schemeful_same_site("http", "example.com", "https", "example.com"),
        "http://example.com and https://example.com are CROSS-SITE (Schemeful Same-Site boundary)"
    );

    // 6. Origin-Bound Cookies (OBC) & Port Isolation
    var c_obc = wing::CanonicalCookie { .. };
    c_obc.name.append("service_cookie");
    c_obc.host_only = true;
    c_obc.source_scheme = wing::CookieSourceScheme.Secure;
    c_obc.source_port = 8443;

    assert(wing::is_cookie_sendable_for_obc(c_obc, "https", 8443), "Host-only cookie sent to matching port 8443");
    assert(!wing::is_cookie_sendable_for_obc(c_obc, "https", 443), "Host-only cookie BLOCKED on differing port 443");

    // Domain cookies opt-out of port isolation
    c_obc.host_only = false;
    assert(wing::is_cookie_sendable_for_obc(c_obc, "https", 443), "Domain cookie sent to port 443 (opt-out of port isolation)");

    // Trustworthy non-cryptographic URL port rewrite (localhost port 80 -> 443)
    var c_local = wing::CanonicalCookie { .. };
    c_local.secure = true;
    wing::adjust_origin_bound_cookies_on_insert(c_local, "localhost", 80, false);
    assert(c_local.source_port == 443, "Localhost port 80 with Secure rewritten to 443");
    assert(c_local.source_scheme == wing::CookieSourceScheme.Secure, "Localhost source_scheme set to Secure");

    // 7. CHIPS Partitioned requirement
    var c_chips = wing::CanonicalCookie { .. };
    c_chips.name.append("part_cookie");
    c_chips.partitioned = true;
    c_chips.secure = false;
    assert(!wing::validate_canonical_cookie_security(c_chips, true, true), "Partitioned cookie rejected without Secure flag");
    c_chips.secure = true;
    assert(wing::validate_canonical_cookie_security(c_chips, true, true), "Partitioned cookie accepted with Secure flag");

    print("  -> Step 4 Complete: Security, SameSite & OBC Verified!\n");
}

// =====================================================================================
// STEP 5: Memory Management, 2-Level Indexing & Garbage Collection Engine
// =====================================================================================
fn test_step5_engine_and_gc() {
    print("=== Step 5: Memory Management, 2-Level Indexing & Garbage Collection Engine ===");

    // 1. Collision Resolution & creation_utc Invariant
    var jar = wing::new_canonical_cookie_jar();
    let t0: i64 = 1000000000;
    let t1: i64 = 2000000000;

    var c1 = make_test_cookie("sess_id", "val_alpha", "example.com", "/", false, true, wing::CookiePriority.Medium);
    let ok1 = wing::set_canonical_cookie(jar, c1, true, true, t0);
    assert(ok1, "Initial cookie inserted successfully");
    assert(jar.cookies.len == 1, "Jar has exactly 1 cookie");
    assert(jar.cookies[0].creation_utc == t0, "Initial creation_utc matches t0");
    assert(jar.cookies[0].value[..] == "val_alpha", "Initial value is val_alpha");

    // Overwrite the cookie with new value at t1
    var c1_update = make_test_cookie("sess_id", "val_omega", "example.com", "/", false, true, wing::CookiePriority.High);
    let ok1_up = wing::set_canonical_cookie(jar, c1_update, true, true, t1);
    assert(ok1_up, "Cookie overwrite accepted");
    assert(jar.cookies.len == 1, "Jar still has 1 cookie after collision update");
    assert(jar.cookies[0].value[..] == "val_omega", "Value updated to val_omega");
    assert(jar.cookies[0].priority == wing::CookiePriority.High, "Priority updated to High");
    assert(jar.cookies[0].creation_utc == t0, "CRITICAL: creation_utc PRESERVED across overwrite (t0)");
    assert(jar.cookies[0].last_update_utc == t1, "last_update_utc updated to t1");
    assert(jar.cookies[0].last_access_utc == t1, "last_access_utc updated to t1");
    assert(jar.overwritten_count == 1, "overwritten_count telemetry incremented");

    // 2. RFC 6265bis §5.6 / Chromium: Insecure Overwrite / Shadowing Blocking
    var c_secure = make_test_cookie("csrf_token", "super_secret", "secure.bank.com", "/", true, true, wing::CookiePriority.High);
    let ok_sec = wing::set_canonical_cookie(jar, c_secure, true, true, t1);
    assert(ok_sec, "Secure cookie installed over HTTPS");

    // Insecure channel attempt to overwrite csrf_token
    var c_insecure = make_test_cookie("csrf_token", "tampered", "secure.bank.com", "/", true, false, wing::CookiePriority.Low);
    let ok_insec = wing::set_canonical_cookie(jar, c_insecure, true, false, t1 + 100);
    assert(!ok_insec, "Non-secure channel BLOCKED from overwriting Secure cookie");
    assert(jar.rejected_security_count >= 1, "rejected_security_count telemetry recorded");

    // Verify original cookie remains intact
    var found_sec = false;
    for i in jar.cookies.len {
        if jar.cookies[i].name[..] == "csrf_token" {
            assert(jar.cookies[i].value[..] == "super_secret", "Secure cookie payload unmodified");
            assert(jar.cookies[i].secure, "Secure cookie flag untouched");
            found_sec = true;
        }
    }
    assert(found_sec, "Secure cookie preserved");

    // 3. Domain Garbage Collection: Step 1 Expired Eviction
    var jar_exp = wing::new_canonical_cookie_jar();
    jar_exp.max_cookies_per_domain = 2; // custom threshold to test GC trigger
    jar_exp.target_cookies_per_domain = 2;

    var c_alive = make_test_cookie("alive", "1", "api.test.com", "/", false, false, wing::CookiePriority.Medium);
    c_alive.persistent = true;
    c_alive.expires_utc = t1 + 10000000; // expires in future

    var c_dead1 = make_test_cookie("dead1", "1", "api.test.com", "/", false, false, wing::CookiePriority.Medium);
    c_dead1.persistent = true;
    c_dead1.expires_utc = t1 - 1000; // already expired!

    var c_dead2 = make_test_cookie("dead2", "1", "api.test.com", "/", false, false, wing::CookiePriority.Medium);
    c_dead2.persistent = true;
    c_dead2.expires_utc = t1 - 2000; // already expired!

    wing::set_canonical_cookie(jar_exp, c_alive, true, false, t1);
    wing::set_canonical_cookie(jar_exp, c_dead1, true, false, t1);
    wing::set_canonical_cookie(jar_exp, c_dead2, true, false, t1);

    assert(jar_exp.evicted_expired_count >= 1, "Expired cookies purged during domain ingestion");
    var has_dead = false;
    for i in jar_exp.cookies.len {
        if jar_exp.cookies[i].name[..] == "dead1" || jar_exp.cookies[i].name[..] == "dead2" {
            has_dead = true;
        }
    }
    assert(!has_dead, "Expired cookies successfully evicted from jar");

    // 4. Domain GC: Chromium 6-Round Priority Quota Invariants
    // Invariant: High Non-Secure is evicted BEFORE Medium Secure (Round 4 before Round 5)!
    var jar_prio = wing::new_canonical_cookie_jar();
    jar_prio.max_cookies_per_domain = 1; // Trigger when > 1
    jar_prio.target_cookies_per_domain = 1;
    jar_prio.quota_low = 0;
    jar_prio.quota_medium = 1; // Medium has quota for 1
    jar_prio.quota_high = 0;   // High has quota 0 (so any High cookie is excess)

    var c_med_sec = make_test_cookie("med_sec", "val", "prio.com", "/", false, true, wing::CookiePriority.Medium);
    var c_hi_nonsec = make_test_cookie("hi_nonsec", "val", "prio.com", "/", false, false, wing::CookiePriority.High);

    wing::set_canonical_cookie(jar_prio, c_med_sec, true, true, t1);
    wing::set_canonical_cookie(jar_prio, c_hi_nonsec, true, false, t1 + 10);

    assert(jar_prio.cookies.len == 1, "Domain reduced to target count 1");
    assert(jar_prio.cookies[0].name[..] == "med_sec", "High Non-Secure evicted BEFORE Medium Secure (Round 4 vs Round 5)");

    // 5. Domain GC: OBC (Origin-Bound Cookies) Priority Invariant
    var jar_obc = wing::new_canonical_cookie_jar();
    jar_obc.max_cookies_per_domain = 1; // Trigger when > 1
    jar_obc.target_cookies_per_domain = 1;
    jar_obc.quota_low = 1;

    var c_host = make_test_cookie("host_only_c", "val", "site.com", "/", true, false, wing::CookiePriority.Low);
    var c_domain = make_test_cookie("domain_c", "val", "site.com", "/", false, false, wing::CookiePriority.Low);

    wing::set_canonical_cookie(jar_obc, c_host, true, false, t1);
    wing::set_canonical_cookie(jar_obc, c_domain, true, false, t1 + 50);

    assert(jar_obc.cookies.len == 1, "Domain reduced to target count 1");
    assert(jar_obc.cookies[0].name[..] == "host_only_c", "OBC: Domain cookie evicted BEFORE Host-only cookie");

    // 6. Domain GC Full Hysteresis (181 -> 150 cookies)
    var jar_full = wing::new_canonical_cookie_jar();
    assert(jar_full.max_cookies_per_domain == 180, "Default max_cookies_per_domain is 180");
    assert(jar_full.target_cookies_per_domain == 150, "Default target_cookies_per_domain is 150");

    for i in 181 {
        var name_buf: u8[..32] = [];
        name_buf.append("cookie_");
        format(name_buf, i);

        let prio = if i < 40 { wing::CookiePriority.Low } else if i < 110 { wing::CookiePriority.Medium } else { wing::CookiePriority.High };
        let sec = (i % 2 == 0);
        var c = make_test_cookie(name_buf[..], "x", "massive.com", "/", false, sec, prio);
        wing::set_canonical_cookie(jar_full, c, true, sec, t1 + i * 100);
    }

    let final_domain_count = wing::count_domain_cookies(jar_full, "massive.com");
    assert(final_domain_count == 150, "Full Domain GC automatically purged 181 down to 150 target");
    assert(jar_full.evicted_domain_count == 31, "Exactly 31 cookies evicted during domain purge (181 - 150)");

    // 7. Global Garbage Collection & 30-Day Purge Immunity
    var jar_glob = wing::new_canonical_cookie_jar();
    jar_glob.max_cookies_global = 4;
    jar_glob.target_cookies_global = 2;

    let now_test_us = t1 + wing::K_SAFE_FROM_GLOBAL_PURGE_US + 100000000;

    var c_recent = make_test_cookie("recent_active", "val", "active.com", "/", true, false, wing::CookiePriority.Low);
    c_recent.last_access_utc = now_test_us - 1000000; // 1 second ago
    c_recent.creation_seq = 1;

    var c_old1 = make_test_cookie("old_1", "val", "old1.com", "/", true, false, wing::CookiePriority.Low);
    c_old1.last_access_utc = now_test_us - (35 * 86400 * 1000000);
    c_old1.creation_seq = 2;

    var c_old2 = make_test_cookie("old_2", "val", "old2.com", "/", true, false, wing::CookiePriority.Low);
    c_old2.last_access_utc = now_test_us - (40 * 86400 * 1000000);
    c_old2.creation_seq = 3;

    var c_old3 = make_test_cookie("old_3", "val", "old3.com", "/", true, false, wing::CookiePriority.Low);
    c_old3.last_access_utc = now_test_us - (50 * 86400 * 1000000);
    c_old3.creation_seq = 4;

    var c_old4 = make_test_cookie("old_4", "val", "old4.com", "/", true, false, wing::CookiePriority.Low);
    c_old4.last_access_utc = now_test_us - (60 * 86400 * 1000000);
    c_old4.creation_seq = 5;

    jar_glob.cookies.push(c_recent);
    jar_glob.cookies.push(c_old1);
    jar_glob.cookies.push(c_old2);
    jar_glob.cookies.push(c_old3);
    jar_glob.cookies.push(c_old4);

    wing::garbage_collect_global(jar_glob, now_test_us);

    assert(jar_glob.cookies.len == 2, "Global GC purged cookies down to target 2");
    var recent_survived = false;
    for i in jar_glob.cookies.len {
        if jar_glob.cookies[i].name[..] == "recent_active" {
            recent_survived = true;
        }
    }
    assert(recent_survived, "30-Day Purge Immunity: Recently accessed cookie was PROTECTED from global eviction");

    // 8. CHIPS 10KB Quota Enforcement
    var jar_chips = wing::new_canonical_cookie_jar();
    var pkey: u8[..256] = [];
    pkey.append("https://parent.site");

    var large_val: u8[..4096] = [];
    for k in 3800 { large_val.push('X'); }

    var p1 = make_test_cookie("chip1", large_val[..], "child.site", "/", true, true, wing::CookiePriority.Medium);
    p1.partitioned = true;
    p1.partition_key.append(pkey[..]);

    var p2 = make_test_cookie("chip2", large_val[..], "child.site", "/", true, true, wing::CookiePriority.Medium);
    p2.partitioned = true;
    p2.partition_key.append(pkey[..]);

    var p3 = make_test_cookie("chip3", large_val[..], "child.site", "/", true, true, wing::CookiePriority.Medium);
    p3.partitioned = true;
    p3.partition_key.append(pkey[..]);

    wing::set_canonical_cookie(jar_chips, p1, true, true, t1);
    wing::set_canonical_cookie(jar_chips, p2, true, true, t1 + 100);
    wing::set_canonical_cookie(jar_chips, p3, true, true, t1 + 200);

    var total_chips_bytes: i64 = 0;
    for i in jar_chips.cookies.len {
        let c = jar_chips.cookies[i];
        if c.partitioned {
            total_chips_bytes += (wing::payload_size(c) + c.domain.len + c.path.len);
        }
    }
    assert(total_chips_bytes <= wing::K_PER_PARTITION_DOMAIN_MAX_COOKIE_BYTES, "CHIPS 10KB memory quota strictly enforced");
    assert(jar_chips.evicted_chips_count >= 1, "Oldest partitioned cookies evicted to respect 10KB cap");

    // 9. Outgoing Request Cookie Matching & RFC 6265 §5.4 Path/Creation Sorting
    var jar_req = wing::new_canonical_cookie_jar();
    var r1 = make_test_cookie("cookie_short", "v1", "site.com", "/app", false, false, wing::CookiePriority.Medium);
    var r2 = make_test_cookie("cookie_long_old", "v2", "site.com", "/app/v1/api", false, false, wing::CookiePriority.Medium);
    var r3 = make_test_cookie("cookie_long_new", "v3", "site.com", "/app/v1/api", false, false, wing::CookiePriority.Medium);
    var r4 = make_test_cookie("cookie_mid", "v4", "site.com", "/app/v1", false, false, wing::CookiePriority.Medium);

    wing::set_canonical_cookie(jar_req, r1, true, false, t1);
    wing::set_canonical_cookie(jar_req, r2, true, false, t0);
    wing::set_canonical_cookie(jar_req, r3, true, false, t1);
    wing::set_canonical_cookie(jar_req, r4, true, false, t1);

    var matched: wing::CanonicalCookie[>..] = [];
    wing::get_canonical_cookies_for_request(
        jar_req,
        "site.com",
        "/app/v1/api/endpoint",
        "http",
        80,
        false,
        true,
        "",
        t1 + 500,
        matched
    );

    assert(matched.len == 4, "All 4 cookies matched request path");
    assert(matched[0].name[..] == "cookie_long_old", "1st: Longest path + oldest creation_utc (RFC 6265 §5.4)");
    assert(matched[1].name[..] == "cookie_long_new", "2nd: Longest path + newer creation_utc");
    assert(matched[2].name[..] == "cookie_mid", "3rd: Medium path length");
    assert(matched[3].name[..] == "cookie_short", "4th: Shortest path length");
    assert(matched[0].last_access_utc == t1 + 500, "last_access_utc updated on request read (LRA tracking)");

    print("  -> Step 5 Complete: Memory Engine, GC & Indexing Verified!\n");
}

// =====================================================================================
// STEP 6: Persistence Engine, SQLite V24, Write-Back Batcher & Serialization
// =====================================================================================
fn test_step6_store_and_persistence() {
    print("=== Step 6: Persistence Engine, SQLite V24, Write-Back Batcher & Serialization ===");

    // 1. SQLite V24 Schema DDL Generation
    var ddl_buf: u8[>..] = [];
    wing::generate_sqlite_v24_schema(ddl_buf);

    assert(contains_substr(ddl_buf[..], "CREATE TABLE meta"), "Schema includes meta table");
    assert(contains_substr(ddl_buf[..], "'version', 24"), "Meta specifies schema version 24");
    assert(contains_substr(ddl_buf[..], "'last_compatible_version', 24"), "Meta specifies last_compatible_version 24");
    assert(contains_substr(ddl_buf[..], "CREATE TABLE cookies"), "Schema includes cookies table");
    assert(contains_substr(ddl_buf[..], "top_frame_site_key TEXT NOT NULL"), "Cookies table includes top_frame_site_key (CHIPS)");
    assert(contains_substr(ddl_buf[..], "creation_utc INTEGER NOT NULL"), "Cookies table includes creation_utc");
    assert(contains_substr(ddl_buf[..], "last_update_utc INTEGER NOT NULL"), "Cookies table includes last_update_utc (V18+)");
    assert(contains_substr(ddl_buf[..], "source_scheme INTEGER NOT NULL"), "Cookies table includes source_scheme (OBC)");
    assert(contains_substr(ddl_buf[..], "source_port INTEGER NOT NULL"), "Cookies table includes source_port (OBC)");
    assert(contains_substr(ddl_buf[..], "INDEX is_transient ON cookies(is_persistent) WHERE is_persistent = 0"), "Partial index for transient/session cookies");

    // 2. SQL Statement Generation & Escaping
    var c_sql = wing::CanonicalCookie { .. };
    c_sql.name.append("pref's");
    c_sql.value.append("val'ue");
    c_sql.domain.append("example.com");
    c_sql.path.clear();
    c_sql.path.append("/shop");
    c_sql.creation_utc = 1700000000000000;
    c_sql.last_access_utc = 1700000001000000;
    c_sql.last_update_utc = 1700000001000000;
    c_sql.expires_utc = 1730000000000000;
    c_sql.persistent = true;
    c_sql.secure = true;
    c_sql.httponly = true;
    c_sql.priority = wing::CookiePriority.High;
    c_sql.same_site = wing::CookieSameSite.Strict;
    c_sql.source_scheme = wing::CookieSourceScheme.Secure;
    c_sql.source_port = 443;

    var insert_sql: u8[>..] = [];
    wing::generate_sqlite_insert_sql(insert_sql, c_sql);
    assert(contains_substr(insert_sql[..], "INSERT OR REPLACE INTO cookies"), "Generated INSERT OR REPLACE");
    assert(contains_substr(insert_sql[..], "'pref''s'"), "Single quotes in name safely escaped as ''");
    assert(contains_substr(insert_sql[..], "'val''ue'"), "Single quotes in value safely escaped as ''");
    assert(contains_substr(insert_sql[..], "1700000000000000"), "Microsecond creation timestamp included");

    var delete_sql: u8[>..] = [];
    wing::generate_sqlite_delete_sql(delete_sql, c_sql);
    assert(contains_substr(delete_sql[..], "DELETE FROM cookies WHERE"), "Generated DELETE SQL");
    assert(contains_substr(delete_sql[..], "host_key = 'example.com'"), "DELETE targets matching host_key");

    var cleanup_sql: u8[>..] = [];
    wing::generate_sqlite_session_cleanup_sql(cleanup_sql);
    assert(contains_substr(cleanup_sql[..], "DELETE FROM cookies WHERE is_persistent = 0;"), "Generated session cookies cleanup SQL");

    // 3. Write-Back Batching Engine with Operation Coalescing
    var batcher = wing::new_write_back_batcher();
    assert(batcher.max_batch_size == 512, "Default max_batch_size is 512");
    assert(batcher.commit_interval_ms == 30000, "Default commit_interval_ms is 30,000 ms");

    var c_mut = wing::CanonicalCookie { .. };
    c_mut.name.append("counter");
    c_mut.value.append("1");
    c_mut.domain.append("app.io");

    // Enqueue 1st update
    wing::queue_store_mutation(batcher, wing::StoreOpType.InsertOrUpdate, c_mut);
    assert(batcher.pending_ops.len == 1, "Queue has 1 pending op");

    // Enqueue 2nd update to same cookie (should coalesce)
    c_mut.value.clear();
    c_mut.value.append("2");
    wing::queue_store_mutation(batcher, wing::StoreOpType.InsertOrUpdate, c_mut);
    assert(batcher.pending_ops.len == 1, "Queue coalesced update: length remains 1");
    assert(batcher.pending_ops[0].cookie.value[..] == "2", "Queue updated with newest value '2'");
    assert(batcher.total_coalesced_ops == 1, "total_coalesced_ops incremented");

    // Enqueue 3rd update to same cookie
    c_mut.value.clear();
    c_mut.value.append("3");
    wing::queue_store_mutation(batcher, wing::StoreOpType.InsertOrUpdate, c_mut);
    assert(batcher.pending_ops.len == 1, "Queue coalesced again");
    assert(batcher.pending_ops[0].cookie.value[..] == "3", "Queue updated with newest value '3'");
    assert(batcher.total_coalesced_ops == 2, "total_coalesced_ops is 2");

    // Insert-then-Delete cancellation:
    var c_temp = wing::CanonicalCookie { .. };
    c_temp.name.append("temp_token");
    c_temp.domain.append("app.io");
    wing::queue_store_mutation(batcher, wing::StoreOpType.InsertOrUpdate, c_temp);
    assert(batcher.pending_ops.len == 2, "Temp cookie queued (length 2)");

    wing::queue_store_mutation(batcher, wing::StoreOpType.Delete, c_temp);
    assert(batcher.pending_ops.len == 1, "Temp cookie cancelled out before commit (length back to 1)");
    assert(batcher.total_coalesced_ops == 3, "Cancellation counted as coalesced op");

    // Flush batch to SQL transaction
    var tx_sql: u8[>..] = [];
    let flushed = wing::flush_store_batch(batcher, tx_sql, 1000);
    assert(flushed == 1, "Flushed exactly 1 coalesced operation");
    assert(batcher.pending_ops.len == 0, "Queue cleared after flush");
    assert(batcher.total_committed_ops == 1, "total_committed_ops is 1");
    assert(contains_substr(tx_sql[..], "BEGIN TRANSACTION;"), "Transaction began");
    assert(contains_substr(tx_sql[..], "COMMIT;"), "Transaction committed");

    // 4. Outgoing Cookie Header Formatting (§5.4)
    var out_cookies: wing::CanonicalCookie[>..] = [];
    var ck1 = wing::CanonicalCookie { .. };
    ck1.name.append("theme");
    ck1.value.append("dark");
    var ck2 = wing::CanonicalCookie { .. };
    ck2.name.append("lang");
    ck2.value.append("en-US");
    out_cookies.push(ck1);
    out_cookies.push(ck2);

    var header_val: u8[>..] = [];
    wing::format_cookie_header_value(header_val, out_cookies[..]);
    assert(header_val[..] == "theme=dark; lang=en-US", "Formatted outgoing Cookie header value per RFC 6265 §5.4");

    // 5. Server-Side Ingoing Cookie Header Parser (§5.4 First Occurrence Invariant)
    let raw_header = "SID=first_val; user=alice; SID=shadow_val; theme=dark; user=mallory";
    var parsed_cookies: wing::CanonicalCookie[>..] = [];
    wing::parse_server_cookie_header(raw_header, 1000000, parsed_cookies);

    assert(parsed_cookies.len == 3, "Parsed exactly 3 distinct cookies");
    assert(parsed_cookies[0].name[..] == "SID", "1st cookie is SID");
    assert(parsed_cookies[0].value[..] == "first_val", "RFC 6265bis §5.4: FIRST occurrence preserved (first_val)");
    assert(parsed_cookies[1].name[..] == "user", "2nd cookie is user");
    assert(parsed_cookies[1].value[..] == "alice", "FIRST occurrence of user preserved (alice, not mallory)");
    assert(parsed_cookies[2].name[..] == "theme", "3rd cookie is theme");
    assert(parsed_cookies[2].value[..] == "dark", "theme is dark");

    // 6. Netscape Format Export & Import
    var jar_netscape = wing::new_canonical_cookie_jar();
    var n1 = wing::CanonicalCookie { .. };
    n1.name.append("auth");
    n1.value.append("secret_token_123");
    n1.domain.append("mybank.com");
    n1.path.clear();
    n1.path.append("/account");
    n1.host_only = false;
    n1.secure = true;
    n1.httponly = true;
    n1.expires_utc = 1800000000000000;
    n1.persistent = true;
    wing::set_canonical_cookie(jar_netscape, n1, true, true, 1000000);

    var netscape_txt: u8[>..] = [];
    wing::export_canonical_netscape(jar_netscape, netscape_txt);
    assert(contains_substr(netscape_txt[..], "# Netscape HTTP Cookie File"), "Netscape header present");
    assert(contains_substr(netscape_txt[..], "#HttpOnly_mybank.com"), "HttpOnly prefix correctly serialized");
    assert(contains_substr(netscape_txt[..], "secret_token_123"), "Cookie value present in Netscape output");

    // Import into fresh jar
    var jar_imported_ns = wing::new_canonical_cookie_jar();
    let imported_ns_count = wing::import_canonical_netscape(jar_imported_ns, netscape_txt[..], 1000000);
    assert(imported_ns_count == 1, "Imported 1 cookie from Netscape format");
    assert(jar_imported_ns.cookies.len == 1, "Jar contains imported cookie");
    assert(jar_imported_ns.cookies[0].name[..] == "auth", "Imported name matches");
    assert(jar_imported_ns.cookies[0].value[..] == "secret_token_123", "Imported value matches");
    assert(jar_imported_ns.cookies[0].httponly, "Imported HttpOnly flag restored");
    assert(jar_imported_ns.cookies[0].secure, "Imported Secure flag restored");

    // 7. Chromium V24 JSON Export & Import (Full Fidelity Roundtrip)
    var jar_json = wing::new_canonical_cookie_jar();
    var j1 = wing::CanonicalCookie { .. };
    j1.name.append("session_token");
    j1.value.append("v24_json_payload");
    j1.domain.append("portal.dev");
    j1.path.clear();
    j1.path.append("/v1");
    j1.creation_utc = 1623233894000000;
    j1.last_access_utc = 1623233994000000;
    j1.last_update_utc = 1623233994000000;
    j1.expires_utc = 1750000000000000;
    j1.host_only = false;
    j1.persistent = true;
    j1.secure = true;
    j1.httponly = true;
    j1.same_site = wing::CookieSameSite.Strict;
    j1.priority = wing::CookiePriority.High;
    j1.source_scheme = wing::CookieSourceScheme.Secure;
    j1.source_port = 443;
    wing::set_canonical_cookie(jar_json, j1, true, true, 1623233894000000);

    var json_out: u8[>..] = [];
    wing::export_canonical_json(jar_json, json_out);
    assert(contains_substr(json_out[..], "\"name\":\"session_token\""), "JSON includes name field");
    assert(contains_substr(json_out[..], "\"value\":\"v24_json_payload\""), "JSON includes value field");
    assert(contains_substr(json_out[..], "\"creation_utc\":1623233894000000"), "JSON preserves microsecond creation_utc");
    assert(contains_substr(json_out[..], "\"same_site\":\"Strict\""), "JSON preserves SameSite=Strict");
    assert(contains_substr(json_out[..], "\"priority\":\"High\""), "JSON preserves Priority=High");

    // Import into fresh jar and verify full fidelity
    var jar_imported_json = wing::new_canonical_cookie_jar();
    let imported_json_count = wing::import_canonical_json(jar_imported_json, json_out[..], 1623233894000000);
    assert(imported_json_count == 1, "Imported 1 cookie from JSON");
    assert(jar_imported_json.cookies.len == 1, "Jar contains JSON-imported cookie");
    assert(jar_imported_json.cookies[0].name[..] == "session_token", "Name matches");
    assert(jar_imported_json.cookies[0].value[..] == "v24_json_payload", "Value matches");
    assert(jar_imported_json.cookies[0].same_site == wing::CookieSameSite.Strict, "SameSite is Strict");
    assert(jar_imported_json.cookies[0].priority == wing::CookiePriority.High, "Priority is High");
    assert(jar_imported_json.cookies[0].secure, "Secure flag restored");
    assert(jar_imported_json.cookies[0].httponly, "HttpOnly flag restored");

    print("  -> Step 6 Complete: Persistence, V24 & Serialization Verified!\n");
}

fn main() {
    print("==================================================================");
    print("  goose-wing Canonical Cookie Monster Industrial Master Suite     ");
    print("  Clean Room Implementation: RFC 6265, RFC 6265bis, Chromium V24  ");
    print("==================================================================\n");

    test_step1_canonical_model();
    test_step2_psl_and_matching();
    test_step3_parser_and_dates();
    test_step4_policy_and_isolation();
    test_step5_engine_and_gc();
    test_step6_store_and_persistence();

    print("==================================================================");
    print("  ALL 6 STEPS (100+ ASSERTIONS) PASSED CLEANLY WITH ZERO ERRORS!  ");
    print("  INDUSTRIAL CHROMIUM-GRADE COOKIE MONSTER FULLY OPERATIONAL!     ");
    print("==================================================================");
}
