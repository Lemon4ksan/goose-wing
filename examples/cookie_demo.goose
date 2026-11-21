// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Example demonstrating cookie jar usage and method chaining.
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

fn main() {
    print("goose-wing Cookie Jar Example (UFCS)\n");

    var jar = cookie::CanonicalCookieJar { .. };
    let now_us: i64 = 1700000000 * 1000000;

    // 1. Fluent Builder via UFCS: push returns a reference configured in-place!
    print("--- 1. Fluent In-Place Cookie Builder ---");
    jar.add("auth_jwt", "secret_jwt_token_999")
       .with_host("api.crypto-dex.io")
       .with_path("/v1")
       .with_secure()
       .with_http_only()
       .with_same_site(cookie::SameSite.Strict)
       .with_priority(cookie::Priority.High)
       .with_max_age_seconds(86400 * 30, now_us);

    jar.add("theme", "nord-dark")
       .with_domain(".crypto-dex.io")
       .with_path("/");

    jar.add("visitor_id", "vis_12345")
       .with_domain("crypto-dex.io")
       .with_path("/")
       .with_max_age_seconds(86400 * 365, now_us);

    assert(jar.cookies.len == 3, "All 3 cookies added via fluent builder");
    assert(jar.cookies[0].name[..] == "auth_jwt", "auth_jwt cookie present");
    assert(jar.cookies[0].host_only, "auth_jwt is host_only (with_host)");
    assert(!jar.cookies[1].host_only, "theme is domain cookie (with_domain .crypto-dex.io)");
    assert(!jar.cookies[2].host_only, "visitor_id is domain cookie (with_domain crypto-dex.io)");
    assert(jar.cookies[0].secure, "auth_jwt is Secure");
    assert(jar.cookies[0].httponly, "auth_jwt is HttpOnly");
    assert(jar.cookies[0].same_site == cookie::SameSite.Strict, "auth_jwt is SameSite=Strict");
    assert(jar.cookies[0].priority == cookie::Priority.High, "auth_jwt is Priority=High");

    // 2. Direct Printing with Universal `format<B>`
    print("\n--- 2. Direct Renders via Universal format ---");
    for c in jar.cookies {
        print("  Rendered Set-Cookie: ", c);
    }

    // 3. Declarative Filtering with trailing closure and implicit `it`
    print("\n--- 3. Declarative Filtering via Closure & it ---");
    let secure_cookies = jar.cookies.filter() { it.secure };
    print("  Found ", secure_cookies.len, " secure cookie(s)");
    assert(secure_cookies.len == 1, "Exactly 1 secure cookie");

    let root_cookies = jar.cookies.filter() { it.path[..] == "/" };
    print("  Found ", root_cookies.len, " root path cookie(s)");
    assert(root_cookies.len == 2, "Exactly 2 root path cookies");

    // 4. Outgoing Request Header Generation
    print("\n--- 4. Outgoing Header Generation per RFC 6265 Section 5.4 ---");
    var req_header: u8[>..] = [];
    jar.build_cookie_header("api.crypto-dex.io", "/v1/trade", true, now_us, req_header);
    print("  Cookie Header: ", req_header[..]);
    assert(find(req_header[..], "auth_jwt=secret_jwt_token_999") >= 0, "Contains auth_jwt");
    assert(find(req_header[..], "theme=nord-dark") >= 0, "Contains theme");

    // 5. Expired Cookie Purge in one line with `retain() { !it.is_expired() }`
    print("\n--- 5. One-Line Garbage Collection via retain & it ---");
    jar.add("temp_del", "expired_val")
       .with_domain("crypto-dex.io")
       .with_expires_utc(now_us - 1000); // expired 1ms ago

    assert(jar.cookies.len == 4, "Cookie added before purge");
    let purged_count = jar.purge_expired(now_us);
    print("  Purged ", purged_count, " expired cookie(s) in one line");
    assert(purged_count == 1, "Exactly 1 expired cookie purged");
    assert(jar.cookies.len == 3, "Jar size restored to 3");

    // 6. High-Level URL Ingestion & Dynamic Origin Routing
    print("\n--- 6. High-Level URL Ingestion & Origin Routing ---");
    let ingested = jar.set_cookie_header(
        "https://api.crypto-dex.io/v1/orders",
        "order_token=ord_live_7766; Secure; HttpOnly; SameSite=Strict; Max-Age=3600",
        now_us,
    );
    assert(ingested, "Set-Cookie from HTTPS URL ingested");
    let val_by_url = jar.get("https://api.crypto-dex.io/v1/orders", "order_token", now_us);
    assert(val_by_url == "ord_live_7766", "Retrieved cookie value by URL route");

    // Verify origin isolation: insecure HTTP cannot retrieve Secure cookie
    let val_by_http = jar.get("http://api.crypto-dex.io/v1/orders", "order_token", now_us);
    assert(val_by_http.len == 0, "Secure cookie isolated from non-secure HTTP");

    // 7. URL-Based Outgoing Request Header
    print("\n--- 7. URL-Based Request Header Generation ---");
    var url_req_hdr: u8[>..] = [];
    jar.build_cookie_header("https://api.crypto-dex.io/v1/orders", now_us, url_req_hdr);
    print("  URL Request Header: ", url_req_hdr[..]);
    assert(find(url_req_hdr[..], "order_token=ord_live_7766") >= 0, "Header contains order_token");
    assert(find(url_req_hdr[..], "auth_jwt=secret_jwt_token_999") >= 0, "Header contains auth_jwt");

    // 8. Formats & Interop (Netscape & JSON)
    print("\n--- 8. Formats & Interop (Netscape & JSON) ---");
    var netscape_buf: u8[>..] = [];
    jar.export_netscape(netscape_buf);
    assert(find(netscape_buf[..], "#HttpOnly_api.crypto-dex.io") >= 0, "Netscape export contains HttpOnly prefix");

    var json_buf: u8[>..] = [];
    jar.export_json(json_buf);
    assert(find(json_buf[..], "\"name\":\"order_token\"") >= 0, "JSON export contains order_token");

    var fresh_jar = cookie::CanonicalCookieJar { .. };
    let imported_count = fresh_jar.import_json(json_buf[..], now_us);
    print("  Imported ", imported_count, " cookies into fresh jar from JSON");
    assert(imported_count == jar.cookies.len, "All cookies successfully imported");
    assert(fresh_jar.get("order_token") == "ord_live_7766", "Global getter retrieves imported cookie");

    // 9. PSL and Domain-Match Validation on Ingestion (RFC 6265 Section 5.3 Step 5 & 6)
    print("\n--- 9. PSL & Domain-Match Ingestion Validation ---");
    let evil_cross = jar.set_cookie_header("https://evil.com/phish", "steal=1; Domain=bank.com", now_us);
    assert(!evil_cross, "evil.com blocked from setting Domain=bank.com");

    let evil_psl = jar.set_cookie_header("https://evil.co.uk/page", "track=1; Domain=co.uk", now_us);
    assert(!evil_psl, "evil.co.uk blocked from setting public suffix Domain=co.uk");

    let parent_sub = jar.set_cookie_header("https://example.com/", "test=1; Domain=sub.example.com", now_us);
    assert(!parent_sub, "example.com blocked from setting child subdomain Domain=sub.example.com");

    let valid_sub = jar.set_cookie_header("https://sub.example.com/", "auth=1; Domain=example.com", now_us);
    assert(valid_sub, "sub.example.com allowed to set parent Domain=example.com");

    // 10. Expired Overwrite Memory Hygiene (Max-Age=0)
    print("\n--- 10. Expired Overwrite Memory Hygiene (Max-Age=0) ---");
    let initial_count = jar.cookies.len;
    // Set a temporary cookie
    jar.set_cookie_header("https://api.crypto-dex.io/v1/", "to_expire=hello; Path=/v1", now_us);
    assert(jar.cookies.len == initial_count + 1, "to_expire cookie added");
    // Send Max-Age=0 to delete it
    jar.set_cookie_header("https://api.crypto-dex.io/v1/", "to_expire=bye; Path=/v1; Max-Age=0", now_us);
    assert(jar.cookies.len == initial_count, "Existing cookie immediately removed on Max-Age=0 overwrite");

    // Send Max-Age=0 for a non-existent cookie (should NOT allocate dead record)
    jar.set_cookie_header("https://api.crypto-dex.io/v1/", "ghost_cookie=none; Max-Age=0", now_us);
    assert(jar.cookies.len == initial_count, "Non-existent expired cookie did NOT push dead record to jar");

    // 11. Localhost Port Rewrite (80 -> 443) & Secure Context Recognition
    print("\n--- 11. Localhost Port 80 -> 443 Rewrite & Secure Context ---");
    let local_ok = jar.set_cookie_header(
        "http://127.0.0.1:80/dev",
        "__Host-dev_key=secret_123; Secure; Path=/",
        now_us,
    );
    assert(local_ok, "__Host- cookie accepted on http://127.0.0.1 as trustworthy secure context");
    let dev_val = jar.get("http://127.0.0.1:80/dev", "__Host-dev_key", now_us);
    assert(dev_val == "secret_123", "Retrieved __Host- cookie from http://127.0.0.1");

    // 12. Standalone Builder & Safe Insert via jar.set(c, now_us)
    print("\n--- 12. Standalone Builder & Safe Insert ---");
    var standalone = cookie::new_canonical_cookie("safe_token", "st_val_99");
    standalone.with_host("api.crypto-dex.io")
              .with_path("/")
              .with_secure()
              .with_http_only();
    let set_ok = jar.set(standalone, now_us);
    assert(set_ok, "Standalone cookie safely inserted with full validation");
    assert(jar.get("safe_token") == "st_val_99", "Retrieved safely inserted cookie");

    // 13. SameSite Cross-Site Isolation
    print("\n--- 13. SameSite Isolation in Querying ---");
    // Cross-site subresource (is_same_site = false, is_top_level = false)
    let strict_cross = jar.get(
        "https://api.crypto-dex.io/v1/orders",
        "auth_jwt",
        now_us,
        cookie::AccessOptions { is_same_site: false, is_top_level_navigation: false, is_safe_method: true },
    );
    assert(strict_cross.len == 0, "SameSite=Strict cookie BLOCKED on cross-site subresource");

    // Same-site request
    let strict_same = jar.get(
        "https://api.crypto-dex.io/v1/orders",
        "auth_jwt",
        now_us,
        cookie::AccessOptions { is_same_site: true, is_top_level_navigation: true, is_safe_method: true },
    );
    assert(strict_same == "secret_jwt_token_999", "SameSite=Strict cookie sent on same-site request");

    // 14. CHIPS (Partitioned Cookies) Isolation
    print("\n--- 14. CHIPS Partitioned Cookies ---");
    let chips_ingested = jar.set_cookie_header(
        "https://embed.partner-service.com/api",
        "__Host-embed_session=token_abc; Secure; Path=/; Partitioned",
        now_us,
        true,
        "https://site-a.com",
    );
    assert(chips_ingested, "CHIPS partitioned cookie ingested under site-a partition");

    // Visible from site-a
    let val_site_a = jar.get(
        "https://embed.partner-service.com/api",
        "__Host-embed_session",
        now_us,
        cookie::AccessOptions { .. },
        "https://site-a.com",
    );
    assert(val_site_a == "token_abc", "Cookie visible under site-a partition");

    // Isolated from site-b
    let val_site_b = jar.get(
        "https://embed.partner-service.com/api",
        "__Host-embed_session",
        now_us,
        cookie::AccessOptions { .. },
        "https://site-b.com",
    );
    assert(val_site_b.len == 0, "Cookie isolated and blocked under site-b partition");

    // 15. Polish & Edge Cases: SQLite V24 host_key, IPv6 URL, Server CTL, JSON Scheme Downgrade
    print("\n--- 15. Edge Cases: SQLite host_key, IPv6, Server CTL, Scheme Downgrade ---");
    var sql_host_buf: u8[>..] = [];
    cookie::generate_sqlite_delete_sql(jar.cookies[0], sql_host_buf); // auth_jwt (host_only)
    assert(find(sql_host_buf[..], "host_key = 'api.crypto-dex.io'") >= 0, "SQLite host_key encodes host-only without leading dot");

    var sql_dom_buf: u8[>..] = [];
    cookie::generate_sqlite_delete_sql(jar.cookies[1], sql_dom_buf); // theme (domain cookie)
    assert(find(sql_dom_buf[..], "host_key = '.crypto-dex.io'") >= 0, "SQLite host_key encodes domain cookie WITH leading dot");

    let ipv6_url = cookie::parse_canonical_cookie_url("http://[::1]:8080/api/v1");
    assert(ipv6_url.host[..] == "::1", "IPv6 parsed without brackets into clean host ::1");
    assert(ipv6_url.port == 8080, "IPv6 port 8080 successfully parsed");

    var srv_cookies: cookie::CanonicalCookie[>..] = [];
    cookie::parse_server_cookie_header("valid1=ok; bad_ctl\x01=hacked; valid2=good", now_us, srv_cookies);
    assert(srv_cookies.len == 2, "Server Cookie parser dropped pair with prohibited CTL byte");
    assert(srv_cookies[0].name[..] == "valid1", "First clean cookie parsed");
    assert(srv_cookies[1].name[..] == "valid2", "Second clean cookie parsed");

    let json_downgrade = "[{\"name\":\"sid_downgrade\",\"value\":\"tok123\",\"domain\":\"crypto-dex.io\",\"path\":\"/\",\"source_scheme\":\"secure\",\"source_port\":443}]";
    var json_test_jar = cookie::CanonicalCookieJar { .. };
    let imported_down = json_test_jar.import_json(json_downgrade, now_us);
    assert(imported_down == 1, "Non-secure cookie with source_scheme:secure imported without channel rejection");
    assert(json_test_jar.get("sid_downgrade") == "tok123", "Retrieved imported cookie");
}
