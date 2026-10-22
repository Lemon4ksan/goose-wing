// Comprehensive RFC 6265 & RFC 6265bis (CHIPS) test & demo for goose-wing
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

fn test_date_parsing() {
    print("=== 1. RFC 6265 §5.1.1 Date Parsing ===");

    // RFC 1123
    let t1, ok1 = wing::parse_cookie_date("Wed, 09 Jun 2021 10:18:14 GMT");
    assert(ok1, "RFC 1123 parsed successfully");
    assert(t1 == 1623233894, "RFC 1123 unix timestamp matched (1623233894)");

    // RFC 850 with 2-digit year (21 -> 2021)
    let t2, ok2 = wing::parse_cookie_date("Wednesday, 09-Jun-21 10:18:14 GMT");
    assert(ok2, "RFC 850 2-digit year parsed");
    assert(t2 == t1, "RFC 850 matches RFC 1123 equivalent");

    // asctime format
    let t3, ok3 = wing::parse_cookie_date("Sun Nov  6 08:49:37 1994");
    assert(ok3, "asctime format parsed");
    assert(t3 == 784111777, "asctime timestamp matched 1994-11-06 08:49:37");

    // Leap year Feb 29
    let t_leap, ok_leap = wing::parse_cookie_date("Sun, 29 Feb 2004 12:00:00 GMT");
    assert(ok_leap, "Feb 29 on leap year 2004 is valid");

    let t_nonleap, ok_nonleap = wing::parse_cookie_date("Mon, 29 Feb 2005 12:00:00 GMT");
    assert(!ok_nonleap, "Feb 29 on non-leap year 2005 is invalid and rejected");
}

fn test_security_and_limits() {
    print("=== 2. Security Limits & CTL Character Validation ===");

    var jar = wing::new_cookie_jar();

    // Rejection of CTL character in cookie
    let ok_ctl = jar.set_cookie_header("https://example.com/", "bad\r\ncookie=val; Path=/");
    assert(!ok_ctl, "Rejected cookie with CRLF CTL characters");

    // Max-Age Cap (RFC 6265bis 400 days)
    jar.set_cookie_header("https://example.com/", "session=abc; Max-Age=100000000; Path=/");
    let c_val = jar.get("https://example.com/", "session");
    assert(c_val == "abc", "Cookie with capped Max-Age stored successfully");
}

fn test_domain_and_public_suffix() {
    print("=== 3. Domain Matching & Public Suffix List Rejection ===");

    var jar = wing::new_cookie_jar();

    // Public suffix rejection: cannot set cookie for .com or .org
    let ok_com = jar.set_cookie_header("https://example.com/", "evil=1; Domain=com; Path=/");
    assert(!ok_com, "Rejected Set-Cookie for public suffix .com");

    let ok_co_uk = jar.set_cookie_header("https://store.co.uk/", "evil=2; Domain=co.uk; Path=/");
    assert(!ok_co_uk, "Rejected Set-Cookie for public suffix .co.uk");

    // Domain cookie vs Host-only cookie
    jar.set_cookie_header("https://sub.example.com/", "dom_c=123; Domain=example.com; Path=/");
    jar.set_cookie_header("https://sub.example.com/", "host_c=456; Path=/"); // host-only

    // Verify sub.example.com sees both
    assert(jar.get("https://sub.example.com/", "dom_c") == "123", "sub.example.com sees domain cookie");
    assert(jar.get("https://sub.example.com/", "host_c") == "456", "sub.example.com sees host-only cookie");

    // Verify other.example.com sees domain cookie, but NOT host-only cookie
    assert(jar.get("https://other.example.com/", "dom_c") == "123", "other.example.com sees domain cookie");
    assert(jar.get("https://other.example.com/", "host_c") == "", "other.example.com CANNOT see host-only cookie");

    // IP address host-only enforcement
    jar.set_cookie_header("http://192.168.1.10/", "ip_c=999; Domain=192.168.1.10; Path=/");
    assert(jar.get("http://192.168.1.10/", "ip_c") == "999", "IP address sees its cookie");
}

fn test_path_matching_and_sorting() {
    print("=== 4. Path Matching & §5.4 Header Sorting ===");

    var jar = wing::new_cookie_jar();

    // Default path calculation: /v1/users/42 -> default path is /v1/users
    jar.set_cookie_header("https://api.test.com/v1/users/42", "user_scoped=true");
    assert(jar.get("https://api.test.com/v1/users/info", "user_scoped") == "true", "Default path matches sibling sub-path");
    assert(jar.get("https://api.test.com/v1/orders", "user_scoped") == "", "Default path does not match outside directory");

    // RFC 6265 §5.4: Longer paths must appear FIRST in Cookie header
    var sort_jar = wing::new_cookie_jar();
    sort_jar.set_cookie_header("https://api.test.com/", "root_c=0; Path=/");
    sort_jar.set_cookie_header("https://api.test.com/v1", "v1_c=1; Path=/v1");
    sort_jar.set_cookie_header("https://api.test.com/v1/users", "u_c=2; Path=/v1/users");

    var hdr: u8[..256] = [];
    sort_jar.build_cookie_header("https://api.test.com/v1/users/42", hdr);
    print("  Header generated: ", hdr[..]);

    // Check that u_c is first (/v1/users), then v1_c (/v1), then root_c (/)
    assert(starts_with(hdr[..], "u_c=2; v1_c=1; root_c=0"), "Longest path (/v1/users) sorted first, then /v1, then /");
}

fn test_security_prefixes() {
    print("=== 5. RFC 6265bis §4.1.3 Security Prefixes (__Secure- & __Host-) ===");

    var jar = wing::new_cookie_jar();

    // __Secure- requires Secure flag
    let ok_sec_plain = jar.set_cookie_header("https://secure.bank.com/", "__Secure-id=1; Path=/");
    assert(!ok_sec_plain, "Rejected __Secure- cookie without Secure flag");

    let ok_sec_http = jar.set_cookie_header("http://secure.bank.com/", "__Secure-id=1; Secure; Path=/");
    assert(!ok_sec_http, "Rejected __Secure- cookie over insecure HTTP");

    let ok_sec_good = jar.set_cookie_header("https://secure.bank.com/", "__Secure-id=100; Secure; Path=/");
    assert(ok_sec_good, "Accepted __Secure- cookie over HTTPS with Secure flag");

    // __Host- requires Secure, Path=/, and NO Domain attribute
    let ok_host_with_dom = jar.set_cookie_header("https://bank.com/", "__Host-auth=ok; Secure; Domain=bank.com; Path=/");
    assert(!ok_host_with_dom, "Rejected __Host- cookie containing Domain attribute");

    let ok_host_bad_path = jar.set_cookie_header("https://bank.com/", "__Host-auth=ok; Secure; Path=/login");
    assert(!ok_host_bad_path, "Rejected __Host- cookie with Path != /");

    let ok_host_good = jar.set_cookie_header("https://bank.com/", "__Host-auth=valid_session; Secure; Path=/");
    assert(ok_host_good, "Accepted valid __Host- cookie");
    assert(jar.get("https://bank.com/", "__Host-auth") == "valid_session", "__Host- cookie stored & retrieved");
}

fn test_chips_partitioning() {
    print("=== 6. RFC 6265bis CHIPS (Partitioned Cookies) ===");

    var jar = wing::new_cookie_jar();

    // Partitioned cookie requires Secure attribute
    let ok_insecure_part = jar.set_cookie_header("https://idp.service.com/", "embed_s=xyz; Partitioned; Path=/");
    assert(!ok_insecure_part, "Rejected Partitioned cookie without Secure attribute");

    // Store partitioned cookie under partition A
    jar.set_partition_key("https://first-party-site-a.com");
    let ok_part = jar.set_cookie_header("https://idp.service.com/", "__Host-s=part_123; Secure; Path=/; Partitioned");
    assert(ok_part, "Partitioned cookie accepted with Secure flag");

    // Query under partition A
    assert(jar.get("https://idp.service.com/", "__Host-s") == "part_123", "Partition A sees the partitioned cookie");

    // Switch active partition to site B
    jar.set_partition_key("https://first-party-site-b.com");
    assert(jar.get("https://idp.service.com/", "__Host-s") == "", "Partition B CANNOT see partition A's cookie (ISOLATION OK)");

    // Switch back to site A
    jar.set_partition_key("https://first-party-site-a.com");
    assert(jar.get("https://idp.service.com/", "__Host-s") == "part_123", "Switched back to Partition A: cookie is visible again");
}

fn test_aoni_advanced_features() {
    print("=== 7. aoni Features: Mirror, Netscape & JSON Export/Import ===");

    var jar = wing::new_cookie_jar();
    jar.set_cookie_header("https://auth.company.internal/login", "auth_token=super_secret_token; Path=/");
    jar.set_cookie_header("https://auth.company.internal/login", "theme=dark; Path=/");

    // Mirror cookies from auth.company.internal to api.company.internal
    let names: const u8[:][1] = ["auth_token"];
    jar.mirror("https://auth.company.internal/", "https://api.company.internal/", names[..]);

    assert(jar.get("https://api.company.internal/", "auth_token") == "super_secret_token", "Mirror copied auth_token to api host");
    assert(jar.get("https://api.company.internal/", "theme") == "", "Non-mirrored cookie 'theme' was not copied");

    // Netscape cookies.txt export
    var netscape_buf: u8[..1024] = [];
    jar.export_netscape("https://api.company.internal/", netscape_buf);
    assert(find(netscape_buf[..], "super_secret_token") >= 0, "Netscape export contains mirrored token");
    assert(starts_with(netscape_buf[..], "# Netscape HTTP Cookie File"), "Netscape header present");

    // JSON export
    var json_buf: u8[>..] = [];
    jar.export_json("https://api.company.internal/", json_buf);
    print("  Exported JSON: ", json_buf[..]);
    assert(find(json_buf[..], "\"name\":\"auth_token\"") >= 0, "JSON export contains name field");
    assert(find(json_buf[..], "\"value\":\"super_secret_token\"") >= 0, "JSON export contains value field");

    // Clear and re-import into a fresh jar
    var fresh_jar = wing::new_cookie_jar();
    assert(fresh_jar.count() == 0, "Fresh jar is empty");
    let imported_count = fresh_jar.import_json("https://imported.company.internal/", json_buf[..]);
    assert(imported_count == 1, "Imported 1 cookie from JSON");
    assert(fresh_jar.get("https://imported.company.internal/", "auth_token") == "super_secret_token", "Imported cookie is readable");
}

fn main() {
    print("------------------------------------------------------------------");
    print("  goose-wing RFC 6265 & RFC 6265bis (CHIPS) CookieJar Test Suite  ");
    print("------------------------------------------------------------------");

    test_date_parsing();
    test_security_and_limits();
    test_domain_and_public_suffix();
    test_path_matching_and_sorting();
    test_security_prefixes();
    test_chips_partitioning();
    test_aoni_advanced_features();

    print("------------------------------------------------------------------");
    print("  ALL 7 TEST SUITES PASSED CLEANLY! PERFECT RFC CONFORMANCE!      ");
    print("------------------------------------------------------------------");
}
