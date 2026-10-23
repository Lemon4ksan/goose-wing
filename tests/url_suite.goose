// Verification Suite for WHATWG URL, IPv6 RFC 5952, Origin Model & Swift-Style Path APIs
// Conforming to WHATWG URL Standard and RFC 5952 IPv6 representation.
import std;
import wing from "..";

// ----------------------------------------------------------------------------
// 1. WHATWG URL Parser, IPv6 RFC 5952 Compression, and Origin
// ----------------------------------------------------------------------------
fn test_url_parser_and_origin(t: wing::T&) {
    t.run("Absolute URL Normalization & Default Port Stripping") { sub =>
        // Default port 80 for HTTP is stripped from authority
        let url_http = wing::new_url("HTTP://Example.COM:80/path/to/resource?query=1#frag");
        sub.assert_true(url_http.valid, "valid HTTP url");
        sub.assert_bytes_eq(wing::scheme(url_http), "http", "scheme normalized to lowercase");
        sub.assert_bytes_eq(wing::host(url_http), "example.com", "host normalized to lowercase");
        sub.assert_eq(wing::effective_port(url_http), 80, "effective port is 80");
        sub.assert_bytes_eq(wing::port_str(url_http), "", "default port stripped from port string");
        sub.assert_bytes_eq(wing::pathname(url_http), "/path/to/resource", "pathname preserved");
        sub.assert_bytes_eq(wing::search(url_http), "?query=1", "search query parsed");
        sub.assert_bytes_eq(wing::hash(url_http), "#frag", "fragment parsed");
        sub.assert_true(wing::is_special(url_http), "http is a special scheme");

        // Non-default port 8080 for HTTP is preserved
        let url_custom_port = wing::new_url("https://secure.example.com:8443/api");
        sub.assert_true(url_custom_port.valid, "valid custom port url");
        sub.assert_bytes_eq(wing::scheme(url_custom_port), "https", "https scheme");
        sub.assert_bytes_eq(wing::hostname(url_custom_port), "secure.example.com", "hostname without port");
        sub.assert_bytes_eq(wing::host(url_custom_port), "secure.example.com:8443", "host includes port");
        sub.assert_eq(wing::effective_port(url_custom_port), 8443, "effective port 8443");
        sub.assert_bytes_eq(wing::port_str(url_custom_port), "8443", "port string is 8443");
        sub.assert_bytes_eq(wing::pathname(url_custom_port), "/api", "pathname is /api");
    };

    t.run("IPv6 Zero-Run Compression (RFC 5952)") { sub =>
        // Full 8-group IPv6 with zero runs compressed to ::
        let url_ipv6 = wing::new_url("http://[2001:0db8:0000:0000:0000:ff00:0042:8329]/");
        sub.assert_true(url_ipv6.valid, "valid IPv6 url");
        sub.assert_bytes_eq(wing::host(url_ipv6), "[2001:db8::ff00:42:8329]", "zero run compressed per RFC 5952");

        // Loopback IPv6 ::1
        let url_loopback = wing::new_url("http://[0000:0000:0000:0000:0000:0000:0000:0001]:8080/");
        sub.assert_true(url_loopback.valid, "valid loopback IPv6");
        sub.assert_bytes_eq(wing::hostname(url_loopback), "[::1]", "loopback hostname compressed to [::1]");
        sub.assert_bytes_eq(wing::host(url_loopback), "[::1]:8080", "host includes port 8080");
        sub.assert_eq(wing::effective_port(url_loopback), 8080, "port 8080 preserved");

        // IPv4-mapped IPv6 [::ffff:192.168.1.1]
        let url_mapped = wing::new_url("http://[::ffff:192.168.1.1]/");
        sub.assert_true(url_mapped.valid, "valid IPv4-mapped IPv6");
        sub.assert_bytes_eq(wing::host(url_mapped), "[::ffff:c0a8:101]", "IPv4-mapped hex normalized");
    };

    t.run("Dot-Segment Normalization & Relative Resolution") { sub =>
        // Path dot-segment collapsing
        let url_dots = wing::new_url("https://example.com/a/b/../c/./d");
        sub.assert_bytes_eq(wing::pathname(url_dots), "/a/c/d", "dot segments collapsed");

        // Relative resolution against base URL
        let base_url = wing::new_url("https://example.com/v1/auth/login.html");
        sub.assert_true(base_url.valid, "base url valid");

        // Relative path navigation ../dashboard
        let rel_url = wing::new_url("../dashboard", base_url);
        sub.assert_true(rel_url.valid, "relative url valid");
        sub.assert_bytes_eq(wing::href(rel_url), "https://example.com/v1/dashboard", "resolved ../ relative to base");

        // Root-relative path /logout
        let root_rel = wing::new_url("/logout", base_url);
        sub.assert_true(root_rel.valid, "root-relative url valid");
        sub.assert_bytes_eq(wing::href(root_rel), "https://example.com/logout", "resolved root-relative to base");
    };

    t.run("Origin Model: Tuple vs Opaque and Serialization") { sub =>
        let url1 = wing::new_url("https://example.com/path");
        let url2 = wing::new_url("https://example.com:443/other");
        let url3 = wing::new_url("http://example.com/path");
        let url4 = wing::new_url("https://example.com:8443/path");

        let orig1 = wing::origin_from_url(url1);
        let orig2 = wing::origin_from_url(url2);
        let orig3 = wing::origin_from_url(url3);
        let orig4 = wing::origin_from_url(url4);

        // Same origin: https://example.com == https://example.com:443
        sub.assert_true(wing::is_same_origin(orig1, orig2), "same origin matches");

        // Cross-origin: scheme mismatch (https vs http)
        sub.assert_false(wing::is_same_origin(orig1, orig3), "scheme mismatch is cross-origin");

        // Cross-origin: port mismatch (443 vs 8443)
        sub.assert_false(wing::is_same_origin(orig1, orig4), "port mismatch is cross-origin");

        // Origin serialization
        var orig_str: u8[..64] = [];
        wing::serialize_origin(orig1, orig_str);
        sub.assert_bytes_eq(orig_str[..], "https://example.com", "origin serialized without default port");

        // Opaque origin
        let opaque_a = wing::new_opaque_origin();
        let opaque_b = wing::new_opaque_origin();
        sub.assert_true(opaque_a.kind == wing::OriginKind.Opaque, "opaque kind");
        sub.assert_false(wing::is_same_origin(opaque_a, opaque_b), "two opaque origins never match");

        var opaque_str: u8[..32] = [];
        wing::serialize_origin(opaque_a, opaque_str);
        sub.assert_bytes_eq(opaque_str[..], "null", "opaque origin serializes to 'null'");
    };
}

// ----------------------------------------------------------------------------
// 2. File URL & Path Manipulation
// ----------------------------------------------------------------------------
fn test_swift_style_file_and_path_api(t: wing::T&) {
    t.run("new_file_url Cross-Platform Normalization") { sub =>
        // 1. Windows path with backslashes
        let url_win = wing::new_file_url("C:\\Users\\senya\\Documents\\report.pdf");
        sub.assert_true(url_win.valid, "valid windows file url");
        sub.assert_true(wing::is_file_url(url_win), "is_file_url is true");
        sub.assert_bytes_eq(wing::scheme(url_win), "file", "scheme is file");
        sub.assert_bytes_eq(wing::pathname(url_win), "/C:/Users/senya/Documents/report.pdf", "normalized to file:///C:/...");

        // 2. Windows path with spaces
        let url_spaces = wing::new_file_url("C:\\Program Files\\My App\\app.exe");
        sub.assert_bytes_eq(wing::pathname(url_spaces), "/C:/Program%20Files/My%20App/app.exe", "spaces percent-encoded to %20");

        // 3. POSIX absolute path
        let url_posix = wing::new_file_url("/var/log/system.log");
        sub.assert_bytes_eq(wing::pathname(url_posix), "/var/log/system.log", "posix path preserved");

        // 4. Windows UNC network path
        let url_unc = wing::new_file_url("\\\\nas\\share\\backup.zip");
        sub.assert_bytes_eq(wing::host(url_unc), "nas", "UNC host parsed");
        sub.assert_bytes_eq(wing::pathname(url_unc), "/share/backup.zip", "UNC pathname parsed");
    };

    t.run("file_path Native Operating System Path Extraction") { sub =>
        // Windows path round-trip
        let url_win = wing::new_file_url("C:\\Program Files\\app\\data.json");
        var os_path_win: u8[..256] = [];
        let ok_win = wing::file_path(url_win, os_path_win);
        sub.assert_true(ok_win, "file_path succeeded on windows url");
        sub.assert_bytes_eq(os_path_win[..], "C:\\Program Files\\app\\data.json", "round-trip windows path with native backslashes");

        // POSIX path round-trip
        let url_posix = wing::new_file_url("/etc/nginx/nginx.conf");
        var os_path_posix: u8[..256] = [];
        let ok_posix = wing::file_path(url_posix, os_path_posix);
        sub.assert_true(ok_posix, "file_path succeeded on posix url");
        sub.assert_bytes_eq(os_path_posix[..], "/etc/nginx/nginx.conf", "round-trip posix path");

        // Non-file URL returns false
        let url_web = wing::new_url("https://example.com/file.txt");
        var os_path_web: u8[..64] = [];
        sub.assert_false(wing::file_path(url_web, os_path_web), "file_path fails on non-file URL");
    };

    t.run("last_path_component & path_extension (Swift-style)") { sub =>
        let url_file = wing::new_file_url("C:\\Projects\\app\\report.final.pdf");
        sub.assert_bytes_eq(wing::last_path_component(url_file), "report.final.pdf", "lastPathComponent with dots");
        sub.assert_bytes_eq(wing::path_extension(url_file), "pdf", "pathExtension is pdf");

        // Multi-extension archive
        let url_tar = wing::new_url("https://archive.org/data.tar.gz");
        sub.assert_bytes_eq(wing::last_path_component(url_tar), "data.tar.gz", "last component is data.tar.gz");
        sub.assert_bytes_eq(wing::path_extension(url_tar), "gz", "extension is gz");

        // Hidden file without extension (.gitignore)
        let url_hidden = wing::new_file_url("C:\\Repo\\.gitignore");
        sub.assert_bytes_eq(wing::last_path_component(url_hidden), ".gitignore", "last component is .gitignore");
        sub.assert_bytes_eq(wing::path_extension(url_hidden), "", "hidden file leading dot has no extension");

        // Folder with trailing slash
        let url_dir = wing::new_file_url("C:\\Projects\\src\\");
        sub.assert_bytes_eq(wing::last_path_component(url_dir), "src", "trailing slash ignored for lastPathComponent");
        sub.assert_bytes_eq(wing::path_extension(url_dir), "", "directory has no extension");

        // Root path
        let url_root = wing::new_url("file:///");
        sub.assert_bytes_eq(wing::last_path_component(url_root), "/", "root lastPathComponent is /");
    };

    t.run("deleting_path_extension & deleting_last_path_component") { sub =>
        let url1 = wing::new_file_url("C:\\Docs\\report.pdf");
        let no_ext = wing::deleting_path_extension(url1);
        sub.assert_bytes_eq(wing::pathname(no_ext), "/C:/Docs/report", "deletingPathExtension removes .pdf");
        sub.assert_bytes_eq(wing::path_extension(no_ext), "", "now has no extension");

        // Deleting last component moves to parent folder
        let parent = wing::deleting_last_path_component(url1);
        sub.assert_bytes_eq(wing::pathname(parent), "/C:/Docs/", "deletingLastPathComponent points to parent folder");

        // Chained navigation up
        let grandparent = wing::deleting_last_path_component(parent);
        sub.assert_bytes_eq(wing::pathname(grandparent), "/C:/", "grandparent points to drive root");
    };

    t.run("appending_path_component, appending_path, appending_path_extension") { sub =>
        let base_url = wing::new_file_url("C:\\Projects\\my_app");

        // Append component
        let assets_url = wing::appending_path_component(base_url, "assets");
        sub.assert_bytes_eq(wing::pathname(assets_url), "/C:/Projects/my_app/assets", "appended component");

        // Append component with spaces (must be encoded)
        let img_url = wing::appending_path_component(assets_url, "app logo.svg");
        sub.assert_bytes_eq(wing::pathname(img_url), "/C:/Projects/my_app/assets/app%20logo.svg", "spaces encoded in appended component");

        // Append multi-segment subpath
        let deep_url = wing::appending_path(base_url, "src/components/button.goose");
        sub.assert_bytes_eq(wing::pathname(deep_url), "/C:/Projects/my_app/src/components/button.goose", "appended multi-segment subpath");

        // Append extension
        let file_no_ext = wing::new_file_url("C:\\Data\\payload");
        let with_ext = wing::appending_path_extension(file_no_ext, "json");
        sub.assert_bytes_eq(wing::pathname(with_ext), "/C:/Data/payload.json", "appended .json extension");

        // Append extension with leading dot (.xml)
        let with_dot_ext = wing::appending_path_extension(file_no_ext, ".xml");
        sub.assert_bytes_eq(wing::pathname(with_dot_ext), "/C:/Data/payload.xml", "leading dot stripped before appending extension");
    };

    t.run("Swift-Style UFCS Method Chaining") { sub =>
        // url.appending(...).appending_path_extension(...)
        let base = wing::new_file_url("C:\\Workspace");
        let final_url = base.appending("build")
                            .appending("release")
                            .appending("binary")
                            .appending_path_extension("exe");

        sub.assert_bytes_eq(wing::pathname(final_url), "/C:/Workspace/build/release/binary.exe", "fluent chained path construction");
        sub.assert_bytes_eq(final_url.last_path_component(), "binary.exe", "UFCS last_path_component");
        sub.assert_bytes_eq(final_url.path_extension(), "exe", "UFCS path_extension");

        var native_out: u8[..256] = [];
        sub.assert_true(final_url.file_path(native_out), "UFCS file_path succeeded");
        sub.assert_bytes_eq(native_out[..], "C:\\Workspace\\build\\release\\binary.exe", "native Windows path ready for OS calls");
    };
}

// ----------------------------------------------------------------------------
// 3. WHATWG URL Standard & Security Audit Verification
// ----------------------------------------------------------------------------
fn test_whatwg_audit_fixes(t: wing::T&) {
    t.run("1.1 & 1.2: Same-Site Isolation for data:, about: & blob: Origin") { sub =>
        // 1.1: data: and about: without registrable domain must NEVER match same-site
        let data1 = wing::new_url("data:text/html,1");
        let data2 = wing::new_url("data:text/html,2");
        sub.assert_false(wing::is_schemeful_same_site_urls(data1, data2), "data: URLs must never match same-site");

        let about_blank = wing::new_url("about:blank");
        let about_srcdoc = wing::new_url("about:srcdoc");
        sub.assert_false(wing::is_schemeful_same_site_urls(about_blank, about_srcdoc), "about: URLs must never match same-site");

        let opaque_orig = wing::new_opaque_origin();
        let web_url = wing::new_url("https://example.com/");
        sub.assert_false(wing::is_same_site_origin_url(opaque_orig, web_url), "opaque origin is never same-site");

        // 1.2: blob: URLs inherit tuple origin from embedded URL in pathname
        let blob_url = wing::new_url("blob:https://example.com/550e8400-e29b-41d4-a716-446655440000");
        let blob_orig = wing::origin_from_url(blob_url);
        sub.assert_true(blob_orig.kind == wing::OriginKind.Tuple, "blob: inherits tuple origin");
        var blob_orig_str: u8[..64] = [];
        wing::serialize_origin(blob_orig, blob_orig_str);
        sub.assert_bytes_eq(blob_orig_str[..], "https://example.com", "blob origin matches embedded origin");

        let blob_custom_port = wing::new_url("blob:http://example.com:8080/uuid");
        let blob_cp_orig = wing::origin_from_url(blob_custom_port);
        var blob_cp_str: u8[..64] = [];
        wing::serialize_origin(blob_cp_orig, blob_cp_str);
        sub.assert_bytes_eq(blob_cp_str[..], "http://example.com:8080", "blob origin preserves custom port");
    };

    t.run("1.3: C0 Control Code Points & Host Sanitization") { sub =>
        // Control character injection in host
        let bad_host_c0, err_c0 = wing::parse_url("http://exam\x01ple.com/");
        sub.assert_true(err_c0 == wing::UrlParseError.ForbiddenHostCodePoint, "C0 control byte 0x01 in host rejected");

        let bad_host_pct, err_pct = wing::parse_url("http://example%.com/");
        sub.assert_true(err_pct == wing::UrlParseError.ForbiddenHostCodePoint, "percent in host rejected");

        let bad_host_caret, err_caret = wing::parse_url("http://exam^ple.com/");
        sub.assert_true(err_caret == wing::UrlParseError.ForbiddenHostCodePoint, "caret in host rejected");
    };

    t.run("1.4 & 5.2: Scheme Integrity in Relative Resolution & Non-Special Schemes") { sub =>
        // 1.4: Different scheme from base does NOT silently downgrade to base scheme
        let base_http = wing::new_url("http://example.com/dir/page");
        let res_https, err_https = wing::parse_url_with_base("https:/secure/login", base_http);
        sub.assert_true(res_https.valid, "parsed https:/secure/login");
        sub.assert_bytes_eq(wing::scheme(res_https), "https", "scheme remains https (no downgrade to http)");
        sub.assert_bytes_eq(wing::host(res_https), "secure", "secure parsed as authority");
        sub.assert_bytes_eq(wing::pathname(res_https), "/login", "login parsed as pathname");

        // Same scheme as base resolves path against base authority
        let res_same_scheme = wing::new_url("http:/api/v1", base_http);
        sub.assert_bytes_eq(wing::href(res_same_scheme), "http://example.com/api/v1", "same-scheme single slash resolves against base");

        // 5.2: Non-special scheme with single slash path
        let custom_url, custom_err = wing::parse_url("custom:/a/b/c");
        sub.assert_true(custom_url.valid, "non-special scheme with single slash path is valid");
        sub.assert_bytes_eq(wing::scheme(custom_url), "custom", "scheme is custom");
        sub.assert_bytes_eq(wing::pathname(custom_url), "/a/b/c", "pathname is /a/b/c");

        // 5.2: Non-special scheme with empty host
        let git_url, git_err = wing::parse_url("git:///repo");
        sub.assert_true(git_url.valid, "non-special scheme allows empty host");
        sub.assert_bytes_eq(wing::pathname(git_url), "/repo", "git pathname is /repo");
    };

    t.run("2.1..2.3: Trailing Slash on Dot Segments, Empty Paths & 64B+ Segments") { sub =>
        // 2.1: Trailing slash preserved when path ends in .. or .
        let url_dots_parent = wing::new_url("https://example.com/a/b/..");
        sub.assert_bytes_eq(wing::pathname(url_dots_parent), "/a/", "trailing slash preserved on /..");

        let url_dots_cur = wing::new_url("https://example.com/a/b/.");
        sub.assert_bytes_eq(wing::pathname(url_dots_cur), "/a/b/", "trailing slash preserved on /.");

        let url_encoded_dots = wing::new_url("https://example.com/a/b/%2e%2e");
        sub.assert_bytes_eq(wing::pathname(url_encoded_dots), "/a/", "trailing slash preserved on /%2e%2e");

        // 2.2: Preserving empty path segments (// inside pathname)
        let url_empty_segs = wing::new_url("https://example.com/api//v1///users");
        sub.assert_bytes_eq(wing::pathname(url_empty_segs), "/api//v1///users", "empty path segments preserved");

        // 2.3: Segment longer than 64 bytes (JWT / hash)
        let long_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.abcdefghijklmnopqrstuvwxyz0123456789";
        var long_path: u8[..256] = [];
        long_path.append("https://example.com/auth/verify/");
        long_path.append(long_token);
        let url_long = wing::new_url(long_path[..]);
        sub.assert_true(url_long.valid, "long segment url valid");
        sub.assert_contains(wing::pathname(url_long), long_token, "long segment > 64B preserved without truncation");

        // Deep path (> 16 segments)
        let url_deep = wing::new_url("https://example.com/1/2/3/4/5/6/7/8/9/10/11/12/13/14/15/16/17/18/19/20");
        sub.assert_true(url_deep.valid, "deep path > 16 segments valid");
        sub.assert_bytes_eq(wing::last_path_component(url_deep), "20", "20th segment preserved");
    };

    t.run("3.1..3.4: Strict IPv6 Boundary Validation, Leading Zeros & Port 0") { sub =>
        // 3.1: Single leading colon is invalid
        let bad_ipv6_lead, err_lead = wing::parse_url("http://[:1:2:3:4:5:6:7]/");
        sub.assert_false(bad_ipv6_lead.valid, "single leading colon in IPv6 rejected");
        sub.assert_true(err_lead == wing::UrlParseError.InvalidIpv6, "InvalidIpv6 error on single leading colon");

        // 3.2: Trailing single colon is invalid
        let bad_ipv6_trail, err_trail = wing::parse_url("http://[fe80::1:]/");
        sub.assert_false(bad_ipv6_trail.valid, "trailing single colon in IPv6 rejected");

        let bad_ipv6_full_trail, err_ft = wing::parse_url("http://[1:2:3:4:5:6:7:8:]/");
        sub.assert_false(bad_ipv6_full_trail.valid, "trailing single colon on 8-piece IPv6 rejected");

        // 3.3: Leading zeros in IPv4 octet within IPv6 forbidden
        let bad_ipv4_zero, err_zero = wing::parse_url("http://[::ffff:192.168.001.1]/");
        sub.assert_false(bad_ipv4_zero.valid, "leading zero in IPv4-in-IPv6 octet rejected");

        // 3.4: Port 0 is valid in WHATWG URL
        let url_port_zero, err_zero_port = wing::parse_url("http://example.com:0/path");
        sub.assert_true(url_port_zero.valid, "port 0 is valid");
        sub.assert_eq(wing::effective_port(url_port_zero), 0, "effective port is 0");
        sub.assert_bytes_eq(wing::port_str(url_port_zero), "0", "port_str is 0");

        // Empty port after IPv6 is valid (defaults to scheme default)
        let url_ipv6_empty_port, err_ep = wing::parse_url("http://[::1]:/path");
        sub.assert_true(url_ipv6_empty_port.valid, "empty port after IPv6 is valid");
        sub.assert_eq(wing::effective_port(url_ipv6_empty_port), 80, "empty port defaults to 80");

        // Empty host with port in HTTP is rejected
        let url_empty_host, err_eh = wing::parse_url("http://:80/path");
        sub.assert_false(url_empty_host.valid, "empty host in http rejected");
        sub.assert_true(err_eh == wing::UrlParseError.MissingHost, "MissingHost on empty host");
    };

    t.run("4.1..4.3: UNC Server Round-Trip, Drive Protection & Trailing Slash Extensions") { sub =>
        // 4.1: UNC server name preserved in file_path()
        let url_unc = wing::new_file_url("\\\\nas\\share\\backup.zip");
        var os_unc: u8[..256] = [];
        let ok_unc = wing::file_path(url_unc, os_unc);
        sub.assert_true(ok_unc, "file_path succeeded on UNC URL");
        sub.assert_bytes_eq(os_unc[..], "\\\\nas\\share\\backup.zip", "UNC server name preserved in file_path");

        // 4.2: Windows drive letter C: protected on .. and deleting_last_path_component
        let url_drive_up = wing::new_url("file:///C:/Users/..");
        sub.assert_bytes_eq(wing::pathname(url_drive_up), "/C:/", "popping above Users leaves drive root /C:/");

        let url_drive_root_up = wing::new_url("file:///C:/..");
        sub.assert_bytes_eq(wing::pathname(url_drive_root_up), "/C:/", "popping above drive root stays at /C:/");

        let url_drive_root = wing::new_file_url("C:\\");
        let stay_root = wing::deleting_last_path_component(url_drive_root);
        sub.assert_bytes_eq(wing::pathname(stay_root), "/C:/", "deletingLastPathComponent on drive root stays at /C:/");

        // 4.3: deleting_path_extension and appending_path_extension with trailing slash
        let url_folder_ext = wing::new_url("file:///a/b/archive.tar/");
        let url_no_ext = wing::deleting_path_extension(url_folder_ext);
        sub.assert_bytes_eq(wing::pathname(url_no_ext), "/a/b/archive/", "deletingPathExtension with trailing slash leaves clean folder");

        let url_folder = wing::new_url("file:///a/b/dir/");
        let url_added_ext = wing::appending_path_extension(url_folder, "bundle");
        sub.assert_bytes_eq(wing::pathname(url_added_ext), "/a/b/dir.bundle/", "appendingPathExtension with trailing slash preserves folder structure");
    };

    t.run("5.1 & 5.3: Base URL Without Authority & InvalidScheme Rejection") { sub =>
        // 5.1: Base URL without authority (custom:/root) does not panic on relative resolution
        let base_no_auth, err_base = wing::parse_url("custom:/root");
        sub.assert_true(base_no_auth.valid, "base without authority valid");
        let rel_resolved, err_rel = wing::parse_url_with_base("leaf", base_no_auth);
        sub.assert_true(rel_resolved.valid, "relative resolution against authority-less base succeeded");
        sub.assert_bytes_eq(wing::href(rel_resolved), "custom:/leaf", "resolved relative path against authority-less base");

        // 5.3: InvalidScheme error returned when leading character is non-alpha
        let bad_scheme, err_scheme = wing::parse_url("123://example.com");
        sub.assert_false(bad_scheme.valid, "123:// rejected");
        sub.assert_true(err_scheme == wing::UrlParseError.InvalidScheme, "InvalidScheme returned on 123://");
    };
}

// ----------------------------------------------------------------------------
// 4. Canonical WPT & Edge Case Test Vectors (Categories 2 through 8)
// ----------------------------------------------------------------------------
fn test_canonical_wpt_and_edge_vectors(t: wing::T&) {
    t.run("Category 2: Lexer, C0 Controls, Spaces & Scheme Parsing (LEX-01..09)") { sub =>
        // LEX-01: Trim C0 control characters and spaces (<= 0x20) around edges
        let url_lex01, err_lex01 = wing::parse_url("\x00\x01\x1F https://example.com/path \x20\x09\x0A");
        sub.assert_true(url_lex01.valid, "LEX-01: valid after edge trimming");
        sub.assert_bytes_eq(wing::href(url_lex01), "https://example.com/path", "LEX-01: trimmed href matches");

        // LEX-02: Strip internal ASCII tab (0x09), LF (0x0A), CR (0x0D) across all parts
        let url_lex02, err_lex02 = wing::parse_url("ht\ttp\n://ex\rample.com/a\tb\nc?q=1\t2#h\nash");
        sub.assert_true(url_lex02.valid, "LEX-02: valid after internal tab/newline stripping");
        sub.assert_bytes_eq(wing::href(url_lex02), "http://example.com/abc?q=12#hash", "LEX-02: internal tabs/newlines removed");

        // LEX-03: Lowercase scheme and host, preserve pathname casing
        let url_lex03, err_lex03 = wing::parse_url("HTTP://ExAmPlE.CoM/Path");
        sub.assert_true(url_lex03.valid, "LEX-03: valid mixed case URL");
        sub.assert_bytes_eq(wing::href(url_lex03), "http://example.com/Path", "LEX-03: scheme/host lowercased, pathname preserved");

        // LEX-04: Forbidden C0 byte 0x01 in host rejected
        let url_lex04, err_lex04 = wing::parse_url("http://exam\x01ple.com/");
        sub.assert_false(url_lex04.valid, "LEX-04: C0 in host rejected");
        sub.assert_true(err_lex04 == wing::UrlParseError.ForbiddenHostCodePoint, "LEX-04: ForbiddenHostCodePoint on 0x01");

        // LEX-05: Forbidden byte 0x7F in host rejected
        let url_lex05, err_lex05 = wing::parse_url("http://exam\x7Fple.com/");
        sub.assert_false(url_lex05.valid, "LEX-05: 0x7F DEL in host rejected");
        sub.assert_true(err_lex05 == wing::UrlParseError.ForbiddenHostCodePoint, "LEX-05: ForbiddenHostCodePoint on 0x7F");

        // LEX-06: Raw percent '%' in special scheme host rejected
        let url_lex06, err_lex06 = wing::parse_url("http://example%2ecom/");
        sub.assert_false(url_lex06.valid, "LEX-06: percent in host rejected");
        sub.assert_true(err_lex06 == wing::UrlParseError.ForbiddenHostCodePoint, "LEX-06: ForbiddenHostCodePoint on %");

        // LEX-07: Scheme starting with digit rejected
        let url_lex07, err_lex07 = wing::parse_url("123://example.com");
        sub.assert_false(url_lex07.valid, "LEX-07: scheme starting with digit rejected");
        sub.assert_true(err_lex07 == wing::UrlParseError.InvalidScheme, "LEX-07: InvalidScheme on leading digit");

        // LEX-08: Scheme containing +, -, ., and digits from second char accepted
        let url_lex08, err_lex08 = wing::parse_url("a+b-c.1://example.com/test");
        sub.assert_true(url_lex08.valid, "LEX-08: valid scheme with +, -, ., digits");
        sub.assert_bytes_eq(wing::scheme(url_lex08), "a+b-c.1", "LEX-08: scheme matches");
        sub.assert_bytes_eq(wing::href(url_lex08), "a+b-c.1://example.com/test", "LEX-08: href matches");

        // LEX-09: Empty input or whitespace-only input rejected
        let url_lex09_empty, err_lex09_empty = wing::parse_url("");
        sub.assert_false(url_lex09_empty.valid, "LEX-09: empty input rejected");
        sub.assert_true(err_lex09_empty == wing::UrlParseError.EmptyInput, "LEX-09: EmptyInput error on empty string");

        let url_lex09_ws, err_lex09_ws = wing::parse_url(" \t\r\n ");
        sub.assert_false(url_lex09_ws.valid, "LEX-09: whitespace-only rejected");
        sub.assert_true(err_lex09_ws == wing::UrlParseError.EmptyInput, "LEX-09: EmptyInput on whitespace");
    };

    t.run("Category 3: Authority, Userinfo & Interop Collisions (AUTH-01..08)") { sub =>
        // AUTH-01: Backslashes equivalent to slashes in special schemes
        let url_auth01 = wing::new_url("http:\\\\example.com\\a\\b");
        sub.assert_true(url_auth01.valid, "AUTH-01: valid backslashes url");
        sub.assert_bytes_eq(wing::href(url_auth01), "http://example.com/a/b", "AUTH-01: backslashes normalized to slashes");

        // AUTH-02: Special schemes absorb leading slashes
        let url_auth02 = wing::new_url("https://///example.com/test");
        sub.assert_true(url_auth02.valid, "AUTH-02: valid multi-slash url");
        sub.assert_bytes_eq(wing::href(url_auth02), "https://example.com/test", "AUTH-02: excess leading slashes absorbed");

        // AUTH-03: Single slash with different special scheme from base does not downgrade
        let base_auth03 = wing::new_url("http://old.com/dir/p");
        let url_auth03 = wing::new_url("https:/example.com/login", base_auth03);
        sub.assert_true(url_auth03.valid, "AUTH-03: valid https URL");
        sub.assert_bytes_eq(wing::href(url_auth03), "https://example.com/login", "AUTH-03: scheme remains https and host is example.com");

        // AUTH-04: Single slash with same scheme as base resolves from base root
        let base_auth04 = wing::new_url("http://example.com/dir/p");
        let url_auth04 = wing::new_url("http:/secure/login", base_auth04);
        sub.assert_true(url_auth04.valid, "AUTH-04: valid relative resolution");
        sub.assert_bytes_eq(wing::href(url_auth04), "http://example.com/secure/login", "AUTH-04: single slash resolves from root of base");

        // AUTH-05: Last @ in authority serves as userinfo delimiter per WHATWG URL
        let url_auth05 = wing::new_url("http://user@evil.com:pass@good.com/");
        sub.assert_true(url_auth05.valid, "AUTH-05: valid userinfo with multiple @");
        sub.assert_bytes_eq(wing::hostname(url_auth05), "good.com", "AUTH-05: host after last @ is good.com");
        sub.assert_bytes_eq(wing::username(url_auth05), "user%40evil.com", "AUTH-05: username has @ encoded as %40");
        sub.assert_bytes_eq(wing::password(url_auth05), "pass", "AUTH-05: password is pass");

        // AUTH-06: Empty username and empty password (:@) omitted in serialization
        let url_auth06 = wing::new_url("https://:@example.com/path");
        sub.assert_true(url_auth06.valid, "AUTH-06: valid empty credentials url");
        sub.assert_bytes_eq(wing::href(url_auth06), "https://example.com/path", "AUTH-06: :@ omitted from href");
        sub.assert_false(wing::has_credentials(url_auth06), "AUTH-06: has_credentials is false");

        // AUTH-07: Empty password after colon (user:@) omits colon before @
        let url_auth07 = wing::new_url("https://user:@example.com/");
        sub.assert_true(url_auth07.valid, "AUTH-07: valid user without password");
        sub.assert_bytes_eq(wing::href(url_auth07), "https://user@example.com/", "AUTH-07: empty password omits colon");
        sub.assert_bytes_eq(wing::username(url_auth07), "user", "AUTH-07: username is user");
        sub.assert_bytes_eq(wing::password(url_auth07), "", "AUTH-07: password is empty");

        // AUTH-08: Empty username with password (:pass@) retains leading colon
        let url_auth08 = wing::new_url("https://:pass@example.com/");
        sub.assert_true(url_auth08.valid, "AUTH-08: valid password without user");
        sub.assert_bytes_eq(wing::href(url_auth08), "https://:pass@example.com/", "AUTH-08: retains leading colon");
        sub.assert_bytes_eq(wing::username(url_auth08), "", "AUTH-08: username is empty");
        sub.assert_bytes_eq(wing::password(url_auth08), "pass", "AUTH-08: password is pass");
    };

    t.run("Category 4: IPv6 RFC 5952 Canonical Compression & Ports (IPV6-01..10, PORT-01..07)") { sub =>
        // IPV6-01: Zero run compressed to :: and leading zeros stripped
        let url_ip01 = wing::new_url("http://[2001:0db8:0000:0000:0000:0000:1428:57ab]/");
        sub.assert_bytes_eq(wing::href(url_ip01), "http://[2001:db8::1428:57ab]/", "IPV6-01: zero run compressed to ::");

        // IPV6-02: Single zero block is not compressed to ::
        let url_ip02 = wing::new_url("http://[2001:db8:0:1:1:1:1:1]/");
        sub.assert_bytes_eq(wing::href(url_ip02), "http://[2001:db8:0:1:1:1:1:1]/", "IPV6-02: single zero block not compressed");

        // IPV6-03: Two equal zero runs compress the first run
        let url_ip03 = wing::new_url("http://[2001:db8:0:0:1:0:0:1]/");
        sub.assert_bytes_eq(wing::href(url_ip03), "http://[2001:db8::1:0:0:1]/", "IPV6-03: first equal zero run compressed");

        // IPV6-04: Loopback address compressed and port separation
        let url_ip04 = wing::new_url("http://[0:0:0:0:0:0:0:1]:8080/");
        sub.assert_bytes_eq(wing::hostname(url_ip04), "[::1]", "IPV6-04: hostname is [::1]");
        sub.assert_bytes_eq(wing::host(url_ip04), "[::1]:8080", "IPV6-04: host is [::1]:8080");

        // IPV6-05: All eight zero groups compressed to [::]
        let url_ip05 = wing::new_url("http://[0:0:0:0:0:0:0:0]/");
        sub.assert_bytes_eq(wing::href(url_ip05), "http://[::]/", "IPV6-05: all zeros compressed to [::]");

        // IPV6-06: IPv4-mapped IPv6 suffix parsed into 2 hex blocks
        let url_ip06 = wing::new_url("http://[::ffff:192.0.2.128]/");
        sub.assert_bytes_eq(wing::href(url_ip06), "http://[::ffff:c000:280]/", "IPV6-06: mapped IPv4 hex converted");

        // IPV6-07: Single leading colon rejected
        let url_ip07, err_ip07 = wing::parse_url("http://[:1:2:3:4:5:6:7]/");
        sub.assert_false(url_ip07.valid, "IPV6-07: single leading colon rejected");
        sub.assert_true(err_ip07 == wing::UrlParseError.InvalidIpv6, "IPV6-07: InvalidIpv6");

        // IPV6-08: Trailing colon rejected
        let url_ip08, err_ip08 = wing::parse_url("http://[fe80::1:]/");
        sub.assert_false(url_ip08.valid, "IPV6-08: trailing colon rejected");
        sub.assert_true(err_ip08 == wing::UrlParseError.InvalidIpv6, "IPV6-08: InvalidIpv6");

        // IPV6-09: Multiple :: compressions rejected
        let url_ip09, err_ip09 = wing::parse_url("http://[2001::db8::1]/");
        sub.assert_false(url_ip09.valid, "IPV6-09: double :: rejected");
        sub.assert_true(err_ip09 == wing::UrlParseError.InvalidIpv6, "IPV6-09: InvalidIpv6");

        // IPV6-10: Leading zeros in IPv4 octets within IPv6 rejected
        let url_ip10, err_ip10 = wing::parse_url("http://[::ffff:192.168.001.1]/");
        sub.assert_false(url_ip10.valid, "IPV6-10: leading zero in IPv4 octet rejected");
        sub.assert_true(err_ip10 == wing::UrlParseError.InvalidIpv6, "IPV6-10: InvalidIpv6");

        // PORT-01: Default ports stripped in special schemes
        let u_p1_1 = wing::new_url("http://example.com:80/");
        let u_p1_2 = wing::new_url("https://example.com:443/");
        let u_p1_3 = wing::new_url("ws://example.com:80/");
        let u_p1_4 = wing::new_url("wss://example.com:443/");
        sub.assert_bytes_eq(wing::href(u_p1_1), "http://example.com/", "PORT-01: http:80 stripped");
        sub.assert_bytes_eq(wing::href(u_p1_2), "https://example.com/", "PORT-01: https:443 stripped");
        sub.assert_bytes_eq(wing::href(u_p1_3), "ws://example.com/", "PORT-01: ws:80 stripped");
        sub.assert_bytes_eq(wing::href(u_p1_4), "wss://example.com/", "PORT-01: wss:443 stripped");

        // PORT-02: Non-default ports preserved
        let u_p2_1 = wing::new_url("http://example.com:443/");
        let u_p2_2 = wing::new_url("https://example.com:80/");
        sub.assert_bytes_eq(wing::href(u_p2_1), "http://example.com:443/", "PORT-02: http:443 preserved");
        sub.assert_bytes_eq(wing::href(u_p2_2), "https://example.com:80/", "PORT-02: https:80 preserved");

        // PORT-03: Leading zeros stripped from port and default port eliminated
        let url_port03 = wing::new_url("http://example.com:00000000000080/");
        sub.assert_bytes_eq(wing::href(url_port03), "http://example.com/", "PORT-03: leading zeros stripped and port 80 omitted");

        // PORT-04: Port 0 is valid
        let url_port04 = wing::new_url("http://example.com:0/");
        sub.assert_bytes_eq(wing::href(url_port04), "http://example.com:0/", "PORT-04: port 0 serialized");
        sub.assert_bytes_eq(wing::port_str(url_port04), "0", "PORT-04: port_str is 0");
        sub.assert_eq(wing::effective_port(url_port04), 0, "PORT-04: effective port is 0");

        // PORT-05: Empty port after colon ignored
        let u_p5_1 = wing::new_url("http://example.com:/");
        let u_p5_2 = wing::new_url("http://[::1]:/");
        sub.assert_bytes_eq(wing::href(u_p5_1), "http://example.com/", "PORT-05: empty port on host ignored");
        sub.assert_bytes_eq(wing::href(u_p5_2), "http://[::1]/", "PORT-05: empty port on IPv6 ignored");

        // PORT-06: Port out of range (> 65535) or double port rejected
        let url_p6_high, err_p6_high = wing::parse_url("http://example.com:65536/");
        sub.assert_false(url_p6_high.valid, "PORT-06: 65536 rejected");
        sub.assert_true(err_p6_high == wing::UrlParseError.InvalidPort, "PORT-06: InvalidPort on 65536");

        let url_p6_double, err_p6_double = wing::parse_url("http://127.0.0.1:11211:80/");
        sub.assert_false(url_p6_double.valid, "PORT-06: double port rejected");
        sub.assert_true(err_p6_double == wing::UrlParseError.InvalidPort, "PORT-06: InvalidPort on double port");

        // PORT-07: Missing host in special scheme rejected
        let url_p7_mh1, err_p7_mh1 = wing::parse_url("http://:80/path");
        sub.assert_false(url_p7_mh1.valid, "PORT-07: empty host in http rejected");
        sub.assert_true(err_p7_mh1 == wing::UrlParseError.MissingHost, "PORT-07: MissingHost on http://:80");

        let url_p7_mh2, err_p7_mh2 = wing::parse_url("https:///path");
        sub.assert_false(url_p7_mh2.valid, "PORT-07: empty host in https rejected");
        sub.assert_true(err_p7_mh2 == wing::UrlParseError.MissingHost, "PORT-07: MissingHost on https:///path");
    };

    t.run("Category 5: Path Collapsing, Dot-Segments & Relative Resolution (PATH-01..07, REL-01..07)") { sub =>
        // PATH-01: Trailing slash preserved after ..
        let u_path01 = wing::new_url("https://example.com/a/b/..");
        sub.assert_bytes_eq(wing::pathname(u_path01), "/a/", "PATH-01: trailing slash after ..");

        // PATH-02: Trailing slash preserved after .
        let u_path02 = wing::new_url("https://example.com/a/b/.");
        sub.assert_bytes_eq(wing::pathname(u_path02), "/a/b/", "PATH-02: trailing slash after .");

        // PATH-03: Percent-encoded dot segments recognized case-insensitively
        let u_path03_1 = wing::new_url("https://example.com/a/b/%2e");
        let u_path03_2 = wing::new_url("https://example.com/a/b/%2E%2e");
        sub.assert_bytes_eq(wing::pathname(u_path03_1), "/a/b/", "PATH-03: %2e preserved as dot");
        sub.assert_bytes_eq(wing::pathname(u_path03_2), "/a/", "PATH-03: %2E%2e popped like ..");

        // PATH-04: Popping above root is absorbed
        let u_path04 = wing::new_url("https://example.com/../../../a/b");
        sub.assert_bytes_eq(wing::pathname(u_path04), "/a/b", "PATH-04: above root absorbed");

        // PATH-05: Empty path segments (//) preserved
        let u_path05 = wing::new_url("https://example.com/api//v1///users");
        sub.assert_bytes_eq(wing::pathname(u_path05), "/api//v1///users", "PATH-05: // preserved");

        // PATH-06: Long 120-byte segment preserved without truncation
        var long_a: u8[..256] = [];
        long_a.append("https://example.com/v1/");
        for idx in 120 {
            long_a.push('a');
        }
        long_a.append("/profile");
        let url_p6 = wing::new_url(long_a[..]);
        sub.assert_true(url_p6.valid, "PATH-06: 120B segment url valid");
        sub.assert_bytes_eq(wing::pathname(url_p6), long_a[19..], "PATH-06: 120B segment not truncated");

        // PATH-07: Deep path with 25 segments preserved
        var deep_path: u8[..256] = [];
        deep_path.append("https://example.com");
        for seg_idx in 25 {
            deep_path.append("/s");
            format(deep_path, (seg_idx + 1) as i64);
        }
        let url_p7 = wing::new_url(deep_path[..]);
        sub.assert_true(url_p7.valid, "PATH-07: 25 segments valid");
        sub.assert_bytes_eq(wing::last_path_component(url_p7), "s25", "PATH-07: 25th segment preserved");

        // REL-01: Empty relative URL strips fragment from base
        let base_rel = wing::new_url("https://example.com/a/b?q=1#old");
        let url_rel01 = wing::new_url("", base_rel);
        sub.assert_bytes_eq(wing::href(url_rel01), "https://example.com/a/b?q=1", "REL-01: empty rel strips hash");

        // REL-02: Hash-only relative replaces hash
        let url_rel02 = wing::new_url("#new-frag", base_rel);
        sub.assert_bytes_eq(wing::href(url_rel02), "https://example.com/a/b?q=1#new-frag", "REL-02: replaces hash");

        // REL-03: Query and hash relative replaces search and hash
        let base_rel_q = wing::new_url("https://example.com/a/b?old=1#old");
        let url_rel03 = wing::new_url("?new-query#frag", base_rel_q);
        sub.assert_bytes_eq(wing::href(url_rel03), "https://example.com/a/b?new-query#frag", "REL-03: replaces search and hash");

        // REL-04: Relative without trailing slash drops last component of base
        let base_no_slash = wing::new_url("https://example.com/a/b");
        let url_rel04 = wing::new_url("c/d.html", base_no_slash);
        sub.assert_bytes_eq(wing::href(url_rel04), "https://example.com/a/c/d.html", "REL-04: drops b and appends c/d.html");

        // REL-05: Relative with trailing slash appends inside directory
        let base_with_slash = wing::new_url("https://example.com/a/b/");
        let url_rel05 = wing::new_url("c/d.html", base_with_slash);
        sub.assert_bytes_eq(wing::href(url_rel05), "https://example.com/a/b/c/d.html", "REL-05: appends inside directory b/");

        // REL-06: Network-path (//...) inherits scheme from base
        let url_rel06 = wing::new_url("//cdn.example.org/app.js", base_no_slash);
        sub.assert_bytes_eq(wing::href(url_rel06), "https://cdn.example.org/app.js", "REL-06: inherits https from base");

        // REL-07: Empty query and hash boundary (?#)
        let url_rel07 = wing::new_url("https://example.com?#");
        sub.assert_bytes_eq(wing::href(url_rel07), "https://example.com/?#", "REL-07: href includes ?#");
        sub.assert_bytes_eq(wing::search(url_rel07), "?", "REL-07: search is ?");
        sub.assert_bytes_eq(wing::hash(url_rel07), "#", "REL-07: hash is #");
    };

    t.run("Category 6: Non-Special URLs & Opaque Paths (NSPEC-01..07)") { sub =>
        // NSPEC-01: Non-special scheme with opaque path
        let url_ns01 = wing::new_url("mailto:user@example.com?subject=Test#top");
        sub.assert_true(url_ns01.has_opaque_path, "NSPEC-01: opaque path true");
        sub.assert_bytes_eq(wing::pathname(url_ns01), "user@example.com", "NSPEC-01: pathname is user@example.com");
        sub.assert_bytes_eq(wing::search(url_ns01), "?subject=Test", "NSPEC-01: search parsed");
        sub.assert_bytes_eq(wing::hash(url_ns01), "#top", "NSPEC-01: hash parsed");

        // NSPEC-02: Relative path cannot resolve against opaque base
        let base_ns02 = wing::new_url("mailto:user@example.com");
        let url_ns02, err_ns02 = wing::parse_url_with_base("subpage.html", base_ns02);
        sub.assert_false(url_ns02.valid, "NSPEC-02: relative against opaque base rejected");
        sub.assert_true(err_ns02 == wing::UrlParseError.OpaqueBaseCannotResolveRelative, "NSPEC-02: OpaqueBaseCannotResolveRelative");

        // NSPEC-03: Fragment-only replacement allowed against opaque base
        let base_ns03 = wing::new_url("data:text/html,<h1>Hi</h1>#section1");
        let url_ns03 = wing::new_url("#section2", base_ns03);
        sub.assert_true(url_ns03.valid, "NSPEC-03: fragment replacement on opaque base succeeded");
        sub.assert_bytes_eq(wing::href(url_ns03), "data:text/html,<h1>Hi</h1>#section2", "NSPEC-03: hash replaced on opaque base");

        // NSPEC-04: Non-special scheme does not convert backslash to slash
        let url_ns04 = wing::new_url("git://github.com/a\\b/c");
        sub.assert_bytes_eq(wing::href(url_ns04), "git://github.com/a\\b/c", "NSPEC-04: backslash preserved in non-special scheme");

        // NSPEC-05: Non-special scheme allows empty host
        let url_ns05 = wing::new_url("git:///repo/path");
        sub.assert_true(url_ns05.valid, "NSPEC-05: valid non-special empty host");
        sub.assert_bytes_eq(wing::hostname(url_ns05), "", "NSPEC-05: hostname is empty");
        sub.assert_bytes_eq(wing::pathname(url_ns05), "/repo/path", "NSPEC-05: pathname is /repo/path");

        // NSPEC-06: Non-special scheme with single slash has hierarchical path with dot collapsing
        let url_ns06 = wing::new_url("custom:/a/b/../c");
        sub.assert_true(url_ns06.valid, "NSPEC-06: valid hierarchical non-special");
        sub.assert_false(url_ns06.has_opaque_path, "NSPEC-06: has_opaque_path is false");
        sub.assert_bytes_eq(wing::href(url_ns06), "custom:/a/c", "NSPEC-06: collapsed path to custom:/a/c");

        // NSPEC-07: Relative resolution against non-special base with slash
        let base_ns07 = wing::new_url("git://host/");
        let url_ns07 = wing::new_url("path", base_ns07);
        sub.assert_bytes_eq(wing::href(url_ns07), "git://host/path", "NSPEC-07: resolved against non-special base");
    };

    t.run("Category 7: File URLs & Swift Path Manipulation (FILE-01..09)") { sub =>
        // FILE-01: localhost host on file: URL is normalized to empty host
        let url_f01 = wing::new_url("file://localhost/etc/hosts");
        sub.assert_bytes_eq(wing::href(url_f01), "file:///etc/hosts", "FILE-01: localhost normalized to empty host");
        sub.assert_bytes_eq(wing::hostname(url_f01), "", "FILE-01: hostname is empty");

        // FILE-02: Windows drive letter normalization and encoding
        let url_f02 = wing::new_file_url("C:\\Users\\Admin\\my doc#1.txt");
        sub.assert_bytes_eq(wing::href(url_f02), "file:///C:/Users/Admin/my%20doc%231.txt", "FILE-02: normalized drive letter and encoded #");

        // FILE-03: file_path conversion from file: URL to Windows path
        let url_f03 = wing::new_url("file:///C:/Users/my%20doc.txt");
        var win_path: u8[..256] = [];
        let ok_f03 = wing::file_path(url_f03, win_path);
        sub.assert_true(ok_f03, "FILE-03: file_path succeeded");
        sub.assert_bytes_eq(win_path[..], "C:\\Users\\my doc.txt", "FILE-03: decoded Windows path");

        // FILE-04: UNC network share round-trip
        let url_f04 = wing::new_file_url("\\\\server\\share\\folder\\file.txt");
        sub.assert_bytes_eq(wing::href(url_f04), "file://server/share/folder/file.txt", "FILE-04: UNC host in href");
        var unc_path: u8[..256] = [];
        let ok_f04 = wing::file_path(url_f04, unc_path);
        sub.assert_true(ok_f04, "FILE-04: file_path succeeded for UNC");
        sub.assert_bytes_eq(unc_path[..], "\\\\server\\share\\folder\\file.txt", "FILE-04: UNC path preserved");

        // FILE-05: Windows drive root cannot be popped by ..
        let url_f05 = wing::new_url("file:///C:/Users/../..");
        sub.assert_bytes_eq(wing::href(url_f05), "file:///C:/", "FILE-05: popping above drive root stays at file:///C:/");

        // FILE-06: deleting_path_extension on directory with trailing slash
        let url_f06_base = wing::new_url("file:///a/b/archive.tar/");
        let url_f06 = wing::deleting_path_extension(url_f06_base);
        sub.assert_bytes_eq(wing::pathname(url_f06), "/a/b/archive/", "FILE-06: trailing slash preserved after extension deletion");

        // FILE-07: appending_path_extension before trailing slash
        let url_f07_base = wing::new_url("file:///a/b/dir/");
        let url_f07 = wing::appending_path_extension(url_f07_base, "Bak");
        sub.assert_bytes_eq(wing::pathname(url_f07), "/a/b/dir.Bak/", "FILE-07: extension appended before trailing slash");

        // FILE-08: Leading and trailing dots are not considered extensions
        let url_f08_git = wing::new_url("file:///a/.gitignore");
        let url_f08_dot = wing::new_url("file:///a/file.");
        sub.assert_bytes_eq(wing::path_extension(url_f08_git), "", "FILE-08: .gitignore has empty extension");
        sub.assert_bytes_eq(wing::path_extension(url_f08_dot), "", "FILE-08: trailing dot has empty extension");

        // FILE-09: deleting_last_path_component on drive root stays at drive root
        let url_f09_root = wing::new_url("file:///C:/");
        let url_f09 = wing::deleting_last_path_component(url_f09_root);
        sub.assert_bytes_eq(wing::pathname(url_f09), "/C:/", "FILE-09: deletingLastPathComponent on C:/ stays at /C:/");
    };

    t.run("Category 8: Origin, PSL & Schemeful Same-Site RFC 6265bis (SEC-01..10)") { sub =>
        // SEC-01: Tuple origin omits default port 443
        let url_sec01 = wing::new_url("https://Example.COM:443/a");
        var orig_str01: u8[..64] = [];
        wing::serialize_origin(wing::origin_from_url(url_sec01), orig_str01);
        sub.assert_bytes_eq(orig_str01[..], "https://example.com", "SEC-01: default port omitted");

        // SEC-02: Non-default port serialized in origin
        let url_sec02 = wing::new_url("https://example.com:8443/a");
        var orig_str02: u8[..64] = [];
        wing::serialize_origin(wing::origin_from_url(url_sec02), orig_str02);
        sub.assert_bytes_eq(orig_str02[..], "https://example.com:8443", "SEC-02: non-default port serialized");

        // SEC-03: blob: inherits nested origin tuple
        let url_sec03 = wing::new_url("blob:https://example.com:8443/550e8400-e29b");
        let orig_blob = wing::origin_from_url(url_sec03);
        sub.assert_true(orig_blob.kind == wing::OriginKind.Tuple, "SEC-03: blob origin is Tuple");
        sub.assert_bytes_eq(orig_blob.scheme[..], "https", "SEC-03: blob inherited scheme");
        sub.assert_bytes_eq(orig_blob.host[..], "example.com", "SEC-03: blob inherited host");
        sub.assert_eq(orig_blob.port, 8443, "SEC-03: blob inherited port 8443");

        // SEC-04: file: and data: origins are opaque with distinct nonces
        let url_sec04_file = wing::new_url("file:///path");
        let url_sec04_data = wing::new_url("data:text/plain,hi");
        let orig_file = wing::origin_from_url(url_sec04_file);
        let orig_data = wing::origin_from_url(url_sec04_data);
        var ser_file: u8[..64] = [];
        var ser_data: u8[..64] = [];
        wing::serialize_origin(orig_file, ser_file);
        wing::serialize_origin(orig_data, ser_data);
        sub.assert_bytes_eq(ser_file[..], "null", "SEC-04: file origin serialized to null");
        sub.assert_bytes_eq(ser_data[..], "null", "SEC-04: data origin serialized to null");
        sub.assert_false(wing::is_same_origin(orig_file, orig_data), "SEC-04: distinct opaque origins are not same-origin");

        // SEC-05: ICANN multi-part suffix (co.uk) eTLD+1 extraction
        let url_sec05 = wing::new_url("https://sub.books.amazon.co.uk/p");
        let site_uk = wing::registrable_site_from_url(url_sec05);
        sub.assert_bytes_eq(site_uk.scheme[..], "https", "SEC-05: scheme is https");
        sub.assert_bytes_eq(site_uk.registrable_domain[..], "amazon.co.uk", "SEC-05: eTLD+1 is amazon.co.uk");

        // SEC-06: PSL private section tenant isolation (github.io)
        let url_sec06_a = wing::new_url("https://tenantA.github.io");
        let url_sec06_b = wing::new_url("https://tenantB.github.io");
        let same_site_tenants = wing::is_schemeful_same_site_urls(url_sec06_a, url_sec06_b);
        sub.assert_false(same_site_tenants, "SEC-06: different tenants on private suffix are cross-site");

        // SEC-07: Subdomains and ports on same eTLD+1 with same scheme are schemeful same-site
        let url_sec07_a = wing::new_url("https://a.example.com:8000");
        let url_sec07_b = wing::new_url("https://b.example.com:9000");
        let same_site_sub = wing::is_schemeful_same_site_urls(url_sec07_a, url_sec07_b);
        sub.assert_true(same_site_sub, "SEC-07: subdomains and different ports are same-site");

        // SEC-08: Scheme difference (https vs http) is cross-site
        let url_sec08_a = wing::new_url("https://example.com");
        let url_sec08_b = wing::new_url("http://example.com");
        let same_site_diff_scheme = wing::is_schemeful_same_site_urls(url_sec08_a, url_sec08_b);
        sub.assert_false(same_site_diff_scheme, "SEC-08: scheme mismatch is cross-site");

        // SEC-09: Empty registrable domain (data:, about:) is never same-site
        let url_sec09_a = wing::new_url("data:text/html,1");
        let url_sec09_b = wing::new_url("data:text/html,2");
        let same_site_data = wing::is_schemeful_same_site_urls(url_sec09_a, url_sec09_b);
        sub.assert_false(same_site_data, "SEC-09: data: URLs are never same-site");

        // SEC-10: IP literals compare entire host and scheme
        let url_sec10_a1 = wing::new_url("http://127.0.0.1:8080/");
        let url_sec10_a2 = wing::new_url("http://127.0.0.1:9090/");
        let ip_same = wing::is_schemeful_same_site_urls(url_sec10_a1, url_sec10_a2);
        sub.assert_true(ip_same, "SEC-10: same IPv4 with different ports is same-site");

        let url_sec10_b1 = wing::new_url("http://127.0.0.1/");
        let url_sec10_b2 = wing::new_url("http://127.0.0.2/");
        let ip_diff = wing::is_schemeful_same_site_urls(url_sec10_b1, url_sec10_b2);
        sub.assert_false(ip_diff, "SEC-10: different IPv4 addresses are cross-site");
    };

    t.run("Exhaustive Non-Happy Path Matrix: Errors, Bounds & Injection Rejection") { sub =>
        // 1. RelativeWithoutBase error when no base is provided
        let u_nobase_1, err_nobase_1 = wing::parse_url("../path");
        sub.assert_false(u_nobase_1.valid, "NEG: ../path rejected without base");
        sub.assert_true(err_nobase_1 == wing::UrlParseError.RelativeWithoutBase, "NEG: RelativeWithoutBase on ../path");

        let u_nobase_2, err_nobase_2 = wing::parse_url("/absolute/path");
        sub.assert_false(u_nobase_2.valid, "NEG: /path rejected without base");
        sub.assert_true(err_nobase_2 == wing::UrlParseError.RelativeWithoutBase, "NEG: RelativeWithoutBase on /path");

        let u_nobase_3, err_nobase_3 = wing::parse_url("?search");
        sub.assert_false(u_nobase_3.valid, "NEG: ?search rejected without base");
        sub.assert_true(err_nobase_3 == wing::UrlParseError.RelativeWithoutBase, "NEG: RelativeWithoutBase on ?search");

        let u_nobase_4, err_nobase_4 = wing::parse_url("#fragment");
        sub.assert_false(u_nobase_4.valid, "NEG: #frag rejected without base");
        sub.assert_true(err_nobase_4 == wing::UrlParseError.RelativeWithoutBase, "NEG: RelativeWithoutBase on #frag");

        let u_nobase_5, err_nobase_5 = wing::parse_url("rel/leaf");
        sub.assert_false(u_nobase_5.valid, "NEG: rel/leaf rejected without base");
        sub.assert_true(err_nobase_5 == wing::UrlParseError.RelativeWithoutBase, "NEG: RelativeWithoutBase on rel/leaf");

        // 2. Strict IPv6 syntax rejections
        let u_ipv6_too_many, err_ipv6_tm = wing::parse_url("http://[1:2:3:4:5:6:7:8:9]/");
        sub.assert_false(u_ipv6_too_many.valid, "NEG: 9-piece IPv6 rejected");
        sub.assert_true(err_ipv6_tm == wing::UrlParseError.InvalidIpv6, "NEG: InvalidIpv6 on 9 pieces");

        let u_ipv6_too_few, err_ipv6_tf = wing::parse_url("http://[1:2:3]/");
        sub.assert_false(u_ipv6_too_few.valid, "NEG: 3-piece IPv6 without :: rejected");
        sub.assert_true(err_ipv6_tf == wing::UrlParseError.InvalidIpv6, "NEG: InvalidIpv6 on 3 pieces");

        let u_ipv6_triple, err_ipv6_triple = wing::parse_url("http://[fe80:::1]/");
        sub.assert_false(u_ipv6_triple.valid, "NEG: triple colon IPv6 rejected");
        sub.assert_true(err_ipv6_triple == wing::UrlParseError.InvalidIpv6, "NEG: InvalidIpv6 on :::");

        let u_ipv6_nonhex, err_ipv6_nonhex = wing::parse_url("http://[zz::1]/");
        sub.assert_false(u_ipv6_nonhex.valid, "NEG: non-hex IPv6 rejected");
        sub.assert_true(err_ipv6_nonhex == wing::UrlParseError.InvalidIpv6, "NEG: InvalidIpv6 on zz");

        let u_ipv6_v4_high, err_ipv6_v4_high = wing::parse_url("http://[::192.168.1.300]/");
        sub.assert_false(u_ipv6_v4_high.valid, "NEG: IPv4 mapped octet > 255 rejected");
        sub.assert_true(err_ipv6_v4_high == wing::UrlParseError.InvalidIpv6, "NEG: InvalidIpv6 on octet 300");

        let u_ipv6_v4_short, err_ipv6_v4_short = wing::parse_url("http://[::192.168.1]/");
        sub.assert_false(u_ipv6_v4_short.valid, "NEG: IPv4 mapped incomplete octets rejected");
        sub.assert_true(err_ipv6_v4_short == wing::UrlParseError.InvalidIpv6, "NEG: InvalidIpv6 on 3 octets");

        let u_ipv6_v4_long, err_ipv6_v4_long = wing::parse_url("http://[::192.168.1.1.1]/");
        sub.assert_false(u_ipv6_v4_long.valid, "NEG: IPv4 mapped 5 octets rejected");
        sub.assert_true(err_ipv6_v4_long == wing::UrlParseError.InvalidIpv6, "NEG: InvalidIpv6 on 5 octets");

        // 3. Port parsing rejections
        let u_port_huge, err_port_huge = wing::parse_url("http://example.com:999999/");
        sub.assert_false(u_port_huge.valid, "NEG: port 999999 rejected");
        sub.assert_true(err_port_huge == wing::UrlParseError.InvalidPort, "NEG: InvalidPort on 999999");

        let u_port_alpha, err_port_alpha = wing::parse_url("http://example.com:abc/");
        sub.assert_false(u_port_alpha.valid, "NEG: port abc rejected");
        sub.assert_true(err_port_alpha == wing::UrlParseError.InvalidPort, "NEG: InvalidPort on abc");

        let u_port_neg, err_port_neg = wing::parse_url("http://example.com:-1/");
        sub.assert_false(u_port_neg.valid, "NEG: port -1 rejected");
        sub.assert_true(err_port_neg == wing::UrlParseError.InvalidPort, "NEG: InvalidPort on -1");

        let u_port_space, err_port_space = wing::parse_url("http://example.com: 80/");
        sub.assert_false(u_port_space.valid, "NEG: space in port rejected");
        sub.assert_true(err_port_space == wing::UrlParseError.InvalidPort, "NEG: InvalidPort on space in port");

        // 4. Host forbidden character rejections
        let u_host_space, err_host_space = wing::parse_url("http://exam ple.com/");
        sub.assert_false(u_host_space.valid, "NEG: space in host rejected");
        sub.assert_true(err_host_space == wing::UrlParseError.ForbiddenHostCodePoint, "NEG: ForbiddenHostCodePoint on space");

        let u_host_lt, err_host_lt = wing::parse_url("http://exam<ple.com/");
        sub.assert_false(u_host_lt.valid, "NEG: < in host rejected");
        sub.assert_true(err_host_lt == wing::UrlParseError.ForbiddenHostCodePoint, "NEG: ForbiddenHostCodePoint on <");

        let u_host_gt, err_host_gt = wing::parse_url("http://exam>ple.com/");
        sub.assert_false(u_host_gt.valid, "NEG: > in host rejected");
        sub.assert_true(err_host_gt == wing::UrlParseError.ForbiddenHostCodePoint, "NEG: ForbiddenHostCodePoint on >");

        let u_host_pipe, err_host_pipe = wing::parse_url("http://exam|ple.com/");
        sub.assert_false(u_host_pipe.valid, "NEG: | in host rejected");
        sub.assert_true(err_host_pipe == wing::UrlParseError.ForbiddenHostCodePoint, "NEG: ForbiddenHostCodePoint on |");

        // 5. Invalid scheme initial character rejections
        let u_scheme_excl, err_scheme_excl = wing::parse_url("!https://example.com/");
        sub.assert_false(u_scheme_excl.valid, "NEG: !scheme rejected");
        sub.assert_true(err_scheme_excl == wing::UrlParseError.InvalidScheme, "NEG: InvalidScheme on !");

        let u_scheme_dash, err_scheme_dash = wing::parse_url("-http://example.com/");
        sub.assert_false(u_scheme_dash.valid, "NEG: -scheme rejected");
        sub.assert_true(err_scheme_dash == wing::UrlParseError.InvalidScheme, "NEG: InvalidScheme on -");

        let u_scheme_plus, err_scheme_plus = wing::parse_url("+ftp://example.com/");
        sub.assert_false(u_scheme_plus.valid, "NEG: +scheme rejected");
        sub.assert_true(err_scheme_plus == wing::UrlParseError.InvalidScheme, "NEG: InvalidScheme on +");
    };
}

// ----------------------------------------------------------------------------
// Suite Entry Point
// ----------------------------------------------------------------------------
fn main() {
    var runner = wing::new_runner("WHATWG URL & Path Verification Suite", wing::Verbosity.Verbose);

    wing::run_case(runner, "1. WHATWG URL Parser, IPv6 RFC 5952 Compression & Origin", test_url_parser_and_origin);
    wing::run_case(runner, "2. File URL & Path Manipulation", test_swift_style_file_and_path_api);
    wing::run_case(runner, "3. WHATWG URL Standard & Security Audit Verification", test_whatwg_audit_fixes);
    wing::run_case(runner, "4. Canonical WPT & Edge Case Vectors (Categories 2..8)", test_canonical_wpt_and_edge_vectors);

    let ok = wing::finish(runner);
    assert(ok);
}
