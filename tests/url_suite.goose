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
// Suite Entry Point
// ----------------------------------------------------------------------------
fn main() {
    var runner = wing::new_runner("WHATWG URL & Path Verification Suite", wing::Verbosity.Verbose);

    wing::run_case(runner, "1. WHATWG URL Parser, IPv6 RFC 5952 Compression & Origin", test_url_parser_and_origin);
    wing::run_case(runner, "2. File URL & Path Manipulation", test_swift_style_file_and_path_api);

    let ok = wing::finish(runner);
    assert(ok);
}
