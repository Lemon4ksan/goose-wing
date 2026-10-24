// Verification Suite for Passive OS Fingerprinting (p0f v3) TCP SYN Engine.
import std;
import core from "..";
import wing from "..";

fn test_wing_authentic_p0f(t: core::T&) {
    t.run("1. Wing Authentic TCP SYN Identity Spec") { sub =>
        let sig = wing::wing_p0f_signature();

        sub.assert_eq(sig.ip_version as i64, 0, "Dual-stack wildcard IP version ('*')");
        sub.assert_eq(sig.ttl as i64, 64, "Initial TTL 64");
        sub.assert_false(sig.has_ttl_minus, "Default profile has exact initial TTL");
        sub.assert_eq(sig.ip_opt_len as i64, 0, "No archaic IP options");
        sub.assert_eq(sig.mss as i64, -1, "Wildcard MSS ('*') discovered via Path MTU");
        sub.assert_eq(sig.window_type, wing::P0fWindowType.Mss, "Dynamic window based on MSS multiplier");
        sub.assert_eq(sig.window_size as i64, 20, "Window multiplier: mss*20");
        sub.assert_eq(sig.window_scale as i64, 10, "Window scale: 10 for multi-gigabit throughput");

        // Options layout
        sub.assert_eq(sig.options.len, 5, "5 standard RFC TCP options");
        sub.assert_eq(sig.options[0], wing::P0fTcpOption.Mss, "Option 1: MSS");
        sub.assert_eq(sig.options[1], wing::P0fTcpOption.Sok, "Option 2: SACK Permitted");
        sub.assert_eq(sig.options[2], wing::P0fTcpOption.Ts, "Option 3: Timestamps");
        sub.assert_eq(sig.options[3], wing::P0fTcpOption.Nop, "Option 4: NOP alignment");
        sub.assert_eq(sig.options[4], wing::P0fTcpOption.Ws, "Option 5: Window Scale");

        // Quirks
        sub.assert_true(sig.quirks.df, "Don't Fragment (DF) enabled for Path MTU Discovery");
        sub.assert_true(sig.quirks.id_plus, "Random IP ID generated");
        sub.assert_false(sig.quirks.ecn, "ECN not set in default SYN");

        // Canonical format
        let formatted = wing::format_p0f(sig);
        sub.assert_bytes_eq(
            formatted[..],
            "*:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0",
            "Wing authentic p0f v3 wire signature matches canonical specification"
        );
    };

    t.run("2. Socket Parameter Derivation & Client Integration") { sub =>
        let sig = wing::wing_p0f_signature();
        let sock_opts = wing::p0f_to_socket_opts(sig, 1460);

        sub.assert_eq(sock_opts.ttl as i64, 64, "Socket TTL option is 64");
        sub.assert_true(sock_opts.dont_fragment, "Socket IP_DONTFRAGMENT is enabled");
        sub.assert_eq(sock_opts.receive_buffer_size as i64, 29200, "SO_RCVBUF is 1460 * 20 = 29200 bytes");

        // Profile default has wing_p0f_signature
        let profile = wing::wing_default_profile();
        let p_p0f = wing::profile_p0f(profile);
        sub.assert_bytes_eq(
            p_p0f[..],
            "*:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0",
            "Default BrowserProfile exports authentic Wing p0f signature"
        );

        // Client session exposes p0f signature
        let session = wing::new_client();
        let s_p0f = wing::session_p0f(session);
        sub.assert_bytes_eq(
            s_p0f[..],
            "*:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0",
            "New client session default p0f reflects Wing authentic identity"
        );
    };
}

fn test_p0f_parser_and_roundtrip(t: core::T&) {
    t.run("1. Standard p0f v3 Signatures Roundtrip") { sub =>
        // Vector 1: Wing Authentic Profile
        let raw1 = "*:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0";
        let sig1, ok1 = wing::parse_p0f(raw1);
        sub.assert_true(ok1, "Must parse Wing signature");
        sub.assert_bytes_eq(wing::format_p0f(sig1)[..], raw1, "Roundtrip 1 must be exact");

        // Vector 2: MTU multiplier window with IPv4
        let raw2 = "4:64:0:1460:mtu*4,0:mss,sok:df:0";
        let sig2, ok2 = wing::parse_p0f(raw2);
        sub.assert_true(ok2, "Must parse MTU window signature");
        sub.assert_eq(sig2.ip_version as i64, 4, "IPv4");
        sub.assert_eq(sig2.mss as i64, 1460, "MSS 1460");
        sub.assert_eq(sig2.window_type, wing::P0fWindowType.Mtu, "MTU multiplier");
        sub.assert_eq(sig2.window_size as i64, 4, "Window size 4");
        sub.assert_eq(sig2.window_scale as i64, 0, "Window scale 0");
        sub.assert_bytes_eq(wing::format_p0f(sig2)[..], raw2, "Roundtrip 2 must be exact");

        // Vector 3: Exact / Normal window size with IPv6
        let raw3 = "6:128:0:1440:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0";
        let sig3, ok3 = wing::parse_p0f(raw3);
        sub.assert_true(ok3, "Must parse exact window signature");
        sub.assert_eq(sig3.ip_version as i64, 6, "IPv6");
        sub.assert_eq(sig3.ttl as i64, 128, "TTL 128");
        sub.assert_eq(sig3.window_type, wing::P0fWindowType.Normal, "Normal window");
        sub.assert_eq(sig3.window_size as i64, 65535, "Window size 65535");
        sub.assert_eq(sig3.window_scale as i64, 8, "Window scale 8");
        sub.assert_bytes_eq(wing::format_p0f(sig3)[..], raw3, "Roundtrip 3 must be exact");

        // Vector 4: Wildcard window size (*,-1)
        let raw4 = "*:64:0:*:*,-1:mss,sok,ts,nop,ws:df,id+:0";
        let sig4, ok4 = wing::parse_p0f(raw4);
        sub.assert_true(ok4, "Must parse wildcard window signature");
        sub.assert_eq(sig4.window_type, wing::P0fWindowType.Any, "Any window type");
        sub.assert_eq(sig4.window_size as i64, -1, "Wildcard window size");
        sub.assert_eq(sig4.window_scale as i64, -1, "Wildcard window scale");
        sub.assert_bytes_eq(wing::format_p0f(sig4)[..], raw4, "Roundtrip 4 must be exact");

        // Vector 5: TTL minus wildcard (64-)
        let raw5 = "*:64-:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0";
        let sig5, ok5 = wing::parse_p0f(raw5);
        sub.assert_true(ok5, "Must parse TTL minus signature");
        sub.assert_true(sig5.has_ttl_minus, "has_ttl_minus is true");
        sub.assert_eq(sig5.ttl as i64, 64, "Base TTL 64");
        sub.assert_bytes_eq(wing::format_p0f(sig5)[..], raw5, "Roundtrip 5 must be exact");
    };

    t.run("2. Robust Parsing and Error Rejection") { sub =>
        // Too few fields
        let _, err1 = wing::parse_p0f("too:few:parts");
        sub.assert_false(err1, "Rejects signature with < 8 fields");

        // Empty input
        let _, err2 = wing::parse_p0f("");
        sub.assert_false(err2, "Rejects empty input");

        // Invalid IP version
        let _, err3 = wing::parse_p0f("3:64:0:*:mss*20,10:mss:df:0");
        sub.assert_false(err3, "Rejects invalid IP version '3'");

        // Invalid TTL
        let _, err4 = wing::parse_p0f("*:invalid:0:*:mss*20,10:mss:df:0");
        sub.assert_false(err4, "Rejects non-numeric TTL");

        // Missing window scale
        let _, err5 = wing::parse_p0f("*:64:0:*:65535:mss:df:0");
        sub.assert_false(err5, "Rejects window field without comma separator");
    };
}

fn test_p0f_pattern_matching(t: core::T&) {
    t.run("1. Exact and Self Matching") { sub =>
        let sig = wing::wing_p0f_signature();
        sub.assert_true(wing::match_p0f(sig, sig), "Signature matches itself");
    };

    t.run("2. Hop Degradation Tolerance with TTL-minus") { sub =>
        let pattern_raw = "*:64-:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0";
        let pattern, ok = wing::parse_p0f(pattern_raw);
        sub.assert_true(ok, "Parsed pattern");

        // Packet arrived with TTL degraded from 64 to 52 (12 network hops)
        var actual = wing::wing_p0f_signature();
        actual.ttl = 52;
        sub.assert_true(wing::match_p0f(actual, pattern), "Accepts TTL degraded within 35 hops");

        // Packet arrived with TTL degraded by > 35 hops (TTL 20)
        actual.ttl = 20;
        sub.assert_false(wing::match_p0f(actual, pattern), "Rejects TTL degraded beyond 35 hops");
    };

    t.run("3. Option Layout and Quirk Discrimination") { sub =>
        let base = wing::wing_p0f_signature();

        // Altered option layout (missing Timestamps)
        var altered_opts = base;
        altered_opts.options.clear();
        altered_opts.options.push(wing::P0fTcpOption.Mss);
        altered_opts.options.push(wing::P0fTcpOption.Sok);
        altered_opts.options.push(wing::P0fTcpOption.Nop);
        altered_opts.options.push(wing::P0fTcpOption.Ws);
        sub.assert_false(wing::match_p0f(altered_opts, base), "Option layout mismatch fails matching");

        // Altered quirks (DF disabled)
        var altered_quirks = base;
        altered_quirks.quirks.df = false;
        sub.assert_false(wing::match_p0f(altered_quirks, base), "Missing required DF quirk fails matching");

        // Payload mismatch
        var altered_payload = base;
        altered_payload.payload.clear();
        altered_payload.payload.append("+");
        sub.assert_false(wing::match_p0f(altered_payload, base), "Unexpected non-zero payload fails matching");
    };

    t.run("4. Custom P0f Builder and Quirk Helpers") { sub =>
        var custom = wing::custom_p0f_signature(4, 128, false, 1400, wing::P0fWindowType.Normal, 16384, 2);
        wing::p0f_push_option(custom, wing::P0fTcpOption.Mss);
        wing::p0f_push_option(custom, wing::P0fTcpOption.Ws);
        wing::p0f_set_quirk(custom, "df", true);
        wing::p0f_set_quirk(custom, "ecn", true);
        custom.payload.append("0");

        sub.assert_true(wing::p0f_has_quirk(custom, "df"), "Quirk 'df' is set");
        sub.assert_true(wing::p0f_has_quirk(custom, "ecn"), "Quirk 'ecn' is set");
        sub.assert_false(wing::p0f_has_quirk(custom, "id+"), "Quirk 'id+' is not set");

        let formatted = wing::format_p0f(custom);
        sub.assert_bytes_eq(
            formatted[..],
            "4:128:0:1400:16384,2:mss,ws:df,ecn:0",
            "Custom signature formatted correctly"
        );

        // Plug into BrowserProfile
        var profile = wing::custom_profile();
        wing::set_p0f(profile, custom);
        let prof_str = wing::profile_p0f(profile);
        sub.assert_bytes_eq(
            prof_str[..],
            "4:128:0:1400:16384,2:mss,ws:df,ecn:0",
            "BrowserProfile successfully incorporates custom p0f signature"
        );
    };
}

fn main() {
    var runner = core::new_runner("p0f v3 Passive TCP SYN Signature Verification Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. Wing Authentic TCP SYN Identity", test_wing_authentic_p0f);
    core::run_case(runner, "2. Standard p0f v3 Parser & Roundtrip", test_p0f_parser_and_roundtrip);
    core::run_case(runner, "3. Pattern Matching & Discrimination", test_p0f_pattern_matching);

    let ok = core::finish(runner);
    assert(ok);
}
