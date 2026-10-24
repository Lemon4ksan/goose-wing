// Verification Suite for W3C Trace Context (RFC 9239).
import std;
import core from "..";
import wing from "..";

fn test_w3c_traceparent(t: core::T&) {
    t.run("1. Standard W3C traceparent Vector Parsing & Formatting") { sub =>
        let raw = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let tp, ok = wing::parse_traceparent(raw);
        sub.assert_true(ok, "Valid traceparent must parse successfully");
        sub.assert_eq(tp.version as i64, 0, "Version must be 0x00");
        sub.assert_true(wing::traceparent_is_sampled(tp), "Trace flags 0x01 indicates sampled");

        // Format roundtrip
        var formatted: u8[>..] = [];
        wing::format_traceparent(tp, formatted);
        sub.assert_bytes_eq(formatted[..], raw, "traceparent wire formatting must exactly roundtrip");
    };

    t.run("2. W3C Invariant Violations & Strict Reject Defenses") { sub =>
        // Version 0xFF is strictly forbidden (W3C Section 3.2.1)
        let invalid_ver = "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let tp1, ok1 = wing::parse_traceparent(invalid_ver);
        sub.assert_false(ok1, "Version 0xFF must be rejected");

        // All-zero trace-id is strictly forbidden (W3C Section 3.2.2)
        let zero_trace = "00-00000000000000000000000000000000-00f067aa0ba902b7-01";
        let tp2, ok2 = wing::parse_traceparent(zero_trace);
        sub.assert_false(ok2, "All-zero trace-id must be rejected");

        // All-zero parent-id is strictly forbidden (W3C Section 3.2.3)
        let zero_parent = "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01";
        let tp3, ok3 = wing::parse_traceparent(zero_parent);
        sub.assert_false(ok3, "All-zero parent-id must be rejected");

        // Trailing garbage on version 00 must be rejected
        let trailing = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra";
        let tp4, ok4 = wing::parse_traceparent(trailing);
        sub.assert_false(ok4, "Version 00 with length > 55 must be rejected");

        // Malformed delimiters
        let bad_delim = "00_4bf92f3577b34da6a3ce929d0e0e4736_00f067aa0ba902b7_01";
        let tp5, ok5 = wing::parse_traceparent(bad_delim);
        sub.assert_false(ok5, "Underscore delimiters must be rejected");
    };

    t.run("3. Programmatic Constructor & Bitmask Flags") { sub =>
        var trace_id: u8[16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        var parent_id: u8[8] = [17, 18, 19, 20, 21, 22, 23, 24];

        let tp = wing::new_traceparent(trace_id, parent_id, true);
        sub.assert_true(tp.valid, "New traceparent must be marked valid");
        sub.assert_true(wing::traceparent_is_sampled(tp), "Sampled flag is set");

        var out: u8[>..] = [];
        wing::format_traceparent(tp, out);
        sub.assert_bytes_eq(out[..], "00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01", "Formatted hex output");
    };
}

fn test_w3c_tracestate(t: core::T&) {
    t.run("1. Multi-Vendor Tracestate Parsing & Formatting") { sub =>
        let raw = "rojo=1,congo=t61rcWkgMzE";
        let ts, ok = wing::parse_tracestate(raw);
        sub.assert_true(ok, "Valid tracestate must parse");
        sub.assert_eq(ts.members.len, 2, "2 members parsed");

        sub.assert_bytes_eq(wing::tracestate_get(ts, "rojo"), "1", "rojo value is 1");
        sub.assert_bytes_eq(wing::tracestate_get(ts, "congo"), "t61rcWkgMzE", "congo value matches");

        var out: u8[>..] = [];
        wing::format_tracestate(ts, out);
        sub.assert_bytes_eq(out[..], raw, "tracestate wire roundtrip");
    };

    t.run("2. Tenant Specific Keys & Position Invariance") { sub =>
        let raw = "congo=t61rcWkgMzE,rojo@corp=99";
        let ts, ok = wing::parse_tracestate(raw);
        sub.assert_true(ok, "Tenant key must be accepted");
        sub.assert_bytes_eq(wing::tracestate_get(ts, "rojo@corp"), "99", "Tenant key lookup");

        // Mutate with tracestate_set (prepends updated member to head)
        var mut_ts = ts;
        wing::tracestate_set(mut_ts, "rojo@corp", "100");
        sub.assert_bytes_eq(wing::tracestate_get(mut_ts, "rojo@corp"), "100", "Updated value");
        sub.assert_bytes_eq(mut_ts.members[0].key[..], "rojo@corp", "Updated entry moved to front");
    };

    t.run("3. Tracestate Character Constraints & Bounds") { sub =>
        // Disallowed equal sign in value
        let bad_val = "rojo=1=2";
        let ts1, ok1 = wing::parse_tracestate(bad_val);
        sub.assert_false(ok1, "Equal sign in value must be rejected");

        // Disallowed uppercase character in key
        let bad_key = "Rojo=1";
        let ts2, ok2 = wing::parse_tracestate(bad_key);
        sub.assert_false(ok2, "Uppercase key must be rejected");
    };
}

fn main() {
    var runner = core::new_runner("W3C Trace Context (RFC 9239) Verification Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. W3C traceparent Conformance & Invariants", test_w3c_traceparent);
    core::run_case(runner, "2. W3C tracestate Multi-Vendor Management", test_w3c_tracestate);

    let ok = core::finish(runner);
    assert(ok);
}
