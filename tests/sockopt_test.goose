// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for L4 OS Socket Parameter Tuning (sysnet / net/sockopt.goose):
// - Authentic Wing NetStack, Custom, and None L4 socket profile configurations
// - p0f v3 TCP stack parameter invariants (TTL, Window, MSS, WScale, DF, TCP_NODELAY)
// - Profile and ClientProfile dispatch overloads
// - Socket option summary formatting
import std;
import core from "..";
import wing from "..";

fn test_socket_p0f_profiles(t: core::T&) {
    t.run("Wing Authentic Zero-Heap NetStack Profile") { sub =>
        let wing_cfg = internal::p0f_socket_config(wing::Profile.Wing);
        sub.assert_eq(wing_cfg.ttl, 64, "Wing TTL is 64");
        sub.assert_eq(wing_cfg.window_size, 65535, "Wing window size is 65535");
        sub.assert_true(wing_cfg.has_dont_fragment, "Wing DF is enabled");
        sub.assert_true(wing_cfg.tcp_nodelay, "Wing TCP_NODELAY is enabled");
        sub.assert_eq(wing_cfg.wscale, 8, "Wing WScale is 8");
        sub.assert_eq(wing_cfg.mss, 1460, "Wing MSS is 1460");
        sub.assert_true(internal::validate_p0f_socket_invariants(wing_cfg), "Wing invariants valid");
    };

    t.run("Custom Socket Profile") { sub =>
        let custom_cfg = internal::p0f_socket_config(wing::Profile.Custom);
        sub.assert_eq(custom_cfg.ttl, 64, "Custom TTL is 64");
        sub.assert_eq(custom_cfg.window_size, 65535, "Custom window size is 65535");
        sub.assert_true(custom_cfg.has_dont_fragment, "Custom DF is enabled");
        sub.assert_eq(custom_cfg.wscale, 8, "Custom WScale is 8");
        sub.assert_true(internal::validate_p0f_socket_invariants(custom_cfg), "Custom invariants valid");
    };

    t.run("None / Raw Socket Profile") { sub =>
        let none_cfg = internal::p0f_socket_config(wing::Profile.None);
        sub.assert_eq(none_cfg.ttl, 64, "None TTL is 64");
        sub.assert_eq(none_cfg.window_size, 65535, "None window size is 65535");
        sub.assert_false(none_cfg.has_dont_fragment, "None DF is disabled");
        sub.assert_eq(none_cfg.wscale, 7, "None WScale is 7");
        sub.assert_true(internal::validate_p0f_socket_invariants(none_cfg), "None invariants valid");
    };
}

fn test_socket_invariant_validation(t: core::T&) {
    t.run("Invariant Boundary Checks") { sub =>
        var bad_cfg = internal::p0f_socket_config(wing::Profile.Wing);

        // Invalid TTL
        bad_cfg.ttl = 99;
        sub.assert_false(internal::validate_p0f_socket_invariants(bad_cfg), "TTL 99 is invalid");

        // Valid TTLs
        bad_cfg.ttl = 64;
        sub.assert_true(internal::validate_p0f_socket_invariants(bad_cfg), "TTL 64 is valid");
        bad_cfg.ttl = 128;
        sub.assert_true(internal::validate_p0f_socket_invariants(bad_cfg), "TTL 128 is valid");

        // Invalid Window Size
        bad_cfg.window_size = 0;
        sub.assert_false(internal::validate_p0f_socket_invariants(bad_cfg), "Window 0 is invalid");
        bad_cfg.window_size = 70000;
        sub.assert_false(internal::validate_p0f_socket_invariants(bad_cfg), "Window 70000 is invalid");
        bad_cfg.window_size = 64240;

        // Invalid MSS
        bad_cfg.mss = 200;
        sub.assert_false(internal::validate_p0f_socket_invariants(bad_cfg), "MSS 200 is invalid");
        bad_cfg.mss = 1460;

        // Invalid WScale
        bad_cfg.wscale = 15;
        sub.assert_false(internal::validate_p0f_socket_invariants(bad_cfg), "WScale 15 is invalid");
    };

    t.run("Summary String Formatting") { sub =>
        let cfg = internal::p0f_socket_config(wing::Profile.Wing);
        var summary: u8[>..] = [];
        internal::format_socket_p0f_summary(cfg, summary);
        sub.assert_true(summary.len > 0, "Summary formatted");
        // Verify key substrings
        sub.assert_contains(summary[..], "Wing/1.0 NetStack", "Summary contains OS/stack name");
        sub.assert_contains(summary[..], "TTL=64", "Summary contains TTL");
        sub.assert_contains(summary[..], "Window=65535", "Summary contains Window");
    };
}

fn test_live_socket_options(t: core::T&) {
    t.run("OS Socket Option Tuning & Telemetry") { sub =>
        let listener = wing::tcp_listen("127.0.0.1", 0, 16);
        sub.assert_gt(listener, 0, "Listener socket created");

        let port = wing::tcp_getsockname_port(listener);
        sub.assert_gt(port as i64, 0, "Bound to valid ephemeral port");

        // TCP_DEFER_ACCEPT (Linux / FreeBSD)
        let ok_defer = wing::tcp_set_defer_accept(listener, 1);
        sub.assert_true(ok_defer, "tcp_set_defer_accept returns success");

        // TCP_USER_TIMEOUT
        let ok_ut = wing::tcp_set_user_timeout(listener, 5000);
        sub.assert_true(ok_ut, "tcp_set_user_timeout returns success");

        // Aggressive SO_KEEPALIVE
        let ok_keep = wing::tcp_set_keepalive(listener, 1, 11, 3);
        sub.assert_true(ok_keep, "tcp_set_keepalive returns success");

        // TCP_SYNCNT
        let ok_syn = wing::tcp_set_syn_retries(listener, 3);
        sub.assert_true(ok_syn, "tcp_set_syn_retries returns success");

        // Queue telemetry
        let notsent = wing::tcp_get_notsent_bytes(listener);
        sub.assert_ge(notsent, 0, "notsent_bytes >= 0");

        let readable = wing::tcp_get_readable_bytes(listener);
        sub.assert_ge(readable, 0, "readable_bytes >= 0");

        // End-to-end CorkBuffer -> tcp_flush_cork -> tcp_recv_pipe into PipeBuffer
        let client_sock = wing::tcp_connect("127.0.0.1", port, 2000);
        sub.assert_gt(client_sock, 0, "Client connected to listener");

        let accepted_sock = wing::tcp_accept(listener, 2000);
        sub.assert_gt(accepted_sock, 0, "Accepted incoming connection");

        var cork = core::new_cork_buffer();
        cork.cork_write("WING_PIPE_STREAM_PAYLOAD");
        sub.assert_eq(cork.cork_pending(), 24, "Cork has 24 bytes pending");

        let flushed = wing::tcp_flush_cork(client_sock, cork);
        sub.assert_eq(flushed, 24, "Flushed all 24 bytes via tcp_flush_cork");
        sub.assert_eq(cork.cork_pending(), 0, "Cork drained to 0");

        var pipe = core::new_pipe_buffer();
        let recvd = wing::tcp_recv_pipe(accepted_sock, pipe, 1024, 2000);
        sub.assert_eq(recvd, 24, "tcp_recv_pipe read directly into pipe storage");
        sub.assert_eq(pipe.readable_len(), 24, "PipeBuffer has 24 readable bytes");
        sub.assert_eq(pipe.readable_slice(), "WING_PIPE_STREAM_PAYLOAD", "Direct pipe slice matches wire payload");

        wing::tcp_close(client_sock);
        wing::tcp_close(accepted_sock);
        wing::tcp_close(listener);
    };
}

fn main() {
    var runner = core::new_runner("L4 Socket Parameter Tuning Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. Socket p0f Profiles", test_socket_p0f_profiles);
    core::run_case(runner, "2. Socket Invariant Validation", test_socket_invariant_validation);
    core::run_case(runner, "3. Live OS Socket Tuning & Telemetry", test_live_socket_options);
    let ok = core::finish(runner);
    assert(ok);
}
