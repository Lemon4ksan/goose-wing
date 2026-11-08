// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Unit tests for hardware cycle profiler, nested stage spans, memory watermarks, and BenchSuite.
//
// RUN: goose build --include shim/prof_hook.h -o %t.exe %s && %t.exe | %FileCheck %s
// CHECK: 0. Framing (CRLFCRLF)
// CHECK: Bench_Outer/Sub_Inner
// CHECK: SUITE: Hardware Cycle Profiler Test Suite | PASS: 4/4 | FAIL: 0
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

recursive fn fill_transient_scratch(dst: u8[>..]&, count: i64, depth: i32) -> i64 {
    if depth <= 0 {
        for i in count {
            dst.push((i & 0xFF) as u8);
        }
        return dst.len;
    }
    return fill_transient_scratch(dst, count, depth - 1);
}

recursive fn alloc_transient_scratch_in_span(depth: i32) -> i64 {
    if depth <= 0 {
        var scratch_buf: u8[>..] = [];
        let tok = wing::prof_enter("test.scratch_stage");
        let n = fill_transient_scratch(scratch_buf, 512, 1);
        wing::prof_leave(tok);
        return n;
    }
    return alloc_transient_scratch_in_span(depth - 1);
}

// ----------------------------------------------------------------------------
// 1. Legacy Stage Counters & Monotonicity
// ----------------------------------------------------------------------------
fn test_legacy_profiler(t: lit::T&) {
    t.run("RDTSC Clock Monotonicity and Legacy Stage Recording") { sub =>
        let c0 = wing::prof_rdtsc();
        var sum: i64 = 0;
        for i in 1000 {
            sum = sum + i;
        }
        let c1 = wing::prof_rdtsc();
        sub.assert_gt(c1, c0);
        sub.assert_gt(sum, 0);

        wing::prof_reset();
        sub.assert_eq(wing::prof_sample_count(wing::PROF_STAGE_FRAMING), 0);
        sub.assert_eq(wing::prof_total_cycles(wing::PROF_STAGE_FRAMING), 0);
        sub.assert_eq(wing::prof_min_cycles(wing::PROF_STAGE_FRAMING), 0);
        sub.assert_eq(wing::prof_max_cycles(wing::PROF_STAGE_FRAMING), 0);

        wing::prof_record(wing::PROF_STAGE_FRAMING, 100);
        wing::prof_record(wing::PROF_STAGE_FRAMING, 300);

        sub.assert_eq(wing::prof_sample_count(wing::PROF_STAGE_FRAMING), 2);
        sub.assert_eq(wing::prof_total_cycles(wing::PROF_STAGE_FRAMING), 400);
        sub.assert_eq(wing::prof_min_cycles(wing::PROF_STAGE_FRAMING), 100);
        sub.assert_eq(wing::prof_max_cycles(wing::PROF_STAGE_FRAMING), 300);
        sub.assert_gt(wing::prof_avg_cycles(wing::PROF_STAGE_FRAMING), 199.0);
        sub.assert_eq(wing::prof_stage_p50_cycles(wing::PROF_STAGE_FRAMING), 100);
        sub.assert_eq(wing::prof_stage_p99_cycles(wing::PROF_STAGE_FRAMING), 300);

        wing::prof_print_summary();
        wing::prof_reset();
    };
}

// ----------------------------------------------------------------------------
// 2. Dynamic Nested Spans & Percentiles
// ----------------------------------------------------------------------------
fn test_dynamic_nested_spans(t: lit::T&) {
    t.run("Dynamic Stage Registration, Self Cycles, and Percentiles") { sub =>
        wing::prof_reset();
        for _ in 16 {
            let tok_outer = wing::prof_enter("test.outer");
            var acc: i64 = 0;
            for i in 200 {
                acc += i;
            }
            wing::prof_span("test.inner") {
                var inner_acc: i64 = 0;
                for j in 400 {
                    inner_acc += j;
                }
                assert(inner_acc > 0);
            };
            assert(acc > 0);
            wing::prof_leave(tok_outer);
        }

        let outer_id = wing::prof_find_stage("test.outer");
        let inner_id = wing::prof_find_stage("test.inner");
        sub.assert_ge(outer_id, 16);
        sub.assert_ge(inner_id, 16);
        sub.assert_eq(wing::prof_stage_count(), 2);

        sub.assert_eq(wing::prof_sample_count(outer_id), 16);
        sub.assert_eq(wing::prof_sample_count(inner_id), 16);

        let outer_tot = wing::prof_total_cycles(outer_id);
        let outer_self = wing::prof_stage_self_cycles(outer_id);
        let inner_tot = wing::prof_total_cycles(inner_id);
        sub.assert_ge(outer_tot, outer_self);
        sub.assert_gt(inner_tot, 0);
        sub.assert_gt(wing::prof_stage_p99_cycles(inner_id), 0);
        sub.assert_ge(wing::prof_stage_p99_cycles(inner_id), wing::prof_stage_p50_cycles(inner_id));
    };
}

// ----------------------------------------------------------------------------
// 3. Three-Channel Scratch & Surviving Watermarks
// ----------------------------------------------------------------------------
fn test_memory_watermarks(t: lit::T&) {
    t.run("Transient Scratch Rewind vs Surviving Data Stack Watermarks") { sub =>
        wing::prof_reset();
        let tok_outer = wing::prof_enter("test.scratch_outer");
        let n = alloc_transient_scratch_in_span(0);
        wing::prof_leave(tok_outer);
        sub.assert_eq(n, 512);

        let sid_inner = wing::prof_find_stage("test.scratch_stage");
        let sid_outer = wing::prof_find_stage("test.scratch_outer");
        sub.assert_ge(sid_inner, 16);
        sub.assert_ge(sid_outer, 16);
        sub.assert_eq(wing::prof_sample_count(sid_inner), 1);
        sub.assert_eq(wing::prof_stage_net_bytes(sid_inner), 0);
        sub.assert_eq(wing::prof_stage_scratch_bytes(sid_inner), 512);
        sub.assert_eq(wing::prof_stage_net_bytes(sid_outer), 0);
        sub.assert_ge(wing::prof_stage_scratch_bytes(sid_outer), 512);
        sub.assert_ge(wing::prof_stage_peak_bytes(sid_outer), 512);
        sub.assert_eq(wing::prof_stage_pool_allocs(sid_outer), 0);
        sub.assert_eq(wing::prof_stage_pool_frees(sid_outer), 0);
    };
}

// ----------------------------------------------------------------------------
// 4. BenchSuite & Real Pipeline Stage Recording
// ----------------------------------------------------------------------------
fn test_bench_suite_and_pipeline(t: lit::T&) {
    t.run("Multi-Pass BenchSuite Execution and Server Pipeline Stage Capture") { sub =>
        var suite = wing::new_bench_suite("Profiler_LIT_Suite", 5);
        suite.bench("Bench_Outer") { b =>
            b.stop_timer();
            var server = wing::new_http_server("127.0.0.1", 8080);
            server.pipeline.enable_rate_limiter = false;
            let _ = wing::add_route(server.pipeline.router, "GET", "/hello", 1001);
            let req_wire = "GET /hello HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n";
            var resp_wire: u8[..1024] = [];
            b.set_bytes(req_wire.len);
            b.report_metric(1.0, "req/turn");
            b.start_timer();
            b.reset_timer();

            for _ in b.n {
                let handled, _, ok, _ = wing::handle_connection_wire_pipelined_stream(
                    server, "127.0.0.1", req_wire, 1000000000, resp_wire,
                );
                assert(ok && handled == 1);
            }

            b.run("Sub_Inner") { sb =>
                sb.set_bytes(req_wire.len);
                sb.reset_timer();
                for _ in sb.n {
                    let handled, _, ok, _ = wing::handle_connection_wire_pipelined_stream(
                        server, "127.0.0.1", req_wire, 1000000000, resp_wire,
                    );
                    assert(ok && handled == 1);
                }
            };
        };
        suite.finish_suite();

        let id_framing = wing::prof_find_stage("http1.framing");
        let id_req_line = wing::prof_find_stage("http1.req_line");
        let id_headers = wing::prof_find_stage("http1.headers");
        let id_route = wing::prof_find_stage("stage.route_match");
        let id_handler = wing::prof_find_stage("stage.handler");
        let id_resp = wing::prof_find_stage("http1.resp_serialize");

        sub.assert_ge(id_framing, 16);
        sub.assert_ge(id_req_line, 16);
        sub.assert_ge(id_headers, 16);
        sub.assert_ge(id_route, 16);
        sub.assert_ge(id_handler, 16);
        sub.assert_ge(id_resp, 16);
        sub.assert_gt(wing::prof_sample_count(id_route), 0);
        sub.assert_gt(wing::prof_sample_count(id_handler), 0);
    };
}

// ----------------------------------------------------------------------------
// 5. F006 W3C Trace Context Conformance
// ----------------------------------------------------------------------------
fn test_f006_trace_w3c_conformance(t: lit::T&) {
    t.run("parse_traceparent rejects uppercase hex in trace-id per W3C Section 3.2.2.1") { sub =>
        // Uppercase hex '4BF9...' MUST be rejected
        let raw = "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01";
        let tp, ok = wing::parse_traceparent(raw);
        sub.assert_false(ok, "Uppercase hex in traceparent MUST be rejected per W3C §3.2.2.1");
    };

    t.run("parse_tracestate rejects multi-tenant key whose system-id starts with digit") { sub =>
        // System-id starts with digit '1' -> forbidden by W3C §3.3.1.2 (system-id must start with [a-z])
        let ts, ok = wing::parse_tracestate("tenant@1sys=val");
        sub.assert_false(ok, "System-id starting with digit MUST be rejected per W3C §3.3.1.2");
    };

    t.run("parse_tracestate rejects multi-tenant key whose tenant-id starts with non-alnum") { sub =>
        // Tenant-id starts with '_' -> forbidden by W3C §3.3.1.2 (tenant-id must start with [a-z0-9])
        let ts, ok = wing::parse_tracestate("_bad@sys=val");
        sub.assert_false(ok, "Tenant-id starting with non-alnum MUST be rejected per W3C §3.3.1.2");
    };

    t.run("parse_tracestate rejects > 32 members rather than silent drop") { sub =>
        var raw: u8[..1024] = [];
        for i in 33 {
            if i > 0 { raw.push(','); }
            raw.append("m");
            format(raw, i);
            raw.append("=1");
        }

        let ts, ok = wing::parse_tracestate(raw[..]);
        sub.assert_false(ok, "Tracestate > 32 members MUST return ok == false rather than dropping 33rd");
    };
}

// ----------------------------------------------------------------------------
// 6. W3C Trace Context 256-byte key specification compliance (http/trace.goose)
// ----------------------------------------------------------------------------
fn test_trace_context_spec_key_length(t: lit::T&) {
    t.run("tracestate parser MUST accept valid 100-byte multi-tenant key without abort") { sub =>
        // Construct valid W3C key: 90 chars tenant + '@' + 9 chars system = 100 chars
        var header_val: u8[..256] = [];
        for i in 90 { header_val.push('a'); }
        header_val.push('@');
        for i in 9 { header_val.push('b'); }
        header_val.append("=congo");

        let ts, ok = wing::parse_tracestate(header_val[..]);
        sub.assert_true(ok, "W3C tracestate with 100-byte valid key MUST parse successfully");
        sub.assert_eq(ts.members.len, 1, "Exactly one member parsed");
    };
}

fn main() {
    let runner = lit::new_runner("Hardware Cycle Profiler Test Suite");

    lit::run_case(runner, "1. Legacy Stage Counters & Monotonicity", test_legacy_profiler);
    lit::run_case(runner, "2. Dynamic Nested Spans & Percentiles", test_dynamic_nested_spans);
    lit::run_case(runner, "3. Three-Channel Scratch & Surviving Watermarks", test_memory_watermarks);
    lit::run_case(runner, "4. BenchSuite & Real Pipeline Stage Recording", test_bench_suite_and_pipeline);
    lit::run_case(runner, "5. F006 W3C Trace Context Conformance", test_f006_trace_w3c_conformance);
    lit::run_case(runner, "6. W3C Trace Context 256-byte key support (http/trace.goose)", test_trace_context_spec_key_length);

    let ok = lit::finish(runner);
    assert(ok);
}
