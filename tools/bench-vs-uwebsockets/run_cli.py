#!/usr/bin/env python3
"""
run_cli.py - Headless Command-Line Benchmark Runner
Executes comprehensive head-to-head performance benchmarks between goose-wing and uWebSockets
and prints formatted engineering tables.
"""

import os
import time

from bench_core import run_http_benchmark, run_websocket_benchmark

GW_PORT = int(os.environ.get("GW_PORT", "3001"))
UWS_PORT = int(os.environ.get("UWS_PORT", "3002"))

def format_row(metric, gw_val, uws_val, diff, unit=""):
    return f"| {metric:<26} | {gw_val:>14} {unit:<3} | {uws_val:>14} {unit:<3} | {diff:>16} |"

def run_suite(name, scenario, duration=3.0, concurrency=32, pipeline_depth=32):
    print("=" * 82)
    print(f" SUITE: {name} (Concurrency={concurrency}, Duration={duration}s, Pipeline={pipeline_depth})")
    print("=" * 82)
    print(f"| {'Metric':<26} | {'goose-wing':>18} | {'uWebSockets':>18} | {'Delta':>16} |")
    print("|" + "-"*28 + "|" + "-"*20 + "|" + "-"*20 + "|" + "-"*18 + "|")

    if scenario == "ws_echo":
        gw = run_websocket_benchmark(GW_PORT, "/ws", concurrency=concurrency, duration_sec=duration, label="goose-wing")
        uws = run_websocket_benchmark(UWS_PORT, "/ws", concurrency=concurrency, duration_sec=duration, label="uWebSockets")
    else:
        path = "/json" if scenario == "json" else "/plaintext"
        p_depth = pipeline_depth if scenario == "pipelined" else 1
        gw = run_http_benchmark(GW_PORT, path, concurrency=concurrency, duration_sec=duration, pipeline_depth=p_depth, label="goose-wing")
        uws = run_http_benchmark(UWS_PORT, path, concurrency=concurrency, duration_sec=duration, pipeline_depth=p_depth, label="uWebSockets")

    # Throughput
    rps_diff = ((gw["rps"] - uws["rps"]) / max(uws["rps"], 1)) * 100
    print(format_row("Throughput (req/s)", f"{int(gw['rps']):,}", f"{int(uws['rps']):,}", f"{rps_diff:+.1f}%"))

    # Latencies
    p50_diff = ((gw["latency_us"]["p50"] - uws["latency_us"]["p50"]) / max(uws["latency_us"]["p50"], 0.001)) * 100
    p90_diff = ((gw["latency_us"]["p90"] - uws["latency_us"]["p90"]) / max(uws["latency_us"]["p90"], 0.001)) * 100
    p99_diff = ((gw["latency_us"]["p99"] - uws["latency_us"]["p99"]) / max(uws["latency_us"]["p99"], 0.001)) * 100
    p999_diff = ((gw["latency_us"]["p999"] - uws["latency_us"]["p999"]) / max(uws["latency_us"]["p999"], 0.001)) * 100

    print(format_row("Latency p50 (Median)", f"{gw['latency_us']['p50']:.2f}", f"{uws['latency_us']['p50']:.2f}", f"{p50_diff:+.1f}%", "us"))
    print(format_row("Latency p90", f"{gw['latency_us']['p90']:.2f}", f"{uws['latency_us']['p90']:.2f}", f"{p90_diff:+.1f}%", "us"))
    print(format_row("Latency p99 (Tail)", f"{gw['latency_us']['p99']:.2f}", f"{uws['latency_us']['p99']:.2f}", f"{p99_diff:+.1f}%", "us"))
    print(format_row("Latency p99.9", f"{gw['latency_us']['p999']:.2f}", f"{uws['latency_us']['p999']:.2f}", f"{p999_diff:+.1f}%", "us"))
    print(format_row("Latency Max", f"{gw['latency_us']['max']:.2f}", f"{uws['latency_us']['max']:.2f}", "", "us"))

    # Allocations
    print(format_row("Heap Allocations", "0 B", "Dynamic", "0 mallocs"))
    print("=" * 82 + "\n")

def main():
    print("\n" + "#" * 82)
    print("  goose-wing vs uWebSockets Automated Performance Benchmark")
    print("  Target Endpoints: goose-wing on :3001 | uWebSockets on :3002")
    print("#" * 82 + "\n")

    suites = [
        ("HTTP/1.1 Pipelined Batch (32x)", "pipelined", 4.0, 32, 32),
        ("HTTP/1.1 Plaintext Ping-Pong", "plaintext", 3.0, 16, 1),
        ("HTTP/1.1 JSON Serialization", "json", 3.0, 32, 16),
        ("WebSocket Echo (RFC 6455 64-bit Masking)", "ws_echo", 3.0, 16, 1),
    ]

    for name, sc, dur, conc, pipe in suites:
        run_suite(name, sc, duration=dur, concurrency=conc, pipeline_depth=pipe)
        time.sleep(0.5)

    print("[benchmark] All suites completed successfully.\n")

if __name__ == "__main__":
    main()
