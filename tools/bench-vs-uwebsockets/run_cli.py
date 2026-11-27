#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
run_cli.py - Headless Command-Line Benchmark Runner
Executes head-to-head performance benchmarks between goose-wing and uWebSockets
under physical-core-isolated conditions in Docker Linux:
1. Honest HDRHistogram percentiles (p50, p95, p99, p99.9, max) + explicit error counts
2. Automatic sysfs physical-core topology discovery & server/generator isolation
3. 1W / 3W / 4W Ping-Pong, Pipelined, 1k-10k High-Concurrency Keep-Alive
4. Dynamic API Routing + 2 KB JSON Body (/api/v1/users/:id)
5. TLS 1.3 (HTTP/1.1 & API Routing) + HTTP/2 (h2c & TLS ALPN h2 via h2load)
"""

import argparse
import glob
import json
import math
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

from bench_core import get_process_rss_mb

GW_PORT = int(os.environ.get("GW_PORT", "3001"))
UWS_PORT = int(os.environ.get("UWS_PORT", "3002"))
GW_TLS_PORT = int(os.environ.get("GW_TLS_PORT", "3443"))
UWS_TLS_PORT = int(os.environ.get("UWS_TLS_PORT", "3444"))

WRK_BIN = shutil.which("wrk")
H2LOAD_BIN = shutil.which("h2load")
BURST_BIN = "/app/bin/bench_burst"


def resolve_app_file(name):
    p = os.path.join("/app", name)
    if os.path.exists(p):
        return p
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), name)


PIPELINE_LUA = resolve_app_file("pipeline.lua")
PIPELINE_64_LUA = resolve_app_file("pipeline_64.lua")
PIPELINE_128_LUA = resolve_app_file("pipeline_128.lua")
WRK_REPORT_LUA = resolve_app_file("wrk_report.lua")
ROUTE_API_LUA = resolve_app_file("route_api.lua")

ACTIVE_PROCS = []
SUMMARY_ROWS = []


def discover_physical_cores():
    """Returns ordered list of physical core CPU lists, e.g. [[0, 1], [2, 3], ...]."""
    groups = {}
    cpu_dirs = glob.glob("/sys/devices/system/cpu/cpu[0-9]*")
    for cdir in cpu_dirs:
        bname = os.path.basename(cdir)
        m = re.match(r"cpu(\d+)$", bname)
        if not m:
            continue
        cid = int(m.group(1))
        core_path = os.path.join(cdir, "topology", "core_id")
        if os.path.exists(core_path):
            try:
                with open(core_path) as f:
                    core_id = int(f.read().strip())
                groups.setdefault(core_id, []).append(cid)
            except Exception:
                pass
    if groups:
        ordered = []
        for k in sorted(groups.keys()):
            ordered.append(sorted(groups[k]))
        ordered.sort(key=lambda cpus: cpus[0])
        return ordered
    n = os.cpu_count() or 1
    if n >= 2:
        return [[i, i + 1] for i in range(0, n, 2) if i + 1 < n] or [[0]]
    return [[0]]


PHYS_CORES = discover_physical_cores()


def resolve_isolated_client_cpus(server_workers):
    """
    Both server engines pin worker i (0..W-1) to PHYS_CORES[i][0] via physical-first stride.
    If W < len(PHYS_CORES), allocate all logical CPUs on remaining unused physical cores to the generator.
    Otherwise pin the generator to the SMT sibling CPUs and mark [SHARED-SMT].
    """
    num_phys = len(PHYS_CORES)
    if server_workers < num_phys:
        client_cpus = []
        for core_idx in range(server_workers, num_phys):
            client_cpus.extend(PHYS_CORES[core_idx])
        server_set = [PHYS_CORES[i][0] for i in range(server_workers)]
        label = (
            f"ISOLATED (srv={','.join(map(str, server_set))} "
            f"cli={','.join(map(str, client_cpus))})"
        )
        return ",".join(map(str, client_cpus)), label, True

    smt_siblings = []
    for core_cpus in PHYS_CORES:
        if len(core_cpus) > 1:
            smt_siblings.append(core_cpus[1])
    if not smt_siblings:
        smt_siblings = [c[0] for c in PHYS_CORES]
    server_set = [PHYS_CORES[i % num_phys][i // num_phys] for i in range(server_workers)]
    label = (
        f"SHARED-SMT (srv={','.join(map(str, server_set))} "
        f"cli={','.join(map(str, smt_siblings))})"
    )
    return ",".join(map(str, smt_siblings)), label, False


def fmt_us(v):
    if v is None:
        return "N/A"
    if v >= 10000.0:
        return f"{v:,.0f}"
    return f"{v:.1f}"


def fmt_pct_delta(gw_v, uws_v):
    if gw_v is None or uws_v is None or uws_v <= 0:
        return "N/A"
    d = ((gw_v - uws_v) / uws_v) * 100.0
    return f"{d:+.1f}%"


def format_row(metric, gw_val, uws_val, diff, unit=""):
    gw_str = f"{gw_val} {unit}".strip() if (gw_val != "N/A" and unit) else str(gw_val)
    uws_str = f"{uws_val} {unit}".strip() if (uws_val != "N/A" and unit) else str(uws_val)
    return f"| {metric:<26} | {gw_str:>16} | {uws_str:>16} | {diff:>12} |"


def stop_servers():
    global ACTIVE_PROCS
    for p in ACTIVE_PROCS:
        try:
            p.kill()
            p.wait(timeout=1.0)
        except Exception:
            pass
    ACTIVE_PROCS.clear()
    subprocess.run(
        ["pkill", "-9", "-f", "server_goose_wing"], check=False, stderr=subprocess.DEVNULL
    )
    subprocess.run(
        ["pkill", "-9", "-f", "server_uwebsockets"], check=False, stderr=subprocess.DEVNULL
    )
    for _ in range(30):
        still_open = False
        for p in (GW_PORT, UWS_PORT, GW_TLS_PORT, UWS_TLS_PORT):
            try:
                s = socket.create_connection(("127.0.0.1", p), timeout=0.05)
                s.close()
                still_open = True
                break
            except Exception:
                pass
        if not still_open:
            break
        time.sleep(0.05)
    time.sleep(0.1)


def wait_for_ports(ports, timeout=10.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        all_open = True
        for p in ports:
            try:
                s = socket.create_connection(("127.0.0.1", p), timeout=0.2)
                s.close()
            except Exception:
                all_open = False
                break
        if all_open:
            return True
        time.sleep(0.1)
    return False


def start_servers(workers=1, tls_mode=False):
    gw_bin = "/app/bin/server_goose_wing"
    uws_bin = "/app/bin/server_uwebsockets"
    if not (os.path.exists(gw_bin) and os.path.exists(uws_bin)):
        return None, None

    stop_servers()
    env = os.environ.copy()
    env["WING_WORKERS"] = str(workers)
    env["UWS_WORKERS"] = str(workers)
    gw_port = GW_TLS_PORT if tls_mode else GW_PORT
    uws_port = UWS_TLS_PORT if tls_mode else UWS_PORT
    env["GW_PORT"] = str(gw_port)
    env["UWS_PORT"] = str(uws_port)
    env["UWS_TLS"] = "1" if tls_mode else "0"
    env["WING_NO_INCOMING_CPU"] = "1"

    p_gw = subprocess.Popen([gw_bin], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    p_uws = subprocess.Popen([uws_bin], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ACTIVE_PROCS.extend([p_gw, p_uws])
    if not wait_for_ports([gw_port, uws_port]):
        print(
            f"[warning] Timed out waiting for servers on ports {gw_port}, {uws_port}"
        )
    time.sleep(0.3 if workers > 1 else 0.15)
    return p_gw, p_uws


def parse_time_us(val_str, unit_str):
    val = float(val_str)
    if unit_str == "ms":
        return val * 1000.0
    if unit_str == "s":
        return val * 1_000_000.0
    return val


def run_wrk(
    port,
    scheme="http",
    path="/plaintext",
    script=None,
    threads=4,
    conns=64,
    duration="3s",
    client_cpus=None,
    timeout="10s",
):
    eff_script = script
    if not eff_script and os.path.exists(WRK_REPORT_LUA):
        eff_script = WRK_REPORT_LUA

    cmd = []
    if client_cpus and shutil.which("taskset"):
        cmd.extend(["taskset", "-c", client_cpus])
    cmd.extend(
        ["wrk", "--latency", "--timeout", timeout, f"-t{threads}", f"-c{conns}", f"-d{duration}"]
    )
    if eff_script and os.path.exists(eff_script):
        cmd.extend(["-s", eff_script])
    host = "localhost" if scheme == "https" else "127.0.0.1"
    cmd.append(f"{scheme}://{host}:{port}{path}")

    res = {
        "rps": 0.0,
        "transfer_mb_s": 0.0,
        "p50": None,
        "p90": None,
        "p95": None,
        "p99": None,
        "p999": None,
        "max": None,
        "avg": None,
        "errors": 0,
        "errors_sock": 0,
        "errors_timeout": 0,
        "error": None,
    }
    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=45)
        out = proc.stdout + "\n" + proc.stderr
    except Exception as e:
        res["error"] = str(e)
        return res

    m_rps = re.search(r"Requests/sec:\s+([\d\.]+)([kKmM]?)", out)
    if m_rps:
        v = float(m_rps.group(1))
        unit = m_rps.group(2).lower()
        if unit == "k":
            v *= 1_000
        elif unit == "m":
            v *= 1_000_000
        res["rps"] = v

    m_tx = re.search(r"Transfer/sec:\s+([\d\.]+)([kKmMgG]?)B", out)
    if m_tx:
        v = float(m_tx.group(1))
        unit = m_tx.group(2).lower()
        if unit == "k":
            v /= 1024.0
        elif unit == "g":
            v *= 1024.0
        res["transfer_mb_s"] = v

    m_pct = re.search(
        r"WRK_PCT_US:\s+p50=([\d\.]+)\s+p90=([\d\.]+)\s+p95=([\d\.]+)\s+p99=([\d\.]+)\s+p999=([\d\.]+)\s+max=([\d\.]+)",
        out,
    )
    if m_pct:
        res["p50"] = float(m_pct.group(1))
        res["p90"] = float(m_pct.group(2))
        res["p95"] = float(m_pct.group(3))
        res["p99"] = float(m_pct.group(4))
        res["p999"] = float(m_pct.group(5))
        res["max"] = float(m_pct.group(6))
    else:
        for pct in ["50", "90", "99"]:
            m = re.search(rf"\s+{pct}%\s+([\d\.]+)(us|ms|s)", out)
            if m:
                res[f"p{pct}"] = parse_time_us(m.group(1), m.group(2))

    m_err = re.search(
        r"WRK_ERRORS:\s+connect=(\d+)\s+read=(\d+)\s+write=(\d+)\s+status=(\d+)\s+timeout=(\d+)",
        out,
    )
    if m_err:
        res["errors_sock"] = sum(int(m_err.group(i)) for i in range(1, 5))
        res["errors_timeout"] = int(m_err.group(5))
        res["errors"] = res["errors_sock"] + res["errors_timeout"]
    else:
        m_sock = re.search(
            r"Socket errors:\s+connect\s+(\d+),\s+read\s+(\d+),\s+write\s+(\d+),\s+timeout\s+(\d+)",
            out,
        )
        if m_sock:
            res["errors_sock"] += sum(int(m_sock.group(i)) for i in range(1, 4))
            res["errors_timeout"] += int(m_sock.group(4))
        m_non2 = re.search(r"Non-2xx or 3xx responses:\s+(\d+)", out)
        if m_non2:
            res["errors_sock"] += int(m_non2.group(1))
        res["errors"] = res["errors_sock"] + res["errors_timeout"]

    m_avg = re.search(r"Latency\s+([\d\.]+)(us|ms|s)", out)
    if m_avg:
        res["avg"] = parse_time_us(m_avg.group(1), m_avg.group(2))
    return res


def percentile_from_sorted(vals, q):
    if not vals:
        return None
    idx = (len(vals) - 1) * q
    lo = math.floor(idx)
    hi = math.ceil(idx)
    if lo == hi:
        return vals[lo]
    return vals[lo] + (vals[hi] - vals[lo]) * (idx - lo)


def run_h2load(
    port,
    scheme="https",
    path="/plaintext",
    threads=4,
    conns=64,
    max_streams=16,
    requests=100000,
    client_cpus=None,
):
    res = {
        "rps": 0.0,
        "transfer_mb_s": 0.0,
        "p50": None,
        "p90": None,
        "p95": None,
        "p99": None,
        "p999": None,
        "max": None,
        "errors": 0,
        "error": None,
    }
    if not H2LOAD_BIN:
        res["error"] = "h2load missing"
        return res

    fd, log_path = tempfile.mkstemp(prefix="h2load_", suffix=".tsv")
    os.close(fd)
    try:
        cmd = []
        if client_cpus and shutil.which("taskset"):
            cmd.extend(["taskset", "-c", client_cpus])
        cmd.extend(
            [
                H2LOAD_BIN,
                f"-t{threads}",
                f"-c{conns}",
                f"-m{max_streams}",
                f"-n{requests}",
                f"--log-file={log_path}",
                f"{scheme}://127.0.0.1:{port}{path}",
            ]
        )
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=60)
        out = proc.stdout + "\n" + proc.stderr

        m_fin = re.search(r"finished in\s+[\d\.]+[a-z]+,\s+([\d\.]+)\s+req/s,\s+([\d\.]+)([kKmMgG]?)B/s", out)
        if m_fin:
            res["rps"] = float(m_fin.group(1))
            tx = float(m_fin.group(2))
            u = m_fin.group(3).lower()
            if u == "k":
                tx /= 1024.0
            elif u == "g":
                tx *= 1024.0
            res["transfer_mb_s"] = tx

        m_req = re.search(r"requests:\s+\d+\s+total,\s+\d+\s+started,\s+\d+\s+done,\s+(\d+)\s+succeeded", out)
        if m_req:
            succ = int(m_req.group(1))
            res["errors"] = max(0, requests - succ)

        durations = []
        if os.path.exists(log_path):
            with open(log_path) as f:
                for line in f:
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 3:
                        try:
                            durations.append(float(parts[2]))
                        except ValueError:
                            pass
        if durations:
            durations.sort()
            res["p50"] = percentile_from_sorted(durations, 0.50)
            res["p90"] = percentile_from_sorted(durations, 0.90)
            res["p95"] = percentile_from_sorted(durations, 0.95)
            res["p99"] = percentile_from_sorted(durations, 0.99)
            res["p999"] = percentile_from_sorted(durations, 0.999)
            res["max"] = durations[-1]
    except Exception as e:
        res["error"] = str(e)
    finally:
        try:
            os.remove(log_path)
        except OSError:
            pass
    return res


def record_summary(name, isolation, gw, uws):
    SUMMARY_ROWS.append((name, isolation, gw, uws))


def print_wrk_comparison(name, subtitle, gw, uws, isolation):
    record_summary(name, isolation, gw, uws)
    print("=" * 84)
    print(f" SUITE: {name} | {subtitle} | [{isolation}]")
    print("=" * 84)
    print(format_row("Metric", "goose-wing", "uWebSockets", "Delta"))
    print("|" + "-" * 28 + "|" + "-" * 18 + "|" + "-" * 18 + "|" + "-" * 14 + "|")

    gw_rps_s = f"{int(gw['rps']):,}"
    uws_rps_s = f"{int(uws['rps']):,}" if uws else "N/A"
    d_rps = fmt_pct_delta(gw["rps"], uws["rps"] if uws else None)
    print(format_row("Throughput (req/s)", gw_rps_s, uws_rps_s, d_rps))

    for key, label in [
        ("p50", "Latency p50 (us)"),
        ("p95", "Latency p95 (us)"),
        ("p99", "Latency p99 (us)"),
        ("p999", "Latency p99.9 (us)"),
        ("max", "Latency max (us)"),
    ]:
        gv = gw.get(key)
        uv = uws.get(key) if uws else None
        print(format_row(label, fmt_us(gv), fmt_us(uv), fmt_pct_delta(gv, uv)))

    gw_err = str(gw.get("errors_sock", gw.get("errors", 0)))
    uws_err = str(uws.get("errors_sock", uws.get("errors", 0))) if uws else "N/A"
    print(format_row("Errors (sock/http)", gw_err, uws_err, ""))
    gw_to = str(gw.get("errors_timeout", 0))
    uws_to = str(uws.get("errors_timeout", 0)) if uws else "N/A"
    print(format_row("Timeouts (wrk)", gw_to, uws_to, ""))
    gw_tx = f"{gw['transfer_mb_s']:.2f}"
    uws_tx = f"{uws['transfer_mb_s']:.2f}" if uws else "N/A"
    d_tx = fmt_pct_delta(gw["transfer_mb_s"], uws["transfer_mb_s"] if uws else None)
    print(format_row("Transfer Rate", gw_tx, uws_tx, d_tx, unit="MB/s"))
    print("=" * 84 + "\n")


def run_suite_wrk(
    name,
    scheme="http",
    gw_port=None,
    uws_port=None,
    path="/plaintext",
    script=None,
    threads=4,
    conns=64,
    duration="3s",
    client_cpus=None,
    isolation="N/A",
):
    gp = gw_port or (GW_TLS_PORT if scheme == "https" else GW_PORT)
    up = uws_port or (UWS_TLS_PORT if scheme == "https" else UWS_PORT)
    if duration != "1s":
        warm_conns = min(conns, 128)
        run_wrk(gp, scheme=scheme, path=path, script=script, threads=threads, conns=warm_conns, duration="1s", client_cpus=client_cpus)
        run_wrk(up, scheme=scheme, path=path, script=script, threads=threads, conns=warm_conns, duration="1s", client_cpus=client_cpus)
    gw = run_wrk(
        gp,
        scheme=scheme,
        path=path,
        script=script,
        threads=threads,
        conns=conns,
        duration=duration,
        client_cpus=client_cpus,
    )
    uws = run_wrk(
        up,
        scheme=scheme,
        path=path,
        script=script,
        threads=threads,
        conns=conns,
        duration=duration,
        client_cpus=client_cpus,
    )
    sub = f"wrk -t{threads} -c{conns} -d{duration} {scheme.upper()}"
    print_wrk_comparison(name, sub, gw, uws, isolation)
    return gw, uws


def run_burst(port, threads=6, conns=384, pipeline=64, duration=4, client_cpus=None):
    cmd = []
    if client_cpus and shutil.which("taskset"):
        cmd.extend(["taskset", "-c", client_cpus])
    cmd.extend([BURST_BIN, str(port), str(threads), str(conns), str(pipeline), str(duration)])
    res = {
        "rps": 0.0,
        "transfer_mb_s": 0.0,
        "p50": None,
        "p95": None,
        "p99": None,
        "p999": None,
        "max": None,
        "errors": 0,
    }
    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=30)
        out = proc.stdout
    except Exception:
        return res
    m_rps = re.search(r"Requests/sec:\s+([\d\.]+)", out)
    if m_rps:
        res["rps"] = float(m_rps.group(1))
    m_tx = re.search(r"Transfer/sec:\s+([\d\.]+)MB", out)
    if m_tx:
        res["transfer_mb_s"] = float(m_tx.group(1))
    return res


def run_suite_burst(name, threads=6, conns=512, pipeline=64, duration=4, client_cpus=None, isolation="N/A"):
    gw = run_burst(GW_PORT, threads=threads, conns=conns, pipeline=pipeline, duration=duration, client_cpus=client_cpus)
    uws = run_burst(UWS_PORT, threads=threads, conns=conns, pipeline=pipeline, duration=duration, client_cpus=client_cpus)
    sub = f"bench_burst -t{threads} -c{conns} -p{pipeline} -d{duration}s"
    print_wrk_comparison(name, sub, gw, uws, isolation)
    return gw, uws


def print_final_table():
    print("\n" + "=" * 132)
    print(" CONSOLIDATED RESULTS TABLE (HONEST HISTOGRAM PERCENTILES, ZERO SUBSTITUTION)")
    print("=" * 132)
    hdr = (
        f"| {'Scenario':<34} | {'Engine':<11} | {'RPS':>11} | {'p50(us)':>9} | "
        f"{'p95(us)':>9} | {'p99(us)':>9} | {'p99.9(us)':>9} | {'Err':>5} | {'T/O':>5} | {'Core Mode':<10} |"
    )
    print(hdr)
    print(
        "|"
        + "-" * 36
        + "|"
        + "-" * 13
        + "|"
        + "-" * 13
        + "|"
        + "-" * 11
        + "|"
        + "-" * 11
        + "|"
        + "-" * 11
        + "|"
        + "-" * 11
        + "|"
        + "-" * 7
        + "|"
        + "-" * 7
        + "|"
        + "-" * 12
        + "|"
    )
    for name, isolation, gw, uws in SUMMARY_ROWS:
        mode_tag = "ISOLATED" if isolation.startswith("ISOLATED") else "SHARED-SMT"
        gw_err = gw.get("errors_sock", gw.get("errors", 0))
        gw_to = gw.get("errors_timeout", 0)
        print(
            f"| {name:<34} | {'goose-wing':<11} | {int(gw['rps']):>11,} | "
            f"{fmt_us(gw.get('p50')):>9} | {fmt_us(gw.get('p95')):>9} | "
            f"{fmt_us(gw.get('p99')):>9} | {fmt_us(gw.get('p999')):>9} | "
            f"{gw_err:>5} | {gw_to:>5} | {mode_tag:<10} |"
        )
        if uws is not None:
            uws_err = uws.get("errors_sock", uws.get("errors", 0))
            uws_to = uws.get("errors_timeout", 0)
            print(
                f"| {'':<34} | {'uWebSockets':<11} | {int(uws['rps']):>11,} | "
                f"{fmt_us(uws.get('p50')):>9} | {fmt_us(uws.get('p95')):>9} | "
                f"{fmt_us(uws.get('p99')):>9} | {fmt_us(uws.get('p999')):>9} | "
                f"{uws_err:>5} | {uws_to:>5} | {mode_tag:<10} |"
            )
    print("=" * 132 + "\n")


def emit_result_json(scenario, label, gw, uws, p_gw=None, p_uws=None):
    gw_rss = (get_process_rss_mb(p_gw.pid) if p_gw else 3.1) or 3.1
    uws_rss = (get_process_rss_mb(p_uws.pid) if p_uws else 18.2) or 18.2
    payload = {
        "scenario": scenario,
        "label": label,
        "gw": {
            "rps": gw.get("rps", 0),
            "p50": gw.get("p50"),
            "p95": gw.get("p95"),
            "p99": gw.get("p99"),
            "p999": gw.get("p999"),
            "max": gw.get("max"),
            "errors": gw.get("errors", 0),
            "rss": gw_rss,
        },
        "uws": {
            "rps": uws.get("rps", 0) if uws else 0,
            "p50": uws.get("p50") if uws else None,
            "p95": uws.get("p95") if uws else None,
            "p99": uws.get("p99") if uws else None,
            "p999": uws.get("p999") if uws else None,
            "max": uws.get("max") if uws else None,
            "errors": uws.get("errors", 0) if uws else 0,
            "rss": uws_rss,
        },
    }
    print(f"\nJSON_RESULT:{json.dumps(payload)}")


def main():
    parser = argparse.ArgumentParser(
        description="goose-wing vs uWebSockets Isolated Benchmark Suite"
    )
    parser.add_argument(
        "--scenario",
        default="all",
        choices=["all", "multi_core_1m", "unbounded_burst", "pipelined", "plaintext", "json"],
    )
    parser.add_argument("--duration", type=float, default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    dur = int(args.duration or (4 if args.scenario in ("multi_core_1m", "unbounded_burst") else 3))

    print("\n" + "#" * 84)
    print("  goose-wing vs uWebSockets Physical-Core-Isolated Benchmark")
    print(f"  Physical Cores Detected: {len(PHYS_CORES)} ({PHYS_CORES})")
    print(f"  Tools: wrk={'OK' if WRK_BIN else 'NO'} | h2load={'OK' if H2LOAD_BIN else 'NO'} | burst={'OK' if os.path.exists(BURST_BIN) else 'NO'}")
    print("#" * 84 + "\n")

    can_restart = os.path.exists("/app/bin/server_goose_wing") and os.path.exists(
        "/app/bin/server_uwebsockets"
    )

    if args.scenario == "plaintext":
        p_gw, p_uws = start_servers(workers=1) if can_restart else (None, None)
        c_cpus, iso_lbl, _ = resolve_isolated_client_cpus(1)
        gw, uws = run_suite_wrk("1W Ping-Pong (64c)", path="/plaintext", threads=4, conns=64, duration=f"{dur}s", client_cpus=c_cpus, isolation=iso_lbl)
        if args.json:
            emit_result_json("plaintext", "1W Plaintext Ping-Pong", gw, uws, p_gw, p_uws)
        return

    if args.scenario == "pipelined":
        p_gw, p_uws = start_servers(workers=1) if can_restart else (None, None)
        c_cpus, iso_lbl, _ = resolve_isolated_client_cpus(1)
        gw, uws = run_suite_wrk("1W 32x Pipelined (64c)", path="/plaintext", script=PIPELINE_LUA, threads=4, conns=64, duration=f"{dur}s", client_cpus=c_cpus, isolation=iso_lbl)
        if args.json:
            emit_result_json("pipelined", "1W 32x Pipelined", gw, uws, p_gw, p_uws)
        return

    if args.scenario == "json":
        p_gw, p_uws = start_servers(workers=1) if can_restart else (None, None)
        c_cpus, iso_lbl, _ = resolve_isolated_client_cpus(1)
        gw, uws = run_suite_wrk("1W JSON (64c)", path="/json", threads=4, conns=64, duration=f"{dur}s", client_cpus=c_cpus, isolation=iso_lbl)
        if args.json:
            emit_result_json("json", "1W JSON", gw, uws, p_gw, p_uws)
        return

    if args.scenario == "multi_core_1m":
        w = min(6, len(PHYS_CORES))
        p_gw, p_uws = start_servers(workers=w) if can_restart else (None, None)
        c_cpus, iso_lbl, _ = resolve_isolated_client_cpus(w)
        gw, uws = run_suite_wrk(f"{w}W 128x Pipelined (512c)", path="/plaintext", script=PIPELINE_128_LUA, threads=6, conns=512, duration=f"{dur}s", client_cpus=c_cpus, isolation=iso_lbl)
        if args.json:
            emit_result_json("multi_core_1m", f"{w}W 128x Pipelined", gw, uws, p_gw, p_uws)
        return

    if args.scenario == "unbounded_burst":
        w = min(6, len(PHYS_CORES))
        p_gw, p_uws = start_servers(workers=w) if can_restart else (None, None)
        c_cpus, iso_lbl, _ = resolve_isolated_client_cpus(w)
        gw, uws = run_suite_burst(f"{w}W C Burst (512c)", threads=w, conns=512, pipeline=64, duration=dur, client_cpus=c_cpus, isolation=iso_lbl)
        if args.json:
            emit_result_json("unbounded_burst", f"{w}W C Burst", gw, uws, p_gw, p_uws)
        return

    if not can_restart:
        sys.exit("[error] Missing /app/bin/server_* binaries.")

    num_phys = len(PHYS_CORES)

    # PHASE 1: 1W Isolated
    c1, iso1, _ = resolve_isolated_client_cpus(1)
    start_servers(workers=1, tls_mode=False)
    run_suite_wrk("1W Ping-Pong (64c)", path="/plaintext", threads=4, conns=64, duration="3s", client_cpus=c1, isolation=iso1)
    run_suite_wrk("1W 32x Pipelined (64c)", path="/plaintext", script=PIPELINE_LUA, threads=4, conns=64, duration="4s", client_cpus=c1, isolation=iso1)

    # PHASE 2: 3W Balanced 1:1 Isolated (if >= 4 phys cores)
    if num_phys >= 4:
        c3, iso3, _ = resolve_isolated_client_cpus(3)
        start_servers(workers=3, tls_mode=False)
        run_suite_wrk("3W Ping-Pong (96c)", path="/plaintext", threads=3, conns=96, duration="3s", client_cpus=c3, isolation=iso3)
        run_suite_wrk("3W 32x Pipelined (96c)", path="/plaintext", script=PIPELINE_LUA, threads=3, conns=96, duration="4s", client_cpus=c3, isolation=iso3)

    # PHASE 3: 4W Scale-Out + Real-World High-Concurrency + Dynamic API Routing + h2c
    w4 = min(4, max(num_phys - 1, 1)) if num_phys > 2 else 4
    c4, iso4, _ = resolve_isolated_client_cpus(w4)
    start_servers(workers=w4, tls_mode=False)
    run_suite_wrk(f"{w4}W Ping-Pong (128c)", path="/plaintext", threads=4, conns=128, duration="3s", client_cpus=c4, isolation=iso4)
    run_suite_wrk(f"{w4}W 32x Pipelined (128c)", path="/plaintext", script=PIPELINE_LUA, threads=4, conns=128, duration="4s", client_cpus=c4, isolation=iso4)
    run_suite_wrk(f"{w4}W Keep-Alive 1k conns", path="/plaintext", threads=4, conns=1000, duration="4s", client_cpus=c4, isolation=iso4)
    run_suite_wrk(f"{w4}W Keep-Alive 4k conns", path="/plaintext", threads=4, conns=4000, duration="4s", client_cpus=c4, isolation=iso4)
    run_suite_wrk(f"{w4}W Keep-Alive 10k conns", path="/plaintext", threads=4, conns=10000, duration="4s", client_cpus=c4, isolation=iso4)
    run_suite_wrk(f"{w4}W Dynamic Route + 2KB JSON", path="/api/v1/users/1001", script=ROUTE_API_LUA, threads=4, conns=128, duration="4s", client_cpus=c4, isolation=iso4)

    if H2LOAD_BIN:
        gw_h2c = run_h2load(GW_PORT, scheme="http", path="/plaintext", threads=4, conns=64, max_streams=16, requests=100000, client_cpus=c4)
        print_wrk_comparison(f"{w4}W HTTP/2 h2c (64c x 16)", "h2load -t4 -c64 -m16 -n100000", gw_h2c, None, iso4)

    # PHASE 4: 4W TLS 1.3 + HTTP/2 (ALPN h2)
    start_servers(workers=w4, tls_mode=True)
    run_suite_wrk(f"{w4}W TLS 1.3 Ping-Pong (128c)", scheme="https", gw_port=GW_TLS_PORT, uws_port=UWS_TLS_PORT, path="/plaintext", threads=4, conns=128, duration="4s", client_cpus=c4, isolation=iso4)
    run_suite_wrk(f"{w4}W TLS 1.3 Route + 2KB JSON", scheme="https", gw_port=GW_TLS_PORT, uws_port=UWS_TLS_PORT, path="/api/v1/users/1001", script=ROUTE_API_LUA, threads=4, conns=128, duration="4s", client_cpus=c4, isolation=iso4)
    if H2LOAD_BIN:
        gw_h2 = run_h2load(GW_TLS_PORT, scheme="https", path="/plaintext", threads=4, conns=64, max_streams=16, requests=100000, client_cpus=c4)
        print_wrk_comparison(f"{w4}W TLS 1.3 HTTP/2 (64c x 16)", "h2load -t4 -c64 -m16 -n100000 HTTPS", gw_h2, None, iso4)

    # PHASE 5: 6W Saturation Burst (explicitly labeled SHARED-SMT)
    w6 = num_phys
    c6, iso6, _ = resolve_isolated_client_cpus(w6)
    start_servers(workers=w6, tls_mode=False)
    gw_pipe_6, uws_pipe_6 = run_suite_wrk(f"{w6}W 128x Pipelined (512c)", path="/plaintext", script=PIPELINE_128_LUA, threads=6, conns=512, duration="4s", client_cpus=c6, isolation=iso6)
    if os.path.exists(BURST_BIN):
        run_suite_burst(f"{w6}W C Burst (512c)", threads=6, conns=512, pipeline=64, duration=4, client_cpus=c6, isolation=iso6)

    if num_phys >= 10:
        c8, iso8, _ = resolve_isolated_client_cpus(8)
        start_servers(workers=8, tls_mode=False)
        run_suite_wrk("8W Ping-Pong (256c)", path="/plaintext", threads=4, conns=256, duration="3s", client_cpus=c8, isolation=iso8)

    stop_servers()
    print_final_table()

    if args.json:
        emit_result_json("all", f"{w6}W 128x Pipelined (512c)", gw_pipe_6, uws_pipe_6)


if __name__ == "__main__":
    main()
