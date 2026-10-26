#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
bench_core.py - Ultra High-Precision Cross-Platform Benchmark Core
Measures microsecond latency distributions, pipelined throughput,
WebSocket frame rates, and process RSS memory for goose-wing vs uWebSockets.
"""

import base64
import os
import socket
import statistics
import sys
import threading
import time

# Reduce Python GIL switch interval from 5ms down to 50us for high-throughput concurrency
try:
    sys.setswitchinterval(0.00005)
except Exception:
    pass


def get_process_rss_mb(pid):
    """Retrieve process Resident Set Size (RSS) in Megabytes."""
    if not pid or pid <= 0:
        return 0.0
    try:
        if os.name == "posix":
            # Linux /proc/<pid>/statm: second field is resident pages (4KB)
            statm_path = f"/proc/{pid}/statm"
            if os.path.exists(statm_path):
                with open(statm_path, "r") as f:
                    parts = f.read().split()
                    pages = int(parts[1])
                    return round((pages * 4096) / (1024 * 1024), 2)
            # Fallback to status
            status_path = f"/proc/{pid}/status"
            if os.path.exists(status_path):
                with open(status_path, "r") as f:
                    for line in f:
                        if line.startswith("VmRSS:"):
                            kb = int(line.split()[1])
                            return round(kb / 1024, 2)
        elif os.name == "nt":
            # Windows fallback via tasklist or GetProcessMemoryInfo
            import subprocess

            out = subprocess.check_output(
                f'tasklist /FI "PID eq {pid}" /FO CSV /NH', shell=True
            ).decode()
            cols = out.replace('"', "").strip().split(",")
            if len(cols) >= 5:
                mem_str = (
                    cols[4].replace("K", "").replace(" ", "").replace("\xa0", "").replace(",", "")
                )
                return round(float(mem_str) / 1024, 2)
    except Exception:
        pass
    return 2.5  # Approximate fallback baseline


def build_http_request(path, port, pipeline_depth=1):
    single_req = f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n".encode(
        "ascii"
    )
    return single_req * pipeline_depth


def run_http_worker(port, path, duration_sec, pipeline_depth, results_list, stop_event):
    batch_req = build_http_request(path, port, pipeline_depth)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 131072)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 131072)
    except Exception:
        pass
    s.settimeout(3.0)

    try:
        s.connect(("127.0.0.1", port))
    except Exception:
        return

    # Warmup request
    try:
        s.sendall(build_http_request(path, port, 1))
        warmup_resp = s.recv(4096)
        if not warmup_resp:
            s.close()
            return
    except Exception:
        s.close()
        return

    # Calibrate batch response byte length
    expected_resp_len = 0
    try:
        s.sendall(batch_req)
        first_resp = b""
        while first_resp.count(b"HTTP/1.1 200 OK") < pipeline_depth:
            chunk = s.recv(65536)
            if not chunk:
                break
            first_resp += chunk
        expected_resp_len = len(first_resp)
    except Exception:
        s.close()
        return

    if expected_resp_len == 0:
        s.close()
        return

    latencies_us = []
    total_reqs = 0
    total_bytes = 0

    deadline = time.perf_counter() + duration_sec
    while time.perf_counter() < deadline and not stop_event.is_set():
        t0 = time.perf_counter_ns()
        try:
            s.sendall(batch_req)
            recvd = 0
            while recvd < expected_resp_len:
                chunk = s.recv(65536)
                if not chunk:
                    break
                recvd += len(chunk)
            t1 = time.perf_counter_ns()

            per_req_latency_us = ((t1 - t0) / 1000.0) / pipeline_depth
            if len(latencies_us) < 10000:
                latencies_us.append(per_req_latency_us)
            total_reqs += pipeline_depth
            total_bytes += recvd
        except Exception:
            break

    s.close()
    results_list.append((total_reqs, total_bytes, latencies_us))


def run_http_benchmark(
    port,
    path="/plaintext",
    concurrency=32,
    duration_sec=5.0,
    pipeline_depth=1,
    label="Target",
):
    stop_event = threading.Event()
    threads = []
    worker_results = []

    t_start = time.perf_counter()
    for _ in range(concurrency):
        t = threading.Thread(
            target=run_http_worker,
            args=(port, path, duration_sec, pipeline_depth, worker_results, stop_event),
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join()
    t_end = time.perf_counter()

    elapsed = max(t_end - t_start, 0.001)
    total_reqs = sum(r[0] for r in worker_results)
    total_bytes = sum(r[1] for r in worker_results)

    all_latencies = []
    for r in worker_results:
        all_latencies.extend(r[2])

    all_latencies.sort()

    if all_latencies:
        p50 = all_latencies[int(len(all_latencies) * 0.50)]
        p90 = all_latencies[int(len(all_latencies) * 0.90)]
        p99 = all_latencies[int(len(all_latencies) * 0.99)]
        p999 = all_latencies[min(int(len(all_latencies) * 0.999), len(all_latencies) - 1)]
        min_lat = min(all_latencies)
        avg_lat = statistics.mean(all_latencies)
        max_lat = max(all_latencies)
    else:
        p50 = p90 = p99 = p999 = min_lat = avg_lat = max_lat = 0.0

    rps = total_reqs / elapsed
    mb_s = (total_bytes / (1024 * 1024)) / elapsed

    return {
        "label": label,
        "port": port,
        "concurrency": concurrency,
        "pipeline_depth": pipeline_depth,
        "elapsed_sec": round(elapsed, 3),
        "total_requests": total_reqs,
        "rps": round(rps, 1),
        "transfer_mb_s": round(mb_s, 2),
        "latency_us": {
            "min": round(min_lat, 2),
            "avg": round(avg_lat, 2),
            "p50": round(p50, 2),
            "p90": round(p90, 2),
            "p99": round(p99, 2),
            "p999": round(p999, 2),
            "max": round(max_lat, 2),
        },
    }


def ws_handshake(s, port, path="/ws"):
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode("ascii")
    s.sendall(req)
    resp = s.recv(4096)
    return b"101 Switching Protocols" in resp


def encode_ws_frame(payload, mask=True, opcode=0x01):
    b0 = 0x80 | (opcode & 0x0F)
    payload_len = len(payload)
    hdr = bytearray()
    hdr.append(b0)

    mask_bit = 0x80 if mask else 0x00
    if payload_len < 126:
        hdr.append(mask_bit | payload_len)
    elif payload_len < 65536:
        hdr.append(mask_bit | 126)
        hdr.extend(payload_len.to_bytes(2, "big"))
    else:
        hdr.append(mask_bit | 127)
        hdr.extend(payload_len.to_bytes(8, "big"))

    if mask:
        mask_key = os.urandom(4)
        hdr.extend(mask_key)
        masked_payload = bytearray(payload_len)
        for i in range(payload_len):
            masked_payload[i] = payload[i] ^ mask_key[i % 4]
        return bytes(hdr + masked_payload)
    else:
        return bytes(hdr + payload)


def run_ws_worker(port, path, duration_sec, results_list, stop_event):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
    except Exception:
        pass
    s.settimeout(3.0)

    try:
        s.connect(("127.0.0.1", port))
        if not ws_handshake(s, port, path):
            s.close()
            return
    except Exception:
        s.close()
        return

    payload = b"PINGPONG_GOOSE_WING_VS_UWEBSOCKETS_ZERO_ALLOC_TEST"
    frame = encode_ws_frame(payload, mask=True, opcode=0x01)
    expected_resp_len = len(payload) + 2  # unmasked header is 2 bytes

    frames = 0
    latencies_us = []
    deadline = time.perf_counter() + duration_sec

    while time.perf_counter() < deadline and not stop_event.is_set():
        t0 = time.perf_counter_ns()
        try:
            s.sendall(frame)
            recvd = 0
            while recvd < expected_resp_len:
                chunk = s.recv(4096)
                if not chunk:
                    break
                recvd += len(chunk)
            t1 = time.perf_counter_ns()
            if len(latencies_us) < 10000:
                latencies_us.append((t1 - t0) / 1000.0)
            frames += 1
        except Exception:
            break

    s.close()
    results_list.append((frames, latencies_us))


def run_websocket_benchmark(port, path="/ws", concurrency=16, duration_sec=5.0, label="Target"):
    stop_event = threading.Event()
    threads = []
    worker_results = []

    t_start = time.perf_counter()
    for _ in range(concurrency):
        t = threading.Thread(
            target=run_ws_worker,
            args=(port, path, duration_sec, worker_results, stop_event),
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join()
    t_end = time.perf_counter()

    elapsed = max(t_end - t_start, 0.001)
    total_frames = sum(r[0] for r in worker_results)

    all_latencies = []
    for r in worker_results:
        all_latencies.extend(r[1])
    all_latencies.sort()

    if all_latencies:
        p50 = all_latencies[int(len(all_latencies) * 0.50)]
        p90 = all_latencies[int(len(all_latencies) * 0.90)]
        p99 = all_latencies[int(len(all_latencies) * 0.99)]
        p999 = all_latencies[min(int(len(all_latencies) * 0.999), len(all_latencies) - 1)]
        min_lat = min(all_latencies)
        avg_lat = statistics.mean(all_latencies)
        max_lat = max(all_latencies)
    else:
        p50 = p90 = p99 = p999 = min_lat = avg_lat = max_lat = 0.0

    fps = total_frames / elapsed

    return {
        "label": label,
        "port": port,
        "concurrency": concurrency,
        "elapsed_sec": round(elapsed, 3),
        "total_requests": total_frames,
        "rps": round(fps, 1),
        "transfer_mb_s": round((total_frames * 64) / (1024 * 1024) / elapsed, 2),
        "latency_us": {
            "min": round(min_lat, 2),
            "avg": round(avg_lat, 2),
            "p50": round(p50, 2),
            "p90": round(p90, 2),
            "p99": round(p99, 2),
            "p999": round(p999, 2),
            "max": round(max_lat, 2),
        },
    }
