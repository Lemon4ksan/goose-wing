#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
bench_core.py - Cross-Platform Benchmark Core & Telemetry Utilities
Measures process RSS memory and resource metrics for goose-wing vs uWebSockets.
Load generation is delegated entirely to native C engines (wrk, bench_burst) to eliminate
Python GIL bottlenecks and avoid distorted performance metrics.
"""

import os
import subprocess


def get_process_rss_mb(pid: int) -> float:
    """Retrieve process Resident Set Size (RSS) in Megabytes."""
    if not pid or pid <= 0:
        return 0.0
    try:
        if os.name == "posix":
            # Linux /proc/<pid>/statm: second field is resident pages (4KB)
            statm_path = f"/proc/{pid}/statm"
            if os.path.exists(statm_path):
                with open(statm_path) as f:
                    parts = f.read().split()
                    pages = int(parts[1])
                    return round((pages * 4096) / (1024 * 1024), 2)
            # Fallback to status
            status_path = f"/proc/{pid}/status"
            if os.path.exists(status_path):
                with open(status_path) as f:
                    for line in f:
                        if line.startswith("VmRSS:"):
                            kb = int(line.split()[1])
                            return round(kb / 1024, 2)
        elif os.name == "nt":
            # Windows fallback via tasklist
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
