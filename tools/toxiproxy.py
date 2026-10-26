#!/usr/bin/env python3
"""
Toxiproxy module entry point at tools/ level.
Redirects to tools/toxiproxy package and provides CLI for running
the chaos suite locally or via Docker.
"""

import subprocess
import sys
from pathlib import Path

_pkg_dir = str(Path(__file__).resolve().parent / "toxiproxy")
if _pkg_dir not in sys.path:
    sys.path.insert(0, _pkg_dir)

from toxiproxy import (
    BandwidthToxic,
    ChaosProxy,
    LatencyToxic,
    LimitDataToxic,
    ResetPeerToxic,
    SlicerToxic,
    SlowCloseToxic,
    TimeoutToxic,
    Toxic,
    ToxiproxyClient,
    ToxiproxyError,
    ToxiproxyServer,
    ensure_server_running,
    find_toxiproxy_server_binary,
)

__all__ = [
    "BandwidthToxic",
    "ChaosProxy",
    "LatencyToxic",
    "LimitDataToxic",
    "ResetPeerToxic",
    "SlicerToxic",
    "SlowCloseToxic",
    "TimeoutToxic",
    "Toxic",
    "ToxiproxyClient",
    "ToxiproxyError",
    "ToxiproxyServer",
    "ensure_server_running",
    "find_toxiproxy_server_binary",
]

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Toxiproxy Chaos Test Runner for goose-wing")
    parser.add_argument("--docker", action="store_true", help="Execute 43-stage chaos suite inside Docker container")
    parser.add_argument("--daemon", action="store_true", help="Start standalone Toxiproxy daemon in Docker")
    args, unknown = parser.parse_known_args()

    root = Path(__file__).resolve().parent.parent
    compose_file = root / "tools" / "toxiproxy" / "docker-compose.yml"

    if args.daemon:
        cmd = ["docker", "compose", "-f", str(compose_file), "up", "--build", "toxiproxy-daemon"]
        sys.exit(subprocess.run(cmd, cwd=str(root)).returncode)
    elif args.docker:
        cmd = ["docker", "compose", "-f", str(compose_file), "up", "--build", "chaos-suite", "--abort-on-container-exit"]
        sys.exit(subprocess.run(cmd, cwd=str(root)).returncode)
    else:
        # Default: run local Python stress runner
        runner_script = Path(_pkg_dir) / "stress_all_goose.py"
        cmd = [sys.executable, str(runner_script)] + unknown
        sys.exit(subprocess.run(cmd, cwd=str(root)).returncode)
