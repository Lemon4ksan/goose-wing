#!/usr/bin/env python3
"""
Convenience entry point for gRPC & gRPC-Web E2E Verification Suite.
Delegates directly to tools/grpc/runner.py.
"""

import sys
from pathlib import Path

_runner_dir = str(Path(__file__).resolve().parent / "grpc")
if _runner_dir not in sys.path:
    sys.path.insert(0, _runner_dir)

from runner import main

if __name__ == "__main__":
    main()
