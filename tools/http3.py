#!/usr/bin/env python3
"""
Convenience entry point for HTTP/3 & QUIC Interop Verification Suite.
Delegates directly to tools/http3/runner.py.
"""

import sys
from pathlib import Path

_runner_dir = str(Path(__file__).resolve().parent / "http3")
if _runner_dir not in sys.path:
    sys.path.insert(0, _runner_dir)

from runner import main

if __name__ == "__main__":
    main()
