#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
Convenience entry point for the TLS Interop Canary (badssl.com + Offline Local CA Matrix).
Delegates directly to tools/badssl_canary/runner.py.
"""

import sys
from pathlib import Path

_runner_dir = str(Path(__file__).resolve().parent / "badssl_canary")
if _runner_dir not in sys.path:
    sys.path.insert(0, _runner_dir)

from runner import main

if __name__ == "__main__":
    main()
