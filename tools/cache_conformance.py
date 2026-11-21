#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
Convenience entry point for RFC 9111 / RFC 5861 / RFC 9875 HTTP Cache Conformance Suite.
Delegates directly to tools/cache_conformance/runner.py.
"""

import sys
from pathlib import Path

_runner_dir = str(Path(__file__).resolve().parent / "cache_conformance")
if _runner_dir not in sys.path:
    sys.path.insert(0, _runner_dir)

from runner import main

if __name__ == "__main__":
    main()
