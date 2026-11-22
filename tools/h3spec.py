#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
Convenience entry point for the h3spec HTTP/3 Conformance Suite.
Delegates directly to tools/h3spec/runner.py.
"""

import sys
from pathlib import Path

_runner_dir = str(Path(__file__).resolve().parent / "h3spec")
if _runner_dir not in sys.path:
    sys.path.insert(0, _runner_dir)

from runner import main

if __name__ == "__main__":
    main()
