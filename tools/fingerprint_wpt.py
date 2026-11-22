#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
Convenience entry point for Browser Fingerprints (JA3/JA4/Akamai H2/JA4DB)
and Web Platform Tests (WPT Cookies, Redirects, CORS) conformance suite.
Delegates directly to tools/fingerprint_wpt/runner.py.
"""

import sys
from pathlib import Path

_runner_dir = str(Path(__file__).resolve().parent / "fingerprint_wpt")
if _runner_dir not in sys.path:
    sys.path.insert(0, _runner_dir)

from runner import main

if __name__ == "__main__":
    main()
