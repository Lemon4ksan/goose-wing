#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
Toxiproxy module entry point.
Exposes real Shopify Toxiproxy client and chaos harness.
"""

import sys
from pathlib import Path

# Ensure directory is on sys.path for top-level script execution
_cur_dir = str(Path(__file__).resolve().parent)
if _cur_dir not in sys.path:
    sys.path.insert(0, _cur_dir)

try:
    from .client import ToxiproxyClient, ToxiproxyError
    from .proxy import ChaosProxy
    from .server import (
        ToxiproxyServer,
        ensure_server_running,
        find_toxiproxy_server_binary,
    )
    from .toxics import (
        BandwidthToxic,
        LatencyToxic,
        LimitDataToxic,
        ResetPeerToxic,
        SlicerToxic,
        SlowCloseToxic,
        TimeoutToxic,
        Toxic,
    )
except ImportError:
    from toxics import (
        BandwidthToxic,
        LatencyToxic,
        LimitDataToxic,
        ResetPeerToxic,
        SlicerToxic,
        SlowCloseToxic,
        TimeoutToxic,
        Toxic,
    )

    from client import ToxiproxyClient, ToxiproxyError
    from proxy import ChaosProxy
    from server import (
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
