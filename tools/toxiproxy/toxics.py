#!/usr/bin/env python3
"""
Toxiproxy Toxic Definitions.
Maps directly to Shopify Toxiproxy native toxic specifications.
"""

from typing import Any


class Toxic:
    """Base class for Toxiproxy toxics."""

    def __init__(
        self,
        name: str,
        type_name: str,
        stream: str = "both",
        toxicity: float = 1.0,
        attributes: dict[str, Any] | None = None,
    ):
        self.name = name
        self.type_name = type_name
        self.stream = stream.lower()  # "upstream", "downstream", or "both"
        self.toxicity = max(0.0, min(1.0, toxicity))
        self.attributes = attributes or {}

    def to_api_payloads(self) -> list[dict[str, Any]]:
        """
        Generates REST API payloads. If stream is 'both', generates
        separate upstream and downstream toxic entries for Toxiproxy.
        """
        if self.stream == "both":
            return [
                {
                    "name": f"{self.name}_up",
                    "type": self.type_name,
                    "stream": "upstream",
                    "toxicity": self.toxicity,
                    "attributes": dict(self.attributes),
                },
                {
                    "name": f"{self.name}_down",
                    "type": self.type_name,
                    "stream": "downstream",
                    "toxicity": self.toxicity,
                    "attributes": dict(self.attributes),
                },
            ]
        elif self.stream in ("upstream", "downstream"):
            return [
                {
                    "name": self.name,
                    "type": self.type_name,
                    "stream": self.stream,
                    "toxicity": self.toxicity,
                    "attributes": dict(self.attributes),
                }
            ]
        else:
            raise ValueError(f"Invalid stream direction: {self.stream}. Must be upstream, downstream, or both.")


class LatencyToxic(Toxic):
    """
    Delays data transmission by latency_ms +/- jitter_ms.
    Native Toxiproxy type: 'latency'.
    """

    def __init__(
        self,
        name: str = "latency",
        latency_ms: int = 50,
        jitter_ms: int = 0,
        stream: str = "both",
        toxicity: float = 1.0,
    ):
        super().__init__(
            name=name,
            type_name="latency",
            stream=stream,
            toxicity=toxicity,
            attributes={"latency": int(latency_ms), "jitter": int(jitter_ms)},
        )
        self.latency_ms = latency_ms
        self.jitter_ms = jitter_ms


class BandwidthToxic(Toxic):
    """
    Throttles throughput to a maximum rate in KiB/s (KB/s).
    Native Toxiproxy type: 'bandwidth'.
    """

    def __init__(
        self,
        name: str = "bandwidth",
        rate_kib: int = 32,
        stream: str = "both",
        toxicity: float = 1.0,
    ):
        super().__init__(
            name=name,
            type_name="bandwidth",
            stream=stream,
            toxicity=toxicity,
            attributes={"rate": int(rate_kib)},
        )
        self.rate_kib = rate_kib


class SlicerToxic(Toxic):
    """
    Slices stream into smaller chunks with microsecond delays.
    Native Toxiproxy type: 'slicer'.
    Supports min_bytes/max_bytes bounds or direct average_size/size_variation.
    """

    def __init__(
        self,
        name: str = "slicer",
        min_bytes: int | None = None,
        max_bytes: int | None = None,
        delay_ms: int | float = 0,
        average_size: int = 100,
        size_variation: int = 20,
        stream: str = "both",
        toxicity: float = 1.0,
    ):
        if min_bytes is not None or max_bytes is not None:
            lo = max(1, min_bytes if min_bytes is not None else 1)
            hi = max(lo, max_bytes if max_bytes is not None else lo)
            avg = max(1, (lo + hi) // 2)
            var = max(0, min(avg, (hi - lo) // 2))
        else:
            avg = max(1, average_size)
            var = max(0, min(avg, size_variation))

        delay_us = int(delay_ms * 1000)
        super().__init__(
            name=name,
            type_name="slicer",
            stream=stream,
            toxicity=toxicity,
            attributes={
                "average_size": avg,
                "size_variation": var,
                "delay": delay_us,
            },
        )
        self.min_bytes = min_bytes
        self.max_bytes = max_bytes
        self.delay_ms = delay_ms


class ResetPeerToxic(Toxic):
    """
    Abruptly terminates the connection with a TCP RST (SO_LINGER 0).
    If reset_after_bytes > 0, leverages native 'limit_data' toxic to abort
    exactly after the specified byte count. Otherwise triggers native 'reset_peer'.
    """

    def __init__(
        self,
        name: str = "reset_peer",
        reset_after_bytes: int = 0,
        timeout_ms: int = 0,
        stream: str = "both",
        toxicity: float = 1.0,
    ):
        self.reset_after_bytes = reset_after_bytes
        self.timeout_ms = timeout_ms

        if reset_after_bytes > 0:
            type_name = "limit_data"
            attrs = {"bytes": int(reset_after_bytes)}
        else:
            type_name = "reset_peer"
            attrs = {"timeout": int(timeout_ms)}

        super().__init__(
            name=name,
            type_name=type_name,
            stream=stream,
            toxicity=toxicity,
            attributes=attrs,
        )


class TimeoutToxic(Toxic):
    """
    Drops data and times out connection after timeout_ms.
    Native Toxiproxy type: 'timeout'.
    """

    def __init__(
        self,
        name: str = "timeout",
        timeout_ms: int = 1000,
        stream: str = "both",
        toxicity: float = 1.0,
    ):
        super().__init__(
            name=name,
            type_name="timeout",
            stream=stream,
            toxicity=toxicity,
            attributes={"timeout": int(timeout_ms)},
        )


class SlowCloseToxic(Toxic):
    """
    Delays TCP socket close until delay_ms has elapsed.
    Native Toxiproxy type: 'slow_close'.
    """

    def __init__(
        self,
        name: str = "slow_close",
        delay_ms: int = 500,
        stream: str = "both",
        toxicity: float = 1.0,
    ):
        super().__init__(
            name=name,
            type_name="slow_close",
            stream=stream,
            toxicity=toxicity,
            attributes={"delay": int(delay_ms)},
        )


class LimitDataToxic(Toxic):
    """
    Closes connection when transmitted data exceeds limit bytes.
    Native Toxiproxy type: 'limit_data'.
    """

    def __init__(
        self,
        name: str = "limit_data",
        bytes_limit: int = 1024,
        stream: str = "both",
        toxicity: float = 1.0,
    ):
        super().__init__(
            name=name,
            type_name="limit_data",
            stream=stream,
            toxicity=toxicity,
            attributes={"bytes": int(bytes_limit)},
        )
