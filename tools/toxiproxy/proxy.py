#!/usr/bin/env python3
"""
Toxiproxy Proxy Wrapper (ChaosProxy).
Provides full compatibility with existing Goose-Wing stress test harness
while running against official Shopify Toxiproxy daemon.
"""

import contextlib
import logging
import os
import uuid

try:
    from .client import ToxiproxyClient
    from .server import ensure_server_running
    from .toxics import Toxic
except ImportError:
    from toxics import Toxic

    from client import ToxiproxyClient
    from server import ensure_server_running

logger = logging.getLogger("ChaosProxy")


class ChaosProxy:
    """
    High-level Toxiproxy proxy session.
    Automatically ensures toxiproxy-server is active and coordinates
    proxy lifecycle and network toxic injection.
    """

    def __init__(
        self,
        listen_host: str = "127.0.0.1",
        listen_port: int = 0,
        upstream_host: str = "127.0.0.1",
        upstream_port: int = 0,
        name: str | None = None,
        api_host: str = "127.0.0.1",
        api_port: int = 8474,
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.name = name or f"gw_chaos_{os.getpid()}_{uuid.uuid4().hex[:8]}"
        self.api_host = api_host
        self.api_port = api_port

        self.client = ToxiproxyClient(api_host, api_port)
        self.bound_port: int = 0
        self.listen_addr: str = ""
        self._active_toxics: list[Toxic] = []
        self._is_running = False

    def add_toxic(self, toxic: Toxic):
        """Adds a network toxic to this proxy in the live Toxiproxy daemon."""
        self._active_toxics.append(toxic)
        if self._is_running:
            self.client.add_toxic(self.name, toxic)

    def clear_toxics(self):
        """Clears all active toxics from this proxy."""
        self._active_toxics.clear()
        if self._is_running:
            self.client.clear_toxics(self.name)

    @contextlib.contextmanager
    def toxic(self, t: Toxic):
        """Context manager to temporarily apply a toxic to this proxy session."""
        self.add_toxic(t)
        try:
            yield t
        finally:
            if self._is_running:
                for p in t.to_api_payloads():
                    try:
                        self.client.delete_toxic(self.name, p["name"])
                    except Exception:
                        pass
            if t in self._active_toxics:
                self._active_toxics.remove(t)

    @contextlib.asynccontextmanager
    async def atoxic(self, t: Toxic):
        """Async context manager to temporarily apply a toxic to this proxy session."""
        with self.toxic(t):
            yield t

    def start_sync(self) -> int:
        """Starts the proxy synchronously and returns the bound listen port."""
        return self._start_sync()

    def stop_sync(self):
        """Stops the proxy synchronously."""
        self._stop_sync()

    async def start(self) -> int:
        """
        Starts the proxy in Toxiproxy and resolves bound listen port.
        Can be awaited in asyncio code or run in async runners.
        """
        return self._start_sync()

    def _start_sync(self) -> int:
        ensure_server_running(self.api_host, self.api_port)

        # Remove existing proxy with same name if stale
        try:
            self.client.delete_proxy(self.name)
        except Exception:
            pass

        listen_spec = f"{self.listen_host}:{self.listen_port}"
        upstream_spec = f"{self.upstream_host}:{self.upstream_port}"

        data = self.client.create_proxy(
            name=self.name,
            listen=listen_spec,
            upstream=upstream_spec,
            enabled=True,
        )

        self.listen_addr = data.get("listen", "")
        # Extract port from "127.0.0.1:port" or "[::1]:port"
        port_str = self.listen_addr.rsplit(":", 1)[-1]
        self.bound_port = int(port_str)
        self._is_running = True

        # Re-apply any queued toxics
        for toxic in self._active_toxics:
            self.client.add_toxic(self.name, toxic)

        return self.bound_port

    async def stop(self):
        """Tears down this proxy in Toxiproxy."""
        self._stop_sync()

    def _stop_sync(self):
        if self._is_running:
            try:
                self.client.delete_proxy(self.name)
            except Exception:
                pass
            finally:
                self._is_running = False

    def __enter__(self):
        self._start_sync()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._stop_sync()

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.stop()
