#!/usr/bin/env python3
"""
Zero-dependency, high-performance Chaos Proxy engine (ToxiProxy equivalent)
implemented entirely in Python 3 using asyncio.

Supports programmatic injection of real-world network anomalies:
  - Slicer: chops streams into 1..N byte chunks with micro-delays (stresses framing)
  - Latency & Jitter: simulates high latency & erratic packet arrival
  - Bandwidth / Drip: rate limits upstream or downstream byte transfers
  - Reset Peer: forcibly aborts connection via TCP RST (SO_LINGER 0)
"""

import asyncio
import logging
import random
import socket
import struct

logger = logging.getLogger("ToxiProxy")


class Toxic:
    """Base class for all network toxics."""

    def __init__(self, name: str, stream: str = "both", toxicity: float = 1.0):
        self.name = name
        self.stream = stream  # "upstream", "downstream", or "both"
        self.toxicity = toxicity

    def applies_to(self, direction: str) -> bool:
        if self.stream != "both" and self.stream != direction:
            return False
        return self.toxicity < 1.0 and random.random() > self.toxicity

    async def transform(
        self, data: bytes, writer: asyncio.StreamWriter, direction: str
    ) -> bool:
        """
        Transforms or delivers data to writer.
        Returns False if connection was reset or terminated by toxic.
        """
        writer.write(data)
        await writer.drain()
        return True


class LatencyToxic(Toxic):
    """Adds fixed latency with Gaussian or uniform jitter."""

    def __init__(
        self,
        name: str = "latency",
        latency_ms: int = 50,
        jitter_ms: int = 10,
        stream: str = "both",
    ):
        super().__init__(name, stream)
        self.latency_ms = latency_ms
        self.jitter_ms = jitter_ms

    async def transform(
        self, data: bytes, writer: asyncio.StreamWriter, direction: str
    ) -> bool:
        if not self.applies_to(direction):
            writer.write(data)
            await writer.drain()
            return True

        delay = self.latency_ms
        if self.jitter_ms > 0:
            delay += random.randint(-self.jitter_ms, self.jitter_ms)
        if delay > 0:
            await asyncio.sleep(delay / 1000.0)

        writer.write(data)
        await writer.drain()
        return True


class SlicerToxic(Toxic):
    """
    Slices incoming byte buffers into tiny pieces (min_bytes..max_bytes)
    with a delay between slices. Ideal for testing wire chunked parsers and TLS boundaries.
    """

    def __init__(
        self,
        name: str = "slicer",
        min_bytes: int = 1,
        max_bytes: int = 5,
        delay_ms: int = 2,
        stream: str = "both",
    ):
        super().__init__(name, stream)
        self.min_bytes = max(1, min_bytes)
        self.max_bytes = max(self.min_bytes, max_bytes)
        self.delay_ms = delay_ms

    async def transform(
        self, data: bytes, writer: asyncio.StreamWriter, direction: str
    ) -> bool:
        if not self.applies_to(direction):
            writer.write(data)
            await writer.drain()
            return True

        idx = 0
        total = len(data)
        while idx < total:
            chunk_sz = random.randint(self.min_bytes, self.max_bytes)
            chunk = data[idx : idx + chunk_sz]
            idx += chunk_sz
            writer.write(chunk)
            await writer.drain()
            if self.delay_ms > 0 and idx < total:
                await asyncio.sleep(self.delay_ms / 1000.0)
        return True


class BandwidthToxic(Toxic):
    """Throttles throughput to a maximum rate in KiB/s."""

    def __init__(
        self, name: str = "bandwidth", rate_kib: int = 32, stream: str = "both"
    ):
        super().__init__(name, stream)
        self.rate_bytes_per_sec = rate_kib * 1024

    async def transform(
        self, data: bytes, writer: asyncio.StreamWriter, direction: str
    ) -> bool:
        if not self.applies_to(direction) or self.rate_bytes_per_sec <= 0:
            writer.write(data)
            await writer.drain()
            return True

        chunk_size = 512
        interval = chunk_size / self.rate_bytes_per_sec
        idx = 0
        while idx < len(data):
            chunk = data[idx : idx + chunk_size]
            idx += chunk_size
            writer.write(chunk)
            await writer.drain()
            await asyncio.sleep(interval)
        return True


class ResetPeerToxic(Toxic):
    """
    Forcibly resets the connection using TCP RST (SO_LINGER 0)
    after an optional byte threshold is reached.
    """

    def __init__(
        self, name: str = "reset_peer", reset_after_bytes: int = 0, stream: str = "both"
    ):
        super().__init__(name, stream)
        self.reset_after_bytes = reset_after_bytes
        self.bytes_seen = 0

    async def transform(
        self, data: bytes, writer: asyncio.StreamWriter, direction: str
    ) -> bool:
        if not self.applies_to(direction):
            writer.write(data)
            await writer.drain()
            return True

        self.bytes_seen += len(data)
        if self.bytes_seen >= self.reset_after_bytes:
            # Force RST on underlying socket
            sock = writer.get_extra_info("socket")
            if sock:
                try:
                    sock.setsockopt(
                        socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
                    )
                except Exception:
                    pass
            writer.close()
            return False

        writer.write(data)
        await writer.drain()
        return True


class ChaosProxy:
    """
    Asynchronous TCP chaos proxy linking listen_port -> upstream_target.
    Supports dynamic adding/removing of toxics on the fly.
    """

    def __init__(
        self,
        listen_host: str = "127.0.0.1",
        listen_port: int = 0,
        upstream_host: str = "127.0.0.1",
        upstream_port: int = 0,
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.server: asyncio.Server | None = None
        self.bound_port: int = 0
        self.toxics: list[Toxic] = []
        self._active_connections = set()
        self._is_running = False

    def add_toxic(self, toxic: Toxic):
        self.toxics.append(toxic)

    def clear_toxics(self):
        self.toxics.clear()

    async def start(self) -> int:
        self.server = await asyncio.start_server(
            self._handle_client, self.listen_host, self.listen_port
        )
        self.bound_port = self.server.sockets[0].getsockname()[1]
        self._is_running = True
        return self.bound_port

    async def stop(self):
        self._is_running = False
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        for task in list(self._active_connections):
            task.cancel()

    async def _handle_client(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
    ):
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(
                self.upstream_host, self.upstream_port
            )
        except Exception:
            client_writer.close()
            return

        task = asyncio.current_task()
        if task:
            self._active_connections.add(task)

        pipe_up = asyncio.create_task(
            self._pipe(client_reader, upstream_writer, client_writer, "upstream")
        )
        pipe_down = asyncio.create_task(
            self._pipe(upstream_reader, client_writer, upstream_writer, "downstream")
        )

        try:
            _, pending = await asyncio.wait(
                [pipe_up, pipe_down], return_when=asyncio.FIRST_COMPLETED
            )
            for p in pending:
                p.cancel()
        except asyncio.CancelledError:
            pass
        finally:
            client_writer.close()
            upstream_writer.close()
            if task in self._active_connections:
                self._active_connections.remove(task)

    async def _pipe(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        peer_writer: asyncio.StreamWriter,
        direction: str,
    ):
        try:
            while self._is_running:
                data = await reader.read(4096)
                if not data:
                    break

                # Apply active toxics for this direction
                processed = False
                for toxic in list(self.toxics):
                    if not toxic.applies_to(direction):
                        break

                    ok = await toxic.transform(data, writer, direction)
                    processed = True
                    if not ok:
                        continue

                    # If toxic aborted the connection, force RST on peer_writer too
                    sock = peer_writer.get_extra_info("socket")
                    if sock:
                        try:
                            sock.setsockopt(
                                socket.SOL_SOCKET,
                                socket.SO_LINGER,
                                struct.pack("ii", 1, 0),
                            )
                        except Exception:
                            pass
                    peer_writer.close()
                    return

                if not processed:
                    writer.write(data)
                    await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass
