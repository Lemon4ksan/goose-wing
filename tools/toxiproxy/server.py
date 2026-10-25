#!/usr/bin/env python3
"""
Toxiproxy Server Lifecycle Manager.
Discovers or downloads official Shopify Toxiproxy binary and manages server process.
"""

import atexit
import json
import logging
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

logger = logging.getLogger("ToxiproxyServer")

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8474
GITHUB_RELEASE_VERSION = "v2.13.0"

_MANAGED_SERVER_PROCESS: subprocess.Popen | None = None


def find_toxiproxy_server_binary() -> Path | None:
    """Finds toxiproxy-server executable on system PATH or local tools/bin directories."""
    binary_name = "toxiproxy-server.exe" if sys.platform == "win32" else "toxiproxy-server"

    # 1. Local tools/bin directory
    local_bin = Path(__file__).resolve().parent.parent / "bin" / binary_name
    if local_bin.is_file() and os.access(local_bin, os.X_OK):
        return local_bin

    # 2. System PATH
    found = shutil.which(binary_name) or shutil.which("toxiproxy-server")
    if found:
        return Path(found)

    # 3. User go/bin directory
    home = Path.home()
    go_bin = home / "go" / "bin" / binary_name
    if go_bin.is_file() and os.access(go_bin, os.X_OK):
        return go_bin

    return None


def download_toxiproxy_server(target_dir: Path | None = None) -> Path:
    """Downloads official Shopify toxiproxy-server binary from GitHub releases."""
    if target_dir is None:
        target_dir = Path(__file__).resolve().parent.parent / "bin"
    target_dir.mkdir(parents=True, exist_ok=True)

    if sys.platform == "win32":
        artifact = "toxiproxy-server-windows-amd64.exe"
        dest_name = "toxiproxy-server.exe"
    elif sys.platform == "darwin":
        artifact = "toxiproxy-server-darwin-amd64"
        dest_name = "toxiproxy-server"
    else:
        artifact = "toxiproxy-server-linux-amd64"
        dest_name = "toxiproxy-server"

    url = f"https://github.com/Shopify/toxiproxy/releases/download/{GITHUB_RELEASE_VERSION}/{artifact}"
    dest_path = target_dir / dest_name

    logger.info("Downloading official Toxiproxy binary from %s -> %s", url, dest_path)
    urllib.request.urlretrieve(url, dest_path)
    os.chmod(dest_path, 0o755)
    return dest_path


class ToxiproxyServer:
    """Controls the local Shopify Toxiproxy daemon."""

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, binary_path: Path | None = None):
        self.host = host
        self.port = port
        self.binary_path = binary_path or find_toxiproxy_server_binary()
        self.process: subprocess.Popen | None = None
        self._is_managed = False

    @property
    def api_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def is_healthy(self) -> bool:
        """Checks if Toxiproxy HTTP API is reachable and responding."""
        try:
            req = urllib.request.Request(f"{self.api_url}/version")
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    return "version" in data
        except Exception:
            return False
        return False

    def start(self, timeout_sec: float = 5.0):
        """Starts toxiproxy-server if not already running."""
        global _MANAGED_SERVER_PROCESS
        if self.is_healthy():
            logger.debug("Toxiproxy server already active at %s", self.api_url)
            return

        if not self.binary_path or not self.binary_path.exists():
            self.binary_path = download_toxiproxy_server()

        cmd = [
            str(self.binary_path),
            "-host", self.host,
            "-port", str(self.port),
        ]
        logger.info("Starting Toxiproxy daemon: %s", " ".join(cmd))
        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            close_fds=(sys.platform != "win32"),
        )
        self._is_managed = True
        _MANAGED_SERVER_PROCESS = self.process

        # Wait until server responds
        start_time = time.time()
        while time.time() - start_time < timeout_sec:
            if self.is_healthy():
                logger.info("Toxiproxy server successfully started on %s", self.api_url)
                return
            if self.process.poll() is not None:
                raise RuntimeError(
                    f"Toxiproxy server process exited unexpectedly with code {self.process.returncode}"
                )
            time.sleep(0.1)

        raise TimeoutError(f"Toxiproxy server failed to become healthy at {self.api_url} within {timeout_sec}s")

    def stop(self):
        """Stops the managed server process if this instance spawned it."""
        global _MANAGED_SERVER_PROCESS
        if self._is_managed and self.process:
            logger.info("Stopping managed Toxiproxy server (PID %s)", self.process.pid)
            try:
                self.process.terminate()
                self.process.wait(timeout=2.0)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
            finally:
                self.process = None
                self._is_managed = False
                _MANAGED_SERVER_PROCESS = None


def cleanup_managed_server():
    global _MANAGED_SERVER_PROCESS
    if _MANAGED_SERVER_PROCESS:
        try:
            _MANAGED_SERVER_PROCESS.terminate()
            _MANAGED_SERVER_PROCESS.wait(timeout=1.0)
        except Exception:
            try:
                _MANAGED_SERVER_PROCESS.kill()
            except Exception:
                pass
        _MANAGED_SERVER_PROCESS = None


atexit.register(cleanup_managed_server)


def ensure_server_running(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> ToxiproxyServer:
    server = ToxiproxyServer(host, port)
    if not server.is_healthy():
        server.start()
    return server


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Toxiproxy Server Supervisor")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Host to bind to")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port for Toxiproxy HTTP API")
    parser.add_argument("--status", action="store_true", help="Check server status")
    parser.add_argument("--start", action="store_true", help="Start server in foreground")
    parser.add_argument("--download", action="store_true", help="Download official toxiproxy binary")

    args = parser.parse_args()

    if args.download:
        p = download_toxiproxy_server()
        print(f"Downloaded toxiproxy binary to: {p}")
        sys.exit(0)

    server = ToxiproxyServer(args.host, args.port)
    if args.status:
        if server.is_healthy():
            print(f"[OK] Toxiproxy server is running and healthy at {server.api_url}")
            sys.exit(0)
        else:
            print(f"[DOWN] Toxiproxy server is not reachable at {server.api_url}")
            sys.exit(1)

    print(f"Ensuring Toxiproxy server is running at {server.api_url}...")
    server.start()
    print(f"[OK] Toxiproxy is live at {server.api_url}. Press Ctrl+C to terminate.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping Toxiproxy...")
        server.stop()
