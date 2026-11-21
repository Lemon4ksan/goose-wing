#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
Deterministic HTTP/1.1 Origin Server for the goose-wing Cache Conformance Suite.
Used both inside Docker (`docker-compose.yml`) and on local loopback in `--local` mode
to verify real wire HTTP/1.1 caching, ETag 304 revalidation, Vary headers, and Cache-Groups.
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_DATE = "Thu, 01 Jan 2026 00:00:00 GMT"
LM_DATE = "Wed, 31 Dec 2025 23:00:00 GMT"


class CacheOriginHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args) -> None:
        return

    def _send(self, code: int, headers: list[tuple[str, str]], body: bytes) -> None:
        self.send_response(code)
        has_date = False
        for k, v in headers:
            if k.lower() == "date":
                has_date = True
            self.send_header(k, v)
        if not has_date:
            self.send_header("Date", BASE_DATE)
        if code not in (204, 304):
            self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if code not in (204, 304) and body:
            self.wfile.write(body)

    def do_GET(self) -> None:
        inm = self.headers.get("If-None-Match", "")
        ae = self.headers.get("Accept-Encoding", "")

        if self.path == "/health":
            self._send(200, [("Content-Type", "text/plain")], b"OK")
            return

        if self.path == "/live/etag":
            if inm == '"live-v1"':
                self._send(
                    304,
                    [
                        ("ETag", '"live-v1"'),
                        ("Cache-Control", "max-age=300"),
                        ("X-Tag", "revalidated-304"),
                        ("Content-Type", "application/evil-override"),
                    ],
                    b"",
                )
                return
            self._send(
                200,
                [
                    ("Content-Type", "text/plain"),
                    ("Cache-Control", "max-age=10"),
                    ("ETag", '"live-v1"'),
                    ("X-Tag", "origin-fresh"),
                ],
                b"LIVE_ETAG_BODY",
            )
            return

        if self.path == "/live/vary":
            body = f"ENC:{ae or 'none'}".encode("ascii")
            self._send(
                200,
                [
                    ("Content-Type", "text/plain"),
                    ("Cache-Control", "max-age=120"),
                    ("Vary", "Accept-Encoding"),
                    ("X-Tag", ae or "none"),
                ],
                body,
            )
            return

        if self.path == "/live/group-a":
            self._send(
                200,
                [
                    ("Content-Type", "text/plain"),
                    ("Cache-Control", "max-age=300"),
                    ("Cache-Groups", '"catalog"'),
                    ("X-Tag", "grp-a"),
                ],
                b"GROUP_A_DATA",
            )
            return

        if self.path == "/live/group-b":
            self._send(
                200,
                [
                    ("Content-Type", "text/plain"),
                    ("Cache-Control", "max-age=300"),
                    ("Cache-Groups", '"blog"'),
                    ("X-Tag", "grp-b"),
                ],
                b"GROUP_B_DATA",
            )
            return

        if self.path == "/live/nostore":
            self._send(
                200,
                [
                    ("Content-Type", "text/plain"),
                    ("Cache-Control", "no-store"),
                    ("X-Tag", "secret"),
                ],
                b"NO_STORE_DATA",
            )
            return

        self._send(
            200,
            [("Content-Type", "text/plain"), ("Cache-Control", "max-age=60")],
            b"DEFAULT_ORIGIN",
        )

    def do_POST(self) -> None:
        if self.path == "/live/purge-catalog":
            self._send(
                200,
                [
                    ("Content-Type", "text/plain"),
                    ("Cache-Group-Invalidation", '"catalog"'),
                    ("X-Tag", "purged"),
                ],
                b"PURGED",
            )
            return
        self._send(200, [("Content-Type", "text/plain")], b"POST_OK")


def create_origin_server(host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), CacheOriginHandler)


def main() -> None:
    parser = argparse.ArgumentParser(description="HTTP/1.1 origin server for cache conformance")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8082)
    args = parser.parse_args()
    srv = create_origin_server(args.host, args.port)
    print(f"READY_PORT:{srv.server_address[1]}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
