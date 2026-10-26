#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
Toxiproxy REST API Client.
Communicates directly with Shopify Toxiproxy HTTP API on localhost:8474.
Requires zero external dependencies (pure Python standard library).
"""

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any

try:
    from .toxics import Toxic
except ImportError:
    from toxics import Toxic

logger = logging.getLogger("ToxiproxyClient")


class ToxiproxyError(Exception):
    """Base exception for Toxiproxy API errors."""

    def __init__(self, status: int, message: str):
        super().__init__(f"Toxiproxy HTTP {status}: {message}")
        self.status = status
        self.message = message


class ToxiproxyClient:
    """Synchronous REST client for Shopify Toxiproxy."""

    def __init__(self, host: str | None = None, port: int | None = None):
        self.host = host or os.environ.get("TOXIPROXY_HOST", "127.0.0.1")
        self.port = port or int(os.environ.get("TOXIPROXY_PORT", "8474"))
        self.base_url = f"http://{self.host}:{self.port}"

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        url = f"{self.base_url}{path}"
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                _ = resp.status
                body = resp.read()
                if body:
                    return json.loads(body.decode("utf-8"))
                return None
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            raise ToxiproxyError(exc.code, err_body) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f"Could not connect to Toxiproxy at {self.base_url}: {exc.reason}"
            ) from exc

    def version(self) -> str:
        data = self._request("GET", "/version")
        return data.get("version", "") if isinstance(data, dict) else str(data)

    def reset(self):
        """Resets all proxies to enabled state and removes all active toxics."""
        self._request("POST", "/reset")

    def list_proxies(self) -> dict[str, Any]:
        return self._request("GET", "/proxies")

    def create_proxy(
        self, name: str, listen: str = "127.0.0.1:0", upstream: str = "", enabled: bool = True
    ) -> dict[str, Any]:
        """Creates a new proxy mapping. If listen port is 0, an ephemeral port is selected."""
        payload = {
            "name": name,
            "listen": listen,
            "upstream": upstream,
            "enabled": enabled,
        }
        return self._request("POST", "/proxies", payload)

    def get_proxy(self, name: str) -> dict[str, Any]:
        return self._request("GET", f"/proxies/{name}")

    def update_proxy(
        self,
        name: str,
        listen: str | None = None,
        upstream: str | None = None,
        enabled: bool | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        if listen is not None:
            payload["listen"] = listen
        if upstream is not None:
            payload["upstream"] = upstream
        if enabled is not None:
            payload["enabled"] = enabled
        return self._request("POST", f"/proxies/{name}", payload)

    def delete_proxy(self, name: str):
        try:
            self._request("DELETE", f"/proxies/{name}")
        except ToxiproxyError as exc:
            if exc.status != 404:
                raise

    def list_toxics(self, proxy_name: str) -> list[dict[str, Any]]:
        return self._request("GET", f"/proxies/{proxy_name}/toxics")

    def add_toxic(self, proxy_name: str, toxic: Toxic) -> list[dict[str, Any]]:
        """Applies a Toxic to the specified proxy."""
        results = []
        for payload in toxic.to_api_payloads():
            # If toxic already exists, remove it first
            try:
                self.delete_toxic(proxy_name, payload["name"])
            except Exception:
                pass
            res = self._request("POST", f"/proxies/{proxy_name}/toxics", payload)
            results.append(res)
        return results

    def delete_toxic(self, proxy_name: str, toxic_name: str):
        try:
            self._request("DELETE", f"/proxies/{proxy_name}/toxics/{toxic_name}")
        except ToxiproxyError as exc:
            if exc.status != 404:
                raise

    def clear_toxics(self, proxy_name: str):
        """Removes all toxics configured on a proxy."""
        try:
            toxics = self.list_toxics(proxy_name)
            for t in toxics:
                t_name = t.get("name")
                if t_name:
                    self.delete_toxic(proxy_name, t_name)
        except ToxiproxyError as exc:
            if exc.status != 404:
                raise
