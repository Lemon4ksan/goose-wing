#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
RFC 9111 / RFC 5861 / RFC 9875 HTTP Cache Conformance Runner (`mnot/http-tests`-style).
Drives `tools/cache_conformance/cache_harness.goose` across structured cache compliance
scenarios covering Cache-Control directives, Age/Expires/heuristic freshness, Vary matching,
conditional revalidation (ETag/Last-Modified 304 merge), unsafe method invalidation,
RFC 5861 stale-while-revalidate / stale-if-error, RFC 9875 Cache-Groups invalidation,
and live HTTP/1.1 origin roundtrips.
"""

from __future__ import annotations

import argparse
import io
import os
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import format_datetime
from pathlib import Path

from origin_server import create_origin_server

if (
    isinstance(sys.stdout, io.TextIOWrapper)
    and sys.stdout.encoding
    and sys.stdout.encoding.lower() != "utf-8"
):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if (
    isinstance(sys.stderr, io.TextIOWrapper)
    and sys.stderr.encoding
    and sys.stderr.encoding.lower() != "utf-8"
):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
TOOLS_DIR = ROOT_DIR / "tools"
BIN_DIR = TOOLS_DIR / "bin"
HARNESS_SRC = TOOLS_DIR / "cache_conformance" / "cache_harness.goose"
HARNESS_EXE = BIN_DIR / ("cache_harness.exe" if sys.platform == "win32" else "cache_harness")

T0 = 1767225600  # 2026-01-01 00:00:00 UTC


def http_date(unix_sec: int) -> str:
    return format_datetime(datetime.fromtimestamp(unix_sec, tz=UTC), usegmt=True)


def enc_headers(hdrs: dict[str, str] | None) -> str:
    if not hdrs:
        return "-"
    lines = "".join(f"{k}: {v}\n" for k, v in hdrs.items())
    return lines.encode("utf-8").hex()


def enc_body(body: str) -> str:
    return body.encode("utf-8").hex() if body else "-"


@dataclass
class StepExpect:
    lookup: str
    action: str | None = None
    swr_bg: int | None = None
    status: int | None = None
    body: str | None = None
    min_age: int | None = None
    content_type: str | None = None
    x_tag: str | None = None
    inm: str | None = None
    ims: str | None = None
    require_via: bool = False


@dataclass
class CacheStep:
    step_id: str
    now_sec: int
    method: str
    url: str
    req_headers: dict[str, str] = field(default_factory=dict)
    orig_status: int = 200
    orig_headers: dict[str, str] = field(default_factory=dict)
    orig_body: str = ""
    expect: StepExpect = field(default_factory=lambda: StepExpect(lookup="MISS"))


@dataclass
class CacheScenario:
    name: str
    rfc: str
    shared: bool
    steps: list[CacheStep]


def build_offline_scenarios() -> list[CacheScenario]:
    """25 mnot/http-tests-style scenarios covering RFC 9111, RFC 5861, and RFC 9875."""
    d0 = http_date(T0)
    lm_1000 = http_date(T0 - 1000)
    exp_plus_120 = http_date(T0 + 120)
    exp_past = http_date(T0 - 60)

    return [
        # 1. Cache-Control: no-store response
        CacheScenario(
            "cc_no_store_response",
            "RFC 9111 §5.2.2.5",
            True,
            [
                CacheStep(
                    "s1",
                    T0,
                    "GET",
                    "https://origin.test/secret",
                    orig_headers={"Date": d0, "Cache-Control": "no-store, max-age=300"},
                    orig_body="secret-1",
                    expect=StepExpect(lookup="MISS", action="PASS", status=200, body="secret-1", require_via=True),
                ),
                CacheStep(
                    "s2",
                    T0 + 1,
                    "GET",
                    "https://origin.test/secret",
                    orig_headers={"Date": d0, "Cache-Control": "no-store"},
                    orig_body="secret-2",
                    expect=StepExpect(lookup="MISS", action="PASS", status=200, body="secret-2"),
                ),
            ],
        ),
        # 2. Cache-Control: no-store request bypass
        CacheScenario(
            "cc_no_store_request",
            "RFC 9111 §5.2.1.5",
            True,
            [
                CacheStep(
                    "s1",
                    T0,
                    "GET",
                    "https://origin.test/pub",
                    orig_headers={"Date": d0, "Cache-Control": "max-age=300"},
                    orig_body="cached-v1",
                    expect=StepExpect(lookup="MISS", action="STORE", body="cached-v1"),
                ),
                CacheStep(
                    "s2",
                    T0 + 5,
                    "GET",
                    "https://origin.test/pub",
                    req_headers={"Cache-Control": "no-store"},
                    orig_headers={"Date": d0, "Cache-Control": "max-age=300"},
                    orig_body="fresh-v2",
                    expect=StepExpect(lookup="MISS", action="PASS", body="fresh-v2"),
                ),
            ],
        ),
        # 3. Cache-Control: private rejected by shared cache
        CacheScenario(
            "cc_private_shared_not_stored",
            "RFC 9111 §5.2.2.7",
            True,
            [
                CacheStep(
                    "s1",
                    T0,
                    "GET",
                    "https://origin.test/me",
                    orig_headers={"Date": d0, "Cache-Control": "private, max-age=300"},
                    orig_body="user-1",
                    expect=StepExpect(lookup="MISS", action="PASS", body="user-1"),
                ),
                CacheStep(
                    "s2",
                    T0 + 5,
                    "GET",
                    "https://origin.test/me",
                    orig_headers={"Date": d0, "Cache-Control": "private, max-age=300"},
                    orig_body="user-2",
                    expect=StepExpect(lookup="MISS", action="PASS", body="user-2"),
                ),
            ],
        ),
        # 4. Cache-Control: private stored by private cache
        CacheScenario(
            "cc_private_private_cache_stored",
            "RFC 9111 §5.2.2.7",
            False,
            [
                CacheStep(
                    "s1",
                    T0,
                    "GET",
                    "https://origin.test/me",
                    orig_headers={"Date": d0, "Cache-Control": "private, max-age=300"},
                    orig_body="user-1",
                    expect=StepExpect(lookup="MISS", action="STORE", body="user-1"),
                ),
                CacheStep(
                    "s2",
                    T0 + 10,
                    "GET",
                    "https://origin.test/me",
                    expect=StepExpect(lookup="HIT", status=200, body="user-1", min_age=10),
                ),
            ],
        ),
        # 5. Cache-Control: no-cache forces revalidation
        CacheScenario(
            "cc_no_cache_forces_revalidation",
            "RFC 9111 §5.2.2.4",
            True,
            [
                CacheStep(
                    "s1",
                    T0,
                    "GET",
                    "https://origin.test/nc",
                    orig_headers={"Date": d0, "Cache-Control": "no-cache", "ETag": '"nc-1"'},
                    orig_body="nc-body",
                    expect=StepExpect(lookup="MISS", action="STORE", body="nc-body"),
                ),
                CacheStep(
                    "s2",
                    T0 + 2,
                    "GET",
                    "https://origin.test/nc",
                    orig_status=304,
                    orig_headers={"Date": http_date(T0 + 2), "Cache-Control": "no-cache", "ETag": '"nc-1"'},
                    expect=StepExpect(lookup="REVALIDATE", action="FRESHEN", status=200, body="nc-body", inm='"nc-1"'),
                ),
            ],
        ),
        # 6. Cache-Control: max-age=0 immediately stale
        CacheScenario(
            "cc_max_age_zero_revalidates",
            "RFC 9111 §5.2.2.1",
            True,
            [
                CacheStep(
                    "s1",
                    T0,
                    "GET",
                    "https://origin.test/z",
                    orig_headers={"Date": d0, "Cache-Control": "max-age=0", "ETag": '"z-1"'},
                    orig_body="zero-body",
                    expect=StepExpect(lookup="MISS", action="STORE"),
                ),
                CacheStep(
                    "s2",
                    T0,
                    "GET",
                    "https://origin.test/z",
                    orig_status=304,
                    orig_headers={"Date": d0, "Cache-Control": "max-age=60", "ETag": '"z-1"'},
                    expect=StepExpect(lookup="REVALIDATE", action="FRESHEN", status=200, body="zero-body", inm='"z-1"'),
                ),
            ],
        ),
        # 7. s-maxage overrides max-age on shared cache
        CacheScenario(
            "cc_s_maxage_shared_precedence",
            "RFC 9111 §5.2.2.10",
            True,
            [
                CacheStep(
                    "s1",
                    T0,
                    "GET",
                    "https://origin.test/smax",
                    orig_headers={"Date": d0, "Cache-Control": "max-age=10, s-maxage=120"},
                    orig_body="smax-body",
                    expect=StepExpect(lookup="MISS", action="STORE"),
                ),
                CacheStep(
                    "s2",
                    T0 + 60,
                    "GET",
                    "https://origin.test/smax",
                    expect=StepExpect(lookup="HIT", status=200, body="smax-body", min_age=60),
                ),
                CacheStep(
                    "s3",
                    T0 + 130,
                    "GET",
                    "https://origin.test/smax",
                    orig_headers={"Date": http_date(T0 + 130), "Cache-Control": "max-age=10"},
                    orig_body="smax-new",
                    expect=StepExpect(lookup="REVALIDATE", action="STORE", body="smax-new"),
                ),
            ],
        ),
        # 8. s-maxage ignored on private cache
        CacheScenario(
            "cc_s_maxage_ignored_private",
            "RFC 9111 §5.2.2.10",
            False,
            [
                CacheStep(
                    "s1",
                    T0,
                    "GET",
                    "https://origin.test/smax-p",
                    orig_headers={"Date": d0, "Cache-Control": "max-age=10, s-maxage=120"},
                    orig_body="priv-v1",
                    expect=StepExpect(lookup="MISS", action="STORE"),
                ),
                CacheStep(
                    "s2",
                    T0 + 60,
                    "GET",
                    "https://origin.test/smax-p",
                    orig_headers={"Date": http_date(T0 + 60), "Cache-Control": "max-age=10"},
                    orig_body="priv-v2",
                    expect=StepExpect(lookup="REVALIDATE", action="STORE", body="priv-v2"),
                ),
            ],
        ),
        # 9. must-revalidate prohibits max-stale serving
        CacheScenario(
            "cc_must_revalidate_blocks_max_stale",
            "RFC 9111 §5.2.2.2",
            True,
            [
                CacheStep(
                    "s1",
                    T0,
                    "GET",
                    "https://origin.test/mr",
                    orig_headers={"Date": d0, "Cache-Control": "max-age=10, must-revalidate", "ETag": '"mr1"'},
                    orig_body="mr-v1",
                    expect=StepExpect(lookup="MISS", action="STORE"),
                ),
                CacheStep(
                    "s2",
                    T0 + 30,
                    "GET",
                    "https://origin.test/mr",
                    req_headers={"Cache-Control": "max-stale=120"},
                    orig_status=304,
                    orig_headers={"Date": http_date(T0 + 30), "Cache-Control": "max-age=60"},
                    expect=StepExpect(lookup="REVALIDATE", action="FRESHEN", status=200, body="mr-v1", inm='"mr1"'),
                ),
            ],
        ),
        # 10. immutable directive (RFC 8246)
        CacheScenario(
            "cc_immutable_freshness",
            "RFC 8246 §2",
            True,
            [
                CacheStep(
                    "s1",
                    T0,
                    "GET",
                    "https://origin.test/static/app.abc123.js",
                    orig_headers={"Date": d0, "Cache-Control": "public, immutable"},
                    orig_body="console.log(1);",
                    expect=StepExpect(lookup="MISS", action="STORE"),
                ),
                CacheStep(
                    "s2",
                    T0 + 3600,
                    "GET",
                    "https://origin.test/static/app.abc123.js",
                    expect=StepExpect(lookup="HIT", status=200, body="console.log(1);", min_age=3600),
                ),
            ],
        ),
        # 11. Age header subtracts from max-age freshness lifetime
        CacheScenario(
            "freshness_age_header_deduction",
            "RFC 9111 §4.2.3",
            True,
            [
                CacheStep(
                    "s1",
                    T0,
                    "GET",
                    "https://origin.test/aged",
                    orig_headers={"Date": d0, "Cache-Control": "max-age=60", "Age": "50"},
                    orig_body="aged-v1",
                    expect=StepExpect(lookup="MISS", action="STORE"),
                ),
                CacheStep(
                    "s2",
                    T0 + 5,
                    "GET",
                    "https://origin.test/aged",
                    expect=StepExpect(lookup="HIT", status=200, body="aged-v1", min_age=55),
                ),
                CacheStep(
                    "s3",
                    T0 + 15,
                    "GET",
                    "https://origin.test/aged",
                    orig_headers={"Date": http_date(T0 + 15), "Cache-Control": "max-age=60"},
                    orig_body="aged-v2",
                    expect=StepExpect(lookup="REVALIDATE", action="STORE", body="aged-v2"),
                ),
            ],
        ),
        # 12. Expires header freshness calculation (future fresh, past stale)
        CacheScenario(
            "freshness_expires_future_and_past",
            "RFC 9111 §4.2.1",
            True,
            [
                CacheStep(
                    "s1",
                    T0,
                    "GET",
                    "https://origin.test/exp-ok",
                    orig_headers={"Date": d0, "Expires": exp_plus_120},
                    orig_body="exp-body",
                    expect=StepExpect(lookup="MISS", action="STORE"),
                ),
                CacheStep(
                    "s2",
                    T0 + 60,
                    "GET",
                    "https://origin.test/exp-ok",
                    expect=StepExpect(lookup="HIT", status=200, body="exp-body", min_age=60),
                ),
                CacheStep(
                    "s3",
                    T0 + 150,
                    "GET",
                    "https://origin.test/exp-ok",
                    orig_headers={"Date": http_date(T0 + 150), "Expires": exp_past},
                    orig_body="exp-stale",
                    expect=StepExpect(lookup="REVALIDATE", action="STORE", body="exp-stale"),
                ),
                CacheStep(
                    "s4",
                    T0 + 151,
                    "GET",
                    "https://origin.test/exp-ok",
                    orig_headers={"Date": http_date(T0 + 151), "Cache-Control": "max-age=60"},
                    orig_body="exp-refreshed",
                    expect=StepExpect(lookup="REVALIDATE", action="STORE", body="exp-refreshed"),
                ),
            ],
        ),
        # 13. max-age takes precedence over past Expires
        CacheScenario(
            "freshness_max_age_overrides_expires",
            "RFC 9111 §4.2.1",
            True,
            [
                CacheStep(
                    "s1",
                    T0,
                    "GET",
                    "https://origin.test/prec",
                    orig_headers={"Date": d0, "Cache-Control": "max-age=120", "Expires": exp_past},
                    orig_body="prec-v1",
                    expect=StepExpect(lookup="MISS", action="STORE"),
                ),
                CacheStep(
                    "s2",
                    T0 + 60,
                    "GET",
                    "https://origin.test/prec",
                    expect=StepExpect(lookup="HIT", status=200, body="prec-v1", min_age=60),
                ),
            ],
        ),
        # 14. Last-Modified 10% heuristic freshness
        CacheScenario(
            "freshness_heuristic_last_modified",
            "RFC 9111 §4.2.2",
            True,
            [
                CacheStep(
                    "s1",
                    T0,
                    "GET",
                    "https://origin.test/heur",
                    orig_headers={"Date": d0, "Last-Modified": lm_1000},
                    orig_body="heur-v1",
                    expect=StepExpect(lookup="MISS", action="STORE"),
                ),
                CacheStep(
                    "s2",
                    T0 + 50,
                    "GET",
                    "https://origin.test/heur",
                    expect=StepExpect(lookup="HIT", status=200, body="heur-v1", min_age=50),
                ),
                CacheStep(
                    "s3",
                    T0 + 120,
                    "GET",
                    "https://origin.test/heur",
                    orig_headers={"Date": http_date(T0 + 120), "Last-Modified": lm_1000},
                    orig_body="heur-v2",
                    expect=StepExpect(lookup="REVALIDATE", action="STORE", body="heur-v2", ims=lm_1000),
                ),
            ],
        ),
        # 15. Vary: Accept-Encoding match, mismatch, and absence
        CacheScenario(
            "vary_accept_encoding",
            "RFC 9111 §4.1",
            True,
            [
                CacheStep(
                    "s1",
                    T0,
                    "GET",
                    "https://origin.test/var",
                    req_headers={"Accept-Encoding": "gzip"},
                    orig_headers={"Date": d0, "Cache-Control": "max-age=300", "Vary": "Accept-Encoding"},
                    orig_body="gzip-payload",
                    expect=StepExpect(lookup="MISS", action="STORE", body="gzip-payload"),
                ),
                CacheStep(
                    "s2",
                    T0 + 5,
                    "GET",
                    "https://origin.test/var",
                    req_headers={"Accept-Encoding": "gzip"},
                    expect=StepExpect(lookup="HIT", status=200, body="gzip-payload"),
                ),
                CacheStep(
                    "s3",
                    T0 + 6,
                    "GET",
                    "https://origin.test/var",
                    req_headers={"Accept-Encoding": "br"},
                    orig_headers={"Date": d0, "Cache-Control": "max-age=300", "Vary": "Accept-Encoding"},
                    orig_body="br-payload",
                    expect=StepExpect(lookup="MISS", action="STORE", body="br-payload"),
                ),
                CacheStep(
                    "s4",
                    T0 + 7,
                    "GET",
                    "https://origin.test/var",
                    orig_headers={"Date": d0, "Cache-Control": "max-age=300", "Vary": "Accept-Encoding"},
                    orig_body="plain-payload",
                    expect=StepExpect(lookup="MISS", action="STORE", body="plain-payload"),
                ),
            ],
        ),
        # 16. Vary: * never reused from cache
        CacheScenario(
            "vary_star_never_reused",
            "RFC 9111 §4.1",
            True,
            [
                CacheStep(
                    "s1",
                    T0,
                    "GET",
                    "https://origin.test/vstar",
                    req_headers={"Accept-Encoding": "gzip"},
                    orig_headers={"Date": d0, "Cache-Control": "max-age=300", "Vary": "*"},
                    orig_body="vstar-1",
                    expect=StepExpect(lookup="MISS", body="vstar-1"),
                ),
                CacheStep(
                    "s2",
                    T0 + 2,
                    "GET",
                    "https://origin.test/vstar",
                    req_headers={"Accept-Encoding": "gzip"},
                    orig_headers={"Date": d0, "Cache-Control": "max-age=300", "Vary": "*"},
                    orig_body="vstar-2",
                    expect=StepExpect(lookup="MISS", body="vstar-2"),
                ),
            ],
        ),
        # 17. ETag + If-None-Match -> 304 header freshening & Content-Type protection
        CacheScenario(
            "revalidate_etag_304_merge",
            "RFC 9111 §3.2 / §4.3",
            True,
            [
                CacheStep(
                    "s1",
                    T0,
                    "GET",
                    "https://origin.test/doc",
                    orig_headers={
                        "Date": d0,
                        "Cache-Control": "max-age=10",
                        "ETag": '"doc-v1"',
                        "Content-Type": "text/plain",
                        "X-Tag": "old-tag",
                    },
                    orig_body="IMMUTABLE_BODY",
                    expect=StepExpect(lookup="MISS", action="STORE", body="IMMUTABLE_BODY"),
                ),
                CacheStep(
                    "s2",
                    T0 + 20,
                    "GET",
                    "https://origin.test/doc",
                    orig_status=304,
                    orig_headers={
                        "Date": http_date(T0 + 20),
                        "Cache-Control": "max-age=300",
                        "ETag": '"doc-v1"',
                        "Content-Type": "text/html",
                        "X-Tag": "freshened-tag",
                    },
                    expect=StepExpect(
                        lookup="REVALIDATE",
                        action="FRESHEN",
                        status=200,
                        body="IMMUTABLE_BODY",
                        content_type="text/plain",
                        x_tag="freshened-tag",
                        inm='"doc-v1"',
                    ),
                ),
                CacheStep(
                    "s3",
                    T0 + 50,
                    "GET",
                    "https://origin.test/doc",
                    expect=StepExpect(
                        lookup="HIT",
                        status=200,
                        body="IMMUTABLE_BODY",
                        content_type="text/plain",
                        x_tag="freshened-tag",
                        min_age=30,
                    ),
                ),
            ],
        ),
        # 18. Last-Modified + If-Modified-Since -> 304 revalidation
        CacheScenario(
            "revalidate_last_modified_304",
            "RFC 9111 §4.3",
            True,
            [
                CacheStep(
                    "s1",
                    T0,
                    "GET",
                    "https://origin.test/lm",
                    orig_headers={
                        "Date": d0,
                        "Cache-Control": "max-age=10",
                        "Last-Modified": lm_1000,
                        "X-Tag": "lm-v1",
                    },
                    orig_body="LM_BODY",
                    expect=StepExpect(lookup="MISS", action="STORE"),
                ),
                CacheStep(
                    "s2",
                    T0 + 20,
                    "GET",
                    "https://origin.test/lm",
                    orig_status=304,
                    orig_headers={
                        "Date": http_date(T0 + 20),
                        "Cache-Control": "max-age=120",
                        "X-Tag": "lm-freshened",
                    },
                    expect=StepExpect(
                        lookup="REVALIDATE",
                        action="FRESHEN",
                        status=200,
                        body="LM_BODY",
                        x_tag="lm-freshened",
                        ims=lm_1000,
                    ),
                ),
                CacheStep(
                    "s3",
                    T0 + 40,
                    "GET",
                    "https://origin.test/lm",
                    expect=StepExpect(lookup="HIT", status=200, body="LM_BODY", x_tag="lm-freshened"),
                ),
            ],
        ),
        # 19. Unsafe POST / PUT / DELETE target URI invalidation
        CacheScenario(
            "unsafe_post_put_delete_invalidation",
            "RFC 9111 §4.4",
            True,
            [
                CacheStep(
                    "s1",
                    T0,
                    "GET",
                    "https://origin.test/item/1",
                    orig_headers={"Date": d0, "Cache-Control": "max-age=300"},
                    orig_body="v1",
                    expect=StepExpect(lookup="MISS", action="STORE"),
                ),
                CacheStep(
                    "s2",
                    T0 + 1,
                    "POST",
                    "https://origin.test/item/1",
                    orig_status=200,
                    orig_body="updated",
                    expect=StepExpect(lookup="MISS", action="PASS"),
                ),
                CacheStep(
                    "s3",
                    T0 + 2,
                    "GET",
                    "https://origin.test/item/1",
                    orig_headers={"Date": d0, "Cache-Control": "max-age=300"},
                    orig_body="v2",
                    expect=StepExpect(lookup="MISS", action="STORE", body="v2"),
                ),
                CacheStep(
                    "s4",
                    T0 + 3,
                    "PUT",
                    "https://origin.test/item/1",
                    orig_status=204,
                    expect=StepExpect(lookup="MISS", action="PASS"),
                ),
                CacheStep(
                    "s5",
                    T0 + 4,
                    "GET",
                    "https://origin.test/item/1",
                    orig_headers={"Date": d0, "Cache-Control": "max-age=300"},
                    orig_body="v3",
                    expect=StepExpect(lookup="MISS", action="STORE", body="v3"),
                ),
                CacheStep(
                    "s6",
                    T0 + 5,
                    "DELETE",
                    "https://origin.test/item/1",
                    orig_status=200,
                    orig_body="deleted",
                    expect=StepExpect(lookup="MISS", action="PASS"),
                ),
                CacheStep(
                    "s7",
                    T0 + 6,
                    "GET",
                    "https://origin.test/item/1",
                    orig_headers={"Date": d0, "Cache-Control": "max-age=300"},
                    orig_body="v4",
                    expect=StepExpect(lookup="MISS", action="STORE", body="v4"),
                ),
            ],
        ),
        # 20. Same-origin Location & Content-Location invalidation + cross-origin isolation
        CacheScenario(
            "unsafe_location_content_location_invalidation",
            "RFC 9111 §4.4",
            True,
            [
                CacheStep(
                    "s1",
                    T0,
                    "GET",
                    "https://origin.test/items",
                    orig_headers={"Date": d0, "Cache-Control": "max-age=300"},
                    orig_body="list-v1",
                    expect=StepExpect(lookup="MISS", action="STORE"),
                ),
                CacheStep(
                    "s2",
                    T0,
                    "GET",
                    "https://origin.test/items/42",
                    orig_headers={"Date": d0, "Cache-Control": "max-age=300"},
                    orig_body="item42-v1",
                    expect=StepExpect(lookup="MISS", action="STORE"),
                ),
                CacheStep(
                    "s3",
                    T0,
                    "GET",
                    "https://other.test/items/42",
                    orig_headers={"Date": d0, "Cache-Control": "max-age=300"},
                    orig_body="other-v1",
                    expect=StepExpect(lookup="MISS", action="STORE"),
                ),
                CacheStep(
                    "s4",
                    T0 + 2,
                    "POST",
                    "https://origin.test/items/create",
                    orig_status=201,
                    orig_headers={
                        "Location": "/items/42",
                        "Content-Location": "/items",
                    },
                    orig_body="created",
                    expect=StepExpect(lookup="MISS", action="PASS"),
                ),
                CacheStep(
                    "s5",
                    T0 + 3,
                    "POST",
                    "https://origin.test/items/cross",
                    orig_status=200,
                    orig_headers={"Location": "https://other.test/items/42"},
                    orig_body="cross",
                    expect=StepExpect(lookup="MISS", action="PASS"),
                ),
                CacheStep(
                    "s6",
                    T0 + 4,
                    "GET",
                    "https://origin.test/items",
                    orig_headers={"Date": d0, "Cache-Control": "max-age=300"},
                    orig_body="list-v2",
                    expect=StepExpect(lookup="MISS", action="STORE", body="list-v2"),
                ),
                CacheStep(
                    "s7",
                    T0 + 4,
                    "GET",
                    "https://origin.test/items/42",
                    orig_headers={"Date": d0, "Cache-Control": "max-age=300"},
                    orig_body="item42-v2",
                    expect=StepExpect(lookup="MISS", action="STORE", body="item42-v2"),
                ),
                CacheStep(
                    "s8",
                    T0 + 4,
                    "GET",
                    "https://other.test/items/42",
                    expect=StepExpect(lookup="HIT", status=200, body="other-v1"),
                ),
            ],
        ),
        # 21. Unsafe 4xx/5xx MUST NOT invalidate
        CacheScenario(
            "unsafe_error_status_preserves_cache",
            "RFC 9111 §4.4",
            True,
            [
                CacheStep(
                    "s1",
                    T0,
                    "GET",
                    "https://origin.test/keep",
                    orig_headers={"Date": d0, "Cache-Control": "max-age=300"},
                    orig_body="keep-v1",
                    expect=StepExpect(lookup="MISS", action="STORE"),
                ),
                CacheStep(
                    "s2",
                    T0 + 1,
                    "POST",
                    "https://origin.test/keep",
                    orig_status=500,
                    orig_body="err",
                    expect=StepExpect(lookup="MISS", action="PASS"),
                ),
                CacheStep(
                    "s3",
                    T0 + 2,
                    "GET",
                    "https://origin.test/keep",
                    expect=StepExpect(lookup="HIT", status=200, body="keep-v1"),
                ),
            ],
        ),
        # 22. RFC 5861 stale-while-revalidate
        CacheScenario(
            "rfc5861_stale_while_revalidate",
            "RFC 5861 §3",
            True,
            [
                CacheStep(
                    "s1",
                    T0,
                    "GET",
                    "https://origin.test/swr",
                    orig_headers={"Date": d0, "Cache-Control": "max-age=10, stale-while-revalidate=30"},
                    orig_body="swr-v1",
                    expect=StepExpect(lookup="MISS", action="STORE"),
                ),
                CacheStep(
                    "s2",
                    T0 + 5,
                    "GET",
                    "https://origin.test/swr",
                    expect=StepExpect(lookup="HIT", swr_bg=0, status=200, body="swr-v1"),
                ),
                CacheStep(
                    "s3",
                    T0 + 20,
                    "GET",
                    "https://origin.test/swr",
                    expect=StepExpect(lookup="HIT", swr_bg=1, status=200, body="swr-v1"),
                ),
                CacheStep(
                    "s4",
                    T0 + 50,
                    "GET",
                    "https://origin.test/swr",
                    orig_headers={"Date": http_date(T0 + 50), "Cache-Control": "max-age=10"},
                    orig_body="swr-v2",
                    expect=StepExpect(lookup="REVALIDATE", action="STORE", body="swr-v2"),
                ),
            ],
        ),
        # 23. RFC 5861 stale-if-error on 503 origin outage
        CacheScenario(
            "rfc5861_stale_if_error",
            "RFC 5861 §4",
            True,
            [
                CacheStep(
                    "s1",
                    T0,
                    "GET",
                    "https://origin.test/sie",
                    orig_headers={
                        "Date": d0,
                        "Cache-Control": "max-age=10, stale-if-error=60",
                        "ETag": '"sie-1"',
                    },
                    orig_body="sie-cached-good",
                    expect=StepExpect(lookup="MISS", action="STORE"),
                ),
                CacheStep(
                    "s2",
                    T0 + 25,
                    "GET",
                    "https://origin.test/sie",
                    orig_status=503,
                    orig_body="origin-down",
                    expect=StepExpect(lookup="REVALIDATE", status=200, body="sie-cached-good", inm='"sie-1"'),
                ),
            ],
        ),
        # 24. RFC 9875 Cache-Groups & Cache-Group-Invalidation (same-origin targeted purge)
        CacheScenario(
            "rfc9875_cache_groups_targeted_eviction",
            "RFC 9875 §2 / §3",
            True,
            [
                CacheStep(
                    "s1",
                    T0,
                    "GET",
                    "https://origin.test/p/1",
                    orig_headers={
                        "Date": d0,
                        "Cache-Control": "max-age=300",
                        "Cache-Groups": '"catalog", "featured"',
                    },
                    orig_body="p1-v1",
                    expect=StepExpect(lookup="MISS", action="STORE"),
                ),
                CacheStep(
                    "s2",
                    T0,
                    "GET",
                    "https://origin.test/p/2",
                    orig_headers={
                        "Date": d0,
                        "Cache-Control": "max-age=300",
                        "Cache-Groups": '"catalog"',
                    },
                    orig_body="p2-v1",
                    expect=StepExpect(lookup="MISS", action="STORE"),
                ),
                CacheStep(
                    "s3",
                    T0,
                    "GET",
                    "https://origin.test/p/3",
                    orig_headers={
                        "Date": d0,
                        "Cache-Control": "max-age=300",
                        "Cache-Groups": '"blog"',
                    },
                    orig_body="p3-v1",
                    expect=StepExpect(lookup="MISS", action="STORE"),
                ),
                CacheStep(
                    "s4",
                    T0,
                    "GET",
                    "https://other.test/p/4",
                    orig_headers={
                        "Date": d0,
                        "Cache-Control": "max-age=300",
                        "Cache-Groups": '"catalog"',
                    },
                    orig_body="other-p4-v1",
                    expect=StepExpect(lookup="MISS", action="STORE"),
                ),
                CacheStep(
                    "s5",
                    T0 + 5,
                    "POST",
                    "https://origin.test/admin/purge",
                    orig_status=200,
                    orig_headers={"Cache-Group-Invalidation": '"catalog"'},
                    orig_body="ok",
                    expect=StepExpect(lookup="MISS", action="PASS"),
                ),
                CacheStep(
                    "s6",
                    T0 + 6,
                    "GET",
                    "https://origin.test/p/1",
                    orig_headers={"Date": d0, "Cache-Control": "max-age=300"},
                    orig_body="p1-v2",
                    expect=StepExpect(lookup="MISS", action="STORE", body="p1-v2"),
                ),
                CacheStep(
                    "s7",
                    T0 + 6,
                    "GET",
                    "https://origin.test/p/2",
                    orig_headers={"Date": d0, "Cache-Control": "max-age=300"},
                    orig_body="p2-v2",
                    expect=StepExpect(lookup="MISS", action="STORE", body="p2-v2"),
                ),
                CacheStep(
                    "s8",
                    T0 + 6,
                    "GET",
                    "https://origin.test/p/3",
                    expect=StepExpect(lookup="HIT", status=200, body="p3-v1"),
                ),
                CacheStep(
                    "s9",
                    T0 + 6,
                    "GET",
                    "https://other.test/p/4",
                    expect=StepExpect(lookup="HIT", status=200, body="other-p4-v1"),
                ),
            ],
        ),
        # 25. RFC 9875 Cache-Groups case-sensitive comparison
        CacheScenario(
            "rfc9875_cache_group_case_sensitive",
            "RFC 9875 §2.1",
            True,
            [
                CacheStep(
                    "s1",
                    T0,
                    "GET",
                    "https://origin.test/case/1",
                    orig_headers={
                        "Date": d0,
                        "Cache-Control": "max-age=300",
                        "Cache-Groups": '"catalog"',
                    },
                    orig_body="lower-v1",
                    expect=StepExpect(lookup="MISS", action="STORE"),
                ),
                CacheStep(
                    "s2",
                    T0 + 2,
                    "POST",
                    "https://origin.test/admin/purge",
                    orig_status=200,
                    orig_headers={"Cache-Group-Invalidation": '"Catalog"'},
                    orig_body="ok",
                    expect=StepExpect(lookup="MISS", action="PASS"),
                ),
                CacheStep(
                    "s3",
                    T0 + 3,
                    "GET",
                    "https://origin.test/case/1",
                    expect=StepExpect(lookup="HIT", status=200, body="lower-v1"),
                ),
            ],
        ),
    ]


def build_live_origin_scenarios(base_url: str) -> list[CacheScenario]:
    """4 live HTTP/1.1 wire origin scenarios executed over TCP sockets."""
    return [
        CacheScenario(
            "live_etag_304_roundtrip",
            "RFC 9111 Live HTTP/1.1",
            True,
            [
                CacheStep(
                    "l1",
                    T0,
                    "GET",
                    f"{base_url}/live/etag",
                    expect=StepExpect(
                        lookup="MISS",
                        action="STORE",
                        status=200,
                        body="LIVE_ETAG_BODY",
                        x_tag="origin-fresh",
                    ),
                ),
                CacheStep(
                    "l2",
                    T0 + 5,
                    "GET",
                    f"{base_url}/live/etag",
                    expect=StepExpect(lookup="HIT", status=200, body="LIVE_ETAG_BODY", min_age=5),
                ),
                CacheStep(
                    "l3",
                    T0 + 20,
                    "GET",
                    f"{base_url}/live/etag",
                    expect=StepExpect(
                        lookup="REVALIDATE",
                        action="FRESHEN",
                        status=200,
                        body="LIVE_ETAG_BODY",
                        content_type="text/plain",
                        x_tag="revalidated-304",
                        inm='"live-v1"',
                    ),
                ),
                CacheStep(
                    "l4",
                    T0 + 30,
                    "GET",
                    f"{base_url}/live/etag",
                    expect=StepExpect(
                        lookup="HIT",
                        status=200,
                        body="LIVE_ETAG_BODY",
                        x_tag="revalidated-304",
                    ),
                ),
            ],
        ),
        CacheScenario(
            "live_vary_accept_encoding",
            "RFC 9111 Live HTTP/1.1",
            True,
            [
                CacheStep(
                    "v1",
                    T0,
                    "GET",
                    f"{base_url}/live/vary",
                    req_headers={"Accept-Encoding": "gzip"},
                    expect=StepExpect(lookup="MISS", action="STORE", body="ENC:gzip"),
                ),
                CacheStep(
                    "v2",
                    T0 + 3,
                    "GET",
                    f"{base_url}/live/vary",
                    req_headers={"Accept-Encoding": "gzip"},
                    expect=StepExpect(lookup="HIT", body="ENC:gzip"),
                ),
                CacheStep(
                    "v3",
                    T0 + 4,
                    "GET",
                    f"{base_url}/live/vary",
                    req_headers={"Accept-Encoding": "br"},
                    expect=StepExpect(lookup="MISS", action="STORE", body="ENC:br"),
                ),
            ],
        ),
        CacheScenario(
            "live_cache_groups_purge",
            "RFC 9875 Live HTTP/1.1",
            True,
            [
                CacheStep(
                    "g1",
                    T0,
                    "GET",
                    f"{base_url}/live/group-a",
                    expect=StepExpect(lookup="MISS", action="STORE", body="GROUP_A_DATA"),
                ),
                CacheStep(
                    "g2",
                    T0,
                    "GET",
                    f"{base_url}/live/group-b",
                    expect=StepExpect(lookup="MISS", action="STORE", body="GROUP_B_DATA"),
                ),
                CacheStep(
                    "g3",
                    T0 + 2,
                    "POST",
                    f"{base_url}/live/purge-catalog",
                    expect=StepExpect(lookup="MISS", action="PASS", body="PURGED"),
                ),
                CacheStep(
                    "g4",
                    T0 + 3,
                    "GET",
                    f"{base_url}/live/group-a",
                    expect=StepExpect(lookup="MISS", action="STORE", body="GROUP_A_DATA"),
                ),
                CacheStep(
                    "g5",
                    T0 + 3,
                    "GET",
                    f"{base_url}/live/group-b",
                    expect=StepExpect(lookup="HIT", body="GROUP_B_DATA"),
                ),
            ],
        ),
        CacheScenario(
            "live_no_store_not_cached",
            "RFC 9111 Live HTTP/1.1",
            True,
            [
                CacheStep(
                    "n1",
                    T0,
                    "GET",
                    f"{base_url}/live/nostore",
                    expect=StepExpect(lookup="MISS", action="PASS", body="NO_STORE_DATA"),
                ),
                CacheStep(
                    "n2",
                    T0 + 1,
                    "GET",
                    f"{base_url}/live/nostore",
                    expect=StepExpect(lookup="MISS", action="PASS", body="NO_STORE_DATA"),
                ),
            ],
        ),
    ]


def ensure_harness_binary(force_rebuild: bool = False) -> Path:
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    if not force_rebuild and HARNESS_EXE.is_file() and HARNESS_EXE.stat().st_mtime >= HARNESS_SRC.stat().st_mtime:
        return HARNESS_EXE

    print(f"[*] Building cache conformance harness: {HARNESS_SRC.name} -> {HARNESS_EXE.name}...")
    env = os.environ.copy()
    build_flags = ["-O2"]
    if sys.platform == "win32":
        build_flags = ["-O0"]
        if "GOOSE_CC" not in env:
            stack_cc = ROOT_DIR / "tools" / "gcc_stack.bat"
            if stack_cc.is_file():
                env["GOOSE_CC"] = str(stack_cc)
    cmd = ["goose", "build", *build_flags, "-o", str(HARNESS_EXE), str(HARNESS_SRC)]
    res = subprocess.run(
        cmd, check=False, cwd=str(ROOT_DIR), capture_output=True, text=True, env=env
    )
    if res.returncode != 0:
        print("[!] Failed to build cache harness:", file=sys.stderr)
        if res.stdout:
            print(res.stdout, file=sys.stderr)
        if res.stderr:
            print(res.stderr, file=sys.stderr)
        sys.exit(1)
    print(f"[+] Built {HARNESS_EXE.name}")
    return HARNESS_EXE


def serialize_scenarios_tsv(scenarios: list[CacheScenario]) -> str:
    lines: list[str] = []
    for sc in scenarios:
        lines.append(f"CASE\t{sc.name}\t{1 if sc.shared else 0}")
        for st in sc.steps:
            lines.append(
                "\t".join(
                    [
                        "STEP",
                        st.step_id,
                        str(st.now_sec),
                        st.method,
                        st.url,
                        enc_headers(st.req_headers),
                        str(st.orig_status),
                        enc_headers(st.orig_headers),
                        enc_body(st.orig_body),
                    ]
                )
            )
    return "\n".join(lines) + "\n"


def evaluate_scenarios(
    exe: Path, scenarios: list[CacheScenario], origin_addr: str = "-"
) -> tuple[int, int]:
    tsv_text = serialize_scenarios_tsv(scenarios)
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".tsv", encoding="utf-8", delete=False
    ) as tmp:
        tsv_path = Path(tmp.name)
        tmp.write(tsv_text)

    try:
        res = subprocess.run(
            [str(exe), str(tsv_path), origin_addr],
            cwd=str(ROOT_DIR),
            capture_output=True,
            text=True,
            timeout=30.0,
            check=False,
        )
    finally:
        tsv_path.unlink(missing_ok=True)

    if res.returncode != 0:
        raise RuntimeError(f"cache_harness failed (exit {res.returncode}): {res.stderr}\n{res.stdout}")

    results: dict[tuple[str, str], list[str]] = {}
    for line in res.stdout.splitlines():
        cols = line.strip().split("\t")
        if len(cols) >= 14 and cols[0] == "RESULT":
            results[(cols[1], cols[2])] = cols

    passed = 0
    failed = 0
    for sc in scenarios:
        sc_errors: list[str] = []
        for st in sc.steps:
            row = results.get((sc.name, st.step_id))
            if not row:
                sc_errors.append(f"{st.step_id}: missing result")
                continue
            lookup_got = row[3]
            action_got = row[4]
            swr_got = int(row[5])
            status_got = int(row[6])
            body_got = "" if row[7] == "-" else bytes.fromhex(row[7]).decode("utf-8", errors="replace")
            age_got = -1 if row[8] == "-" else int(row[8])
            ct_got = row[9]
            tag_got = row[10]
            inm_got = row[11]
            ims_got = row[12]
            via_got = int(row[13])

            exp = st.expect
            if lookup_got != exp.lookup:
                sc_errors.append(f"{st.step_id}: lookup={lookup_got} want {exp.lookup}")
            if exp.action is not None and action_got != exp.action:
                sc_errors.append(f"{st.step_id}: action={action_got} want {exp.action}")
            if exp.swr_bg is not None and swr_got != exp.swr_bg:
                sc_errors.append(f"{st.step_id}: swr_bg={swr_got} want {exp.swr_bg}")
            if exp.status is not None and status_got != exp.status:
                sc_errors.append(f"{st.step_id}: status={status_got} want {exp.status}")
            if exp.body is not None and body_got != exp.body:
                sc_errors.append(f"{st.step_id}: body={body_got!r} want {exp.body!r}")
            if exp.min_age is not None and age_got < exp.min_age:
                sc_errors.append(f"{st.step_id}: age={age_got} < {exp.min_age}")
            if exp.content_type is not None and ct_got != exp.content_type:
                sc_errors.append(f"{st.step_id}: content-type={ct_got!r} want {exp.content_type!r}")
            if exp.x_tag is not None and tag_got != exp.x_tag:
                sc_errors.append(f"{st.step_id}: x-tag={tag_got!r} want {exp.x_tag!r}")
            if exp.inm is not None and inm_got != exp.inm:
                sc_errors.append(f"{st.step_id}: If-None-Match={inm_got!r} want {exp.inm!r}")
            if exp.ims is not None and ims_got != exp.ims:
                sc_errors.append(f"{st.step_id}: If-Modified-Since={ims_got!r} want {exp.ims!r}")
            if exp.require_via and via_got != 1:
                sc_errors.append(f"{st.step_id}: proxy Via/hop-by-hop hygiene failed")

        if not sc_errors:
            passed += 1
            print(f"  [PASS] [{sc.rfc:22s}] {sc.name} ({len(sc.steps)} steps)")
        else:
            failed += 1
            print(f"  [FAIL] [{sc.rfc:22s}] {sc.name}: {'; '.join(sc_errors)}")

    return passed, failed


def run_suite(rebuild: bool = False, origin_addr: str = "") -> int:
    exe = ensure_harness_binary(force_rebuild=rebuild)

    print("\nExecuting RFC 9111 / RFC 5861 / RFC 9875 HTTP Cache Conformance Suite...")
    off_pass, off_fail = evaluate_scenarios(exe, build_offline_scenarios(), origin_addr="-")

    live_pass = 0
    live_fail = 0
    if origin_addr:
        print(f"\nExecuting Live HTTP/1.1 Origin Cache Scenarios against {origin_addr}...")
        live_pass, live_fail = evaluate_scenarios(
            exe, build_live_origin_scenarios(f"http://{origin_addr}"), origin_addr=origin_addr
        )
    else:
        srv = create_origin_server("127.0.0.1", 0)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            addr = f"127.0.0.1:{port}"
            print(f"\nExecuting Live HTTP/1.1 Loopback Origin Cache Scenarios ({addr})...")
            live_pass, live_fail = evaluate_scenarios(
                exe, build_live_origin_scenarios(f"http://{addr}"), origin_addr=addr
            )
        finally:
            srv.shutdown()
            srv.server_close()

    total_pass = off_pass + live_pass
    total_fail = off_fail + live_fail
    total = total_pass + total_fail
    print(
        f"\nCompleted: {total_pass}/{total} passed "
        f"({off_pass}/{off_pass + off_fail} virtual-clock, "
        f"{live_pass}/{live_pass + live_fail} live HTTP/1.1 origin), {total_fail} failed."
    )
    return 0 if total_fail == 0 and total > 0 else 1


def main() -> None:
    parser = argparse.ArgumentParser(
        description="RFC 9111 / RFC 5861 / RFC 9875 HTTP Cache Conformance Suite for goose-wing"
    )
    parser.add_argument("--local", action="store_true", help="Run local suite with loopback origin")
    parser.add_argument("--docker", action="store_true", help="Run suite via docker compose")
    parser.add_argument("--origin", default="", help="External live HTTP/1.1 origin host:port")
    parser.add_argument("--rebuild", action="store_true", help="Force rebuild cache harness")
    args = parser.parse_args()

    if args.docker:
        compose_file = TOOLS_DIR / "cache_conformance" / "docker-compose.yml"
        cmd = [
            "docker",
            "compose",
            "-f",
            str(compose_file),
            "up",
            "--build",
            "--abort-on-container-exit",
            "--exit-code-from",
            "cache-runner",
        ]
        print(f"[*] Running cache conformance suite via docker compose ({compose_file.name})...")
        sys.exit(subprocess.run(cmd, check=False, cwd=str(ROOT_DIR)).returncode)

    sys.exit(run_suite(rebuild=args.rebuild, origin_addr=args.origin))


if __name__ == "__main__":
    main()
