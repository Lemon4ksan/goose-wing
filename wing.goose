// The goose-wing networking and HTTP application-layer stack for Goose.
//
// Core Subsystems:
//   core/time   - Nanosecond calendar, durations, RFC 3339, HTTP-Date, Stopwatch, Deadline.
//   core/test   - Zero-allocation testing harness, structural diffing, MockClock, FuzzRng.
//   core/url    - WHATWG URL parser, IPv6 RFC 5952 compression, Origin, and Swift-style File URLs.
//   cookie/*    - Clean-room Chromium CookieMonster (RFC 6265bis, CHIPS, PSL, 6-round GC).
//   app/*       - Unified ClientSession, 6-phase pipeline, Redirect FSM, SSRF guard, Profiles.
//
// Standards & Specifications:
//   WHATWG URL Living Standard, WHATWG Fetch Section 4.5 (HTTP-redirect fetch), RFC 9110 (HTTP Semantics).
//   RFC 6265bis (draft-22 Schemeful Same-Site, Lax-by-default), RFC 5952 (IPv6 Canonical Form).
namespace wing;

import std;
import json;

// ---- core primitives (time, test harness, url & path engine) ---------------

import core.time;
import core.test;
import core.url;

// ---- canonical cookie engine (chromium cookiemonster architecture) ---------

import cookie.constants;
import cookie.canonical;
import cookie.psl;
import cookie.parser;
import cookie.policy;
import cookie.engine;
import cookie.store;

// ---- client session, redirect fsm & application layer ----------------------

import app.profile;
import app.request;
import app.response;
import app.redirect;
import app.session;
import app.policy;
import app.ufcs;
