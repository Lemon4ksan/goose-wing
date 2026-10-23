// The goose-wing networking and HTTP application-layer stack for Goose.
//
// Core Subsystems:
//   core/time   - Nanosecond calendar, durations, RFC 3339, HTTP-Date, Stopwatch, Deadline.
//   core/test   - Zero-allocation testing harness, structural diffing, MockClock, FuzzRng.
//   core/url    - WHATWG URL parser, IPv6 RFC 5952 compression, Origin, and Swift-style File URLs.
//   cookie/*    - Clean-room Chromium CookieMonster (RFC 6265bis, CHIPS, PSL, 6-round GC).
//   app/*       - Unified ClientSession, 6-phase pipeline, Redirect FSM, SSRF guard, Profiles.
//   security/*  - W3C Fetch Metadata, Constant-Time CryptoJar, GCRA rate limiter & DDoS shield.
//   server/*    - Zero-allocation Radix trie router, Tako v2 pool, and defense-in-depth pipeline.
//
// Standards & Specifications:
//   WHATWG URL Living Standard, WHATWG Fetch Section 4.5 (HTTP-redirect fetch), RFC 9110 (HTTP Semantics).
//   RFC 6265bis (draft-22 Schemeful Same-Site, Lax-by-default), RFC 5952 (IPv6 Canonical Form).
//   W3C Fetch Metadata Request Headers, Go 1.25 net/http.CrossOriginProtection, NIST SP 800-38D, RFC 8439.
namespace wing;

import std;
import json;

// ---- core primitives (time, test harness, url & path engine) ---------------

import core.time;
import core.test;
import core.url;
import core.sync;

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

// ---- high-performance zero-heap http subsystems ----------------------------

import http.headers;
import http.mime;
import http.multipart;
import http.h2_framer;

// ---- application security & cryptographic container ------------------------

import security.ct;
import security.crypto_jar;
import security.csrf;
import security.cors;
import security.rate_limiter;

// ---- zero-allocation server routing & state pooling ------------------------

import server.router;
import server.pool;
import server.pipeline;

// ---- universal ufcs method bridges -----------------------------------------

import app.ufcs;
