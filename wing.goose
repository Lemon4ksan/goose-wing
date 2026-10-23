// Networking and HTTP application-layer stack for Goose.
// Provides URL parsing, cookie management, HTTP framing and headers,
// client sessions with redirect and SSRF handling, and server primitives.
namespace wing;

import std;
import json;

// ---- core primitives -------------------------------------------------------

import core.time;
import core.test;
import core.url;
import core.sync;
import core.compress;

// ---- cookie engine ---------------------------------------------------------

import cookie.constants;
import cookie.canonical;
import cookie.psl;
import cookie.parser;
import cookie.policy;
import cookie.engine;
import cookie.store;

// ---- client session and application layer ----------------------------------

import app.profile;
import app.request;
import app.response;
import app.redirect;
import app.session;
import app.policy;

// ---- http primitives -------------------------------------------------------

import http.headers;
import http.mime;
import http.multipart;
import http.h2_framer;

// ---- http cache engine (rfc 9111) ------------------------------------------

import http.cache.cache_control;
import http.cache.freshness;
import http.cache.validators;
import http.cache.engine;

// ---- security --------------------------------------------------------------

import security.ct;
import security.crypto_jar;
import security.csrf;
import security.cors;
import security.rate_limiter;

// ---- server primitives -----------------------------------------------------

import server.router;
import server.pool;
import server.pipeline;

// ---- resilient networking & transport (rfc 8305, socks5, pool, retry) ------

import net.pool;
import net.happy_eyeballs;
import net.proxy;
import net.retry;

// ---- ufcs method bridges ---------------------------------------------------

import app.ufcs;
