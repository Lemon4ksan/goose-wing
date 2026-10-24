// Networking and HTTP application-layer stack for Goose.
// Provides URL parsing, cookie management, HTTP framing and headers,
// client sessions with redirect and SSRF handling, and server primitives.
namespace wing;

import std;
import json;

// ---- core subsystem --------------------------------------------------------

import core from ".";

// ---- cookie engine ---------------------------------------------------------

import cookie.constants;
import cookie.canonical;
import cookie.psl;
import cookie.parser;
import cookie.policy;
import cookie.engine;
import cookie.store;

// ---- fingerprinting, persona & ja4 (inspired by aoni) ----------------------

import fingerprint.ja4;
import fingerprint.profile;
import fingerprint.p0f;

// ---- client session and application layer ----------------------------------

import client.profile;
import client.request;
import client.response;
import client.redirect;
import client.client;
import client.policy;

// ---- http primitives -------------------------------------------------------

import http.headers;
import http.mime;
import http.multipart;
import http.h2_framer;
import http2.framing;
import http2.hpack;
import http2.connection;
import http3.qpack;
import quic.packet;
import quic.AckFrame;
import quic.bbr;

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

import client.ufcs;
