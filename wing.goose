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
import client.replay_guard;
import client.telemetry;
import client.interceptor;

// ---- http primitives -------------------------------------------------------

import http.headers;
import http.mime;
import http.multipart;
import http.trace;
import http.altsvc;
import http.compression_dict;
import http.early_hints;
import http.novarysearch;
import http.h2_framer;
import http2.framing;
import http2.hpack;
import http2.connection;
import http3.qpack;
import http3.framing;
import http3.connection;
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
import security.md5;
import security.x25519;
import security.crypto_jar;
import security.csrf;
import security.cors;
import security.rate_limiter;

// ---- authentication (rfc 7616 digest & aws sigv4) -------------------------

import auth.digest;
import auth.sigv4;

// ---- tls 1.3 & x.509 pki -------------------------------------------------

import tls.record;
import tls.key_schedule;
import tls.handshake;
import tls.x509;
import tls.hpke;
import tls.ech;

// ---- server primitives -----------------------------------------------------

import server.router;
import server.pool;
import server.pipeline;
import server.server;

// ---- resilient networking & transport (rfc 8305, socks5, pool, retry) ------

import net.pool;
import net.happy_eyeballs;
import net.proxy;
import net.retry;
import net.dns;
import net.masque;
import net.isolation;

// ---- realtime & streaming (rfc 6455 ws & w3c eventsource sse) --------------

import realtime.websocket;
import realtime.sse;

// ---- grpc over http/2 & http/3 & grpc-web ---------------------------------

import grpc.constants;
import grpc.framing;
import grpc.status;
import grpc.client;

// ---- ufcs method bridges ---------------------------------------------------

import client.ufcs;
