// Networking and HTTP application-layer stack for Goose.
// Provides URL parsing, cookie management, HTTP framing and headers,
// client sessions with redirect and SSRF handling, and server primitives.
namespace wing;

import std;
import json;

// ---- core subsystem --------------------------------------------------------

import core from ".";

// ---- cookie engine ---------------------------------------------------------

import cookie.limits;
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
import fingerprint.akamai;

// ---- http primitives & headers ---------------------------------------------

import http.headers;
import http.headers.lexical;
import http.headers.chunked;
import http.headers.chunked_fsm;

// ---- client session and application layer ----------------------------------

import client.profile;
import client.request;
import client.response;
import client.redirect;
import client.session.ssrf;
import client.session.mock;
import client.client;
import client.session.cookie_bridge;
import client.session.exec;
import client.session.verbs;
import client.policy;
import client.replay_guard;
import client.telemetry;
import client.interceptor;
import client.stream;

// ---- http protocols & extensions -------------------------------------------

import http.mime;
import http.multipart;
import http.trace;
import http.altsvc;
import http.compression_dict;
import http.signatures;
import http.resumable_upload;
import http.status_diagnostics;
import http.hsts;
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

import security.crypto_jar;
import security.csrf;
import security.cors;
import security.rate_limiter;
import security.privacypass;
import security.cross_origin_isolation;

// ---- authentication (rfc 7616 digest, aws sigv4, rfc 7636 pkce, rfc 9449 dpop) -

import auth.digest;
import auth.sigv4;
import auth.pkce;
import auth.dpop;
import auth.jwt;
import auth.jwks;

// ---- tls 1.3 & x.509 pki -------------------------------------------------

import tls.record;
import tls.key_schedule;
import tls.handshake;
import tls.x509;
import tls.hpke;
import tls.ech;
import tls.post_quantum;

// ---- server primitives -----------------------------------------------------

import server.router;
import server.pool;
import server.pipeline;
import server.cache;
import server.server;
import server.h2_multiplexer;


// ---- resilient networking & transport (rfc 8305, socks5, pool, retry) ------

import net.types;
import net.proxy;
import net.pool;
import net.happy_eyeballs;
import net.proxy_protocol;
import net.retry;
import net.dns;
import net.masque;
import net.tcp;
import net.tick_timer;
import net.isolation;

import net.sockopt;
import net.driver;
import net.poller;

// ---- realtime & streaming (rfc 6455 ws & w3c eventsource sse) --------------

import realtime.websocket;
import realtime.topic_tree;
import realtime.sse;
import realtime.webtransport;

// ---- grpc over http/2 & http/3 & grpc-web ---------------------------------

import grpc.constants;
import grpc.framing;
import grpc.status;
import grpc.client;
import grpc.server;

// ---- ufcs method bridges ---------------------------------------------------

import client.ufcs;
