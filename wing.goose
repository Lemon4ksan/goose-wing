// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Networking and HTTP application-layer stack for Goose.
// Provides URL parsing, cookie management, HTTP framing and headers,
// client sessions with redirect and SSRF handling, and server primitives.
namespace wing;

import std;
import json;

// ---- core & rfc subsystems (Layers 0-1) ------------------------------------

import core from ".";
import rfc.http;
import rfc.h2;
import rfc.h3_quic;
import rfc.tls;
import rfc.ws;
import rfc.grpc;

// ---- nanosecond time unit helpers ------------------------------------------

const MICROSECOND: i64 = 1000;
const MILLISECOND: i64 = 1000000;
const SECOND:      i64 = 1000000000;
const MINUTE:      i64 = 60000000000;
const HOUR:        i64 = 3600000000000;

inline fn micros(n: i64) -> i64 { return n * MICROSECOND; }
inline fn millis(n: i64) -> i64 { return n * MILLISECOND; }
inline fn secs(n: i64) -> i64 { return n * SECOND; }
inline fn mins(n: i64) -> i64 { return n * MINUTE; }
inline fn hours(n: i64) -> i64 { return n * HOUR; }

// ---- domain name system & security primitives (Layer 2) --------------------

import dns.svcb;
import dns.wire;
import dns.cache;
import dns.doh;

import security.gcra;
import security.ssrf;
import security.hpke;
import security.crypto_jar;
import security.csrf;
import security.cors;
import security.rate_limiter;
import security.privacypass;
import security.cross_origin_isolation;

// ---- http primitives, models, headers & cache (Layer 3) --------------------

import http.headers;
import http.headers.lexical;
import http.headers.chunked;
import http.headers.chunked_fsm;
import http.headers.perfect_hash;
import http.sfv;
import http.priority;
import http.incremental;
import http.forwarded;
import http.problem;
import http.negotiate;
import http.server_timing;
import http.early_hints;
import http.compression_dict;
import http.trace;
import http.request;
import http.response;
import http.bind;
import http.mime;
import http.multipart;
import http.client_cert;
import http.altsvc;
import http.signatures;
import http.digest_fields;
import http.security_txt;
import http.targeted_cache;
import http.resumable_upload;
import http.status_diagnostics;
import http.hsts;
import http.novarysearch;
import http.bhttp;
import http.ohttp;
import http.cache.cache_control;
import http.cache.freshness;
import http.cache.validators;
import http.cache.engine;
import http.cache.cache_groups;

// ---- cookie engine, http/2 & authentication (Layer 4) ----------------------

import cookie.limits;
import cookie.constants;
import cookie.canonical;
import cookie.dafsa;
import cookie.psl;
import cookie.parser;
import cookie.policy;
import cookie.engine;
import cookie.store;

import http2.framing;
import http2.frames;
import http2.hpack;
import http2.connection;

import auth.digest;
import auth.pkce;
import auth.device_grant;
import auth.introspection;
import auth.dpop;
import auth.jwt;
import auth.jwe;
import auth.jwk;
import auth.jwks;
import auth.acme;

// ---- fingerprinting & resilient l4 networking (Layer 5) --------------------

import fingerprint.ja4;
import fingerprint.p0f;
import fingerprint.akamai;
import fingerprint.profile;

import net.want_queue;
import net.slowloris;
import net.proxy;
import net.socks5;
import net.http_connect;
import net.tcp;
import net.transport;
import net.pool;
import net.upstream_pool;
import net.happy_eyeballs;
import net.proxy_protocol_internal;
import net.proxy_protocol;
import net.retry;
import net.masque;
import net.isolation;
import net.sockopt;
import net.driver;
import net.accel;
import net.poller;
import net.event_loop;
import net.io_host;

// ---- tls 1.3, quic & http/3 (Layers 6-8) -----------------------------------

import tls.record;
import tls.key_schedule;
import tls.asn1;
import tls.sct;
import tls.x509;
import tls.ocsp;
import tls.crl;
import tls.ticket;
import tls.handshake;
import tls.ech;
import tls.post_quantum;
import tls.cert_compression;
import tls.session;
import tls.pem;

import quic.packet;
import quic.frames;
import quic.migration;
import quic.dplpmtud;
import quic.stream;
import quic.flow_control;
import quic.AckFrame;
import quic.bbr;
import quic.connection;

import http3.qpack;
import http3.framing;
import http3.connection;

// ---- wire subsystem (Layer 9) ----------------------------------------------

import wire.types;
import wire.h1;
import wire.h1_exchange;
import wire.hpack;
import wire.h2;
import wire.h3;
import wire.pipeline;
import wire.service;

// ---- realtime & streaming (Layer 10) ---------------------------------------

import realtime.ws_deflate;
import realtime.ws_handshake;
import realtime.websocket;
import realtime.topic_tree;
import realtime.sse;
import realtime.webtransport;

// ---- client session & server engines (Layer 11) ----------------------------

import client.redirect;
import client.session.ssrf;
import client.session.mock;
import client.client;
import client.contract;
import client.session.cookie_bridge;
import client.session.stages;
import client.session.exec;
import client.session.verbs;
import client.policy;
import client.replay_guard;
import client.telemetry;
import client.interceptor;
import client.stream;

import server.router;
import server.pool;
import server.edge_filter;
import server.cache;
import server.pipeline;
import server.h1_codec;
import server.cork;
import server.stream_consumer;
import server.sni;
import server.server;
import server.reactor;
import server.async_reactor;
import server.h2_multiplexer;
import server.soa_timer;
import server.profiler;

// ---- grpc & reverse proxy gateways (Layer 12) ------------------------------

import grpc.constants;
import grpc.framing;
import grpc.status;
import grpc.connect;
import grpc.health;
import grpc.client;
import grpc.server;

import proxy.health_check;
import proxy.load_balancer;
import proxy.reverse_proxy;
