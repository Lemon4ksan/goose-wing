// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Networking and HTTP application-layer stack for Goose.
// Provides URL parsing, cookie management, HTTP framing and headers,
// client sessions with redirect and SSRF handling, and server primitives.
namespace wing;

import std;
import json;

// ---- core & rfc subsystems (Layers 0-1) ------------------------------------

import core;
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
import http.headers.internal;
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
import http.cache.internal;
import http.internal;
import http.ext_internal;
import http.meta_internal;
import http.codec_internal;
import http.sfv_sig_internal;

// Ergonomic facade struct aliases for core HTTP application types.
type Request = http::Request;
type Response = http::Response;
type HeaderMap = http::HeaderMap;
type Error = http::Error;

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

import http2.internal;
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

import net.internal;
import net.want_queue;
import net.slowloris;
import net.proxy;
import net.socks5;
import net.http_connect;
import net.tcp;
import net.udp;
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
import net.io_host_internal;
import net.io_host;
import net.dst_internal;
import net.dst;
import net.goose_io;

// ---- tls 1.3, quic & http/3 (Layers 6-8) -----------------------------------

import tls.internal;
import tls.record;
import tls.record_internal;
import tls.key_schedule;
import tls.asn1;
import tls.types;
import tls.sct;
import tls.ticket_internal;
import tls.ticket;
import tls.pki_internal;
import tls.x509_san;
import tls.x509_chain_internal;
import tls.x509;
import tls.ocsp;
import tls.crl;
import tls.post_quantum;
import tls.cert_compression;
import tls.handshake_internal;
import tls.handshake;
import tls.ech;
import tls.pem;
import tls.session_internal;
import tls.session;
import tls.handshake_io_internal;
import tls.client_handshake;
import tls.server_handshake;
import tls.backend;
import tls.stream;

import quic.internal;
import quic.packet_internal;
import quic.packet;
import quic.frames_internal;
import quic.frames;
import quic.migration;
import quic.dplpmtud;
import quic.stream;
import quic.flow_control;
import quic.AckFrame;
import quic.bbr;
import quic.conn_internal;
import quic.connection;

import http3.internal;
import http3.types;
import http3.framing;
import http3.qpack_codec;
import http3.qpack_internal;
import http3.qpack;
import http3.connection_internal;
import http3.connection;

// ---- wire subsystem (Layer 9) ----------------------------------------------

import wire.types;
import wire.budget;
import wire.h1;
import wire.h1_exchange;
import wire.hpack;
import wire.h2;
import wire.h3;
import wire.pipeline;
import wire.service;

// ---- realtime & streaming (Layer 10) ---------------------------------------

import realtime.internal;
import realtime.ws_deflate;
import realtime.ws_handshake;
import realtime.websocket;
import realtime.topic_tree;
import realtime.sse;
import realtime.webtransport;

// ---- client session & server engines (Layer 11) ----------------------------

import client.internal;
import client.redirect;
import client.session.internal;
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

type Client = client::Client;
type Session = client::Session;
type ClientConfig = client::Config;
type SessionConfig = client::Config;

import server.internal;
import server.router_internal;
import server.router;
import server.pool;
import server.edge_filter;
import server.cache;
import server.pipeline_internal;
import server.pipeline;
import server.h1_codec_internal;
import server.h1_codec;
import server.cork;
import server.stream;
import server.stream_consumer;
import server.sni;
import server.server_internal;
import server.server;
import server.reactor_internal;
import server.reactor;
import server.async_reactor;
import server.h2_multiplexer;
import server.soa_timer;
import server.profiler;

// Top-level server facade struct/enum aliases (preserve UFCS without wrapper functions).
type HttpServer = server::HttpServer;
type RadixRouter = server::RadixRouter;
type ServerPipelineConfig = server::ServerPipelineConfig;
type ServerStageCtx = server::ServerStageCtx;
type PipelineOutcome = server::PipelineOutcome;
type RouteMatchResult = server::RouteMatchResult;
type SoAConnTable = server::SoAConnTable;
type AsyncServerReactor = server::AsyncServerReactor;
type EdgeFilter = server::EdgeFilter;
type EdgeFilterVerdict = server::EdgeFilterVerdict;
type HttpRouteCache = server::HttpRouteCache;
type CacheLookup = server::CacheLookup;
type H3ServerEndpoint = server::H3ServerEndpoint;
type H3L2Config = server::H3L2Config;
type H3L2Backend = server::H3L2Backend;

// ---- grpc & reverse proxy gateways (Layer 12) ------------------------------

import grpc.internal;
import grpc.constants;
import grpc.framing;
import grpc.status;
import grpc.connect;
import grpc.health;
import grpc.client;
import grpc.server_internal;
import grpc.server;

import proxy.internal;
import proxy.health_check;
import proxy.load_balancer;
import proxy.reverse_proxy;
