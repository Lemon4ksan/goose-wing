// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Networking and HTTP application-layer stack for Goose.
// Provides URL parsing, cookie management, HTTP framing and headers,
// client sessions with redirect and SSRF handling, and server primitives.
namespace wing;

import std;
import json;

// ---- core & rfc subsystems -------------------------------------------------

import core from ".";
import rfc.http;
import rfc.h2;
import rfc.h3_quic;
import rfc.tls;
import rfc.ws_grpc;

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
import http.headers.perfect_hash;
import http.sfv;
import http.priority;
import http.incremental;
import http.forwarded;
import http.problem;

// ---- tls 1.3 & x.509 pki -------------------------------------------------

import tls.record;
import tls.key_schedule;
import tls.handshake;
import tls.x509;
import tls.hpke;
import tls.ech;
import tls.post_quantum;
import tls.cert_compression;
import tls.session;

// ---- resilient networking & transport (rfc 8305, socks5, pool, retry) ------

import net.proxy;
import net.tcp;
import net.transport;
import net.pool;
import net.happy_eyeballs;
import net.proxy_protocol_internal;
import net.proxy_protocol;
import net.retry;
import net.dns;
import net.masque;
import net.tick_timer;
import net.isolation;
import net.sockopt;
import net.driver;
import net.poller;

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
import client.session.h1_exchange;
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
import http.client_cert;
import http.altsvc;
import http.compression_dict;
import http.signatures;
import http.digest_fields;
import http.security_txt;
import http.targeted_cache;
import http.resumable_upload;
import http.status_diagnostics;
import http.hsts;
import http.early_hints;
import http.novarysearch;
import http.h2_framer;
import http.bhttp;
import http.ohttp;
import http2.framing;
import http2.frames;
import http2.hpack;
import http2.connection;
import http3.qpack;
import http3.framing;
import http3.connection;
import quic.packet;
import quic.frames;
import quic.migration;
import quic.dplpmtud;
import quic.stream;
import quic.flow_control;
import quic.AckFrame;
import quic.bbr;
import quic.connection;

// ---- http cache engine (rfc 9111) ------------------------------------------

import http.cache.cache_control;
import http.cache.freshness;
import http.cache.validators;
import http.cache.engine;
import http.cache.cache_groups;

// ---- security --------------------------------------------------------------

import security.crypto_jar;
import security.csrf;
import security.cors;
import security.rate_limiter;
import security.privacypass;
import security.cross_origin_isolation;

// ---- authentication (rfc 7616 digest, rfc 7636 pkce, rfc 9449 dpop) ---------

import auth.digest;
import auth.pkce;
import auth.dpop;
import auth.jwt;
import auth.jwks;
import auth.acme;

// ---- server primitives -----------------------------------------------------

import server.router;
import server.pool;
import server.pipeline;
import server.edge_filter;
import server.cache;
import server.server;
import server.h2_multiplexer;
import server.soa_timer;
import server.profiler;

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

// ---- reverse proxy & load balancer -----------------------------------------

import proxy.gcra;
import proxy.health_check;
import proxy.load_balancer;
import proxy.reverse_proxy;

// ---- wire subsystem (vulkan-style explicit networking) --------------------

import wire.result;
import wire.types;
import wire.hpack;
import wire.h2;
import wire.pool;
import wire.cmd;
import wire.pipeline;
import wire.sync;
import wire.submit;
