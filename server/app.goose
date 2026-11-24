// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Typed route enum registration and transport-free `Reply<T>` dispatchers over `RadixRouter`.
namespace server;

import std;
import core;
import rfc.http;
import wire.pipeline;
import http.request;
import http.response;
import http.bind;
import http.problem;
import http.secret;
import client.contract;
import .router;
import .pipeline;
import .server;
import .reply;

// Keeps user route enum IDs strictly below RadixRouter static sentinel ranges (`1001..1003`, `2048+`).
const MAX_USER_ROUTE_ID: i32 = 999;

// Maps a user route enum value to a deterministic 1-based `RadixRouter` handler ID (`1..=999`).
// Skips any `"Unknown"` sentinel variant and returns `-1` when unmappable or past `MAX_USER_ROUTE_ID`.
fn route_enum_id<E>(route: E) -> i32 {
    var idx: i64 = 1;
    const for <Name, V> in variants<E> {
        if Name != "Unknown" {
            let candidate: E = default<V>();
            if route == candidate {
                return if idx <= (MAX_USER_ROUTE_ID as i64) { idx as i32 } else { -1 };
            }
            idx = core::add_sat_i64(idx, 1);
        }
    }
    return -1;
}

// Reconstructs a user route enum variant from a 1-based `ServerStageCtx.handler_id`.
// Returns `default<E>()` when `id` is out of `1..=MAX_USER_ROUTE_ID` or matches no variant.
fn route_from_id<E>(id: i32) -> E {
    guard id >= 1 && id <= MAX_USER_ROUTE_ID else { return default<E>(); }
    let target = id as i64;
    var idx: i64 = 1;
    const for <Name, V> in variants<E> {
        if Name != "Unknown" {
            if target == idx {
                return default<V>();
            }
            idx = core::add_sat_i64(idx, 1);
        }
    }
    return default<E>();
}

fn route_get<E>(srv: HttpServer&, path: const u8[:], route: E) -> bool {
    let id = route_enum_id(route);
    guard id >= 1 else { return false; }
    return add_route(srv.pipeline.router, "GET", path, id);
}

fn route_post<E>(srv: HttpServer&, path: const u8[:], route: E) -> bool {
    let id = route_enum_id(route);
    guard id >= 1 else { return false; }
    return add_route(srv.pipeline.router, "POST", path, id);
}

fn route_put<E>(srv: HttpServer&, path: const u8[:], route: E) -> bool {
    let id = route_enum_id(route);
    guard id >= 1 else { return false; }
    return add_route(srv.pipeline.router, "PUT", path, id);
}

fn route_patch<E>(srv: HttpServer&, path: const u8[:], route: E) -> bool {
    let id = route_enum_id(route);
    guard id >= 1 else { return false; }
    return add_route(srv.pipeline.router, "PATCH", path, id);
}

fn route_delete<E>(srv: HttpServer&, path: const u8[:], route: E) -> bool {
    let id = route_enum_id(route);
    guard id >= 1 else { return false; }
    return add_route(srv.pipeline.router, "DELETE", path, id);
}

fn route_contract<S, E>(srv: HttpServer&, spec: const S&, route: E) -> bool {
    let id = route_enum_id(route);
    guard id >= 1 else { return false; }
    return add_route(srv.pipeline.router, spec.method[..], spec.path_template[..], id);
}

fn route_group<E>(
    router:   RadixRouter&,
    group:    const RouteGroup&,
    method:   const u8[:],
    sub_path: const u8[:],
    route:    E,
) -> bool {
    let id = route_enum_id(route);
    guard id >= 1 else { return false; }
    return add_group_route(router, group, method, sub_path, id);
}

fn finish_reply_verdict(res: const http::Response&) -> wire::StageVerdict {
    let code: i32 = if res.status_code >= 100 && res.status_code <= 599 {
        res.status_code
    } else {
        500
    };
    return wire::StageVerdict.ShortCircuit { status_code: code as u16 };
}

// Executes a zero-input domain block returning `Reply<Res>` and writes it to `res`.
fn dispatch_empty<Res, F: fn() -> Reply<Res>>(res: http::Response&) -> wire::StageVerdict {
    let rep = F();
    write_reply(res, rep);
    return finish_reply_verdict(res);
}

fn ingest_stage_dto<Dto>(
    cfg:     const ServerPipelineConfig&,
    sctx:    const ServerStageCtx&,
    req:     const http::Request&,
    dto_val: Dto&,
    vp:      http::ValidationProblem&,
) -> bool {
    if sctx.ext_slot_idx >= 0 && sctx.ext_slot_idx < cfg.ext_pool.slots.len {
        let slot .= cfg.ext_pool.slots[sctx.ext_slot_idx];
        return http::ingest_dto(req, slot.params, slot.canon_url[..], slot.peer_ip[..], dto_val, vp);
    }
    let empty_params = http::ZeroAllocParams { .. };
    return http::ingest_dto(req, empty_params, req.url[..], "", dto_val, vp);
}

// Ingests `Dto` from `cfg.ext_pool` (`canon_url`, `params`, `peer_ip`) or `req` fallback, runs `F(dto)`,
// wipes any `core::Secret` fields on return, and writes either `ValidationProblem` or `Reply<Res>`.
fn dispatch_dto<Dto, Res, F: fn(const Dto&) -> Reply<Res>>(
    cfg:         const ServerPipelineConfig&,
    sctx:        const ServerStageCtx&,
    req:         const http::Request&,
    res:         http::Response&,
    detail_mode: http::ValidationDetailMode = http::ValidationDetailMode.Detailed,
) -> wire::StageVerdict {
    var dto_val = default<Dto>();
    defer http::zeroize_struct_secrets(dto_val);
    var vp = http::ValidationProblem { .. };
    guard ingest_stage_dto(cfg, sctx, req, dto_val, vp) else {
        http::write_validation_problem_response(res, vp, detail_mode);
        return finish_reply_verdict(res);
    }
    let rep = F(dto_val);
    write_reply(res, rep);
    return finish_reply_verdict(res);
}

// Enforces pre-extracted `auth_ok` / `auth_err` before ingesting `Dto` and invoking `F(auth, dto)`.
fn dispatch_with_auth<Auth, Dto, Res, F: fn(const Auth&, const Dto&) -> Reply<Res>>(
    cfg:         const ServerPipelineConfig&,
    sctx:        const ServerStageCtx&,
    req:         const http::Request&,
    res:         http::Response&,
    auth:        const Auth&,
    auth_ok:     bool,
    auth_err:    const DomainError&,
    detail_mode: http::ValidationDetailMode = http::ValidationDetailMode.Detailed,
) -> wire::StageVerdict {
    guard auth_ok else {
        let err_rep = fail<EmptyBody>(auth_err);
        write_reply(res, err_rep);
        return finish_reply_verdict(res);
    }
    var dto_val = default<Dto>();
    defer http::zeroize_struct_secrets(dto_val);
    var vp = http::ValidationProblem { .. };
    guard ingest_stage_dto(cfg, sctx, req, dto_val, vp) else {
        http::write_validation_problem_response(res, vp, detail_mode);
        return finish_reply_verdict(res);
    }
    let rep = F(auth, dto_val);
    write_reply(res, rep);
    return finish_reply_verdict(res);
}

fn raw_query_from_url(url: const u8[:]) -> const u8[:] {
    let _, raw_q, has_q = url.split_once_byte('?');
    return if has_q { raw_q } else { "" };
}

fn write_bind_bad_request(
    res:         http::Response&,
    vp:          http::ValidationProblem&,
    detail_mode: http::ValidationDetailMode,
) -> wire::StageVerdict {
    vp.problem.status = rfc::STATUS_BAD_REQUEST;
    if vp.problem.title.len == 0 {
        let _ = vp.problem.title.try_set("bad_request");
    }
    http::write_validation_problem_response(res, vp, detail_mode);
    return finish_reply_verdict(res);
}

// Executes a contract endpoint with no request inputs (`F(out)`), writing `out` or error to `res`.
fn handle_empty<P, Q, B, ResBody, F: fn(ResBody&) -> Reply<EmptyBody>>(
    _spec: const client::EndpointSpec<P, Q, B, ResBody>&,
    res:   http::Response&,
) -> wire::StageVerdict {
    var out = ResBody { .. };
    let rep = F(&out);
    write_out_reply(res, rep, out);
    return finish_reply_verdict(res);
}

// Binds JSON `ReqBody` from `req` per `spec`, wipes secrets on exit, and writes `out` or `400`.
fn handle_json<P, Q, ReqBody, ResBody, F: fn(const ReqBody&, ResBody&) -> Reply<EmptyBody>>(
    _spec:       const client::EndpointSpec<P, Q, ReqBody, ResBody>&,
    req:         const http::Request&,
    res:         http::Response&,
    detail_mode: http::ValidationDetailMode = http::ValidationDetailMode.Detailed,
) -> wire::StageVerdict {
    var body = ReqBody { .. };
    defer http::zeroize_struct_secrets(body);
    var vp = http::ValidationProblem { .. };
    guard http::bind_json(req.body[..], body, vp) else {
        return write_bind_bad_request(res, vp, detail_mode);
    }
    var out = ResBody { .. };
    let rep = F(body, &out);
    write_out_reply(res, rep, out);
    return finish_reply_verdict(res);
}

// Binds URL query `Query` from `req` per `spec`, wipes secrets on exit, and writes `out` or `400`.
fn handle_query<P, Query, B, ResBody, F: fn(const Query&, ResBody&) -> Reply<EmptyBody>>(
    _spec:       const client::EndpointSpec<P, Query, B, ResBody>&,
    req:         const http::Request&,
    res:         http::Response&,
    detail_mode: http::ValidationDetailMode = http::ValidationDetailMode.Detailed,
) -> wire::StageVerdict {
    let raw_q = raw_query_from_url(req.url[..]);
    var q = Query { .. };
    defer http::zeroize_struct_secrets(q);
    var vp = http::ValidationProblem { .. };
    guard http::bind_query(raw_q, q, vp) else {
        return write_bind_bad_request(res, vp, detail_mode);
    }
    var out = ResBody { .. };
    let rep = F(q, &out);
    write_out_reply(res, rep, out);
    return finish_reply_verdict(res);
}
