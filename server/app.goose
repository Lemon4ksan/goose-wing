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
    var dto_val = Dto { .. };
    defer http::zeroize_struct_secrets(dto_val);
    var vp = http::ValidationProblem { .. };
    let ok_ing = ingest_stage_dto(cfg, sctx, req, dto_val, vp);
    let ok_val = ok_ing &&
        http::check_field(
            vp, http::check_dto_valid(dto_val), http::ValidationLocation.Body,
            "$", "invalid_payload", "payload validation failed",
        );
    guard ok_val else {
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
    var dto_val = Dto { .. };
    defer http::zeroize_struct_secrets(dto_val);
    var vp = http::ValidationProblem { .. };
    let ok_ing = ingest_stage_dto(cfg, sctx, req, dto_val, vp);
    let ok_val = ok_ing &&
        http::check_field(
            vp, http::check_dto_valid(dto_val), http::ValidationLocation.Body,
            "$", "invalid_payload", "payload validation failed",
        );
    guard ok_val else {
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

// Binds JSON `ReqBody` from `req` per `spec`, validates it, wipes secrets on exit, and writes `out` or `400`.
fn handle_json<P, Q, ReqBody, ResBody, F: fn(const ReqBody&, ResBody&) -> Reply<EmptyBody>>(
    _spec:       const client::EndpointSpec<P, Q, ReqBody, ResBody>&,
    req:         const http::Request&,
    res:         http::Response&,
    detail_mode: http::ValidationDetailMode = http::ValidationDetailMode.Detailed,
) -> wire::StageVerdict {
    var body = ReqBody { .. };
    defer http::zeroize_struct_secrets(body);
    var vp = http::ValidationProblem { .. };
    let ok_bind = http::bind_json(req.body[..], body, vp) &&
        http::check_field(
            vp, http::check_dto_valid(body), http::ValidationLocation.Body,
            "$", "invalid_payload", "payload validation failed",
        );
    guard ok_bind else {
        return write_bind_bad_request(res, vp, detail_mode);
    }
    var out = ResBody { .. };
    let rep = F(body, &out);
    write_out_reply(res, rep, out);
    return finish_reply_verdict(res);
}

// Binds URL query `Query` from `req` per `spec`, validates it, wipes secrets on exit, and writes `out` or `400`.
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
    let ok_bind = http::bind_query(raw_q, q, vp) &&
        http::check_field(
            vp, http::check_dto_valid(q), http::ValidationLocation.Query,
            "$", "invalid_query_param", "query validation failed",
        );
    guard ok_bind else {
        return write_bind_bad_request(res, vp, detail_mode);
    }
    var out = ResBody { .. };
    let rep = F(q, &out);
    write_out_reply(res, rep, out);
    return finish_reply_verdict(res);
}

// ---- Compile-time API route table (const for mount & dispatch) -------------

struct EmptyRoute<ResBody, Tag> {
    method: u8[..16]  = "GET",
    path:   u8[..256] = "/",
    tag:    Tag       = default<Tag>(),
}

struct QueryRoute<Query, ResBody, Tag> {
    method: u8[..16]  = "GET",
    path:   u8[..256] = "/",
    tag:    Tag       = default<Tag>(),
}

struct JsonRoute<ReqBody, ResBody, Tag> {
    method: u8[..16]  = "POST",
    path:   u8[..256] = "/",
    tag:    Tag       = default<Tag>(),
}

fn empty_route<P, Q, B, ResBody, Tag>(
    spec: const client::EndpointSpec<P, Q, B, ResBody>&,
    tag:  Tag,
) -> EmptyRoute<ResBody, Tag> {
    return EmptyRoute<ResBody, Tag> {
        method: spec.method,
        path:   spec.path_template,
        tag:    tag,
    };
}

fn query_route<P, Query, B, ResBody, Tag>(
    spec: const client::EndpointSpec<P, Query, B, ResBody>&,
    tag:  Tag,
) -> QueryRoute<Query, ResBody, Tag> {
    return QueryRoute<Query, ResBody, Tag> {
        method: spec.method,
        path:   spec.path_template,
        tag:    tag,
    };
}

fn json_route<P, Q, ReqBody, ResBody, Tag>(
    spec: const client::EndpointSpec<P, Q, ReqBody, ResBody>&,
    tag:  Tag,
) -> JsonRoute<ReqBody, ResBody, Tag> {
    return JsonRoute<ReqBody, ResBody, Tag> {
        method: spec.method,
        path:   spec.path_template,
        tag:    tag,
    };
}

fn dispatch_api_entry<ResBody, Tag, App>(
    r:            const EmptyRoute<ResBody, Tag>&,
    app:          App&,
    _req:         const http::Request&,
    res:          http::Response&,
    _detail_mode: http::ValidationDetailMode,
) -> wire::StageVerdict {
    var out = ResBody { .. };
    let rep = r.tag.serve(app, &out);
    write_out_reply(res, rep, out);
    return finish_reply_verdict(res);
}

fn dispatch_api_entry<Query, ResBody, Tag, App>(
    r:           const QueryRoute<Query, ResBody, Tag>&,
    app:         App&,
    req:         const http::Request&,
    res:         http::Response&,
    detail_mode: http::ValidationDetailMode,
) -> wire::StageVerdict {
    let raw_q = raw_query_from_url(req.url[..]);
    var q = Query { .. };
    defer http::zeroize_struct_secrets(q);
    var vp = http::ValidationProblem { .. };
    let ok_bind = http::bind_query(raw_q, q, vp) &&
        http::check_field(
            vp, http::check_dto_valid(q), http::ValidationLocation.Query,
            "$", "invalid_query_param", "query validation failed",
        );
    guard ok_bind else {
        return write_bind_bad_request(res, vp, detail_mode);
    }
    var out = ResBody { .. };
    let rep = r.tag.serve(app, q, &out);
    write_out_reply(res, rep, out);
    return finish_reply_verdict(res);
}

fn dispatch_api_entry<ReqBody, ResBody, Tag, App>(
    r:           const JsonRoute<ReqBody, ResBody, Tag>&,
    app:         App&,
    req:         const http::Request&,
    res:         http::Response&,
    detail_mode: http::ValidationDetailMode,
) -> wire::StageVerdict {
    var body = ReqBody { .. };
    defer http::zeroize_struct_secrets(body);
    var vp = http::ValidationProblem { .. };
    let ok_bind = http::bind_json(req.body[..], body, vp) &&
        http::check_field(
            vp, http::check_dto_valid(body), http::ValidationLocation.Body,
            "$", "invalid_payload", "payload validation failed",
        );
    guard ok_bind else {
        return write_bind_bad_request(res, vp, detail_mode);
    }
    var out = ResBody { .. };
    let rep = r.tag.serve(app, body, &out);
    write_out_reply(res, rep, out);
    return finish_reply_verdict(res);
}

// Mounts all route fields in struct `api` onto `srv` sequentially starting at `base_id`.
// Returns the next free route ID and `true` when every route fits inside `1..=MAX_USER_ROUTE_ID`.
fn mount_api<Api>(srv: HttpServer&, api: const Api&, base_id: i32 = 1) -> i32, bool {
    var id: i64 = base_id as i64;
    var all_ok = true;
    const for <Name, Acc> in fields<Api> {
        let _ = Name;
        let ok_range = id >= 1 && id <= (MAX_USER_ROUTE_ID as i64);
        let ok_add = ok_range &&
            add_route(srv.pipeline.router, api.Acc.method[..], api.Acc.path[..], id as i32);
        all_ok = all_ok && ok_add;
        id = core::add_sat_i64(id, 1);
    }
    let next_id: i32 = if id <= (MAX_USER_ROUTE_ID as i64) + 1 { id as i32 } else { -1 };
    return next_id, all_ok;
}

// Returns the sequential handler ID of field `field_name` in struct `api` (or `-1` if absent).
fn api_route_id<Api>(_api: const Api&, field_name: const u8[:], base_id: i32 = 1) -> i32 {
    var id: i64 = base_id as i64;
    const for <Name, Acc> in fields<Api> {
        if Name == field_name {
            return if id >= 1 && id <= (MAX_USER_ROUTE_ID as i64) { id as i32 } else { -1 };
        }
        id = core::add_sat_i64(id, 1);
    }
    return -1;
}

// Dispatches `sctx.handler_id` against struct `api` via `const for`, invoking `tag.serve(app, ..., &out)`.
fn dispatch_api<Api, App>(
    api:         const Api&,
    app:         App&,
    req:         const http::Request&,
    sctx:        const ServerStageCtx&,
    res:         http::Response&,
    base_id:     i32                        = 1,
    detail_mode: http::ValidationDetailMode = http::ValidationDetailMode.Detailed,
) -> wire::StageVerdict, bool {
    let target: i64 = sctx.handler_id as i64;
    var id: i64 = base_id as i64;
    const for <Name, Acc> in fields<Api> {
        let _ = Name;
        if target == id {
            return dispatch_api_entry(api.Acc, app, req, res, detail_mode), true;
        }
        id = core::add_sat_i64(id, 1);
    }
    return wire::StageVerdict.Continue, false;
}
