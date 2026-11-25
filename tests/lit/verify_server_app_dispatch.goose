// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
import std;
import wing from "../..";

enum ApiRoute {
    Unknown,
    Health,
    CreateItem,
    PatchItem,
    DeleteItem,
    GetUser,
    SecretNote,
    GroupPing,
    ContractNote,
    ContractSearch,
}

struct SearchQueryDto {
    q: u8[..16] = [],
}

struct SearchItemsRes {
    items: UserRes[>..] = [],
}

struct StrictItemBody {
    name:  dto::NonEmpty<u8[..32]> = dto::NonEmpty<u8[..32]> { .. },
    count: dto::Positive<i64>      = dto::Positive<i64> { .. },
    pin:   core::Secret<u8[..16]>  = core::Secret<u8[..16]> { .. },
}

fn http::validate(d: const StrictItemBody&) -> bool {
    return d.name.val[..] != "banned" && d.pin.val.len >= 3;
}

fn http::validate_code(d: const StrictItemBody&) -> const u8[:] {
    return if d.name.val[..] == "banned" { "banned_name" } else { "" };
}

struct PingApiTag {}
struct SearchApiTag {}
struct CreateApiTag {}

fn server::serve(_t: PingApiTag, st: const AppStage&, out: HealthRes&) -> server::Reply<server::EmptyBody> {
    let _ = out.status.try_set(st.service_tag[..]);
    return server::ok_reply();
}

fn server::serve(_t: SearchApiTag, _st: const AppStage&, q: const SearchQueryDto&, out: SearchItemsRes&) -> server::Reply<server::EmptyBody> {
    var item = UserRes { id: 5, .. };
    let _ = item.tag.try_set(q.q[..]);
    out.items.push(item);
    return server::ok_reply();
}

fn server::serve(_t: CreateApiTag, _st: const AppStage&, b: const StrictItemBody&, out: UserRes&) -> server::Reply<server::EmptyBody> {
    out.id = b.count.val;
    let _ = out.tag.try_set(b.name.val[..]);
    return server::created(server::EmptyBody {});
}

struct DemoApi {
    ping:   server::EmptyRoute<HealthRes, PingApiTag>,
    search: server::QueryRoute<SearchQueryDto, SearchItemsRes, SearchApiTag>,
    create: server::JsonRoute<StrictItemBody, UserRes, CreateApiTag>,
}

struct HealthRes {
    status: u8[..16] = "ok",
}

struct UserPathDto {
    id:  dto::Path<i64>                  = dto::Path<i64> { .. },
    tag: dto::Query<core::Opt<u8[..16]>> = dto::Query<core::Opt<u8[..16]>> { .. },
}

struct UserRes {
    id:  i64      = 0,
    tag: u8[..16] = [],
}

fn http::json_encode(v: const UserRes&, out: u8[>..]&) {
    http::encode_json_struct(v, out);
}

struct EmptyInDto {}

struct NoteBodyDto {
    title: u8[..32]               = [],
    token: core::Secret<u8[..64]> = core::Secret<u8[..64]> { .. },
}

struct Principal {
    user_id: i64 = 0,
}

struct AppStage {
    service_tag: u8[..16] = "app",
}

fn verify_req_principal(req: const http::Request&) -> Principal, server::DomainError, bool {
    let raw = http::header(req, "X-User-Id");
    let uid, ok = raw.parse_i64_dec();
    if !ok || uid <= 0 {
        return Principal { .. }, server::err_unauthorized("missing X-User-Id"), false;
    }
    return Principal { user_id: uid }, server::DomainError { .. }, true;
}

fn health_domain() -> server::Reply<HealthRes> {
    return server::ok(HealthRes { .. });
}

fn get_user_domain(d: const UserPathDto&) -> server::Reply<UserRes> {
    let t = if d.tag.val.present { d.tag.val.value[..] } else { "none" };
    var out = UserRes { id: d.id.val, .. };
    let _ = out.tag.try_set(t);
    return server::ok(out);
}

fn secret_note_domain(auth: const Principal&, d: const NoteBodyDto&) -> server::Reply<UserRes> {
    let _ = d.title;
    return server::created(UserRes { id: auth.user_id, tag: "saved" });
}

const EP_HEALTH_SPEC = client::EndpointSpec<client::EmptyPart, client::EmptyPart, client::EmptyPart, HealthRes> {
    method:        "GET",
    path_template: "/contract/health",
};
const EP_NOTE_SPEC = client::EndpointSpec<client::EmptyPart, client::EmptyPart, NoteBodyDto, UserRes> {
    method:        "POST",
    path_template: "/contract/notes",
};
const EP_SEARCH_SPEC = client::EndpointSpec<client::EmptyPart, SearchQueryDto, client::EmptyPart, SearchItemsRes> {
    method:        "GET",
    path_template: "/contract/search",
};
const EP_STRICT_SPEC = client::EndpointSpec<client::EmptyPart, client::EmptyPart, StrictItemBody, UserRes> {
    method:        "POST",
    path_template: "/api/items",
};
const EP_API_PING_SPEC = client::EndpointSpec<client::EmptyPart, client::EmptyPart, client::EmptyPart, HealthRes> {
    method:        "GET",
    path_template: "/api/ping",
};
const EP_API_SEARCH_SPEC = client::EndpointSpec<client::EmptyPart, SearchQueryDto, client::EmptyPart, SearchItemsRes> {
    method:        "GET",
    path_template: "/api/search",
};

fn make_demo_api() -> DemoApi {
    return DemoApi {
        ping:   server::empty_route(EP_API_PING_SPEC, PingApiTag {}),
        search: server::query_route(EP_API_SEARCH_SPEC, SearchApiTag {}),
        create: server::json_route(EP_STRICT_SPEC, CreateApiTag {}),
    };
}

fn server::on_server_stage(
    stage: AppStage&,
    phase: wire::ServerHookPhase,
    cfg:   server::ServerPipelineConfig&,
    req:   const http::Request&,
    sctx:  server::ServerStageCtx&,
    res:   http::Response&,
) -> wire::StageVerdict {
    guard phase == wire::ServerHookPhase.RouteHandler else {
        return wire::StageVerdict.Continue;
    }
    let demo_api = make_demo_api();
    let api_verdict, matched = server::dispatch_api(demo_api, stage, req, sctx, res, 500);
    if matched {
        return api_verdict;
    }
    match server::route_from_id<ApiRoute>(sctx.handler_id) {
        Health => {
            return server::dispatch_empty<HealthRes>(res) { health_domain() };
        },
        GetUser => {
            return server::dispatch_dto<UserPathDto, UserRes>(cfg, sctx, req, res) { d =>
                get_user_domain(d)
            };
        },
        SecretNote => {
            let p, a_err, a_ok = verify_req_principal(req);
            return server::dispatch_with_auth<Principal, NoteBodyDto, UserRes>(
                cfg, sctx, req, res, p, a_ok, a_err,
            ) { auth, d =>
                secret_note_domain(auth, d)
            };
        },
        PatchItem => {
            return server::dispatch_empty<HealthRes>(res) {
                server::ok(HealthRes { status: "patched" })
            };
        },
        GroupPing => {
            return server::dispatch_empty<HealthRes>(res) {
                server::ok(HealthRes { status: "pong" })
            };
        },
        ContractNote => {
            return server::handle_json(EP_NOTE_SPEC, req, res) { b, out =>
                let _ = out.tag.try_set(b.title[..]);
                out.id = 77;
                server::ok_reply()
            };
        },
        ContractSearch => {
            return server::handle_query(EP_SEARCH_SPEC, req, res) { q, out =>
                var item = UserRes { id: 1, .. };
                let _ = item.tag.try_set(q.q[..]);
                out.items.push(item);
                server::ok_reply()
            };
        },
        _ => {
            return wire::StageVerdict.Continue;
        },
    };
}

fn main() {
    // 1. Route enum sentinel checks (`Unknown` rejected, `0` and `>= 1000` rejected in `route_from_id`).
    let unk_id = server::route_enum_id(ApiRoute.Unknown);
    let h_id = server::route_enum_id(ApiRoute.Health);
    let out_of_range = server::route_from_id<ApiRoute>(1000);
    let zero_route = server::route_from_id<ApiRoute>(0);
    // CHECK: ids=-1 1 true true
    print(
        "ids=", unk_id,
        " ", h_id,
        " ", out_of_range == ApiRoute.Unknown,
        " ", zero_route == ApiRoute.Unknown, "\n",
    );

    var srv = server::new_http_server("127.0.0.1", 8080);
    srv.pipeline.enable_cors = false;
    srv.pipeline.enable_csrf_guard = false;
    srv.pipeline.enable_rate_limiter = false;

    let get_spec = client::EndpointSpec<EmptyInDto, EmptyInDto, EmptyInDto, HealthRes> {
        method:        "GET",
        path_template: "/contract/health",
    };
    let ok1 = server::route_get(srv, "/health", ApiRoute.Health);
    let ok2 = server::route_post(srv, "/items", ApiRoute.CreateItem);
    let ok3 = server::route_put(srv, "/items/:id", ApiRoute.CreateItem);
    let ok4 = server::route_patch(srv, "/items/:id", ApiRoute.PatchItem);
    let ok5 = server::route_delete(srv, "/items/:id", ApiRoute.DeleteItem);
    let ok6 = server::route_get(srv, "/users/:id", ApiRoute.GetUser);
    let ok7 = server::route_post(srv, "/notes", ApiRoute.SecretNote);
    let ok8 = server::route_contract(srv, EP_HEALTH_SPEC, ApiRoute.Health);
    let _ = server::route_contract(srv, EP_NOTE_SPEC, ApiRoute.ContractNote);
    let _ = server::route_contract(srv, EP_SEARCH_SPEC, ApiRoute.ContractSearch);
    let demo_api = make_demo_api();
    let demo_next, demo_ok = server::mount_api(srv, demo_api, 500);
    let demo_cid = server::api_route_id(demo_api, "create", 500);
    let _ = demo_next;
    let _ = demo_ok;
    let _ = demo_cid;
    let grp, grp_ok = server::make_route_group("/v1");
    let ok9 = grp_ok && server::route_group(srv.pipeline.router, grp, "GET", "/ping", ApiRoute.GroupPing);
    let bad_reg = server::route_get(srv, "/nope", ApiRoute.Unknown);
    // CHECK: reg=true true true true true true true true true false
    print(
        "reg=", ok1, " ", ok2, " ", ok3, " ", ok4, " ", ok5,
        " ", ok6, " ", ok7, " ", ok8, " ", ok9, " ", bad_reg, "\n",
    );

    var stage = AppStage { .. };
    var wire_out: u8[>..] = [];

    // 2. GET /health via dispatch_empty
    let _o1, h1_ok = server::handle_connection_wire(
        srv, "127.0.0.1", "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n", 1000, wire_out, stage,
    );
    // CHECK: wire1_ok=true has_ok=true
    print("wire1_ok=", h1_ok, " has_ok=", core::contains(wire_out[..], "\"status\":\"ok\""), "\n");

    // 3. GET //users//42?tag=vip -> canonicalized path param + dispatch_dto
    let _o2, h2_ok = server::handle_connection_wire(
        srv, "127.0.0.1", "GET //users//42?tag=vip HTTP/1.1\r\nHost: localhost\r\n\r\n", 2000, wire_out, stage,
    );
    // CHECK: wire2_ok=true has_u=true
    print("wire2_ok=", h2_ok, " has_u=", core::contains(wire_out[..], "\"id\":42,\"tag\":\"vip\""), "\n");

    // 4. PATCH /items/7 and GET /v1/ping
    let _o3, h3_ok = server::handle_connection_wire(
        srv, "127.0.0.1", "PATCH /items/7 HTTP/1.1\r\nHost: localhost\r\n\r\n", 3000, wire_out, stage,
    );
    let patch_ok = h3_ok && core::contains(wire_out[..], "\"status\":\"patched\"");
    let _o4, h4_ok = server::handle_connection_wire(
        srv, "127.0.0.1", "GET /v1/ping HTTP/1.1\r\nHost: localhost\r\n\r\n", 4000, wire_out, stage,
    );
    let ping_ok = h4_ok && core::contains(wire_out[..], "\"status\":\"pong\"");
    // CHECK: patch_ping=true true
    print("patch_ping=", patch_ok, " ", ping_ok, "\n");

    // 5. dispatch_with_auth: missing auth -> 401; valid auth -> 201
    let _o5, _ = server::handle_connection_wire(
        srv,
        "127.0.0.1",
        "POST /notes HTTP/1.1\r\nHost: localhost\r\nContent-Length: 27\r\n\r\n{\"title\":\"t\",\"token\":\"sec\"}",
        5000,
        wire_out,
        stage,
    );
    // CHECK: auth401=true
    print("auth401=", core::contains(wire_out[..], "401 Unauthorized"), "\n");

    let _o6, _ = server::handle_connection_wire(
        srv,
        "127.0.0.1",
        "POST /notes HTTP/1.1\r\nHost: localhost\r\nX-User-Id: 9\r\nContent-Length: 27\r\n\r\n{\"title\":\"t\",\"token\":\"sec\"}",
        6000,
        wire_out,
        stage,
    );
    // CHECK: auth201=true
    print("auth201=", core::contains(wire_out[..], "\"id\":9,\"tag\":\"saved\""), "\n");

    // 6. Contract-driven handle_empty, handle_json, handle_query (including resizable array ResBody)
    var h_res = http::Response { .. };
    let h_v = server::handle_empty(EP_HEALTH_SPEC, h_res) { out =>
        let _ = out.status.try_set("ready");
        server::ok_reply()
    };
    let _ = h_v;
    let _o7, _ = server::handle_connection_wire(
        srv,
        "127.0.0.1",
        "POST /contract/notes HTTP/1.1\r\nHost: localhost\r\nContent-Length: 29\r\n\r\n{\"title\":\"abc\",\"token\":\"sec\"}",
        7000,
        wire_out,
        stage,
    );
    let c_note_ok = core::contains(wire_out[..], "\"id\":77,\"tag\":\"abc\"");
    let _o8, _ = server::handle_connection_wire(
        srv,
        "127.0.0.1",
        "GET /contract/search?q=hi HTTP/1.1\r\nHost: localhost\r\n\r\n",
        8000,
        wire_out,
        stage,
    );
    let c_q_ok = core::contains(wire_out[..], "\"tag\":\"hi\"");
    // CHECK: contract_srv=true true true
    print("contract_srv=", core::contains(h_res.body[..], "\"ready\""), " ", c_note_ok, " ", c_q_ok, "\n");

    // 7. Compile-time const for API table (`mount_api`/`dispatch_api`) + dto::NonEmpty/Positive + fn validate
    let _a1, _ = server::handle_connection_wire(
        srv, "127.0.0.1", "GET /api/ping HTTP/1.1\r\nHost: localhost\r\n\r\n", 9000, wire_out, stage,
    );
    let api_ping_ok = demo_ok && demo_next == 503 && demo_cid == 502 &&
        core::contains(wire_out[..], "\"status\":\"app\"");

    let _a2, _ = server::handle_connection_wire(
        srv, "127.0.0.1", "GET /api/search?q=go HTTP/1.1\r\nHost: localhost\r\n\r\n", 9100, wire_out, stage,
    );
    let api_search_ok = core::contains(wire_out[..], "\"id\":5,\"tag\":\"go\"");

    let _a3, _ = server::handle_connection_wire(
        srv,
        "127.0.0.1",
        "POST /api/items HTTP/1.1\r\nHost: localhost\r\nContent-Length: 37\r\n\r\n{\"name\":\"pen\",\"count\":3,\"pin\":\"1234\"}",
        9200,
        wire_out,
        stage,
    );
    let api_create_ok = core::contains(wire_out[..], "201 Created") &&
        core::contains(wire_out[..], "\"id\":3,\"tag\":\"pen\"");

    // Empty name, non-positive count, or custom validate() rejection -> 400
    let _b1, _ = server::handle_connection_wire(
        srv,
        "127.0.0.1",
        "POST /api/items HTTP/1.1\r\nHost: localhost\r\nContent-Length: 34\r\n\r\n{\"name\":\"\",\"count\":3,\"pin\":\"1234\"}",
        9300,
        wire_out,
        stage,
    );
    let rej_empty = core::contains(wire_out[..], "400 Bad Request");

    let _b2, _ = server::handle_connection_wire(
        srv,
        "127.0.0.1",
        "POST /api/items HTTP/1.1\r\nHost: localhost\r\nContent-Length: 37\r\n\r\n{\"name\":\"pen\",\"count\":0,\"pin\":\"1234\"}",
        9400,
        wire_out,
        stage,
    );
    let rej_zero = core::contains(wire_out[..], "400 Bad Request");

    let _b3, _ = server::handle_connection_wire(
        srv,
        "127.0.0.1",
        "POST /api/items HTTP/1.1\r\nHost: localhost\r\nContent-Length: 40\r\n\r\n{\"name\":\"banned\",\"count\":3,\"pin\":\"1234\"}",
        9500,
        wire_out,
        stage,
    );
    let rej_val = core::contains(wire_out[..], "400 Bad Request") &&
        core::contains(wire_out[..], "\"title\":\"banned_name\"");
    let owns_ok = server::api_route_count<DemoApi>() == 3 &&
        server::api_owns_id<DemoApi>(500, 500) &&
        server::api_owns_id<DemoApi>(502, 500) &&
        !server::api_owns_id<DemoApi>(503, 500);

    let _b4, _ = server::handle_connection_wire(
        srv,
        "127.0.0.1",
        "POST /api/items HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}",
        9600,
        wire_out,
        stage,
    );
    let rej_missing = core::contains(wire_out[..], "400 Bad Request");

    // CHECK: const_api=true true true true true true true true
    print(
        "const_api=", api_ping_ok, " ", api_search_ok, " ", api_create_ok,
        " ", rej_empty, " ", rej_zero, " ", rej_val, " ", owns_ok, " ", rej_missing, "\n",
    );
}
