// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
import std;
import json;
import wing from "../..";

struct DemoQueryDto {
    page:   i64      = 1,
    limit:  u32      = 20,
    offset: u64      = 0,
    delta:  i32      = 0,
    active: bool     = false,
    tag:    u8[..16] = [],
}

struct DemoHeaderDto {
    x_request_id: u8[..32] = [],
    x_retry_max:  i32      = 0,
}

struct DemoParamDto {
    org_id:  u64      = 0,
    user_id: i64      = 0,
    slug:    u8[..16] = [],
}

struct DemoCookieDto {
    sid:   u8[..32] = [],
    debug: bool     = false,
}

struct DemoJsonDto {
    id:    i64      = 0,
    count: u64      = 0,
    code:  i32      = 0,
    score: f64      = 0.0,
    admin: bool     = false,
    name:  u8[..16] = [],
}

struct BoundedReplyDto {
    token: u8[..8] = [],
}

struct GrowableReplyDto {
    token: u8[>..] = [],
}

struct ContractPathParams {
    org_id:  u64      = 0,
    user_id: i64      = 0,
    tier:    u32      = 0,
    rev:     i32      = 0,
    preview: bool     = false,
    slug:    u8[..32] = [],
}

struct ContractQueryDto {
    limit:   u32      = 10,
    verbose: bool     = false,
    filter:  u8[..16] = [],
}

struct ContractReqBody {
    title: u8[..32] = [],
    count: i64      = 0,
}

struct ContractResBody {
    id:     i64      = 0,
    status: u8[..16] = [],
}

enum DemoRole {
    Guest,
    Admin,
}

fn http::json_encode(v: DemoRole, out: u8[>..]&) {
    json::format_string(out, if v == DemoRole.Admin { "admin" } else { "guest" });
}

fn http::json_decode(dst: DemoRole&, r: json::Reader&) {
    var tok: u8[..16] = [];
    guard core::read_json_string_into(r, tok) else {
        if r.error.len == 0 { json::fail(r, "bad role"); }
        return;
    }
    if tok[..] == "admin" { dst = DemoRole.Admin; }
    else if tok[..] == "guest" { dst = DemoRole.Guest; }
    else { json::fail(r, "unknown role"); }
}

fn http::query_parse(dst: DemoRole&, raw: const u8[:]) -> bool {
    if raw == "admin" { dst = DemoRole.Admin; return true; }
    if raw == "guest" { dst = DemoRole.Guest; return true; }
    return false;
}

fn http::query_format<B>(v: DemoRole, out: B&) -> bool {
    return out.try_append(if v == DemoRole.Admin { "admin" } else { "guest" });
}

struct NestedTag {
    slot:  u8      = 0,
    delta: i8      = 0,
    label: u8[..8] = [],
}

fn http::json_encode(v: const NestedTag&, out: u8[>..]&) { http::encode_json_struct(v, out); }
fn http::json_decode(dst: NestedTag&, r: json::Reader&) { http::decode_json_struct(dst, r); }
fn http::json_decode(dst: NestedTag[..4]&, r: json::Reader&) {
    http::decode_bounded_array<NestedTag[..4], NestedTag>(dst, r);
}

struct RichPayloadDto {
    role:    DemoRole            = DemoRole.Guest,
    sem:     core::Opt<u8>       = core::Opt<u8> { .. },
    note:    core::Opt<u8[..16]> = core::Opt<u8[..16]> { .. },
    fixed:   NestedTag[..4]      = [],
    entries: NestedTag[>..]      = [],
}

struct OptQueryDto {
    role: DemoRole            = DemoRole.Guest,
    sem:  core::Opt<u8>       = core::Opt<u8> { .. },
    kind: core::Opt<u8[..16]> = core::Opt<u8[..16]> { .. },
}

fn test_validation_problem() {
    var vp = http::ValidationProblem { .. };
    print("vp_init_valid: ", http::is_valid_problem(vp));
    print(
        "loc_names: ",
        http::location_wire_name(http::ValidationLocation.Query), ",",
        http::location_wire_name(http::ValidationLocation.Header), ",",
        http::location_wire_name(http::ValidationLocation.PathParam), ",",
        http::location_wire_name(http::ValidationLocation.Cookie), ",",
        http::location_wire_name(http::ValidationLocation.Body), ",",
        http::location_wire_name(http::ValidationLocation.Response), ",",
        http::location_wire_name(http::ValidationLocation.Unknown),
    );

    let ok_pass = http::check_field(vp, true, http::ValidationLocation.Query, "page", "ok", "ok");
    let ok_fail = http::check_field(
        vp,
        false,
        http::ValidationLocation.Query,
        "bad\r\nkey",
        "invalid_int",
        "must be positive integer",
    );
    print("check_field: ", ok_pass, " ", ok_fail, " valid=", http::is_valid_problem(vp));

    var detailed_out: u8[..1024] = [];
    http::serialize_validation_problem(vp, detailed_out, http::ValidationDetailMode.Detailed);
    print("detailed: ", detailed_out[..]);

    var redacted_out: u8[..512] = [];
    http::serialize_validation_problem(vp, redacted_out, http::ValidationDetailMode.Redacted);
    print("redacted: ", redacted_out[..]);

    var res = http::Response { .. };
    http::write_validation_problem_response(res, vp, http::ValidationDetailMode.Detailed);
    print("vp_res: ", res.status_code, " ct=", http::header(res, "Content-Type"));
}

fn test_declarative_binders() {
    var q_dto = DemoQueryDto { page: 99, .. };
    var vp = http::ValidationProblem { .. };
    let ok_q = http::bind_query(
        "/items?page=3&limit=50&offset=100&delta=-5&active=true&tag=alpha#frag",
        q_dto,
        vp,
    );
    print(
        "bind_query_ok: ", ok_q, " page=", q_dto.page, " limit=", q_dto.limit,
        " offset=", q_dto.offset, " delta=", q_dto.delta, " active=", q_dto.active,
        " tag=", q_dto.tag[..],
    );

    let fail_q = http::bind_query("page=not_an_int&limit=10", q_dto, vp);
    print("bind_query_rollback: ", fail_q, " page_preserved=", q_dto.page, " errs=", vp.errors.len);

    var hdrs = http::HeaderMap { .. };
    http::set_header(hdrs, "X-Request-Id", "req-777", false);
    http::set_header(hdrs, "X-Retry-Max", "4", false);
    var h_dto = DemoHeaderDto { .. };
    var vp_h = http::ValidationProblem { .. };
    let ok_h = http::bind_headers(hdrs, h_dto, vp_h);
    print("bind_headers_ok: ", ok_h, " id=", h_dto.x_request_id[..], " retry=", h_dto.x_retry_max);

    let req_path = "/orgs/12/users/345/profile";
    var router_params = http::ZeroAllocParams { len: 3, .. };
    let _ = router_params.spans[0].name.try_set("org_id");
    router_params.spans[0].val_start = 6;
    router_params.spans[0].val_end = 8;
    let _ = router_params.spans[1].name.try_set("user_id");
    router_params.spans[1].val_start = 15;
    router_params.spans[1].val_end = 18;
    let _ = router_params.spans[2].name.try_set("slug");
    router_params.spans[2].val_start = 19;
    router_params.spans[2].val_end = 26;

    var p_dto = DemoParamDto { .. };
    var vp_p = http::ValidationProblem { .. };
    let ok_p = http::bind_params(router_params, req_path, p_dto, vp_p);
    print("bind_params_ok: ", ok_p, " org=", p_dto.org_id, " user=", p_dto.user_id, " slug=", p_dto.slug[..]);

    var c_dto = DemoCookieDto { .. };
    var vp_c = http::ValidationProblem { .. };
    let ok_c = http::bind_cookies("theme=light; sid=\"tok_xyz\"; debug=1", c_dto, vp_c);
    print("bind_cookies_ok: ", ok_c, " sid=", c_dto.sid[..], " debug=", c_dto.debug);

    var j_dto = DemoJsonDto { id: 11, .. };
    var vp_j = http::ValidationProblem { .. };
    let ok_j = http::bind_json(
        "{\"id\":42,\"count\":1000,\"code\":201,\"score\":9.5,\"admin\":true,\"name\":\"wing\",\"extra\":1}",
        j_dto,
        vp_j,
    );
    print(
        "bind_json_ok: ", ok_j, " id=", j_dto.id, " count=", j_dto.count,
        " code=", j_dto.code, " admin=", j_dto.admin, " name=", j_dto.name[..],
    );

    let fail_j = http::bind_json("{\"id\":999,\"name\":\"this_string_is_way_too_long_for_16\"}", j_dto, vp_j);
    print("bind_json_rollback: ", fail_j, " id_preserved=", j_dto.id, " errs=", vp_j.errors.len);
}

fn test_request_and_response_ufcs() {
    var req = http::new_post("https://example.com:8443/v1/orders?region=eu&tier=gold#sec");
    let _ = http::query(req, "local_k", "local_v");
    http::bearer(req, "secret_jwt_123");
    http::raw_json(req, "{\"id\":77,\"count\":5,\"code\":1,\"score\":1.0,\"admin\":false,\"name\":\"item\"}");

    print("req_path: ", http::path_slice(req), " query=", http::extract_request_query(req.url[..]));
    var q_val: u8[..64] = [];
    let has_reg = http::has_query_param(req, "region");
    let ok_reg = http::query_param(req, "region", q_val);
    var loc_val: u8[..64] = [];
    let ok_loc = http::query_param(req, "local_k", loc_val);
    print("req_query: ", has_reg, " ", ok_reg, " reg=", q_val[..], " loc=", ok_loc, ":", loc_val[..]);
    print("req_bearer: ", http::bearer_token(req));

    var decoded_body = DemoJsonDto { .. };
    let dec_err = http::decode_json_body(req, decoded_body);
    print("decode_req_json: ", http::ok(dec_err), " id=", decoded_body.id, " name=", decoded_body.name[..]);

    // Bug #5: bounded JSON string capacity check vs growable u8[>..]
    var res_over = http::Response { status_code: 200, .. };
    http::respond_json_str(res_over, 200, "{\"token\":\"0123456789abcdef\"}");
    let bounded_out, bounded_err = http::decode_json<BoundedReplyDto>(res_over);
    let grow_out, grow_err = http::decode_json<GrowableReplyDto>(res_over);
    print("bug5_bounded_ok: ", http::ok(bounded_err), " len=", bounded_out.token.len);
    print("bug5_grow_ok: ", http::ok(grow_err), " val=", grow_out.token[..]);

    // Bug #4: client auto-decompress guard policy
    let pol = http::DecompressGuardPolicy { .. };
    print(
        "bug4_decompress: get200=", http::should_auto_decompress("GET", 200, pol),
        " head200=", http::should_auto_decompress("HEAD", 200, pol),
        " get204=", http::should_auto_decompress("GET", 204, pol),
        " get500=", http::should_auto_decompress("GET", 500, pol),
    );

    // Ergonomic response helpers
    var res = http::Response { .. };
    http::respond_html(res, 200, "<h1>Hello</h1>");
    print("res_html: ", res.status_code, " ct=", http::header(res, "Content-Type"), " body=", res.body[..]);
    http::respond_bytes(res, 200, "RAW", "application/octet-stream");
    print("res_bytes: ", res.body[..]);
    http::respond_not_found(res, "missing");
    print("res_404: ", res.status_code, " body=", res.body[..]);
    http::respond_no_content(res);
    print("res_204: ", res.status_code, " len=", res.body.len);

    let redir_ok = http::respond_redirect(res, "/login", 302);
    let redir_crlf = http::respond_redirect(res, "/bad\r\nSet-Cookie: evil=1", 302);
    let redir_status = http::respond_redirect(res, "/bad", 200);
    print(
        "res_redirect: ", redir_ok, " crlf=", redir_crlf, " bad_code=", redir_status,
        " loc=", http::header(res, "Location"),
    );

    let _ = http::append_vary(res, "Accept-Encoding");
    let _ = http::append_vary(res, "accept-encoding");
    let _ = http::append_vary(res, "Origin");
    print("res_vary: ", http::header(res, "Vary"));
}

fn test_cookie_deltas_and_contracts() {
    var jar = cookie::ServerCookieDeltaJar { .. };
    let _ = cookie::add_original(jar, cookie::new_canonical_cookie("orig_only", "v0"));
    let _ = cookie::add_original(jar, cookie::new_canonical_cookie("to_remove", "v1"));
    let _ = cookie::add(jar, cookie::new_canonical_cookie("session_id", "s_new"));
    let _ = cookie::remove(jar, cookie::new_canonical_cookie("to_remove", "v1"));

    var out_hdrs = http::HeaderMap { .. };
    let flush_ok = cookie::flush_deltas(jar, out_hdrs);
    print(
        "cookie_flush: ", flush_ok, " count=", out_hdrs.entries.len,
        " first=", http::get_header(out_hdrs, "Set-Cookie"),
    );

    print(
        "non_empty: ", client::type_is_non_empty<client::EmptyPart>(), " ",
        client::type_is_non_empty<ContractReqBody>(),
    );

    let spec = client::EndpointSpec<ContractPathParams, ContractQueryDto, ContractReqBody, ContractResBody> {
        method:        "POST",
        path_template: "/orgs/:org_id/users/:user_id/tiers/:tier/revs/:rev/preview/:preview/slug/:slug",
    };
    let params = ContractPathParams {
        org_id:  9,
        user_id: 42,
        tier:    2,
        rev:     -1,
        preview: true,
        slug:    "alpha",
    };
    let q_dto = ContractQueryDto { limit: 25, verbose: true, filter: "all" };
    let b_dto = ContractReqBody { title: "Create", count: 3 };

    var built_req = http::Request { .. };
    let build_ok = client::build_contract_request(spec, "https://api.example.com/", params, q_dto, b_dto, built_req);
    print(
        "contract_req: ", build_ok, " method=", built_req.method[..],
        " url=", built_req.url[..], " q_count=", built_req.query_params.len,
        " body=", built_req.body[..],
    );

    // Reject path traversal in contract path param and call_endpoint
    let bad_params = ContractPathParams { org_id: 1, user_id: 1, tier: 1, rev: 1, preview: false, slug: "../admin" };
    let bad_ok = client::build_contract_request(spec, "https://api.example.com", bad_params, q_dto, b_dto, built_req);
    var client = client::Client { .. };
    let _, _, call_err = client::call_endpoint(client, spec, "https://api.example.com", bad_params, q_dto, b_dto);
    print("contract_traversal_rejected: ", bad_ok, " call_err_code=", call_err.code);
}

struct U64Dto {
    v: u64 = 0,
}

struct SlugParams {
    slug: u8[..16] = [],
}

fn test_recursive_json_opt_and_session_contracts() {
    var payload = RichPayloadDto { role: DemoRole.Admin, sem: core::opt_some<u8>(5), .. };
    var t1 = NestedTag { slot: 1, delta: -2, .. };
    let _ = t1.label.try_set("a");
    let _ = payload.fixed.try_push(t1);
    var t2 = NestedTag { slot: 2, delta: 3, .. };
    let _ = t2.label.try_set("b");
    payload.entries.push(t2);

    var res = http::Response { .. };
    http::respond_json(res, 200, payload);
    print("rich_json_enc: ", res.body[..]);

    var decoded = RichPayloadDto { .. };
    let dec_err = http::json(res, decoded);
    print(
        "rich_json_dec: ", http::ok(dec_err), " role=", decoded.role == DemoRole.Admin,
        " sem=", decoded.sem.present, ":", decoded.sem.value, " note=", decoded.note.present,
        " fixed=", decoded.fixed.len, ":", decoded.fixed[0].delta,
        " entries=", decoded.entries.len, ":", decoded.entries[0].label[..],
    );

    // Optional query binding + custom enum + rollback on invalid optional value
    var oq = OptQueryDto { .. };
    var vp = http::ValidationProblem { .. };
    let ok_omitted = http::bind_query("/v1/x?role=admin", oq, vp);
    print("opt_query_omit: ", ok_omitted, " role=", oq.role == DemoRole.Admin, " sem=", oq.sem.present);

    let ok_present = http::bind_query("/v1/x?role=guest&sem=4&kind=exams", oq, vp);
    print(
        "opt_query_set: ", ok_present, " sem=", oq.sem.present, ":", oq.sem.value,
        " kind=", oq.kind.present, ":", oq.kind.value[..],
    );

    let bad_opt = http::bind_query("/v1/x?role=admin&sem=999", oq, vp);
    print("opt_query_bad: ", bad_opt, " sem_kept=", oq.sem.value);

    // Contract request skips absent Opt<T> query params; server::add_contract_route registers spec
    let ep = client::EndpointSpec<client::EmptyPart, OptQueryDto, client::EmptyPart, RichPayloadDto> {
        method:        "GET",
        path_template: "/v1/rich",
    };
    let empty = client::EmptyPart {};
    let q_min = OptQueryDto { role: DemoRole.Admin, sem: core::opt_some<u8>(3), .. };
    var built = http::Request { .. };
    let ok_b = client::build_contract_request(ep, "https://api.example.com", empty, q_min, empty, built);
    print("opt_contract_q: ", ok_b, " q_count=", built.query_params.len);

    // Trailing-block call_endpoint over mocked Client: 200 decodes RichPayloadDto, 401 skips ResBody decode
    var mc = client::Client { .. };
    let _ = client::mock_route(mc, "GET", "https://api.example.com/v1/rich", 200, res.body[..]);
    let got_ok, res_ok, err_ok = client::call_endpoint(mc, ep, "https://api.example.com", empty, q_min, empty) { req =>
        http::bearer(req, "test_tok");
    };
    print("call_ep_200: ", http::ok(err_ok), " st=", res_ok.status_code, " sem=", got_ok.sem.value);

    var mc401 = client::Client { .. };
    let _ = client::mock_route(mc401, "GET", "https://api.example.com/v1/rich", 401, "{\"title\":\"unauthorized\"}");
    let _, res_401, err_401 = client::call_endpoint(mc401, ep, "https://api.example.com", empty, q_min, empty) { req =>
        http::bearer(req, "bad_tok");
    };
    print("call_ep_401: ", http::ok(err_401), " st=", res_401.status_code);

    var srv = server::new_http_server("127.0.0.1", 0);
    let ok_rt = server::add_contract_route(srv, ep, 42);
    print("contract_route: ", ok_rt);

    // Oversize Opt<T> query param (> 512 bytes) must be rejected, never silently dropped
    var huge_q: u8[>..] = [];
    huge_q.append("/v1/x?role=admin&kind=");
    for _ in 520 {
        huge_q.push('a');
    }
    var oq_huge = OptQueryDto { .. };
    let huge_ok = http::bind_query(huge_q[..], oq_huge, vp);
    print("opt_query_huge: ", huge_ok);

    // Full-range u64 round-trip and negative u64 rejection
    let max_u = U64Dto { v: 18446744073709551615 };
    var u_res = http::Response { .. };
    http::respond_json(u_res, 200, max_u);
    var u_dec = U64Dto { .. };
    let u_err = http::json(u_res, u_dec);
    var u_neg = http::Response { .. };
    u_neg.body.append("{\"v\":-1}");
    var u_neg_dec = U64Dto { .. };
    let u_neg_err = http::json(u_neg, u_neg_dec);
    print("u64_bounds: ", http::ok(u_err), " max=", u_dec.v == 18446744073709551615, " neg_ok=", http::ok(u_neg_err));

    // Dot-segment and unsafe path params rejected
    let ep_slug = client::EndpointSpec<SlugParams, client::EmptyPart, client::EmptyPart, client::EmptyPart> {
        method:        "GET",
        path_template: "/items/:slug",
    };
    var p_dot = SlugParams { .. };
    let _ = p_dot.slug.try_set("..");
    var p_sp = SlugParams { .. };
    let _ = p_sp.slug.try_set("a b");
    var p_pct = SlugParams { .. };
    let _ = p_pct.slug.try_set("%2f");
    var b_tmp = http::Request { .. };
    let ok_dot = client::build_contract_request(ep_slug, "https://api.example.com", p_dot, empty, empty, b_tmp);
    let ok_sp = client::build_contract_request(ep_slug, "https://api.example.com", p_sp, empty, empty, b_tmp);
    let ok_pct = client::build_contract_request(ep_slug, "https://api.example.com", p_pct, empty, empty, b_tmp);
    print("path_unsafe: ", ok_dot, " ", ok_sp, " ", ok_pct);
}

struct LenientChild {
    val: u8[..8] = [],
}

struct LenientItem {
    type_work: u8[..12]           = [],
    progress:  i32                = -1,
    active:    bool               = false,
    score:     f64                = 0.0,
    count_u64: u64                = 0,
    code_u32:  u32                = 0,
    small_i16: i16                = 0,
    small_u16: u16                = 0,
    flag_i8:   i8                 = -1,
    sem_u8:    u8                 = 0,
    opt_tag:   core::Opt<u8[..8]> = core::Opt<u8[..8]> { .. },
    children:  LenientChild[..2]  = [],
    note:      u8[..16]           = [],
}

fn http::json_decode_lenient(dst: GrowableReplyDto&, r: json::Reader&) {
    http::decode_json_struct_lenient(dst, r);
}

fn http::json_decode_lenient(dst: LenientChild&, r: json::Reader&) {
    http::decode_json_struct_lenient(dst, r);
}

fn http::json_decode_lenient(dst: LenientChild[..2]&, r: json::Reader&) {
    http::decode_bounded_array_lenient<LenientChild[..2], LenientChild>(dst, r);
}

fn http::json_decode_lenient(dst: LenientItem&, r: json::Reader&) {
    http::decode_json_struct_lenient(dst, r);
}

fn test_json_helpers_and_lenient() {
    // 1. to_json / from_json round-trip and rollback on bad JSON
    var arr: NestedTag[>..] = [
        NestedTag { slot: 1, delta: -2, label: "a" },
        NestedTag { slot: 3, delta: 4, label: "b" },
    ];
    var enc: u8[>..] = [];
    http::to_json(arr, enc);
    var dec: NestedTag[>..] = [];
    let ok_rt = http::from_json(enc[..], dec);
    let ok_bad = http::from_json("{bad", dec);
    print("to_from_json: ", ok_rt, " len=", dec.len, " bad=", ok_bad, " kept=", dec.len);

    // 2. DOM path & value extractors
    var doc:     json::Node[>..] = [];
    var decoded: u8[>..]         = [];
    let root, err = json::parse(
        "{\"data\":{\"msg\":\"Привет\",\"num\":42,\"flt\":3.9,\"flag\":1,\"empty\":null}}",
        doc,
        decoded,
    );
    guard err.len == 0 else { abort("parse failed"); }
    var b_msg:  u8[..5] = [];
    var g_msg:  u8[>..] = [];
    var b_num:  u8[..4] = [];
    var g_num:  u8[>..] = [];
    var b_null: u8[..4] = "old";
    let ok_bm = http::json_str_into(http::json_path(root, "data.msg"), b_msg);
    let ok_gm = http::json_str_into(http::json_path(root, "data.msg"), g_msg);
    let ok_bn = http::json_str_into(http::json_path(root, "data.num"), b_num);
    let ok_gn = http::json_str_into(http::json_path(root, "data.num"), g_num);
    let ok_nl = http::json_str_into(http::json_path(root, "data.empty"), b_null);
    print(
        "dom_path: ",
        ok_bm && ok_gm && ok_bn && ok_gn && ok_nl,
        " bm=", b_msg[..],
        " gm=", g_msg[..],
        " bn=", b_num[..],
        " gn=", g_num[..],
        " nl=", b_null.len,
        " str_or=", http::json_str_or(http::json_path(root, "data.missing"), "def"),
        " i64=", http::json_i64_or(http::json_path(root, "data.flt"), 0),
        " bool=", http::json_bool_or(http::json_path(root, "data.flag"), false),
    );

    // 3. Lenient reflective decoder
    var items: LenientItem[>..] = [];
    let raw_lenient = "[{\"TypeWork\":\"ПриветМир\",\"progress\":87.5,\"active\":1,\"score\":12.5,\"countU64\":99,\"codeU32\":7,\"smallI16\":-12,\"smallU16\":33,\"flagI8\":1,\"semU8\":5,\"optTag\":null,\"children\":[{\"Val\":\"c1\"},{\"Val\":\"c2\"},{\"Val\":\"c3\"}],\"note\":1234}]";
    let ok_len = http::from_json_lenient(raw_lenient, items);
    var tags: u8[..8][>..] = [];
    let ok_tags = http::from_json_lenient("[\"x\",123]", tags);
    var grow_len = GrowableReplyDto { .. };
    let ok_grow = http::from_json_lenient("{\"Token\":\"grow-ok\"}", grow_len);
    print(
        "lenient: ",
        ok_len && ok_tags && ok_grow && grow_len.token[..] == "grow-ok",
        " tw=", items[0].type_work[..],
        " prog=", items[0].progress,
        " act=", items[0].active,
        " u64=", items[0].count_u64,
        " note=", items[0].note[..],
        " opt=", items[0].opt_tag.present,
        " ch=", items[0].children.len,
        " tags=", tags.len,
    );

    // 4. Auto-comma JsonWriter
    var jw_buf: u8[>..] = [];
    var w = http::json_writer(jw_buf);
    w.begin_obj();
    w.field_str("a", "ok");
    w.field_str_ne("skip", "");
    w.field_str_ne("keep", "yes");
    w.field_i64("n", 0);
    w.field_i64_pos("neg", -1);
    w.field_i64_pos("pos", 5);
    w.field_bool("bf", false);
    w.field_bool_true("bt", true);
    w.key_obj("sub");
    w.field_i64("x", 9);
    w.end_obj();
    w.key_arr("arr");
    w.begin_arr();
    w.raw_value("{\"raw\":1}");
    w.end_arr();
    w.end_arr();
    w.end_obj();
    print("json_writer: ", jw_buf[..]);
}

fn main() {
    test_validation_problem();
    test_declarative_binders();
    test_request_and_response_ufcs();
    test_cookie_deltas_and_contracts();
    test_recursive_json_opt_and_session_contracts();
    test_json_helpers_and_lenient();
}

// CHECK: vp_init_valid: true
// CHECK-NEXT: loc_names: query,header,path,cookie,body,response,unknown
// CHECK-NEXT: check_field: true false valid=false
// CHECK-NEXT: detailed: {"type":"about:blank","status":422,"title":"Validation Failed","errors":[{"on":"query","property":"bad??key","code":"invalid_int","summary":"must be positive integer"}]}
// CHECK-NEXT: redacted: {"type":"about:blank","status":422,"title":"Validation Failed"}
// CHECK-NEXT: vp_res: 422 ct=application/problem+json
// CHECK-NEXT: bind_query_ok: true page=3 limit=50 offset=100 delta=-5 active=true tag=alpha
// CHECK-NEXT: bind_query_rollback: false page_preserved=3 errs=5
// CHECK-NEXT: bind_headers_ok: true id=req-777 retry=4
// CHECK-NEXT: bind_params_ok: true org=12 user=345 slug=profile
// CHECK-NEXT: bind_cookies_ok: true sid=tok_xyz debug=true
// CHECK-NEXT: bind_json_ok: true id=42 count=1000 code=201 admin=true name=wing
// CHECK-NEXT: bind_json_rollback: false id_preserved=42 errs=1
// CHECK-NEXT: req_path: /v1/orders query=region=eu&tier=gold
// CHECK-NEXT: req_query: true true reg=eu loc=true:local_v
// CHECK-NEXT: req_bearer: secret_jwt_123
// CHECK-NEXT: decode_req_json: true id=77 name=item
// CHECK-NEXT: bug5_bounded_ok: false len=0
// CHECK-NEXT: bug5_grow_ok: true val=0123456789abcdef
// CHECK-NEXT: bug4_decompress: get200=true head200=false get204=false get500=false
// CHECK-NEXT: res_html: 200 ct=text/html; charset=utf-8 body=<h1>Hello</h1>
// CHECK-NEXT: res_bytes: RAW
// CHECK-NEXT: res_404: 404 body=missing
// CHECK-NEXT: res_204: 204 len=0
// CHECK-NEXT: res_redirect: true crlf=false bad_code=false loc=/login
// CHECK-NEXT: res_vary: Accept-Encoding, Origin
// CHECK-NEXT: cookie_flush: true count=2 first=to_remove=; Path=/; Max-Age=0
// CHECK-NEXT: non_empty: false true
// CHECK-NEXT: contract_req: true method=POST url=https://api.example.com/orgs/9/users/42/tiers/2/revs/-1/preview/true/slug/alpha q_count=3 body={"title":"Create","count":3}
// CHECK-NEXT: contract_traversal_rejected: false call_err_code=400
// CHECK-NEXT: rich_json_enc: {"role":"admin","sem":5,"fixed":[{"slot":1,"delta":-2,"label":"a"}],"entries":[{"slot":2,"delta":3,"label":"b"}]}
// CHECK-NEXT: rich_json_dec: true role=true sem=true:5 note=false fixed=1:-2 entries=1:b
// CHECK-NEXT: opt_query_omit: true role=true sem=false
// CHECK-NEXT: opt_query_set: true sem=true:4 kind=true:exams
// CHECK-NEXT: opt_query_bad: false sem_kept=4
// CHECK-NEXT: opt_contract_q: true q_count=2
// CHECK-NEXT: call_ep_200: true st=200 sem=5
// CHECK-NEXT: call_ep_401: true st=401
// CHECK-NEXT: contract_route: true
// CHECK-NEXT: opt_query_huge: false
// CHECK-NEXT: u64_bounds: true max=true neg_ok=false
// CHECK-NEXT: path_unsafe: false false false
// CHECK-NEXT: to_from_json: true len=2 bad=false kept=2
// CHECK-NEXT: dom_path: true bm=Пр gm=Привет bn=42 gn=42 nl=0 str_or=def i64=3 bool=true
// CHECK-NEXT: lenient: true tw=Привет prog=87 act=true u64=99 note=1234 opt=false ch=2 tags=2
// CHECK-NEXT: json_writer: {"a":"ok","keep":"yes","n":0,"pos":5,"bf":false,"bt":true,"sub":{"x":9},"arr":[[{"raw":1}]]}
