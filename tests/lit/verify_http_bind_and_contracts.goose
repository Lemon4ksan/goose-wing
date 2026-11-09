// RUN: goose %s | %FileCheck %s
import std;
import core from "../..";
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

fn test_validation_problem() {
    var vp = wing::ValidationProblem { .. };
    print("vp_init_valid: ", wing::is_valid_problem(vp));
    print(
        "loc_names: ",
        wing::location_wire_name(wing::ValidationLocation.Query), ",",
        wing::location_wire_name(wing::ValidationLocation.Header), ",",
        wing::location_wire_name(wing::ValidationLocation.PathParam), ",",
        wing::location_wire_name(wing::ValidationLocation.Cookie), ",",
        wing::location_wire_name(wing::ValidationLocation.Body), ",",
        wing::location_wire_name(wing::ValidationLocation.Response), ",",
        wing::location_wire_name(wing::ValidationLocation.Unknown),
    );

    let ok_pass = wing::check_field(vp, true, wing::ValidationLocation.Query, "page", "ok", "ok");
    let ok_fail = wing::check_field(
        vp,
        false,
        wing::ValidationLocation.Query,
        "bad\r\nkey",
        "invalid_int",
        "must be positive integer",
    );
    print("check_field: ", ok_pass, " ", ok_fail, " valid=", wing::is_valid_problem(vp));

    var detailed_out: u8[..1024] = [];
    wing::serialize_validation_problem(vp, detailed_out, wing::ValidationDetailMode.Detailed);
    print("detailed: ", detailed_out[..]);

    var redacted_out: u8[..512] = [];
    wing::serialize_validation_problem(vp, redacted_out, wing::ValidationDetailMode.Redacted);
    print("redacted: ", redacted_out[..]);

    var res = wing::Response { .. };
    wing::write_validation_problem_response(res, vp, wing::ValidationDetailMode.Detailed);
    print("vp_res: ", res.status_code, " ct=", wing::header(res, "Content-Type"));
}

fn test_declarative_binders() {
    var q_dto = DemoQueryDto { page: 99, .. };
    var vp = wing::ValidationProblem { .. };
    let ok_q = wing::bind_query(
        "/items?page=3&limit=50&offset=100&delta=-5&active=true&tag=alpha#frag",
        q_dto,
        vp,
    );
    print(
        "bind_query_ok: ", ok_q, " page=", q_dto.page, " limit=", q_dto.limit,
        " offset=", q_dto.offset, " delta=", q_dto.delta, " active=", q_dto.active,
        " tag=", q_dto.tag[..],
    );

    let fail_q = wing::bind_query("page=not_an_int&limit=10", q_dto, vp);
    print("bind_query_rollback: ", fail_q, " page_preserved=", q_dto.page, " errs=", vp.errors.len);

    var hdrs = wing::HeaderMap { .. };
    wing::set_header(hdrs, "X-Request-Id", "req-777", false);
    wing::set_header(hdrs, "X-Retry-Max", "4", false);
    var h_dto = DemoHeaderDto { .. };
    var vp_h = wing::ValidationProblem { .. };
    let ok_h = wing::bind_headers(hdrs, h_dto, vp_h);
    print("bind_headers_ok: ", ok_h, " id=", h_dto.x_request_id[..], " retry=", h_dto.x_retry_max);

    let req_path = "/orgs/12/users/345/profile";
    var router_params = wing::ZeroAllocParams { len: 3, .. };
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
    var vp_p = wing::ValidationProblem { .. };
    let ok_p = wing::bind_params(router_params, req_path, p_dto, vp_p);
    print("bind_params_ok: ", ok_p, " org=", p_dto.org_id, " user=", p_dto.user_id, " slug=", p_dto.slug[..]);

    var c_dto = DemoCookieDto { .. };
    var vp_c = wing::ValidationProblem { .. };
    let ok_c = wing::bind_cookies("theme=light; sid=\"tok_xyz\"; debug=1", c_dto, vp_c);
    print("bind_cookies_ok: ", ok_c, " sid=", c_dto.sid[..], " debug=", c_dto.debug);

    var j_dto = DemoJsonDto { id: 11, .. };
    var vp_j = wing::ValidationProblem { .. };
    let ok_j = wing::bind_json(
        "{\"id\":42,\"count\":1000,\"code\":201,\"score\":9.5,\"admin\":true,\"name\":\"wing\",\"extra\":1}",
        j_dto,
        vp_j,
    );
    print(
        "bind_json_ok: ", ok_j, " id=", j_dto.id, " count=", j_dto.count,
        " code=", j_dto.code, " admin=", j_dto.admin, " name=", j_dto.name[..],
    );

    let fail_j = wing::bind_json("{\"id\":999,\"name\":\"this_string_is_way_too_long_for_16\"}", j_dto, vp_j);
    print("bind_json_rollback: ", fail_j, " id_preserved=", j_dto.id, " errs=", vp_j.errors.len);
}

fn test_request_and_response_ufcs() {
    var req = wing::new_post("https://example.com:8443/v1/orders?region=eu&tier=gold#sec");
    let _ = wing::query(req, "local_k", "local_v");
    wing::bearer(req, "secret_jwt_123");
    wing::raw_json(req, "{\"id\":77,\"count\":5,\"code\":1,\"score\":1.0,\"admin\":false,\"name\":\"item\"}");

    print("req_path: ", wing::path_slice(req), " query=", wing::extract_request_query(req.url[..]));
    var q_val: u8[..64] = [];
    let has_reg = wing::has_query_param(req, "region");
    let ok_reg = wing::query_param(req, "region", q_val);
    var loc_val: u8[..64] = [];
    let ok_loc = wing::query_param(req, "local_k", loc_val);
    print("req_query: ", has_reg, " ", ok_reg, " reg=", q_val[..], " loc=", ok_loc, ":", loc_val[..]);
    print("req_bearer: ", wing::bearer_token(req));

    var decoded_body = DemoJsonDto { .. };
    let dec_err = wing::decode_json_body(req, decoded_body);
    print("decode_req_json: ", wing::ok(dec_err), " id=", decoded_body.id, " name=", decoded_body.name[..]);

    // Bug #5: bounded JSON string capacity check vs growable u8[>..]
    var res_over = wing::Response { status_code: 200, .. };
    wing::respond_json_str(res_over, 200, "{\"token\":\"0123456789abcdef\"}");
    let bounded_out, bounded_err = wing::decode_json<BoundedReplyDto>(res_over);
    let grow_out, grow_err = wing::decode_json<GrowableReplyDto>(res_over);
    print("bug5_bounded_ok: ", wing::ok(bounded_err), " len=", bounded_out.token.len);
    print("bug5_grow_ok: ", wing::ok(grow_err), " val=", grow_out.token[..]);

    // Bug #4: client auto-decompress guard policy
    let pol = wing::DecompressGuardPolicy { .. };
    print(
        "bug4_decompress: get200=", wing::should_auto_decompress("GET", 200, pol),
        " head200=", wing::should_auto_decompress("HEAD", 200, pol),
        " get204=", wing::should_auto_decompress("GET", 204, pol),
        " get500=", wing::should_auto_decompress("GET", 500, pol),
    );

    // Ergonomic response helpers
    var res = wing::Response { .. };
    wing::respond_html(res, 200, "<h1>Hello</h1>");
    print("res_html: ", res.status_code, " ct=", wing::header(res, "Content-Type"), " body=", res.body[..]);
    wing::respond_bytes(res, 200, "RAW", "application/octet-stream");
    print("res_bytes: ", res.body[..]);
    wing::respond_not_found(res, "missing");
    print("res_404: ", res.status_code, " body=", res.body[..]);
    wing::respond_no_content(res);
    print("res_204: ", res.status_code, " len=", res.body.len);

    let redir_ok = wing::respond_redirect(res, "/login", 302);
    let redir_crlf = wing::respond_redirect(res, "/bad\r\nSet-Cookie: evil=1", 302);
    let redir_status = wing::respond_redirect(res, "/bad", 200);
    print(
        "res_redirect: ", redir_ok, " crlf=", redir_crlf, " bad_code=", redir_status,
        " loc=", wing::header(res, "Location"),
    );

    let _ = wing::append_vary(res, "Accept-Encoding");
    let _ = wing::append_vary(res, "accept-encoding");
    let _ = wing::append_vary(res, "Origin");
    print("res_vary: ", wing::header(res, "Vary"));
}

fn test_cookie_deltas_and_contracts() {
    var jar = wing::ServerCookieDeltaJar { .. };
    let _ = wing::add_original(jar, wing::new_canonical_cookie("orig_only", "v0"));
    let _ = wing::add_original(jar, wing::new_canonical_cookie("to_remove", "v1"));
    let _ = wing::add(jar, wing::new_canonical_cookie("session_id", "s_new"));
    let _ = wing::remove(jar, wing::new_canonical_cookie("to_remove", "v1"));

    var out_hdrs = wing::HeaderMap { .. };
    let flush_ok = wing::flush_cookie_deltas(jar, out_hdrs);
    print(
        "cookie_flush: ", flush_ok, " count=", out_hdrs.entries.len,
        " first=", wing::get_header(out_hdrs, "Set-Cookie"),
    );

    print(
        "non_empty: ", wing::type_is_non_empty<wing::EmptyPart>(), " ",
        wing::type_is_non_empty<ContractReqBody>(),
    );

    let spec = wing::EndpointSpec<ContractPathParams, ContractQueryDto, ContractReqBody, ContractResBody> {
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

    var built_req = wing::Request { .. };
    let build_ok = wing::build_contract_request(spec, "https://api.example.com/", params, q_dto, b_dto, built_req);
    print(
        "contract_req: ", build_ok, " method=", built_req.method[..],
        " url=", built_req.url[..], " q_count=", built_req.query_params.len,
        " body=", built_req.body[..],
    );

    // Reject path traversal in contract path param and call_endpoint
    let bad_params = ContractPathParams { org_id: 1, user_id: 1, tier: 1, rev: 1, preview: false, slug: "../admin" };
    let bad_ok = wing::build_contract_request(spec, "https://api.example.com", bad_params, q_dto, b_dto, built_req);
    var client = wing::Client { .. };
    let _, _, call_err = wing::call_endpoint(client, spec, "https://api.example.com", bad_params, q_dto, b_dto);
    print("contract_traversal_rejected: ", bad_ok, " call_err_code=", call_err.code);
}

fn main() {
    test_validation_problem();
    test_declarative_binders();
    test_request_and_response_ufcs();
    test_cookie_deltas_and_contracts();
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
