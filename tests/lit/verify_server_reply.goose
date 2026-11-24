// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
import std;
import wing from "../..";

struct ReplyUserOut {
    id:     i64                    = 0,
    name:   u8[..32]               = [],
    api_pw: core::Secret<u8[..64]> = core::Secret<u8[..64]> { .. },
}

struct ReplyListOut {
    items: ReplyUserOut[>..] = [],
}

fn http::json_encode(v: const ReplyUserOut&, out: u8[>..]&) {
    http::encode_json_struct(v, out);
}

enum SampleDomainErr {
    Unknown,
    MissingUser,
    BadInput,
    Throttle,
    ForbiddenOp,
    UnauthOp,
    MethodErr,
    ConflictErr,
    ValidationErr,
    UpstreamErr,
    DownErr,
}

fn to_domain_error(e: SampleDomainErr) -> server::DomainError {
    return match e {
        MissingUser => server::err_not_found("user missing"),
        BadInput => server::err_bad_request("bad_input", "bad"),
        Throttle => server::err_rate_limited(30, "slow down"),
        ForbiddenOp => server::err_forbidden(),
        UnauthOp => server::err_unauthorized(),
        MethodErr => server::err_method_not_allowed(),
        ConflictErr => server::err_conflict("dup_key", "already exists"),
        ValidationErr => server::err_validation("invalid_range", "bad range"),
        UpstreamErr => server::err_bad_gateway(),
        DownErr => server::err_unavailable(),
        _ => server::err_internal(),
    };
}

fn main() {
    // 1. Structured payload + Secret redaction + custom header.
    var r1 = server::ok(ReplyUserOut {
        id:     7,
        name:   "alice",
        api_pw: core::Secret<u8[..64]> { val: "top-secret" },
    });
    let ok_cc = server::with_cache_control(r1, "max-age=60");
    var res1 = http::Response { .. };
    server::write_reply(res1, r1);
    // CHECK: r1=200 cc=max-age=60 ok_cc=true body={"id":7,"name":"alice","api_pw":"******"}
    print(
        "r1=", res1.status_code,
        " cc=", http::header(res1, "Cache-Control"),
        " ok_cc=", ok_cc,
        " body=", res1.body[..], "\n",
    );

    // 2. Dynamic array field in response struct (`created` + `accepted`).
    var list_out = ReplyListOut { .. };
    list_out.items.push(ReplyUserOut { id: 1, name: "bob", .. });
    let r2 = server::created(list_out);
    var res2 = http::Response { .. };
    server::write_reply(res2, r2);
    // CHECK: r2=201 ct=application/json; charset=utf-8 body={"items":[{"id":1,"name":"bob","api_pw":"******"}]}
    print("r2=", res2.status_code, " ct=", http::header(res2, "Content-Type"), " body=", res2.body[..], "\n");

    let r2b = server::accepted(ReplyUserOut { id: 2, name: "queued", .. });
    var res2b = http::Response { .. };
    server::write_reply(res2b, r2b);
    // CHECK: r2b=202
    print("r2b=", res2b.status_code, "\n");

    // 3. 204 No Content and 304 Not Modified (preserving 304 instead of forcing 204).
    let r_204 = server::no_content();
    var res_204 = http::Response { .. };
    server::write_reply(res_204, r_204);
    // CHECK: r204=204 len=0
    print("r204=", res_204.status_code, " len=", res_204.body.len, "\n");

    let r_304 = server::not_modified();
    var res_304 = http::Response { .. };
    http::set_header(res_304, "Content-Type", "application/json");
    server::write_reply(res_304, r_304);
    // CHECK: r304=304 ct= len=0
    print("r304=", res_304.status_code, " ct=", http::header(res_304, "Content-Type"), " len=", res_304.body.len, "\n");

    // 4. Redirect valid and CRLF injection fail-safe.
    let r_red = server::redirect_to("/dashboard");
    var res_red = http::Response { .. };
    server::write_reply(res_red, r_red);
    // CHECK: red=302 loc=/dashboard
    print("red=", res_red.status_code, " loc=", http::header(res_red, "Location"), "\n");

    let r_bad_red = server::redirect_to("/evil\r\nSet-Cookie: a=b");
    var res_bad_red = http::Response { .. };
    server::write_reply(res_bad_red, r_bad_red);
    // CHECK: bad_red=500
    print("bad_red=", res_bad_red.status_code, "\n");

    // 5. DomainError rate-limited (429 + Retry-After + Cache-Control: no-store even when custom header added).
    var r_err = server::fail<ReplyUserOut>(to_domain_error(SampleDomainErr.Throttle));
    let _ = server::with_cache_control(r_err, "public");
    var res_err = http::Response { .. };
    server::write_reply(res_err, r_err);
    // CHECK: err429=429 ra=30 cc=no-store
    print(
        "err429=", res_err.status_code,
        " ra=", http::header(res_err, "Retry-After"),
        " cc=", http::header(res_err, "Cache-Control"), "\n",
    );

    // Exercise remaining DomainError constructors.
    let e_sum = to_domain_error(SampleDomainErr.MissingUser).status
        + to_domain_error(SampleDomainErr.BadInput).status
        + to_domain_error(SampleDomainErr.ForbiddenOp).status
        + to_domain_error(SampleDomainErr.UnauthOp).status
        + to_domain_error(SampleDomainErr.MethodErr).status
        + to_domain_error(SampleDomainErr.ConflictErr).status
        + to_domain_error(SampleDomainErr.ValidationErr).status
        + to_domain_error(SampleDomainErr.UpstreamErr).status
        + to_domain_error(SampleDomainErr.DownErr).status
        + to_domain_error(SampleDomainErr.Unknown).status;
    // CHECK: err_sum=4349
    print("err_sum=", e_sum, "\n");

    // 6. Header overflow fail-safe -> 500 instead of silent drop.
    var r_ovf = server::ok(ReplyUserOut { id: 9, name: "ovf", .. });
    for i in 9 {
        let _ = i;
        let _ = server::with_header(r_ovf, "X-Test", "1");
    }
    var res_ovf = http::Response { .. };
    server::write_reply(res_ovf, r_ovf);
    // CHECK: ovf=500 flag=true
    print("ovf=", res_ovf.status_code, " flag=", r_ovf.headers_overflowed, "\n");
}
