// Response representation and inspection helpers for goose-wing.
namespace wing;

import std;
import json;

struct Error {
    code: i32 = 0,
    stage: u8[..64] = [],
    message: u8[..256] = [],
}

fn no_error() -> Error {
    return Error { .. };
}

fn make_error(code: i32, stage: const u8[:], message: const u8[:]) -> Error {
    var err = Error { code: code, .. };
    err.stage.append(stage);
    err.message.append(message);
    return err;
}

fn ok(err: const Error&) -> bool {
    return err.code == 0;
}

struct Response {
    status_code: i32 = 0,
    effective_url: u8[..512] = [],
    headers: HeaderItem[..32] = [],
    body: u8[>..] = [],
}

fn is_success(res: const Response&) -> bool {
    return res.status_code >= 200 && res.status_code < 300;
}

fn is_redirect(res: const Response&) -> bool {
    return res.status_code == 301 || res.status_code == 302 || res.status_code == 303 ||
        res.status_code == 307 || res.status_code == 308;
}

fn header(res: const Response&, name: const u8[:]) -> const u8[:] {
    for &h in res.headers {
        if eq_ascii_fold(h.name[..], name) {
            return h.value[..];
        }
    }
    return "";
}

fn text(res: const Response&) -> const u8[:] {
    return res.body[..];
}

// --- Overloaded JSON field readers for zero-codegen struct deserialization ---

fn read_json_field(r: json::Reader&, dst: i64&) {
    dst = json::read_int(r);
}

fn read_json_field(r: json::Reader&, dst: i32&) {
    dst = json::read_int(r) as! i32;
}

fn read_json_field(r: json::Reader&, dst: f64&) {
    dst = json::read_number(r);
}

fn read_json_field(r: json::Reader&, dst: bool&) {
    dst = json::read_bool(r);
}

fn read_json_field(r: json::Reader&, dst) {
    var scratch: u8[>..] = [];
    let s = json::read_string(r, scratch);
    dst.clear();
    dst.append(s);
}

fn json<T>(res: const Response&, out: T&) -> Error {
    var r = json::reader(res.body[..]);
    json::each_member(r) { key =>
        var matched = false;
        const for <Name, Acc> in fields<T> {
            if !matched && key == Name {
                read_json_field(r, &out.Acc);
                matched = true;
            }
        }
        if !matched {
            json::skip(r);
        }
    };
    if !json::finish(r) {
        let msg = json::message(r);
        return make_error(422, "json_decode", msg[..]);
    }
    return no_error();
}

fn decode_json<T>(res: const Response&) -> T, Error {
    var out = T { .. };
    let err = json(res, out);
    return out, err;
}
