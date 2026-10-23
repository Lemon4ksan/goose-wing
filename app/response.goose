// HTTP response representation, header inspectors, and JSON decoding (RFC 9110).
namespace wing;

import std;
import json;
import app.profile;
import core.compress;

// ---- error model & diagnostics ---------------------------------------------

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

// ---- response model & inspectors -------------------------------------------

struct Response {
    status_code: i32 = 0,
    effective_url: u8[..2048] = [],
    headers: HeaderItem[..32] = [],
    redirect_count: i64 = 0,
    url_chain: u8[..256][..16] = [],
    final_method: u8[..16] = "GET",
    sent_headers: HeaderItem[..32] = [],
    set_cookies: u8[..256][..16] = [],
    body: u8[>..] = [],
}

fn new_response() -> Response {
    return Response { .. };
}

fn success(res: const Response&) -> bool {
    return res.status_code >= 200 && res.status_code < 300;
}

fn is_success(res: const Response&) -> bool {
    return success(res);
}

fn status(res: const Response&) -> i32 {
    return res.status_code;
}

fn redirect(res: const Response&) -> bool {
    return res.status_code == 301 || res.status_code == 302 || res.status_code == 303 ||
           res.status_code == 307 || res.status_code == 308;
}

fn is_redirect(res: const Response&) -> bool {
    return redirect(res);
}

fn header(res: const Response&, name: const u8[:]) -> const u8[:] {
    for &header_entry in res.headers {
        if eq_ascii_fold(header_entry.name[..], name) {
            return header_entry.value[..];
        }
    }
    return "";
}

fn sent_header(res: const Response&, name: const u8[:]) -> const u8[:] {
    for &header_entry in res.sent_headers {
        if eq_ascii_fold(header_entry.name[..], name) {
            return header_entry.value[..];
        }
    }
    return "";
}

fn text(res: const Response&) -> const u8[:] {
    return res.body[..];
}

// Automatically decompresses response.body if Content-Encoding is gzip or deflate.
// Replaces res.body in-place with decompressed bytes and clears the Content-Encoding header.
// Returns true if body was successfully decompressed or if uncompressed; false on corrupted stream.
fn decode_body(res: Response&) -> bool {
    let enc = header(res, "content-encoding");
    if eq_ascii_fold(enc, "gzip") {
        var uncompressed: u8[>..] = [];
        let ok_d, err = decompress_gzip(res.body[..], uncompressed);
        if ok_d {
            res.body.clear();
            res.body.append(uncompressed[..]);
            return true;
        }
        return false;
    } else if eq_ascii_fold(enc, "deflate") {
        var uncompressed: u8[>..] = [];
        let ok_z, err_z = decompress_zlib(res.body[..], uncompressed);
        if ok_z {
            res.body.clear();
            res.body.append(uncompressed[..]);
            return true;
        }
        uncompressed.clear();
        let ok_d, err_d = decompress_deflate(res.body[..], uncompressed);
        if ok_d {
            res.body.clear();
            res.body.append(uncompressed[..]);
            return true;
        }
        return false;
    }
    return true;
}

// ---- json reflection readers -----------------------------------------------

fn read_json_field(reader: json::Reader&, dst: i64&) {
    dst = json::read_int(reader);
}

fn read_json_field(reader: json::Reader&, dst: i32&) {
    dst = json::read_int(reader) as! i32;
}

fn read_json_field(reader: json::Reader&, dst: f64&) {
    dst = json::read_number(reader);
}

fn read_json_field(reader: json::Reader&, dst: bool&) {
    dst = json::read_bool(reader);
}

fn read_json_field(reader: json::Reader&, dst) {
    var scratch: u8[>..] = [];
    let str_val = json::read_string(reader, scratch);
    dst.clear();
    dst.append(str_val);
}

// ---- json response decoding -------------------------------------------------

fn json<T>(res: const Response&, out: T&) -> Error {
    var reader = json::reader(res.body[..]);
    json::each_member(reader) { key =>
        var matched = false;
        const for <Name, Acc> in fields<T> {
            if !matched && key == Name {
                read_json_field(reader, &out.Acc);
                matched = true;
            }
        }
        if !matched {
            json::skip(reader);
        }
    };
    if !json::finish(reader) {
        let msg = json::message(reader);
        return make_error(422, "json_decode", msg[..]);
    }
    return no_error();
}

fn decode_json<T>(res: const Response&) -> T, Error {
    var out = T { .. };
    let err = json(res, out);
    return out, err;
}
