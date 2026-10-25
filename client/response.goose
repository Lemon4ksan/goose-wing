// HTTP response representation, header inspectors, and JSON decoding (RFC 9110).
namespace wing;

import std;
import json;
import http.compression_dict;

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
    trailers: HeaderItem[..16] = [],
    redirect_count: i64 = 0,
    url_chain: u8[..256][..16] = [],
    final_method: u8[..16] = "GET",
    protocol: u8[..16] = "HTTP/1.1",
    sent_headers: HeaderItem[..32] = [],
    set_cookies: u8[..256][..16] = [],
    body: u8[>..] = [],
}

fn new_response() -> Response {
    return Response { .. };
}

fn protocol(res: const Response&) -> const u8[:] {
    return res.protocol[..];
}

fn is_http3(res: const Response&) -> bool {
    return res.protocol[..] == "h3" || res.protocol[..] == "HTTP/3";
}

fn is_http2(res: const Response&) -> bool {
    return res.protocol[..] == "h2" || res.protocol[..] == "HTTP/2";
}

fn is_http1(res: const Response&) -> bool {
    return res.protocol[..] == "HTTP/1.1" || res.protocol[..] == "HTTP/1.0" || res.protocol[..] == "h1";
}

// Returns true if the HTTP response status code is within the 2xx Successful range [200, 299] (RFC 9110 Section 15.3).
fn is_success(res: const Response&) -> bool {
    return res.status_code >= 200 && res.status_code < 300;
}

fn status(res: const Response&) -> i32 {
    return res.status_code;
}

// Returns true if the HTTP response status code indicates a redirect (301, 302, 303, 307, or 308) (RFC 9110 Section 15.4).
fn is_redirect(res: const Response&) -> bool {
    return res.status_code == 301 || res.status_code == 302 || res.status_code == 303 ||
           res.status_code == 307 || res.status_code == 308;
}

fn header(res: const Response&, name: const u8[:]) -> const u8[:] {
    for &header_entry in res.headers {
        if eq_ascii_fold(header_entry.name[..], name) {
            return header_entry.value[..];
        }
    }
    return "";
}

// Returns the value of a response trailer by name (case-insensitive lookup)
fn trailer(res: const Response&, name: const u8[:]) -> const u8[:] {
    for &t in res.trailers {
        if eq_ascii_fold(t.name[..], name) {
            return t.value[..];
        }
    }
    return "";
}

fn has_trailer(res: const Response&, name: const u8[:]) -> bool {
    for &t in res.trailers {
        if eq_ascii_fold(t.name[..], name) {
            return true;
        }
    }
    return false;
}

fn add_trailer(res: Response&, name: const u8[:], value: const u8[:]) {
    guard !is_disallowed_trailer_field(name) else { return; }
    for &t in res.trailers {
        if eq_ascii_fold(t.name[..], name) {
            t.value.clear();
            t.value.append(value);
            return;
        }
    }
    if res.trailers.len < res.trailers.cap {
        res.trailers.push(make_header(name, value));
    }
}

fn header(res: Response&, name: const u8[:], value: const u8[:]) {
    for &header_entry in res.headers {
        if eq_ascii_fold(header_entry.name[..], name) {
            header_entry.value.clear();
            header_entry.value.append(value);
            return;
        }
    }
    if res.headers.len < 32 {
        res.headers.push(make_header(name, value));
    }
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
    if eq_ascii_fold(enc, "zstd") {
        var uncompressed: u8[>..] = [];
        let ok_z, err_z = core::decompress_zstd(res.body[..], uncompressed);
        if ok_z {
            res.body.clear();
            res.body.append(uncompressed[..]);
            return true;
        }
        return false;
    } else if eq_ascii_fold(enc, "gzip") {
        var uncompressed: u8[>..] = [];
        let ok_d, err = core::decompress_gzip(res.body[..], uncompressed);
        if ok_d {
            res.body.clear();
            res.body.append(uncompressed[..]);
            return true;
        }
        return false;
    } else if eq_ascii_fold(enc, "br") {
        var uncompressed: u8[>..] = [];
        let ok_b, err_b = core::decompress_brotli(res.body[..], uncompressed);
        if ok_b {
            res.body.clear();
            res.body.append(uncompressed[..]);
            return true;
        }
        return false;
    } else if eq_ascii_fold(enc, "deflate") {
        var uncompressed: u8[>..] = [];
        let ok_z, err_z = core::decompress_zlib(res.body[..], uncompressed);
        if ok_z {
            res.body.clear();
            res.body.append(uncompressed[..]);
            return true;
        }
        uncompressed.clear();
        let ok_d, err_d = core::decompress_deflate(res.body[..], uncompressed);
        if ok_d {
            res.body.clear();
            res.body.append(uncompressed[..]);
            return true;
        }
        return false;
    }
    return true;
}

// Automatically decompresses response.body, supporting standard encodings (gzip, deflate, zstd)
// as well as Chrome 123+ shared dictionary compression (dcz) using the client's dictionary cache.
fn decode_body_with_dictionary(res: Response&, dict_cache: const DictionaryCache&) -> bool {
    let enc = header(res, "content-encoding");
    if eq_ascii_fold(enc, "dcz") {
        var dict_hash: u8[32] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let p_slice, ok_hdr = decode_dcz_header(res.body[..], dict_hash);
        guard ok_hdr else { return false; }

        var found = false;
        var decompressed: u8[>..] = [];
        for &entry in dict_cache.entries {
            if entry.valid && entry.sha256_hash == dict_hash {
                let ok_dec = decompress_dcz_payload(p_slice, entry.content[..], decompressed);
                guard ok_dec else { return false; }
                found = true;
                break;
            }
        }
        guard found else { return false; }

        res.body.clear();
        res.body.append(decompressed[..]);
        return true;
    } else if eq_ascii_fold(enc, "dcb") {
        var dict_hash: u8[32] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let p_slice, ok_hdr = decode_dcb_header(res.body[..], dict_hash);
        guard ok_hdr else { return false; }

        var found = false;
        var decompressed: u8[>..] = [];
        for &entry in dict_cache.entries {
            if entry.valid && entry.sha256_hash == dict_hash {
                let ok_dec = decompress_dcb_payload(p_slice, entry.content[..], decompressed);
                guard ok_dec else { return false; }
                found = true;
                break;
            }
        }
        guard found else { return false; }

        res.body.clear();
        res.body.append(decompressed[..]);
        return true;
    }
    return decode_body(res);
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
