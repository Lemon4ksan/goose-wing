// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP/1.1 smuggling differential oracle harness for full `wing` (`server::HttpServer`).
// Reads TSV lines `<name>\t<hex_wire>` from argv[1] and prints per-case verdicts.
import std;
import wing from "../..";

// Decodes an even-length hexadecimal ASCII string into `out`.
// Clears `out` and returns false on odd length or invalid hex digit.
//
// Example:
//   hex_str = "474554"
//   returns: true, out = "GET"
fn decode_hex_payload(hex_str: const u8[:], out: u8[>..]&) -> bool {
    out.clear();
    guard (hex_str.len & 1) == 0 else { return false; }
    var i: i64 = 0;
    while i < hex_str.len {
        let next_i = core::add_sat_i64(i, 2);
        let b, ok = core::parse_u8_hex(hex_str[i..next_i]);
        guard ok else {
            out.clear();
            return false;
        }
        out.push(b);
        i = next_i;
    }
    return true;
}

// Encodes up to 128 bytes of `data` as lowercase hexadecimal into `out`, or "-" when empty.
fn format_body_preview_hex(data: const u8[:], out: u8[..260]&) {
    out.clear();
    if data.len == 0 {
        let _ = out.try_push('-');
        return;
    }
    let take = min(data.len, 128);
    for i in take {
        core::format_u64_hex_fixed(data[i], 2, out, false);
    }
}

// Extracts the 3-digit HTTP status code from a serialized HTTP/1.1 status line.
// Returns 0 when `wire` does not begin with `HTTP/1.x NNN`.
//
// Example:
//   wire = "HTTP/1.1 400 Bad Request\r\n\r\n"
//   returns: 400
fn extract_http_status_code(wire: const u8[:]) -> u16 {
    guard wire.len >= 12 && wire[..7] == "HTTP/1." else { return 0; }
    let code_u, ok = core::parse_u64_dec(wire[9..12]);
    guard ok && code_u >= 100 && code_u <= 599 else { return 0; }
    return code_u as u16;
}

fn eval_single_vector(
    srv:       server::HttpServer&,
    name:      const u8[:],
    wire_data: const u8[:],
    req:       http::Request&,
    wire_out:  u8[..4096]&,
    body_hex:  u8[..260]&,
) {
    req = http::new_request("GET", "");
    let ok_parse, consumed = server::parse_http1_wire_request(wire_data, req);

    wire_out.clear();
    let _, ok_srv = server::handle_connection_wire(srv, "127.0.0.1", wire_data, 1000, wire_out);
    let srv_status = extract_http_status_code(wire_out[..]);

    if !ok_parse {
        print(name, "\tREJECT\t0\t-\t-\t0\t-\t", srv_status, "\t", if ok_srv { 1 } else { 0 });
        return;
    }

    format_body_preview_hex(req.body[..], body_hex);
    print(
        name, "\tACCEPT\t", consumed, "\t", req.method[..], "\t", req.url[..],
        "\t", req.body.len, "\t", body_hex[..], "\t", srv_status, "\t", if ok_srv { 1 } else { 0 },
    );
}

fn process_vector_batch(srv: server::HttpServer&, batch_raw: const u8[:]) {
    var wire_buf: u8[>..]    = [];
    var wire_out: u8[..4096] = [];
    var body_hex: u8[..260]  = [];
    var req = http::new_request("GET", "");

    var tok = core::make_byte_tokenizer(batch_raw, '\n');
    while true {
        let raw_line, has_more = core::token_next(tok);
        guard has_more else { break; }
        let line = raw_line.trim_end_byte('\r');
        guard line.len > 0 else { continue; }
        let name, hex_str, ok_cols = line.split_once_byte('\t');
        guard ok_cols && decode_hex_payload(hex_str, wire_buf) else {
            print(name, "\tERROR\t0\t-\t-\t0\t-\t0\t0");
            continue;
        }
        eval_single_vector(srv, name, wire_buf[..], req, wire_out, body_hex);
    }
}

fn main() {
    let a = args();
    guard a.len >= 2 else {
        print("ERR:USAGE\n");
        exit(2);
    }
    var batch_raw: u8[>..] = [];
    guard read_file(a[1], batch_raw) else {
        print("ERR:READ_FILE\n");
        exit(2);
    }

    var srv = server::new_http_server("127.0.0.1", 8080);
    srv.enable_header_memoization = false;
    server::add_static_get_route(srv, "/", "text/plain", "OK", 1);
    server::add_post_route(srv, "/echo", 2);
    server::add_post_route(srv, "/", 3);

    process_vector_batch(srv, batch_raw[..]);
}
