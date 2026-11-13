// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Differential client verdict oracle runner for live TLS 1.3 + HTTP/2 + X.509.
import std;
import core from "../..";
import wing from "../..";

// Decodes an even-length hexadecimal ASCII string into `out`.
// Leaves `out` empty and returns false if length is odd or a byte is non-hex.
//
// Example:
//   hex_str = "6869"
//   returns: true, out = "hi"
fn decode_hex_bytes(hex_str: const u8[:], out: u8[>..]&) -> bool {
    out.clear();
    guard (hex_str.len & 1) == 0 else { return false; }
    var i: i64 = 0;
    while i < hex_str.len {
        let hi = core::hex_digit_to_val(hex_str[i]);
        let lo = core::hex_digit_to_val(hex_str[i + 1]);
        guard hi >= 0 && lo >= 0 else {
            out.clear();
            return false;
        }
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    return true;
}

// Computes lowercase hexadecimal SHA-256 digest for `data`.
fn sha256_hex_digest(data: const u8[:]) -> u8[..64] {
    let raw = core::sha256(data);
    var out: u8[..64] = [];
    for b in raw {
        core::format_u64_hex_fixed(b, 2, out, false);
    }
    return out;
}

// Parses newline-delimited "Name: Value" lines into request headers.
// Returns false if any non-empty line is missing ':'.
//
// Example:
//   raw_hdrs = "X-Req-Tag: alpha-99\n"
//   returns: true, req has X-Req-Tag = "alpha-99"
fn parse_header_lines_into_req(raw_hdrs: const u8[:], req: wing::Request&) -> bool {
    var tok = core::make_byte_tokenizer(raw_hdrs, '\n');
    while true {
        let raw_line, has_more = core::token_next(tok);
        guard has_more else { break; }
        let line = raw_line.trim_lws();
        guard line.len > 0 else { continue; }
        let k_raw, v_raw, ok = line.split_once_byte(':');
        guard ok else { return false; }
        let k = k_raw.trim_lws();
        let v = v_raw.trim_lws();
        wing::set_header(req, k, v);
    }
    return true;
}

fn format_checked_headers(res: const wing::Response&, hdr_csv: const u8[:], out: u8[..1024]&) {
    out.clear();
    guard hdr_csv != "-" else {
        let _ = out.try_append("-");
        return;
    }
    var first = true;
    var tok = core::make_byte_tokenizer(hdr_csv, ',');
    while true {
        let raw_name, has_more = core::token_next(tok);
        guard has_more else { break; }
        let name = raw_name.trim_lws();
        guard name.len > 0 else { continue; }
        if !first {
            let _ = out.try_push(';');
        }
        first = false;
        let _ = out.try_append(name);
        let _ = out.try_push('=');
        let _ = out.try_append(res.header(name));
    }
}

struct VerdictCase {
    name:     const u8[:],
    use_ca:   bool,
    method:   const u8[:],
    url:      const u8[:],
    hdr_hex:  const u8[:],
    body_hex: const u8[:],
    hdr_csv:  const u8[:],
}

// Parses a 7-column TSV case line into a `VerdictCase`.
//
// Example:
//   line = "h2_get\t1\tGET\thttps://localhost:8443/get\t-\t-\tcontent-type"
//   returns: VerdictCase { name: "h2_get", ... }, true
fn parse_verdict_case(line: const u8[:]) -> VerdictCase, bool {
    var out = VerdictCase {
        name:     "",
        use_ca:   false,
        method:   "",
        url:      "",
        hdr_hex:  "-",
        body_hex: "-",
        hdr_csv:  "-",
    };
    let c0, r0, ok0 = line.split_once_byte('\t');
    let c1, r1, ok1 = r0.split_once_byte('\t');
    let c2, r2, ok2 = r1.split_once_byte('\t');
    let c3, r3, ok3 = r2.split_once_byte('\t');
    let c4, r4, ok4 = r3.split_once_byte('\t');
    let c5, c6, ok5 = r4.split_once_byte('\t');
    guard ok0 && ok1 && ok2 && ok3 && ok4 && ok5 else { return out, false; }
    guard c1 == "0" || c1 == "1" else { return out, false; }
    out.name = c0;
    out.use_ca = c1 == "1";
    out.method = c2;
    out.url = c3;
    out.hdr_hex = c4;
    out.body_hex = c5;
    out.hdr_csv = c6;
    return out, true;
}

fn execute_verdict_case(
    sess:     wing::Session&,
    vc:       const VerdictCase&,
    hdr_buf:  u8[>..]&,
    body_buf: u8[>..]&,
    hdr_out:  u8[..1024]&,
) {
    var req = wing::new_request(vc.method, vc.url);
    if vc.hdr_hex != "-" {
        guard decode_hex_bytes(vc.hdr_hex, hdr_buf) else {
            print(vc.name, "\tERR\t-\tbad-hdr-hex");
            return;
        }
        guard parse_header_lines_into_req(hdr_buf[..], req) else {
            print(vc.name, "\tERR\t-\tbad-hdr-line");
            return;
        }
    }
    if vc.body_hex != "-" {
        guard decode_hex_bytes(vc.body_hex, body_buf) else {
            print(vc.name, "\tERR\t-\tbad-body-hex");
            return;
        }
        req.set_stream_body(body_buf[..], true);
    }

    let res, err = wing::execute_request(sess, req);
    if !wing::ok(err) {
        print(vc.name, "\tERR\t-\t", err.stage[..], ":", err.code, ":", err.message[..]);
        return;
    }

    let digest = sha256_hex_digest(res.body[..]);
    format_checked_headers(res, vc.hdr_csv, hdr_out);
    print(vc.name, "\tOK ", res.protocol[..], " ", res.status_code, " ", res.body.len, " ",
        digest[..], "\t", hdr_out[..]);
}

fn main() {
    let a = args();
    guard a.len >= 3 else {
        print("usage: h2_tls_client_verdict <ca_pem_path> <cases_tsv_path>\n");
        exit(2);
    }

    var ca_pem: u8[>..] = [];
    guard read_file(a[1], ca_pem) else {
        print("failed to read ca_pem_path\n");
        exit(2);
    }
    var cases_raw: u8[>..] = [];
    guard read_file(a[2], cases_raw) else {
        print("failed to read cases_tsv_path\n");
        exit(2);
    }

    let cfg = wing::ClientConfig { timeout_ms: 5000, .. };
    var sess_trusted = wing::new_session(cfg);
    defer sess_trusted.close();
    sess_trusted.ssrf_guard.enabled = false;
    sess_trusted.insecure_skip_verify = false;
    let added, pem_ok = wing::add_trust_anchors_pem(sess_trusted.trust_store, ca_pem[..]);
    guard pem_ok && added > 0 else {
        print("failed to load CA trust anchor\n");
        exit(2);
    }

    var sess_untrusted = wing::new_session(cfg);
    defer sess_untrusted.close();
    sess_untrusted.ssrf_guard.enabled = false;
    sess_untrusted.insecure_skip_verify = false;

    var hdr_buf:  u8[>..]    = [];
    var body_buf: u8[>..]    = [];
    var hdr_out:  u8[..1024] = [];

    var line_tok = core::make_byte_tokenizer(cases_raw[..], '\n');
    while true {
        let raw_line, has_more = core::token_next(line_tok);
        guard has_more else { break; }
        let line = raw_line.trim_end_byte('\r');
        guard line.len > 0 else { continue; }
        let vc, ok = parse_verdict_case(line);
        guard ok else {
            print("invalid case line: ", line, "\n");
            exit(2);
        }
        if vc.use_ca {
            execute_verdict_case(sess_trusted, vc, hdr_buf, body_buf, hdr_out);
        } else {
            execute_verdict_case(sess_untrusted, vc, hdr_buf, body_buf, hdr_out);
        }
    }
}
