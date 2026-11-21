// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Demonstration of Google OAuth 2.0 CLI Authorization Code Flow with PKCE
// (RFC 7636, RFC 8252) and Google Drive API v3 Request Dispatching.
import std;
import core from "..";
import wing from "..";

const GOOGLE_AUTH_ENDPOINT:   const u8[:] = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_ENDPOINT:  const u8[:] = "https://oauth2.googleapis.com/token";
const GOOGLE_DRIVE_SCOPE:     const u8[:] = "https://www.googleapis.com/auth/drive.readonly";
const GOOGLE_DRIVE_FILES_API: const u8[:] = "https://www.googleapis.com/drive/v3/files?pageSize=10";

// Formats canonical loopback redirect URI with port (RFC 8252 §7.3).
fn format_redirect_uri<B>(port: u16, out: B&) -> bool {
    guard out.cap >= 64 else { return false; }
    out.clear();
    out.append("http://127.0.0.1:");
    var port_buf: u8[16] = [0; 16];
    let n = core::fast_u64toa(port as u64, port_buf[..]);
    guard n > 0 && n <= 5 else { return false; }
    out.append(port_buf[..n]);
    out.append("/callback");
    return true;
}

// Assembles RFC 8252 authorization URL with PKCE parameters (RFC 7636 §4.3).
// Returns false if parameters exceed safe bounds or output buffer is insufficient.
fn build_google_auth_url<B>(
    client_id:      const u8[:],
    redirect_uri:   const u8[:],
    scope:          const u8[:],
    state:          const u8[:],
    code_challenge: const u8[:],
    out:            B&,
) -> bool {
    guard client_id.len > 0 && client_id.len <= 256 else { return false; }
    guard redirect_uri.len > 0 && redirect_uri.len <= 128 else { return false; }
    guard scope.len > 0 && scope.len <= 128 else { return false; }
    guard state.len > 0 && state.len <= 64 else { return false; }
    guard code_challenge.len > 0 && code_challenge.len <= 64 else { return false; }
    guard out.cap >= 1024 else { return false; }

    out.clear();
    out.append(GOOGLE_AUTH_ENDPOINT);
    out.append("?response_type=code&client_id=");
    out.append(client_id);
    out.append("&redirect_uri=");
    out.append(redirect_uri);
    out.append("&scope=");
    out.append(scope);
    out.append("&state=");
    out.append(state);
    out.append("&code_challenge=");
    out.append(code_challenge);
    out.append("&code_challenge_method=S256&access_type=offline");
    return true;
}

// Extracts the target URI from an HTTP/1.1 request line (RFC 9112 §3.1).
//
// Example:
//   wire_in = "GET /callback?code=123 HTTP/1.1\r\n"
//   returns: "/callback?code=123", ok = true
fn extract_request_target(wire_in: const u8[:]) -> const u8[:], bool {
    guard wire_in.len >= 14 && wire_in.len <= 4096 else { return "", false; }
    guard wire_in[0] == 'G' && wire_in[1] == 'E' && wire_in[2] == 'T' && wire_in[3] == ' ' else {
        return "", false;
    }
    let after_get = wire_in[4..];
    let sp = core::index_of_byte(after_get, ' ');
    guard sp > 0 && sp < after_get.len else { return "", false; }
    return after_get[..sp], true;
}

// Extracts and validates OAuth authorization callback parameters from the request target.
//
// Example:
//   target = "/callback?code=4/0AY0e-g7abc&state=sec_state_987"
//   returns: code = "4/0AY0e-g7abc", state = "sec_state_987", ok = true
fn parse_callback_params<B1, B2>(
    target:    const u8[:],
    out_code:  B1&,
    out_state: B2&,
) -> bool {
    out_code.clear();
    out_state.clear();
    let q_pos = core::index_of_byte(target, '?');
    guard q_pos >= 0 else { return false; }
    let params = core::parse_query_params(target[q_pos..]);
    guard !params.overflow else { return false; }
    let code = core::get_query_param(params, "code");
    let state = core::get_query_param(params, "state");
    guard code.len > 0 && code.len <= out_code.cap else { return false; }
    guard state.len > 0 && state.len <= out_state.cap else { return false; }
    out_code.append(code);
    out_state.append(state);
    return true;
}

// Assembles application/x-www-form-urlencoded POST body for OAuth token exchange (RFC 7636 §4.5).
fn build_token_request_body<B>(
    client_id:     const u8[:],
    client_secret: const u8[:],
    code:          const u8[:],
    code_verifier: const u8[:],
    redirect_uri:  const u8[:],
    out:           B&,
) -> bool {
    guard client_id.len > 0 && client_id.len <= 256 else { return false; }
    guard client_secret.len <= 256 else { return false; }
    guard code.len > 0 && code.len <= 256 else { return false; }
    guard code_verifier.len >= 43 && code_verifier.len <= 128 else { return false; }
    guard redirect_uri.len > 0 && redirect_uri.len <= 128 else { return false; }
    guard out.cap >= 1152 else { return false; }

    out.clear();
    out.append("grant_type=authorization_code&client_id=");
    out.append(client_id);
    if client_secret.len > 0 {
        out.append("&client_secret=");
        out.append(client_secret);
    }
    out.append("&code=");
    out.append(code);
    out.append("&code_verifier=");
    out.append(code_verifier);
    out.append("&redirect_uri=");
    out.append(redirect_uri);
    return true;
}

// Constructs an authenticated Google Drive v3 file listing request (RFC 6750 §2.1).
fn build_drive_api_request(access_token: const u8[:]) -> http::Request {
    var req = http::new_request("GET", GOOGLE_DRIVE_FILES_API) { r =>
        r.bearer(access_token);
        r.set_header("Accept", "application/json");
    };
    return req;
}

fn bind_loopback_listener() -> i64, u16 {
    var listener = net::tcp_listen("127.0.0.1", 8085, 1);
    var eff_port: u16 = 8085;
    if listener < 0 {
        listener = net::tcp_listen("127.0.0.1", 0, 1);
        if listener > 0 {
            eff_port = net::tcp_getsockname_port(listener);
        }
    }
    return listener, eff_port;
}

fn accept_live_callback<B1, B2>(
    listener:       i64,
    received_code:  B1&,
    received_state: B2&,
) -> bool {
    guard listener > 0 else { return false; }
    let client_fd = net::tcp_accept(listener, 50);
    guard client_fd > 0 else { return false; }

    var recv_buf: u8[2048] = [0; 2048];
    let bytes_read = net::tcp_recv_slice(client_fd, recv_buf[..], 1000);
    guard bytes_read > 0 else {
        net::tcp_close(client_fd);
        return false;
    }

    let target, ok_tgt = extract_request_target(recv_buf[..bytes_read]);
    guard ok_tgt && parse_callback_params(target, received_code, received_state) else {
        net::tcp_close(client_fd);
        return false;
    }

    let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 49\r\nConnection: close\r\n\r\n<html><body>Authorization received.</body></html>";
    let _ = net::tcp_send(client_fd, resp);
    net::tcp_close(client_fd);
    return true;
}

fn format_callback_target(csrf_state: const u8[:], out: u8[..256]&) -> bool {
    guard csrf_state.len > 0 && csrf_state.len <= 64 else { return false; }
    out.clear();
    out.append("/callback?code=4/0AY0e-g7ExampleGoogleAuthCode12345&state=");
    out.append(csrf_state);
    return true;
}

fn format_callback_wire_request(csrf_state: const u8[:], out: u8[..512]&) -> bool {
    guard csrf_state.len > 0 && csrf_state.len <= 64 else { return false; }
    out.clear();
    out.append("GET /callback?code=4/0AY0e-g7ExampleGoogleAuthCode12345&state=");
    out.append(csrf_state);
    out.append(" HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    return true;
}

fn simulate_wire_callback(port: u16, csrf_state: const u8[:]) -> i64 {
    var srv = server::new_http_server("127.0.0.1", port);
    server::add_static_get_route(
        srv,
        "/callback",
        "text/html; charset=utf-8",
        "<html><body>Authorization complete.</body></html>",
        1,
    );

    var wire_req: u8[..512] = [];
    guard format_callback_wire_request(csrf_state, wire_req) else { return 0; }

    var wire_resp: u8[>..] = [];
    let outcome, ok_wire = server::handle_connection_wire(srv, "127.0.0.1", wire_req[..], 1000000000, wire_resp);
    guard ok_wire && outcome == server::PipelineOutcome.Handled else { return 0; }
    return wire_resp.len;
}

fn main() {
    print("Google OAuth 2.0 CLI Client (PKCE & Google Drive API)\n");

    let client_id = "109876543210-exampleappsuffix.apps.googleusercontent.com";

    // 1. Generate PKCE pair and CSRF state token
    let pkce, ok_pkce = auth::create_pkce_pair("", "S256");
    assert(ok_pkce);

    var csrf_state: u8[..64] = [];
    auth::generate_code_verifier(csrf_state, "");

    print("[1] Generated PKCE Pair & State:");
    print("    Code Verifier Length: ", pkce.verifier.len, " bytes");
    print("    Code Challenge (S256): ", pkce.challenge[..]);
    print("    CSRF State: ", csrf_state[..]);

    // 2. Bind loopback listener
    let listener, eff_port = bind_loopback_listener();
    var redirect_uri: u8[..128] = [];
    assert(format_redirect_uri(eff_port, redirect_uri));

    // 3. Assemble Google authorization URL
    var auth_url: u8[..1024] = [];
    assert(build_google_auth_url(
        client_id,
        redirect_uri[..],
        GOOGLE_DRIVE_SCOPE,
        csrf_state[..],
        pkce.challenge[..],
        auth_url,
    ));

    print("\n[2] Google Authorization URL:");
    print("    ", auth_url[..]);

    // 4. Intercept authorization code (live loopback socket or simulated wire)
    var received_code:  u8[..256] = [];
    var received_state: u8[..64]  = [];

    if accept_live_callback(listener, received_code, received_state) {
        print("\n[3] Intercepted Authorization Callback (Live Socket):");
    } else {
        print("\n[3] Intercepted Authorization Callback (Simulated Wire):");
        let resp_len = simulate_wire_callback(eff_port, csrf_state[..]);
        print("    Callback Route Handled: 200 OK (", resp_len, " bytes response)");

        var sample_target: u8[..256] = [];
        assert(format_callback_target(csrf_state[..], sample_target));
        assert(parse_callback_params(sample_target[..], received_code, received_state));
    }

    // 5. Validate CSRF state token with constant-time equality
    let state_valid = core::ct_eq_bytes(received_state[..], csrf_state[..]);
    assert(state_valid);
    print("    CSRF State Match: ", state_valid);
    print("    Authorization Code: ", received_code[..]);

    // 6. Build Token Exchange POST Request
    var token_body: u8[..1152] = [];
    assert(build_token_request_body(
        client_id,
        "",
        received_code[..],
        pkce.verifier[..],
        redirect_uri[..],
        token_body,
    ));

    var token_req = http::new_request("POST", GOOGLE_TOKEN_ENDPOINT) { r =>
        r.set_header("Content-Type", "application/x-www-form-urlencoded");
        r.set_header("Accept", "application/json");
        r.text(token_body[..]);
    };

    print("\n[4] Token Exchange Request Formatted (POST oauth2.googleapis.com/token):");
    print("    Target: ", token_req.url);
    print("    Content-Type: ", token_req.header("Content-Type"));
    print("    Payload: ", token_req.body);

    // 7. Build Authenticated Google Drive API Request
    let simulated_access_token = "ya29.a0ARrdaM_ExampleBearerTokenForGoogleDriveApiAccess";
    var drive_req = build_drive_api_request(simulated_access_token);

    print("\n[5] Authenticated Google Drive API Request (GET googleapis.com/drive/v3/files):");
    print("    Target: ", drive_req.url);
    print("    Authorization: ", drive_req.header("Authorization"));
    print("    Accept: ", drive_req.header("Accept"));

    if listener > 0 {
        net::tcp_close(listener);
    }
}
