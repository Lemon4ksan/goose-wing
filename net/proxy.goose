// Multi-protocol proxying (SOCKS5/5h RFC 1928 & RFC 1929, SOCKS4/4a, HTTP CONNECT),
// credential isolation, TLS tunnel buffer hygiene, and 4-tier Slowloris tarpit defenses.
namespace wing;

import std;
import core from "..";

// ---- 1. SOCKS5 normative constants (RFC 1928 & RFC 1929) -------------------

enum ProxyScheme {
    Direct,
    Http,
    Https,
    Socks4,
    Socks4a,
    Socks5,
    Socks5h,
}

let SOCKS5_VER: u8 = 0x05;
let SOCKS5_RFC1929_VER: u8 = 0x01; // First byte of RFC 1929 subnegotiation MUST be 0x01

let SOCKS5_AUTH_NONE: u8 = 0x00;
let SOCKS5_AUTH_GSSAPI: u8 = 0x01;
let SOCKS5_AUTH_USERPASS: u8 = 0x02;
let SOCKS5_AUTH_NO_ACCEPTABLE: u8 = 0xFF;

let SOCKS5_CMD_CONNECT: u8 = 0x01;
let SOCKS5_CMD_BIND: u8 = 0x02;
let SOCKS5_CMD_UDP_ASSOCIATE: u8 = 0x03;

let SOCKS5_ATYP_IPV4: u8 = 0x01;
let SOCKS5_ATYP_DOMAIN: u8 = 0x03;
let SOCKS5_ATYP_IPV6: u8 = 0x04;

let SOCKS5_REP_SUCCEEDED: u8 = 0x00;
let SOCKS5_REP_GENERAL_FAILURE: u8 = 0x01;
let SOCKS5_REP_NOT_ALLOWED: u8 = 0x02;
let SOCKS5_REP_NET_UNREACHABLE: u8 = 0x03;
let SOCKS5_REP_HOST_UNREACHABLE: u8 = 0x04;
let SOCKS5_REP_CONN_REFUSED: u8 = 0x05;
let SOCKS5_REP_TTL_EXPIRED: u8 = 0x06;
let SOCKS5_REP_CMD_NOT_SUPPORTED: u8 = 0x07;
let SOCKS5_REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

enum Socks5Error {
    None,
    InvalidVersion,
    NoAcceptableAuth,
    AuthFailed,
    InvalidAuthResponse,
    InvalidReplyHeader,
    ServerFailure,
    ConnectionNotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
    BufferTruncated,
}

// ---- 2. SOCKS5 frame builders & parsers ------------------------------------

// Builds Phase 1 Greeting frame [VER, NAUTH, AUTH...].
fn build_socks5_greeting(
    has_credentials: bool,
    enable_gssapi: bool,
    out: u8[..16]&
) {
    out.clear();
    out.push(SOCKS5_VER);
    var auth_count: u8 = 1;
    if has_credentials { auth_count++; }
    if enable_gssapi { auth_count++; }

    out.push(auth_count);
    out.push(SOCKS5_AUTH_NONE);
    if has_credentials {
        out.push(SOCKS5_AUTH_USERPASS);
    }
    if enable_gssapi {
        out.push(SOCKS5_AUTH_GSSAPI);
    }
}

// Parses Phase 1 Server Greeting Reply [VER, METHOD].
fn parse_socks5_greeting_reply(buf: const u8[:]) -> u8, Socks5Error {
    guard buf.len >= 2 else { return 0xFF, Socks5Error.BufferTruncated; }
    guard buf[0] == SOCKS5_VER else { return 0xFF, Socks5Error.InvalidVersion; }
    let selected_method = buf[1];
    if selected_method == SOCKS5_AUTH_NO_ACCEPTABLE {
        return 0xFF, Socks5Error.NoAcceptableAuth;
    }
    return selected_method, Socks5Error.None;
}

// Builds Phase 2 RFC 1929 Username/Password Subnegotiation [0x01, ULEN, UNAME, PLEN, PASSWD].
// Invariant: First byte MUST be 0x01, NOT 0x05!
fn build_socks5_rfc1929_auth(
    username: const u8[:],
    password: const u8[:],
    out: u8[..520]&
) -> Socks5Error {
    out.clear();
    guard username.len >= 1 && username.len <= 255 else { return Socks5Error.AuthFailed; }
    guard password.len >= 1 && password.len <= 255 else { return Socks5Error.AuthFailed; }

    out.push(SOCKS5_RFC1929_VER); // Version 0x01
    out.push(username.len as u8);
    out.append(username);
    out.push(password.len as u8);
    out.append(password);

    return Socks5Error.None;
}

// Parses Phase 2 RFC 1929 Reply [0x01, STATUS].
fn parse_socks5_rfc1929_reply(buf: const u8[:]) -> Socks5Error {
    guard buf.len >= 2 else { return Socks5Error.BufferTruncated; }
    guard buf[0] == SOCKS5_RFC1929_VER else { return Socks5Error.InvalidAuthResponse; }
    if buf[1] != 0x00 {
        return Socks5Error.AuthFailed;
    }
    return Socks5Error.None;
}

// Builds Phase 3 Connect Request [VER=0x05, CMD=0x01, RSV=0x00, ATYP, DST.ADDR, DST.PORT].
// Enforces socks5:// (local DNS ATYP=0x01/0x04) vs socks5h:// (proxy DNS ATYP=0x03) distinction.
fn build_socks5_connect_request(
    scheme: ProxyScheme,
    host_str: const u8[:],
    resolved_ipv4: const u8[4]&,
    has_ipv4: bool,
    port: u16,
    out: u8[..300]&
) -> Socks5Error {
    out.clear();
    out.push(SOCKS5_VER);
    out.push(SOCKS5_CMD_CONNECT);
    out.push(0x00); // RSV

    if scheme == ProxyScheme.Socks5h {
        // Delegate DNS resolution to proxy: ATYP = 0x03 (Domain Name)
        guard host_str.len >= 1 && host_str.len <= 255 else { return Socks5Error.AddressTypeNotSupported; }
        out.push(SOCKS5_ATYP_DOMAIN);
        out.push(host_str.len as u8);
        out.append(host_str);
    } else if has_ipv4 {
        // Local DNS resolution: ATYP = 0x01 (IPv4)
        out.push(SOCKS5_ATYP_IPV4);
        out.append(resolved_ipv4[..]);
    } else {
        // Fallback to domain if IPv4 is absent
        guard host_str.len >= 1 && host_str.len <= 255 else { return Socks5Error.AddressTypeNotSupported; }
        out.push(SOCKS5_ATYP_DOMAIN);
        out.push(host_str.len as u8);
        out.append(host_str);
    }

    // DST.PORT (2 bytes, big-endian)
    core::write_be_u16(out, port);

    return Socks5Error.None;
}

struct Socks5Reply {
    reply_code: u8 = 0,
    atyp: u8 = 0,
    bound_port: u16 = 0,
    bytes_consumed: i64 = 0,
}

// Calculates expected wire length of SOCKS5 connect reply based on ATYP (RFC 1928 Section 5).
fn socks5_needed_length(buf: const u8[:], atyp: u8) -> i64, Socks5Error {
    if atyp != SOCKS5_ATYP_IPV4 && atyp != SOCKS5_ATYP_IPV6 && atyp != SOCKS5_ATYP_DOMAIN {
        return 0, Socks5Error.AddressTypeNotSupported;
    }
    if atyp == SOCKS5_ATYP_DOMAIN && buf.len < 5 {
        return 0, Socks5Error.BufferTruncated;
    }
    if buf.len >= 5 {
        let expected_len = core::socks5_expected_frame_len_ct(buf);
        if expected_len > 0 {
            return expected_len, Socks5Error.None;
        }
    }
    if atyp == SOCKS5_ATYP_IPV4 { return 10, Socks5Error.None; }
    if atyp == SOCKS5_ATYP_IPV6 { return 22, Socks5Error.None; }
    return 0, Socks5Error.AddressTypeNotSupported;
}

// Maps RFC 1928 REP octet to corresponding Socks5Error variant.
fn socks5_rep_to_error(rep: u8) -> Socks5Error {
    if rep == SOCKS5_REP_SUCCEEDED { return Socks5Error.None; }
    if rep == SOCKS5_REP_GENERAL_FAILURE { return Socks5Error.ServerFailure; }
    if rep == SOCKS5_REP_NOT_ALLOWED { return Socks5Error.ConnectionNotAllowed; }
    if rep == SOCKS5_REP_NET_UNREACHABLE { return Socks5Error.NetworkUnreachable; }
    if rep == SOCKS5_REP_HOST_UNREACHABLE { return Socks5Error.HostUnreachable; }
    if rep == SOCKS5_REP_CONN_REFUSED { return Socks5Error.ConnectionRefused; }
    if rep == SOCKS5_REP_TTL_EXPIRED { return Socks5Error.TtlExpired; }
    if rep == SOCKS5_REP_CMD_NOT_SUPPORTED { return Socks5Error.CommandNotSupported; }
    return Socks5Error.AddressTypeNotSupported;
}

// Parses Phase 4 Server Connect Reply [VER=0x05, REP, RSV=0x00, ATYP, BND.ADDR, BND.PORT].
// Completely consumes bound address and port to ensure no leftover protocol bytes.
fn parse_socks5_connect_reply(buf: const u8[:]) -> Socks5Reply, Socks5Error {
    guard buf.len >= 4 else { return Socks5Reply { .. }, Socks5Error.BufferTruncated; }
    guard buf[0] == SOCKS5_VER else { return Socks5Reply { .. }, Socks5Error.InvalidVersion; }

    let rep = buf[1];
    let atyp = buf[3];
    let needed_len, err = socks5_needed_length(buf, atyp);
    guard err == Socks5Error.None else { return Socks5Reply { .. }, err; }
    guard buf.len >= needed_len else { return Socks5Reply { .. }, Socks5Error.BufferTruncated; }

    let bnd_port = core::read_be_u16(buf, needed_len - 2);

    let res = Socks5Reply {
        reply_code: rep,
        atyp: atyp,
        bound_port: bnd_port,
        bytes_consumed: needed_len,
    };

    return res, socks5_rep_to_error(rep);
}

// ---- 3. HTTP CONNECT tunnel & TLS buffer hygiene ---------------------------

enum ConnectTunnelError {
    None,
    InvalidStatusLine,
    ProxyAuthRequired,
    ConnectFailed,
    TunnelBufferedTooManyBytes, // OkHttp leftover buffer defense
    MalformedHeaders,
}

// Builds an isolated HTTP CONNECT request for tunneling through proxy.
fn build_http_connect_request(
    target_host: const u8[:],
    target_port: u16,
    proxy_auth: const u8[:],
    user_agent: const u8[:],
    out: u8[..1024]&
) {
    out.clear();
    format(out, "CONNECT ", target_host, ":", target_port, " HTTP/1.1\r\nHost: ", target_host, ":", target_port, "\r\n");

    if proxy_auth.len > 0 {
        out.append("Proxy-Authorization: ");
        out.append(proxy_auth);
        out.append("\r\n");
    }

    if user_agent.len > 0 {
        out.append("User-Agent: ");
        out.append(user_agent);
        out.append("\r\n");
    }

    out.append("Proxy-Connection: Keep-Alive\r\n\r\n");
}

// Strips Proxy-Authorization, Proxy-Connection, standard hop-by-hop headers, and Connection tokens so credentials never leak to origin (RFC 9110 Section 7.6.1 & Go #16875).
fn sanitize_tunnel_headers_for_origin<H>(headers: H&) {
    var custom_tokens: u8[..64][..16] = [];
    for &h in headers {
        if eq_ascii_fold(h.name[..], "connection") {
            var rest: const u8[:] = h.value[..];
            while rest.len > 0 {
                let token_raw, remaining, has_comma = core::split_once_byte(rest, ',');
                let token = trim_lws(token_raw);
                if token.len > 0 && !is_hop_by_hop_header_name(token) && !eq_ascii_fold(token, "close") {
                    if custom_tokens.len < 16 {
                        var tok_buf: u8[..64] = [];
                        tok_buf.append(token);
                        custom_tokens.push(tok_buf);
                    }
                }
                if !has_comma { break; }
                rest = remaining;
            }
        }
    }

    var write_idx = 0;
    for read_idx in headers.len {
        let h_name = headers[read_idx].name[..];
        var drop = is_hop_by_hop_header_name(h_name);
        if !drop {
            for &tok in custom_tokens {
                if eq_ascii_fold(h_name, tok[..]) {
                    drop = true;
                    break;
                }
            }
        }
        if !drop {
            if write_idx != read_idx {
                headers[write_idx] = copy(headers[read_idx]);
            }
            write_idx++;
        }
    }
    headers.resize(write_idx);
}

// Inspects HTTP CONNECT response and defends against data injection before TLS handshake.
// OkHttp RealConnection parity: "TLS tunnel buffered too many bytes".
fn verify_connect_tunnel_response(
    raw_response: const u8[:],
    sink_buffered_bytes: i64 = 0
) -> ConnectTunnelError {
    guard raw_response.len >= 12 else { return ConnectTunnelError.InvalidStatusLine; }

    // Find \r\n\r\n boundary separating headers from potential smuggled body bytes
    let delim_idx = core::index_of_slice(raw_response, "\r\n\r\n");
    guard delim_idx >= 0 else { return ConnectTunnelError.MalformedHeaders; }
    let header_end_pos = delim_idx + 4;

    // Parse status code from "HTTP/1.x 200 ..."
    let space_idx = core::index_of_byte(raw_response, ' ');
    guard space_idx > 0 && space_idx + 4 <= raw_response.len else { return ConnectTunnelError.InvalidStatusLine; }

    let status_code_str = raw_response[space_idx + 1..space_idx + 4];
    if status_code_str == "407" {
        return ConnectTunnelError.ProxyAuthRequired;
    }
    if status_code_str != "200" {
        return ConnectTunnelError.ConnectFailed;
    }

    // Defense: If extra bytes exist in response buffer after \r\n\r\n or in output sink,
    // abort immediately to prevent TLS session prefix injection attacks!
    if raw_response.len > header_end_pos || sink_buffered_bytes > 0 {
        return ConnectTunnelError.TunnelBufferedTooManyBytes;
    }

    return ConnectTunnelError.None;
}

// CVE-2026-56866 defense: Whether a failed or rejected CONNECT response requires
// the underlying transport connection to be closed immediately rather than returned to pool.
fn should_close_connection_on_connect_error(err: ConnectTunnelError) -> bool {
    return err != ConnectTunnelError.None;
}

// ---- 4. 4-tier Slowloris and Reverse-Slowloris tarpit defenses --------------

enum SlowlorisViolation {
    None,
    HeaderTimeoutExpired,
    ExpectContinueTimeoutExpired,
    MaxHeaderBytesExceeded,
    MinIngressRateViolated,
    MaxHeaderCountExceeded,
}

struct SlowlorisDefenseConfig {
    response_header_timeout_ns: i64 = 10000000000, // 10 seconds monotonic cumulative deadline
    expect_continue_timeout_ns: i64 = 1000000000,  // 1 second Expect: 100-continue ceiling
    max_response_header_bytes: i64 = 65536,         // 64 KB hard memory ceiling
    min_header_ingress_rate_bps: i64 = 256,         // 256 B/s minimum streaming rate
    max_header_count: i32 = 100,                    // 100 header fields cap
}

fn new_slowloris_defense_config() -> SlowlorisDefenseConfig {
    return SlowlorisDefenseConfig { .. };
}

struct HeaderReader {
    config: SlowlorisDefenseConfig = SlowlorisDefenseConfig { .. },
    header_read_start_ns: i64 = 0,
    cumulative_header_bytes: i64 = 0,
    header_lines_count: i32 = 0,
    headers_complete: bool = false,
    poison_connection: bool = false,
}

fn new_header_reader(cfg: SlowlorisDefenseConfig, start_mono_ns: i64) -> HeaderReader {
    return HeaderReader {
        config: cfg,
        header_read_start_ns: start_mono_ns,
        ..
    };
}

// Feeds incoming header chunk and verifies all 4 Slowloris defense invariants.
fn feed_header_bytes(
    reader: HeaderReader&,
    chunk: const u8[:],
    now_mono_ns: i64
) -> SlowlorisViolation {
    if reader.headers_complete { return SlowlorisViolation.None; }

    let elapsed_ns = core::ct_max_i64(0, now_mono_ns - reader.header_read_start_ns);

    // Barrier 1: Monotonic Cumulative Header Deadline (never reset per-byte!)
    if elapsed_ns >= reader.config.response_header_timeout_ns {
        reader.poison_connection = true;
        return SlowlorisViolation.HeaderTimeoutExpired;
    }

    reader.cumulative_header_bytes += chunk.len;

    // Barrier 3: Hard memory ceiling on header block
    if reader.cumulative_header_bytes > reader.config.max_response_header_bytes {
        reader.poison_connection = true;
        return SlowlorisViolation.MaxHeaderBytesExceeded;
    }

    // Barrier 4: Byte-Drip Gate (minimum ingress rate check on windows >= 1s)
    if elapsed_ns >= 1000000000 {
        let elapsed_sec: f64 = elapsed_ns / 1000000000;
        let current_rate: f64 = reader.cumulative_header_bytes / elapsed_sec;
        let min_rate: f64 = reader.config.min_header_ingress_rate_bps;
        if current_rate < min_rate {
            reader.poison_connection = true;
            return SlowlorisViolation.MinIngressRateViolated;
        }
    }

    // Count header lines and enforce ceiling
    let newlines = core::count_byte(chunk, '\n') as i32;
    if newlines > 0 {
        reader.header_lines_count += newlines;
        if reader.header_lines_count > reader.config.max_header_count {
            reader.poison_connection = true;
            return SlowlorisViolation.MaxHeaderCountExceeded;
        }
    }

    return SlowlorisViolation.None;
}
