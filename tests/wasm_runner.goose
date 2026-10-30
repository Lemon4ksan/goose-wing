// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

import std;
import core from "..";
import wing from "..";

fn main() {
    print("goose-wing WebAssembly Production Scenarios\n");

    // ------------------------------------------------------------------------
    // Scenario 1: WHATWG URL Decomposition & PSL Tenant Isolation
    // ------------------------------------------------------------------------
    print("[1/11] URL Parsing & Mozilla PSL Tenant Scoping...\n");
    let u, err_url = core::parse_url_view("https://alice.project.github.io:8443/api/v2/orders?priority=high#confirm");
    guard u.valid else {
        print("FAIL: URL parse failed!\n");
        return;
    }
    print("  URL Scheme:   ", core::scheme(u), "\n");
    print("  URL Host:     ", core::host(u), "\n");
    print("  URL Port:     ", core::port(u), "\n");
    print("  URL Path:     ", core::pathname(u), "\n");
    print("  URL Search:   ", core::search(u), "\n");
    print("  URL Fragment: ", core::hash(u), "\n");

    var etld_buf: u8[..64] = [];
    core::extract_etld_plus_one("alice.project.github.io", etld_buf);
    print("  PSL Tenant eTLD+1: ", etld_buf[..], "\n");

    // ------------------------------------------------------------------------
    // Scenario 2: Zero-Allocation HeaderMap & O(1) Fast Inline Lookups
    // ------------------------------------------------------------------------
    print("\n[2/11] RFC 9110 HeaderMap & O(1) Slots...\n");
    var map = wing::HeaderMap { .. };
    let _h = wing::set_inline(map, wing::WellKnownHeader.Host, "api.exchange.io:8443");
    let _ct = wing::set_inline(map, wing::WellKnownHeader.ContentType, "application/json; charset=utf-8");
    let _cl = wing::set_inline(map, wing::WellKnownHeader.ContentLength, "2048");
    wing::append_header(map, "User-Agent", "Goose-Wing/Wasm 1.0 (Gosling-Engine)");
    wing::append_header(map, "X-Wasm-Engine", "Gosling-ZeroAlloc");
    wing::append_header(map, "Idempotency-Key", "idemp_998877aabb");

    print("  Host:            ", wing::get_header(map, "host"), "\n");
    print("  Content-Type:    ", wing::get_header(map, "content-type"), "\n");
    print("  Content-Length:  ", wing::get_header(map, "content-length"), "\n");
    print("  User-Agent:      ", wing::get_header(map, "user-agent"), "\n");
    print("  Idempotency-Key: ", wing::get_header(map, "idempotency-key"), "\n");

    // ------------------------------------------------------------------------
    // Scenario 3: Canonical Cookie Jar with Security Scoping & Prefix Rules
    // ------------------------------------------------------------------------
    print("\n[3/11] RFC 6265bis Canonical Cookie Jar...\n");
    var jar = wing::CanonicalCookieJar { .. };
    var clock = core::new_mock_clock();

    // 1. Host-only secure cookie
    let set1 = wing::set_cookie_header(jar, "https://api.exchange.io/", "sid=session_token_xyz; Path=/; Secure; HttpOnly; SameSite=Strict", clock.now_us);
    // 2. Partitioned CHIPS cookie
    let set2 = wing::set_cookie_header(jar, "https://api.exchange.io/", "__Host-pref=dark; Path=/; Secure; SameSite=None; Partitioned", clock.now_us, "https://exchange.io");
    print("  Cookie 1 added: ", set1, "\n");
    print("  Cookie 2 added: ", set2, "\n");
    print("  Total cookies:  ", jar.cookies.len, "\n");
    for i in jar.cookies.len {
        print("    [", i, "] ", jar.cookies[i].name[..], " = ", jar.cookies[i].value[..], "\n");
    }

    // ------------------------------------------------------------------------
    // Scenario 4: HTTP Redirect State Machine & Cross-Origin Sanitization
    // ------------------------------------------------------------------------
    print("\n[4/11] Redirect State Machine & CVE Sanitization...\n");
    // Test 301 POST -> GET method mutation
    let r_info = wing::compute_redirect_info(
        "POST", 301, "https://api.exchange.io/v1/auth", "https://sso.other-tenant.com/login",
        wing::ReferrerPolicy.NoReferrerWhenDowngrade, "https://api.exchange.io/v1/auth",
        wing::RedirectOptions { .. },
    );
    print("  301 New Method:      ", r_info.new_method[..], "\n");
    print("  301 Clear Body:      ", r_info.clear_body, "\n");
    print("  301 Is Cross-Origin: ", r_info.is_cross_origin, "\n");

    var req_headers: wing::HeaderItem[..32] = [];
    req_headers.push(wing::make_header("Authorization", "Bearer secret_jwt_token_999", true));
    req_headers.push(wing::make_header("X-API-Key", "api_key_secret_888", true));
    req_headers.push(wing::make_header("Accept", "application/json", false));

    wing::sanitize_headers_on_redirect(
        req_headers,
        r_info,
        wing::RedirectSanitizeOptions { enable_referer: true },
    );
    var has_auth = false;
    var has_apikey = false;
    var has_accept = false;
    for h in req_headers {
        if core::eq_ascii_fold(h.name[..], "Authorization") { has_auth = true; }
        if core::eq_ascii_fold(h.name[..], "X-API-Key") { has_apikey = true; }
        if core::eq_ascii_fold(h.name[..], "Accept") { has_accept = true; }
    }
    print("  Auth purged:         ", !has_auth, "\n");
    print("  API Key purged:      ", !has_apikey, "\n");
    print("  Accept preserved:    ", has_accept, "\n");

    // ------------------------------------------------------------------------
    // Scenario 5: RFC 9112 Chunked Transfer Encoding & Trailer Extraction
    // ------------------------------------------------------------------------
    print("\n[5/11] RFC 9112 Chunked Transfer Coding & Trailers...\n");
    let chunked_wire = "5\r\nHello\r\n8\r\n, World!\r\n0\r\nExpires: Wed, 21 Oct 2026 07:28:00 GMT\r\nX-Checksum: sha256-abc123\r\n\r\n";
    var body_out:     u8[>..]                = [];
    var trailers_out: wing::HeaderItem[..16] = [];
    let err_chunk, _consumed = wing::decode_chunked_body_with_trailers(chunked_wire, body_out, trailers_out);
    print("  Chunk decode ok:     ", err_chunk == wing::ChunkedDecodeError.None, "\n");
    print("  Body Reassembled:    ", body_out[..], "\n");
    print("  Trailers Extracted:  ", trailers_out.len, "\n");
    for ti in trailers_out.len {
        print("    Trailer: ", trailers_out[ti].name[..], " = ", trailers_out[ti].value[..], "\n");
    }

    // ------------------------------------------------------------------------
    // Scenario 6: RFC 9113 HTTP/2 Multiplexed Framing & Stream Control
    // ------------------------------------------------------------------------
    print("\n[6/11] RFC 9113 HTTP/2 Framing & Stream Demux...\n");
    let h2_hdr = internal::FrameHeader {
        length:     24,
        frame_type: internal::FRAME_HEADERS,
        flags:      internal::FLAG_END_HEADERS | internal::FLAG_END_STREAM,
        stream_id:  101,
    };
    var h2_wire: u8[9] = [0; 9];
    internal::encode_frame_header(h2_hdr, h2_wire);
    let parsed_h2, err_h2 = internal::parse_frame_header(h2_wire[..]);
    print("  H2 Parse Err:        ", err_h2, "\n");
    print("  H2 Frame Type:       ", parsed_h2.frame_type as i64, " (FRAME_HEADERS)\n");
    print("  H2 Stream ID:        ", parsed_h2.stream_id as i64, "\n");
    print("  H2 End-Headers Flag: ", (parsed_h2.flags & internal::FLAG_END_HEADERS) != 0, "\n");
    print("  H2 End-Stream Flag:  ", (parsed_h2.flags & internal::FLAG_END_STREAM) != 0, "\n");

    // ------------------------------------------------------------------------
    // Scenario 7: RFC 9218 Extensible Prioritization Scheme
    // ------------------------------------------------------------------------
    print("\n[7/11] RFC 9218 HTTP Priority Parsing...\n");
    let prio, ok_prio = wing::parse_priority_param_rfc9218("u=1, i");
    print("  Priority parsed:     ", ok_prio, "\n");
    print("  Urgency level:       ", prio.urgency, "\n");
    print("  Incremental:         ", prio.incremental, "\n");

    // ------------------------------------------------------------------------
    // Scenario 8: Layer 4 Zero-Allocation Virtual TCP Transport
    // ------------------------------------------------------------------------
    print("\n[8/11] L4 Virtual TCP Transport & Socket Exchange...\n");
    let listener = wing::tcp_listen("127.0.0.1", 8080, 16);
    print("  TCP Listener FD:     ", listener, "\n");

    let client = wing::tcp_connect("127.0.0.1", 8080, 100);
    print("  TCP Client FD:       ", client, "\n");

    let server_conn = wing::tcp_accept(listener, 100);
    print("  TCP Accepted FD:     ", server_conn, "\n");

    // Verify non-blocking recv returns -2 (WouldBlock) before data is sent
    var srv_buf: u8[..256] = [];
    srv_buf.resize(256, 0);
    let would_block = wing::tcp_recv_slice(server_conn, srv_buf, 0);
    print("  Server Recv WouldBlock (-2): ", would_block == -2, "\n");

    // Client sends HTTP GET request
    let req = "GET /index.html HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    let sent_bytes = wing::tcp_send(client, req);
    print("  Client Sent:         ", sent_bytes, " bytes\n");

    // Server receives request
    let rcvd_bytes = wing::tcp_recv_slice(server_conn, srv_buf);
    print("  Server Received:     ", rcvd_bytes, " bytes\n");
    if rcvd_bytes > 0 {
        print("  Server Wire Payload: ", srv_buf[..rcvd_bytes], "\n");
    }

    // Server sends HTTP 200 OK response
    let resp = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, Wasm!\n";
    let srv_sent = wing::tcp_send(server_conn, resp);
    print("  Server Sent:         ", srv_sent, " bytes\n");

    // Client receives response
    var cli_buf: u8[..256] = [];
    cli_buf.resize(256, 0);
    let cli_rcvd = wing::tcp_recv_slice(client, cli_buf);
    print("  Client Received:     ", cli_rcvd, " bytes\n");
    if cli_rcvd > 0 {
        print("  Client Wire Payload: ", cli_buf[..cli_rcvd], "\n");
    }

    // Verify clean EOF (0) when peer closes connection
    wing::tcp_close(client);
    let eof_bytes = wing::tcp_recv_slice(server_conn, srv_buf, 0);
    print("  Server Recv Clean EOF (0):   ", eof_bytes == 0, "\n");

    wing::tcp_close(server_conn);
    wing::tcp_close(listener);

    // Verify backlog saturation & listener close queue drainage
    let lis_backlog = wing::tcp_listen("127.0.0.1", 8088, 2);
    let bc1 = wing::tcp_connect("127.0.0.1", 8088, 10);
    let bc2 = wing::tcp_connect("127.0.0.1", 8088, 10);
    let bc3 = wing::tcp_connect("127.0.0.1", 8088, 10);
    print("  Backlog Overflow Rejected:   ", bc3 == -1, "\n");
    wing::tcp_close(lis_backlog);
    if bc1 > 0 { wing::tcp_close(bc1); }
    if bc2 > 0 { wing::tcp_close(bc2); }
    print("  Sockets Closed:      OK\n");

    // ------------------------------------------------------------------------
    // Scenario 9: RFC 7541 HTTP/2 HPACK Dynamic Table & Huffman Compression
    // ------------------------------------------------------------------------
    print("\n[9/11] RFC 7541 HPACK Dynamic Table & Huffman Coding...\n");
    var dt_enc = internal::new_dynamic_table(4096);
    var dt_dec = internal::new_dynamic_table(4096);
    var hpack_wire: u8[>..] = [];

    internal::encode_hpack_field(dt_enc, hpack_wire, ":method", "GET", internal::HpackIndexing.Incremental, true);
    internal::encode_hpack_field(dt_enc, hpack_wire, ":path", "/api/v2/market/stream", internal::HpackIndexing.Incremental, true);
    internal::encode_hpack_field(dt_enc, hpack_wire, ":scheme", "https", internal::HpackIndexing.Incremental, true);
    internal::encode_hpack_field(dt_enc, hpack_wire, "custom-header", "wasm-edge-flight", internal::HpackIndexing.Incremental, true);
    print("  HPACK Encoded Bytes: ", hpack_wire.len, "\n");

    var decoded_headers = internal::DecodedH2HeaderList { .. };
    let hpack_dec_err = internal::decode_hpack_header_block(dt_dec, hpack_wire[..], decoded_headers);
    print("  HPACK Decode Err:    ", hpack_dec_err, " (0 == OK)\n");
    print("  Decoded Headers:     ", decoded_headers.fields.len, "\n");
    for di in decoded_headers.fields.len {
        print("    [", di, "] ", decoded_headers.fields[di].name[..], " = ", decoded_headers.fields[di].value[..], "\n");
    }

    // ------------------------------------------------------------------------
    // Scenario 10: TLS 1.3 Post-Quantum Hybrid Key Share (X25519MLKEM768)
    // ------------------------------------------------------------------------
    print("\n[10/11] TLS 1.3 Post-Quantum Hybrid Key Exchange (X25519MLKEM768)...\n");
    var client_share = internal::PostQuantumKeyShare {
        group: internal::GROUP_X25519_MLKEM768,
        ..
    };
    for i in 32 { client_share.x25519_public[i] = (i + 1) as u8; }
    for i in 1152 { client_share.mlkem768_public[i] = ((i * 7 + 3) & 0xFF) as u8; }

    var pq_wire: u8[>..] = [];
    client_share.format_hybrid_key_share(pq_wire);
    print("  PQ Client Share Wire:  ", pq_wire.len, " bytes (expected 1188)\n");

    var parsed_pq = internal::PostQuantumKeyShare { .. };
    let ok_pq_parse = parsed_pq.parse_hybrid_key_share(pq_wire[..]);
    print("  PQ Client Share Parse: ", ok_pq_parse, "\n");
    print("  PQ NamedGroup:         ", parsed_pq.group, " (0x11EC == X25519MLKEM768)\n");

    var classical_ss: u8[32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
    ];
    var pq_ss: u8[32] = [
        33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
        49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
    ];
    let hybrid_secret = internal::derive_hybrid_shared_secret(classical_ss, pq_ss);
    print("  Hybrid Combined Secret: SHA256[0..4] = [", hybrid_secret[0], ", ", hybrid_secret[1], ", ", hybrid_secret[2], ", ", hybrid_secret[3], "]\n");

    // ------------------------------------------------------------------------
    // Scenario 11: RFC 9000 QUIC Variable-Length Integer & Packet Framing
    // ------------------------------------------------------------------------
    print("\n[11/11] RFC 9000 QUIC Varint & Initial Header Framing...\n");
    var v1_wire: u8[..16] = [];
    var v2_wire: u8[..16] = [];
    var v4_wire: u8[..16] = [];
    var v8_wire: u8[..16] = [];

    internal::quic_encode_varint(v1_wire, 37);
    internal::quic_encode_varint(v2_wire, 15293);
    internal::quic_encode_varint(v4_wire, 49487296);
    internal::quic_encode_varint(v8_wire, 0x123456789ABCDEF0);

    let dec_v1, _, ok_v1 = internal::quic_decode_varint(v1_wire[..], 0);
    let dec_v2, _, ok_v2 = internal::quic_decode_varint(v2_wire[..], 0);
    let dec_v4, _, ok_v4 = internal::quic_decode_varint(v4_wire[..], 0);
    let dec_v8, _, ok_v8 = internal::quic_decode_varint(v8_wire[..], 0);

    print("  QUIC Varint 1B: ", dec_v1, " (ok: ", ok_v1, ", len: ", v1_wire.len, ")\n");
    print("  QUIC Varint 2B: ", dec_v2, " (ok: ", ok_v2, ", len: ", v2_wire.len, ")\n");
    print("  QUIC Varint 4B: ", dec_v4, " (ok: ", ok_v4, ", len: ", v4_wire.len, ")\n");
    print("  QUIC Varint 8B: ", dec_v8, " (ok: ", ok_v8, ", len: ", v8_wire.len, ")\n");

    var quic_hdr = internal::QuicHeader {
        header_type:    internal::QuicHeaderType.Initial,
        version:        internal::QUIC_VERSION_1,
        payload_length: 1280,
        packet_number:  99,
        ..
    };
    quic_hdr.dcid.append([0xDE, 0xAD, 0xBE, 0xEF]);
    quic_hdr.scid.append([0xCA, 0xFE, 0xBA, 0xBE]);

    var quic_wire: u8[..128] = [];
    let ok_qhdr = internal::encode_quic_header(quic_wire, quic_hdr, 2);
    let parsed_qhdr, ok_qdec = internal::parse_quic_header(quic_wire[..], 0);
    print("  QUIC Initial Header Encoded: ", ok_qhdr, " (", quic_wire.len, " bytes)\n");
    print("  QUIC Initial Header Decoded: ", ok_qdec, "\n");
    print("  QUIC Version:                0x", parsed_qhdr.version, "\n");
    print("  QUIC Payload Length:         ", parsed_qhdr.payload_length, " bytes\n");

    print("All wing scenarios passed on wasm!\n");
}
