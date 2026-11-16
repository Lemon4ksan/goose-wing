// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Goose LIT Verification Suite: lit_dns_and_sockets
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// ============================================================================
// 1. verify_dns_https_svcb (1/6)
// ============================================================================
// CHECK: === [1/6] verify_dns_https_svcb ===

// tests/lit/verify_dns_https_svcb.goose
// Verification of RFC 9460 HTTPS/SVCB DNS wire parameter decoding,
// strictly ascending SvcParamKeys ordering, and uncompressed target names.
//

// Wire bridge to RFC 9460 SvcParams decoder
fn decode_svc_params_wire(buf: const u8[:]) -> i64 {
    if buf.len < 24 { return -1; }
    var rec = wing::HttpsRecord { .. };
    let ok = wing::parse_https_svc_params(buf, rec);
    if !ok { return -2; }
    return rec.port;
}

fn test_valid_svc_params() {
    var params_pkt: u8[>..] = [];
    // Key 1 (ALPN, len 6: "h2", "h3"), Key 3 (Port, len 2: 8443), Key 4 (IPv4Hint, len 4: 192.0.2.1)
    assert(wire_kit::parse_hex("000100060268320268330003000220FB00040004C0000201", params_pkt));

    var rec = wing::HttpsRecord { .. };
    let ok = wing::parse_https_svc_params(params_pkt[..], rec);
    assert(ok);
    assert(rec.alpns.len == 2);
    assert(rec.alpns[0] == "h2");
    assert(rec.alpns[1] == "h3");
    assert(rec.port == 8443);
    assert(rec.ipv4_hints.len == 1);
    assert(rec.ipv4_hints[0] == 0xC0000201);

    assert(wire_kit::verify_split_stream(params_pkt[..], -1, 8443, decode_svc_params_wire));
    assert(wire_kit::fuzz_payload(params_pkt[..], 100, decode_svc_params_wire));
    print("SVC_PARAMS_VALID: OK");
}

fn test_invalid_svc_params() {
    // 1. Out of order keys: Key 3 (Port) followed by Key 1 (ALPN)
    var out_of_order: u8[>..] = [];
    assert(wire_kit::parse_hex("0003000201BB00010003026832", out_of_order));
    var rec1 = wing::HttpsRecord { .. };
    assert(!wing::parse_https_svc_params(out_of_order[..], rec1));

    // 2. Duplicate key: Key 1 followed by Key 1
    var dup_keys: u8[>..] = [];
    assert(wire_kit::parse_hex("0001000302683200010003026833", dup_keys));
    var rec2 = wing::HttpsRecord { .. };
    assert(!wing::parse_https_svc_params(dup_keys[..], rec2));

    // 3. Invalid port length: 3 bytes instead of 2
    var bad_port_len: u8[>..] = [];
    assert(wire_kit::parse_hex("0003000301BB00", bad_port_len));
    var rec3 = wing::HttpsRecord { .. };
    assert(!wing::parse_https_svc_params(bad_port_len[..], rec3));

    // 4. Invalid IPv4 hint length: 3 bytes (not multiple of 4)
    var bad_ip4_len: u8[>..] = [];
    assert(wire_kit::parse_hex("00040003C00002", bad_ip4_len));
    var rec4 = wing::HttpsRecord { .. };
    assert(!wing::parse_https_svc_params(bad_ip4_len[..], rec4));

    // 5. Invalid no_default_alpn length: 1 byte instead of 0
    var bad_no_default: u8[>..] = [];
    assert(wire_kit::parse_hex("0002000100", bad_no_default));
    var rec5 = wing::HttpsRecord { .. };
    assert(!wing::parse_https_svc_params(bad_no_default[..], rec5));

    print("SVC_PARAMS_INVALID_REJECTED: OK");
}

fn test_full_dns_https_response() {
    // DNS response packet with 1 HTTPS record:
    // Header 12B: ID=0x5678, QR=1 (response), AA=1, RCODE=0, QDCOUNT=1, ANCOUNT=1
    // Question: example.com, Type=HTTPS (65 = 0x0041), Class=IN (1)
    // Answer: pointer 0xC00C -> example.com, Type=HTTPS, Class=IN, TTL=60, RDLENGTH=9
    // RDATA: Priority=1, TargetName="." (0x00, root), SvcParams=(Port=443)
    var resp_pkt: u8[>..] = [];
    assert(wire_kit::parse_hex("567881800001000100000000076578616d706c6503636f6d0000410001C00C004100010000003C00090001000003000201BB", resp_pkt));

    var resp = wing::DnsResponse { .. };
    let ok = wing::parse_dns_response(resp_pkt[..], resp);
    assert(ok);
    assert(resp.https_records.len == 1);
    assert(resp.https_records[0].priority == 1);
    assert(resp.https_records[0].port == 443);
    assert(resp.https_records[0].target_name == "");

    // RFC 9460 §2.5.1: HTTPS TargetName containing compression pointer must be rejected
    var bad_https_wire: u8[>..] = [];
    assert(wire_kit::parse_hex("567881800001000100000000076578616d706c6503636f6d0000410001C00C004100010000003C00040001C00C", bad_https_wire));
    var resp_bad = wing::DnsResponse { .. };
    assert(!wing::parse_dns_response(bad_https_wire[..], resp_bad));

    print("DNS_HTTPS_RESPONSE: OK");
}

fn run_01_verify_dns_https_svcb() {
    test_valid_svc_params();
    test_invalid_svc_params();
    test_full_dns_https_response();
    print("DNS_HTTPS_SVCB: ALL INVARIANTS PASS");
}

// CHECK: SVC_PARAMS_VALID: OK
// CHECK: SVC_PARAMS_INVALID_REJECTED: OK
// CHECK: DNS_HTTPS_RESPONSE: OK
// CHECK: DNS_HTTPS_SVCB: ALL INVARIANTS PASS

// ============================================================================
// 2. verify_masque_dns_edge (2/6)
// ============================================================================
// CHECK: === [2/6] verify_masque_dns_edge ===

// tests/lit/verify_masque_dns_edge.goose
// Verification of RFC 9297 MASQUE capsules and RFC 1035 DNS compression pointers via wing::net.
//

// Wire adapter for verify_split_stream and fuzzing using wing's real parse_http_capsule
fn wing_validate_masque_capsule_wire(buf: const u8[:]) -> i64 {
    let cap, ok = wing::parse_http_capsule(buf);
    if ok {
        return cap.payload.len;
    }
    return -1;
}

fn wing_validate_dns_pointer_wire(buf: const u8[:], start_off: i64) -> i32 {
    var out: u8[..256] = [];
    var off = start_off;
    let ok = wing::dns_decode_name(buf, off, out);
    if ok {
        return 0;
    }
    return -2;
}

fn validate_svcb_target_wire(buf: const u8[:], start_off: i64) -> i32 {
    let len = buf.len;
    var cur = start_off;
    while cur < len {
        let b = buf[cur];
        if b == 0 { return 1; }
        if (b & 192) != 0 { return -2; }
        if b > 63 { return -3; }
        cur += 1 + b;
        if cur > len { return -1; }
    }
    return -1;
}

fn run_02_verify_masque_dns_edge() {
    var raw_cap: u8[>..] = [];
    assert(wire_kit::parse_hex("000568656C6C6F", raw_cap));
    assert(wire_kit::verify_split_stream(raw_cap[..], -1, 5, wing_validate_masque_capsule_wire));
    assert(wire_kit::fuzz_payload(raw_cap[..], 100, wing_validate_masque_capsule_wire));
    print("MASQUE_CAPSULE: OK");

    var ovf_cap: u8[>..] = []; wire_kit::parse_hex("00C0000000FFFFFFFF", ovf_cap);
    assert(wing_validate_masque_capsule_wire(ovf_cap[..]) == -1);
    print("MASQUE_OVF: OK");

    var dns_ok: u8[>..] = []; wire_kit::parse_hex("123481800001000100000000076578616d706c6503636f6d0000010001c00c", dns_ok);
    assert(wing_validate_dns_pointer_wire(dns_ok[..], 29) == 0);

    var dns_fwd: u8[>..] = []; wire_kit::parse_hex("123481800001000100000000076578616d706c6503636f6d0000010001c023", dns_fwd);
    assert(wing_validate_dns_pointer_wire(dns_fwd[..], 29) == -2);

    var dns_hdr: u8[>..] = []; wire_kit::parse_hex("123481800001000100000000076578616d706c6503636f6d0000010001c004", dns_hdr);
    assert(wing_validate_dns_pointer_wire(dns_hdr[..], 29) == -2);

    var dns_loop: u8[>..] = []; wire_kit::parse_hex("123481800001000100000000076578616d706c6500c015", dns_loop);
    assert(wing_validate_dns_pointer_wire(dns_loop[..], 29) == -2);
    print("DNS_POINTERS: OK");

    var svcb_ok: u8[>..] = []; wire_kit::parse_hex("076578616d706c6500", svcb_ok);
    assert(validate_svcb_target_wire(svcb_ok[..], 0) == 1);

    var svcb_bad: u8[>..] = []; wire_kit::parse_hex("c00c", svcb_bad);
    assert(validate_svcb_target_wire(svcb_bad[..], 0) == -2);
    print("SVCB_POINTERS: OK");
}

// CHECK: MASQUE_CAPSULE: OK
// CHECK: MASQUE_OVF: OK
// CHECK: DNS_POINTERS: OK
// CHECK: SVCB_POINTERS: OK

// ============================================================================
// 3. verify_l4_sockets (3/6)
// ============================================================================
// CHECK: === [3/6] verify_l4_sockets ===

enum SocketState {
    Closed,
    Listening,
    Connected,
}

struct L4Socket {
    id:      i32              = 0,
    port:    u16              = 0,
    state:   SocketState      = SocketState.Closed,
    peer_id: i32              = 0,
    rx_ring: core::RingBuffer = core::RingBuffer { .. },
}

struct L4Subsystem {
    sockets: L4Socket[8] = [
        L4Socket {}, L4Socket {}, L4Socket {}, L4Socket {},
        L4Socket {}, L4Socket {}, L4Socket {}, L4Socket {},
    ],
    next_id: i32 = 1,
}

fn tcp_listen(sub: L4Subsystem&, port: u16) -> i32 {
    let id = sub.next_id;
    sub.next_id += 1;
    sub.sockets[id].id = id;
    sub.sockets[id].port = port;
    sub.sockets[id].state = SocketState.Listening;
    return id;
}

fn tcp_connect(sub: L4Subsystem&, port: u16) -> i32 {
    let cli_id = sub.next_id;
    sub.next_id += 1;
    sub.sockets[cli_id].id = cli_id;
    sub.sockets[cli_id].port = port;
    sub.sockets[cli_id].state = SocketState.Connected;
    return cli_id;
}

fn tcp_accept(sub: L4Subsystem&, lis_id: i32) -> i32 {
    assert(sub.sockets[lis_id].state == SocketState.Listening);
    let srv_id = sub.next_id;
    sub.next_id += 1;
    sub.sockets[srv_id].id = srv_id;
    sub.sockets[srv_id].port = sub.sockets[lis_id].port;
    sub.sockets[srv_id].state = SocketState.Connected;
    return srv_id;
}

fn tcp_send(sub: L4Subsystem&, sock_id: i32, data: const u8[:]) -> i32 {
    assert(sub.sockets[sock_id].state == SocketState.Connected);
    let n, err = core::write(sub.sockets[sock_id].rx_ring, data);
    assert(err == core::IoError.None);
    return n as! i32;
}

fn tcp_recv(sub: L4Subsystem&, sock_id: i32, out: u8[:]) -> i32 {
    assert(sub.sockets[sock_id].state == SocketState.Connected);
    let n, err = core::read(sub.sockets[sock_id].rx_ring, out);
    assert(err == core::IoError.None || err == core::IoError.Eof);
    return n as! i32;
}

fn tcp_close(sub: L4Subsystem&, sock_id: i32) {
    sub.sockets[sock_id].state = SocketState.Closed;
    core::clear(sub.sockets[sock_id].rx_ring);
}

fn test_proxy_protocol_wire_ingress() {
    // PROXY v1 text ingress
    let v1_wire = "PROXY TCP4 203.0.113.195 198.51.100.1 56324 443\r\nPING-PONG-TEST";
    var v1_hdr = wing::ProxyHeader { .. };
    let app_stream, ok1 = wing::detect_and_strip_proxy_header(v1_wire, v1_hdr);
    assert(ok1);
    assert(v1_hdr.version == wing::ProxyProtocolVersion.V1);
    assert(v1_hdr.family == wing::ProxyAddressFamily.Inet4);
    assert(v1_hdr.src_port == 56324);
    assert(v1_hdr.dst_port == 443);
    assert(app_stream == "PING-PONG-TEST");

    // PROXY v2 binary ingress
    var v2_hdr_orig = wing::ProxyHeader {
        version:   wing::ProxyProtocolVersion.V2,
        command:   wing::ProxyCommand.Proxy,
        family:    wing::ProxyAddressFamily.Inet4,
        transport: wing::ProxyTransportProtocol.Stream,
        src_ipv4:  [192, 168, 1, 50],
        dst_ipv4:  [10, 0, 0, 1],
        src_port:  8080,
        dst_port:  80,
    };
    var v2_wire: u8[..512] = [];
    assert(wing::format_proxy_v2(v2_hdr_orig, v2_wire));
    v2_wire.append("PONG-REPLY-OK!");

    var v2_hdr_parsed = wing::ProxyHeader { .. };
    let v2_app, ok2 = wing::detect_and_strip_proxy_header(v2_wire[..], v2_hdr_parsed);
    assert(ok2);
    assert(v2_hdr_parsed.version == wing::ProxyProtocolVersion.V2);
    assert(v2_hdr_parsed.src_port == 8080);
    assert(v2_hdr_parsed.dst_port == 80);
    assert(v2_app == "PONG-REPLY-OK!");
}

fn run_03_verify_l4_sockets() {
    test_proxy_protocol_wire_ingress();

    var sub = L4Subsystem {};
    let lis = tcp_listen(sub, 9001);
    assert(lis > 0);
    print("LIS_SOCKET: ", lis);

    let cli = tcp_connect(sub, 9001);
    assert(cli > 0);
    print("CLI_SOCKET: ", cli);

    let srv = tcp_accept(sub, lis);
    assert(srv > 0);
    print("SRV_SOCKET: ", srv);

    let sent = tcp_send(sub, cli, "PING-PONG-TEST");
    assert(sent == 14);

    var rcv_buf: u8[14] = [0; 14];
    let rcvd = tcp_recv(sub, cli, rcv_buf[..]);
    assert(rcvd == 14);
    assert(rcv_buf[0] == 80 && rcv_buf[1] == 73 && rcv_buf[2] == 78 && rcv_buf[3] == 71); // "PING"
    assert(rcv_buf[13] == 84); // "T"
    print("RECV_CLIENT: ", rcvd, " BYTES");

    let reply_sent = tcp_send(sub, srv, "PONG-REPLY-OK!");
    assert(reply_sent == 14);

    var reply_buf: u8[14] = [0; 14];
    let reply_rcvd = tcp_recv(sub, srv, reply_buf[..]);
    assert(reply_rcvd == 14);
    assert(reply_buf[0] == 80 && reply_buf[1] == 79 && reply_buf[2] == 78 && reply_buf[3] == 71); // "PONG"
    print("RECV_REPLY: ", reply_rcvd, " BYTES");

    tcp_close(sub, cli);
    tcp_close(sub, srv);
    tcp_close(sub, lis);
    print("L4_SOCKETS: ALL CLOSED OK");
}

// CHECK: LIS_SOCKET: 1
// CHECK: CLI_SOCKET: 2
// CHECK: SRV_SOCKET: 3
// CHECK: RECV_CLIENT: 14 BYTES
// CHECK: RECV_REPLY: 14 BYTES
// CHECK: L4_SOCKETS: ALL CLOSED OK

// ============================================================================
// 4. verify_udp_batch (4/6)
// ============================================================================
// CHECK: === [4/6] verify_udp_batch ===

// Native LIT verification suite for Ring-Zero L4 & Wire Engine:
// - Task #1: Batched UDP & GSO Engine (`UdpBatchQueue`, `batch_send_messages`, `batch_recv_messages`, auto-flush on 33rd packet)
// - Task #2: Linux `io_uring` Provided Buffer Ring (`uring_register_buf_ring` power-of-2 & bounds validation)
// - Task #3: Windows RIO `RioAddressPool` O(1) free-list acquire/release and fail-closed exhaustion at 129th acquire
// - Task #4: Upstream Pool (`UpstreamPool`) NIK partition isolation and `EPOLLRDHUP` (`0x2000`) idle closure eviction
// - Task #5: Canonical HTTP/2 frame reader (`read_wire_h2_frame` over `const u8[:]` + `cursor: i64&`) with transactional cursor

inline fn advance_test_loop_idx(idx: i32) -> i32 {
    return idx + 1;
}

fn verify_udp_batch_engine() {
    var queue = wing::UdpBatchQueue { .. };
    print("WING_UDP_BATCH_INITIALIZED: capacity=", wing::UDP_BATCH_CAPACITY, "\n");

    let payload = "QUIC-SHORT-HEADER-FRAME-PAYLOAD-1200";
    let dgram, build_ok = wing::build_udp_datagram(payload, 0x0100007F, 4433, 1200);
    assert(build_ok);
    assert(dgram.gso_size == 1200);

    // Negative test: oversize UDP datagram (> 1472 bytes) must be rejected (Invariant 13)
    var oversize_buf: u8[1500] = [0x41; 1500];
    let _, ovf_ok = wing::build_udp_datagram(oversize_buf[..], 0x0100007F, 4433, 0);
    if ovf_ok {
        print("WING_BUFFER_OVERFLOW_SILENT_DROP\n");
    }
    assert(!ovf_ok);

    // Enqueue 32 datagrams without triggering an intermediate flush
    var i: i32 = 0;
    while i < 32 {
        let flushed, enq_ok = wing::enqueue_udp_datagram(0, queue, dgram);
        assert(enq_ok);
        assert(flushed == 0);
        i = advance_test_loop_idx(i);
    }
    assert(queue.count == 32);
    assert(queue.flushed_batches == 0);

    // Enqueue 33rd datagram: must automatically flush the 32 queued datagrams before buffering packet 33
    let flushed_on_33, ok_33 = wing::enqueue_udp_datagram(0, queue, dgram);
    if !ok_33 || flushed_on_33 != 32 || queue.count != 1 {
        print("WING_BUFFER_OVERFLOW_SILENT_DROP\n");
    }
    assert(ok_33);
    assert(flushed_on_33 == 32);
    assert(queue.count == 1);
    assert(queue.flushed_batches == 1);
    assert(queue.total_sent == 32);
    print("UDP_BATCH_AUTO_FLUSH_33RD: flushed=", flushed_on_33, " remaining=", queue.count, "\n");

    // Flush the remaining 1 datagram explicitly
    let final_sent, final_ok = wing::batch_send_messages(0, queue);
    assert(final_ok && final_sent == 1 && queue.count == 0);

    // Verify batch_recv_messages on virtual descriptor 0 and negative fd rejection
    let recvd, recv_ok = wing::batch_recv_messages(0, queue);
    assert(recv_ok && recvd == 0);
    let _, bad_recv_ok = wing::batch_recv_messages(-1, queue);
    assert(!bad_recv_ok);
    let _, bad_send_ok = wing::batch_send_messages(-1, queue);
    assert(!bad_send_ok);
    print("UDP_BATCH_RECV_AND_BOUNDS: OK\n");
}

fn verify_uring_pbuf_ring() {
    // Negative tests: non-power-of-2 entries (0, 3, 100), negative ring_fd
    assert(!net_internal::uring_register_buf_ring(1, 0, 1));
    assert(!net_internal::uring_register_buf_ring(1, 3, 1));
    assert(!net_internal::uring_register_buf_ring(1, 100, 1));
    assert(!net_internal::uring_register_buf_ring(1, 40000, 1));
    assert(!net_internal::uring_register_buf_ring(-1, 128, 1));

    // Positive power-of-2 validator check
    assert(net_internal::is_valid_pbuf_ring_entries(1));
    assert(net_internal::is_valid_pbuf_ring_entries(64));
    assert(net_internal::is_valid_pbuf_ring_entries(1024));
    assert(net_internal::is_valid_pbuf_ring_entries(32768));
    assert(!net_internal::is_valid_pbuf_ring_entries(32769));
    print("URING_PBUF_RING_VALIDATION: OK\n");
}

fn verify_rio_address_pool() {
    var pool = net_internal::RioAddressPool { .. };
    assert(net_internal::rio_init_address_pool(pool, 0xCAFE0001));
    assert(pool.initialized && pool.active_count == 0);

    // Acquire all 128 pre-registered address descriptors in O(1)
    var k: i32 = 0;
    while k < 128 {
        let slot_idx, buf_desc, ok = net_internal::rio_acquire_address_buf(pool);
        assert(ok);
        assert(slot_idx == k);
        assert(buf_desc.length == 28);
        k = advance_test_loop_idx(k);
    }
    assert(pool.active_count == 128);

    // 129th acquire MUST fail closed (Invariant 13)
    let _, _, ok_129 = net_internal::rio_acquire_address_buf(pool);
    if ok_129 {
        print("WING_BUFFER_OVERFLOW_SILENT_DROP\n");
    }
    assert(!ok_129);
    print("RIO_ADDRESS_POOL_EXHAUSTION_129: REJECTED_OK\n");

    // Release descriptor 42 and re-acquire in O(1)
    assert(net_internal::rio_release_address_buf(pool, 42));
    assert(!net_internal::rio_release_address_buf(pool, 42)); // Double-release rejected
    assert(!net_internal::rio_release_address_buf(pool, -1));
    assert(!net_internal::rio_release_address_buf(pool, 128));

    let re_idx, _, re_ok = net_internal::rio_acquire_address_buf(pool);
    assert(re_ok && re_idx == 42);
    print("RIO_ADDRESS_POOL_RECYCLE: slot=", re_idx, "\n");
}

fn verify_upstream_pool_nik_and_rdhup() {
    var upool = wing::UpstreamPool { .. };
    let origin = wing::new_origin_endpoint("api.internal.example.com", 443);
    let tls_fp:       u64 = 0xAABBCCDDEEFF0011;
    let nik_tenant_a: u64 = 1001;
    let nik_tenant_b: u64 = 2002;

    assert(wing::register_upstream_conn(upool, 55, origin, tls_fp, nik_tenant_a));

    // Tenant B (different NIK) MUST NOT acquire Tenant A's warm socket
    let _, cross_nik_ok = wing::acquire_upstream_conn(upool, origin, tls_fp, nik_tenant_b);
    assert(!cross_nik_ok);
    print("UPSTREAM_POOL_NIK_ISOLATION: OK\n");

    // Tenant A acquires and releases its socket cleanly
    let fd_a, ok_a = wing::acquire_upstream_conn(upool, origin, tls_fp, nik_tenant_a);
    assert(ok_a && fd_a == 55);
    assert(wing::release_upstream_conn(upool, 55, 0));

    // Simulate kernel signaling EPOLLRDHUP (0x2000) while idle
    assert(wing::notify_upstream_epoll_events(upool, 55, wing::EPOLLRDHUP));
    assert(upool.evicted_rdhup == 1);

    // Subsequent acquire for Tenant A MUST NOT return the half-closed socket
    let _, stale_ok = wing::acquire_upstream_conn(upool, origin, tls_fp, nik_tenant_a);
    assert(!stale_ok);
    print("UPSTREAM_POOL_EPOLLRDHUP_EVICTION: evicted=", upool.evicted_rdhup, "\n");
}

fn verify_wire_h2_frame_slice_cursor() {
    var buf: u8[..64] = [];
    assert(wire::encode_window_update_frame(0, 2048, buf));
    let ping_payload: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
    assert(wire::encode_ping_frame(ping_payload, true, buf));

    var cursor: i64 = 0;
    let hdr1, pay1, ok1 = wire::read_wire_h2_frame(buf[..], cursor);
    assert(ok1 && hdr1.frame_type == rfc::H2_FRAME_WINDOW_UPDATE && pay1.len == 4 && cursor == 13);

    // Truncated frame test: slice off the last 2 bytes of the PING frame and verify cursor rollback
    let truncated_view = buf[..28];
    let saved_cursor = cursor;
    let _, _, trunc_ok = wire::read_wire_h2_frame(truncated_view, cursor);
    assert(!trunc_ok);
    assert(cursor == saved_cursor);

    // Full second frame read succeeds
    let hdr2, pay2, ok2 = wire::read_wire_h2_frame(buf[..], cursor);
    assert(ok2 && hdr2.frame_type == rfc::H2_FRAME_PING && pay2.len == 8 && cursor == 30);
    print("WIRE_H2_SLICE_CURSOR: cursor=", cursor, "\n");
}

fn run_04_verify_udp_batch() {
    // CHECK: WING_UDP_BATCH_INITIALIZED: capacity=32
    // CHECK-NOT: WING_BUFFER_OVERFLOW_SILENT_DROP
    // CHECK: UDP_BATCH_AUTO_FLUSH_33RD: flushed=32 remaining=1
    // CHECK: UDP_BATCH_RECV_AND_BOUNDS: OK
    // CHECK: URING_PBUF_RING_VALIDATION: OK
    // CHECK: RIO_ADDRESS_POOL_EXHAUSTION_129: REJECTED_OK
    // CHECK: RIO_ADDRESS_POOL_RECYCLE: slot=42
    // CHECK: UPSTREAM_POOL_NIK_ISOLATION: OK
    // CHECK: UPSTREAM_POOL_EPOLLRDHUP_EVICTION: evicted=1
    // CHECK: WIRE_H2_SLICE_CURSOR: cursor=30
    verify_udp_batch_engine();
    verify_uring_pbuf_ring();
    verify_rio_address_pool();
    verify_upstream_pool_nik_and_rdhup();
    verify_wire_h2_frame_slice_cursor();
}

// ============================================================================
// 5. verify_net_audit (5/6)
// ============================================================================
// CHECK: === [5/6] verify_net_audit ===

// tests/lit/verify_net_audit.goose
// Regression test suite for net/ bug-hunter findings F001..F011.
//

var g_reentrant_ran: i32 = 0;

fn reentrant_task_cb(tag: u64, user_data: u64, task_id: u32, el: wing::EventLoop&) {
    if tag == 101 {
        let _ = wing::defer_task(el, 202, 0, 2);
    } else if tag == 202 {
        g_reentrant_ran = 1;
    }
}

fn verify_iocomp_track_e(p_cfg: const net_internal::TransportDriverConfig&) {
    assert(net_internal::URING_OP_SEND_ZC == 47);
    assert(net_internal::URING_CQE_F_NOTIF == 8);
    assert(net_internal::URING_RECV_MULTISHOT == 2);

    var r_state = net_internal::new_ring_queue_state(32);
    assert(net_internal::uring_prep_recv_multishot(r_state, 10, 7, 1234));
    assert(r_state.staged_sqes[0].buf_index == 7 && r_state.staged_sqes[0].ioprio == net_internal::URING_RECV_MULTISHOT);

    var br = net_internal::UringBufRing { .. };
    net_internal::uring_buf_ring_recycle(br, 5, 0x1000, 2048);
    assert(br.tail == 1 && br.entries[0].bid == 5);
    let cqe_buf = net_internal::UringCqe { user_data: 1, res: 64, flags: (5 << 16) | net_internal::URING_CQE_F_BUFFER };
    let sel_bid, has_bid = net_internal::extract_uring_cqe_buffer_id(cqe_buf);
    assert(has_bid && sel_bid == 5);

    var rio_res: net_internal::RioResult[..64] = [];
    let _ = net_internal::rio_drain_completions(0, rio_res);
    rio_res.push(net_internal::RioResult { status: 0, bytes_transferred: 128, socket_context: 9001, request_context: 1 });
    var p_rio = wing::new_poller(p_cfg);
    wing::register_socket(p_rio, 88, 9001, core::PollInterest.Read, core::PollTrigger.Level);
    var rio_evs: core::PollReadyEvent[..64] = [];
    let mapped_rio = wing::rio_map_completions_to_events(p_rio, rio_res[..], rio_evs);
    assert(mapped_rio == 1 && rio_evs[0].fd == 88 && rio_evs[0].bytes_available == 128);
    wing::close_poller(p_rio);

    let sock_opts = net_internal::SocketOptions {
        keepalive_idle_secs:      60,
        keepalive_interval_secs:  10,
        keepalive_probes:         3,
        ipv6_only:                true,
        win_skip_iocp_on_success: true,
        ..
    };
    assert(net_internal::apply_socket_options(-1, sock_opts));

    var dpdk_ctx = net_internal::DpdkContext { .. };
    let mbuf_batch: u64[5] = [101, 102, 103, 104, 105];
    let staged_dpdk = net_internal::dpdk_stage_tx_burst(dpdk_ctx, mbuf_batch[..]);
    assert(staged_dpdk == 5 && dpdk_ctx.tx_burst[4] == 105);

    var xsk_ring = net_internal::XskRingState { prod_head: 62, cons_head: 60, .. };
    let xsk_enq = net_internal::xsk_fill_ring_enqueue_burst(xsk_ring, mbuf_batch[..]);
    assert(xsk_enq == 5 && xsk_ring.entries[62] == 101 && xsk_ring.entries[0] == 103);

    var fmt_dict: u8[..64] = [0x37, 0xA4, 0x30, 0xEC, 0x01, 0x00, 0x00, 0x00];
    fmt_dict.append("shared-dictionary-prefix-content-for-rfc9842-dcz!");
    let plain_dcz = "shared-dictionary-prefix-content-for-rfc9842-dcz! trailing payload";
    let dict_sha = core::sha256(fmt_dict[..]);
    var dcz_wire: u8[..512] = [];
    assert(wing::encode_dcz_response(dcz_wire, dict_sha, plain_dcz, fmt_dict[..]));
    var parsed_sha: u8[32] = [0; 32];
    let dcz_zstd, dcz_hdr_ok = wing::decode_dcz_header(dcz_wire[..], parsed_sha);
    assert(dcz_hdr_ok && core::ct_eq_bytes(parsed_sha[..], dict_sha[..]));
    var dcz_decoded: u8[..512] = [];
    assert(wing::decompress_dcz_payload(dcz_zstd, fmt_dict[..], dcz_decoded));
    assert(dcz_decoded[..] == plain_dcz);

    var z_frames: u8[..512] = [];
    assert(core::zstd_compress("frame-one|", z_frames));
    assert(core::zstd_compress("frame-two", z_frames));
    var z_stream = core::new_zstream_decompressor(core::ContainerFormat.Zstd);
    var z_stream_out: u8[..512] = [];
    let z_err1 = core::zstream_decompress_write_limit(z_stream, z_frames[..10], z_stream_out, 512);
    assert(z_err1 == core::CompressError.None);
    let z_err2 = core::zstream_decompress_write_limit(z_stream, z_frames[10..], z_stream_out, 512);
    assert(z_err2 == core::CompressError.None && z_stream_out[..] == "frame-one|frame-two");

    var zc = core::new_zstream_compressor(core::ContainerFormat.Zlib, 6);
    var zc_out: u8[..128] = [];
    assert(core::write(zc, "hello", zc_out));
    assert(core::sync_flush(zc, zc_out));
    assert(core::full_flush(zc, zc_out));
    assert(core::finish(zc, zc_out));
    print("IOCOMP_TRACK_E_OK: 1");
}

fn run_05_verify_net_audit() {
    // F001: tick_timer_arm u8 wrap-around when current_tick + delay_sec >= 256
    var wheel = core::TickTimerWheel { current_tick: 200, .. };
    let target_slot = core::tick_timer_arm(wheel, 60);
    assert(target_slot == 20);
    print("F001_TICK_SLOT: ", target_slot);

    // F002: uniform_random i64 overflow when max_val - min_val == i64::MAX
    var seed: u64 = 42;
    let ur = wing::uniform_random(seed, 0, 9223372036854775807);
    assert(ur >= 0);
    let cfg_neg = wing::BackoffConfig {
        base_ms:  0,
        cap_ms:   -500,
        strategy: wing::JitterStrategy.DecorrelatedJitter,
    };
    var prev_sleep: i64 = 4000000000000000000;
    let backoff_neg = wing::compute_backoff_jitter_ms(cfg_neg, 1, prev_sleep, seed);
    assert(backoff_neg == 0);
    print("F002_BACKOFF_OK: ", backoff_neg);

    // F003: CircuitBreaker expired slot reclamation on 17th host and >256B host rejection
    var breaker = wing::new_host_circuit_breaker(1000);
    for i in 16 {
        var h: u8[..32] = [];
        h.append("host-");
        h.push(('a' + i) as u8);
        h.append(".example.com");
        let tripped = wing::trip_circuit_breaker_if_exceeded(breaker, h[..], 2000, 1000);
        assert(tripped);
    }
    // At t = 5000000000 (5s > 2s cooldown), all 16 entries have expired.
    // Tripping a 17th host must reclaim an expired slot so is_host_circuit_broken returns true.
    let tripped17 = wing::trip_circuit_breaker_if_exceeded(breaker, "host-17.example.com", 2000, 5000000000);
    assert(tripped17);
    let broken17 = wing::is_host_circuit_broken(breaker, "host-17.example.com", 5500000000);
    assert(broken17);
    print("F003_BREAKER_17: ", if broken17 { 1 } else { 0 });

    // F004: Pool active connection protection on EPOLLRDHUP, release idempotency, and case-folded hash
    var up_pool = wing::UpstreamPool { .. };
    var ep = wing::OriginEndpoint { port: 8080, .. };
    ep.host.append("10.0.0.1");
    assert(wing::register_upstream_conn(up_pool, 0, ep, 111, 222));
    let acq_fd, acq_ok = wing::acquire_upstream_conn(up_pool, ep, 111, 222);
    assert(acq_ok && acq_fd == 0);
    // Delivering EPOLLRDHUP while in_use == true must NOT evict the active entry while borrowed
    let _ = wing::notify_upstream_epoll_events(up_pool, 0, wing::EPOLLRDHUP);
    assert(up_pool.entries[0].in_use && up_pool.entries[0].healthy);

    // Case-insensitive pool_key_hash when PoolKey constructed with mixed-case host
    var pk_upper = wing::PoolKey { scheme: wing::PoolScheme.Https, .. };
    pk_upper.origin_endpoint.host.append("API.EXAMPLE.COM");
    pk_upper.origin_endpoint.port = 443;
    var pk_lower = wing::PoolKey { scheme: wing::PoolScheme.Https, .. };
    pk_lower.origin_endpoint.host.append("api.example.com");
    pk_lower.origin_endpoint.port = 443;
    assert(wing::pool_key_equals(pk_upper, pk_lower));
    assert(wing::pool_key_hash(pk_upper) == wing::pool_key_hash(pk_lower));

    // Double release_connection must not underflow active_conns or double-increment idle_conns
    var sp = wing::new_stream_pool(6, 32, 4);
    let cid = wing::register_connection(sp, pk_lower, wing::NegotiatedProtocol.Http11, "1.1.1.1", 1, 1000);
    wing::release_connection(sp, cid, 2000);
    wing::release_connection(sp, cid, 3000);
    let g_idx = wing::find_group_index(sp, pk_lower);
    assert(g_idx >= 0);
    assert(sp.groups[g_idx].active_conns == 0);
    assert(sp.groups[g_idx].idle_conns == 1);
    print("F004_POOL_OK: ", sp.groups[g_idx].idle_conns);

    // F005: Poller coarse timeout preserved when out_events full, re-entrant defer_task, and bounded consume_read
    var p_cfg = net_internal::auto_transport_driver_config();
    var poller = wing::new_poller(p_cfg);
    wing::register_socket(poller, 50, 7001, core::PollInterest.Read, core::PollTrigger.Level);
    wing::set_socket_timeout(poller, 50, 4);
    var full_evs: core::PollReadyEvent[..64] = [];
    let _ = wing::poll_events(poller, 0, 1000000000, full_evs);
    for _ in 64 {
        full_evs.push(core::PollReadyEvent { .. });
    }
    // Advance 5 seconds with full (64/64) event buffer: timeout must NOT be lost!
    let c_full = wing::check_coarse_timeouts(poller, 6000000000, full_evs);
    assert(c_full == 0);
    assert(wing::get_socket_timeout(poller, 50) != wing::COARSE_TIMEOUT_DISABLED);
    wing::close_poller(poller);

    var el = wing::new_event_loop(p_cfg);
    let _ = wing::bind_connection(el, 30, 5001, core::PollInterest.Read);
    let _ = wing::feed_read(el, 5001, "0123456789");
    var small_out: u8[..4] = [];
    let consumed1 = wing::consume_read(el, 5001, small_out);
    assert(consumed1 == 4 && small_out[..] == "0123");
    var rest_out: u8[..16] = [];
    let consumed2 = wing::consume_read(el, 5001, rest_out);
    assert(consumed2 == 6 && rest_out[..] == "456789");

    let _ = wing::defer_task(el, 101, 0, 1);
    let _ = wing::drain_deferred_tasks(el, reentrant_task_cb);
    let _ = wing::drain_deferred_tasks(el, reentrant_task_cb);
    assert(g_reentrant_ran == 1);
    wing::close_event_loop(el);
    print("F005_POLLER_OK: ", g_reentrant_ran);

    // F006: MASQUE transactional capacity check on encode_http_capsule and out_packet clear in receive_capsule
    var tiny_cap: u8[..4] = [];
    let cap_ok = wing::encode_http_capsule(tiny_cap, rfc::CAPSULE_DATAGRAM, "0123456789");
    assert(!cap_ok && tiny_cap.len == 0);

    var tun = wing::new_connect_udp_tunnel("https://proxy.org", "1.1.1.1", 53);
    tun.state = wing::MasqueTunnelState.Established;
    var wire_dg: u8[..64] = [];
    assert(wing::encode_connect_udp_datagram_capsule(wire_dg, 0, "hello"));
    var recv_buf: u8[..16] = [];
    recv_buf.append("STALE_PREFIX_");
    assert(wing::receive_capsule(tun, wire_dg[..], recv_buf));
    assert(recv_buf[..] == "hello");
    print("F006_MASQUE_LEN: ", recv_buf.len);

    // F007: HTTP CONNECT status line space in header and split-chunk CRLFCRLF in HeaderReader
    let spoofed_connect = "HTTP/1.1\r\nX-Spoof: 200 OK\r\n\r\n";
    let spoof_err = wing::verify_connect_tunnel_response(spoofed_connect, 0);
    assert(spoof_err == wing::ConnectTunnelError.MalformedHeaders);

    let sl_cfg = wing::SlowlorisDefenseConfig { .. };
    var h_reader = wing::new_header_reader(sl_cfg, 0);
    let v_part1 = wing::feed_header_bytes(h_reader, "HTTP/1.1 200 OK\r\nHost: a\r\n", 1000000);
    assert(v_part1 == wing::SlowlorisViolation.None && !h_reader.headers_complete);
    let v_part2 = wing::feed_header_bytes(h_reader, "\r\n", 2000000);
    assert(v_part2 == wing::SlowlorisViolation.None && h_reader.headers_complete);
    print("F007_CONNECT_OK: ", if h_reader.headers_complete { 1 } else { 0 });

    // F008: PROXY v1 leading zeros / double spaces rejection and format_proxy_v2 bounded buffer guard
    let _, _, ok_lead_zero_ip = wing::parse_proxy_v1("PROXY TCP4 010.0.0.1 10.0.0.2 5000 80\r\n");
    assert(!ok_lead_zero_ip);
    let _, _, ok_lead_zero_port = wing::parse_proxy_v1("PROXY TCP4 10.0.0.1 10.0.0.2 05000 80\r\n");
    assert(!ok_lead_zero_port);
    let _, _, ok_double_space = wing::parse_proxy_v1("PROXY  TCP4 10.0.0.1 10.0.0.2 5000 80\r\n");
    assert(!ok_double_space);

    var phdr = wing::ProxyHeader {
        version:   wing::ProxyProtocolVersion.V2,
        command:   wing::ProxyCommand.Proxy,
        family:    wing::ProxyAddressFamily.Inet4,
        transport: wing::ProxyTransportProtocol.Stream,
        src_ipv4:  [10, 0, 0, 1],
        dst_ipv4:  [10, 0, 0, 2],
        src_port:  1234,
        dst_port:  80,
        ..
    };
    var tiny_v2: u8[..8] = [];
    let v2_ok = wing::format_proxy_v2(phdr, tiny_v2);
    assert(!v2_ok && tiny_v2.len == 0);
    print("F008_PROXY_OK: 1");

    // F009: DNS label validation, RFC 9460 mandatory SvcParam verification, and DnsResponse reuse
    assert(!core::validate_idna_domain_bounds("-bad.example.com"));
    assert(!core::validate_idna_domain_bounds("bad-.example.com"));
    assert(!core::validate_idna_domain_bounds("bad space.example.com"));

    // Mandatory key 0x0003 (port) declared in Key 0, but Key 3 is missing from SvcParams
    let missing_mandatory_params: const u8[6] = [0x00, 0x00, 0x00, 0x02, 0x00, 0x03];
    var h_rec = wing::HttpsRecord { .. };
    let mand_ok = wing::parse_https_svc_params(missing_mandatory_params[..], h_rec);
    assert(!mand_ok);
    print("F009_DNS_OK: ", if !mand_ok { 1 } else { 0 });

    // F010: Happy Eyeballs start_attempt_race state reset on reuse & Isolation key content comparison
    var he_mgr = wing::new_attempt_manager(250);
    var cands: wing::DnsCandidate[..2] = [];
    cands.push(wing::new_dns_candidate(wing::AddressFamily.IPv6, "2001:db8::1", 443));
    wing::start_attempt_race(he_mgr, cands[..], 0);
    assert(he_mgr.attempts.len == 1);
    wing::start_attempt_race(he_mgr, cands[..], 100);
    assert(he_mgr.attempts.len == 1);

    var site1: u8[..32] = [];
    site1.append("https://example.com");
    var site2: u8[..32] = [];
    site2.append("https://example.com");
    let nik = wing::new_network_isolation_key(site1[..], site2[..]);
    assert(!nik.is_cross_site);

    // Exercise late DNS candidate injection, MASQUE QUIC datagram ingress, Poller helpers, and L4 driver APIs
    var late_q: wing::DnsCandidate[..32] = [];
    wing::inject_late_dns_candidates(late_q, cands[..]);
    assert(late_q.len == 1);

    var dgram_wire: u8[..64] = [];
    let dgram_enc_ok = wing::encode_http_datagram(dgram_wire, tun.quarter_stream_id, 0, "quux");
    assert(dgram_enc_ok);
    var dgram_out: u8[..32] = [];
    let dgram_rx_ok = wing::receive_quic_datagram(tun, dgram_wire[..], dgram_out);
    assert(dgram_rx_ok && dgram_out[..] == "quux");

    var p2 = wing::new_poller(p_cfg);
    wing::register_socket(p2, 60, 8001, core::PollInterest.Read, core::PollTrigger.Level);
    assert(wing::find_by_tag(p2, 8001) >= 0);
    assert(wing::simulate_error(p2, 60));
    wing::close_poller(p2);

    var el2 = wing::new_event_loop(p_cfg);
    let _ = wing::bind_connection(el2, 61, 8002, core::PollInterest.Read);
    assert(wing::set_connection_timeout(el2, 8002, 8));
    wing::close_event_loop(el2);

    assert(!wing::tcp_set_reuseport(-1, true));
    assert(!wing::epoll_mod(-1, 1, wing::EPOLL_READ, 0));
    wing::tcp_cleanup();

    let probe_res = net_internal::probe_transport_driver(net_internal::TransportDriverKind.Standard);
    assert(probe_res.available);
    assert(net_internal::platform_name(net_internal::TargetPlatform.Windows) == "Windows");

    var xsk, _ = net_internal::af_xdp_open_socket(1, 0, 0, 4096);
    net_internal::af_xdp_close(xsk);

    var sqe = net_internal::UringSqe { .. };
    net_internal::uring_prep_accept_multishot(sqe, 10, 99);
    assert(sqe.ioprio == net_internal::URING_ACCEPT_MULTISHOT);
    var iov: net_internal::UringIovec[1] = [net_internal::UringIovec { iov_base: 0, iov_len: 4096 }];
    assert(net_internal::uring_register_buffers(-1, iov[..]) == -1);
    assert(net_internal::uring_unregister_buffers(-1) == -1);
    let _ = net_internal::uring_has_fast_poll(-1);

    print("F010_HE_ISO_OK: ", he_mgr.attempts.len);

    // F011: RFC 9484 §§4.7.1-4.7.3 empty ADDRESS_ASSIGN / ROUTE_ADVERTISEMENT revocation vs malformed rejection
    let empty_payload: const u8[:] = "";
    let empty_assign, ok_empty_assign = wing::decode_address_assign_capsule(empty_payload);
    assert(ok_empty_assign && empty_assign.assigned_ip.len == 0 && empty_assign.prefix_len == 0);
    let _, ok_empty_req = wing::decode_address_request_capsule(empty_payload);
    assert(!ok_empty_req);
    let empty_route, ok_empty_route = wing::decode_route_advertisement_capsule(empty_payload);
    assert(ok_empty_route && empty_route.start_ip.len == 0 && empty_route.end_ip.len == 0);
    let trunc_assign: const u8[4] = [0x01, 0x04, 10, 0];
    let _, ok_trunc_assign = wing::decode_address_assign_capsule(trunc_assign[..]);
    assert(!ok_trunc_assign);
    let trunc_route: const u8[3] = [0x04, 10, 0];
    let _, ok_trunc_route = wing::decode_route_advertisement_capsule(trunc_route[..]);
    assert(!ok_trunc_route);
    var tun_assigned = wing::new_connect_udp_tunnel("https://proxy.org", "1.1.1.1", 53);
    tun_assigned.state = wing::MasqueTunnelState.Established;
    tun_assigned.assigned_ip.append("192.168.1.100");
    tun_assigned.assigned_prefix_len = 24;
    let zero_reject: const u8[7] = [0x01, 0x04, 0, 0, 0, 0, 32];
    assert(!wing::apply_assigned_ip(tun_assigned, trunc_assign[..]));
    assert(!wing::apply_assigned_ip(tun_assigned, zero_reject[..]));
    assert(tun_assigned.assigned_ip[..] == "192.168.1.100");
    var empty_route_wire: u8[..8] = [];
    assert(wing::encode_http_capsule(empty_route_wire, rfc::CAPSULE_ROUTE_ADVERTISEMENT, empty_payload));
    var pkt_scratch: u8[..16] = [];
    assert(wing::receive_capsule(tun_assigned, empty_route_wire[..], pkt_scratch));
    assert(wing::apply_assigned_ip(tun_assigned, empty_payload));
    assert(tun_assigned.assigned_ip.len == 0 && tun_assigned.assigned_prefix_len == 0);
    print("F011_MASQUE_EMPTY_REVOKE: 1");

    // F012: UpstreamPool EPOLLRDHUP notification while in_use and release preservation
    var up_test = wing::UpstreamPool { .. };
    let ep_test = wing::new_origin_endpoint("backend.test", 443);
    assert(wing::register_upstream_conn(up_test, 77, ep_test, 0x1122, 100));
    let fd_borrowed, acq_ok = wing::acquire_upstream_conn(up_test, ep_test, 0x1122, 100);
    assert(acq_ok && fd_borrowed == 77);
    assert(wing::notify_upstream_epoll_events(up_test, 77, wing::EPOLLRDHUP));
    assert(!wing::release_upstream_conn(up_test, 77, 0));
    let _, reacq_ok = wing::acquire_upstream_conn(up_test, ep_test, 0x1122, 100);
    assert(!reacq_ok);
    print("F012_UPSTREAM_RDHUP_IN_USE: 1");

    // F013: DoH URL query separator (? vs &)
    var doh_query_url: u8[..256] = [];
    assert(wing::build_doh_get_url("https://dns.google/dns-query?client=app", "example.com", 1, doh_query_url));
    assert(find(doh_query_url[..], "?client=app&dns=") >= 0);
    print("F013_DOH_URL_SEP: 1");

    // F014: DNS cache lookup with negative elapsed time and saturated TTL addition
    var dcache = wing::DnsCache { .. };
    var dentry = wing::DnsCacheEntry {
        inserted_at_sec: 1000,
        ttl_sec:         300,
        stale_ttl_sec:   86400,
        ..
    };
    dentry.domain.append("example.com");
    wing::dns_cache_insert(dcache, dentry);
    var out_entry = wing::DnsCacheEntry { .. };
    let skew_stat = wing::dns_cache_lookup(dcache, "example.com", 1, 500, out_entry);
    assert(skew_stat == wing::DnsCacheStatus.Expired);
    print("F014_DNS_CACHE_SKEW: 1");

    // F015: bind_winner_attempt rejects Failed or Cancelled attempts
    var amgr = wing::new_attempt_manager(250);
    var amgr_cands: wing::DnsCandidate[..1] = [];
    amgr_cands.push(wing::new_dns_candidate(wing::AddressFamily.IPv4, "1.1.1.1", 80));
    wing::start_attempt_race(amgr, amgr_cands[..], 0);
    amgr.attempts[0].state = wing::AttemptState.Failed;
    assert(!wing::bind_winner_attempt(amgr, amgr.attempts[0].attempt_id));
    assert(amgr.attempts[0].state == wing::AttemptState.Failed);
    print("F015_BIND_WINNER_FAILED: 1");

    // F016: format_i64_dec formats negative integers correctly
    var drv_neg: u8[..32] = [];
    core::format_i64_dec(-42, drv_neg);
    assert(drv_neg[..] == "-42");
    print("F016_DRIVER_INT_NEG: 1");

    // F017: Capacity protection on new_origin_endpoint, new_dns_candidate, and format_partitioned_key
    var big_host: u8[..300] = [];
    for _ in 280 { big_host.push('x'); }
    let ep_big = wing::new_origin_endpoint(big_host[..], 80);
    assert(ep_big.host.len <= 256);
    let cand_big = wing::new_dns_candidate(wing::AddressFamily.IPv4, big_host[..], 80);
    assert(cand_big.ip.len <= 64);
    var tiny_part: u8[..4] = [];
    let nik_test = wing::new_network_isolation_key("https://a.com", "https://b.com");
    wing::format_partitioned_key("base", nik_test, tiny_part);
    assert(tiny_part.len <= 4);
    print("F017_CAP_GUARDS_OK: 1");

    verify_iocomp_track_e(p_cfg);
}

// CHECK: F001_TICK_SLOT: 20
// CHECK: F002_BACKOFF_OK: 0
// CHECK: F003_BREAKER_17: 1
// CHECK: F004_POOL_OK: 1
// CHECK: F005_POLLER_OK: 1
// CHECK: F006_MASQUE_LEN: 5
// CHECK: F007_CONNECT_OK: 1
// CHECK: F008_PROXY_OK: 1
// CHECK: F009_DNS_OK: 1
// CHECK: F010_HE_ISO_OK: 1
// CHECK: F011_MASQUE_EMPTY_REVOKE: 1
// CHECK: F012_UPSTREAM_RDHUP_IN_USE: 1
// CHECK: F013_DOH_URL_SEP: 1
// CHECK: F014_DNS_CACHE_SKEW: 1
// CHECK: F015_BIND_WINNER_FAILED: 1
// CHECK: F016_DRIVER_INT_NEG: 1
// CHECK: F017_CAP_GUARDS_OK: 1
// CHECK: IOCOMP_TRACK_E_OK: 1

// ============================================================================
// 6. verify_net_rfc_seams (6/6)
// ============================================================================
// CHECK: === [6/6] verify_net_rfc_seams ===

// tests/lit/verify_net_rfc_seams.goose
// Regression test suite for cross-component seams and RFC edge cases in net/.
//

fn test_r001_dns_rfc_edge_cases() {
    // 1. RFC 9460 §7.1.1 & §2.4.3: no-default-alpn (key 2) without alpn (key 1) must be rejected
    let no_def_only: const u8[4] = [0x00, 0x02, 0x00, 0x00];
    var rec_nodef = wing::HttpsRecord { .. };
    assert(!wing::parse_https_svc_params(no_def_only[..], rec_nodef));

    // 2. RFC 9460: empty ech (key 5, len 0) must be rejected
    let empty_ech: const u8[4] = [0x00, 0x05, 0x00, 0x00];
    var rec_ech = wing::HttpsRecord { .. };
    assert(!wing::parse_https_svc_params(empty_ech[..], rec_ech));

    // 3. RFC 9460 §2.4.2: AliasMode (priority == 0) MUST ignore SvcParams
    let alias_wire: const u8[50] = [
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x41, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x41, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x09,
        0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x02, 0x20, 0xfb,
    ];
    var resp_alias = wing::DnsResponse { .. };
    assert(wing::parse_dns_response(alias_wire[..], resp_alias));
    assert(resp_alias.https_records.len == 1);
    assert(resp_alias.https_records[0].priority == 0);
    assert(resp_alias.https_records[0].port == 443);

    // 4. RFC 9460 §9: SVCB (type 64 = 0x0040) must NOT be accepted into https_records
    var svcb_wire = alias_wire;
    svcb_wire[31] = 0x00;
    svcb_wire[32] = 0x40;
    svcb_wire[41] = 0x01;
    var resp_svcb = wing::DnsResponse { .. };
    assert(wing::parse_dns_response(svcb_wire[..], resp_svcb));
    assert(resp_svcb.https_records.len == 0);

    // 5. RFC 2181 §8: TTL with MSB set (0x80000001) must be treated as 0
    var msb_ttl_wire: const u8[45] = [
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x80, 0x00, 0x00, 0x01, 0x00, 0x04,
        127, 0, 0, 1,
    ];
    var resp_ttl = wing::DnsResponse { .. };
    assert(wing::parse_dns_response(msb_ttl_wire[..], resp_ttl));
    assert(resp_ttl.min_ttl_sec == 0);

    // 6. RFC 1035 §3.2.1: ttl_sec == 0 must not be served Stale from DnsCache
    var dcache = wing::DnsCache { .. };
    var zero_ttl_entry = wing::DnsCacheEntry {
        qtype:           1,
        inserted_at_sec: 1000,
        ttl_sec:         0,
        stale_ttl_sec:   86400,
        ..
    };
    zero_ttl_entry.domain.append("zero.example.com");
    wing::dns_cache_insert(dcache, zero_ttl_entry);
    var out_zero = wing::DnsCacheEntry { .. };
    assert(wing::dns_cache_lookup(dcache, "zero.example.com", 1, 1000, out_zero) == wing::DnsCacheStatus.Expired);

    // 7. RFC 5891 §4.2.3.1 & CVE-2026-39821 Punycode validation
    assert(!core::validate_idna_domain_bounds("xn--test-.example.com"));
    assert(!core::validate_idna_domain_bounds("xn---a.example.com"));
    assert(!core::validate_idna_domain_bounds("xn--a_b.example.com"));
    assert(!core::validate_idna_domain_bounds("ab--cd.example.com"));
    print("R001_DNS_RFC: 1");
}

fn test_r002_happy_eyeballs_seams() {
    // 1. 100-byte FQDN passed into new_dns_candidate (client/session/exec.goose seam)
    var fqdn_100: u8[..128] = [];
    for _ in 20 { fqdn_100.append("sub."); }
    fqdn_100.append("example.com");
    let cand = wing::new_dns_candidate(wing::AddressFamily.IPv4, fqdn_100[..], 443);
    assert(cand.ip[..] == fqdn_100[..]);

    // 2. on_dns_a_response when AAAA already Failed must NOT wait 50ms RD delay
    var task = wing::new_dns_race_task(50);
    task.aaaa_status = wing::DnsQueryStatus.Failed;
    let a_ips: (const u8[:])[1] = ["93.184.216.34"];
    wing::on_dns_a_response(task, a_ips[..], 20);
    assert(task.ready_to_connect && !task.rd_timer_armed);

    // 3. new_attempt_manager clamps cad_ms to >= 10ms (RFC 8305 §5)
    let mgr = wing::new_attempt_manager(2);
    assert(mgr.effective_cad_ms >= 10);
    print("R002_HE_SEAMS: 1");
}

fn test_r003_proxy_hop_by_hop_and_handshake() {
    // 1. RFC 9110 §7.6.1: sanitize_tunnel_headers_for_origin must not overwrite Connection
    //    entry in place before checking later headers nominated by Connection!
    var hdrs = wing::HeaderMap { .. };
    wing::append_header(hdrs, "Connection", "X-Secret-Token");
    wing::append_header(hdrs, "Host", "origin.example.com");
    wing::append_header(hdrs, "X-Secret-Token", "leaked-secret-value");
    wing::sanitize_tunnel_headers_for_origin(hdrs);
    assert(!wing::has_header(hdrs, "X-Secret-Token"));
    assert(wing::has_header(hdrs, "Host"));

    // 2. RFC 1928 §6: SOCKS5 connect reply with non-zero RSV byte must be rejected
    let bad_rsv_reply: const u8[10] = [0x05, 0x00, 0x01, 0x01, 127, 0, 0, 1, 0x04, 0x38];
    let _, rsv_err = wing::parse_socks5_connect_reply(bad_rsv_reply[..]);
    assert(rsv_err == wing::Socks5Error.InvalidReplyHeader);

    // 3. Slowloris HeaderReader: bare \n\n must not disarm Slowloris checks
    let sl_cfg = wing::SlowlorisDefenseConfig { .. };
    var reader = wing::new_header_reader(sl_cfg, 0);
    let v1 = wing::feed_header_bytes(reader, "HTTP/1.1 200 OK\n\n", 1000000);
    assert(v1 == wing::SlowlorisViolation.None && !reader.headers_complete);

    // 4. build_http_connect_request rejects whitespace in target_host
    var req_out: u8[..1024] = [];
    wing::build_http_connect_request("bad host.com", 443, "", "", req_out);
    assert(req_out.len == 0);
    print("R003_PROXY_SEAMS: 1");
}

fn test_r004_masque_rfc_invariants() {
    // 1. RFC 9297 §3.4: Capsule-Protocol SFV List (?1, ?0) must be rejected
    assert(!wing::is_capsule_protocol_negotiated("?1, ?0"));
    assert(!wing::is_capsule_protocol_negotiated("?1; a=1, ?1"));

    // 2. RFC 9297 §2.1: quarter_stream_id > 2^60 - 1 rejected
    var dg_out: u8[..64] = [];
    assert(!wing::encode_http_datagram(dg_out, 0x1000000000000000, 0, "pkt"));

    // 3. RFC 9298 §3: IPv6 colons percent-encoded in format_connect_udp_path and decoded in parse_connect_udp_path
    var v6_path: u8[..256] = [];
    wing::format_connect_udp_path(v6_path, "2001:db8::1", 443);
    assert(v6_path[..] == "/.well-known/masque/udp/2001%3Adb8%3A%3A1/443/");
    let dec_h, dec_p, dec_ok = wing::parse_connect_udp_path(v6_path[..]);
    assert(dec_ok && dec_p == 443 && dec_h[..] == "2001:db8::1");
    let _, _, raw_colon_ok = wing::parse_connect_udp_path("/.well-known/masque/udp/2001:db8::1/443/");
    assert(!raw_colon_ok);

    // 4. RFC 9484 §4.7.3: Inverted route range (start_ip > end_ip) rejected in decode and receive_capsule
    var inv_route = wing::RouteAdvertisement { ip_version: 4, ip_protocol: 0, .. };
    inv_route.start_ip.append([10, 0, 0, 255]);
    inv_route.end_ip.append([10, 0, 0, 0]);
    var route_wire: u8[..64] = [];
    assert(!wing::encode_route_advertisement_capsule(route_wire, inv_route));
    let raw_inv_payload: const u8[10] = [4, 10, 0, 0, 255, 10, 0, 0, 0, 0];
    let _, inv_dec_ok = wing::decode_route_advertisement_capsule(raw_inv_payload[..]);
    assert(!inv_dec_ok);
    print("R004_MASQUE_RFC: 1");
}

fn test_r005_proxy_protocol_roundtrip_and_bounds() {
    // 1. HAProxy v2 LOCAL + AF_UNSPEC default ProxyHeader round-trip
    var local_hdr = wing::ProxyHeader {
        version: wing::ProxyProtocolVersion.V2,
        command: wing::ProxyCommand.Local,
        family:  wing::ProxyAddressFamily.Unspec,
        ..
    };
    var v2_out: u8[..64] = [];
    assert(wing::format_proxy_v2(local_hdr, v2_out));
    let parsed_v2, consumed_v2, ok_v2 = wing::parse_proxy_v2(v2_out[..]);
    assert(ok_v2 && consumed_v2 == 16 && parsed_v2.command == wing::ProxyCommand.Local);

    // 2. HAProxy v1 UNKNOWN with embedded NUL rejected
    let _, _, bad_v1 = wing::parse_proxy_v1("PROXY UNKNOWN bad\x00char\r\n");
    assert(!bad_v1);
    print("R005_PROXY_PROTO: 1");
}

fn test_r006_pool_h2_coalescing_and_queues() {
    // 1. RFC 9110 §4.3.1: H2 coalescing MUST NOT coalesce across different origin ports
    let nak = wing::new_network_anonymization_key("https://example.com");
    let chain = wing::new_direct_proxy_chain();
    let pol = wing::TlsAndDnsPolicy { .. };
    let key_443 = wing::new_pool_key(wing::PoolScheme.Https, "a.example.com", 443, chain, nak, pol);
    let key_8443 = wing::new_pool_key(wing::PoolScheme.Https, "b.example.com", 8443, chain, nak, pol);
    var conn = wing::PooledConnection {
        key:                    key_443,
        protocol:               wing::NegotiatedProtocol.Http2,
        max_concurrent_streams: 100,
        cert_valid:             true,
        ..
    };
    conn.resolved_ip.append("93.184.216.34");
    var san: u8[..128] = [];
    san.append("*.example.com");
    conn.san_hosts.push(san);
    assert(!wing::can_coalesce_h2_connection(conn, key_8443, "93.184.216.34"));

    // 2. RFC 6125: matches_san_pattern rejects trailing-dot TLD wildcard and IPv4 wildcard
    assert(!wing::matches_san_pattern("", ""));
    assert(!wing::matches_san_pattern("*.com.", "evil.com."));
    assert(!wing::matches_san_pattern("*.0.0.1", "127.0.0.1"));

    // 3. WantQueue compaction drops cancelled items so 65th push succeeds
    var wq = wing::WantQueue { .. };
    for i in 64 {
        let req_id = (i + 1) as u64;
        assert(wing::push_want(wq, wing::WantConn { req_id: req_id, .. }));
        assert(wing::cancel_want(wq, req_id));
    }
    assert(wing::queue_len(wq) == 0);
    assert(wing::push_want(wq, wing::WantConn { req_id: 65, .. }));

    // 4. UpstreamPool bitwise-OR epoll_events preserves EPOLLRDHUP across subsequent events
    var up = wing::UpstreamPool { .. };
    let ep = wing::new_origin_endpoint("10.0.0.1", 8080);
    assert(wing::register_upstream_conn(up, 55, ep, 1, 1));
    let _, acq_ok = wing::acquire_upstream_conn(up, ep, 1, 1);
    assert(acq_ok);
    let _ = wing::notify_upstream_epoll_events(up, 55, wing::EPOLLRDHUP);
    let _ = wing::notify_upstream_epoll_events(up, 55, wing::EPOLL_READ);
    assert(!wing::release_upstream_conn(up, 55, 0));
    print("R006_POOL_SEAMS: 1");
}

fn test_r007_isolation_and_retry_rfc() {
    // 1. NetworkIsolationKey empty check, case folding, and fail-closed on >128B site
    let empty_nik = wing::new_network_isolation_key("", "");
    assert(empty_nik.is_empty);
    let upper_nik = wing::new_network_isolation_key("HTTPS://EXAMPLE.COM", "https://example.com");
    let lower_nik = wing::new_network_isolation_key("https://example.com", "https://example.com");
    assert(upper_nik.top_level_site[..] == lower_nik.top_level_site[..]);

    // 2. RFC 9110 §5.6.7: Retry-After accepts obsolete RFC 850 and asctime HTTP-dates
    let _, ok_rfc850 = wing::parse_retry_after_ms("Sunday, 06-Nov-94 08:49:37 GMT", 784111770000);
    assert(ok_rfc850);
    let _, ok_asctime = wing::parse_retry_after_ms("Sun Nov  6 08:49:37 1994", 784111770000);
    assert(ok_asctime);

    // 3. CircuitBreaker must not shorten an active longer block
    var cb = wing::new_host_circuit_breaker(60000);
    assert(wing::trip_circuit_breaker_if_exceeded(cb, "api.test", 300000, 1000000000));
    assert(wing::trip_circuit_breaker_if_exceeded(cb, "api.test", 70000, 1000000000));
    assert(wing::is_host_circuit_broken(cb, "api.test", 200000000000));
    print("R007_ISO_RETRY: 1");
}

fn test_r008_poller_timer_tcp_and_drivers() {
    // 1. Edge-triggered Poller preserves unreported readiness bits
    var p_cfg = net_internal::auto_transport_driver_config();
    var p = wing::new_poller(p_cfg);
    wing::register_socket(p, 10, 100, core::PollInterest.Read, core::PollTrigger.Edge);
    let _ = wing::simulate_read_ready(p, 10, 64);
    let _ = wing::simulate_write_ready(p, 10);
    var evs: core::PollReadyEvent[..64] = [];
    let n1 = wing::poll_events(p, 0, 1000, evs);
    assert(n1 == 1 && (evs[0].events & core::POLL_READ) != 0 && (evs[0].events & core::POLL_WRITE) == 0);
    let _ = wing::modify_socket(p, 10, 100, core::PollInterest.Write, core::PollTrigger.Edge);
    evs.clear();
    let n2 = wing::poll_events(p, 0, 2000, evs);
    assert(n2 == 1 && (evs[0].events & core::POLL_WRITE) != 0);
    wing::close_poller(p);

    // 2. TickTimerWheel u32 addition wrap-around when current_tick + elapsed >= 2^32 (2^32 % 240 == 16 != 0)
    var wheel = core::TickTimerWheel { current_tick: 200, .. };
    let next_tick = core::tick_timer_advance(wheel, 0xFFFFFFFF);
    assert(next_tick == 215);

    // 3. UringSqe reuse clears stale ioprio and RIO sub-buffer guards u64 overflow
    var sqe = net_internal::UringSqe { .. };
    net_internal::uring_prep_accept_multishot(sqe, 5, 1);
    net_internal::uring_prep_accept(sqe, 5, 2);
    assert(sqe.ioprio == 0);
    let rio_buf = net_internal::new_rio_buffer(1, 4096);
    let rio_oob = net_internal::rio_sub_buffer(rio_buf, 0xFFFFFFFFFFFFFFFF, 1);
    assert(!rio_oob.is_registered);
    print("R008_REACTOR_DRV: 1");
}

fn test_r009_goose2rfc_net_audit_regressions() {
    // NET1_C01 & NET1_C02: RFC 9484 §4.7.1 & §4.7.2 request_id != 0 and zero host bits
    let raw_req_zero: const u8[7] = [0x00, 4, 10, 0, 0, 1, 32];
    let _, ok_req_zero = wing::decode_address_request_capsule(raw_req_zero[..]);
    assert(!ok_req_zero);
    let raw_assign_host: const u8[7] = [0x01, 4, 192, 168, 1, 100, 24];
    let _, ok_assign_host = wing::decode_address_assign_capsule(raw_assign_host[..]);
    assert(!ok_assign_host);

    // NET1_C03: RFC 9484 §4.7.3 multi-entry ROUTE_ADVERTISEMENT validates all entries
    let two_routes_inv: const u8[20] = [
        4, 10, 0, 0, 0, 10, 0, 0, 255, 0,
        4, 10, 0, 1, 255, 10, 0, 1, 0, 0,
    ];
    let _, ok_two_routes = wing::decode_route_advertisement_capsule(two_routes_inv[..]);
    assert(!ok_two_routes);

    // NET2_C03: StreamPool release_connection_or_handoff closes draining connection
    var sp = wing::new_stream_pool(6, 32, 4);
    var pk = wing::PoolKey { scheme: wing::PoolScheme.Https, .. };
    pk.origin_endpoint.host.append("api.example.com");
    pk.origin_endpoint.port = 443;
    let cid = wing::register_connection(sp, pk, wing::NegotiatedProtocol.Http2, "1.1.1.1", 100, 1000);
    assert(wing::enqueue_group_waiter(sp, pk, 777));
    sp.conns[0].no_new_exchanges = true;
    var waiter_out = wing::WantConn { .. };
    let rel_ok, handed_off = wing::release_connection_or_handoff(sp, cid, 2000, waiter_out);
    assert(rel_ok && !handed_off);
    let g_idx = wing::find_group_index(sp, pk);
    assert(sp.groups[g_idx].active_conns == 0 && sp.groups[g_idx].idle_conns == 0);
    print("GOOSE2RFC_NET_AUDIT_REGRESSIONS: OK");
}

fn run_06_verify_net_rfc_seams() {
    test_r001_dns_rfc_edge_cases();
    test_r002_happy_eyeballs_seams();
    test_r003_proxy_hop_by_hop_and_handshake();
    test_r004_masque_rfc_invariants();
    test_r005_proxy_protocol_roundtrip_and_bounds();
    test_r006_pool_h2_coalescing_and_queues();
    test_r007_isolation_and_retry_rfc();
    test_r008_poller_timer_tcp_and_drivers();
    test_r009_goose2rfc_net_audit_regressions();
}

// CHECK: R001_DNS_RFC: 1
// CHECK: R002_HE_SEAMS: 1
// CHECK: R003_PROXY_SEAMS: 1
// CHECK: R004_MASQUE_RFC: 1
// CHECK: R005_PROXY_PROTO: 1
// CHECK: R006_POOL_SEAMS: 1
// CHECK: R007_ISO_RETRY: 1
// CHECK: R008_REACTOR_DRV: 1
// CHECK: GOOSE2RFC_NET_AUDIT_REGRESSIONS: OK

fn main() {
    print("\n=== [1/6] verify_dns_https_svcb ===\n");
    run_01_verify_dns_https_svcb();
    print("\n=== [2/6] verify_masque_dns_edge ===\n");
    run_02_verify_masque_dns_edge();
    print("\n=== [3/6] verify_l4_sockets ===\n");
    run_03_verify_l4_sockets();
    print("\n=== [4/6] verify_udp_batch ===\n");
    run_04_verify_udp_batch();
    print("\n=== [5/6] verify_net_audit ===\n");
    run_05_verify_net_audit();
    print("\n=== [6/6] verify_net_rfc_seams ===\n");
    run_06_verify_net_rfc_seams();
}
