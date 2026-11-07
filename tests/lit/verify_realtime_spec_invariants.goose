// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_realtime_spec_invariants.goose
// Rigorous protocol specification verification for:
// 1. WebSocket Control Frames (RFC 6455 В§5.5) - length <= 125, non-fragmented (FIN=1)
// 2. WebSocket RSV Bits (RFC 6455 В§5.2, RFC 7692 В§5.1) - zero unless negotiated
// 3. WebSocket Close Codes (RFC 6455 В§7.4.1, В§7.4.2) - invalid/reserved code rejection
// 4. Cookie Syntax & Prefixes (RFC 6265bis В§4.1.3, RFC 6265 В§4.1.1) - __Secure-, __Host-, token & cookie-octet
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// ---- WebSocket Control Frames (RFC 6455 В§5.5) ---------------------------

fn test_ws_control_frame_invariants() {
    print("--- 1. WS Control Frames (RFC 6455 Section 5.5) ---\n");

    // Case 1.1: Ping with payload > 125 bytes MUST fail with PROTOCOL_ERROR (1002)
    var ws1 = wing::new_websocket_session(false);
    var reply1: u8[>..] = [];
    var msg1 = wing::WsMessage { .. };
    var big_ping: u8[>..] = [];
    // 0x89 = FIN=1, opcode=9 (Ping); 0xFE = Masked=1, len=126; extended length 0x007E (126 bytes)
    wire_kit::parse_hex("89FE007E11223344", big_ping);
    for _ in 126 { big_ping.push(0xAA); }
    let _ = wing::receive(ws1, big_ping[..], msg1, reply1);
    print("PING_OVERSIZE_126: closed=", ws1.is_closed, " code=", ws1.close_code, "\n");
    // CHECK: PING_OVERSIZE_126: closed=true code=1002

    // Case 1.2: Fragmented Ping (FIN=0) MUST fail with PROTOCOL_ERROR (1002)
    var ws2 = wing::new_websocket_session(false);
    var reply2: u8[>..] = [];
    var msg2 = wing::WsMessage { .. };
    var frag_ping: u8[>..] = [];
    // 0x09 = FIN=0, opcode=9 (Ping); 0x84 = Masked=1, len=4
    wire_kit::parse_hex("09841122334468656C6C", frag_ping);
    let _ = wing::receive(ws2, frag_ping[..], msg2, reply2);
    print("PING_FRAGMENTED: closed=", ws2.is_closed, " code=", ws2.close_code, "\n");
    // CHECK: PING_FRAGMENTED: closed=true code=1002

    // Case 1.3: Fragmented Close (FIN=0) MUST fail with PROTOCOL_ERROR (1002)
    var ws3 = wing::new_websocket_session(false);
    var reply3: u8[>..] = [];
    var msg3 = wing::WsMessage { .. };
    var frag_close: u8[>..] = [];
    // 0x08 = FIN=0, opcode=8 (Close); 0x82 = Masked=1, len=2; payload code 1000 (0x03E8)
    wire_kit::parse_hex("08821122334412CA", frag_close);
    let _ = wing::receive(ws3, frag_close[..], msg3, reply3);
    print("CLOSE_FRAGMENTED: closed=", ws3.is_closed, " code=", ws3.close_code, "\n");
    // CHECK: CLOSE_FRAGMENTED: closed=true code=1002

    // Case 1.4: Standalone parse_close_payload with payload > 125 bytes MUST fail
    var over_close_payload: u8[>..] = [];
    over_close_payload.push(0x03);
    over_close_payload.push(0xE8); // code 1000
    for _ in 124 { over_close_payload.push('x'); } // total 126 bytes
    let _, _, ok_over = wing::parse_close_payload(over_close_payload[..]);
    print("PARSE_CLOSE_OVER_125: ok=", ok_over, "\n");
    // CHECK: PARSE_CLOSE_OVER_125: ok=false
}

// ---- WebSocket RSV Bits (RFC 6455 В§5.2) ---------------------------------

fn test_ws_rsv_bit_invariants() {
    print("--- 2. WS RSV Bits (RFC 6455 Section 5.2) ---\n");

    // Case 2.1: RSV1=1 without negotiated extension MUST fail with PROTOCOL_ERROR (1002)
    var ws1 = wing::new_websocket_session(false);
    var reply1: u8[>..] = [];
    var msg1 = wing::WsMessage { .. };
    var rsv1_frame: u8[>..] = [];
    // 0xC1 = FIN=1, RSV1=1, opcode=1 (Text); Masked=1, len=5
    wire_kit::parse_hex("C1851122334468656C6C6F", rsv1_frame);
    let _ = wing::receive(ws1, rsv1_frame[..], msg1, reply1);
    print("RSV1_NO_EXT: closed=", ws1.is_closed, " code=", ws1.close_code, "\n");
    // CHECK: RSV1_NO_EXT: closed=true code=1002

    // Case 2.2: RSV2=1 MUST fail with PROTOCOL_ERROR (1002)
    var ws2 = wing::new_websocket_session(false);
    var reply2: u8[>..] = [];
    var msg2 = wing::WsMessage { .. };
    var rsv2_frame: u8[>..] = [];
    // 0xA1 = FIN=1, RSV2=1, opcode=1 (Text); Masked=1, len=5
    wire_kit::parse_hex("A1851122334468656C6C6F", rsv2_frame);
    let _ = wing::receive(ws2, rsv2_frame[..], msg2, reply2);
    print("RSV2_NONZERO: closed=", ws2.is_closed, " code=", ws2.close_code, "\n");
    // CHECK: RSV2_NONZERO: closed=true code=1002

    // Case 2.3: RSV3=1 MUST fail with PROTOCOL_ERROR (1002)
    var ws3 = wing::new_websocket_session(false);
    var reply3: u8[>..] = [];
    var msg3 = wing::WsMessage { .. };
    var rsv3_frame: u8[>..] = [];
    // 0x91 = FIN=1, RSV3=1, opcode=1 (Text); Masked=1, len=5
    wire_kit::parse_hex("91851122334468656C6C6F", rsv3_frame);
    let _ = wing::receive(ws3, rsv3_frame[..], msg3, reply3);
    print("RSV3_NONZERO: closed=", ws3.is_closed, " code=", ws3.close_code, "\n");
    // CHECK: RSV3_NONZERO: closed=true code=1002

    // Case 2.4: RSV1=1 on control frame (Ping) MUST fail even if compression enabled
    var ws4 = wing::new_websocket_session(false);
    wing::enable_permessage_deflate(ws4);
    var reply4: u8[>..] = [];
    var msg4 = wing::WsMessage { .. };
    var rsv1_ping: u8[>..] = [];
    // 0xC9 = FIN=1, RSV1=1, opcode=9 (Ping); Masked=1, len=4
    wire_kit::parse_hex("C9841122334468656C6C", rsv1_ping);
    let _ = wing::receive(ws4, rsv1_ping[..], msg4, reply4);
    print("RSV1_ON_PING: closed=", ws4.is_closed, " code=", ws4.close_code, "\n");
    // CHECK: RSV1_ON_PING: closed=true code=1002
}

// ---- WebSocket Close Code Validation (RFC 6455 В§7.4) --------------------

fn test_ws_close_code_invariants() {
    print("--- 3. WS Close Codes (RFC 6455 Section 7.4) ---\n");

    // Permitted codes
    print("CODE_1000_OK: ", rfc::is_valid_ws_close_code(1000), "\n");
    print("CODE_3000_OK: ", rfc::is_valid_ws_close_code(3000), "\n");
    print("CODE_4999_OK: ", rfc::is_valid_ws_close_code(4999), "\n");
    // CHECK: CODE_1000_OK: true
    // CHECK: CODE_3000_OK: true
    // CHECK: CODE_4999_OK: true

    // Forbidden codes on the wire
    print("CODE_0_FORBIDDEN: ", !rfc::is_valid_ws_close_code(0), "\n");
    print("CODE_999_FORBIDDEN: ", !rfc::is_valid_ws_close_code(999), "\n");
    print("CODE_1004_FORBIDDEN: ", !rfc::is_valid_ws_close_code(1004), "\n");
    print("CODE_1005_FORBIDDEN: ", !rfc::is_valid_ws_close_code(1005), "\n");
    print("CODE_1006_FORBIDDEN: ", !rfc::is_valid_ws_close_code(1006), "\n");
    print("CODE_1015_FORBIDDEN: ", !rfc::is_valid_ws_close_code(1015), "\n");
    print("CODE_1016_FORBIDDEN: ", !rfc::is_valid_ws_close_code(1016), "\n");
    print("CODE_2999_FORBIDDEN: ", !rfc::is_valid_ws_close_code(2999), "\n");
    print("CODE_5000_FORBIDDEN: ", !rfc::is_valid_ws_close_code(5000), "\n");
    // CHECK: CODE_0_FORBIDDEN: true
    // CHECK: CODE_999_FORBIDDEN: true
    // CHECK: CODE_1004_FORBIDDEN: true
    // CHECK: CODE_1005_FORBIDDEN: true
    // CHECK: CODE_1006_FORBIDDEN: true
    // CHECK: CODE_1015_FORBIDDEN: true
    // CHECK: CODE_1016_FORBIDDEN: true
    // CHECK: CODE_2999_FORBIDDEN: true
    // CHECK: CODE_5000_FORBIDDEN: true

    // Wire Close frame with code 1005 received -> MUST fail with 1002
    var ws1 = wing::new_websocket_session(false);
    var reply1: u8[>..] = [];
    var msg1 = wing::WsMessage { .. };
    var close_1005: u8[>..] = [];
    wire_kit::parse_hex("88820000000003ED", close_1005); // 0x03ED = 1005
    let _ = wing::receive(ws1, close_1005[..], msg1, reply1);
    print("RECV_CLOSE_1005: closed=", ws1.is_closed, " code=", ws1.close_code, "\n");
    // CHECK: RECV_CLOSE_1005: closed=true code=1002

    // Wire Close frame with code 5000 received -> MUST fail with 1002
    var ws2 = wing::new_websocket_session(false);
    var reply2: u8[>..] = [];
    var msg2 = wing::WsMessage { .. };
    var close_5000: u8[>..] = [];
    wire_kit::parse_hex("8882000000001388", close_5000); // 0x1388 = 5000
    let _ = wing::receive(ws2, close_5000[..], msg2, reply2);
    print("RECV_CLOSE_5000: closed=", ws2.is_closed, " code=", ws2.close_code, "\n");
    // CHECK: RECV_CLOSE_5000: closed=true code=1002
}

// ---- Cookie Syntax and Prefixes (RFC 6265bis В§4.1.3 & RFC 6265 В§4.1.1) --

fn test_cookie_syntax_and_prefix_invariants() {
    print("--- 4. Cookie Syntax and Prefixes (RFC 6265bis / RFC 6265) ---\n");
    let now_us: i64 = 1700000000000000;

    // 4.1 __Secure- requires Secure attribute
    let _, _, ok_sec_no_sec = wing::parse_canonical_set_cookie("__Secure-id=123", "example.com", "/", now_us);
    let _, _, ok_sec_with_sec = wing::parse_canonical_set_cookie("__Secure-id=123; Secure", "example.com", "/", now_us);
    print("SECURE_PREFIX: no_sec=", ok_sec_no_sec, " with_sec=", ok_sec_with_sec, "\n");
    // CHECK: SECURE_PREFIX: no_sec=false with_sec=true

    // 4.2 __Host- requires Secure attribute
    let _, _, ok_host_no_sec = wing::parse_canonical_set_cookie("__Host-id=123; Path=/", "example.com", "/", now_us);
    print("HOST_NO_SEC: ok=", ok_host_no_sec, "\n");
    // CHECK: HOST_NO_SEC: ok=false

    // 4.3 __Host- MUST NOT have Domain attribute
    let _, _, ok_host_dom = wing::parse_canonical_set_cookie("__Host-id=123; Secure; Path=/; Domain=example.com", "example.com", "/", now_us);
    print("HOST_WITH_DOMAIN: ok=", ok_host_dom, "\n");
    // CHECK: HOST_WITH_DOMAIN: ok=false

    // 4.4 __Host- MUST have Path attribute equal to '/'
    // Must fail when Path attribute is missing entirely, EVEN IF default_path is "/"
    let _, _, ok_host_missing_path = wing::parse_canonical_set_cookie("__Host-id=123; Secure", "example.com", "/", now_us);
    print("HOST_MISSING_PATH_ATTR: ok=", ok_host_missing_path, "\n");
    // CHECK: HOST_MISSING_PATH_ATTR: ok=false

    // Must fail when Path attribute is not '/'
    let _, _, ok_host_sub_path = wing::parse_canonical_set_cookie("__Host-id=123; Secure; Path=/sub", "example.com", "/sub", now_us);
    print("HOST_NON_ROOT_PATH: ok=", ok_host_sub_path, "\n");
    // CHECK: HOST_NON_ROOT_PATH: ok=false

    // Must succeed when Secure, no Domain, and Path=/
    let _, _, ok_host_valid = wing::parse_canonical_set_cookie("__Host-id=123; Secure; Path=/", "example.com", "/", now_us);
    print("HOST_VALID: ok=", ok_host_valid, "\n");
    // CHECK: HOST_VALID: ok=true

    // 4.5 Cookie Name Syntax Validation (RFC 6265 В§4.1.1: cookie-name = token)
    let _, _, ok_name_space = wing::parse_canonical_set_cookie("bad name=123", "example.com", "/", now_us);
    let _, _, ok_name_at = wing::parse_canonical_set_cookie("bad@name=123", "example.com", "/", now_us);
    let _, _, ok_name_comma = wing::parse_canonical_set_cookie("bad,name=123", "example.com", "/", now_us);
    let _, _, ok_name_bracket = wing::parse_canonical_set_cookie("[bad]=123", "example.com", "/", now_us);
    let _, _, ok_name_slash = wing::parse_canonical_set_cookie("bad/name=123", "example.com", "/", now_us);
    let _, _, ok_name_paren = wing::parse_canonical_set_cookie("bad(name)=123", "example.com", "/", now_us);
    print("NAME_SYNTAX: sp=", ok_name_space, " at=", ok_name_at, " comma=", ok_name_comma, " brk=", ok_name_bracket, " slash=", ok_name_slash, " par=", ok_name_paren, "\n");
    // CHECK: NAME_SYNTAX: sp=false at=false comma=false brk=false slash=false par=false

    // 4.6 Cookie Value Syntax Validation (RFC 6265 В§4.1.1: cookie-value = *cookie-octet / (DQUOTE *cookie-octet DQUOTE))
    let _, _, ok_val_space = wing::parse_canonical_set_cookie("id=val ue", "example.com", "/", now_us);
    let _, _, ok_val_comma = wing::parse_canonical_set_cookie("id=val,ue", "example.com", "/", now_us);
    let _, _, ok_val_backslash = wing::parse_canonical_set_cookie("id=val\\ue", "example.com", "/", now_us);
    let _, _, ok_val_unclosed = wing::parse_canonical_set_cookie("id=\"val", "example.com", "/", now_us);
    let _, _, ok_val_unmatched = wing::parse_canonical_set_cookie("id=val\"", "example.com", "/", now_us);
    let _, _, ok_val_good = wing::parse_canonical_set_cookie("id=valid_value", "example.com", "/", now_us);
    let _, _, ok_val_good_quoted = wing::parse_canonical_set_cookie("id=\"valid_quoted_value\"", "example.com", "/", now_us);
    print("VAL_SYNTAX: sp=", ok_val_space, " comma=", ok_val_comma, " bslash=", ok_val_backslash, " unclosed=", ok_val_unclosed, " unmatched=", ok_val_unmatched, " good=", ok_val_good, " quoted=", ok_val_good_quoted, "\n");
    // CHECK: VAL_SYNTAX: sp=false comma=false bslash=false unclosed=false unmatched=false good=true quoted=true
}

// ---- 5. SSE Regression Invariants (W3C EventSource §9.2.6) ----------------

fn test_sse_regressions() {
    print("--- 5. SSE Regressions ---\n");

    // 5.1 sse_process_line MUST reset cur_data/cur_event/has_data even when out_events is at capacity
    var p_cap = wing::SseParser { .. };
    var ev_1: wing::SseEvent[..1] = [];
    wing::sse_feed(p_cap, "event: ev1\ndata: first\n\nevent: ev2\ndata: second\n\n", ev_1);
    var ev_next: wing::SseEvent[..2] = [];
    wing::sse_feed(p_cap, "data: third\n\n", ev_next);
    print("SSE_CAP_RESET: len=", ev_next.len, " event=", ev_next[0].event[..], " data=", ev_next[0].data[..], "\n");
    // CHECK: SSE_CAP_RESET: len=1 event=message data=third

    // 5.2 sse_flush MUST discard incomplete events lacking trailing blank line per W3C EventSource §9.2.6
    var p_eof = wing::SseParser { .. };
    var ev_eof: wing::SseEvent[..4] = [];
    wing::sse_feed(p_eof, "data: complete\n\ndata: incomplete_no_blank_line\n", ev_eof);
    wing::sse_flush(p_eof, ev_eof);
    print("SSE_FLUSH_EOF: count=", ev_eof.len, " has_data=", p_eof.has_data, " bom_checked=", p_eof.bom_checked, "\n");
    // CHECK: SSE_FLUSH_EOF: count=1 has_data=false bom_checked=false

    // 5.3 sse_clean_token_len MUST stop at NUL byte (0x00) as well as CR/LF
    var id_with_nul: u8[..16]  = ['i', 'd', '1', 0, 'x', 'y'];
    var fmt_out:     u8[..128] = [];
    wing::sse_format_event(fmt_out, "ev", "hello", id_with_nul[..], 0);
    var p_rt = wing::SseParser { .. };
    var ev_rt: wing::SseEvent[..2] = [];
    wing::sse_feed(p_rt, fmt_out[..], ev_rt);
    print("SSE_NUL_ID_CLEAN: id=", ev_rt[0].id[..], "\n");
    // CHECK: SSE_NUL_ID_CLEAN: id=id1

    // 5.4 SseSubscription.url MUST support URLs > 256 bytes (up to 2048 bytes)
    var long_url: u8[..512] = [];
    long_url.append("https://api.example.com/events?");
    for _ in 300 { long_url.push('a'); }
    let sub_long = wing::new_sse_subscription(long_url[..]);
    print("SSE_LONG_URL: len=", sub_long.url.len, " expected=", long_url.len, "\n");
    // CHECK: SSE_LONG_URL: len=331 expected=331

    // 5.5 sse_build_request_headers MUST strip CR/LF/NUL from host, path, and last_event_id
    var sub_inj = wing::new_sse_subscription("https://example.com/sse");
    sub_inj.parser.last_event_id.append("42\r\nX-Injected: pwn");
    var hdr_buf: u8[..512] = [];
    wing::sse_build_request_headers(sub_inj, "example.com\r\nX-Host: bad", "/sse\r\nX-Path: bad", hdr_buf);
    let has_injected = core::find(hdr_buf[..], "X-Injected") >= 0 ||
                       core::find(hdr_buf[..], "X-Host") >= 0 ||
                       core::find(hdr_buf[..], "X-Path") >= 0;
    print("SSE_HDR_INJECTION_BLOCKED: blocked=", !has_injected, "\n");
    // CHECK: SSE_HDR_INJECTION_BLOCKED: blocked=true
}

// ---- 6. TopicTree Regression Invariants -----------------------------------

fn test_topic_tree_regressions() {
    print("--- 6. TopicTree Regressions ---\n");

    // 6.1 match_topic MUST reject invalid mid-pattern '#' and wildcard publish topics
    let m_mid_hash = wing::match_topic("sport/#/tennis", "sport/a/b");
    let m_wild_pub = wing::match_topic("sport/+", "sport/+");
    print("TOPIC_MATCH_STRICT: mid_hash=", m_mid_hash, " wild_pub=", m_wild_pub, "\n");
    // CHECK: TOPIC_MATCH_STRICT: mid_hash=false wild_pub=false

    // 6.2 get_socket_topics MUST clear out_topics even when sock_fd <= 0
    var tree = wing::TopicTree { .. };
    var stale_topics: u8[..64][..32] = [];
    var dummy_pat:    u8[..64]       = [];
    dummy_pat.append("stale/topic");
    stale_topics.push(dummy_pat);
    let cnt_bad = wing::get_socket_topics(tree, -1, stale_topics);
    print("TOPIC_GET_CLEAR: ret=", cnt_bad, " len=", stale_topics.len, "\n");
    // CHECK: TOPIC_GET_CLEAR: ret=0 len=0

    // 6.3 subscribe_ex MUST reclaim newly created bucket when 4096 subscription nodes are full
    var full_tree = wing::TopicTree { .. };
    for i in 4096 {
        full_tree.nodes[i].in_use = true;
    }
    var old_c: i32 = 99;
    var new_c: i32 = 99;
    let ok_sub_full = wing::subscribe_ex(full_tree, 10, "new/bucket/pattern", old_c, new_c);
    print("TOPIC_BUCKET_RECLAIM: ok=", ok_sub_full, " active_buckets=", full_tree.active_buckets, " old=", old_c, " new=", new_c, "\n");
    // CHECK: TOPIC_BUCKET_RECLAIM: ok=false active_buckets=0 old=0 new=0

    // 6.4 prepare_message_compressed MUST succeed with has_compressed=false when deflate expands near-16KB incompressible payload
    var prep_msg = wing::PreparedMessage { .. };
    var shared_c = wing::SharedWsCompressor { .. };
    var incomp: u8[..16368] = [];
    var rng_s:  u32         = 0x12345678;
    for _ in 16368 {
        rng_s = rng_s ^ (rng_s << 13);
        rng_s = rng_s ^ (rng_s >> 17);
        rng_s = rng_s ^ (rng_s << 5);
        incomp.push((rng_s & 0xFF) as u8);
    }
    let ok_prep = wing::prepare_message_compressed(prep_msg, incomp[..], shared_c);
    print("TOPIC_PREP_INCOMP_16K: ok=", ok_prep, " has_comp=", prep_msg.has_compressed, " wire_gt_0=", prep_msg.wire.len > 0, "\n");
    // CHECK: TOPIC_PREP_INCOMP_16K: ok=true has_comp=false wire_gt_0=true

    // 6.5 publish_batch called 65 times with 0 subscribers MUST NOT panic with OOB at palette[64]
    var batch_tree = wing::TopicTree { .. };
    for _ in 65 {
        let _ = wing::publish_batch(batch_tree, "unsubscribed/topic", "hello");
    }
    print("TOPIC_BATCH_65_NO_SUBS: publishes=", batch_tree.total_publishes, " palette_len=", batch_tree.palette_len, "\n");
    // CHECK: TOPIC_BATCH_65_NO_SUBS: publishes=65 palette_len=0
}

// ---- 7. WebSocket Regression Invariants -----------------------------------

fn test_websocket_regressions() {
    print("--- 7. WebSocket Regressions ---\n");

    // 7.1 unmask_websocket_shifted MUST guard against signed i64 addition overflow
    var small_frame: u8[..16] = [1, 2, 3, 4, 5, 6, 7, 8];
    let mask_k: u8[4] = [0x11, 0x22, 0x33, 0x44];
    let unm = wing::unmask_websocket_shifted(small_frame[..], 4, 0x7FFFFFFFFFFFFFFE, mask_k);
    print("WS_UNMASK_OVERFLOW_GUARD: len=", unm.len, "\n");
    // CHECK: WS_UNMASK_OVERFLOW_GUARD: len=0

    // 7.2 DedicatedWsCompressor cross-message sliding dictionary compression & decompression
    // Construct message 1 with a high-entropy 64-byte token, and message 2 repeating that token once.
    // Without cross-message dictionary, message 2 cannot compress the single occurrence of the 64-byte token!
    // With cross-message dictionary (deflate_with_dict), message 2 references message 1's history and compresses smaller!
    var ded_c = wing::new_dedicated_ws_compressor(32);
    var ded_d = wing::new_dedicated_ws_compressor(32);
    let dict_msg1 = "UNIQUE_PREFIX_TOKEN_9876543210_ZYXWVUTSRQPONMLKJIHGFEDCBA_0123456789_END";
    var w1: u8[..256] = [];
    var w2: u8[..256] = [];
    let _ = wing::deflate_message_dedicated(ded_c, dict_msg1, w1, false);
    let _ = wing::deflate_message_dedicated(ded_c, dict_msg1, w2, false);
    var p1: u8[..256] = [];
    var p2: u8[..256] = [];
    let ok_p1 = wing::inflate_message_dedicated(ded_d, w1[..], p1, 65536, false);
    let ok_p2 = wing::inflate_message_dedicated(ded_d, w2[..], p2, 65536, false);
    print("WS_DEDICATED_DICT: w2_smaller=", w2.len < w1.len, " ok_p1=", ok_p1, " ok_p2=", ok_p2, " match=", p2[..] == dict_msg1, "\n");
    // CHECK: WS_DEDICATED_DICT: w2_smaller=true ok_p1=true ok_p2=true match=true

    // 7.3 ws_inflate_message and inflate_message_dedicated MUST clear out_plain on OutputBufferOverflow
    var dirty_plain: u8[..512] = [];
    dirty_plain.append("stale_prefix");
    let ok_ovf = wing::inflate_message_dedicated(ded_d, w1[..], dirty_plain, 10, false);
    print("WS_INFLATE_CLEAN_ON_OVF: ok=", ok_ovf, " plain_len=", dirty_plain.len, "\n");
    // CHECK: WS_INFLATE_CLEAN_ON_OVF: ok=false plain_len=0

    // 7.4 encode_ws_frame_compressed MUST clamp control frame payload to 125 bytes
    var big_ctrl_payload: u8[..200] = [];
    for _ in 150 { big_ctrl_payload.push('P'); }
    var ctrl_wire: u8[..256] = [];
    wing::encode_ws_frame_compressed(ctrl_wire, rfc::WS_OPCODE_PING, big_ctrl_payload[..], false, mask_k, true);
    print("WS_COMP_CTRL_CLAMP: wire_len=", ctrl_wire.len, "\n");
    // CHECK: WS_COMP_CTRL_CLAMP: wire_len=127

    // 7.5 is_valid_websocket_key MUST reject non-zero padding bits in 22nd char ('B' has low 4 bits 0001 != 0)
    let bad_pad_key = wing::is_valid_websocket_key("AAAAAAAAAAAAAAAAAAAAAAB==");
    let good_pad_key = wing::is_valid_websocket_key("dGhlIHNhbXBsZSBub25jZQ==");
    print("WS_KEY_PADDING_BITS: bad=", bad_pad_key, " good=", good_pad_key, "\n");
    // CHECK: WS_KEY_PADDING_BITS: bad=false good=true

    // 7.6 validate_websocket_accept MUST reject oversized client_key with empty server_accept
    var long_key: u8[..128] = [];
    for _ in 100 { long_key.push('A'); }
    let bypass_accept = wing::validate_websocket_accept(long_key[..], "");
    print("WS_ACCEPT_EMPTY_BYPASS: ok=", bypass_accept, "\n");
    // CHECK: WS_ACCEPT_EMPTY_BYPASS: ok=false

    // 7.7 ws_has_broken_compression MUST not wrap u32 on minor version overflow
    let ua_overflow = wing::ws_has_broken_compression("Mozilla/5.0 Version/15.4294967296 Safari/605.1.15");
    let ua_affected = wing::ws_has_broken_compression("Mozilla/5.0 Version/15.3 Safari/605.1.15");
    print("WS_SAFARI_OVERFLOW: ovf=", ua_overflow, " affected=", ua_affected, "\n");
    // CHECK: WS_SAFARI_OVERFLOW: ovf=false affected=true

    // 7.8 notify_buffered MUST guard against u64 addition overflow
    var ws_bp = wing::new_websocket_session(false);
    ws_bp.buffered_amount = 100;
    var bp_close: u8[..128] = [];
    let bp_status = wing::notify_buffered(ws_bp, 0xFFFFFFFFFFFFFFFF, bp_close);
    print("WS_BACKPRESSURE_U64_OVF: dropped=", bp_status == wing::WsSendStatus.Dropped, "\n");
    // CHECK: WS_BACKPRESSURE_U64_OVF: dropped=true

    // 7.9 consume_frame_view_into on already-closed session with incomplete frame MUST return (0, false)
    var ws_closed = wing::new_websocket_session(false);
    ws_closed.is_closed = true;
    var partial_wire: u8[..8] = [0x81, 0x85, 0x11, 0x22]; // incomplete masked frame (needs 6 hdr + 5 payload = 11 bytes)
    var c_view = wing::WsMessageView { .. };
    var c_reply: u8[..64] = [];
    let consumed_closed, handled_closed = wing::consume_frame_view(ws_closed, partial_wire[..], c_view, c_reply);
    print("WS_CLOSED_PARTIAL: consumed=", consumed_closed, " handled=", handled_closed, "\n");
    // CHECK: WS_CLOSED_PARTIAL: consumed=0 handled=false

    // 7.10 ws_upgrade_request MUST NOT leave 101 headers in out_resp when subprotocol > 64 bytes, and validate_h2_websocket_request MUST enforce http/https :scheme
    var upg_req = wing::new_request("GET", "http://example.com/ws");
    upg_req.set_header("Host", "example.com");
    upg_req.set_header("Upgrade", "websocket");
    upg_req.set_header("Connection", "Upgrade");
    upg_req.set_header("Sec-WebSocket-Version", "13");
    upg_req.set_header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
    var big_subproto: u8[..128] = [];
    for _ in 70 { big_subproto.push('p'); }
    var upg_resp = wing::Response { .. };
    let _, ok_upg_big = wing::ws_upgrade_request(upg_req, upg_resp, big_subproto[..]);
    let leaked_accept = wing::header(upg_resp, "Sec-WebSocket-Accept").len > 0;

    var h2_req = wing::Request { .. };
    wing::format_h2_websocket_request(h2_req, "/ws", "example.com", "ftp");
    let ok_h2_ftp = wing::validate_h2_websocket_request(h2_req);
    print("WS_UPGRADE_CLEAN: ok_big=", ok_upg_big, " leaked_accept=", leaked_accept, " h2_ftp=", ok_h2_ftp, "\n");
    // CHECK: WS_UPGRADE_CLEAN: ok_big=false leaked_accept=false h2_ftp=false
}

// ---- 8. WebTransport Regression Invariants --------------------------------

fn test_webtransport_regressions() {
    print("--- 8. WebTransport Regressions ---\n");

    // 8.1 read_varint MUST NOT mutate idx on truncated multi-byte varint
    var trunc_varint: u8[1] = [0x40]; // 2-byte prefix (01), missing 2nd byte
    var v_idx:        i64   = 0;
    let _, ok_vi = wing::read_varint(trunc_varint[..], v_idx);
    print("WT_READ_VARINT_ATOMIC: ok=", ok_vi, " idx=", v_idx, "\n");
    // CHECK: WT_READ_VARINT_ATOMIC: ok=false idx=0

    // 8.2 decode_webtransport_datagram MUST reject quarter_id > 0x0FFFFFFFFFFFFFFF (u64 * 4 overflow)
    // 0xFF followed by 7 0xFF bytes encodes varint 0x3FFFFFFFFFFFFFFF
    let ovf_dgram_wire: u8[10] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 'A'];
    var dgram_out = wing::WebTransportDatagram { .. };
    let ok_dgram_ovf = wing::decode_webtransport_datagram(ovf_dgram_wire[..], dgram_out);
    print("WT_DGRAM_QID_OVF: ok=", ok_dgram_ovf, "\n");
    // CHECK: WT_DGRAM_QID_OVF: ok=false

    // 8.3 decode_webtransport_close_session MUST validate UTF-8 and not mutate out on >1024 reason
    var bad_utf8_close: u8[6] = [0x00, 0x00, 0x00, 0x01, 0xFF, 0xFE];
    var close_out = wing::WebTransportCloseSession { error_code: 777, .. };
    let ok_bad_u8 = wing::decode_webtransport_close_session(bad_utf8_close[..], close_out);
    print("WT_CLOSE_UTF8: ok=", ok_bad_u8, " preserved_code=", close_out.error_code, "\n");
    // CHECK: WT_CLOSE_UTF8: ok=false preserved_code=777

    // 8.4 WebTransportDemuxer MUST reuse closed stream slots across > 64 sequential streams
    var demuxer = wing::WebTransportDemuxer { .. };
    let _ = wing::register_webtransport_session(demuxer, 4);
    var all_routed = true;
    for s in 70 {
        let stream_id = (s as u64) * 4; // bidi stream IDs: 0, 4, 8, ...
        let open_pkt: u8[4] = [0x40, 0x41, 0x04, 'A'];
        var p_out = wing::WebTransportStreamPayload { .. };
        // Open with fin=false, then close with fin=true
        let ok1 = wing::demux_webtransport_stream(demuxer, stream_id, open_pkt[..], false, p_out);
        let ok2 = wing::demux_webtransport_stream(demuxer, stream_id, "B", true, p_out);
        if !ok1 || !ok2 || p_out.payload != "B" {
            all_routed = false;
        }
    }
    print("WT_DEMUX_REUSE_70_STREAMS: all_routed=", all_routed, "\n");
    // CHECK: WT_DEMUX_REUSE_70_STREAMS: all_routed=true
}

// ---- 9. Cross-Component & RFC Edge-Case Regressions -----------------------

fn test_cross_component_and_rfc_edge_regressions() {
    print("--- 9. Cross-Component & RFC Edge-Case Regressions ---\n");

    // 9.1 (F001) RFC 7692 §7.2.3 BFINAL=0 sync-flush vectors & bounded buffer capacity
    var shared_c = wing::SharedWsCompressor { .. };
    var ded_c = wing::new_dedicated_ws_compressor(32);
    let rfc7692_hello: u8[7] = [0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00]; // §7.2.3.1
    let rfc7692_win:   u8[5] = [0xf2, 0x00, 0x11, 0x00, 0x00];             // §7.2.3.2
    let rfc7692_empty: u8[1] = [0x00];                                     // §7.2.3.6
    var plain1:  u8[..64] = [];
    var plain2:  u8[..64] = [];
    var plain_e: u8[..16] = [];
    let ok_s1 = wing::ws_inflate_message(shared_c, rfc7692_hello[..], plain1);
    let ok_d1 = wing::inflate_message_dedicated(ded_c, rfc7692_hello[..], plain1);
    let ok_d2 = wing::inflate_message_dedicated(ded_c, rfc7692_win[..], plain2);
    let ok_se = wing::ws_inflate_message(shared_c, rfc7692_empty[..], plain_e);
    var tiny_plain: u8[..3] = [];
    let ok_tiny = wing::ws_inflate_message(shared_c, rfc7692_hello[..], tiny_plain, 65536);
    var tiny_wire: u8[..2] = [];
    let ok_tiny_def = wing::deflate_message_dedicated(ded_c, "HelloHelloHello", tiny_wire);
    print(
        "F001_RFC7692_DEFLATE: s1=", ok_s1 && plain1[..] == "Hello",
        " d12=", ok_d1 && ok_d2 && plain2[..] == "Hello",
        " empty=", ok_se && plain_e.len == 0,
        " tiny_inf=", ok_tiny, " tiny_def=", ok_tiny_def, "\n",
    );
    // CHECK: F001_RFC7692_DEFLATE: s1=true d12=true empty=true tiny_inf=false tiny_def=false

    // 9.2 (F002) RFC 6455 §4.1 & §4.2.1 HTTP/1.0 rejection, duplicate key/version, subprotocol tchar
    var req_h10 = wing::new_request("GET", "/ws");
    req_h10.is_http10 = true;
    wing::set_header(req_h10, "Host", "example.com");
    wing::set_header(req_h10, "Upgrade", "websocket");
    wing::set_header(req_h10, "Connection", "Upgrade");
    wing::set_header(req_h10, "Sec-WebSocket-Version", "13");
    wing::set_header(req_h10, "Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
    var resp_h10 = wing::Response { .. };
    let _, ok_h10 = wing::ws_upgrade_request(req_h10, resp_h10);

    var req_dup = wing::new_request("GET", "/ws");
    wing::set_header(req_dup, "Host", "example.com");
    wing::set_header(req_dup, "Upgrade", "websocket");
    wing::set_header(req_dup, "Connection", "Upgrade");
    wing::set_header(req_dup, "Sec-WebSocket-Version", "13");
    wing::set_header(req_dup, "Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
    let _ = wing::append_header(req_dup.headers, "Sec-WebSocket-Key", "AQIDBAUGBwgJCgsMDQ4PEA==");
    var resp_dup = wing::Response { .. };
    let _, ok_dup = wing::ws_upgrade_request(req_dup, resp_dup);
    let bad_sub = wing::has_subprotocol_token("chat, bad proto", "bad proto");
    print("F002_WS_HANDSHAKE: h10=", ok_h10, " dup_key=", ok_dup, " bad_sub=", bad_sub, "\n");
    // CHECK: F002_WS_HANDSHAKE: h10=false dup_key=false bad_sub=false

    // 9.3 (F003) TopicTree batch FIFO order across overlapping wildcard buckets & unsubscribe migration
    var tt = wing::TopicTree { .. };
    let _ = wing::subscribe(tt, 55, "sport/tennis/+");
    let _ = wing::subscribe(tt, 55, "sport/#");
    let _ = wing::publish_batch(tt, "sport/tennis/p1", "first");
    let _ = wing::publish_batch(tt, "sport/swim", "second");
    let head_idx = tt.drainable_head as i64;
    let fifo_ok = head_idx >= 0 &&
        tt.nodes[head_idx].num_message_indices == 2 &&
        tt.nodes[head_idx].message_indices[0] == 0 &&
        tt.nodes[head_idx].message_indices[1] == 1;
    let _ = wing::unsubscribe(tt, 55, "sport/tennis/+");
    let retained_after_unsub = wing::subscriber_queued_messages(tt, 55);
    print("F003_TOPIC_BATCH: fifo=", fifo_ok, " retained=", retained_after_unsub, "\n");
    // CHECK: F003_TOPIC_BATCH: fifo=true retained=2

    // 9.4 (F004) W3C EventSource §9.2.6 uncommitted id: discarded on sse_flush & prepare_request sanitize
    var sse_p = wing::SseParser { .. };
    var sse_evs: wing::SseEvent[..4] = [];
    wing::sse_feed(sse_p, "id: committed-1\ndata: ok\n\nid: uncommitted-2\ndata: partial", sse_evs);
    wing::sse_flush(sse_p, sse_evs);
    let id_preserved = sse_p.last_event_id[..] == "committed-1";

    // 9.5 (F005) WebTransport QUIC datagram bounded cap, session re-register clean & response reopen
    let dgram_big: u8[7] = [0x31, 0x05, 'A', 'B', 'C', 'D', 'E'];
    var small_dgram_out: u8[..3] = [];
    let ok_small_dg = wing::decode_quic_datagram_frame(dgram_big[..], small_dgram_out);
    var wt_sess = wing::WebTransportSession { is_active: false, is_draining: true, close_code: 99, .. };
    var wt_res = wing::Response { .. };
    wt_res.status_code = 200;
    let _ = wing::handle_webtransport_response(wt_res, wt_sess);
    let wt_reopened = wing::is_webtransport_session_open(wt_sess) && wt_sess.close_code == 0;
    print("F004_F005_SSE_WT: id_ok=", id_preserved, " small_dg=", ok_small_dg, " wt_open=", wt_reopened, "\n");
    // CHECK: F004_F005_SSE_WT: id_ok=true small_dg=false wt_open=true
}

fn main() {
    test_ws_control_frame_invariants();
    test_ws_rsv_bit_invariants();
    test_ws_close_code_invariants();
    test_cookie_syntax_and_prefix_invariants();
    test_sse_regressions();
    test_topic_tree_regressions();
    test_websocket_regressions();
    test_webtransport_regressions();
    test_cross_component_and_rfc_edge_regressions();
    print("ALL REALTIME SPEC INVARIANTS VERIFIED\n");
}

// CHECK: ALL REALTIME SPEC INVARIANTS VERIFIED
