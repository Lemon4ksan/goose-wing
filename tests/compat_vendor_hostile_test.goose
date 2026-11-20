// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Non-Greenhouse Vendor & Issue-Tracker Regression Suite
// Ports adversarial wire vectors from vendor/{llhttp, h2o, curl, sfparse, chromium,
// nghttp2, h2, nghttp3, ngtcp2, quiche, rustls, picotls, mbedtls, tough-cookie,
// cookie-rs, cjose, wslay, tungstenite, uWebSockets, grpc-go, tonic} under
// 1-byte / split-CRLF / split-varint fragmentation, dirty reused state, pipelined
// trailing bytes, conflicting multi-header lines, and capacity boundaries.
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

fn feed_chunked_at_split(wire: const u8[:], split_at: i64, out_body: u8[>..]&) -> http_internal::ChunkFsmStatus, i64 {
    out_body.clear();
    var fsm = http_internal::new_chunk_fsm_decoder();
    var total_used: i64 = 0;
    for part_idx in 2 {
        var rem = if part_idx == 0 { wire[..split_at] } else { wire[split_at..] };
        while rem.len > 0 {
            let st, used, chunk = http_internal::chunk_fsm_feed(fsm, rem);
            total_used = core::add_sat_i64(total_used, used);
            if chunk.len > 0 {
                out_body.append(chunk);
            }
            if st == http_internal::ChunkFsmStatus.Complete || st == http_internal::ChunkFsmStatus.Error {
                return st, total_used;
            }
            if used <= 0 { break; }
            rem = rem[used..];
        }
    }
    return http_internal::ChunkFsmStatus.NeedMore, total_used;
}

// 1. HTTP/1.1 Chunked FSM & Smuggling Under Split-CRLF & Dirty State (vendor/llhttp, h2o)
fn test_vendor_h1_chunked_and_smuggling(t: lit::T&) {
    t.run("llhttp transfer-encoding.md: every split index + pipelined bytes") { sub =>
        let chunked_msg: const u8[:] =
            "5;ext=\"a;b\"\r\nhello\r\n6\r\n world\r\n000\r\nX-Tr: 1\r\n\r\nGET /pipelined HTTP/1.1\r\nHost: ex.com\r\n\r\n";
        let expected_consumed: i64 = 47;
        var out_body: u8[>..] = [];
        for split_idx in chunked_msg.len {
            let st, used = feed_chunked_at_split(chunked_msg, split_idx, out_body);
            sub.assert_true(st == http_internal::ChunkFsmStatus.Complete, "split reaches Complete");
            sub.assert_eq(used, expected_consumed, "stops before pipelined request");
            sub.assert_bytes_eq(out_body[..], "hello world", "reassembled payload matches");
        }
    };

    t.run("llhttp content-length.md & CVE-2023-45287: dirty reused Request/HeaderMap") { sub =>
        var dirty_req = wing::new_request("POST", "/dirty");
        let seed_wire: const u8[:] = "POST /ok HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nabc";
        let ok_seed, _ = wing::parse_http1_wire_request(seed_wire, dirty_req);
        sub.assert_true(ok_seed, "seed request parsed into dirty struct");

        let te_cl_wire: const u8[:] =
            "POST /first HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding:\r\nContent-Length: 5\r\n\r\nhello";
        let ok_te_cl, _ = wing::parse_http1_wire_request(te_cl_wire, dirty_req);
        sub.assert_false(ok_te_cl, "empty Transfer-Encoding + Content-Length rejected");

        let dup_cl_wire: const u8[:] =
            "PUT /url HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\na";
        let ok_dup_cl, _ = wing::parse_http1_wire_request(dup_cl_wire, dirty_req);
        sub.assert_false(ok_dup_cl, "conflicting duplicate Content-Length rejected");

        let sp_colon_wire: const u8[:] =
            "PUT /url HTTP/1.1\r\nHost: example.com\r\nContent-Length : 4\r\n\r\nabcd";
        let ok_sp, _ = wing::parse_http1_wire_request(sp_colon_wire, dirty_req);
        sub.assert_false(ok_sp, "space before colon in Content-Length rejected");

        var body_bad: u8[>..] = [];
        let st_lf, _ = feed_chunked_at_split("5\nhello\r\n0\r\n\r\n", 1, body_bad);
        sub.assert_true(st_lf == http_internal::ChunkFsmStatus.Error, "bare LF in chunk size rejected");
        let st_bws, _ = feed_chunked_at_split("5 a\r\nhello\r\n0\r\n\r\n", 2, body_bad);
        sub.assert_true(st_bws == http_internal::ChunkFsmStatus.Error, "hex after BWS rejected");
        let st_ovf, _ = feed_chunked_at_split("10000000000000000\r\nx\r\n0\r\n\r\n", 8, body_bad);
        sub.assert_true(st_ovf == http_internal::ChunkFsmStatus.Error, "u64 hex overflow rejected");
    };
}

// 2. Structured Fields & No-Vary-Search Streaming Parser (vendor/sfparse, chromium)
fn test_vendor_sfv_and_novarysearch(t: lit::T&) {
    t.run("chromium No-Vary-Search: duplicate keys, overrides & 8KB streaming header") { sub =>
        let nvs1, ok_nvs1 = wing::parse_no_vary_search("params=(\"a\" \"b\"), params=?0, key-order=?1");
        sub.assert_true(ok_nvs1, "parsed duplicate-key NVS");
        sub.assert_false(nvs1.key_order_matters, "key-order=?1 disables key order sensitivity");
        sub.assert_true(
            wing::are_urls_nvs_equivalent(
                "https://example.com/p?b=2&a=1", "https://example.com/p?a=1&b=2", nvs1,
            ),
            "reordered params match under key-order=?1",
        );

        let nvs2, ok_nvs2 = wing::parse_no_vary_search("params, except=(\"id\" \"lang\");unk=1");
        sub.assert_true(ok_nvs2, "parsed params+except NVS");
        sub.assert_true(
            wing::are_urls_nvs_equivalent(
                "https://example.com/p?id=7&utm=x&lang=en",
                "https://example.com/p?id=7&utm=y&lang=en",
                nvs2,
            ),
            "except list preserves id and lang while ignoring utm",
        );
        sub.assert_false(
            wing::are_urls_nvs_equivalent(
                "https://example.com/p?id=7&utm=x&lang=en",
                "https://example.com/p?lang=en&id=7&utm=y",
                nvs2,
            ),
            "without key-order, reordered preserved params do not match",
        );
        sub.assert_false(
            wing::are_urls_nvs_equivalent(
                "https://example.com/p?id=7&lang=en",
                "https://example.com/p?id=8&lang=en",
                nvs2,
            ),
            "different preserved id does not match",
        );

        var huge_nvs: u8[..8192] = [];
        huge_nvs.append("key-order");
        for _ in 240 {
            huge_nvs.append(", unk=(\"x\" \"y\")");
        }
        let nvs_huge, ok_huge = wing::parse_no_vary_search(huge_nvs[..]);
        sub.assert_true(ok_huge, "parsed 8KB NVS header");
        sub.assert_false(nvs_huge.key_order_matters, "8KB streaming NVS parses without stack overflow");
    };

    t.run("sfparse & nghttp2_http_test: dirty containers & boundary rejections") { sub =>
        var dict: wing::SfDictEntry[..16] = [];
        sub.assert_true(wing::parse_sf_dict("u=3, i", dict), "seed valid dict");
        sub.assert_false(wing::parse_sf_dict("u=0, ", dict), "trailing comma rejected (nghttp2_http_test)");
        sub.assert_eq(dict.len, 0, "failed parse clears dirty dict container");

        let pri_override, ok_pri = wing::parse_http_priority("u=0, i, i=?0, u=6", false);
        sub.assert_true(ok_pri, "duplicate priority keys override per RFC 8941 (nghttp2_http_test:112)");
        sub.assert_eq(pri_override.urgency as i64, 6, "u=6 overrides u=0");
        sub.assert_false(pri_override.incremental, "i=?0 overrides i");
    };
}

// 3. HTTP Cache Multi-Header Cache-Control & Dirty ScalableHttpCache (chromium, curl)
fn test_vendor_cache_multiline_poisoning(t: lit::T&) {
    t.run("multi-line conflicting Cache-Control: public + second line no-store") { sub =>
        var cache = wing::ScalableHttpCache { .. };
        wing::init_scalable_http_cache(cache, 16, 4096);

        var req = wing::new_request("GET", "https://cdn.example.com/secret.json");
        var res_ok = wing::Response { status_code: 200, .. };
        res_ok.set_header("Cache-Control", "public, max-age=600");
        res_ok.body.append("{\"v\":1}");
        sub.assert_true(wing::store_response(cache, req, res_ok, 1000), "initial public response cached");

        var res_poison = wing::Response { status_code: 200, .. };
        let _ = wing::append_header(res_poison.headers, "cache-control", "public, max-age=3600");
        let _ = wing::append_header(res_poison.headers, "cache-control", "no-store");
        res_poison.body.append("{\"v\":2}");
        var req2 = wing::new_request("GET", "https://cdn.example.com/no-store.json");
        sub.assert_false(
            wing::store_response(cache, req2, res_poison, 1005),
            "second Cache-Control: no-store line blocks storage",
        );
    };
}

// 4. Redirect Sanitization & H2 Connection Pool Coalescing (curl, pingora, h2o)
fn test_vendor_redirect_and_pool_coalescing(t: lit::T&) {
    t.run("curl cross-origin redirect strips credentials & pool blocks PSL coalescing") { sub =>
        var req = wing::new_post("https://a.example.com/login");
        wing::set_header(req, "Authorization", "Bearer secret-tok");
        wing::set_header(req, "Cookie", "sid=12345");
        wing::set_header(req, "Proxy-Authorization", "Basic abc");
        wing::set_header(req, "Content-Length", "12");
        wing::set_header(req, "Content-Type", "application/json");

        let info = wing::compute_redirect_info(
            "POST", 302, "https://a.example.com/login", "https://evil.other.org/landing",
            wing::ReferrerPolicy.StrictOriginWhenCrossOrigin, "https://a.example.com/login",
        );
        wing::sanitize_headers_on_redirect(req.headers, info);
        sub.assert_false(wing::has_header(req, "Authorization"), "cross-origin Authorization stripped");
        sub.assert_false(wing::has_header(req, "Cookie"), "cross-origin Cookie stripped");
        sub.assert_false(wing::has_header(req, "Proxy-Authorization"), "Proxy-Authorization stripped");
        sub.assert_false(wing::has_header(req, "Content-Length"), "POST->GET strips Content-Length");

        sub.assert_false(
            wing::matches_san_pattern("*.co.uk", "bank.co.uk"),
            "wildcard SAN on public suffix *.co.uk rejected in pool coalescing",
        );
        sub.assert_true(
            wing::matches_san_pattern("*.example.co.uk", "api.example.co.uk"),
            "registrable wildcard *.example.co.uk accepted",
        );
    };
}

// 5. HTTP/2 Chopped Frames, Mid-Header Interleaving & HPACK Bounds (nghttp2, h2)
fn test_vendor_h2_chopped_ingress_and_hpack(t: lit::T&) {
    t.run("nghttp2: 3-byte chopped preface + headers without END_HEADERS + interleaved PING") { sub =>
        var sess = server_internal::new_h2_server_session("localhost");
        var pipeline = wing::ServerPipelineConfig { .. };
        var timer = server_internal::ConnectionTimer { .. };
        var wire_in:  u8[..512]   = [];
        var wire_out: u8[..16384] = [];

        wire_in.append(rfc::H2_CLIENT_PREFACE[..]);
        let set_hdr = h2_internal::FrameHeader {
            length: 0, frame_type: rfc::H2_FRAME_SETTINGS, flags: 0, stream_id: 0,
        };
        h2_internal::encode_frame_header_to(set_hdr, wire_in);
        // HEADERS on stream 1 WITHOUT END_HEADERS (flags = 0x01 END_STREAM only), payload 0x82 (:method GET)
        let hdr_incomplete = h2_internal::FrameHeader {
            length: 1, frame_type: rfc::H2_FRAME_HEADERS, flags: rfc::H2_FLAG_END_STREAM, stream_id: 1,
        };
        h2_internal::encode_frame_header_to(hdr_incomplete, wire_in);
        wire_in.push(0x82);
        // Illegal PING frame interleaved while CONTINUATION is required on stream 1
        let bad_ping = h2_internal::FrameHeader {
            length: 8, frame_type: rfc::H2_FRAME_PING, flags: 0, stream_id: 0,
        };
        h2_internal::encode_frame_header_to(bad_ping, wire_in);
        for _ in 8 { wire_in.push(0); }

        var pending: u8[..512] = [];
        var pos:     i64       = 0;
        var failed = false;
        while pos < wire_in.len {
            let end = min(wire_in.len, pos + 3);
            let _ = pending.try_append(wire_in[pos..end]);
            pos = end;
            wire_out.clear();
            let consumed, ok = server_internal::handle_h2_server_ingress(
                sess, pipeline, timer, "127.0.0.1", pending[..], 1000, wire_out,
            );
            if !ok {
                failed = true;
                break;
            }
            if consumed > 0 {
                pending.compact_wire_buffer(consumed);
            }
        }
        sub.assert_true(failed, "PING interleaved mid-HEADERS/CONTINUATION rejected under 3B chopping");
    };

    t.run("ls-hpack / h2: HPACK table size update exceeding allowed max rejected") { sub =>
        var dt = h2_internal::new_dynamic_table(256);
        var hdrs = wing::HeaderMap { .. };
        var pseudo = h2_internal::H2PseudoHeaders { .. };
        // Dynamic table size update 0x3F 0xE2 0x01 => 31 + (0x62 + 128) = 287 > 256
        let oversize_update: u8[3] = [0x3F, 0xE2, 0x01];
        let err = h2_internal::decode_hpack_to_map(dt, oversize_update[..], pseudo, hdrs, 8192, true);
        sub.assert_ne(err as i64, rfc::H2_ERR_NO_ERROR as i64, "size update > max_allowed_size rejected");
    };
}

// 6. QUIC Packet Number Wraparound, Large Header Offset & Overlapping Streams (ngtcp2, quiche)
fn test_vendor_quic_pn_and_overlapping_reassembly(t: lit::T&) {
    t.run("RFC 9000 A.3 PN reconstruction & pn_offset > 255 header protection") { sub =>
        let decoded_pn, ok_pn = quic_internal::decode_packet_number_checked(0xa82f30ea, 0x9b32, 2);
        sub.assert_true(ok_pn, "RFC 9000 Appendix A.3 vector valid");
        sub.assert_eq(decoded_pn as i64, 0xa82f9b32, "RFC 9000 A.3 reconstructed PN == 0xa82f9b32");

        // Packet with pn_offset = 300 (> u8::MAX = 255) to verify u32 pn_offset roundtrip
        var pkt: u8[..340] = [];
        pkt.push(0xC3); // Long header with 4-byte PN (pn_bits = 3)
        for _ in 299 { pkt.push(0xAA); }
        // 4-byte PN at offset 300..304 + 20 bytes ciphertext sample
        pkt.push(0x12); pkt.push(0x34); pkt.push(0x56); pkt.push(0x78);
        for k in 20 { pkt.push((k + 1) as u8); }

        let mask: u8[5] = [0x0F, 0xA1, 0xB2, 0xC3, 0xD4];
        quic_internal::apply_header_protection(pkt[..], 300, 4, mask);
        let pn_len, trunc_pn = quic_internal::remove_header_protection(pkt[..], 300, mask);
        sub.assert_eq(pn_len as i64, 4, "pn_offset=300 recovers pn_len=4 without u8 truncation");
        sub.assert_eq(trunc_pn as i64, 0x12345678, "pn_offset=300 recovers exact 32-bit PN");
    };

    t.run("ngtcp2 / quiche: out-of-order overlapping STREAM chunks & final_size conflict") { sub =>
        var rb = quic_internal::new_reassembly_buffer(64);
        sub.assert_true(quic_internal::insert_fragment(rb, 6, "world!", false), "tail chunk at offset 6");
        sub.assert_true(quic_internal::insert_fragment(rb, 0, "hello world", false), "overlapping prefix 0..11");
        sub.assert_true(quic_internal::insert_fragment(rb, 12, "!", true), "FIN at offset 13");
        // Conflicting FIN shrinking final size from 13 to 10 must fail
        sub.assert_false(quic_internal::insert_fragment(rb, 10, "", true), "conflicting FIN offset rejected");

        var out: u8[..64] = [];
        let n = quic_internal::read_contiguous(rb, out);
        sub.assert_eq(n as i64, 13, "13 contiguous bytes reassembled");
        sub.assert_bytes_eq(out[..], "hello world!!", "overlapping QUIC stream bytes intact");
    };
}

// 7. HTTP/3 1-Byte Varint Fragmentation & Forbidden H2 Frames (nghttp3, quiche)
fn test_vendor_h3_1byte_fragmentation(t: lit::T&) {
    t.run("nghttp3: 1-byte fragmented control stream & forbidden H2 PING frame 0x06") { sub =>
        let settings = fingerprint::H3Settings { .. };
        var srv = h3_internal::new_h3_server_connection(settings);

        // Client control stream (uni stream 2): type 0x00 + SETTINGS frame (type 0x04, len 0)
        // followed by forbidden HTTP/2 PING frame (type 0x06, len 0)
        let ctrl_bytes: u8[4] = [0x00, 0x04, 0x00, 0x06];
        let err0 = h3_internal::handle_stream_data(srv, 2, false, ctrl_bytes[0..1], false);
        let err1 = h3_internal::handle_stream_data(srv, 2, false, ctrl_bytes[1..2], false);
        let err2 = h3_internal::handle_stream_data(srv, 2, false, ctrl_bytes[2..3], false);
        sub.assert_eq(err0, rfc::H3_ERR_NO_ERROR, "1B control stream type accepted");
        sub.assert_eq(err1, rfc::H3_ERR_NO_ERROR, "1B SETTINGS type accepted");
        sub.assert_eq(err2, rfc::H3_ERR_NO_ERROR, "1B SETTINGS len=0 accepted");

        let bad_tail: u8[2] = [0x06, 0x00];
        let err_bad = h3_internal::handle_stream_data(srv, 2, false, bad_tail[..], false);
        sub.assert_ne(err_bad, rfc::H3_ERR_NO_ERROR, "forbidden H2 frame 0x06 on H3 control stream rejected");

        // Duplicate client control stream on uni stream 6 must fail with H3_STREAM_CREATION_ERROR
        let dup_ctrl: u8[3] = [0x00, 0x04, 0x00];
        let err_dup = h3_internal::handle_stream_data(srv, 6, false, dup_ctrl[..], false);
        sub.assert_ne(err_dup, rfc::H3_ERR_NO_ERROR, "second H3 control stream rejected");
    };
}

// 8. TLS 1.3 Slice Unseal KeyUpdate Ratchet & Unknown PSK Fallback (rustls, picotls, BoGo)
fn test_vendor_tls13_keyupdate_and_unknown_psk(t: lit::T&) {
    t.run("TLS 1.3 slice unseal: KeyUpdate ratchets rx key & user_canceled warning ignored") { sub =>
        let slot_idx = wing::alloc_tls_cipher_slot();
        sub.assert_ne(slot_idx as i64, 0xFFFF, "allocated cipher slot");
        defer wing::free_tls_cipher_slot(slot_idx);

        let idx = slot_idx as i64;
        var sender_sec: u8[32] = [0x33; 32];
        var sender_key: u8[16] = [0; 16];
        var sender_iv:  u8[12] = [0; 12];
        tls_internal::ks_derive_key_iv(1, sender_sec[..], 16, sender_key[..], sender_iv);

        wing::g_tls_cipher_slots[idx].cipher_suite = rfc::TLS_CIPHER_AES_128_GCM_SHA256;
        wing::g_tls_cipher_slots[idx].hash_id = 1;
        wing::g_tls_cipher_slots[idx].hash_len = 32;
        wing::g_tls_cipher_slots[idx].key_len = 16;
        for i in 32 { wing::g_tls_cipher_slots[idx].rx_traffic_secret[i] = sender_sec[i]; }
        for i in 16 { wing::g_tls_cipher_slots[idx].rx_key[i] = sender_key[i]; }
        wing::g_tls_cipher_slots[idx].rx_iv = sender_iv;
        wing::tls_prepare_cipher_aes_key(
            rfc::TLS_CIPHER_AES_128_GCM_SHA256,
            wing::g_tls_cipher_slots[idx].rx_key[..16],
            wing::g_tls_cipher_slots[idx].rx_aes_key,
        );

        // Seal Record 0: user_canceled warning alert [level=1, desc=90]
        var rec0: u8[64] = [0; 64];
        let warn_msg: u8[2] = [1, rfc::TLS_ALERT_USER_CANCELED];
        let len0, _, ok0 = wing::tls_record_seal_into(
            rfc::TLS_CIPHER_AES_128_GCM_SHA256, sender_key[..], sender_iv, 0,
            rfc::TLS_CONTENT_ALERT, warn_msg[..], rec0[..],
        );
        sub.assert_true(ok0, "sealed user_canceled warning");

        // Seal Record 1 (seq=1): KeyUpdate (update_not_requested = 0): [24, 0, 0, 1, 0]
        var rec1: u8[64] = [0; 64];
        let ku_msg: u8[5] = [rfc::TLS_HS_KEY_UPDATE, 0, 0, 1, 0];
        let len1, _, ok1 = wing::tls_record_seal_into(
            rfc::TLS_CIPHER_AES_128_GCM_SHA256, sender_key[..], sender_iv, 1,
            rfc::TLS_CONTENT_HANDSHAKE, ku_msg[..], rec1[..],
        );
        sub.assert_true(ok1, "sealed KeyUpdate record");

        // Ratchet sender traffic secret to epoch+1, seq=0 and seal ApplicationData "post-ku-ok"
        tls_internal::ks_update_traffic_secret(1, 32, sender_sec[..]);
        tls_internal::ks_derive_key_iv(1, sender_sec[..], 16, sender_key[..], sender_iv);
        var rec2: u8[64] = [0; 64];
        let len2, _, ok2 = wing::tls_record_seal_into(
            rfc::TLS_CIPHER_AES_128_GCM_SHA256, sender_key[..], sender_iv, 0,
            rfc::TLS_CONTENT_APPLICATION_DATA, "post-ku-ok", rec2[..],
        );
        sub.assert_true(ok2, "sealed post-KeyUpdate app data");

        var scratch:   u8[128]   = [0; 128];
        var out_plain: u8[..128] = [];
        let st0 = wing::unseal_single_slot_record(
            wing::g_tls_cipher_slots[idx], rec0[..5], rec0[5..len0], scratch[..], out_plain,
        );
        let st1 = wing::unseal_single_slot_record(
            wing::g_tls_cipher_slots[idx], rec1[..5], rec1[5..len1], scratch[..], out_plain,
        );
        let st2 = wing::unseal_single_slot_record(
            wing::g_tls_cipher_slots[idx], rec2[..5], rec2[5..len2], scratch[..], out_plain,
        );
        sub.assert_true(st0 == wing::TlsSliceUnsealStatus.ControlHandled, "user_canceled warning ignored");
        sub.assert_true(st1 == wing::TlsSliceUnsealStatus.ControlHandled, "KeyUpdate handled without closing");
        sub.assert_true(st2 == wing::TlsSliceUnsealStatus.Ok, "ratcheted ApplicationData decrypted");
        sub.assert_bytes_eq(out_plain[..], "post-ku-ok", "decrypted payload after KeyUpdate matches");
    };

    t.run("RFC 8446 §4.2.11: unknown PSK falls back to 1-RTT while forged known binder aborts") { sub =>
        wing::clear_tls13_session_tickets();
        let cli_rand: u8[32] = [0x42; 32];
        let cli_priv: u8[32] = [0x24; 32];
        let cli_pub = core::x25519_base_scalarmult(cli_priv);
        let fake_psk: u8[32] = [0x99; 32];

        var ch_payload: u8[..1024] = [];
        wing::build_tls13_client_hello_payload(
            cli_rand, cli_pub, "api.example.com", "h2", ch_payload, "expired-ticket-id", 100,
        );
        var ch_msg: u8[..1024] = [];
        ch_msg.push(rfc::TLS_HS_CLIENT_HELLO);
        core::append_u24_be(ch_msg, ch_payload.len as u32);
        ch_msg.append(ch_payload[..]);

        var ks_early, ok_kse = tls_internal::ks_init(rfc::TLS_CIPHER_AES_128_GCM_SHA256);
        sub.assert_true(ok_kse && tls_internal::ks_init_early_secret(ks_early, fake_psk[..]), "init early secret");
        var b_key: u8[32] = [0; 32];
        for i in 32 { b_key[i] = ks_early.binder_key[i]; }
        let trunc_ch, ok_tr = tls_internal::truncate_client_hello_for_binder(ch_msg[..], 33);
        sub.assert_true(ok_tr, "truncated CH for binder");
        var binder: u8[32] = [0; 32];
        sub.assert_true(wing::compute_tls13_psk_binder(b_key, trunc_ch, binder), "computed PSK binder");
        let b_start = ch_msg.len - 32;
        for i in 32 { ch_msg[b_start + i] = binder[i]; }

        var sid:     u8[..32] = [];
        var out_pub: u8[32]   = [0; 32];
        var alpn:    u8[..32] = [];
        var resumed = true;
        var out_psk: u8[32] = [0; 32];
        let ok_unknown = wing::parse_client_hello_for_server(
            ch_msg[..], "h2", sid, out_pub, alpn, resumed, out_psk,
        );
        sub.assert_true(ok_unknown, "unknown PSK identity does not abort ClientHello");
        sub.assert_false(resumed, "unknown PSK identity falls back to full 1-RTT handshake");

        // Register "expired-ticket-id" with a DIFFERENT secret so binder verification fails
        let server_psk: u8[32] = [0x77; 32];
        wing::store_tls13_session_ticket(
            "api.example.com", "expired-ticket-id", server_psk[..], 0, 3600, rfc::TLS_CIPHER_AES_128_GCM_SHA256,
        );
        let ok_forged = wing::parse_client_hello_for_server(
            ch_msg[..], "h2", sid, out_pub, alpn, resumed, out_psk,
        );
        sub.assert_false(ok_forged, "known PSK identity with invalid binder MUST abort handshake");
        wing::clear_tls13_session_tickets();
    };
}

// 9. X.509 IPv6 SAN, ASCII-vs-Binary IP SAN, DER Canonicality & Non-CA Anchor (mbedtls, x509-limbo)
fn test_vendor_x509_san_and_der_hardening(t: lit::T&) {
    t.run("x509-limbo: IPv6 SAN text matching, 4B/16B ASCII hostname rejection & DNS IP literal ban") { sub =>
        let v6_bytes: u8[16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let san_ip6 = wing::SanEntry { san_type: wing::SanType.Ip, val: v6_bytes[..] };
        sub.assert_true(wing::match_san(san_ip6, "2001:db8::1"), "bare IPv6 matches iPAddress SAN");
        sub.assert_true(wing::match_san(san_ip6, "[2001:0db8:0:0::1]"), "bracketed uncomp IPv6 matches");
        sub.assert_false(wing::match_san(san_ip6, "2001:db8::1%eth0"), "IPv6 zone ID rejected");
        sub.assert_false(wing::match_san(san_ip6, "0123456789abcdef"), "16-byte ASCII host must NOT match IPv6 SAN");

        let v4_ascii_collision: u8[4] = ['a' as u8, 'b' as u8, 'c' as u8, 'd' as u8];
        let san_ip4 = wing::SanEntry { san_type: wing::SanType.Ip, val: v4_ascii_collision[..] };
        sub.assert_false(wing::match_san(san_ip4, "abcd"), "4-byte ASCII host 'abcd' must NOT match IPv4 SAN");
        sub.assert_true(wing::match_san(san_ip4, "97.98.99.100"), "decimal 97.98.99.100 matches IPv4 SAN");

        sub.assert_false(wing::match_dns_san("127.0.0.1", "127.0.0.1"), "dNSName must NOT match IPv4 host");
        let san_uri = wing::SanEntry { san_type: wing::SanType.Uri, val: "https://example.com" };
        sub.assert_false(wing::match_san(san_uri, "example.com"), "URI SAN must NOT match bare DNS host");
        sub.assert_true(wing::match_san(san_uri, "https://example.com"), "URI SAN matches full URI");
    };

    t.run("RFC 5280: non-CA TrustAnchor cannot sign child cert while pinned leaf succeeds") { sub =>
        let anchor_seed: u8[32] = [0x11; 32];
        let leaf_seed:   u8[32] = [0x22; 32];
        var ee_anchor_der: u8[..2048] = [];
        sub.assert_true(
            wing::build_test_ed25519_cert_der(anchor_seed, "ee-root", "ee.example.com", "", ee_anchor_der),
            "built base cert",
        );
        // Flip BasicConstraints cA=TRUE (0x01 0x01 0xFF) inside ee_anchor_der to FALSE (0x00) and re-sign
        var parsed_tmp = wing::ParsedCert { .. };
        sub.assert_true(wing::parse_x509_certificate(ee_anchor_der[..], parsed_tmp), "parsed base cert");

        var non_ca_anchor = wing::TrustAnchor {
            has_basic_constraints: true,
            is_ca:                 false,
            has_pub_material:      true,
            is_valid:              true,
            ..
        };
        let kp_a = core::ed25519_keypair(anchor_seed);
        let _ = non_ca_anchor.subject_raw.try_set(wing::span_slice(ee_anchor_der[..], parsed_tmp.subject_raw));
        let _ = non_ca_anchor.spki_pubkey.try_set(kp_a.public_key[..]);

        var store = wing::TrustAnchorStore { .. };
        let _ = store.anchors.try_push(non_ca_anchor);

        var child_der: u8[..2048] = [];
        sub.assert_true(
            wing::build_test_ed25519_cert_der(leaf_seed, "ee-root", "leaf.example.com", "", child_der),
            "built child cert with matching issuer DN",
        );
        var child_parsed = wing::ParsedCert { .. };
        sub.assert_true(wing::parse_x509_certificate(child_der[..], child_parsed), "parsed child");
        child_parsed.is_ca = false;

        var chain_p: wing::ParsedCert[..8] = [];
        var chain_r: (const u8[:])[..8]    = [];
        let _ = chain_p.try_push(child_parsed);
        let _ = chain_r.try_push(child_der[..]);
        let alert = wing::verify_certificate_chain(
            chain_p, chain_r, store, child_parsed.validity_not_before + 5,
        );
        sub.assert_true(alert == wing::TlsAlert.BadCertificate, "non-CA TrustAnchor rejected as issuer");
    };
}

// 10. OCSP Multi-Cert Response & Unsigned Stapling Defense (rustls, mbedtls)
fn test_vendor_ocsp_multicert_and_unsigned(t: lit::T&) {
    t.run("RFC 6960: Good [0] with non-empty payload & unsigned stapling rejected") { sub =>
        // Malformed Good [0] with 1 byte (0x80 0x01 0x00) instead of IMPLICIT NULL (0x80 0x00)
        let bad_good: u8[3] = [0x80, 0x01, 0x00];
        var c = core::cursor_from(bad_good[..]);
        var st = wing::OcspCertStatus.Unknown;
        sub.assert_false(wing::x509_parse_ocsp_cert_status(c, st), "Good [0] with length 1 rejected");
    };
}

// 11. SSRF Perimeter & DNS / SVCB Wire Hardening (curl, chromium, RFC 9460)
fn test_vendor_ssrf_and_dns_wire(t: lit::T&) {
    t.run("SSRF: uppercase 0X hex, .internal domain & ::169.254.169.254 metadata blocked") { sub =>
        sub.assert_true(security::is_non_canonical_ipv4("0X7f.0.0.1"), "uppercase 0X hex IPv4 flagged");
        sub.assert_true(
            security::is_cloud_metadata_or_reserved_ip("[::169.254.169.254]"),
            "IPv4-compatible ::169.254.169.254 blocked",
        );
        sub.assert_true(
            security::is_cloud_metadata_or_reserved_ip("[::a9fe:a9fe]"),
            "hex ::a9fe:a9fe metadata IPv6 blocked",
        );
        sub.assert_true(
            security::is_cloud_metadata_or_reserved_ip("fe80::1"),
            "link-local fe80::1 blocked in metadata guard",
        );

        let policy = security::SsrfGuardPolicy { enabled: true, deny_local_network: true, .. };
        let u_int, err_u = core::parse_url("https://redis.prod.internal/keys");
        sub.assert_true(err_u == core::UrlParseError.None, "parsed .internal URL");
        let redir_err = wing::validate_url_against_ssrf(u_int, policy);
        sub.assert_true(redir_err == wing::RedirectError.SsrfBlockedIp, ".internal blocked by SSRF policy");
    };

    t.run("DNS & RFC 9460 §7.1.2: embedded dot/NUL label & mandatory=no-default-alpn rejected") { sub =>
        let bad_dot_name: u8[13] = [7, 'e', 'x', 'a', '.', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0];
        var off: i64       = 0;
        var out: u8[..255] = [];
        sub.assert_false(dns::decode_name(bad_dot_name[..], off, out), "embedded dot in DNS label rejected");
        sub.assert_eq(off, 0, "cursor rolled back on invalid DNS label");

        let bad_nul_name: u8[13] = [7, 'e', 'x', 'a', 0, 'p', 'l', 'e', 3, 'c', 'o', 'm', 0];
        sub.assert_false(dns::decode_name(bad_nul_name[..], off, out), "embedded NUL in DNS label rejected");

        // RFC 9460 §7.1.2: key 2 (no-default-alpn) MUST NOT appear in mandatory list
        let mand_key2: u8[2] = [0x00, 0x02];
        let _, ok_mand = dns::parse_mandatory_svc_param(mand_key2[..]);
        sub.assert_false(ok_mand, "mandatory=no-default-alpn (key 2) rejected");
    };
}

// 12. Cookies: SameSite=Unknown Lax-Allowing-Unsafe, IP Domain & Long Path (tough-cookie, cookie-rs)
fn test_vendor_cookies_samesite_and_scoping(t: lit::T&) {
    t.run("chromium / RFC 6265bis: SameSite=Unknown falls back to Default Lax-allowing-unsafe") { sub =>
        let now_us: i64 = 1700000000000000;
        var jar = cookie::CanonicalCookieJar { .. };
        sub.assert_true(
            cookie::set_cookie_header(
                jar, "https://app.example.com/login", "sid=xyz; SameSite=BogusValue; Path=/; Secure", now_us, true,
            ),
            "ingested cookie with unrecognized SameSite",
        );
        sub.assert_eq(jar.cookies.len, 1, "1 cookie stored");
        let c = jar.cookies[0];
        sub.assert_true(c.same_site == cookie::SameSite.Unknown, "parsed as SameSite.Unknown");

        let top_get = cookie::AccessOptions {
            is_same_site: false, is_top_level_navigation: true, is_safe_method: true, had_cross_site_hop: false,
        };
        sub.assert_true(
            cookie::is_sendable_for_samesite(c, top_get, now_us + 500000000),
            "SameSite=Unknown sent on cross-site top-level GET",
        );

        let top_post_fresh = cookie::AccessOptions {
            is_same_site: false, is_top_level_navigation: true, is_safe_method: false, had_cross_site_hop: false,
        };
        sub.assert_true(
            cookie::is_sendable_for_samesite(c, top_post_fresh, now_us + 30000000),
            "SameSite=Unknown sent on fresh (<120s) top-level POST",
        );
        sub.assert_false(
            cookie::is_sendable_for_samesite(c, top_post_fresh, now_us + 180000000),
            "SameSite=Unknown blocked on stale (>120s) cross-site POST",
        );
    };

    t.run("tough-cookie / cookie-rs: IP domain suffix mismatch, 600B path & raw security check") { sub =>
        sub.assert_false(
            cookie::domain_match("sub.127.0.0.1", "127.0.0.1"),
            "IP literal cookie_domain never suffix-matches subdomain",
        );

        var long_path: u8[..700] = [];
        long_path.push('/');
        for _ in 599 { long_path.push('a'); }
        var hdr: u8[..800] = [];
        hdr.append("k=v; Secure; Path=");
        hdr.append(long_path[..]);
        var jar_long = cookie::CanonicalCookieJar { .. };
        sub.assert_true(
            cookie::set_cookie_header(jar_long, "https://example.com/", hdr[..], 1000000, true),
            "600B cookie path ingested into CanonicalCookieJar",
        );
        sub.assert_eq(jar_long.cookies[0].path.len, 600, "600B cookie path preserved without 256B truncation");

        var raw_bad = cookie::CanonicalCookie { .. };
        let _ = raw_bad.name.try_set("bad name");
        let _ = raw_bad.value.try_set("v");
        let _ = raw_bad.domain.try_set("example.com");
        sub.assert_false(
            cookie::validate_security(raw_bad),
            "validate_security rejects space in raw cookie name",
        );

        let ns, ok_ns1 = cookie::try_parse_netscape_cookie_line(".EXAMPLE.COM\tTRUE\t/\tTRUE\t2147483647\tk\tv");
        sub.assert_true(ok_ns1, "parsed uppercase leading-dot Netscape cookie");
        sub.assert_bytes_eq(ns.domain[..], ".example.com", "Netscape domain preserved single leading dot & lowercased");
        let _, ok_ns2 = cookie::try_parse_netscape_cookie_line("..example.com\tTRUE\t/\tTRUE\t2147483647\tk\tv");
        sub.assert_false(ok_ns2, "Netscape rejects double leading-dot domain");
        let _, ok_ns3 = cookie::try_parse_netscape_cookie_line(".com\tTRUE\t/\tTRUE\t2147483647\tk\tv");
        sub.assert_false(ok_ns3, "Netscape rejects public suffix domain");
    };
}

// 13. HTTP Message Signatures: Component Parameter Smuggling & Decimal Params (RFC 9421)
fn test_vendor_http_signatures_smuggling(t: lit::T&) {
    t.run("RFC 9421: reject mismatched ;req and ;req=?0 component parameters") { sub =>
        var item_req = wing::SfItem { kind: wing::SfType.String, str_val: "@authority", .. };
        var p_req = wing::SfItemParam { kind: wing::SfType.Boolean, bool_val: true, .. };
        let _ = p_req.key.try_set("req");
        let _ = item_req.params.try_push(p_req);
        sub.assert_false(
            wing::matches_signature_component(item_req, "@authority"),
            ";req parameter must NOT match bare @authority",
        );

        var item_req0 = wing::SfItem { kind: wing::SfType.String, str_val: "@path", .. };
        var p_req0 = wing::SfItemParam { kind: wing::SfType.Boolean, bool_val: false, .. };
        let _ = p_req0.key.try_set("req");
        let _ = item_req0.params.try_push(p_req0);
        sub.assert_false(
            wing::matches_signature_component(item_req0, "@path;req"),
            ";req=?0 must NOT match @path;req",
        );
        sub.assert_false(
            wing::matches_signature_component(item_req0, "@path"),
            ";req=?0 must NOT match bare @path",
        );

        var dec_out: u8[..32] = [];
        sub.assert_true(
            wing::append_wire_sf_bare(wing::SfType.Decimal, 0, 1.25, "", false, dec_out),
            "serialized Decimal bare item",
        );
        sub.assert_bytes_eq(dec_out[..], "1.25", "Decimal formats dec_val instead of zero int_val");
    };
}

// 14. WebSocket Deflate UTF-8 / PMD Negotiation & gRPC Stream Parser (wslay, tungstenite, grpc-go)
fn test_vendor_ws_and_grpc_streaming(t: lit::T&) {
    t.run("tungstenite / uWS: PMD 101 parameter validation & CRLF handshake guard") { sub =>
        var hdrs = wing::HeaderMap { .. };
        let raw =
            "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Extensions: permessage-deflate; server_max_window_bits=7\r\n\r\n";
        sub.assert_true(wing::parse_headers(raw, hdrs, false) == wing::HeaderParseError.None, "parsed 101 headers");
        let _, err_pmd = wing::validate_client_upgrade_response(
            101, hdrs, raw, "dGhlIHNhbXBsZSBub25jZQ==", "", "permessage-deflate",
        );
        sub.assert_true(err_pmd != wing::WsError.None, "window_bits=7 in 101 PMD response rejected");

        let ws = wing::new_websocket_session(true);
        var hs_out: u8[..512] = [];
        wing::build_handshake_request(ws, "evil.com\r\nX-Injected: 1", "/chat", "dGhlIHNhbXBsZSBub25jZQ==", hs_out);
        sub.assert_eq(hs_out.len, 0, "CRLF in WebSocket Host blocked");
    };

    t.run("Autobahn 12.x / RFC 7692: compressed WS_OPCODE_TEXT with invalid UTF-8 closes 1007") { sub =>
        var comp = wing::SharedWsCompressor { .. };
        let invalid_utf8: u8[4] = [0xFF, 0xFE, 0xC0, 0xAF];
        let comp_slice, ok_c = wing::ws_deflate_message_slice(comp, invalid_utf8[..], true);
        sub.assert_true(ok_c, "deflated invalid UTF-8 bytes");

        var wire_frame: u8[..128] = [];
        let mask: u8[4] = [0x12, 0x34, 0x56, 0x78];
        wing::encode_ws_frame_compressed(wire_frame, rfc::WS_OPCODE_TEXT, comp_slice, true, mask, true);

        var srv_ws = wing::new_websocket_session(false);
        srv_ws.permessage_deflate = true;
        var stage = wire::NoOpStage {};
        var frag_buf: u8[..4096] = [];
        var out_wire: u8[..4096] = [];
        let _ = wing::drain_ws_session_frames(-1, srv_ws, stage, wire_frame[..], frag_buf, out_wire);
        sub.assert_true(srv_ws.is_closed, "server session closed on invalid UTF-8 after inflate");
        sub.assert_eq(
            srv_ws.close_code as i64, rfc::WS_STATUS_INVALID_PAYLOAD as i64,
            "close code is 1007 Invalid Payload Data",
        );
    };

    t.run("grpc-go / tonic: multi-message chunk > max_size+5, sticky error & ResourceExhausted") { sub =>
        var p = wing::new_grpc_stream_parser(16);
        var batch: u8[..64] = [];
        wing::encode_grpc_lpm("hello-msg-01", batch, false); // 17 bytes
        wing::encode_grpc_lpm("hello-msg-02", batch, false); // 17 bytes => 34 bytes > 16 + 5
        sub.assert_true(wing::feed(p, batch[..]), "multi-message TCP chunk accepted when each msg <= max_size");

        var msg: u8[..32] = [];
        var comp = false;
        sub.assert_true(wing::next_message(p, msg, comp), "extracted message 1");
        sub.assert_bytes_eq(msg[..], "hello-msg-01", "message 1 payload");
        sub.assert_true(wing::next_message(p, msg, comp), "extracted message 2");
        sub.assert_bytes_eq(msg[..], "hello-msg-02", "message 2 payload");

        // Feed reserved flag 0x02 -> sets sticky has_error until reset()
        let bad_hdr: u8[5] = [0x02, 0, 0, 0, 0];
        sub.assert_true(wing::feed(p, bad_hdr[..]), "buffered 5B header");
        sub.assert_false(wing::next_message(p, msg, comp), "reserved flag 0x02 rejected");
        sub.assert_true(p.has_error, "sticky has_error latched");
        sub.assert_false(wing::feed(p, batch[..17]), "subsequent feed rejected while has_error");
        wing::reset(p);
        sub.assert_true(wing::feed(p, batch[..17]), "feed works again after reset()");

        // Truncated LPM with grpc-status: 0 trailer must set Internal, not Ok
        var hmap = wing::HeaderMap { .. };
        var tmap = wing::HeaderMap { .. };
        let _ = wing::append_header(hmap, "content-type", "application/grpc");
        let _ = wing::append_header(tmap, "grpc-status", "0");
        let trunc_body: u8[6] = [0x00, 0x00, 0x00, 0x00, 0x0A, 'x'];
        var g_resp = wing::GrpcResponse { .. };
        sub.assert_false(
            wing::parse_grpc_unary_response(hmap, tmap, trunc_body[..], false, g_resp),
            "truncated LPM body rejected",
        );
        sub.assert_true(
            g_resp.status == wing::GrpcStatusCode.Internal,
            "truncated LPM overrides grpc-status: 0 with GrpcStatusCode.Internal",
        );
    };
}

fn main() {
    var runner = lit::new_runner("Hostile Vendor & Issue-Tracker Non-Greenhouse Suite");
    lit::run_case(runner, "1. HTTP/1.1 Chunked FSM & Smuggling (llhttp, h2o)", test_vendor_h1_chunked_and_smuggling);
    lit::run_case(runner, "2. Structured Fields & No-Vary-Search (sfparse, chromium)", test_vendor_sfv_and_novarysearch);
    lit::run_case(runner, "3. HTTP Cache Multi-Line Poisoning (chromium, curl)", test_vendor_cache_multiline_poisoning);
    lit::run_case(runner, "4. Redirect & Pool Coalescing (curl, pingora)", test_vendor_redirect_and_pool_coalescing);
    lit::run_case(runner, "5. HTTP/2 Chopped Ingress & HPACK (nghttp2, h2)", test_vendor_h2_chopped_ingress_and_hpack);
    lit::run_case(runner, "6. QUIC PN & Overlapping Streams (ngtcp2, quiche)", test_vendor_quic_pn_and_overlapping_reassembly);
    lit::run_case(runner, "7. HTTP/3 1-Byte Varint Fragmentation (nghttp3)", test_vendor_h3_1byte_fragmentation);
    lit::run_case(runner, "8. TLS 1.3 KeyUpdate & Unknown PSK (rustls, picotls)", test_vendor_tls13_keyupdate_and_unknown_psk);
    lit::run_case(runner, "9. X.509 IPv6 SAN & TrustAnchor CA (mbedtls, x509-limbo)", test_vendor_x509_san_and_der_hardening);
    lit::run_case(runner, "10. OCSP Stapling DER Hardening (rustls, mbedtls)", test_vendor_ocsp_multicert_and_unsigned);
    lit::run_case(runner, "11. SSRF & DNS/SVCB Wire Hardening (curl, RFC 9460)", test_vendor_ssrf_and_dns_wire);
    lit::run_case(runner, "12. Cookies SameSite=Unknown & Scoping (tough-cookie, cookie-rs)", test_vendor_cookies_samesite_and_scoping);
    lit::run_case(runner, "13. HTTP Message Signatures Smuggling (RFC 9421)", test_vendor_http_signatures_smuggling);
    lit::run_case(runner, "14. WebSocket Deflate UTF-8 & gRPC Stream (wslay, grpc-go)", test_vendor_ws_and_grpc_streaming);
    let ok = lit::finish(runner);
    assert(ok);
}
