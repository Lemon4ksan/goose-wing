// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s

import std;
import wing from "../..";

// ---- 1. Pipeline 64-Slot & Programmable User Stages -------------------------

struct ClientUserStageA {
    hits:      u32 = 0,
    last_slot: u8  = 0,
}

fn client::on_custom_slot(
    stage:     ClientUserStageA&,
    slot_id:   u8,
    _ctx:      client::StageCtx&,
    _headers:  http::HeaderMap&,
    _out_resp: http::Response&,
) -> wire::StageVerdict {
    if slot_id == wire::STAGE_ID_USER_0 {
        stage.hits += 1;
        stage.last_slot = slot_id;
    }
    return wire::StageVerdict.Continue;
}

struct ClientUserStageB {
    hits:      u32 = 0,
    last_slot: u8  = 0,
}

fn client::on_custom_slot(
    stage:     ClientUserStageB&,
    slot_id:   u8,
    _ctx:      client::StageCtx&,
    _headers:  http::HeaderMap&,
    _out_resp: http::Response&,
) -> wire::StageVerdict {
    if slot_id == wire::STAGE_ID_USER_1 {
        stage.hits += 10;
        stage.last_slot = slot_id;
    }
    return wire::StageVerdict.Continue;
}

struct ServerUserStageA {
    order_log: u32 = 0,
}

fn server::on_server_custom_slot(
    stage:      ServerUserStageA&,
    slot_id:    u8,
    param_slot: u8,
    _cfg:       server::ServerPipelineConfig&,
    _req:       const http::Request&,
    _sctx:      server::ServerStageCtx&,
    res:        http::Response&,
) -> wire::StageVerdict {
    if slot_id == wire::STAGE_ID_USER_0 {
        stage.order_log = (param_slot as u32) + 100;
        res.set_header("X-Stage-User-0", "ran");
    }
    return wire::StageVerdict.Continue;
}

struct ServerUserStageB {
    order_log: u32 = 0,
}

fn server::on_server_custom_slot(
    stage:      ServerUserStageB&,
    slot_id:    u8,
    param_slot: u8,
    _cfg:       server::ServerPipelineConfig&,
    _req:       const http::Request&,
    _sctx:      server::ServerStageCtx&,
    res:        http::Response&,
) -> wire::StageVerdict {
    if slot_id == wire::STAGE_ID_USER_1 {
        stage.order_log = (param_slot as u32) + 200;
        res.set_header("X-Stage-User-1", "ran");
    }
    return wire::StageVerdict.Continue;
}

fn test_pipeline_64_slot_and_user_stages() {
    assert(wire::MAX_PIPELINE_STAGES == 64);
    assert(wire::VALID_STAGE_MASK == 0xFFFFFFFFFFFFFFFF);
    assert(wire::is_user_stage_slot(wire::STAGE_ID_USER_0));
    assert(wire::is_user_stage_slot(wire::STAGE_ID_USER_1));
    assert(wire::is_user_stage_slot(wire::STAGE_ID_USER_2));
    assert(wire::is_user_stage_slot(wire::STAGE_ID_USER_3));
    assert(!wire::is_user_stage_slot(15));
    assert(wire::is_valid_stage_id(63));
    assert(!wire::is_valid_stage_id(64));

    let noop = wire::NoOpStage { .. };
    let custom_a = ClientUserStageA { .. };
    assert(client::is_noop_stage(noop));
    assert(!client::is_noop_stage(custom_a));

    // Client custom slot dispatch via StageChain at arbitrary ingress positions
    var client = client::new_client();
    client.wire_pipeline.has_custom_order = true;
    client.wire_pipeline.ingress_stages.clear();
    assert(wire::add_ingress_stage(client.wire_pipeline, wire::STAGE_ID_CLI_IN_URL_HSTS));
    assert(wire::add_ingress_stage(client.wire_pipeline, wire::STAGE_ID_USER_0));
    assert(wire::add_ingress_stage(client.wire_pipeline, wire::STAGE_ID_CLI_IN_SSRF_GUARD));
    assert(wire::add_ingress_stage(client.wire_pipeline, wire::STAGE_ID_USER_1));

    var req = http::new_request("GET", "https://example.com/api/v1/resource");
    var ctx = client_internal::RequestExecutionContext { .. };
    let _ = ctx.current_method.try_set("GET");
    var current_url, url_err = core::parse_url("https://example.com/api/v1/resource");
    assert(url_err == core::UrlParseError.None);
    var samesite = cookie::SameSiteCookieContext { .. };
    var out_resp = http::Response { .. };
    var out_err = http::Error { .. };
    var cli_chain = wire::chain_stages(ClientUserStageA { .. }, ClientUserStageB { .. });

    let cli_verdict = client_internal::run_pre_hop_stages(
        client,
        ctx,
        current_url,
        samesite,
        true,
        1000,
        out_resp,
        out_err,
        cli_chain,
    );
    assert(cli_verdict == wire::StageVerdict.Continue);
    assert(cli_chain.first.hits == 1 && cli_chain.first.last_slot == wire::STAGE_ID_USER_0);
    assert(cli_chain.next.hits == 10 && cli_chain.next.last_slot == wire::STAGE_ID_USER_1);

    // Server custom slot dispatch via StageChain at arbitrary custom_bindings positions
    var srv_cfg = server::new_server_pipeline_config(
        "example.com",
        security::GcraQuota { .. },
    );
    assert(wire::add_stage_binding(srv_cfg.wire_pipeline, wire::STAGE_ID_USER_0, 1));
    assert(wire::add_stage_binding(srv_cfg.wire_pipeline, wire::STAGE_ID_SRV_IN_EXPECT_100, 0));
    assert(wire::add_stage_binding(srv_cfg.wire_pipeline, wire::STAGE_ID_USER_1, 3));

    var srv_res = http::Response { status_code: 200, .. };
    var srv_ext = server_internal::RequestExtensions { .. };
    var srv_sctx = server::ServerStageCtx { .. };
    var srv_chain = wire::chain_stages(ServerUserStageA { .. }, ServerUserStageB { .. });

    let srv_outcome, is_term = server_internal::dispatch_custom_stage_bindings(
        srv_cfg,
        req,
        srv_res,
        srv_ext,
        1000000000,
        srv_sctx,
        srv_chain,
    );
    assert(!is_term && srv_outcome == server::PipelineOutcome.Handled);
    assert(srv_chain.first.order_log == 101);
    assert(srv_chain.next.order_log == 203);
    assert(http::header(srv_res, "X-Stage-User-0") == "ran");
    assert(http::header(srv_res, "X-Stage-User-1") == "ran");

    print(
        "GROUP1_PIPELINE_64_STAGE: OK max=",
        wire::MAX_PIPELINE_STAGES,
        " cli_hits=",
        cli_chain.first.hits + cli_chain.next.hits,
        " srv_log=",
        srv_chain.first.order_log + srv_chain.next.order_log,
    );
}

// ---- 2. Server Time Units, Custom HTTP Methods, H2 Stream Phase & Memo ------

fn test_server_time_methods_h2_and_memo() {
    // 2a. nanos_to_http_date_sec exact division vs >> 30 drift regression
    let sec_1 = server_internal::nanos_to_http_date_sec(1000000000);
    let sec_1700m = server_internal::nanos_to_http_date_sec(1700000000000000000);
    assert(sec_1 == 1);
    assert(sec_1700m == 1700000000);

    // H2 server session ingress with now_ms = now_ns / 1_000_000
    var h2_sess = server_internal::new_h2_server_session("example.com", 1000);
    var h2_cfg = server::new_server_pipeline_config(
        "example.com",
        security::GcraQuota { .. },
    );
    var h2_timer = server_internal::ConnectionTimer { .. };
    var h2_wire: u8[..128] = [];
    h2_wire.append("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    let empty_settings: u8[9] = [0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
    h2_wire.append(empty_settings[..]);
    var h2_out: u8[..4096] = [];
    let now_ns_1: u64 = 1000000000;
    let now_ms_1: u64 = now_ns_1 / 1000000;
    let h2_rc1, h2_ok1 = server_internal::handle_h2_server_ingress(
        h2_sess,
        h2_cfg,
        h2_timer,
        "127.0.0.1",
        h2_wire[..],
        now_ms_1,
        h2_out,
    );
    assert(h2_ok1 && h2_rc1 == h2_wire.len && !h2_sess.conn.goaway_sent);

    // Second frame 5 seconds later (5_000 ms) must not falsely trigger Rapid Reset or GOAWAY
    let ping_frame: u8[17] = [
        0x00, 0x00, 0x08, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ];
    let now_ns_2: u64 = 6000000000;
    let now_ms_2: u64 = now_ns_2 / 1000000;
    h2_out.clear();
    let h2_rc2, h2_ok2 = server_internal::handle_h2_server_ingress(
        h2_sess,
        h2_cfg,
        h2_timer,
        "127.0.0.1",
        ping_frame[..],
        now_ms_2,
        h2_out,
    );
    assert(h2_ok2 && h2_rc2 == ping_frame.len && !h2_sess.conn.goaway_sent);

    // 2b. Custom / WebDAV methods in RadixRouter (MethodTree[..9])
    var router = server::new_radix_router();
    assert(router.trees.len == 9);
    assert(server::add_route(router, "PROPFIND", "/dav/files", 401));
    assert(server::add_route(router, "MKCOL", "/dav/collection", 402));

    var params = http::ZeroAllocParams { .. };
    let m_propfind = server::match_route(router, "PROPFIND", "/dav/files", params);
    let m_mkcol_wrong = server::match_route(router, "MKCOL", "/dav/files", params);
    let m_get_wrong = server::match_route(router, "GET", "/dav/files", params);
    let m_mkcol_ok = server::match_route(router, "MKCOL", "/dav/collection", params);

    assert(server::is_match_found(m_propfind));
    assert(!server::is_match_found(m_mkcol_wrong));
    assert(!server::is_match_found(m_get_wrong));
    assert(server::is_match_found(m_mkcol_ok));

    // 2c. H2StreamPhase enum transitions
    var stream = server_internal::H2ServerStream { .. };
    assert(stream.phase == server_internal::H2StreamPhase.Idle);
    stream.phase = server_internal::H2StreamPhase.Open;
    assert(stream.phase == server_internal::H2StreamPhase.Open);
    stream.phase = server_internal::H2StreamPhase.HalfClosedRemote;
    assert(stream.phase == server_internal::H2StreamPhase.HalfClosedRemote);
    stream.phase = server_internal::H2StreamPhase.Closed;
    assert(stream.phase == server_internal::H2StreamPhase.Closed);

    // 2d. Encapsulated ServerPipelineConfig.memo independence
    var cfg_a = server::new_server_pipeline_config(
        "a.example.com",
        security::GcraQuota { .. },
    );
    var cfg_b = server::new_server_pipeline_config(
        "b.example.com",
        security::GcraQuota { .. },
    );
    let req_etag = http::new_request("GET", "https://a.example.com/data");
    var res_a = http::Response { status_code: 200, .. };
    res_a.body.append("alpha-memo-payload");
    var res_b = http::Response { status_code: 200, .. };
    res_b.body.append("beta-memo-payload");

    let _ = server_internal::stage_server_etag(req_etag, res_a, cfg_a.memo);
    let _ = server_internal::stage_server_etag(req_etag, res_b, cfg_b.memo);
    assert(cfg_a.memo.etag_src[..] == "alpha-memo-payload");
    assert(cfg_b.memo.etag_src[..] == "beta-memo-payload");
    assert(cfg_a.memo.etag_val[..] != cfg_b.memo.etag_val[..]);

    // 2e. 4096-slot SoAConnTable, 128-slot H2 session pool (no slot 0 overwrite!), and opt-in header memoization
    assert(server::SOA_TABLE_CAP == 4096);
    assert(server::REACTOR_MAX_H2_SESSIONS == 128);
    var srv_opt = server::new_http_server("127.0.0.1", 8080);
    assert(!srv_opt.enable_header_memoization);
    assert(!server::g_h1_parse_cache.enabled);
    server::set_header_memoization(srv_opt, true);
    assert(srv_opt.enable_header_memoization && server::g_h1_parse_cache.enabled);
    server::set_header_memoization(srv_opt, false);
    assert(!srv_opt.enable_header_memoization && !server::g_h1_parse_cache.enabled);

    for i in server::REACTOR_MAX_H2_SESSIONS {
        let idx = server::alloc_reactor_h2_session(srv_opt.pipeline, "example.com", 1000);
        assert(idx == i);
    }
    assert(server::alloc_reactor_h2_session(srv_opt.pipeline, "example.com", 1000) == -1);
    for i in server::REACTOR_MAX_H2_SESSIONS {
        server::free_reactor_h2_session(i as i16, srv_opt.pipeline);
    }

    print(
        "GROUP2_SERVER_FIXES: OK date_sec=",
        sec_1700m,
        " trees=",
        router.trees.len,
        " propfind_only=",
        server::is_match_found(m_propfind) && !server::is_match_found(m_mkcol_wrong),
    );
}

// ---- 3. HTTP SFV, RFC 9421 ;req, Cache Groups, DCB & ScalableHttpCache LRU --

fn test_http_sfv_dcb_and_cache_lru() {
    // 3a. RFC 8941 / 9651 SfItem.params & RFC 9421 Signature-Input inner-list ;req as second param
    let sig_input_hdr = "sig1=(\"@authority\";bs;req \"@path\";req);created=1618884473;keyid=\"test-key\"";
    var sf_entries: http::SfDictEntry[..16] = [];
    assert(http::parse_sf_dict(sig_input_hdr, sf_entries));
    assert(sf_entries.len == 1 && sf_entries[0].is_inner_list);
    assert(sf_entries[0].inner_items.len == 2);

    let item0 = sf_entries[0].inner_items[0];
    let item1 = sf_entries[0].inner_items[1];
    assert(item0.str_val == "@authority");
    assert(http::sf_item_has_flag_param(item0, "bs"));
    assert(http::sf_item_has_flag_param(item0, "req"));
    assert(item1.str_val == "@path");
    assert(http::sf_item_has_flag_param(item1, "req"));

    var expected_sig_params = http::SignatureParams {
        created: 1618884473,
        ..
    };
    let _ = expected_sig_params.label.try_set("sig1");
    let _ = expected_sig_params.key_id.try_set("test-key");
    expected_sig_params.components.push("@authority;req");
    expected_sig_params.components.push("@path;req");
    // RFC 9421 Section 2.1 (AUTH-08): unsupported `;bs` component parameter must be rejected,
    // while exact `;req` component parameters match.
    assert(!http::verify_signature_input_label(sig_input_hdr, "sig1", expected_sig_params));
    let sig_input_req_only = "sig1=(\"@authority\";req \"@path\";req);created=1618884473;keyid=\"test-key\"";
    assert(http::verify_signature_input_label(sig_input_req_only, "sig1", expected_sig_params));

    // 3b. cache_group_list_wire_len (RFC 9875)
    var groups: http::CacheGroupTag[..32] = [];
    assert(http::cache_group_list_wire_len(groups[..]) == 0);
    assert(http::parse_cache_group_list("\"scripts\", \"fonts\"", groups));
    assert(groups.len == 2);
    let wire_len = http::cache_group_list_wire_len(groups[..]);
    assert(wire_len == 18);

    // 3c. DCB (dcb) Dictionary-Compressed Brotli (RFC 9842)
    let dict_content = "shared-dictionary-prefix-for-rfc9842-compression-test-payload";
    let raw_payload = "shared-dictionary-prefix-for-rfc9842-compression-test-payload-and-live-delta-suffix";
    let dict_hash = core::sha256(dict_content);

    var encoded_dcb: u8[..4096] = [];
    assert(http::encode_dcb_response(encoded_dcb, dict_hash, raw_payload, dict_content));
    assert(encoded_dcb.len > 36);
    assert(
        encoded_dcb[0] == 0xFF &&
        encoded_dcb[1] == 0x44 &&
        encoded_dcb[2] == 0x43 &&
        encoded_dcb[3] == 0x42,
    );
    var parsed_hash: u8[32] = [0; 32];
    let dcb_payload, ok_dcb_hdr = http::decode_dcb_header(encoded_dcb[..], parsed_hash);
    assert(ok_dcb_hdr && dcb_payload.len > 0);
    assert(core::ct_eq_bytes(parsed_hash[..], dict_hash[..]));

    var decoded_dcb: u8[..4096] = [];
    assert(http::decompress_dcb_payload(dcb_payload, dict_content, decoded_dcb));
    assert(decoded_dcb[..] == raw_payload);

    // Verify apply_negotiated_dictionary_response with dcb + decode_body_with_dictionary
    var dict_cache = http::DictionaryCache { .. };
    assert(http::dictionary_cache_insert(
        dict_cache,
        "https://cdn.example.com",
        "/assets/*",
        "dict-v1",
        dict_content,
        3600,
        1000,
    ));
    var avail_hdr: u8[..64] = [];
    http::format_available_dictionary_header(avail_hdr, dict_hash);
    var dcb_req = http::new_request("GET", "https://cdn.example.com/assets/app.js");
    http::set_header(dcb_req.headers, "Available-Dictionary", avail_hdr[..], true);
    http::set_header(dcb_req.headers, "Dictionary-ID", "\"dict-v1\"", true);
    http::set_header(dcb_req.headers, "Accept-Encoding", "dcb, br", true);
    var dcb_res = http::Response { status_code: 200, .. };
    assert(http::apply_negotiated_dictionary_response(
        dcb_req,
        dcb_res,
        dict_hash,
        raw_payload,
        "dict-v1",
        dict_content,
    ));
    assert(http::header(dcb_res, "Content-Encoding") == "dcb");
    assert(http::decode_body_with_dictionary(dcb_res, dict_cache));
    assert(dcb_res.body[..] == raw_payload);

    // 3d. ScalableHttpCache unified LRU (lru_head = MRU, lru_tail = LRU victim)
    var cache = http::ScalableCache { .. };
    http::init_scalable_cache(cache, 8, 4096);
    let now_ts: i64 = 1700000000;

    let c_req0 = http::new_request("GET", "https://cdn.example.com/lru/0");
    let c_req1 = http::new_request("GET", "https://cdn.example.com/lru/1");
    let c_req2 = http::new_request("GET", "https://cdn.example.com/lru/2");
    var c_resp = http::Response { status_code: 200, .. };
    c_resp.set_header("Cache-Control", "public, max-age=3600");
    c_resp.body.append("cached-val");

    assert(cache.store_response(c_req0, c_resp, now_ts));
    assert(cache.store_response(c_req1, c_resp, now_ts));
    assert(cache.store_response(c_req2, c_resp, now_ts));
    assert(cache.lru_head == 2 && cache.lru_tail == 0);

    let hit0 = cache.lookup(c_req0, now_ts);
    assert(hit0.kind == http::LookupResultKind.Hit);
    assert(cache.lru_head == 0 && cache.lru_tail == 1);

    print(
        "GROUP3_HTTP_FIXES: OK wire_len=",
        wire_len,
        " dcb_len=",
        decoded_dcb.len,
        " lru_head=",
        cache.lru_head,
        " lru_tail=",
        cache.lru_tail,
    );
}

// ---- 4. TLS CSPRNG, FIPS 203 SHA-3/ML-KEM, CRL Serials, Span & Ciphers ------

fn test_tls_crypto_x509_and_cipher_selection() {
    // 4a. CSPRNG state ratchet regression (random_bytes_32_checked)
    var r1: u8[32] = [0; 32];
    var r2: u8[32] = [0; 32];
    assert(tls_internal::random_bytes_32_checked(r1));
    let pool_after_r1 = tls::g_tls_entropy_pool;
    assert(tls_internal::random_bytes_32_checked(r2));
    assert(!core::ct_eq_bytes(r1[..], r2[..]));
    assert(!core::ct_eq_bytes(pool_after_r1[..], r1[..]));
    assert(!core::ct_eq_bytes(tls::g_tls_entropy_pool[..], r2[..]));

    // 4b. FIPS 202 / 203 SHA3-256, SHA3-512, SHAKE128, SHAKE256 & ML-KEM-768
    let sha3_empty = tls_internal::sha3_256("");
    var sha3_hex: u8[..64] = [];
    for b in sha3_empty {
        b.format_u8_hex(sha3_hex, false);
    }
    assert(sha3_hex[..] == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");

    let sha3_512_empty = tls_internal::sha3_512("");
    assert(sha3_512_empty[0] == 0xA6 && sha3_512_empty[1] == 0x9F);

    var shake128_out: u8[32] = [0; 32];
    var shake256_out: u8[32] = [0; 32];
    tls_internal::shake128_squeeze("fips203-test", shake128_out[..]);
    tls_internal::shake256_squeeze("fips203-test", shake256_out[..]);
    assert(!core::ct_eq_bytes(shake128_out[..], shake256_out[..]));

    var d_seed: u8[32] = [0x42; 32];
    var z_seed: u8[32] = [0x99; 32];
    var m_rand: u8[32] = [0x77; 32];
    let ek, dk = tls_internal::mlkem768_keygen(d_seed, z_seed);
    let ct, ss_enc, ok_enc = tls_internal::mlkem768_encapsulate(ek, m_rand);
    assert(ok_enc);

    var ss_dec: u8[32] = [0; 32];
    assert(tls_internal::mlkem768_decapsulate(ct[..], dk[..], ss_dec[..]));
    assert(core::ct_eq_bytes(ss_enc[..], ss_dec[..]));

    var ct_tampered = ct;
    ct_tampered[0] ^= 0x01;
    var ss_reject: u8[32] = [0; 32];
    assert(tls_internal::mlkem768_decapsulate(ct_tampered[..], dk[..], ss_reject[..]));
    assert(!core::ct_eq_bytes(ss_enc[..], ss_reject[..]));

    // 4c. CRL 9..20 byte serial numbers (parse_asn1_serial_u64)
    let serial_16b: u8[16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    ];
    let s16_val, ok_s16 = tls::parse_asn1_serial_u64(serial_16b[..]);
    assert(ok_s16 && (s16_val & 0x8000000000000000) != 0);

    let serial_18b: u8[18] = [
        0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x12, 0x34,
    ];
    let s18_val, ok_s18 = tls::parse_asn1_serial_u64(serial_18b[..]);
    assert(ok_s18 && (s18_val & 0x8000000000000000) != 0 && s18_val != s16_val);

    let serial_21b: u8[21] = [0x01; 21];
    let _, ok_s21 = tls::parse_asn1_serial_u64(serial_21b[..]);
    assert(!ok_s21);

    // 4d. Self-signed certificate make_span(buf, needle, start_hint)
    let dup_buf = "HDR_CN=root.example.com_MID_CN=root.example.com_END";
    let needle1 = dup_buf[4..23];
    let needle2 = dup_buf[28..47];
    let span1 = tls::make_span(dup_buf, needle1, 0);
    let span2 = tls::make_span(dup_buf, needle2, span1.offset + span1.length);
    assert(span1.offset == 4 && span2.offset == 28 && span2.offset > span1.offset);

    // 4e. Server dynamic cipher suite selection (select_cipher_suite)
    let offer_chacha: u8[4] = [0x13, 0x03, 0x13, 0x01];
    let cs_chacha, ok_cc = tls_internal::select_cipher_suite(offer_chacha[..]);
    assert(ok_cc && cs_chacha == rfc::TLS_CIPHER_CHACHA20_POLY1305_SHA256);

    let offer_aes256: u8[4] = [0x13, 0x02, 0x13, 0x01];
    let cs_aes256, ok_a2 = tls_internal::select_cipher_suite(offer_aes256[..]);
    assert(ok_a2 && cs_aes256 == rfc::TLS_CIPHER_AES_256_GCM_SHA384);

    // 4f. CertificateVerify dynamic signing dispatch (Ed25519 & ECDSA P-256)
    let cv_seed: u8[32] = [0x42; 32];
    var ed_cert: u8[..2048] = [];
    assert(tls::build_test_ed25519_cert_der(cv_seed, "test.local", "test.local", "", ed_cert));
    var ed_sig_buf: u8[..128] = [];
    let ed_scheme, ok_ed_sig = tls_internal::sign_certificate_verify(
        ed_cert[..], cv_seed, "tls13-cv-payload", ed_sig_buf,
    );
    let ed_kp = core::ed25519_keypair(cv_seed);
    assert(ok_ed_sig && ed_scheme == rfc::SIG_SCHEME_ED25519);
    assert(tls_internal::verify_certificate_verify_sig(
        ed_scheme, ed_sig_buf[..], ed_kp.public_key[..], "tls13-cv-payload",
    ));

    print(
        "GROUP4_TLS_FIXES: OK mlkem_match=",
        core::ct_eq_bytes(ss_enc[..], ss_dec[..]),
        " span2_off=",
        span2.offset,
        " chacha=",
        cs_chacha,
        " aes256=",
        cs_aes256,
    );
}

fn main() {
    test_pipeline_64_slot_and_user_stages();
    // CHECK: GROUP1_PIPELINE_64_STAGE: OK max=64 cli_hits=11 srv_log=304
    test_server_time_methods_h2_and_memo();
    // CHECK: GROUP2_SERVER_FIXES: OK date_sec=1700000000 trees=9 propfind_only=true
    test_http_sfv_dcb_and_cache_lru();
    // CHECK: GROUP3_HTTP_FIXES: OK wire_len=18 dcb_len=83 lru_head=0 lru_tail=1
    test_tls_crypto_x509_and_cipher_selection();
    // CHECK: GROUP4_TLS_FIXES: OK mlkem_match=true span2_off=28 chacha=4867 aes256=4866
}
