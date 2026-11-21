// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Native Goose port of Google OSS-Fuzz / LLVM libFuzzer mutation engine,
// FuzzedDataProvider (<fuzzer/FuzzedDataProvider.h>), and 12 protocol fuzz targets
// ported from nghttp2, nghttp3, ngtcp2, quinn-proto, rustls, picotls, boringssl,
// llhttp, tungstenite, cookie-rs, and sfparse.
import std;
import core from "../..";
import wing from "../..";

// ---- FuzzedDataProvider (ported from LLVM <fuzzer/FuzzedDataProvider.h>) ----

struct FuzzedDataProvider {
    data: const u8[:] = "",
    pos:  i64         = 0,
}

fn new_fdp(data: const u8[:]) -> FuzzedDataProvider {
    return FuzzedDataProvider { data: data, pos: 0 };
}

inline fn fdp_remaining(fdp: const FuzzedDataProvider&) -> i64 {
    if fdp.pos >= fdp.data.len { return 0; }
    return core::sub_sat_i64(fdp.data.len, fdp.pos);
}

fn fdp_consume_u8(fdp: FuzzedDataProvider&) -> u8 {
    if fdp.pos >= fdp.data.len { return 0; }
    let v = fdp.data[fdp.pos];
    fdp.pos = core::add_sat_i64(fdp.pos, 1);
    return v;
}

fn fdp_consume_bool(fdp: FuzzedDataProvider&) -> bool {
    return (fdp_consume_u8(fdp) & 1) != 0;
}

fn fdp_consume_u16(fdp: FuzzedDataProvider&) -> u16 {
    let b0 = fdp_consume_u8(fdp) as u16;
    let b1 = fdp_consume_u8(fdp) as u16;
    return (b0 << 8) | b1;
}

fn fdp_consume_u32(fdp: FuzzedDataProvider&) -> u32 {
    let w0 = fdp_consume_u16(fdp) as u32;
    let w1 = fdp_consume_u16(fdp) as u32;
    return (w0 << 16) | w1;
}

fn fdp_consume_u64_in_range(fdp: FuzzedDataProvider&, low: u64, high: u64) -> u64 {
    if low >= high { return low; }
    let span = core::sub_sat_u64(high, low);
    let raw: u64 = fdp_consume_u32(fdp);
    let _ = fdp_consume_u32(fdp);
    if span == 0xFFFFFFFFFFFFFFFF { return raw; }
    let modulus = core::add_sat_u64(span, 1);
    let _, scaled = core::mul_wide_u64(raw, modulus);
    return core::add_sat_u64(low, scaled);
}

fn fdp_consume_bytes(fdp: FuzzedDataProvider&, max_len: i64) -> const u8[:] {
    let rem = fdp_remaining(fdp);
    if rem <= 0 || max_len <= 0 { return ""; }
    let take = min(rem, max_len);
    let start = fdp.pos;
    let end = core::add_sat_i64(start, take);
    fdp.pos = end;
    return fdp.data[start..end];
}

fn fdp_consume_remaining(fdp: FuzzedDataProvider&) -> const u8[:] {
    let rem = fdp_remaining(fdp);
    if rem <= 0 { return ""; }
    let start = fdp.pos;
    fdp.pos = fdp.data.len;
    return fdp.data[start..];
}

// ---- libFuzzer ---------

struct FuzzRng {
    state: u64 = 0,
}

fn new_fuzz_rng(seed: u64) -> FuzzRng {
    let clk = core::monotonic_now().nanos;
    let mixed = seed ^ core::mul_sat_u64(clk, 0x9E3779B97F4A7C15) ^ 0xBF58476D1CE4E5B9;
    return FuzzRng { state: if mixed == 0 { 0x94D049BB133111EB } else { mixed } };
}

fn fuzz_rng_next(rng: FuzzRng&) -> u64 {
    var x = rng.state;
    x = x ^ (x >> 12);
    x = x ^ (x << 25);
    x = x ^ (x >> 27);
    rng.state = x;
    return core::mul_sat_u64(x, 0x2545F4914F6CDD1D);
}

fn fuzz_rng_bound(rng: FuzzRng&, bound: u64) -> u64 {
    if bound <= 1 { return 0; }
    let _, scaled = core::mul_wide_u64(fuzz_rng_next(rng), bound);
    return scaled;
}

const BIT_MASKS_U8: u8[8] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80];

const INTERESTING_U8: u8[9] = [0x00, 0x01, 0x20, 0x3F, 0x40, 0x7F, 0x80, 0xFE, 0xFF];

const INTERESTING_U16: u16[9] = [0x0000, 0x003F, 0x0040, 0x007F, 0x0080, 0x00FF, 0x3FFF, 0x4000, 0xFFFF];

const OSS_FUZZ_DICT: const u8[:][24] = [
    "\r\n\r\n",
    "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    "POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
    ":method",
    ":path",
    ":authority",
    ":scheme",
    ":status",
    "content-length: 0\r\n",
    "u=3, i=?0",
    "__Host-sid=abc; Secure; Path=/; HttpOnly; SameSite=Strict",
    "Digest username=\"Mufasa\", realm=\"http-auth@example.org\", uri=\"/dir/index.html\", algorithm=SHA-256",
    "DPoP eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0In0.eyJodG0iOiJHRVQifQ.sig",
    "max-age=3600, stale-while-revalidate=60, public",
    "grpc-status: 0\r\ngrpc-message: OK\r\n",
    "https://user:pass@[2001:db8::1]:8443/a/b/../c?k=v#frag",
    "\x82\x87\x84\x41\x8a\x08\x9d\x5c\x0b\x81\x70\xdc\x78\x0f\x03\x53\x03\x2a\x2f\x2a",
    "\x00\x00\x04\x07\x04\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x10\x00",
    "\x16\x03\x03\x00\x35\x01\x00\x00\x31\x03\x03",
    "\xc3\x00\x00\x00\x01\x08\x83\x94\xc8\xf0\x3e\x51\x57\x08\x00\x00\x44\x9e",
    "\x6b\x33\x43\xcf",
    "\x81\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58",
    "\x00\x00\x00\x00\x05hello",
];

fn mutate_single_byte_in_place<B>(op: u64, rng: FuzzRng&, buf: B&) {
    guard buf.len > 0 else { return; }
    let idx = fuzz_rng_bound(rng, buf.len as u64) as i64;
    if op == 0 {
        let bit = BIT_MASKS_U8[(fuzz_rng_next(rng) & 7) as i64];
        buf[idx] = buf[idx] ^ bit;
        return;
    }
    if op == 1 {
        buf[idx] = (fuzz_rng_next(rng) & 0xFF) as u8;
        return;
    }
    if op == 2 {
        let delta = ((fuzz_rng_next(rng) & 0x1F) as u8) | 1;
        buf[idx] = buf[idx] ^ delta;
        return;
    }
    let next_idx = core::add_sat_i64(idx, 1);
    if buf.len >= 2 && next_idx < buf.len && (fuzz_rng_next(rng) & 1) != 0 {
        let v16 = INTERESTING_U16[fuzz_rng_bound(rng, 9) as i64];
        buf[idx] = (v16 >> 8) as u8;
        buf[next_idx] = (v16 & 0xFF) as u8;
    } else {
        buf[idx] = INTERESTING_U8[fuzz_rng_bound(rng, 9) as i64];
    }
}

fn mutate_length_or_dict<B>(op: u64, rng: FuzzRng&, buf: B&) {
    if op == 4 && buf.len > 2 {
        let new_len = fuzz_rng_bound(rng, buf.len as u64) as i64;
        var tmp: u8[..4096] = [];
        let copy_len = min(new_len, tmp.cap);
        tmp.append(buf[..copy_len]);
        let _ = buf.try_set(tmp[..]);
        return;
    }
    if op == 5 {
        let count = ((fuzz_rng_next(rng) & 7) as i64) | 1;
        let val = INTERESTING_U8[fuzz_rng_bound(rng, 9) as i64];
        for _ in count {
            let _ = buf.try_push(val);
        }
        return;
    }
    let tok = OSS_FUZZ_DICT[fuzz_rng_bound(rng, 24) as i64];
    let _ = buf.try_append(tok);
}

// Applies 1..4 stacked libFuzzer mutations (BitFlip, ByteFlip, Arith8/16,
// Interesting8/16, EraseBytes, InsertRepeat, DictToken) to `buf`.
fn libfuzzer_mutate_inplace<B>(rng: FuzzRng&, buf: B&) {
    let steps = ((fuzz_rng_next(rng) & 3) as i64) | 1;
    for _ in steps {
        let op = fuzz_rng_bound(rng, 7);
        if op <= 3 {
            mutate_single_byte_in_place(op, rng, buf);
        } else {
            mutate_length_or_dict(op, rng, buf);
        }
    }
}

// Mixes a parser state transition or progress milestone into a 64-bit feature signature.
inline fn fuzz_mix_state(acc: u64, tag: u64) -> u64 {
    return core::mul_sat_u64(acc ^ tag, 0x100000001B3);
}

fn fuzz_http1_auth_and_headers(data: const u8[:], sig: u64) -> u64 {
    var s = sig;
    var fwd: wing::ForwardedElement[..8] = [];
    let n_fwd = wing::parse_forwarded_header(data, fwd);
    if n_fwd > 0 { s = fuzz_mix_state(s, 0x1010 ^ (n_fwd as u64)); }

    let _ = wing::parse_no_vary_search(data);

    if wing::verify_digest_field(data, "hello") { s = fuzz_mix_state(s, 0x1030); }
    let short_slice = data[..min(data.len, 64)];
    var dig_hdr: u8[..128] = [];
    if wing::format_digest_field_value("sha-256", short_slice, dig_hdr) {
        assert(wing::verify_digest_field(dig_hdr[..], short_slice));
    }

    let _, ok_sig = wing::extract_signature_value(data, "sig1");
    if ok_sig { s = fuzz_mix_state(s, 0x1040); }

    var dpop_claims = auth::DPoPClaims { .. };
    if auth::parse_dpop_claims(data, dpop_claims) {
        assert(dpop_claims.jti.len > 0 && dpop_claims.htm.len > 0 && dpop_claims.htu.len > 0);
        s = fuzz_mix_state(s, 0x1050);
    }
    let _ = auth::verify_dpop_proof(data, "", "GET", "https://example.com/ resource");

    var jwks = auth::Jwks { .. };
    if auth::parse_jwks_json(data, jwks) {
        s = fuzz_mix_state(s, 0x1060 ^ (jwks.keys.len as u64));
        auth::zeroize_jwks(jwks);
    }

    var jwt_hdr = auth::JwtHeader { .. };
    if auth::parse_jwt_header_json(data, jwt_hdr) {
        assert(jwt_hdr.alg != auth::JwtAlg.None);
        s = fuzz_mix_state(s, 0x100A);
    }
    var jwt_claims = auth::JwtClaims { .. };
    if auth::parse_jwt_claims_json(data, jwt_claims) { s = fuzz_mix_state(s, 0x100B); }
    return s;
}

fn fuzz_chunk_fsm_stream(data: const u8[:], step_mask: u8, out_body: u8[>..]&) -> http_internal::ChunkFsmStatus {
    var fdp = new_fdp(data);
    var fsm = http_internal::new_chunk_fsm_decoder();
    var last_st = http_internal::ChunkFsmStatus.NeedMore;
    while fdp_remaining(fdp) > 0 {
        let step_len = ((fdp_consume_u8(fdp) & step_mask) as i64) | 1;
        var rem = fdp_consume_bytes(fdp, step_len);
        while rem.len > 0 {
            let st, consumed, yielded = http_internal::chunk_fsm_feed(fsm, rem);
            last_st = st;
            if yielded.len > 0 {
                out_body.append(yielded);
            }
            if st == http_internal::ChunkFsmStatus.Complete || st == http_internal::ChunkFsmStatus.Error {
                return st;
            }
            if consumed <= 0 { break; }
            rem = rem[consumed..];
        }
    }
    return last_st;
}

fn verify_chunk_fsm_split_parity(data: const u8[:], oneshot_body: const u8[:], consumed_len: i64) {
    guard consumed_len > 0 && consumed_len <= data.len && oneshot_body.len <= 8192 else { return; }
    var fsm = http_internal::new_chunk_fsm_decoder();
    var streamed: u8[>..] = [];
    var pos:      i64     = 0;
    let src = data[..consumed_len];
    while pos < src.len {
        let step = ((pos & 7) + 1);
        let end = min(src.len, core::add_sat_i64(pos, step));
        var sub = src[pos..end];
        pos = end;
        while sub.len > 0 {
            let st, used, chunk = http_internal::chunk_fsm_feed(fsm, sub);
            if chunk.len > 0 { streamed.append(chunk); }
            if st == http_internal::ChunkFsmStatus.Complete {
                assert(streamed[..] == oneshot_body);
                return;
            }
            assert(st != http_internal::ChunkFsmStatus.Error);
            if used <= 0 { break; }
            sub = sub[used..];
        }
    }
}
// ---- Target 1: HTTP/1.1 Parser, Chunked FSM, Multipart, Cache & Auth -------
// Ported from vendor/llhttp/test/fuzzers/fuzz_parser.c & oss-fuzz/projects/h2o/h2o-fuzzer-http1
fn fuzz_target_http1(data: const u8[:]) -> u64 {
    var sig: u64 = 0xCBF29CE484222325;
    var map = wing::HeaderMap { .. };
    if wing::parse_headers(data, map, true) == wing::HeaderParseError.None {
        sig = fuzz_mix_state(sig, 0x1001 ^ (map.entries.len as u64));
    }

    var map_strict = wing::HeaderMap { .. };
    if wing::parse_headers(data, map_strict, false) == wing::HeaderParseError.None {
        sig = fuzz_mix_state(sig, 0x1002 ^ (map_strict.entries.len as u64));
    }

    var req_map = wing::HeaderMap { .. };
    if wing::parse_request_headers(data, req_map, false) == wing::HeaderParseError.None {
        sig = fuzz_mix_state(sig, 0x1003);
    }

    var res_map = wing::HeaderMap { .. };
    if wing::parse_response_headers(data, res_map, false) == wing::HeaderParseError.None {
        sig = fuzz_mix_state(sig, 0x1004);
    }

    var decoded_body: u8[>..] = [];
    var trailers = wing::HeaderMap { .. };
    let err_chunk, chunk_consumed = wing::decode_chunked_body_with_trailers(data, decoded_body, trailers);
    if err_chunk == wing::ChunkedDecodeError.None {
        sig = fuzz_mix_state(sig, 0x1005 ^ (trailers.entries.len as u64));
        verify_chunk_fsm_split_parity(data, decoded_body[..], chunk_consumed);
    }

    var fsm_body: u8[>..] = [];
    if fuzz_chunk_fsm_stream(data, 0x1F, fsm_body) == http_internal::ChunkFsmStatus.Complete {
        sig = fuzz_mix_state(sig, 0x1006 ^ (fsm_body.len as u64));
    }

    let mp_opts = wing::MultipartOptions { .. };
    let mp_msg, err_mp = wing::parse_multipart(data, "boundary", mp_opts);
    if err_mp == wing::MultipartError.None { sig = fuzz_mix_state(sig, 0x1007 ^ (mp_msg.parts.len as u64)); }

    let rng_res, _ = wing::parse_range_header(data, 10000, true, 16);
    if rng_res.ranges.len > 0 { sig = fuzz_mix_state(sig, 0x1008); }

    var cc = wing::CacheControl { .. };
    wing::parse_cache_control_str(data, cc, true);
    let _, ok_dig = auth::parse_digest_challenge(data);
    if ok_dig { sig = fuzz_mix_state(sig, 0x1009); }

    return fuzz_http1_auth_and_headers(data, sig);
}

// ---- Target 2: HTTP/2 Frame Demuxer & HPACK Decoder ------------------------
// Ported from vendor/nghttp2/fuzz/fuzz_frames.cc & vendor/h2/fuzz/fuzz_targets/fuzz_hpack.rs
fn fuzz_target_http2_hpack_and_frames(data: const u8[:]) -> u64 {
    var sig: u64 = 0x2000;
    var fdp = new_fdp(data);
    let cap_choice = (fdp_consume_u16(fdp) as u64) & 0x1FFF;
    let max_cap = max(cap_choice, 64);
    let rest = fdp_consume_remaining(fdp);

    var dt = http2::new_dynamic_table(max_cap);
    var hdrs = wing::HeaderMap { .. };
    var pseudo = http2::PseudoHeaders { .. };
    let hpack_err = http2::decode_hpack_to_map(dt, rest, pseudo, hdrs, 65536, true);
    assert(dt.used_bytes <= dt.current_max_size && dt.current_max_size <= dt.max_allowed_size && dt.count <= 128);
    if hpack_err == rfc::H2_ERR_NO_ERROR {
        sig = fuzz_mix_state(sig, 0x2001 ^ (hdrs.entries.len as u64));
    }

    var cur:   i64 = 0;
    var steps: i64 = 0;
    while core::add_sat_i64(cur, 9) <= data.len && steps < 32 {
        let hdr_end = core::add_sat_i64(cur, 9);
        let fh, err_fh = http2::parse_frame_header(data[cur..hdr_end]);
        cur = hdr_end;
        steps = core::add_sat_i64(steps, 1);
        if err_fh != 0 { break; }
        sig = fuzz_mix_state(sig, 0x2010 ^ (fh.frame_type as u64));
        let plen = fh.length as i64;
        let pay_end = core::add_sat_i64(cur, plen);
        if plen < 0 || pay_end > data.len { break; }
        let payload = data[cur..pay_end];
        cur = pay_end;

        let _, _ = http2::extract_padded_frame_payload(fh, payload);
        let _, _ = http2::extract_headers_frame_payload(fh, payload);
        let _, _, err_pri = http2::parse_priority_update_payload(payload, false);
        if err_pri == 0 { sig = fuzz_mix_state(sig, 0x2020); }
        let _ = http2::parse_altsvc_frame(payload, fh.stream_id);
    }
    return sig;
}

// ---- Target 3: HTTP/2 Stateful Server & Client Session ---------------------
// Ported from vendor/nghttp2/fuzz/fuzz_target.cc & fuzz_target_fdp.cc
fn fuzz_target_http2_session(data: const u8[:]) -> u64 {
    var sig: u64 = 0x3000;
    var srv_sess = server_internal::new_h2_server_session("localhost");
    var pipeline = wing::ServerPipelineConfig { .. };
    var timer = server_internal::ConnectionTimer { .. };
    var out_wire: u8[..16384] = [];

    var with_preface: u8[..4096] = [];
    with_preface.append(rfc::H2_CLIENT_PREFACE[..]);
    let set_hdr = http2::FrameHeader { length: 0, frame_type: rfc::H2_FRAME_SETTINGS, flags: 0, stream_id: 0 };
    http2::encode_frame_header_to(set_hdr, with_preface);
    let rem_cap = core::sub_sat_i64(with_preface.cap, with_preface.len);
    let take = min(data.len, rem_cap);
    with_preface.append(data[..take]);

    let consumed1, ok1 = server_internal::handle_h2_server_ingress(srv_sess, pipeline, timer, "127.0.0.1", with_preface[..], 1000, out_wire);
    if ok1 { sig = fuzz_mix_state(sig, 0x3001 ^ (consumed1 as u64) ^ (out_wire.len as u64)); }

    var raw_sess = server_internal::new_h2_server_session("localhost");
    out_wire.clear();
    let consumed2, ok2 = server_internal::handle_h2_server_ingress(raw_sess, pipeline, timer, "127.0.0.1", data, 1000, out_wire);
    if ok2 { sig = fuzz_mix_state(sig, 0x3002 ^ (consumed2 as u64)); }
    return sig;
}

// ---- Target 4: HTTP/3 QPACK Decoder & Encoder Stream -----------------------
// Ported from vendor/nghttp3/fuzz/fuzz_qpackdecoder.cc
fn fuzz_target_http3_qpack(data: const u8[:]) -> u64 {
    var sig: u64 = 0x4000;
    var fdp = new_fdp(data);
    let cap = (fdp_consume_u16(fdp) as u64) & 0x0FFF;
    let enc_len = (fdp_consume_u8(fdp) & 0x7F) as i64;
    let enc_bytes = fdp_consume_bytes(fdp, enc_len);
    let block_bytes = fdp_consume_remaining(fdp);

    var tbl = http3::new_qpack_table(cap, 16);
    var off:   u64 = 0;
    var steps: i64 = 0;
    while off < (enc_bytes.len as u64) && steps < 32 {
        let next_off, err = http3::qpack_process_encoder_instruction(tbl, enc_bytes, off);
        assert(tbl.used_bytes <= tbl.capacity_bytes && tbl.capacity_bytes <= tbl.max_capacity_bytes);
        assert(tbl.draining_index <= tbl.insert_count);
        steps = core::add_sat_i64(steps, 1);
        if err != http3::QpackError.None || next_off <= off {
            break;
        }
        off = next_off;
        sig = fuzz_mix_state(sig, 0x4010 ^ off);
    }

    var map = wing::HeaderMap { .. };
    var pseudo = http3::PseudoHeaders { .. };
    let qerr = http3::decode_or_block_qpack_to_map(tbl, 0, block_bytes, pseudo, map, 65536);
    assert(tbl.used_bytes <= tbl.capacity_bytes && tbl.draining_index <= tbl.insert_count);
    if qerr == http3::QpackError.None {
        sig = fuzz_mix_state(sig, 0x4020 ^ (map.entries.len as u64));
    }
    return sig;
}

// ---- Target 5: HTTP/3 Server & Client Connection State Machine -------------
// Ported from vendor/nghttp3/fuzz/fuzz_http3serverreq.cc
fn fuzz_target_http3_conn(data: const u8[:]) -> u64 {
    var sig: u64 = 0x5000;
    var fdp = new_fdp(data);
    let h3_settings = fingerprint::H3Settings { .. };
    var srv = http3::new_server_connection(h3_settings);
    var cli = http3::new_client_connection(h3_settings);
    let stream_ids: u64[8] = [2, 6, 10, 0, 4, 8, 12, 16];

    var steps: i64 = 0;
    while fdp_remaining(fdp) > 0 && steps < 16 {
        steps = core::add_sat_i64(steps, 1);
        let stream_sel = (fdp_consume_u8(fdp) & 0x07) as i64;
        let fin = fdp_consume_bool(fdp);
        let chunk_len = ((fdp_consume_u8(fdp) & 0x7F) as i64) | 1;
        let chunk = fdp_consume_bytes(fdp, chunk_len);

        let is_uni = stream_sel < 3;
        let sid = stream_ids[stream_sel];
        let err_s = http3::handle_stream_data(srv, sid, !is_uni, chunk, fin);
        if err_s == rfc::H3_ERR_NO_ERROR { sig = fuzz_mix_state(sig, 0x5010 ^ sid); }
        let err_c = http3::handle_stream_data(cli, sid, !is_uni, chunk, fin);
        if err_c == rfc::H3_ERR_NO_ERROR { sig = fuzz_mix_state(sig, 0x5020 ^ sid); }
    }
    return sig;
}

// ---- Target 6: QUIC Packet Headers & Frame Decoder -------------------------
// Ported from vendor/ngtcp2/fuzz/decode_frame.cc & vendor/quinn/fuzz/fuzz_targets/packet.rs
fn fuzz_target_quic_packets_and_frames(data: const u8[:]) -> u64 {
    var sig: u64 = 0x6000;
    let cid_lens: u8[4] = [0, 4, 8, 20];
    for i in 4 {
        let hdr, ok_qh = quic::parse_header(data, cid_lens[i]);
        if ok_qh {
            sig = fuzz_mix_state(sig, 0x6010 ^ (hdr.version as u64));
        }
    }

    var cur:   i64 = 0;
    var steps: i64 = 0;
    while cur < data.len && steps < 64 {
        let prev = cur;
        let _, ok = quic::decode_frame_cursor(data, cur);
        steps = core::add_sat_i64(steps, 1);
        if !ok || cur <= prev { break; }
        sig = fuzz_mix_state(sig, 0x6020 ^ (cur as u64));
    }

    let ack_f, _, ok_ack = quic::decode_ack_frame(data, 0);
    if ok_ack {
        assert(ack_f.largest_acked >= ack_f.first_ack_range);
        sig = fuzz_mix_state(sig, 0x6030);
    }
    return sig;
}

fn dispatch_quic_stream_fuzz_op(
    tbl:       quic::QuicStreamTable&,
    op:        u8,
    sid:       u64,
    offset:    u64,
    chunk_len: u64,
    fin:       bool,
) {
    if op == 0 {
        let _, _, _ = quic::open_local_stream(tbl, fin);
        return;
    }
    let idx, ok_s = quic::get_or_open_stream(tbl, sid);
    guard ok_s && idx >= 0 else { return; }
    let s_idx = idx as i64;
    if op == 1 {
        let _, _ = quic::on_recv_stream_frame(tbl.streams[s_idx], offset, chunk_len, fin);
    } else if op == 2 {
        let _, _ = quic::on_recv_reset(tbl.streams[s_idx], offset, offset);
    } else if op == 3 {
        let _, _ = quic::on_recv_stop_sending(tbl.streams[s_idx], offset, quic::QuicRole.Server);
    }
    assert(tbl.streams[s_idx].bytes_recv <= tbl.streams[s_idx].recv_max_data);
    if tbl.streams[s_idx].has_recv_final_size {
        assert(tbl.streams[s_idx].bytes_recv <= tbl.streams[s_idx].recv_final_size);
    }
}

// ---- Target 7: QUIC Reassembly Buffer (rob.cc), ACK Tracker & Stream Table -
// Ported from vendor/ngtcp2/fuzz/rob.cc, ksl.cc & vendor/quinn/fuzz/fuzz_targets/streams.rs
fn fuzz_target_quic_rob_and_streams(data: const u8[:]) -> u64 {
    var sig: u64 = 0x7000;
    var fdp = new_fdp(data);
    var rbuf = quic::new_reassembly_buffer();
    var ack_ranges: quic::AckInterval[..64] = [];
    var tbl = quic::new_stream_table(quic::QuicRole.Server);

    var steps: i64 = 0;
    while fdp_remaining(fdp) > 0 && steps < 32 {
        steps = core::add_sat_i64(steps, 1);
        let op = fdp_consume_u8(fdp) & 0x07;
        let offset = (fdp_consume_u16(fdp) as u64) & 0x1FFF;
        let fin = fdp_consume_bool(fdp);
        let chunk_len = ((fdp_consume_u8(fdp) & 0x3F) as i64) | 1;
        let chunk = fdp_consume_bytes(fdp, chunk_len);

        let prev_consumed = rbuf.consumed_offset;
        if quic::insert_fragment(rbuf, offset, chunk, fin) {
            sig = fuzz_mix_state(sig, 0x7010 ^ rbuf.consumed_offset);
        }
        var read_out: u8[..256] = [];
        let n_read = quic::read_contiguous(rbuf, read_out);
        assert(rbuf.consumed_offset == core::add_sat_u64(prev_consumed, n_read));

        quic::record_received_pn(ack_ranges, offset);
        let _, _ = quic::build_ack_frame(ack_ranges, 10, true);

        let sid = offset & 0x7C;
        dispatch_quic_stream_fuzz_op(tbl, op, sid, offset, chunk.len as u64, fin);
    }
    return sig;
}

// ---- Target 8: QUIC Connection Datagram Ingress (Plain & Encrypted) --------
// Ported from vendor/ngtcp2/fuzz/read_write_pkt.cc
fn fuzz_target_quic_conn(data: const u8[:]) -> u64 {
    var sig: u64 = 0x8000;
    let scid: u8[8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    var srv_plain = quic::new_server_connection(scid[..]);
    var ack_out = quic::AckFrame { .. };
    let _pr_ok1 = quic::process_datagram(srv_plain, data, 1000, ack_out);
    let ok1 = _pr_ok1.handled;
    if ok1 { sig = fuzz_mix_state(sig, 0x8010); }

    var srv_enc = quic::new_server_connection(scid[..]);
    let _ = quic::install_initial_keys(srv_enc, scid[..]);
    let _pr_ok2 = quic::process_datagram(srv_enc, data, 2000, ack_out);
    let ok2 = _pr_ok2.handled;
    if ok2 { sig = fuzz_mix_state(sig, 0x8020); }
    return sig;
}

// ---- Target 9: TLS 1.3 Record Deframer, Handshake & ECH (RFC 9849) ---------
// Ported from vendor/rustls/fuzz/fuzzers/{deframer.rs, message.rs, server.rs, client.rs}
// & vendor/picotls/fuzz/{fuzz-client-hello.c, fuzz-server-hello.c}
fn fuzz_target_tls13_deframer_and_handshake(data: const u8[:]) -> u64 {
    var sig: u64 = 0x9000;
    let r_type, _, _, _, ok_rec = wing::parse_tls_record_header(data);
    if ok_rec { sig = fuzz_mix_state(sig, 0x9001 ^ (r_type as u64)); }
    let hs_type, _, ok_hs = wing::parse_handshake_header(data);
    if ok_hs { sig = fuzz_mix_state(sig, 0x9002 ^ (hs_type as u64)); }

    var ch_pub:  u8[32]    = [0; 32];
    var ch_sid:  u8[..32]  = [];
    var ch_alpn: u8[..32]  = [];
    var ch_sni:  u8[..255] = [];
    var psk_resumed = false;
    var psk_secret: u8[32] = [0; 32];
    if wing::parse_client_hello_for_server_sni(data, "h2,http/1.1", ch_sid, ch_pub, ch_alpn, ch_sni, psk_resumed, psk_secret) {
        sig = fuzz_mix_state(sig, 0x9010 ^ (ch_sni.len as u64));
    }

    var sh_cipher: u16 = 0;
    var sh_is_hrr = false;
    var sh_group: u16        = 0;
    var sh_share: u8[..2048] = [];
    var sh_psk_resumed = false;
    if wing::parse_server_hello_or_hrr(data, sh_cipher, sh_is_hrr, sh_group, sh_share, sh_psk_resumed) {
        assert(rfc::is_supported_tls13_cipher_suite(sh_cipher));
        if sh_is_hrr { assert(sh_share.len == 0); }
        sig = fuzz_mix_state(sig, 0x9020 ^ (sh_cipher as u64));
    }

    var ee_alpn: u8[..32] = [];
    if wing::parse_encrypted_extensions_alpn(data, ee_alpn) { sig = fuzz_mix_state(sig, 0x9030); }

    // Structure-aware extension placement oracle (RFC 8446 §4.2 Table 2)
    var fdp = new_fdp(data);
    let ext_type = fdp_consume_u16(fdp);
    let ext_val = fdp_consume_bytes(fdp, 16);
    var synth_ee: u8[..32] = [];
    let ext_block_len = core::add_sat_i64(4, ext_val.len) as u16;
    core::write_be_u16(synth_ee, ext_block_len);
    core::write_be_u16(synth_ee, ext_type);
    core::write_be_u16(synth_ee, ext_val.len as u16);
    synth_ee.append(ext_val);
    let ok_synth_ee = wing::parse_encrypted_extensions_alpn(synth_ee[..], ee_alpn);
    if rfc::is_forbidden_ee_extension(ext_type) {
        assert(!ok_synth_ee);
    }

    var cert_req = wing::CertificateRequestMsg { .. };
    if wing::parse_certificate_request(data, true, cert_req) { sig = fuzz_mix_state(sig, 0x9040); }

    let _, _, ok_cv = wing::parse_certificate_verify(data);
    if ok_cv { sig = fuzz_mix_state(sig, 0x9050); }

    var nst = wing::NewSessionTicketMsg { .. };
    if wing::parse_new_session_ticket(data, nst) { sig = fuzz_mix_state(sig, 0x9060); }

    let _, ok_ku = wing::parse_key_update(data);
    if ok_ku { sig = fuzz_mix_state(sig, 0x9070); }
    let _, ok_cc = wing::parse_compressed_certificate(data);
    if ok_cc { sig = fuzz_mix_state(sig, 0x9080); }

    var ech_cfg = wing::EchConfig { .. };
    if wing::parse_ech_config(data, ech_cfg) { sig = fuzz_mix_state(sig, 0x9090); }
    var ech_list = wing::EchConfigList { .. };
    if wing::parse_ech_config_list(data, ech_list) {
        sig = fuzz_mix_state(sig, 0x90A0 ^ (ech_list.configs.len as u64));
    }
    return sig;
}

fn fuzz_x509_tamper_oracle(data: const u8[:]) {
    guard data.len >= 2 else { return; }
    let seed: u8[32] = [0x5A; 32];
    var valid_der: u8[..2048] = [];
    guard wing::build_test_ed25519_cert_der(seed, "example.com", "example.com", "127.0.0.1", valid_der) else {
        return;
    }
    var valid_cert = wing::ParsedCert { .. };
    guard wing::parse_x509_certificate(valid_der[..], valid_cert) else { return; }

    var tampered_der: u8[..2048] = [];
    tampered_der.append(valid_der[..]);
    let tbs_start = valid_cert.tbs_cert.offset as u64;
    let last_idx = core::sub_sat_u64(tampered_der.len as u64, 1);
    guard tbs_start <= last_idx else { return; }
    var fdp = new_fdp(data);
    let flip_idx = fdp_consume_u64_in_range(fdp, tbs_start, last_idx) as i64;
    guard flip_idx >= 0 && flip_idx < tampered_der.len else { return; }
    let delta: u8 = fdp_consume_u8(fdp) | 1;
    tampered_der[flip_idx] = tampered_der[flip_idx] ^ delta;

    var tampered_cert = wing::ParsedCert { .. };
    if wing::parse_x509_certificate(tampered_der[..], tampered_cert) {
        let alert = wing::x509_verify_cert_signature(
            tampered_cert, tampered_der[..], valid_cert, valid_der[..],
        );
        assert(alert != wing::TlsAlert.CloseNotify);
    }
}

// ---- Target 10: X.509 ASN.1 DER Certificate, CRL & OCSP Parser -------------
// Ported from vendor/picotls/fuzz/fuzz-asn1.c & boringssl/fuzz/parse_certificate_fuzzer.cc
fn fuzz_target_x509_asn1(data: const u8[:]) -> u64 {
    var sig: u64 = 0xA000;
    var cert = wing::ParsedCert { .. };
    let ok = wing::parse_x509_certificate(data, cert);
    if ok {
        assert(cert.signature_value.length > 0 && cert.tbs_cert.length > 0);
        if cert.has_unsupported_critical {
            var chain_p: wing::ParsedCert[..8] = [];
            var chain_s: (const u8[:])[..8]    = [];
            let _ = chain_p.try_push(cert);
            let _ = chain_s.try_push(data);
            let store = wing::TrustAnchorStore { .. };
            let alert = wing::verify_certificate_chain(chain_p, chain_s, store, 1735689600);
            assert(alert != wing::TlsAlert.CloseNotify);
        }
        sig = fuzz_mix_state(sig, 0xA010);
        var sans: wing::SanEntry[..16] = [];
        if wing::get_cert_san_extension(cert, data, sans) {
            sig = fuzz_mix_state(sig, 0xA020 ^ (sans.len as u64));
        }
        let _ = wing::match_any_san(sans, "example.com");
    }

    var crl = wing::ParsedCrl { .. };
    if wing::parse_x509_crl(data, crl) {
        assert(crl.signature.length > 0 && crl.tbs_raw.length > 0);
        sig = fuzz_mix_state(sig, 0xA030);
    }

    var ocsp = wing::ParsedOcspResponse { .. };
    if wing::parse_ocsp_response(data, ocsp) {
        if ocsp.status == wing::OcspResponseStatus.Successful {
            assert(ocsp.signature.length > 0 && ocsp.tbs_raw.length > 0);
        }
        sig = fuzz_mix_state(sig, 0xA040);
    }
    fuzz_x509_tamper_oracle(data);
    return sig;
}

fn fuzz_masque_dns_proxy(data: const u8[:], sig: u64) -> u64 {
    var s = sig;
    let cap, ok_cap = wing::parse_http_capsule(data);
    if ok_cap {
        s = fuzz_mix_state(s, 0xB050 ^ cap.capsule_type);
        if cap.payload.len <= 1024 {
            var enc_cap: u8[..1200] = [];
            if wing::encode_http_capsule(enc_cap, cap.capsule_type, cap.payload) {
                let cap2, ok2 = wing::parse_http_capsule(enc_cap[..]);
                assert(ok2 && cap2.capsule_type == cap.capsule_type && cap2.payload == cap.payload);
            }
        }
    }
    let qid, _, _, ok_dg = wing::decode_http_datagram(data);
    if ok_dg { s = fuzz_mix_state(s, 0xB060 ^ qid); }
    let udp_h, udp_p, ok_up = wing::parse_connect_udp_path(data);
    if ok_up { s = fuzz_mix_state(s, 0xB070 ^ (udp_p as u64) ^ (udp_h.len as u64)); }
    let _, _, ok_udg = wing::parse_connect_udp_datagram(data);
    if ok_udg { s = fuzz_mix_state(s, 0xB080); }

    let dns_res, ok_dns = dns::parse_response(data);
    if ok_dns {
        s = fuzz_mix_state(s, 0xB090 ^ (dns_res.a_records.len as u64) ^ (dns_res.https_records.len as u64));
    }
    let _ = core::validate_idna_domain_bounds(data);

    let _, consumed_p, ok_p = wing::parse_proxy_header(data);
    if ok_p {
        s = fuzz_mix_state(s, 0xB0A0 ^ (consumed_p as u64));
    }
    return s;
}

fn drain_grpc_parser_messages(p: grpc::StreamParser&, out_acc: u8[>..]&) -> i64 {
    var count:   i64        = 0;
    var msg_buf: u8[..4096] = [];
    var comp = false;
    while grpc::next_message(p, msg_buf, comp) {
        out_acc.push(if comp { 1 } else { 0 });
        out_acc.append(msg_buf[..]);
        count = core::add_sat_i64(count, 1);
        if count >= 16 { break; }
    }
    return count;
}

fn verify_grpc_stream_split_parity(data: const u8[:]) {
    guard data.len > 0 && data.len <= 8192 else { return; }
    var p_full = grpc::new_stream_parser(2048);
    var acc_full: u8[>..] = [];
    guard grpc::feed(p_full, data) else { return; }
    let cnt_full = drain_grpc_parser_messages(p_full, acc_full);
    guard !p_full.has_error else { return; }

    var p_split = grpc::new_stream_parser(2048);
    var acc_split: u8[>..] = [];
    var cnt_split: i64     = 0;
    var pos:       i64     = 0;
    while pos < data.len && cnt_split < 16 {
        let step = ((pos % 5) + 1);
        let end = min(data.len, core::add_sat_i64(pos, step));
        assert(grpc::feed(p_split, data[pos..end]));
        cnt_split = core::add_sat_i64(cnt_split, drain_grpc_parser_messages(p_split, acc_split));
        pos = end;
    }
    assert(cnt_split == cnt_full && acc_split[..] == acc_full[..]);
}
// ---- Target 11: WebSocket, gRPC, MASQUE, DNS & HAProxy PROXY v1/v2 ---------
// Ported from vendor/tungstenite/fuzz/fuzz_targets/{parse_frame_header.rs, read_message_server.rs}
fn fuzz_target_websocket_and_grpc(data: const u8[:]) -> u64 {
    var sig: u64 = 0xB000;
    verify_grpc_stream_split_parity(data);
    let hdr, ok_ws = realtime::parse_ws_frame_header(data);
    let hlen = hdr.header_len as i64;
    if ok_ws {
        if hdr.opcode >= 8 {
            assert(hdr.fin && hdr.payload_len <= 125);
        }
        sig = fuzz_mix_state(sig, 0xB001 ^ (hdr.opcode as u64));
        if hdr.opcode == 8 && hlen <= data.len {
            let _, reason_in, ok_ci = realtime::parse_close_payload(data[hlen..data.len]);
            if ok_ci { assert(reason_in.len <= 123); }
        }
    }
    let _, reason_cls, ok_cls = realtime::parse_close_payload(data);
    if ok_cls {
        assert(reason_cls.len <= 123);
        let _ = core::validate_utf8(reason_cls);
        sig = fuzz_mix_state(sig, 0xB010);
    }

    var ws_comp = realtime::SharedWsCompressor { .. };
    var decomp_ws: u8[..4096] = [];
    if realtime::ws_inflate_message(ws_comp, data, decomp_ws, 4096, true) {
        sig = fuzz_mix_state(sig, 0xB020 ^ (decomp_ws.len as u64));
    }

    let lpm_slice, _, lpm_consumed, ok_lpm = grpc::decode_lpm_slice(data, 0);
    if ok_lpm {
        assert(lpm_consumed >= 5 && lpm_consumed <= data.len && lpm_slice.len <= data.len);
        sig = fuzz_mix_state(sig, 0xB030);
    }
    var web_payload: u8[..2048] = [];
    var is_trailers = false;
    var is_comp = false;
    let _, ok_gw = grpc::decode_web_frame(data, 0, web_payload, is_trailers, is_comp);
    if !ok_gw { sig = fuzz_mix_state(sig, 0xB040); }
    let _, _ = grpc::parse_timeout(data);

    return fuzz_masque_dns_proxy(data, sig);
}

fn verify_compress_roundtrip(data: const u8[:]) {
    let take = min(data.len, 256);
    let src = data[..take];
    var comp:   u8[>..] = [];
    var decomp: u8[>..] = [];
    if core::deflate(src, comp, 6) {
        let _, err_d = core::inflate(comp[..], decomp);
        assert(err_d == core::CompressError.None && decomp[..] == src);
    }
    comp.clear();
    decomp.clear();
    if core::gzip_compress(src, comp, 6) {
        let _, err_g = core::gzip_decompress(comp[..], decomp);
        assert(err_g == core::CompressError.None && decomp[..] == src);
    }
    comp.clear();
    decomp.clear();
    if core::zlib_compress(src, comp, 6) {
        let ok_z, _ = core::zlib_decompress(comp[..], decomp);
        assert(ok_z && decomp[..] == src);
    }
}

fn fuzz_bhttp_ohttp_privacypass(data: const u8[:], sig: u64) -> u64 {
    var s = sig;
    var breq = wing::BhttpRequest { .. };
    if wing::bhttp_decode_request(data, breq) {
        s = fuzz_mix_state(s, 0xC050 ^ (breq.body_len as u64));
        var enc_req: u8[..8192] = [];
        if wing::bhttp_encode_request(breq, enc_req) > 0 {
            var breq2 = wing::BhttpRequest { .. };
            let ok2 = wing::bhttp_decode_request(enc_req[..], breq2);
            assert(ok2 && breq2.method[..] == breq.method[..] && breq2.target[..] == breq.target[..]);
        }
    }
    var bres = wing::BhttpResponse { .. };
    if wing::bhttp_decode_response(data, bres) {
        s = fuzz_mix_state(s, 0xC060 ^ (bres.status as u64));
        var enc_res: u8[..8192] = [];
        if wing::bhttp_encode_response(bres, enc_res) > 0 {
            var bres2 = wing::BhttpResponse { .. };
            let ok2 = wing::bhttp_decode_response(enc_res[..], bres2);
            assert(ok2 && bres2.status == bres.status);
        }
    }

    var ocfg = wing::OhttpKeyConfig { .. };
    if wing::parse_ohttp_key_config(data, ocfg) { s = fuzz_mix_state(s, 0xC070 ^ (ocfg.key_id as u64)); }
    var ocfgs:  wing::OhttpKeyConfig[..4] = [];
    var ocount: i32                       = 0;
    if wing::parse_ohttp_key_configs(data, ocfgs, ocount) {
        s = fuzz_mix_state(s, 0xC080 ^ (ocount as u64));
    }

    let chal, ok_c = security::unmarshal_token_challenge(data);
    if ok_c {
        s = fuzz_mix_state(s, 0xC090 ^ (chal.token_type as u64));
        var enc_c: u8[..1024] = [];
        security::marshal_token_challenge(chal, enc_c);
        let chal2, ok_c2 = security::unmarshal_token_challenge(enc_c[..]);
        assert(ok_c2 && chal2.token_type == chal.token_type && chal2.issuer_name[..] == chal.issuer_name[..]);
    }
    let _, ok_ptok = security::unmarshal_token(data, 32, 64);
    if ok_ptok {
        s = fuzz_mix_state(s, 0xC0A0);
    }
    return s;
}

// ---- Target 12: SFV, Cookie, URL, Compression & BHTTP/OHTTP/PrivacyPass ----
// Ported from vendor/sfparse/fuzz/parser.cc, vendor/cookie-rs/fuzz/fuzz_targets/parser.rs,
// vendor/uWebSockets/libdeflate/scripts/libFuzzer & vendor/zstd/tests/fuzz
fn fuzz_target_url_cookie_sfv_compress(data: const u8[:]) -> u64 {
    var sig:          u64                     = 0xC000;
    var dict_entries: wing::SfDictEntry[..16] = [];
    if wing::parse_sf_dict(data, dict_entries) {
        sig = fuzz_mix_state(sig, 0xC001 ^ (dict_entries.len as u64));
    }

    var list_items: wing::SfParameterizedItem[..16] = [];
    if wing::parse_sf_list(data, list_items) {
        sig = fuzz_mix_state(sig, 0xC002 ^ (list_items.len as u64));
    }

    let _, ok_sfi = wing::parse_sf_item(data);
    if ok_sfi { sig = fuzz_mix_state(sig, 0xC003); }
    let _, ok_pri = wing::parse_http_priority(data, false);
    if ok_pri { sig = fuzz_mix_state(sig, 0xC004); }

    var jar = cookie::CanonicalCookieJar { .. };
    if cookie::set_cookie_header(jar, "https://example.com/path", data, 1700000000000000, true) {
        sig = fuzz_mix_state(sig, 0xC010);
    }
    let ns_cookie, ns_ok = cookie::try_parse_netscape_cookie_line(data);
    if ns_ok {
        assert(ns_cookie.domain.len > 0 && ns_cookie.domain[0] != '.');
        let _ = cookie::validate_security(ns_cookie);
        sig = fuzz_mix_state(sig, 0xC011);
    }
    let _ = security::is_private_or_reserved_ip(data);
    let _ = security::is_cloud_metadata_or_reserved_ip(data);
    let _, ok_v6 = core::parse_ipv6_octets(data);
    if ok_v6 { sig = fuzz_mix_state(sig, 0xC012); }

    let uview, _ = core::parse_url_view(data);
    if uview.valid { sig = fuzz_mix_state(sig, 0xC020 ^ (uview.host.len as u64)); }
    var norm_url: u8[..1024] = [];
    if core::normalize_http_target_uri(data, norm_url) {
        assert(norm_url.len > 0);
        var norm_url2: u8[..1024] = [];
        let ok_n2 = core::normalize_http_target_uri(norm_url[..], norm_url2);
        assert(ok_n2 && norm_url2[..] == norm_url[..]);
        sig = fuzz_mix_state(sig, 0xC021);
    }

    var decomp_buf: u8[>..] = [];
    let _, err_inf = core::inflate(data, decomp_buf);
    if err_inf == core::CompressError.None { sig = fuzz_mix_state(sig, 0xC030 ^ (decomp_buf.len as u64)); }
    decomp_buf.clear();
    let _, err_gz = core::gzip_decompress(data, decomp_buf);
    if err_gz == core::CompressError.None { sig = fuzz_mix_state(sig, 0xC031 ^ (decomp_buf.len as u64)); }
    decomp_buf.clear();
    let ok_z, _ = core::zlib_decompress(data, decomp_buf);
    if ok_z { sig = fuzz_mix_state(sig, 0xC032 ^ (decomp_buf.len as u64)); }
    decomp_buf.clear();
    if core::brotli_decompress(data, decomp_buf) {
        sig = fuzz_mix_state(sig, 0xC033 ^ (decomp_buf.len as u64));
    }
    decomp_buf.clear();
    if core::zstd_decompress(data, decomp_buf) {
        sig = fuzz_mix_state(sig, 0xC034 ^ (decomp_buf.len as u64));
    }

    verify_compress_roundtrip(data);
    return fuzz_bhttp_ohttp_privacypass(data, sig);
}

// Structure-aware compression decoder & streaming chunk-split differential fuzz target (`IOCOMP-08`).
fn fuzz_target_compress_decoders(data: const u8[:]) -> u64 {
    var sig: u64 = 0xD000;
    var fdp = new_fdp(data);
    let step_raw = (fdp_consume_u8(fdp) & 0x1F) as i64;
    let chunk_step = max(1, step_raw);
    let payload = fdp_consume_remaining(fdp);

    var out_oneshot: u8[>..] = [];
    let ok_z, _ = core::zstd_decompress_with_limit(payload, out_oneshot, 4096);
    if ok_z {
        sig = fuzz_mix_state(sig, 0xD001 ^ (out_oneshot.len as u64));
        var zd = core::new_zstream_decompressor(core::ContainerFormat.Zstd);
        var out_stream: u8[>..] = [];
        var pos:        i64     = 0;
        while pos < payload.len {
            let end = min(payload.len, core::add_sat_i64(pos, chunk_step));
            let _ = core::zstream_decompress_write_limit(zd, payload[pos..end], out_stream, 4096);
            pos = end;
        }
        assert(out_stream[..] == out_oneshot[..]);
    }

    out_oneshot.clear();
    let ok_d, _ = core::inflate_with_limit(payload, out_oneshot, 4096);
    if ok_d {
        sig = fuzz_mix_state(sig, 0xD002 ^ (out_oneshot.len as u64));
    }
    return sig;
}

// Structure-aware RFC 9842 Compression Dictionary (`dcz`/`dcb` & Zstd dict) roundtrip fuzz target (`IOCOMP-08`).
fn fuzz_target_compression_dict_roundtrip(data: const u8[:]) -> u64 {
    var sig: u64 = 0xE000;
    var fdp = new_fdp(data);
    let dict_slice = fdp_consume_bytes(fdp, 64);
    let plain_slice = fdp_consume_bytes(fdp, 128);

    var comp_z:   u8[..4096] = [];
    var decomp_z: u8[..4096] = [];
    if core::zstd_compress_with_dict(plain_slice, dict_slice, comp_z, 3) {
        let ok_dec, _ = core::zstd_decompress_with_dict(comp_z[..], dict_slice, decomp_z, 4096);
        assert(ok_dec && decomp_z[..] == plain_slice);
        sig = fuzz_mix_state(sig, 0xE001 ^ (comp_z.len as u64));
    }

    if dict_slice.len > 0 {
        let dict_hash = core::sha256(dict_slice);
        var dcz_wire: u8[..4096] = [];
        if wing::encode_dcz_response(dcz_wire, dict_hash, plain_slice, dict_slice) {
            var parsed_hash: u8[32] = [0; 32];
            let zstd_body, ok_hdr = wing::decode_dcz_header(dcz_wire[..], parsed_hash);
            assert(ok_hdr && core::ct_eq_bytes(parsed_hash[..], dict_hash[..]));
            var dcz_out: u8[..4096] = [];
            let ok_dcz = wing::decompress_dcz_payload(zstd_body, dict_slice, dcz_out);
            assert(ok_dcz && dcz_out[..] == plain_slice);
            sig = fuzz_mix_state(sig, 0xE002 ^ (dcz_out.len as u64));
        }
    }
    return sig;
}

fn fill_fixed_from_fdp_12(fdp: FuzzedDataProvider&) -> u8[12] {
    var out: u8[12] = [0; 12];
    for i in 12 { out[i] = fdp_consume_u8(fdp); }
    return out;
}

fn fill_fixed_from_fdp_16(fdp: FuzzedDataProvider&) -> u8[16] {
    var out: u8[16] = [0; 16];
    for i in 16 { out[i] = fdp_consume_u8(fdp); }
    return out;
}

fn fill_fixed_from_fdp_24(fdp: FuzzedDataProvider&) -> u8[24] {
    var out: u8[24] = [0; 24];
    for i in 24 { out[i] = fdp_consume_u8(fdp); }
    return out;
}

fn fill_fixed_from_fdp_32(fdp: FuzzedDataProvider&) -> u8[32] {
    var out: u8[32] = [0; 32];
    for i in 32 { out[i] = fdp_consume_u8(fdp); }
    return out;
}

// ---- Target 15: AEAD Ciphers, In-Place Zeroization & HKDF ------------------
// Ported from vendor/uWebSockets/uSockets/boringssl/fuzz & Wycheproof AEAD suites.
fn fuzz_target_crypto_aead_and_kdf(data: const u8[:]) -> u64 {
    var sig: u64 = 0xF000;
    var fdp = new_fdp(data);
    let key32 = fill_fixed_from_fdp_32(fdp);
    let key16 = fill_fixed_from_fdp_16(fdp);
    let nonce12 = fill_fixed_from_fdp_12(fdp);
    let nonce24 = fill_fixed_from_fdp_24(fdp);
    let aad = fdp_consume_bytes(fdp, 32);
    let plain = fdp_consume_bytes(fdp, 256);
    let plen = plain.len;

    var ct_buf: u8[256]   = [0; 256];
    var in_out: u8[256]   = [0; 256];
    var dec:    u8[..512] = [];
    for i in plen { in_out[i] = plain[i]; }

    let tag128, n128, ok128 = core::aes128_gcm_seal(key16, nonce12, plain, aad, ct_buf[..plen]);
    let tag128_ip, ok128_ip = core::aes128_gcm_seal_inplace(key16, nonce12, in_out[..plen], aad);
    assert(ok128 && ok128_ip && n128 == plen && core::ct_eq_tag16(tag128, tag128_ip));
    assert(in_out[..plen] == ct_buf[..plen]);
    assert(core::aes128_gcm_open(key16, nonce12, ct_buf[..plen], aad, tag128, dec) && dec[..] == plain);

    var bad_tag128 = tag128;
    bad_tag128[0] ^= 0x01;
    let _, ok_bad128 = core::aes128_gcm_open_inplace(key16, nonce12, in_out[..plen], aad, bad_tag128);
    assert(!ok_bad128);

    for i in plen { in_out[i] = plain[i]; }
    dec.clear();
    let tag_c, nc, ok_c = core::chacha20_poly1305_seal(key32, nonce12, plain, aad, ct_buf[..plen]);
    let tag_cip, ok_cip = core::chacha20_poly1305_seal_inplace(key32, nonce12, in_out[..plen], aad);
    assert(ok_c && ok_cip && nc == plen && core::ct_eq_tag16(tag_c, tag_cip));
    assert(core::chacha20_poly1305_open(key32, nonce12, ct_buf[..plen], aad, tag_c, dec) && dec[..] == plain);

    var xct:  u8[..512] = [];
    var xdec: u8[..512] = [];
    let xtag = core::xchacha20_poly1305_seal(key32, nonce24, plain, aad, xct);
    assert(core::xchacha20_poly1305_open(key32, nonce24, xct[..], aad, xtag, xdec) && xdec[..] == plain);

    let prk256 = core::hkdf_extract(aad, key32[..]);
    var okm256: u8[64] = [0; 64];
    if core::hkdf_expand_bytes_256(prk256[..], plain, 64, okm256[..]) {
        sig = fuzz_mix_state(sig, 0xF001 ^ (okm256[0] as u64));
    }
    return fuzz_mix_state(sig, (plen as u64) ^ tag_c[0]);
}

// ---- Target 16: JOSE (JWT, JWE A256GCM, JWK, OAuth PKCE & DPoP) ------------
// Ported from vendor/cjose, vendor/libjwt, and vendor/libwebsockets/fuzz/fuzz-jose.
fn fuzz_target_jose_jwt_jwe_oauth(data: const u8[:]) -> u64 {
    var sig: u64 = 0x11000;
    var fdp = new_fdp(data);
    let cek = fill_fixed_from_fdp_32(fdp);
    let iv = fill_fixed_from_fdp_12(fdp);
    let body = fdp_consume_remaining(fdp);

    var jwe_plain: u8[..4096] = [];
    if auth::jwe_open_dir_a256gcm(data, cek, jwe_plain) {
        sig = fuzz_mix_state(sig, 0x11001 ^ (jwe_plain.len as u64));
    }

    let short_plain = body[..min(body.len, 128)];
    var compact_jwe: u8[..1024] = [];
    if auth::jwe_seal_dir_a256gcm("eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0", cek, iv, short_plain, compact_jwe) {
        jwe_plain.clear();
        let ok_open = auth::jwe_open_dir_a256gcm(compact_jwe[..], cek, jwe_plain);
        assert(ok_open && jwe_plain[..] == short_plain);
        sig = fuzz_mix_state(sig, 0x11002);
    }

    var unv_hdr = auth::JwtHeader { .. };
    var unv_clm = auth::JwtClaims { .. };
    if auth::parse_jwt_unverified(data, unv_hdr, unv_clm) == auth::JwtError.None {
        sig = fuzz_mix_state(sig, 0x11003);
    }

    let opts = auth::default_jwt_validation_options(auth::JwtAlg.HS256);
    if auth::verify_jwt_hmac(data, cek[..], opts, 1700000000, unv_hdr, unv_clm) == auth::JwtError.None {
        sig = fuzz_mix_state(sig, 0x11004);
    }

    if auth::is_valid_code_verifier(data) {
        var chal_buf: u8[..128] = [];
        if auth::compute_code_challenge(data, "S256", chal_buf) {
            assert(auth::validate_code_challenge_strict(data, chal_buf[..]));
            sig = fuzz_mix_state(sig, 0x11005);
        }
    }
    return sig;
}

// ---- Target 17: IDNA Punycode, Public Suffix List (PSL), IPv6 & URL --------
// Ported from vendor/libpsl/fuzz & vendor/h2o/fuzz/url-corpus.
fn fuzz_target_idna_psl_url_ip(data: const u8[:]) -> u64 {
    var sig:        u64       = 0x12000;
    var ace_domain: u8[..256] = [];
    if core::punycode_encode_domain(data, ace_domain) {
        assert(ace_domain.len > 0 && ace_domain.len <= 256);
        let _ = core::validate_idna_domain_bounds(ace_domain[..]);
        sig = fuzz_mix_state(sig, 0x12001 ^ (ace_domain.len as u64));
    }
    if core::validate_host_punycode_labels(data) {
        sig = fuzz_mix_state(sig, 0x12002);
    }

    var etld:   u8[..256] = [];
    var suffix: u8[..256] = [];
    core::extract_etld_plus_one(data, etld);
    if etld.len > 0 { sig = fuzz_mix_state(sig, 0x12003 ^ (etld.len as u64)); }
    if core::public_suffix_with_icann(data, suffix) {
        sig = fuzz_mix_state(sig, 0x12004 ^ (suffix.len as u64));
    }

    var ip6_comp:  u8[..64] = [];
    var ip6_comp2: u8[..64] = [];
    if core::parse_and_compress_ipv6(data, ip6_comp) {
        let ok2 = core::parse_and_compress_ipv6(ip6_comp[..], ip6_comp2);
        assert(ok2 && ip6_comp2[..] == ip6_comp[..]);
        sig = fuzz_mix_state(sig, 0x12005);
    }
    if core::is_valid_ipv4_format(data) {
        sig = fuzz_mix_state(sig, 0x12006);
    }

    let parsed_u, err_u = core::parse_url(data);
    if core::is_ok(err_u) {
        let site = core::registrable_site_from_url(parsed_u);
        sig = fuzz_mix_state(sig, 0x12007 ^ (site.registrable_domain.len as u64));
    }
    return sig;
}

// ---- Target 18: Extended HTTP Headers (Alt-Svc, Early Hints, W3C Trace) ----
// Ported from vendor/h2o/fuzz & vendor/uWebSockets/fuzzing/seed-corpus.
fn fuzz_target_http_ext_headers_trace(data: const u8[:]) -> u64 {
    var sig:       u64                       = 0x13000;
    var endpoints: wing::AltSvcEndpoint[..8] = [];
    let ok_as, is_clear = wing::parse_altsvc_header(data, endpoints);
    if ok_as {
        sig = fuzz_mix_state(sig, 0x13001 ^ (endpoints.len as u64) ^ (if is_clear { 1 } else { 0 }));
    }

    var links: wing::EarlyHintLink[..8] = [];
    if wing::parse_link_header(data, links) {
        sig = fuzz_mix_state(sig, 0x13002 ^ (links.len as u64));
    }

    var cert_der: u8[..4096] = [];
    var cert_len: i32        = 0;
    if wing::parse_client_cert(data, cert_der, cert_len) {
        var enc_cc: u8[..8192] = [];
        let wr = wing::encode_client_cert(cert_der[..], enc_cc);
        assert(wr > 0);
        sig = fuzz_mix_state(sig, 0x13003 ^ (cert_len as u64));
    }

    var cs_entries: wing::CacheStatusEntry[..8] = [];
    let n_cs = wing::parse_cache_status_header(data, cs_entries);
    if n_cs > 0 { sig = fuzz_mix_state(sig, 0x13004 ^ (n_cs as u64)); }

    var ps_entries: wing::ProxyStatusEntry[..8] = [];
    let n_ps = wing::parse_proxy_status_header(data, ps_entries);
    if n_ps > 0 { sig = fuzz_mix_state(sig, 0x13005 ^ (n_ps as u64)); }

    let tp, ok_tp = wing::parse_traceparent(data);
    if ok_tp {
        var tp_wire: u8[..64] = [];
        wing::format_traceparent(tp, tp_wire);
        let tp2, ok_tp2 = wing::parse_traceparent(tp_wire[..]);
        assert(ok_tp2 && tp2.trace_flags == tp.trace_flags);
        sig = fuzz_mix_state(sig, 0x13006);
    }

    let ts, ok_ts = wing::parse_tracestate(data);
    if ok_ts {
        var ts_wire: u8[..1024] = [];
        wing::format_tracestate(ts, ts_wire);
        sig = fuzz_mix_state(sig, 0x13007 ^ (ts.members.len as u64));
    }
    return sig;
}

// Runs all OSS-Fuzz targets on a single input slice `data` and returns the combined state signature.
fn oss_fuzz_test_one_input(data: const u8[:]) -> u64 {
    var sig: u64 = 0xCBF29CE484222325;
    sig = fuzz_mix_state(sig, fuzz_target_http1(data));
    sig = fuzz_mix_state(sig, fuzz_target_http2_hpack_and_frames(data));
    sig = fuzz_mix_state(sig, fuzz_target_http2_session(data));
    sig = fuzz_mix_state(sig, fuzz_target_http3_qpack(data));
    sig = fuzz_mix_state(sig, fuzz_target_http3_conn(data));
    sig = fuzz_mix_state(sig, fuzz_target_quic_packets_and_frames(data));
    sig = fuzz_mix_state(sig, fuzz_target_quic_rob_and_streams(data));
    sig = fuzz_mix_state(sig, fuzz_target_quic_conn(data));
    sig = fuzz_mix_state(sig, fuzz_target_tls13_deframer_and_handshake(data));
    sig = fuzz_mix_state(sig, fuzz_target_x509_asn1(data));
    sig = fuzz_mix_state(sig, fuzz_target_websocket_and_grpc(data));
    sig = fuzz_mix_state(sig, fuzz_target_url_cookie_sfv_compress(data));
    sig = fuzz_mix_state(sig, fuzz_target_compress_decoders(data));
    sig = fuzz_mix_state(sig, fuzz_target_compression_dict_roundtrip(data));
    sig = fuzz_mix_state(sig, fuzz_target_crypto_aead_and_kdf(data));
    sig = fuzz_mix_state(sig, fuzz_target_jose_jwt_jwe_oauth(data));
    sig = fuzz_mix_state(sig, fuzz_target_idna_psl_url_ip(data));
    sig = fuzz_mix_state(sig, fuzz_target_http_ext_headers_trace(data));
    return sig;
}

const FUZZ_TARGET_NAMES: const u8[:][18] = [
    "http1",
    "h2_hpack",
    "h2_session",
    "h3_qpack",
    "h3_conn",
    "quic_pkt",
    "quic_rob",
    "quic_conn",
    "tls13",
    "x509",
    "ws_grpc",
    "url_cookie_sfv",
    "compress_decoders",
    "dict_roundtrip",
    "crypto_aead_kdf",
    "jose_jwt_jwe_oauth",
    "idna_psl_url_ip",
    "http_ext_headers_trace",
];

// Resolves a target CLI name into a numeric target ID (-1 = all, 0..17 = individual protocol target).
fn parse_fuzz_target_id(target: const u8[:]) -> i32 {
    for i in 18 {
        if target == FUZZ_TARGET_NAMES[i] {
            return (i as i32) | 0;
        }
    }
    return -1;
}

fn oss_fuzz_run_extended_target_id(target_id: i32, data: const u8[:]) -> u64 {
    if target_id == 9 { return fuzz_target_x509_asn1(data); }
    if target_id == 10 { return fuzz_target_websocket_and_grpc(data); }
    if target_id == 11 { return fuzz_target_url_cookie_sfv_compress(data); }
    if target_id == 12 { return fuzz_target_compress_decoders(data); }
    if target_id == 13 { return fuzz_target_compression_dict_roundtrip(data); }
    if target_id == 14 { return fuzz_target_crypto_aead_and_kdf(data); }
    if target_id == 15 { return fuzz_target_jose_jwt_jwe_oauth(data); }
    if target_id == 16 { return fuzz_target_idna_psl_url_ip(data); }
    if target_id == 17 { return fuzz_target_http_ext_headers_trace(data); }
    return oss_fuzz_test_one_input(data);
}

// Dispatches `data` to a numeric OSS-Fuzz target ID (0..17) or all targets (-1) and returns state signature.
fn oss_fuzz_run_target_id(target_id: i32, data: const u8[:]) -> u64 {
    if target_id == 0 { return fuzz_target_http1(data); }
    if target_id == 1 { return fuzz_target_http2_hpack_and_frames(data); }
    if target_id == 2 { return fuzz_target_http2_session(data); }
    if target_id == 3 { return fuzz_target_http3_qpack(data); }
    if target_id == 4 { return fuzz_target_http3_conn(data); }
    if target_id == 5 { return fuzz_target_quic_packets_and_frames(data); }
    if target_id == 6 { return fuzz_target_quic_rob_and_streams(data); }
    if target_id == 7 { return fuzz_target_quic_conn(data); }
    if target_id == 8 { return fuzz_target_tls13_deframer_and_handshake(data); }
    return oss_fuzz_run_extended_target_id(target_id, data);
}
