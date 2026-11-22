// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification LIT test for RFC 9000 Section 7.5 QUIC out-of-order CRYPTO
// stream reassembly and full DST determinism purity across core::now,
// core::csprng_fill/csprng_u64, tls_internal::random_bytes_32, and
// http::generate_multipart_boundary.
// RUN: goose %s | %FileCheck %s

import std;
import wing from "../..";

const SIM_BASE_UNIX_NS: u64 = 1700000000000000000;
const NS_PER_MS:        u64 = 1000000;
const NS_PER_SEC:       u64 = 1000000000;

struct DstPuritySample {
    t1:           core::Time = core::Time { .. },
    t2:           core::Time = core::Time { .. },
    csprng_bytes: u8[32]     = [0; 32],
    csprng_u64_a: u64        = 0,
    csprng_u64_b: u64        = 0,
    tls_rand_a:   u8[32]     = [0; 32],
    tls_rand_b:   u8[32]     = [0; 32],
    boundary_a:   u8[..70]   = [],
    boundary_b:   u8[..70]   = [],
}

fn samples_equal(a: const DstPuritySample&, b: const DstPuritySample&) -> bool {
    return a.t1.wall_sec == b.t1.wall_sec
        && a.t1.nsec == b.t1.nsec
        && a.t2.wall_sec == b.t2.wall_sec
        && a.t2.nsec == b.t2.nsec
        && a.csprng_bytes[..] == b.csprng_bytes[..]
        && a.csprng_u64_a == b.csprng_u64_a
        && a.csprng_u64_b == b.csprng_u64_b
        && a.tls_rand_a[..] == b.tls_rand_a[..]
        && a.tls_rand_b[..] == b.tls_rand_b[..]
        && a.boundary_a[..] == b.boundary_a[..]
        && a.boundary_b[..] == b.boundary_b[..];
}

// 1. 3-way out-of-order reassembly: [chunk2, chunk0, chunk1] -> exact byte match.
fn test_quic_crypto_ooo_three_way_split() {
    var stream = tls::QuicCryptoStream { .. };
    let full = "ClientHello_Part0|Extensions_Part1|KeyShare_Part2";
    let chunk0 = full[0..17];
    let chunk1 = full[17..35];
    let chunk2 = full[35..];

    let n2, ok2 = tls::quic_crypto_stream_ingest(stream, 35, chunk2);
    assert(ok2 && n2 == 0 && stream.consumed_offset == 0 && stream.buf.len == 0);
    assert(stream.ooo_ranges.len == 1);

    let n0, ok0 = tls::quic_crypto_stream_ingest(stream, 0, chunk0);
    assert(ok0 && n0 == chunk0.len && stream.consumed_offset == 17);
    assert(stream.buf[..] == chunk0 && stream.ooo_ranges.len == 1);

    let n1, ok1 = tls::quic_crypto_stream_ingest(stream, 17, chunk1);
    assert(ok1 && n1 == (chunk1.len + chunk2.len));
    assert(stream.consumed_offset == (full.len as u64));
    assert(stream.buf[..] == full);
    assert(stream.ooo_ranges.len == 0);
    print("QUIC_CRYPTO_OOO_THREE_WAY: OK");
}

// 2. Overlapping OOO frames, duplicate frames, first-write-wins preservation,
//    and ring-buffer wraparound across offset 4096.
fn test_quic_crypto_ooo_overlaps_and_wraparound() {
    var stream = tls::QuicCryptoStream { .. };

    // Stage [10..16] = "ABCDEF", then duplicate, then overlapping left/right with conflicting bytes.
    let n_s1, ok_s1 = tls::quic_crypto_stream_ingest(stream, 10, "ABCDEF");
    assert(ok_s1 && n_s1 == 0 && stream.ooo_ranges.len == 1);
    let n_dup, ok_dup = tls::quic_crypto_stream_ingest(stream, 10, "ABCDEF");
    assert(ok_dup && n_dup == 0 && stream.ooo_ranges.len == 1);

    // Overlap [6..12] with "6789XX" -> [6..10] staged as "6789", [10..12] keeps "AB".
    let n_ovl1, ok_ovl1 = tls::quic_crypto_stream_ingest(stream, 6, "6789XX");
    assert(ok_ovl1 && n_ovl1 == 0 && stream.ooo_ranges.len == 1);

    // Stage disjoint [20..24] = "WXYZ", then bridge [14..22] = "YYpqrsZZ" -> keeps "EF" and "WX".
    let n_s2, ok_s2 = tls::quic_crypto_stream_ingest(stream, 20, "WXYZ");
    assert(ok_s2 && n_s2 == 0 && stream.ooo_ranges.len == 2);
    let n_br, ok_br = tls::quic_crypto_stream_ingest(stream, 14, "YYpqrsZZ");
    assert(ok_br && n_br == 0 && stream.ooo_ranges.len == 1);

    // Close gap [0..6] = "012345" -> drains entire merged range [0..24].
    let n_close, ok_close = tls::quic_crypto_stream_ingest(stream, 0, "012345");
    assert(ok_close && n_close == 24 && stream.consumed_offset == 24);
    assert(stream.buf[..] == "0123456789ABCDEFpqrsWXYZ");
    assert(stream.ooo_ranges.len == 0);

    // In-order duplicate after full reassembly is a no-op.
    let n_after, ok_after = tls::quic_crypto_stream_ingest(stream, 4, "4567");
    assert(ok_after && n_after == 0 && stream.consumed_offset == 24);

    // Test ring wraparound across 4096 boundary.
    var wstream = tls::QuicCryptoStream { .. };
    var fill_buf: u8[512] = [0x41; 512];
    for _ in 7 {
        let nb, okb = tls::quic_crypto_stream_ingest(wstream, wstream.consumed_offset, fill_buf[..]);
        assert(okb && nb == 512);
    }
    // Advance consumed_offset to 4090 (3584 + 506).
    let n_pad, ok_pad = tls::quic_crypto_stream_ingest(wstream, 3584, fill_buf[..506]);
    assert(ok_pad && n_pad == 506 && wstream.consumed_offset == 4090);

    // Stage [4094..4104] straddling 4096 ("0123456789"), then close [4090..4094] ("WXYZ").
    let n_wrap, ok_wrap = tls::quic_crypto_stream_ingest(wstream, 4094, "0123456789");
    assert(ok_wrap && n_wrap == 0 && wstream.ooo_ranges.len == 1);
    let n_gap, ok_gap = tls::quic_crypto_stream_ingest(wstream, 4090, "WXYZ");
    assert(ok_gap && n_gap == 14 && wstream.consumed_offset == 4104);
    assert(wstream.buf[4090..4104] == "WXYZ0123456789");
    assert(wstream.ooo_ranges.len == 0);
    print("QUIC_CRYPTO_OOO_OVERLAP_WRAP: OK");
}

// 3. Adversarial DoS limits: oversize OOO window, MAX_QUIC_CRYPTO_BUFFER_LEN,
//    range-table saturation (16 max disjoint slots), and QUIC_ERR_CRYPTO_BUFFER_EXCEEDED.
fn test_quic_crypto_ooo_adversarial_dos() {
    var stream = tls::QuicCryptoStream { .. };

    // Exceeds MAX_QUIC_CRYPTO_BUFFER_LEN (16384) -> fail closed.
    let n_big, ok_big = tls::quic_crypto_stream_ingest(stream, 16384, "X");
    assert(!ok_big && n_big == 0 && stream.ooo_ranges.len == 0 && stream.buf.len == 0);

    // Exceeds OOO staging window (4096) -> fail closed.
    let n_win, ok_win = tls::quic_crypto_stream_ingest(stream, 4096, "X");
    assert(!ok_win && n_win == 0 && stream.ooo_ranges.len == 0);

    // Fill all 16 disjoint range slots at offsets 2, 4, 6, ..., 32.
    let one: u8[1] = [0x5A];
    for i in 16 {
        let off = ((i + 1) * 2) as u64;
        let ns, oks = tls::quic_crypto_stream_ingest(stream, off, one[..]);
        assert(oks && ns == 0);
    }
    assert(stream.ooo_ranges.len == 16);

    // 17th disjoint range MUST fail closed without mutating table.
    let n_17, ok_17 = tls::quic_crypto_stream_ingest(stream, 100, one[..]);
    assert(!ok_17 && n_17 == 0 && stream.ooo_ranges.len == 16);

    // Bridging two existing ranges [2..5] merges slots (16 -> 15) and succeeds.
    let n_merge, ok_merge = tls::quic_crypto_stream_ingest(stream, 2, "abc");
    assert(ok_merge && n_merge == 0 && stream.ooo_ranges.len == 15);

    // Live QuicConnection dispatch_crypto_inbound closes with QUIC_ERR_CRYPTO_BUFFER_EXCEEDED on DoS.
    let scid: u8[8] = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
    var srv = quic::new_server_connection(scid[..]);
    var dos_payload: u8[..64] = [];
    assert(quic::encode_crypto_frame(20000, "DOS_OOO_OVERFLOW", dos_payload));
    let pres = quic::process_payload(srv, dos_payload[..], quic::QuicHeaderType.Initial, 1000);
    assert(!pres.handled);
    assert(srv.state == quic::QuicConnState.Closing);
    assert(srv.close_code == rfc::QUIC_ERR_CRYPTO_BUFFER_EXCEEDED);
    print("QUIC_CRYPTO_OOO_DOS_CLOSED: OK");
}

fn send_initial_crypto_chunk(
    world:   net::DstWorld&,
    uid:     u16,
    q_cli:   quic::QuicConnection&,
    dcid:    const u8[:],
    scid:    const u8[:],
    next_pn: u64&,
    offset:  u64,
    chunk:   const u8[:],
) {
    var plain: u8[..1300] = [];
    assert(quic::encode_crypto_frame(offset, chunk, plain));
    assert(quic::encode_padding_frame(plain, (1200 - plain.len) as u64));
    var hdr = quic::QuicHeader {
        header_type:   quic::QuicHeaderType.Initial,
        version:       rfc::QUIC_VERSION_1,
        packet_number: next_pn,
        ..
    };
    assert(hdr.dcid.try_set(dcid));
    assert(hdr.scid.try_set(scid));
    var pkt: u8[..1400] = [];
    assert(quic::seal_packet(q_cli.tx_initial_space, hdr, 2, plain[..], pkt));
    assert(pkt.len >= 1200);
    assert(net::dst_udp_send(world, uid, net::DstDir.AToB, pkt[..]));
    next_pn = core::add_sat_u64(next_pn, 1);
}

// 4. Live QUIC connection CRYPTO reassembly under DstFaultProfile.LossyQuic
//    with deliberate reverse-order transmission + stochastic reordering/loss/duplication.
fn test_live_quic_crypto_lossy_dst() {
    var world = net::DstWorld { .. };
    net::dst_init(world, 0xA11CE5EED01, SIM_BASE_UNIX_NS);
    defer net::dst_shutdown(world);

    let ep_c, ok_c = net::dst_add_endpoint(world, 0x0A000001, 42000, 0);
    let ep_s, ok_s = net::dst_add_endpoint(world, 0x0A000002, 443, 0);
    assert(ok_c && ok_s);

    let cfg = net::dst_fault_profile(net::DstFaultProfile.LossyQuic);
    let uid, ok_u = net::dst_open_udp_link(world, ep_c, ep_s, cfg);
    assert(ok_u);

    let dcid: u8[8] = [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x08];
    let scid: u8[8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    var q_cli = quic::new_client_connection(dcid[..], scid[..]);
    var q_srv = quic::new_server_connection(dcid[..]);
    assert(quic::install_initial_keys(q_cli, dcid[..]));
    assert(quic::install_initial_keys(q_srv, dcid[..]));

    // 192-byte synthetic TLS handshake flight split into 4 chunks sent out-of-order [3, 2, 1, 0].
    var flight: u8[192] = [0; 192];
    for i in 192 {
        flight[i] = ((i * 7 + 13) & 0xFF) as u8;
    }

    var next_pn:   u64      = 1;
    var dgram_buf: u8[1500] = [0; 1500];
    var saw_ooo_staged = false;
    var rounds: i64 = 0;

    while rounds < 24 && q_srv.initial_crypto.consumed_offset < 192 {
        rounds += 1;
        // Transmit chunks in reverse order (3, 2, 1, 0) so OOO CRYPTO staging is exercised every round.
        for rev in 4 {
            let k = 3 - rev;
            let off = k * 48;
            send_initial_crypto_chunk(
                world, uid, q_cli, dcid[..], scid[..], next_pn, off as u64, flight[off..off + 48],
            );
        }
        let _ = net::dst_run_until(world, world.now_ns + 120 * NS_PER_MS);
        loop {
            let n, _, _, ok_r = net::dst_udp_recv(world, uid, net::DstDir.AToB, dgram_buf[..]);
            if !ok_r { break; }
            var ack_out = quic::AckFrame { .. };
            let _ = quic::process_datagram(q_srv, dgram_buf[..n], world.now_ns / 1000, ack_out);
            if q_srv.initial_crypto.ooo_ranges.len > 0 {
                saw_ooo_staged = true;
            }
            assert(q_srv.state != quic::QuicConnState.Closing);
            assert(q_srv.close_code == 0);
        }
    }

    assert(saw_ooo_staged);
    assert(q_srv.state != quic::QuicConnState.Closing && q_srv.close_code == 0);
    assert(q_srv.initial_crypto.consumed_offset == 192);
    assert(q_srv.initial_crypto.buf[..] == flight[..]);
    assert(q_srv.initial_crypto.ooo_ranges.len == 0);
    print("QUIC_CRYPTO_LOSSY_DST_LIVE: OK");
}

// 5. Full DST purity run capturing core::now, core::csprng_fill, core::csprng_u64,
//    tls_internal::random_bytes_32, and http::generate_multipart_boundary.
fn run_dst_purity_sample(seed: u64) -> DstPuritySample {
    var world = net::DstWorld { .. };
    net::dst_init(world, seed, SIM_BASE_UNIX_NS);
    defer net::dst_shutdown(world);

    var s = DstPuritySample { .. };
    s.t1 = core::now();
    assert(s.t1.wall_sec == 1700000000 && s.t1.nsec == 0);

    net::dst_jump_clock(world, 42 * NS_PER_SEC + 123456789);
    s.t2 = core::now();
    assert(s.t2.wall_sec == 1700000042 && s.t2.nsec == 123456789);

    assert(core::csprng_fill(s.csprng_bytes[..]));
    let u_a, ok_ua = core::csprng_u64();
    let u_b, ok_ub = core::csprng_u64();
    assert(ok_ua && ok_ub && u_a != u_b);
    s.csprng_u64_a = u_a;
    s.csprng_u64_b = u_b;

    assert(tls_internal::random_bytes_32_checked(s.tls_rand_a));
    assert(tls_internal::random_bytes_32_checked(s.tls_rand_b));
    assert(s.tls_rand_a[..] != s.tls_rand_b[..]);

    s.boundary_a = http::generate_multipart_boundary();
    s.boundary_b = http::generate_multipart_boundary();
    assert(s.boundary_a.len == 45 && s.boundary_b.len == 45);
    assert(s.boundary_a[..] != s.boundary_b[..]);
    return s;
}

fn test_dst_purity_and_os_resume() {
    let seed_a: u64 = 0xCAFEBABE12345678;
    let seed_b: u64 = 0xCAFEBABE12345679;

    // Run 1 and Run 2 in the SAME process with identical seed MUST be bit-for-bit identical.
    let run1 = run_dst_purity_sample(seed_a);
    let run2 = run_dst_purity_sample(seed_a);
    assert(samples_equal(run1, run2));

    // Distinct seed MUST produce distinct entropy outputs.
    let run3 = run_dst_purity_sample(seed_b);
    assert(run1.csprng_bytes[..] != run3.csprng_bytes[..]);
    assert(run1.csprng_u64_a != run3.csprng_u64_a);
    assert(run1.tls_rand_a[..] != run3.tls_rand_a[..]);
    assert(run1.boundary_a[..] != run3.boundary_a[..]);
    print("DST_PURITY_REPEATABLE: OK");

    // Verify clean restoration of live OS wall clock & OS CSPRNG after dst_shutdown().
    assert(!core::sim_clock_is_active());
    assert(!core::sim_rng_is_active());

    let live_now = core::now();
    assert(live_now.wall_sec > 1700000000);

    var live_a: u8[32] = [0; 32];
    var live_b: u8[32] = [0; 32];
    assert(core::csprng_fill(live_a[..]) && core::csprng_fill(live_b[..]));
    assert(live_a[..] != live_b[..]);
    assert(live_a[..] != run1.csprng_bytes[..]);

    let lu1, ok_l1 = core::csprng_u64();
    let lu2, ok_l2 = core::csprng_u64();
    assert(ok_l1 && ok_l2 && lu1 != lu2);

    var lt1: u8[32] = [0; 32];
    var lt2: u8[32] = [0; 32];
    assert(tls_internal::random_bytes_32_checked(lt1) && tls_internal::random_bytes_32_checked(lt2));
    assert(lt1[..] != lt2[..] && lt1[..] != run1.tls_rand_a[..]);

    let lb1 = http::generate_multipart_boundary();
    let lb2 = http::generate_multipart_boundary();
    assert(lb1.len == 45 && lb2.len == 45 && lb1[..] != lb2[..]);
    assert(lb1[..] != run1.boundary_a[..]);
    print("DST_OS_RESUME: OK");
}

// CHECK: QUIC_CRYPTO_OOO_THREE_WAY: OK
// CHECK: QUIC_CRYPTO_OOO_OVERLAP_WRAP: OK
// CHECK: QUIC_CRYPTO_OOO_DOS_CLOSED: OK
// CHECK: QUIC_CRYPTO_LOSSY_DST_LIVE: OK
// CHECK: DST_PURITY_REPEATABLE: OK
// CHECK: DST_OS_RESUME: OK
fn main() {
    test_quic_crypto_ooo_three_way_split();
    test_quic_crypto_ooo_overlaps_and_wraparound();
    test_quic_crypto_ooo_adversarial_dos();
    test_live_quic_crypto_lossy_dst();
    test_dst_purity_and_os_resume();
}
