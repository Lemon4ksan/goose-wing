// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Test suite for QUIC Transport RFC 9000 Section 19 Frame Codecs,
// Demuxer, and Section 3 Stream State Machine Invariants.
import std;
import core from "..";
import wing from "..";

fn test_quic_stream_frame_codec(t: core::T&) {
    // 1. STREAM frame: Base (stream_id=4, offset=0, no FIN, with length)
    var wire1: u8[..128] = [];
    let flags1 = wing::QuicStreamFlags { fin: false, with_len: true };
    let ok_enc1 = wing::encode_stream_frame(wire1, 4, 0, "hello quic", flags1);
    t.assert_true(ok_enc1, "encode basic stream frame");

    var r1 = core::new_slice_reader(wire1[..]);
    let frame1, ok_dec1 = wing::decode_quic_frame_reader(r1);
    t.assert_true(ok_dec1, "decode basic stream frame");
    t.assert_eq(frame1.stream_id, 4, "stream id matches");
    t.assert_eq(frame1.offset, 0, "offset is 0");
    t.assert_false(frame1.fin, "fin flag is false");
    t.assert_eq(frame1.payload, "hello quic", "payload matches");

    // 2. STREAM frame with Offset and FIN
    var wire2: u8[..128] = [];
    let flags2 = wing::QuicStreamFlags { fin: true, with_len: true };
    let ok_enc2 = wing::encode_stream_frame(wire2, 8, 1024, "world", flags2);
    t.assert_true(ok_enc2, "encode stream frame with off and fin");

    var r2 = core::new_slice_reader(wire2[..]);
    let frame2, ok_dec2 = wing::decode_quic_frame_reader(r2);
    t.assert_true(ok_dec2, "decode stream frame with off and fin");
    t.assert_eq(frame2.stream_id, 8, "stream id matches");
    t.assert_eq(frame2.offset, 1024, "offset matches");
    t.assert_true(frame2.fin, "fin flag is true");
    t.assert_eq(frame2.payload, "world", "payload matches");

    // 3. STREAM frame without length (consumes remainder of buffer)
    var wire3: u8[..128] = [];
    let flags3 = wing::QuicStreamFlags { fin: false, with_len: false };
    let ok_enc3 = wing::encode_stream_frame(wire3, 12, 2048, "rest-of-packet", flags3);
    t.assert_true(ok_enc3, "encode stream frame without length");

    var r3 = core::new_slice_reader(wire3[..]);
    let frame3, ok_dec3 = wing::decode_quic_frame_reader(r3);
    t.assert_true(ok_dec3, "decode stream frame without length");
    t.assert_eq(frame3.stream_id, 12, "stream id matches");
    t.assert_eq(frame3.offset, 2048, "offset matches");
    t.assert_eq(frame3.payload, "rest-of-packet", "payload matches");

    // 4. Zero-length payload STREAM with FIN
    var wire4: u8[..64] = [];
    let flags4 = wing::QuicStreamFlags { fin: true, with_len: true };
    let ok_enc4 = wing::encode_stream_frame(wire4, 16, 5000, "", flags4);
    t.assert_true(ok_enc4, "encode empty fin stream frame");

    var r4 = core::new_slice_reader(wire4[..]);
    let frame4, ok_dec4 = wing::decode_quic_frame_reader(r4);
    t.assert_true(ok_dec4, "decode empty fin stream frame");
    t.assert_eq(frame4.stream_id, 16, "stream id matches");
    t.assert_eq(frame4.offset, 5000, "offset matches");
    t.assert_true(frame4.fin, "fin is true");
    t.assert_eq(frame4.length, 0, "length is 0");

    // 5. RFC 9000 §19.8 bounds check: offset + length > 2^62 - 1 rejected
    var wire_bad: u8[..64] = [];
    let flags_bad = wing::QuicStreamFlags { fin: false, with_len: true };
    let ok_bad_enc = wing::encode_stream_frame(wire_bad, 4, 0x3FFFFFFFFFFFFFFF, "overflow", flags_bad);
    t.assert_false(ok_bad_enc, "offset + len exceeding 2^62-1 rejected during encoding");
}

fn test_quic_crypto_frame_codec(t: core::T&) {
    var wire: u8[..256] = [];
    let tls_data: const u8[6] = [0x01, 0x00, 0x00, 0x02, 0x03, 0x03];
    let ok_enc = wing::encode_crypto_frame(wire, 500, tls_data[..]);
    t.assert_true(ok_enc, "encode crypto frame");

    var r = core::new_slice_reader(wire[..]);
    let frame, ok_dec = wing::decode_quic_frame_reader(r);
    t.assert_true(ok_dec, "decode crypto frame");
    t.assert_eq(frame.raw_type, wing::QUIC_FRAME_CRYPTO, "frame type is crypto");
    t.assert_eq(frame.offset, 500, "crypto offset matches");
    t.assert_eq(frame.length, 6, "crypto length matches");
    t.assert_eq(frame.payload.len, 6, "crypto payload slice matches");
    t.assert_eq(frame.payload[0], 0x01, "first payload byte matches");

    // RFC 9000 §19.6 bounds: offset + len > 2^62 - 1
    var wire_bad: u8[..64] = [];
    let ok_bad = wing::encode_crypto_frame(wire_bad, 0x3FFFFFFFFFFFFFFF, tls_data[..]);
    t.assert_false(ok_bad, "crypto offset overflow rejected");
}

fn test_quic_control_frames_codec(t: core::T&) {
    // 1. RESET_STREAM
    var wire_rst: u8[..64] = [];
    let ok_rst_enc = wing::encode_reset_stream_frame(wire_rst, 4, 0x101, 4096);
    t.assert_true(ok_rst_enc, "encode reset stream frame");

    var r_rst = core::new_slice_reader(wire_rst[..]);
    let f_rst, ok_rst_dec = wing::decode_quic_frame_reader(r_rst);
    t.assert_true(ok_rst_dec, "decode reset stream frame");
    t.assert_eq(f_rst.stream_id, 4, "reset stream id matches");
    t.assert_eq(f_rst.error_code, 0x101, "reset error code matches");
    t.assert_eq(f_rst.final_size, 4096, "reset final size matches");

    // 2. STOP_SENDING
    var wire_ss: u8[..64] = [];
    let ok_ss_enc = wing::encode_stop_sending_frame(wire_ss, 8, 0x102);
    t.assert_true(ok_ss_enc, "encode stop sending frame");

    var r_ss = core::new_slice_reader(wire_ss[..]);
    let f_ss, ok_ss_dec = wing::decode_quic_frame_reader(r_ss);
    t.assert_true(ok_ss_dec, "decode stop sending frame");
    t.assert_eq(f_ss.stream_id, 8, "stop sending stream id matches");
    t.assert_eq(f_ss.error_code, 0x102, "stop sending error code matches");

    // 3. MAX_DATA
    var wire_md: u8[..64] = [];
    let ok_md_enc = wing::encode_max_data_frame(wire_md, 1048576);
    t.assert_true(ok_md_enc, "encode max data frame");

    var r_md = core::new_slice_reader(wire_md[..]);
    let f_md, ok_md_dec = wing::decode_quic_frame_reader(r_md);
    t.assert_true(ok_md_dec, "decode max data frame");
    t.assert_eq(f_md.max_data, 1048576, "max data limit matches");

    // 4. MAX_STREAM_DATA
    var wire_msd: u8[..64] = [];
    let ok_msd_enc = wing::encode_max_stream_data_frame(wire_msd, 12, 262144);
    t.assert_true(ok_msd_enc, "encode max stream data frame");

    var r_msd = core::new_slice_reader(wire_msd[..]);
    let f_msd, ok_msd_dec = wing::decode_quic_frame_reader(r_msd);
    t.assert_true(ok_msd_dec, "decode max stream data frame");
    t.assert_eq(f_msd.stream_id, 12, "max stream data stream id matches");
    t.assert_eq(f_msd.max_data, 262144, "max stream data limit matches");

    // 5. PING and PADDING
    var wire_ping: u8[..16] = [];
    t.assert_true(wing::encode_ping_frame(wire_ping), "encode ping");
    t.assert_eq(wire_ping.len, 1, "ping length 1");
    t.assert_eq(wire_ping[0], 0x01, "ping byte 0x01");

    var wire_pad: u8[..16] = [];
    t.assert_true(wing::encode_padding_frame(wire_pad, 5), "encode padding x5");
    t.assert_eq(wire_pad.len, 5, "padding length 5");
    for i in 5 {
        t.assert_eq(wire_pad[i], 0x00, "padding byte 0x00");
    }
}

fn test_quic_frame_demuxer(t: core::T&) {
    // Pack multiple distinct frames into a single datagram payload buffer
    var packet_wire: u8[..512] = [];

    // Frame 1: PADDING
    wing::encode_padding_frame(packet_wire, 1);
    // Frame 2: PING
    wing::encode_ping_frame(packet_wire);
    // Frame 3: MAX_DATA
    wing::encode_max_data_frame(packet_wire, 2000000);
    // Frame 4: STREAM (id=0, offset=0, fin=false)
    wing::encode_stream_frame(packet_wire, 0, 0, "demux-part-1", wing::QuicStreamFlags { fin: false, with_len: true });
    // Frame 5: STOP_SENDING (id=4, err=0x99)
    wing::encode_stop_sending_frame(packet_wire, 4, 0x99);
    // Frame 6: STREAM (id=0, offset=12, fin=true)
    wing::encode_stream_frame(packet_wire, 0, 12, "-part-2", wing::QuicStreamFlags { fin: true, with_len: true });

    // Iteratively demux packet frames using zero-alloc slice reader
    var r = core::new_slice_reader(packet_wire[..]);

    // 1. PADDING
    let f1, ok1 = wing::decode_quic_frame_reader(r);
    t.assert_true(ok1, "demux f1 padding ok");
    t.assert_eq(f1.raw_type, wing::QUIC_FRAME_PADDING, "f1 is padding");

    // 2. PING
    let f2, ok2 = wing::decode_quic_frame_reader(r);
    t.assert_true(ok2, "demux f2 ping ok");
    t.assert_eq(f2.raw_type, wing::QUIC_FRAME_PING, "f2 is ping");

    // 3. MAX_DATA
    let f3, ok3 = wing::decode_quic_frame_reader(r);
    t.assert_true(ok3, "demux f3 max_data ok");
    t.assert_eq(f3.raw_type, wing::QUIC_FRAME_MAX_DATA, "f3 is max_data");
    t.assert_eq(f3.max_data, 2000000, "f3 limit matches");

    // 4. STREAM part 1
    let f4, ok4 = wing::decode_quic_frame_reader(r);
    t.assert_true(ok4, "demux f4 stream ok");
    t.assert_eq(f4.stream_id, 0, "f4 stream_id is 0");
    t.assert_eq(f4.payload, "demux-part-1", "f4 payload matches");
    t.assert_false(f4.fin, "f4 fin is false");

    // 5. STOP_SENDING
    let f5, ok5 = wing::decode_quic_frame_reader(r);
    t.assert_true(ok5, "demux f5 stop_sending ok");
    t.assert_eq(f5.stream_id, 4, "f5 stream_id is 4");
    t.assert_eq(f5.error_code, 0x99, "f5 err code matches");

    // 6. STREAM part 2 with FIN
    let f6, ok6 = wing::decode_quic_frame_reader(r);
    t.assert_true(ok6, "demux f6 stream fin ok");
    t.assert_eq(f6.stream_id, 0, "f6 stream_id is 0");
    t.assert_eq(f6.offset, 12, "f6 offset is 12");
    t.assert_eq(f6.payload, "-part-2", "f6 payload matches");
    t.assert_true(f6.fin, "f6 fin is true");

    // Reached end of datagram
    t.assert_true(r.is_eof(), "slice reader reached end of packet");

    // Test offset-based decode_quic_frame API
    var off: u64 = 0;
    let frame_from_off, next_off, ok_off = wing::decode_quic_frame(packet_wire[..], off);
    t.assert_true(ok_off, "decode from offset 0 ok");
    t.assert_eq(frame_from_off.raw_type, wing::QUIC_FRAME_PADDING, "offset 0 is padding");
    t.assert_eq(next_off, 1, "next offset is 1");
}

fn test_quic_stream_state_machine_send(t: core::T&) {
    var s = wing::new_quic_stream(0, 10000); // Bidi client stream, max recv 10000
    s.send_max_data = 5000;

    t.assert_eq(s.send_state, wing::QuicSendState.Ready, "initial state is ready");

    // 1. Ready -> Send: send first data fragment
    let ok1, err1 = wing::quic_stream_on_send_data(s, 0, 1000, false);
    t.assert_true(ok1, "send 1000 bytes ok");
    t.assert_eq(err1, wing::QUIC_ERR_NO_ERROR, "no error");
    t.assert_eq(s.send_state, wing::QuicSendState.Send, "state is Send");
    t.assert_eq(s.bytes_sent, 1000, "bytes sent is 1000");

    // 2. Flow control violation: send beyond send_max_data (5000)
    let ok_fc, err_fc = wing::quic_stream_on_send_data(s, 4500, 1000, false); // 5500 > 5000
    t.assert_false(ok_fc, "sending beyond max_stream_data fails");
    t.assert_eq(err_fc, wing::QUIC_ERR_FLOW_CONTROL, "error is flow control");

    // 3. Send -> DataSent: send FIN
    let ok2, err2 = wing::quic_stream_on_send_data(s, 1000, 500, true);
    t.assert_true(ok2, "send fin fragment ok");
    t.assert_eq(s.send_state, wing::QuicSendState.DataSent, "state is DataSent");
    t.assert_true(s.has_send_final_size, "has final size");
    t.assert_eq(s.send_final_size, 1500, "final size is 1500");

    // 4. DataSent -> DataRecvd (peer acknowledged all data)
    let ack_ok = wing::quic_stream_on_send_ack(s, true);
    t.assert_true(ack_ok, "ack all data accepted");
    t.assert_eq(s.send_state, wing::QuicSendState.DataRecvd, "state is DataRecvd (terminal)");
    t.assert_true(wing::quic_stream_is_send_closed(s), "sender is closed");

    // 5. Reset sending path
    var s2 = wing::new_quic_stream(4, 10000);
    let ok_rst, _ = wing::quic_stream_on_send_reset(s2, 0x404, 300);
    t.assert_true(ok_rst, "send reset ok");
    t.assert_eq(s2.send_state, wing::QuicSendState.ResetSent, "state is ResetSent");
    t.assert_eq(s2.send_error_code, 0x404, "error code is 0x404");

    let ok_rst_ack = wing::quic_stream_on_send_ack(s2, false);
    t.assert_true(ok_rst_ack, "ack reset accepted");
    t.assert_eq(s2.send_state, wing::QuicSendState.ResetRecvd, "state is ResetRecvd (terminal)");
    t.assert_true(wing::quic_stream_is_send_closed(s2), "sender is closed");
}

fn test_quic_stream_state_machine_recv(t: core::T&) {
    var s = wing::new_quic_stream(0, 10000); // Recv limit = 10000
    t.assert_eq(s.recv_state, wing::QuicRecvState.Receive, "initial state is Receive");

    // 1. Receive data fragment [0, 500)
    let ok1, err1 = wing::quic_stream_on_recv_stream_frame(s, 0, 500, false);
    t.assert_true(ok1, "recv 500 bytes ok");
    t.assert_eq(err1, wing::QUIC_ERR_NO_ERROR, "no error");
    t.assert_eq(s.bytes_recv, 500, "bytes_recv is 500");

    // 2. Receive FIN fragment [500, 1000)
    let ok2, err2 = wing::quic_stream_on_recv_stream_frame(s, 500, 500, true);
    t.assert_true(ok2, "recv fin fragment ok");
    t.assert_true(s.has_recv_final_size, "final size known");
    t.assert_eq(s.recv_final_size, 1000, "final size is 1000");
    t.assert_eq(s.recv_state, wing::QuicRecvState.DataRecvd, "state is DataRecvd");

    // 3. Final size violation (RFC 9000 §4.5): frame exceeding declared final size
    let ok_bad_fs, err_bad_fs = wing::quic_stream_on_recv_stream_frame(s, 1000, 10, false);
    t.assert_false(ok_bad_fs, "data exceeding final size rejected");
    t.assert_eq(err_bad_fs, wing::QUIC_ERR_FINAL_SIZE, "error is FINAL_SIZE_ERROR");

    // 4. Application reads all data -> transitions to DataRead
    wing::quic_stream_on_app_read(s, 1000);
    t.assert_eq(s.recv_state, wing::QuicRecvState.DataRead, "state is DataRead (terminal)");
    t.assert_true(wing::quic_stream_is_recv_closed(s), "recv is closed");

    // 5. RFC 9000 §3.2: RESET_STREAM arriving after DataRecvd / DataRead is ignored
    let ok_rst_ign, err_rst_ign = wing::quic_stream_on_recv_reset(s, 0x123, 1000);
    t.assert_true(ok_rst_ign, "reset on DataRead ignored");
    t.assert_eq(err_rst_ign, wing::QUIC_ERR_NO_ERROR, "no error");
    t.assert_eq(s.recv_state, wing::QuicRecvState.DataRead, "state remains DataRead");

    // 6. Receiving STOP_SENDING on send-capable stream
    var s_bidi = wing::new_quic_stream(0, 10000);
    let ok_ss, _ = wing::quic_stream_on_recv_stop_sending(s_bidi, 0x55, wing::QuicRole.Server);
    t.assert_true(ok_ss, "stop sending accepted on bidi stream");
    t.assert_eq(s_bidi.send_state, wing::QuicSendState.ResetSent, "sender transitioned to ResetSent");

    // 7. RFC 9000 §19.5: Receiving STOP_SENDING on receive-only stream -> STREAM_STATE_ERROR
    // Stream ID 2 is ClientUni: Server can ONLY receive on stream 2, cannot send!
    var s_uni = wing::new_quic_stream(2, 10000);
    let ok_ss_bad, err_ss_bad = wing::quic_stream_on_recv_stop_sending(s_uni, 0x55, wing::QuicRole.Server);
    t.assert_false(ok_ss_bad, "stop sending on receive-only stream rejected");
    t.assert_eq(err_ss_bad, wing::QUIC_ERR_STREAM_STATE, "error is STREAM_STATE_ERROR");
}

fn test_quic_stream_table(t: core::T&) {
    var tbl = wing::new_quic_stream_table(wing::QuicRole.Client);

    // Open first local client bidi stream (ID 0)
    let id0, idx0, ok0 = wing::quic_table_open_local_stream(tbl, true);
    t.assert_true(ok0, "open client bidi stream 0 ok");
    t.assert_eq(id0, 0, "first client bidi stream id is 0");
    t.assert_eq(idx0, 0, "index is 0");

    // Open second local client bidi stream (ID 4)
    let id4, idx4, ok4 = wing::quic_table_open_local_stream(tbl, true);
    t.assert_true(ok4, "open client bidi stream 4 ok");
    t.assert_eq(id4, 4, "second client bidi stream id is 4");
    t.assert_eq(idx4, 1, "index is 1");

    // Open client unidirectional stream (ID 2)
    let id2, idx2, ok2 = wing::quic_table_open_local_stream(tbl, false);
    t.assert_true(ok2, "open client uni stream 2 ok");
    t.assert_eq(id2, 2, "first client uni stream id is 2");
    t.assert_eq(idx2, 2, "index is 2");

    // Lookup existing stream
    let found0 = wing::quic_table_find_stream(tbl, 0);
    t.assert_eq(found0, 0, "found stream 0 at index 0");
    let found4 = wing::quic_table_find_stream(tbl, 4);
    t.assert_eq(found4, 1, "found stream 4 at index 1");

    // Peer stream opening (Server bidi stream ID 1)
    let idx_peer, ok_peer = wing::quic_table_get_or_open_stream(tbl, 1);
    t.assert_true(ok_peer, "open peer stream id 1 ok");
    t.assert_eq(idx_peer, 3, "peer stream added at index 3");
    t.assert_eq(tbl.streams.len, 4, "table has 4 streams");
}

fn main() {
    var runner = core::new_runner("QUIC RFC 9000 Frames & Stream State Machine Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. RFC 9000 §19.8 STREAM Frame Codec", test_quic_stream_frame_codec);
    core::run_case(runner, "2. RFC 9000 §19.6 CRYPTO Frame Codec", test_quic_crypto_frame_codec);
    core::run_case(runner, "3. RFC 9000 §19 Control Frames Codec", test_quic_control_frames_codec);
    core::run_case(runner, "4. RFC 9000 Zero-Alloc Frame Demuxer", test_quic_frame_demuxer);
    core::run_case(runner, "5. RFC 9000 §3.1 Sending Stream State Machine", test_quic_stream_state_machine_send);
    core::run_case(runner, "6. RFC 9000 §3.2 & §4.5 Receiving Stream State Machine", test_quic_stream_state_machine_recv);
    core::run_case(runner, "7. RFC 9000 Zero-Alloc Stream Table", test_quic_stream_table);
    let ok = core::finish(runner);
    assert(ok);
}
