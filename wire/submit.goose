// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Vulkan-style transport queue batch submission, TLS 1.3 record protection, and wire poll execution.
namespace wire;

import std;
import core from "..";
import tls.record;
import .result;
import .types;
import .cmd;
import .sync;

// Optional TLS 1.3 traffic key and sequence state attached to a WireQueue (RFC 8446 Section 5.2).
struct WireTlsState {
    enabled: bool   = false,
    tx_key:  u8[16] = [0; 16],
    tx_iv:   u8[12] = [0; 12],
    tx_seq:  u64    = 0,
    rx_key:  u8[16] = [0; 16],
    rx_iv:   u8[12] = [0; 12],
    rx_seq:  u64    = 0,
}

// Physical transport queue wrapping L4 socket descriptor, TLS 1.3 state, and batch tracking.
struct WireQueue {
    fd:             i64              = -1,
    driver:         WireDriverKind   = WireDriverKind.Standard,
    config:         WireDeviceConfig = WireDeviceConfig { .. },
    tls:            WireTlsState     = WireTlsState { .. },
    bytes_sent:     u64              = 0,
    bytes_received: u64              = 0,
    is_connected:   bool             = false,
}

// Obtains a physical transport queue from the logical device (VkGetDeviceQueue).
fn get_device_queue(
    device:             const WireDevice&,
    queue_family_index: u32,
    queue_index:        u32,
) -> WireQueue {
    return WireQueue {
        fd:             -1,
        driver:         device.physical_device.properties.driver_kind,
        config:         device.config,
        tls:            WireTlsState { .. },
        bytes_sent:     0,
        bytes_received: 0,
        is_connected:   false,
    };
}

// Instantiates a new wire queue configured with target device parameters.
fn new_wire_queue(cfg: const WireDeviceConfig&) -> WireQueue {
    return WireQueue {
        fd:             -1,
        driver:         cfg.driver,
        config:         cfg,
        tls:            WireTlsState { .. },
        bytes_sent:     0,
        bytes_received: 0,
        is_connected:   false,
    };
}

// Configures TLS 1.3 traffic keys and IVs on `q` for record-layer sealing and opening (RFC 8446 Section 5.2).
fn enable_wire_queue_tls(
    q:      WireQueue&,
    tx_key: const u8[16]&,
    tx_iv:  const u8[12]&,
    rx_key: const u8[16]&,
    rx_iv:  const u8[12]&,
) {
    core::ct_copy_bytes(q.tls.tx_key[..], tx_key[..]);
    core::ct_copy_bytes(q.tls.tx_iv[..], tx_iv[..]);
    q.tls.tx_seq = 0;
    core::ct_copy_bytes(q.tls.rx_key[..], rx_key[..]);
    core::ct_copy_bytes(q.tls.rx_iv[..], rx_iv[..]);
    q.tls.rx_seq = 0;
    q.tls.enabled = true;
}

// Seals a wire frame slice into a TLS 1.3 TLSCiphertext record and advances `q.tls.tx_seq` (RFC 8446 Section 5.2).
fn seal_queue_frame_into(q: WireQueue&, plain_in: const u8[:], cipher_out: u8[:]) -> i64, bool {
    guard q.tls.enabled else { return 0, false; }
    let sealed_len, _, ok_seal = wing::tls_record_seal_aes128_gcm_into(
        q.tls.tx_key,
        q.tls.tx_iv,
        q.tls.tx_seq,
        rfc::TLS_CONTENT_APPLICATION_DATA,
        plain_in,
        cipher_out,
    );
    guard ok_seal else { return 0, false; }
    guard wing::increment_record_seq_num(q.tls.tx_seq) else { return 0, false; }
    return sealed_len, true;
}

// Establishes physical transport connection and applies low-level socket options.
fn connect_wire_queue(
    q:          WireQueue&,
    host:       const u8[:],
    port:       u16,
    timeout_ms: u32 = 5000,
) -> bool {
    let sock = wing::native_tcp_connect(host, port, timeout_ms);
    guard sock >= 0 else { return false; }

    q.fd = sock;
    q.is_connected = true;

    if q.config.tcp_nodelay {
        wing::native_tcp_set_nodelay(q.fd, 1);
    }
    return true;
}

// Full-drain TCP transmission loop ensuring complete delivery of frame octets.
fn drain_send_slice(fd: i64, data: const u8[:]) -> i64, bool {
    var total_sent: i64 = 0;
    while total_sent < data.len {
        let chunk = data[total_sent..];
        let n = wing::native_tcp_send(fd, chunk);
        guard n > 0 else {
            return total_sent, false;
        }
        total_sent += n;
    }
    return total_sent, true;
}

// Dispatches wire bytes to the appropriate transport driver, sealing into TLS 1.3 records when enabled.
fn dispatch_queue_send(q: WireQueue&, data: const u8[:]) -> i64, bool {
    if q.tls.enabled {
        var tls_buf: u8[16640] = [0; 16640];
        let sealed_len, ok_seal = seal_queue_frame_into(q, data, tls_buf[..]);
        guard ok_seal else { return 0, false; }
        if q.driver == WireDriverKind.Mock {
            return sealed_len, true;
        }
        return drain_send_slice(q.fd, tls_buf[..sealed_len]);
    }
    if q.driver == WireDriverKind.Mock {
        return data.len, true;
    }
    return drain_send_slice(q.fd, data);
}

// Submits a recorded command buffer to the physical transport queue (RFC 9113).
fn submit(q: WireQueue&, cmd: const WireCommandBuffer&) -> i64, bool {
    guard q.is_connected else { return 0, false; }
    guard !cmd.has_error && cmd.state != WireCommandBufferState.RecordingHeaders else { return 0, false; }
    let data = cmd.buf[..];
    guard data.len > 0 else { return 0, true; }

    let sent, ok = dispatch_queue_send(q, data);
    guard ok else { return 0, false; }

    q.bytes_sent = q.bytes_sent + (sent as u64);
    return sent, true;
}

// Submits a raw byte slice directly to the queue without command buffer recording.
fn submit_slice(q: WireQueue&, data: const u8[:]) -> i64, bool {
    guard q.is_connected else { return 0, false; }
    guard data.len > 0 else { return 0, true; }

    let sent, ok = dispatch_queue_send(q, data);
    guard ok else { return 0, false; }

    q.bytes_sent = q.bytes_sent + (sent as u64);
    return sent, true;
}

inline fn submit_single_batch_cmd(q: WireQueue&, cmd: const WireCommandBuffer&) -> i64, bool {
    guard !cmd.has_error && cmd.state != WireCommandBufferState.RecordingHeaders else { return 0, false; }
    let data = cmd.buf[..];
    guard data.len > 0 else { return 0, true; }
    return dispatch_queue_send(q, data);
}

inline fn signal_submit_fence(fence: WireFence&) {
    guard fence.is_valid else { return; }
    fence.status = WireFenceStatus.Signaled;
    fence.signaled_val = 1;
}

// Submits a batch of command buffers atomically to the queue (VkQueueSubmit2).
fn queue_submit_batch(
    q:        WireQueue&,
    cmd_bufs: const WireCommandBuffer[:],
    info:     const WireSubmitInfo&,
    fence:    WireFence&,
) -> i64, WireResult {
    guard q.is_connected else {
        return 0, WireResult.ErrorInitializationFailed;
    }
    var total_batch_bytes: i64 = 0;
    for i in 0..cmd_bufs.len {
        let sent, ok = submit_single_batch_cmd(q, cmd_bufs[i]);
        guard ok else {
            return total_batch_bytes, WireResult.ErrorCommandBufferLocked;
        }
        total_batch_bytes += sent;
        q.bytes_sent = q.bytes_sent + (sent as u64);
    }
    signal_submit_fence(fence);
    return total_batch_bytes, WireResult.Success;
}

// Polls transport queue for incoming wire octets into caller-owned buffer.
fn poll_recv(q: WireQueue&, out: u8[:], timeout_ms: u32 = 0) -> i64, bool {
    guard q.is_connected else { return 0, false; }
    guard out.len > 0 else { return 0, true; }

    let recvd = wing::native_tcp_recv(q.fd, out, timeout_ms);
    guard recvd >= 0 else { return 0, false; }

    q.bytes_received = q.bytes_received + (recvd as u64);
    return recvd, true;
}

// Decrypts and authenticates an incoming TLS 1.3 record on `q` into `plain_out` (RFC 8446 Section 5.2).
//
// Example:
//   cipher_in = <26-byte sealed TLS 1.3 record>, plain_out = [0; 64]
//   returns: plain_len = 4, inner_type = 0x17, ok = true
fn poll_recv_tls(q: WireQueue&, cipher_in: const u8[:], plain_out: u8[:]) -> i64, u8, bool {
    guard q.tls.enabled && cipher_in.len >= rfc::TLS_RECORD_HEADER_LEN else {
        return 0, 0, false;
    }
    let _, _, rec_len, _, ok_hdr = wing::parse_tls_record_header(cipher_in[..5]);
    let rem = cipher_in[5..];
    guard ok_hdr && rem.len >= rec_len else {
        return 0, 0, false;
    }
    let body_slice = rem[..rec_len];
    let plain_len, inner_type, _, ok_dec = wing::tls_record_decrypt_aes128_gcm_into(
        q.tls.rx_key,
        q.tls.rx_iv,
        q.tls.rx_seq,
        cipher_in[..5],
        body_slice,
        plain_out,
    );
    guard ok_dec else { return 0, 0, false; }
    guard wing::increment_record_seq_num(q.tls.rx_seq) else { return 0, 0, false; }
    return plain_len, inner_type, true;
}

// Shuts down transport descriptor and resets queue state (RFC 9113).
fn close_wire_queue(q: WireQueue&) {
    if q.fd >= 0 {
        wing::native_tcp_close(q.fd);
    }
    q.fd = -1;
    q.is_connected = false;
}
