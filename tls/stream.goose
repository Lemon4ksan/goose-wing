// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Non-blocking socket <-> sans-IO TlsEndpoint reactor stream pump.
// Drives live non-blocking TCP descriptors and virtual DST pipes uniformly across
// PureGoose, SystemOpenSsl (with client/server mTLS), SystemSchannel, and SecureTransport.
namespace tls;

import std;
import core;
import net.tcp;
import net.transport;
import .backend;

struct TlsStream {
    fd:            i64         = -1,
    ep:            TlsEndpoint = TlsEndpoint { .. },
    tx_wire:       u8[..16640] = [],
    tx_wire_pos:   i64         = 0,
    rx_wire:       u8[..16640] = [],
    rx_wire_pos:   i64         = 0,
    rx_eof:        bool        = false,
    shutdown_sent: bool        = false,
}

// Opens a non-blocking TLS stream bound to an already-created socket or virtual pipe `fd`.
// The caller retains ownership of `fd` and closes it after `tls_stream_close`.
fn tls_stream_open(fd: i64, cfg: const TlsBackendConfig&) -> TlsStream, TlsBackendStatus {
    guard fd > 0 else { return TlsStream { .. }, TlsBackendStatus.Error; }
    let ep, st = tls_endpoint_open(cfg);
    guard st == TlsBackendStatus.Ok else { return TlsStream { .. }, st; }
    return TlsStream { fd: fd, ep: ep, .. }, TlsBackendStatus.Ok;
}

// Flushes staged `tx_wire` remainder to `s.fd`.
fn tls_stream_flush_staged_tx(s: TlsStream&) -> i64, TlsBackendStatus {
    let pos = s.tx_wire_pos;
    let total = s.tx_wire.len;
    guard pos >= 0 && pos < total && total <= s.tx_wire.cap else {
        s.tx_wire.clear();
        s.tx_wire_pos = 0;
        return 0, TlsBackendStatus.Ok;
    }
    let sent = net::fd_send(s.fd, s.tx_wire[pos..total]);
    if sent == -2 {
        return 0, TlsBackendStatus.WantWrite;
    }
    guard sent > 0 else { return 0, TlsBackendStatus.Error; }
    let next_pos = core::add_sat_i64(pos, sent);
    if next_pos >= total {
        s.tx_wire.clear();
        s.tx_wire_pos = 0;
    } else {
        s.tx_wire_pos = next_pos;
        return sent, TlsBackendStatus.WantWrite;
    }
    return sent, TlsBackendStatus.Ok;
}

// Drains one ciphertext chunk from `s.ep` and sends it on `s.fd`, staging any unsent tail in `s.tx_wire`.
fn tls_stream_send_one_chunk(s: TlsStream&, chunk: u8[:]) -> i64, bool, TlsBackendStatus {
    guard tls_endpoint_pending_wire(s.ep) > 0 else { return 0, false, TlsBackendStatus.Ok; }
    let drained, dst = tls_endpoint_drain_wire(s.ep, chunk);
    guard dst == TlsBackendStatus.Ok else { return 0, false, dst; }
    guard drained > 0 && drained <= chunk.len else { return 0, false, TlsBackendStatus.Ok; }

    let sent = net::fd_send(s.fd, chunk[..drained]);
    if sent == -2 {
        let _ = s.tx_wire.try_set(chunk[..drained]);
        s.tx_wire_pos = 0;
        return 0, false, TlsBackendStatus.WantWrite;
    }
    guard sent > 0 else { return 0, false, TlsBackendStatus.Error; }
    if sent < drained && sent <= chunk.len {
        let _ = s.tx_wire.try_set(chunk[sent..drained]);
        s.tx_wire_pos = 0;
        return sent, false, TlsBackendStatus.WantWrite;
    }
    return sent, true, TlsBackendStatus.Ok;
}

// Drains pending outbound ciphertext from `s.ep` to `s.fd` without blocking.
// Preserves strict FIFO order across partial socket writes and `WouldBlock` (`WantWrite`).
fn tls_stream_flush_wire(s: TlsStream&) -> i64, TlsBackendStatus {
    guard s.fd > 0 && !s.ep.closed else { return 0, TlsBackendStatus.Closed; }
    var total_sent: i64 = 0;

    if s.tx_wire_pos < s.tx_wire.len {
        let n0, st0 = tls_stream_flush_staged_tx(s);
        total_sent = core::add_sat_i64(total_sent, n0);
        guard st0 == TlsBackendStatus.Ok else { return total_sent, st0; }
    }

    guard tls_endpoint_pending_wire(s.ep) > 0 else { return total_sent, TlsBackendStatus.Ok; }
    var chunk: u8[16640] = [0; 16640];
    for _ in 16 {
        let sent, more, st = tls_stream_send_one_chunk(s, chunk[..]);
        total_sent = core::add_sat_i64(total_sent, sent);
        if !more { return total_sent, st; }
    }
    return total_sent, TlsBackendStatus.Ok;
}

// Feeds staged `rx_wire` remainder into `s.ep` before reading more bytes from `s.fd`.
fn tls_stream_feed_staged_rx(s: TlsStream&) -> i64, TlsBackendStatus {
    let pos = s.rx_wire_pos;
    let total = s.rx_wire.len;
    guard pos >= 0 && pos < total && total <= s.rx_wire.cap else {
        s.rx_wire.clear();
        s.rx_wire_pos = 0;
        return 0, TlsBackendStatus.Ok;
    }
    let fed, fst = tls_endpoint_feed_wire(s.ep, s.rx_wire[pos..total]);
    if fed > 0 {
        let next_pos = core::add_sat_i64(pos, fed);
        if next_pos >= total {
            s.rx_wire.clear();
            s.rx_wire_pos = 0;
        } else {
            s.rx_wire_pos = next_pos;
        }
    }
    return fed, fst;
}

// Non-blockingly reads ciphertext from `s.fd` and feeds it into `s.ep` without dropping bytes.
fn tls_stream_pump_rx(s: TlsStream&) -> i64, TlsBackendStatus {
    guard s.fd > 0 && !s.ep.closed else { return 0, TlsBackendStatus.Closed; }
    if s.rx_wire_pos < s.rx_wire.len {
        let fed0, fst0 = tls_stream_feed_staged_rx(s);
        if s.rx_wire_pos < s.rx_wire.len {
            return fed0, fst0;
        }
        if fed0 > 0 {
            return fed0, TlsBackendStatus.Ok;
        }
    }
    guard !s.rx_eof else { return 0, TlsBackendStatus.Error; }

    var rx_buf: u8[16640] = [0; 16640];
    let recvd = net::fd_recv(s.fd, rx_buf[..], 0);
    if recvd == -2 { return 0, TlsBackendStatus.WantRead; }
    if recvd == 0 {
        s.rx_eof = true;
        return 0, TlsBackendStatus.Error;
    }
    guard recvd > 0 && recvd <= rx_buf.len else { return 0, TlsBackendStatus.Error; }

    let fed, fst = tls_endpoint_feed_wire(s.ep, rx_buf[..recvd]);
    if fed < recvd && fed >= 0 && fed <= rx_buf.len {
        let _ = s.rx_wire.try_set(rx_buf[fed..recvd]);
        s.rx_wire_pos = 0;
    }
    return fed, fst;
}

// Executes one non-blocking handshake turn: flush flight, advance state machine, pump peer bytes.
fn tls_stream_handshake_turn(s: TlsStream&) -> bool, TlsBackendStatus {
    let _, fst0 = tls_stream_flush_wire(s);
    guard fst0 == TlsBackendStatus.Ok else { return false, fst0; }
    if tls_endpoint_is_established(s.ep) {
        return false, TlsBackendStatus.Ok;
    }

    let hst = tls_endpoint_step_handshake(s.ep);
    let _, fst1 = tls_stream_flush_wire(s);
    guard fst1 == TlsBackendStatus.Ok || fst1 == TlsBackendStatus.WantWrite else {
        return false, fst1;
    }
    if hst == TlsBackendStatus.Ok {
        return false, fst1;
    }
    guard hst == TlsBackendStatus.WantRead else { return false, hst; }

    let fed, pst = tls_stream_pump_rx(s);
    if fed > 0 { return true, TlsBackendStatus.Ok; }
    if pst == TlsBackendStatus.Closed || (pst == TlsBackendStatus.Error && s.rx_eof) {
        return false, TlsBackendStatus.HandshakeError;
    }
    return false, if fst1 == TlsBackendStatus.WantWrite { TlsBackendStatus.WantWrite } else { pst };
}

// Drives the TLS handshake non-blockingly over `s.fd`, flushing flights and pumping peer bytes.
fn tls_stream_step_handshake(s: TlsStream&) -> TlsBackendStatus {
    guard s.fd > 0 && !s.ep.closed else { return TlsBackendStatus.Closed; }
    for _ in 8 {
        let more, st = tls_stream_handshake_turn(s);
        if !more { return st; }
    }
    return TlsBackendStatus.WantRead;
}

// Encrypts `plaintext` and flushes ciphertext to `s.fd` without blocking.
// Returns `(plaintext_bytes_accepted, status)`. When `status == WantWrite` with `n > 0`,
// the bytes are already queued in TLS/wire buffers and the caller should arm `EPOLL_WRITE`.
fn tls_stream_write(s: TlsStream&, plaintext: const u8[:]) -> i64, TlsBackendStatus {
    guard s.fd > 0 && !s.ep.closed else { return 0, TlsBackendStatus.Closed; }
    guard tls_endpoint_is_established(s.ep) else { return 0, TlsBackendStatus.HandshakeError; }

    let _, fst0 = tls_stream_flush_wire(s);
    guard fst0 == TlsBackendStatus.Ok else { return 0, fst0; }
    guard plaintext.len > 0 else { return 0, TlsBackendStatus.Ok; }

    let written, wst = tls_endpoint_write_app(s.ep, plaintext);
    guard written > 0 else { return 0, wst; }

    let _, fst1 = tls_stream_flush_wire(s);
    return written, fst1;
}

// Non-blockingly reads decrypted application bytes into `dst`, pumping `s.fd` as needed.
// Returns `WantRead` immediately when no complete TLS record is available.
fn tls_stream_read(s: TlsStream&, dst: u8[:]) -> i64, TlsBackendStatus {
    guard s.fd > 0 && !s.ep.closed else { return 0, TlsBackendStatus.Closed; }
    guard tls_endpoint_is_established(s.ep) else { return 0, TlsBackendStatus.HandshakeError; }
    guard dst.len > 0 else { return 0, TlsBackendStatus.Ok; }

    for _ in 4 {
        let n, rst = tls_endpoint_read_app(s.ep, dst);
        if n > 0 || rst != TlsBackendStatus.WantRead {
            return n, rst;
        }
        let fed, pst = tls_stream_pump_rx(s);
        if fed > 0 { continue; }
        if pst == TlsBackendStatus.Closed { return 0, TlsBackendStatus.Error; }
        return 0, pst;
    }
    return 0, TlsBackendStatus.WantRead;
}

// Computes exact reactor interest bitmask (`EPOLL_READ`, plus `EPOLL_WRITE` when outbound wire data is queued).
fn tls_stream_poll_events(s: const TlsStream&) -> u32 {
    var mask: u32 = net::EPOLL_READ;
    if s.tx_wire_pos < s.tx_wire.len || tls_endpoint_pending_wire(s.ep) > 0 {
        mask |= net::EPOLL_WRITE;
    }
    return mask;
}

// Initiates a graceful RFC 8446 CloseNotify alert and flushes it non-blockingly.
fn tls_stream_shutdown(s: TlsStream&) -> TlsBackendStatus {
    guard s.fd > 0 && !s.ep.closed else { return TlsBackendStatus.Closed; }
    if !s.shutdown_sent && tls_endpoint_is_established(s.ep) {
        let st = tls_endpoint_shutdown(s.ep);
        guard st == TlsBackendStatus.Ok else { return st; }
        s.shutdown_sent = true;
    }
    let _, fst = tls_stream_flush_wire(s);
    return fst;
}

// Idempotently sends best-effort CloseNotify, wipes buffers, and closes the underlying TLS endpoint.
// Does not close `s.fd`; the caller owns the socket descriptor lifecycle.
fn tls_stream_close(s: TlsStream&) {
    if !s.ep.closed && s.fd > 0 && tls_endpoint_is_established(s.ep) {
        let _ = tls_stream_shutdown(s);
    }
    tls_endpoint_close(s.ep);
    core::secure_zeroize_slice(s.tx_wire[..]);
    core::secure_zeroize_slice(s.rx_wire[..]);
    s.tx_wire.clear();
    s.rx_wire.clear();
    s.tx_wire_pos = 0;
    s.rx_wire_pos = 0;
    s.fd = -1;
}
