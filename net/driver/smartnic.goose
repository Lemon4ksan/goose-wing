// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 SmartNIC & Hardware TLS Crypto Offload Driver.
// Offloads TCP stream state and TLS 1.2 / 1.3 AES-GCM record encryption/decryption
// directly onto SmartNIC ASICs (Mellanox ConnectX-6/7 Dx, NVIDIA BlueField-2/3 DPU, Intel Mount Evans).
namespace net_internal;

import std;
import net.driver.types;

// Native C bindings from shim/smartnic.c
extern fn native_smartnic_probe() -> i32 = "wing_smartnic_probe";
extern fn native_smartnic_probe_ktls() -> i32 = "wing_smartnic_probe_ktls";
extern fn native_smartnic_enable_ktls(fd: i64) -> i32 = "wing_smartnic_enable_ktls";
extern fn native_smartnic_shutdown(fd: i64, how: i32) -> i32 = "wing_tcp_shutdown";
extern fn native_smartnic_recv_record(fd: i64, dst: u8[:], out_rt: u8[:]) -> i32 = "wing_smartnic_recv_record";
extern fn native_smartnic_send_record(fd: i64, src: const u8[:], record_type: u8) -> i32 = "wing_smartnic_send_record";
extern fn native_smartnic_set_hardware_tls(
    fd:          i64,
    is_tx:       i32,
    version:     u16,
    cipher_type: u16,
    key:         const u8[:],
    iv:          const u8[:],
    salt:        const u8[:],
    rec_seq:     const u8[:],
) -> i32 = "wing_smartnic_set_hardware_tls";

enum SmartNicModel {
    Generic,
    LinuxKtls,
    MellanoxConnectX6Dx,
    MellanoxConnectX7Dx,
    NvidiaBlueField2,
    NvidiaBlueField3,
    IntelMountEvans,
}

fn smartnic_model_name(m: SmartNicModel) -> const u8[:] {
    return match m {
        Generic => "Generic SmartNIC / kTLS Host",
        LinuxKtls => "Linux Kernel TLS (SOL_TLS / TCP_ULP)",
        MellanoxConnectX6Dx => "Mellanox ConnectX-6 Dx (100GbE / kTLS Inline)",
        MellanoxConnectX7Dx => "Mellanox ConnectX-7 Dx (200/400GbE / kTLS Inline)",
        NvidiaBlueField2 => "NVIDIA BlueField-2 DPU (Dual 100GbE / Full Offload)",
        NvidiaBlueField3 => "NVIDIA BlueField-3 DPU (400GbE / Full Offload)",
        IntelMountEvans => "Intel Mount Evans IPU (200GbE / Infrastructure)",
    };
}

fn smartnic_probe_ktls() -> bool {
    return native_smartnic_probe_ktls() > 0;
}

fn smartnic_recv_record(fd: i64, dst: u8[:]) -> i32, u8 {
    guard fd > 0 && dst.len > 0 else { return -22, 0; }
    var rt_buf: u8[1] = [0];
    let n = native_smartnic_recv_record(fd, dst, rt_buf[..]);
    return n, rt_buf[0];
}

fn smartnic_send_record(fd: i64, src: const u8[:], record_type: u8) -> i32 {
    guard fd > 0 && src.len > 0 else { return -22; }
    return native_smartnic_send_record(fd, src, record_type);
}

enum SmartNicCipherSuite {
    AesGcm128,
    AesGcm256,
}

const TLS_CIPHER_AES_GCM_128_ID: u16 = 51;
const TLS_CIPHER_AES_GCM_256_ID: u16 = 52;
struct SmartNicConfig {
    model:               SmartNicModel = SmartNicModel.Generic,
    enable_hardware_tls: bool          = true,
    enable_tcp_chimney:  bool          = true,
    rx_coalesce_usecs:   u32           = 10,
    tx_coalesce_usecs:   u32           = 10,
}

struct SmartNicSession {
    fd:           i64                 = -1,
    ktls_active:  bool                = false,
    tx_offloaded: bool                = false,
    rx_offloaded: bool                = false,
    cipher:       SmartNicCipherSuite = SmartNicCipherSuite.AesGcm128,
}

fn new_smartnic_session(fd: i64 = -1) -> SmartNicSession {
    return SmartNicSession {
        fd:           fd,
        ktls_active:  false,
        tx_offloaded: false,
        rx_offloaded: false,
        cipher:       SmartNicCipherSuite.AesGcm128,
    };
}

inline fn has_valid_tls_offload_material(
    req_klen: i64,
    key:      const u8[:],
    iv:       const u8[:],
    salt:     const u8[:],
    seq:      const u8[:],
) -> bool {
    return key.len == req_klen && iv.len >= 4 && salt.len >= 4 && seq.len >= 8;
}

// Configures hardware SmartNIC TLS crypto offload on a socket.
// Plaintext buffers sent via tcp_send / recv are automatically encrypted/decrypted
// on the NIC chip without CPU cycle consumption.
fn smartnic_attach_hardware_tls(
    fd:      i64,
    cipher:  SmartNicCipherSuite,
    tx_key:  const u8[:],
    tx_iv:   const u8[:],
    tx_salt: const u8[:],
    tx_seq:  const u8[:],
    rx_key:  const u8[:] = "",
    rx_iv:   const u8[:] = "",
    rx_salt: const u8[:] = "",
    rx_seq:  const u8[:] = "",
) -> SmartNicSession, i32 {
    guard fd > 0 else { return new_smartnic_session(), -1; }

    let req_klen: i64 = match cipher {
        AesGcm128 => 16,
        AesGcm256 => 32,
    };
    guard has_valid_tls_offload_material(req_klen, tx_key, tx_iv, tx_salt, tx_seq) else {
        return new_smartnic_session(fd), -22;
    }
    let has_any_rx = rx_key.len > 0 || rx_iv.len > 0 || rx_salt.len > 0 || rx_seq.len > 0;
    if has_any_rx {
        guard has_valid_tls_offload_material(req_klen, rx_key, rx_iv, rx_salt, rx_seq) else {
            return new_smartnic_session(fd), -22;
        }
    }

    let ktls_err = native_smartnic_enable_ktls(fd);
    if ktls_err != 0 {
        return new_smartnic_session(fd), ktls_err;
    }

    let cipher_id = match cipher {
        AesGcm128 => TLS_CIPHER_AES_GCM_128_ID,
        AesGcm256 => TLS_CIPHER_AES_GCM_256_ID,
    };

    let tx_err = native_smartnic_set_hardware_tls(
        fd, 1, rfc::TLS_VERSION_1_3, cipher_id,
        tx_key, tx_iv, tx_salt, tx_seq,
    );
    guard tx_err == 0 else {
        let _ = native_smartnic_shutdown(fd, 2);
        return new_smartnic_session(fd), tx_err;
    }

    var rx_offloaded = false;
    if has_any_rx {
        let rx_err = native_smartnic_set_hardware_tls(
            fd, 0, rfc::TLS_VERSION_1_3, cipher_id,
            rx_key, rx_iv, rx_salt, rx_seq,
        );
        guard rx_err == 0 else {
            let _ = native_smartnic_shutdown(fd, 2);
            return new_smartnic_session(fd), rx_err;
        }
        rx_offloaded = true;
    }

    return SmartNicSession {
        fd:           fd,
        ktls_active:  true,
        tx_offloaded: true,
        rx_offloaded: rx_offloaded,
        cipher:       cipher,
    }, 0;
}
