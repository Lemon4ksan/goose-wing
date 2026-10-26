// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 SmartNIC & Hardware TLS Crypto Offload Driver.
// Offloads TCP stream state and TLS 1.2 / 1.3 AES-GCM record encryption/decryption
// directly onto SmartNIC ASICs (Mellanox ConnectX-6/7 Dx, NVIDIA BlueField-2/3 DPU, Intel Mount Evans).
namespace internal;

import std;
import net.driver.types;

// Native C bindings from shim/smartnic.c
extern fn wing_smartnic_probe() -> i32;
extern fn wing_smartnic_enable_ktls(fd: i64) -> i32;
extern fn wing_smartnic_set_hardware_tls_tx(
    fd: i64, version: u16, cipher_type: u16,
    key: const u8[:],
    iv: const u8[:],
    salt: const u8[:],
    rec_seq: const u8[:],
) -> i32;
extern fn wing_smartnic_set_hardware_tls_rx(
    fd: i64, version: u16, cipher_type: u16,
    key: const u8[:],
    iv: const u8[:],
    salt: const u8[:],
    rec_seq: const u8[:],
) -> i32;

fn native_smartnic_probe() -> i32 { return wing_smartnic_probe(); }
fn native_smartnic_enable_ktls(fd: i64) -> i32 { return wing_smartnic_enable_ktls(fd); }

enum SmartNicModel {
    Generic,
    MellanoxConnectX6Dx,
    MellanoxConnectX7Dx,
    NvidiaBlueField2,
    NvidiaBlueField3,
    IntelMountEvans,
}

fn smartnic_model_name(m: SmartNicModel) -> const u8[:] {
    return match m {
        Generic => "Generic SmartNIC / kTLS Host",
        MellanoxConnectX6Dx => "Mellanox ConnectX-6 Dx (100GbE / kTLS Inline)",
        MellanoxConnectX7Dx => "Mellanox ConnectX-7 Dx (200/400GbE / kTLS Inline)",
        NvidiaBlueField2 => "NVIDIA BlueField-2 DPU (Dual 100GbE / Full Offload)",
        NvidiaBlueField3 => "NVIDIA BlueField-3 DPU (400GbE / Full Offload)",
        IntelMountEvans => "Intel Mount Evans IPU (200GbE / Infrastructure)",
    };
}

enum SmartNicCipherSuite {
    AesGcm128,
    AesGcm256,
}

const TLS_CIPHER_AES_GCM_128_ID: u16 = 51;
const TLS_CIPHER_AES_GCM_256_ID: u16 = 52;
const TLS_1_3_WIRE_VERSION: u16 = 0x0304;

struct SmartNicConfig {
    model: SmartNicModel = SmartNicModel.Generic,
    enable_hardware_tls: bool = true,
    enable_tcp_chimney: bool = true,
    rx_coalesce_usecs: u32 = 10,
    tx_coalesce_usecs: u32 = 10,
}

struct SmartNicSession {
    fd: i64 = -1,
    ktls_active: bool = false,
    tx_offloaded: bool = false,
    rx_offloaded: bool = false,
    cipher: SmartNicCipherSuite = SmartNicCipherSuite.AesGcm128,
}

fn new_smartnic_session(fd: i64 = -1) -> SmartNicSession {
    return SmartNicSession {
        fd: fd,
        ktls_active: false,
        tx_offloaded: false,
        rx_offloaded: false,
        cipher: SmartNicCipherSuite.AesGcm128,
    };
}

// Configures hardware SmartNIC TLS crypto offload on a socket.
// Plaintext buffers sent via tcp_send / recv are automatically encrypted/decrypted
// on the NIC chip without CPU cycle consumption.
fn smartnic_attach_hardware_tls(
    fd: i64,
    cipher: SmartNicCipherSuite,
    key: const u8[:],
    iv: const u8[:],
    salt: const u8[:],
    seq: const u8[:],
) -> SmartNicSession, i32 {
    guard fd > 0 else { return new_smartnic_session(), -1; }

    let ktls_err = native_smartnic_enable_ktls(fd);
    if ktls_err != 0 {
        return new_smartnic_session(fd), ktls_err;
    }

    let cipher_id = match cipher {
        AesGcm128 => TLS_CIPHER_AES_GCM_128_ID,
        AesGcm256 => TLS_CIPHER_AES_GCM_256_ID,
    };

    var sess = SmartNicSession {
        fd: fd,
        ktls_active: true,
        tx_offloaded: false,
        rx_offloaded: false,
        cipher: cipher,
    };

    let tx_err = wing_smartnic_set_hardware_tls_tx(
        fd, TLS_1_3_WIRE_VERSION, cipher_id,
        key, iv, salt, seq,
    );
    if tx_err == 0 {
        sess.tx_offloaded = true;
    }

    let rx_err = wing_smartnic_set_hardware_tls_rx(
        fd, TLS_1_3_WIRE_VERSION, cipher_id,
        key, iv, salt, seq,
    );
    if rx_err == 0 {
        sess.rx_offloaded = true;
    }

    return sess, if (tx_err == 0 || rx_err == 0) { 0 } else { tx_err };
}
