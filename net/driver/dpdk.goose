// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 DPDK (Data Plane Development Kit) Poll Mode Driver (PMD) Interface.
// Maps NIC PCIe BAR registers directly into userspace for line-rate 100G/200G packet processing.
namespace internal;

import std;
import net.driver.types;

// Native C bindings from shim/dpdk.c
extern fn native_dpdk_eal_init() -> i32 = "wing_dpdk_eal_init";
extern fn native_dpdk_pktmbuf_pool_create(
    n_elements:   u32,
    element_size: u32,
    socket_id:    i32,
) -> u64 = "wing_dpdk_pktmbuf_pool_create";
extern fn native_dpdk_eth_dev_configure(
    port_id:      u16,
    rx_queues:    u16,
    tx_queues:    u16,
    rx_ring_size: u16,
    tx_ring_size: u16,
    promiscuous:  i32,
) -> i32 = "wing_dpdk_eth_dev_configure";
extern fn native_dpdk_eth_dev_start(port_id: u16) -> i32 = "wing_dpdk_eth_dev_start";
extern fn native_dpdk_eth_dev_stop(port_id: u16) = "wing_dpdk_eth_dev_stop";
extern fn native_dpdk_rx_burst(
    port_id:  u16,
    queue_id: u16,
    pkts_out: u64&,
    nb_pkts:  u16,
) -> u16 = "wing_dpdk_rx_burst";
extern fn native_dpdk_tx_burst(
    port_id:  u16,
    queue_id: u16,
    pkts_in:  const u64&,
    nb_pkts:  u16,
) -> u16 = "wing_dpdk_tx_burst";

struct DpdkPortConfig {
    port_id:      u16  = 0,
    rx_queues:    u16  = 1,
    tx_queues:    u16  = 1,
    rx_ring_size: u16  = 1024,
    tx_ring_size: u16  = 1024,
    promiscuous:  bool = true,
}

struct DpdkMempool {
    pool_handle:  u64  = 0,
    n_elements:   u32  = 8192,
    element_size: u32  = 2048,
    socket_id:    i32  = 0,
    is_created:   bool = false,
}

struct DpdkDevice {
    port_id:        u16  = 0,
    is_initialized: bool = false,
    is_started:     bool = false,
    rx_burst_size:  u32  = 32,
    tx_burst_size:  u32  = 32,
}

fn new_dpdk_device(port_id: u16 = 0) -> DpdkDevice {
    return DpdkDevice {
        port_id:        port_id,
        is_initialized: false,
        is_started:     false,
        rx_burst_size:  32,
        tx_burst_size:  32,
    };
}

fn dpdk_create_mempool(n_elements: u32 = 8192, element_size: u32 = 2048) -> DpdkMempool {
    let handle = native_dpdk_pktmbuf_pool_create(n_elements, element_size, 0);
    return DpdkMempool {
        pool_handle:  handle,
        n_elements:   n_elements,
        element_size: element_size,
        socket_id:    0,
        is_created:   handle != 0,
    };
}

fn dpdk_init_port(dev: DpdkDevice&, cfg: const DpdkPortConfig&) -> i32 {
    let eal_rc = native_dpdk_eal_init();
    guard eal_rc == 0 else { return eal_rc; }
    let prom_flag: i32 = if cfg.promiscuous { 1 } else { 0 };
    let rc = native_dpdk_eth_dev_configure(
        cfg.port_id,
        cfg.rx_queues,
        cfg.tx_queues,
        cfg.rx_ring_size,
        cfg.tx_ring_size,
        prom_flag,
    );
    guard rc == 0 else { return rc; }
    dev.port_id = cfg.port_id;
    dev.is_initialized = true;
    return 0;
}

fn dpdk_start_port(dev: DpdkDevice&) -> i32 {
    guard dev.is_initialized else { return -1; }
    let rc = native_dpdk_eth_dev_start(dev.port_id);
    guard rc == 0 else { return rc; }
    dev.is_started = true;
    return 0;
}

fn dpdk_stop_port(dev: DpdkDevice&) {
    if dev.is_initialized {
        native_dpdk_eth_dev_stop(dev.port_id);
    }
    dev.is_started = false;
    dev.is_initialized = false;
}

fn dpdk_tx_burst(dev: const DpdkDevice&, queue_id: u16, mbufs: const u64[:]) -> u16 {
    guard dev.is_started && mbufs.len > 0 else { return 0; }
    let nb = min(mbufs.len, 64) as u16;
    return native_dpdk_tx_burst(dev.port_id, queue_id, mbufs[0], nb);
}

fn dpdk_rx_burst(dev: const DpdkDevice&, queue_id: u16, out_mbufs: u64[..32]&, max_pkts: u16 = 32) -> u16 {
    out_mbufs.clear();
    guard dev.is_started && max_pkts > 0 else { return 0; }
    let limit = min(max_pkts as i64, 32) as u16;
    var tmp: u64[32] = [0; 32];
    let n = native_dpdk_rx_burst(dev.port_id, queue_id, tmp[0], limit);
    let safe_n = min(n as i64, 32);
    for i in safe_n {
        let _ = out_mbufs.try_push(tmp[i]);
    }
    return safe_n as u16;
}
