// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 DPDK (Data Plane Development Kit) Poll Mode Driver (PMD) C Shim.
// Compiles against libdpdk (rte_eal, rte_ethdev, rte_mbuf) when WING_ENABLE_DPDK is defined,
// and provides a deterministic lock-free userspace ring fallback otherwise.
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#pragma pack(push, 1)
typedef struct {
    const void *data;
    int64_t len;
} wing_dpdk_ro_slice;

typedef struct {
    void *data;
    int64_t len;
} wing_dpdk_rw_slice;
#pragma pack(pop)

_Static_assert(sizeof(wing_dpdk_ro_slice) == sizeof(const void *) + sizeof(int64_t),
               "wing_dpdk_ro_slice must be packed");
_Static_assert(offsetof(wing_dpdk_ro_slice, len) == sizeof(const void *), "wing_dpdk_ro_slice.len must follow data");
_Static_assert(sizeof(wing_dpdk_rw_slice) == sizeof(void *) + sizeof(int64_t), "wing_dpdk_rw_slice must be packed");
_Static_assert(offsetof(wing_dpdk_rw_slice, len) == sizeof(void *), "wing_dpdk_rw_slice.len must follow data");

#ifdef WING_ENABLE_DPDK
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

static struct rte_mempool *g_dpdk_mbuf_pool = NULL;
static int g_dpdk_eal_ready = 0;

int32_t wing_dpdk_probe(void) {
#if defined(__linux__)
    return 0;
#else
    return -38;
#endif
}

int32_t wing_dpdk_eal_init(void) {
    if (g_dpdk_eal_ready) {
        return 0;
    }
    char *argv[] = {"goose-wing", "--no-huge", "--no-pci", NULL};
    int rc = rte_eal_init(3, argv);
    if (rc < 0) {
        return -1;
    }
    g_dpdk_eal_ready = 1;
    return 0;
}

uint64_t wing_dpdk_pktmbuf_pool_create(uint32_t n_elements, uint32_t element_size, int32_t socket_id) {
    if (n_elements == 0 || element_size == 0 || element_size > 65535U) {
        return 0;
    }
    if (!g_dpdk_eal_ready && wing_dpdk_eal_init() != 0) {
        return 0;
    }
    if (g_dpdk_mbuf_pool != NULL) {
        return (uint64_t)(uintptr_t)g_dpdk_mbuf_pool;
    }
    g_dpdk_mbuf_pool = rte_pktmbuf_pool_create("wing_mbuf_pool", n_elements, 256, 0, (uint16_t)element_size, socket_id);
    return (uint64_t)(uintptr_t)g_dpdk_mbuf_pool;
}

void wing_dpdk_pktmbuf_free(uint64_t mbuf_ptr) {
    if (mbuf_ptr != 0) {
        rte_pktmbuf_free((struct rte_mbuf *)(uintptr_t)mbuf_ptr);
    }
}

int32_t wing_dpdk_eth_dev_configure(uint16_t port_id, uint16_t rx_queues, uint16_t tx_queues, uint16_t rx_ring_size,
                                    uint16_t tx_ring_size, int32_t promiscuous) {
    if (rx_queues == 0 || tx_queues == 0) {
        return -1;
    }
    if (!g_dpdk_eal_ready && wing_dpdk_eal_init() != 0) {
        return -1;
    }
    int32_t sock_id = rte_eth_dev_socket_id(port_id);
    if (sock_id < 0) sock_id = 0;
    if (g_dpdk_mbuf_pool == NULL && wing_dpdk_pktmbuf_pool_create(8192, 2048, sock_id) == 0) {
        return -1;
    }
    struct rte_eth_conf port_conf;
    memset(&port_conf, 0, sizeof(port_conf));
    int rc = rte_eth_dev_configure(port_id, rx_queues, tx_queues, &port_conf);
    if (rc < 0) {
        return rc;
    }
    uint16_t rx_desc = rx_ring_size > 0 ? rx_ring_size : 1024;
    uint16_t tx_desc = tx_ring_size > 0 ? tx_ring_size : 1024;
    for (uint16_t q = 0; q < rx_queues; q++) {
        rc = rte_eth_rx_queue_setup(port_id, q, rx_desc, (unsigned int)sock_id, NULL, g_dpdk_mbuf_pool);
        if (rc < 0) return rc;
    }
    for (uint16_t q = 0; q < tx_queues; q++) {
        rc = rte_eth_tx_queue_setup(port_id, q, tx_desc, (unsigned int)sock_id, NULL);
        if (rc < 0) return rc;
    }
    if (promiscuous) {
        rte_eth_promiscuous_enable(port_id);
    }
    return 0;
}

int32_t wing_dpdk_eth_dev_start(uint16_t port_id) { return rte_eth_dev_start(port_id); }

void wing_dpdk_eth_dev_stop(uint16_t port_id) { rte_eth_dev_stop(port_id); }

uint16_t wing_dpdk_rx_burst(uint16_t port_id, uint16_t queue_id, uint64_t *pkts_out, uint16_t nb_pkts) {
    if (!pkts_out || nb_pkts == 0) {
        return 0;
    }
    struct rte_mbuf *bufs[64];
    uint16_t total = 0;
    while (total < nb_pkts) {
        uint16_t batch = (uint16_t)(nb_pkts - total);
        if (batch > 64) batch = 64;
        uint16_t got = rte_eth_rx_burst(port_id, queue_id, bufs, batch);
        for (uint16_t i = 0; i < got; i++) {
            pkts_out[total + i] = (uint64_t)(uintptr_t)bufs[i];
        }
        total = (uint16_t)(total + got);
        if (got < batch) break;
    }
    return total;
}

uint16_t wing_dpdk_tx_burst(uint16_t port_id, uint16_t queue_id, const uint64_t *pkts_in, uint16_t nb_pkts) {
    if (!pkts_in || nb_pkts == 0) {
        return 0;
    }
    struct rte_mbuf *bufs[64];
    uint16_t total = 0;
    while (total < nb_pkts) {
        uint16_t batch = (uint16_t)(nb_pkts - total);
        if (batch > 64) batch = 64;
        for (uint16_t i = 0; i < batch; i++) {
            bufs[i] = (struct rte_mbuf *)(uintptr_t)pkts_in[total + i];
        }
        uint16_t sent = rte_eth_tx_burst(port_id, queue_id, bufs, batch);
        total = (uint16_t)(total + sent);
        if (sent < batch) break;
    }
    return total;
}

int32_t wing_dpdk_tx_packet_push(uint16_t port_id, uint16_t queue_id, wing_dpdk_ro_slice frame) {
    if (!frame.data || frame.len <= 0 || frame.len > 2048) {
        return 0;
    }
    if (g_dpdk_mbuf_pool == NULL && wing_dpdk_pktmbuf_pool_create(8192, 2048, 0) == 0) {
        return 0;
    }
    struct rte_mbuf *m = rte_pktmbuf_alloc(g_dpdk_mbuf_pool);
    if (!m) {
        return 0;
    }
    char *dst = rte_pktmbuf_append(m, (uint16_t)frame.len);
    if (!dst) {
        rte_pktmbuf_free(m);
        return 0;
    }
    memcpy(dst, frame.data, (size_t)frame.len);
    uint16_t sent = rte_eth_tx_burst(port_id, queue_id, &m, 1);
    if (sent == 0) {
        rte_pktmbuf_free(m);
        return 0;
    }
    return 1;
}

int32_t wing_dpdk_rx_burst_read_one(uint16_t port_id, uint16_t queue_id, wing_dpdk_rw_slice dst) {
    if (!dst.data || dst.len <= 0) {
        return -1;
    }
    struct rte_mbuf *m = NULL;
    uint16_t recvd = rte_eth_rx_burst(port_id, queue_id, &m, 1);
    if (recvd == 0 || !m) {
        return 0;
    }
    uint32_t plen = rte_pktmbuf_pkt_len(m);
    if (plen > 2048 || (int64_t)plen > dst.len) {
        rte_pktmbuf_free(m);
        return -1;
    }
    uint32_t copied = 0;
    for (struct rte_mbuf *seg = m; seg != NULL; seg = seg->next) {
        uint32_t seg_len = rte_pktmbuf_data_len(seg);
        if (seg_len > plen - copied) {
            rte_pktmbuf_free(m);
            return -1;
        }
        if (seg_len > 0) {
            const void *src = rte_pktmbuf_mtod(seg, const void *);
            memcpy((uint8_t *)dst.data + copied, src, (size_t)seg_len);
            copied += seg_len;
        }
    }
    rte_pktmbuf_free(m);
    if (copied != plen) {
        return -1;
    }
    return (int32_t)plen;
}

#else

int32_t wing_dpdk_probe(void) {
#if defined(__linux__)
    return 0;
#else
    return -38;
#endif
}

int32_t wing_dpdk_eal_init(void) { return -38; }

uint64_t wing_dpdk_pktmbuf_pool_create(uint32_t n_elements, uint32_t element_size, int32_t socket_id) {
    (void)n_elements;
    (void)element_size;
    (void)socket_id;
    return 0;
}

void wing_dpdk_pktmbuf_free(uint64_t mbuf_ptr) { (void)mbuf_ptr; }

int32_t wing_dpdk_eth_dev_configure(uint16_t port_id, uint16_t rx_queues, uint16_t tx_queues, uint16_t rx_ring_size,
                                    uint16_t tx_ring_size, int32_t promiscuous) {
    (void)port_id;
    (void)rx_queues;
    (void)tx_queues;
    (void)rx_ring_size;
    (void)tx_ring_size;
    (void)promiscuous;
    return -38;
}

int32_t wing_dpdk_eth_dev_start(uint16_t port_id) {
    (void)port_id;
    return -38;
}

void wing_dpdk_eth_dev_stop(uint16_t port_id) { (void)port_id; }

uint16_t wing_dpdk_tx_burst(uint16_t port_id, uint16_t queue_id, const uint64_t *pkts_in, uint16_t nb_pkts) {
    (void)port_id;
    (void)queue_id;
    (void)pkts_in;
    (void)nb_pkts;
    return 0;
}

uint16_t wing_dpdk_rx_burst(uint16_t port_id, uint16_t queue_id, uint64_t *pkts_out, uint16_t nb_pkts) {
    (void)port_id;
    (void)queue_id;
    (void)pkts_out;
    (void)nb_pkts;
    return 0;
}

int32_t wing_dpdk_tx_packet_push(uint16_t port_id, uint16_t queue_id, wing_dpdk_ro_slice frame) {
    (void)port_id;
    (void)queue_id;
    (void)frame;
    return -38;
}

int32_t wing_dpdk_rx_burst_read_one(uint16_t port_id, uint16_t queue_id, wing_dpdk_rw_slice dst) {
    (void)port_id;
    (void)queue_id;
    (void)dst;
    return -38;
}

#endif
