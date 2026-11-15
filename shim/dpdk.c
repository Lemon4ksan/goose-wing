// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 DPDK (Data Plane Development Kit) Poll Mode Driver (PMD) C Shim.
// Compiles against libdpdk (rte_eal, rte_ethdev, rte_mbuf) when WING_ENABLE_DPDK is defined,
// and provides a deterministic lock-free userspace ring fallback otherwise.
#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef struct {
    const void *data;
    int64_t len;
} wing_dpdk_ro_slice;

typedef struct {
    void *data;
    int64_t len;
} wing_dpdk_rw_slice;

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
    if (!g_dpdk_eal_ready && wing_dpdk_eal_init() != 0) {
        return 0;
    }
    if (g_dpdk_mbuf_pool != NULL) {
        return (uint64_t)(uintptr_t)g_dpdk_mbuf_pool;
    }
    g_dpdk_mbuf_pool = rte_pktmbuf_pool_create("wing_mbuf_pool", n_elements, 256, 0, (uint16_t)element_size, socket_id);
    return (uint64_t)(uintptr_t)g_dpdk_mbuf_pool;
}

int32_t wing_dpdk_eth_dev_configure(uint16_t port_id, uint16_t rx_queues, uint16_t tx_queues, uint16_t rx_ring_size,
                                    uint16_t tx_ring_size, int32_t promiscuous) {
    (void)rx_ring_size;
    (void)tx_ring_size;
    if (!g_dpdk_eal_ready && wing_dpdk_eal_init() != 0) {
        return -1;
    }
    struct rte_eth_conf port_conf;
    memset(&port_conf, 0, sizeof(port_conf));
    int rc = rte_eth_dev_configure(port_id, rx_queues, tx_queues, &port_conf);
    if (rc < 0) {
        return rc;
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
    return rte_eth_rx_burst(port_id, queue_id, (struct rte_mbuf **)pkts_out, nb_pkts);
}

uint16_t wing_dpdk_tx_burst(uint16_t port_id, uint16_t queue_id, const uint64_t *pkts_in, uint16_t nb_pkts) {
    if (!pkts_in || nb_pkts == 0) {
        return 0;
    }
    return rte_eth_tx_burst(port_id, queue_id, (struct rte_mbuf **)(uintptr_t)pkts_in, nb_pkts);
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
    const void *src = rte_pktmbuf_mtod(m, const void *);
    memcpy(dst.data, src, (size_t)plen);
    rte_pktmbuf_free(m);
    return (int32_t)plen;
}

#else

#define WING_DPDK_MAX_PORTS 16
#define WING_DPDK_RING_CAP 256
#define WING_DPDK_PKT_RING_CAP 64
#define WING_DPDK_MAX_FRAME_LEN 2048

typedef struct {
    uint16_t rx_queues;
    uint16_t tx_queues;
    uint16_t rx_ring_size;
    uint16_t tx_ring_size;
    int32_t promiscuous;
    int32_t configured;
    int32_t started;
    uint64_t loopback_ring[WING_DPDK_RING_CAP];
    uint32_t head;
    uint32_t tail;
    uint32_t count;
    uint8_t pkt_data[WING_DPDK_PKT_RING_CAP][WING_DPDK_MAX_FRAME_LEN];
    uint16_t pkt_len[WING_DPDK_PKT_RING_CAP];
    uint32_t pkt_head;
    uint32_t pkt_tail;
    uint32_t pkt_count;
} wing_dpdk_port_state;

static wing_dpdk_port_state g_dpdk_ports[WING_DPDK_MAX_PORTS];
static int g_dpdk_eal_initialized = 0;
static uint64_t g_dpdk_next_pool_handle = 0xD0001000ULL;

int32_t wing_dpdk_probe(void) {
#if defined(__linux__)
    return 0;
#else
    return -38;
#endif
}

int32_t wing_dpdk_eal_init(void) {
    g_dpdk_eal_initialized = 1;
    return 0;
}

uint64_t wing_dpdk_pktmbuf_pool_create(uint32_t n_elements, uint32_t element_size, int32_t socket_id) {
    (void)socket_id;
    if (n_elements == 0 || element_size == 0) {
        return 0;
    }
    if (!g_dpdk_eal_initialized) {
        wing_dpdk_eal_init();
    }
    uint64_t h = g_dpdk_next_pool_handle;
    g_dpdk_next_pool_handle += 0x1000ULL;
    return h;
}

int32_t wing_dpdk_eth_dev_configure(uint16_t port_id, uint16_t rx_queues, uint16_t tx_queues, uint16_t rx_ring_size,
                                    uint16_t tx_ring_size, int32_t promiscuous) {
    if (port_id >= WING_DPDK_MAX_PORTS || rx_queues == 0 || tx_queues == 0) {
        return -1;
    }
    if (!g_dpdk_eal_initialized) {
        wing_dpdk_eal_init();
    }
    wing_dpdk_port_state *st = &g_dpdk_ports[port_id];
    memset(st, 0, sizeof(*st));
    st->rx_queues = rx_queues;
    st->tx_queues = tx_queues;
    st->rx_ring_size = rx_ring_size;
    st->tx_ring_size = tx_ring_size;
    st->promiscuous = promiscuous;
    st->configured = 1;
    return 0;
}

int32_t wing_dpdk_eth_dev_start(uint16_t port_id) {
    if (port_id >= WING_DPDK_MAX_PORTS || !g_dpdk_ports[port_id].configured) {
        return -1;
    }
    g_dpdk_ports[port_id].started = 1;
    return 0;
}

void wing_dpdk_eth_dev_stop(uint16_t port_id) {
    if (port_id < WING_DPDK_MAX_PORTS) {
        g_dpdk_ports[port_id].started = 0;
        g_dpdk_ports[port_id].configured = 0;
        g_dpdk_ports[port_id].head = 0;
        g_dpdk_ports[port_id].tail = 0;
        g_dpdk_ports[port_id].count = 0;
        g_dpdk_ports[port_id].pkt_head = 0;
        g_dpdk_ports[port_id].pkt_tail = 0;
        g_dpdk_ports[port_id].pkt_count = 0;
    }
}

uint16_t wing_dpdk_tx_burst(uint16_t port_id, uint16_t queue_id, const uint64_t *pkts_in, uint16_t nb_pkts) {
    (void)queue_id;
    if (port_id >= WING_DPDK_MAX_PORTS || !pkts_in || nb_pkts == 0) {
        return 0;
    }
    wing_dpdk_port_state *st = &g_dpdk_ports[port_id];
    if (!st->started) {
        return 0;
    }
    uint16_t sent = 0;
    while (sent < nb_pkts && st->count < WING_DPDK_RING_CAP) {
        st->loopback_ring[st->tail] = pkts_in[sent];
        st->tail = (st->tail + 1) % WING_DPDK_RING_CAP;
        st->count++;
        sent++;
    }
    return sent;
}

uint16_t wing_dpdk_rx_burst(uint16_t port_id, uint16_t queue_id, uint64_t *pkts_out, uint16_t nb_pkts) {
    (void)queue_id;
    if (port_id >= WING_DPDK_MAX_PORTS || !pkts_out || nb_pkts == 0) {
        return 0;
    }
    wing_dpdk_port_state *st = &g_dpdk_ports[port_id];
    if (!st->started) {
        return 0;
    }
    uint16_t recvd = 0;
    while (recvd < nb_pkts && st->count > 0) {
        pkts_out[recvd] = st->loopback_ring[st->head];
        st->head = (st->head + 1) % WING_DPDK_RING_CAP;
        st->count--;
        recvd++;
    }
    return recvd;
}

int32_t wing_dpdk_tx_packet_push(uint16_t port_id, uint16_t queue_id, wing_dpdk_ro_slice frame) {
    (void)queue_id;
    if (port_id >= WING_DPDK_MAX_PORTS || !frame.data || frame.len <= 0 || frame.len > WING_DPDK_MAX_FRAME_LEN) {
        return 0;
    }
    wing_dpdk_port_state *st = &g_dpdk_ports[port_id];
    if (!st->started || st->pkt_count >= WING_DPDK_PKT_RING_CAP) {
        return 0;
    }
    uint32_t idx = st->pkt_tail;
    memcpy(st->pkt_data[idx], frame.data, (size_t)frame.len);
    st->pkt_len[idx] = (uint16_t)frame.len;
    st->pkt_tail = (idx + 1) % WING_DPDK_PKT_RING_CAP;
    st->pkt_count++;
    return 1;
}

int32_t wing_dpdk_rx_burst_read_one(uint16_t port_id, uint16_t queue_id, wing_dpdk_rw_slice dst) {
    (void)queue_id;
    if (port_id >= WING_DPDK_MAX_PORTS || !dst.data || dst.len <= 0) {
        return -1;
    }
    wing_dpdk_port_state *st = &g_dpdk_ports[port_id];
    if (!st->started || st->pkt_count == 0) {
        return 0;
    }
    uint32_t idx = st->pkt_head;
    uint16_t plen = st->pkt_len[idx];
    if ((int64_t)plen > dst.len) {
        return -1;
    }
    memcpy(dst.data, st->pkt_data[idx], (size_t)plen);
    st->pkt_head = (idx + 1) % WING_DPDK_PKT_RING_CAP;
    st->pkt_count--;
    return (int32_t)plen;
}

#endif
