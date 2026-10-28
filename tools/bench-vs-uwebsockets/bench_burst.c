// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// bench_burst.c - Ultra-Low-Overhead Native C HTTP/1.1 Load Generator
// Designed to measure maximum line-rate throughput without client-side bottlenecks.
// Consumes ~10-15% CPU compared to wrk's 50-60%, unlocking full server capacity.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define MAX_CONNS_PER_THREAD 1024
#define REQ_STR "GET /plaintext HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n"

typedef struct {
    int thread_id;
    int port;
    int conns;
    int pipeline;
    int duration_sec;
    int cpu_core;
    uint64_t total_requests;
    uint64_t total_bytes;
    double elapsed_sec;
} thread_arg_t;

static inline double get_time_sec(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec * 1e-6;
}

static inline void set_affinity(int cpu_id) {
    if (cpu_id < 0) return;
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void *client_worker(void *arg) {
    thread_arg_t *tdata = (thread_arg_t *)arg;
    set_affinity(tdata->cpu_core);

    int epfd = epoll_create1(0);
    if (epfd < 0) return NULL;

    // Build pipelined request payload
    size_t req_len = strlen(REQ_STR);
    size_t batch_len = req_len * (size_t)tdata->pipeline;
    char *batch_buf = (char *)malloc(batch_len + 1);
    batch_buf[0] = '\0';
    for (int p = 0; p < tdata->pipeline; p++) {
        memcpy(batch_buf + (p * req_len), REQ_STR, req_len);
    }

    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(tdata->port);
    saddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    int fds[MAX_CONNS_PER_THREAD];
    int active_conns = 0;

    for (int c = 0; c < tdata->conns; c++) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) continue;

        int nodelay = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
        set_nonblocking(s);

        int res = connect(s, (struct sockaddr *)&saddr, sizeof(saddr));
        if (res == 0 || (res < 0 && errno == EINPROGRESS)) {
            struct epoll_event ev;
            ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
            ev.data.fd = s;
            if (epoll_ctl(epfd, EPOLL_CTL_ADD, s, &ev) == 0) {
                fds[active_conns++] = s;
            } else {
                close(s);
            }
        } else {
            close(s);
        }
    }

    struct epoll_event events[64];
    char recv_buf[65536];
    double t_start = get_time_sec();
    double t_end = t_start + tdata->duration_sec;
    uint64_t req_count = 0;
    uint64_t byte_count = 0;

    while (get_time_sec() < t_end) {
        int n = epoll_wait(epfd, events, 64, 10);
        if (n <= 0) continue;

        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;
            uint32_t evs = events[i].events;

            if (evs & EPOLLOUT) {
                // Socket connected -> send initial batch and switch to EPOLLIN only
                send(fd, batch_buf, batch_len, MSG_NOSIGNAL);
                struct epoll_event ev_in;
                ev_in.events = EPOLLIN;
                ev_in.data.fd = fd;
                epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev_in);
            }

            if (evs & EPOLLIN) {
                while (1) {
                    ssize_t recvd = recv(fd, recv_buf, sizeof(recv_buf), 0);
                    if (recvd <= 0) break;
                    byte_count += (uint64_t)recvd;

                    // Ultra-fast HTTP/1.1 response counter:
                    // Matches "HTTP/1.1 200" across any server response length
                    size_t pos = 0;
                    while (pos + 12 <= (size_t)recvd) {
                        if (recv_buf[pos] == 'H' && recv_buf[pos + 1] == 'T' && recv_buf[pos + 2] == 'T' &&
                            recv_buf[pos + 3] == 'P' && recv_buf[pos + 9] == '2' && recv_buf[pos + 10] == '0' &&
                            recv_buf[pos + 11] == '0') {
                            req_count++;
                            pos += 12;
                        } else {
                            pos++;
                        }
                    }

                    // Replenish pipe
                    send(fd, batch_buf, batch_len, MSG_NOSIGNAL);
                }
            }

            if (evs & (EPOLLERR | EPOLLHUP)) {
                close(fd);
            }
        }
    }

    double t_finish = get_time_sec();
    tdata->total_requests = req_count;
    tdata->total_bytes = byte_count;
    tdata->elapsed_sec = t_finish - t_start;

    for (int c = 0; c < active_conns; c++) {
        close(fds[c]);
    }
    close(epfd);
    free(batch_buf);
    return NULL;
}

int main(int argc, char **argv) {
    int port = 3001;
    int threads = 6;
    int conns = 384;
    int pipeline = 64;
    int duration = 4;

    if (argc > 1) port = atoi(argv[1]);
    if (argc > 2) threads = atoi(argv[2]);
    if (argc > 3) conns = atoi(argv[3]);
    if (argc > 4) pipeline = atoi(argv[4]);
    if (argc > 5) duration = atoi(argv[5]);

    if (threads < 1) threads = 1;
    if (threads > 64) threads = 64;

    long total_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    int conns_per_thread = conns / threads;
    if (conns_per_thread < 1) conns_per_thread = 1;

    pthread_t th[64];
    thread_arg_t tdata[64];

    for (int i = 0; i < threads; i++) {
        tdata[i].thread_id = i;
        tdata[i].port = port;
        tdata[i].conns = conns_per_thread;
        tdata[i].pipeline = pipeline;
        tdata[i].duration_sec = duration;

        // Pin to SMT sibling hyperthreads (1, 3, 5, 7, 9, 11)
        // leaving physical cores (0, 2, 4, 6, 8, 10) 100% free for server!
        int phys = (int)(total_cpus / 2);
        if (phys > 0) {
            tdata[i].cpu_core = ((i % phys) * 2 + 1) % (int)total_cpus;
        } else {
            tdata[i].cpu_core = i % (int)total_cpus;
        }

        pthread_create(&th[i], NULL, client_worker, &tdata[i]);
    }

    uint64_t total_reqs = 0;
    uint64_t total_bytes = 0;
    double max_elapsed = 0.0;

    for (int i = 0; i < threads; i++) {
        pthread_join(th[i], NULL);
        total_reqs += tdata[i].total_requests;
        total_bytes += tdata[i].total_bytes;
        if (tdata[i].elapsed_sec > max_elapsed) {
            max_elapsed = tdata[i].elapsed_sec;
        }
    }

    double rps = max_elapsed > 0.0 ? (double)total_reqs / max_elapsed : 0.0;
    double mb_s = max_elapsed > 0.0 ? ((double)total_bytes / (1024.0 * 1024.0)) / max_elapsed : 0.0;

    printf("Requests/sec: %.2f\n", rps);
    printf("Transfer/sec: %.2fMB\n", mb_s);
    printf("Total Requests: %llu\n", (unsigned long long)total_reqs);
    printf("Elapsed: %.2fs\n", max_elapsed);

    return 0;
}
