# goose-wing tc netem and packetdrill testbed

Network impairment and TCP/QUIC transport edge-case testbed combining Linux
`tc netem` (`iproute2`) and Google `packetdrill` in Docker with a cross-platform
userspace UDP chaos proxy and `.pkt` DSL validator for `--local` runs on
Windows, macOS, and Linux.

## Quick start

### Local mode (userspace UDP chaos proxy + `.pkt` validation)

```bash
python tools/netem_packetdrill.py --local
```

### Docker mode (live kernel `tc netem` + `packetdrill`)

```bash
python tools/netem_packetdrill.py --docker
```

Or run the image manually with `NET_ADMIN`:

```bash
docker build -f tools/netem_packetdrill/Dockerfile -t goose-wing-netem .
docker run --rm --cap-add=NET_ADMIN goose-wing-netem
```

## Verified scenarios

| Component | Target | Coverage |
| :--- | :--- | :--- |
| `netem_quic_test.sh` | `lo` qdisc | Applies `tc qdisc add dev lo root netem loss 5% delay 15ms 5ms duplicate 2% reorder 10%` during live HTTP/3 transfers and cleans up on exit. |
| `DeterministicNetemProxy` | `tools/http3/server.goose` and `client.goose` | Local cross-platform UDP loss, 15ms +/- 5ms jitter, duplication, reordering, and combined chaos recovery. |
| `tcp_syn_retransmit.pkt` | Wing TCP client | Non-blocking `connect` (`EINPROGRESS`), lost initial SYN, RTO SYN retransmit, handshake completion, and `SO_ERROR` check. |
| `tcp_rst_midstream.pkt` | Wing TCP server | Mid-stream peer `RST` during active HTTP/1.1 exchange verifying fail-closed `ECONNRESET` and `EPIPE`. |
| `tcp_zero_window.pkt` | Wing TCP server | Peer `win 0` stall, persist-timer Zero-Window Probe (`ZWP`), window reopen (`win 4096`), and buffered flush. |
