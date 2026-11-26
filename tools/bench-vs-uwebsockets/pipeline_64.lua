-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2026 Lemon4ksan

-- pipeline_64.lua - 64x pipelined HTTP/1.1 requests for wrk
local r = "GET /plaintext HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n"
local batch = ""
for _ = 1, 64 do
    batch = batch .. r
end

wrk.request = batch

init = function(args)
    wrk.request = batch
end

done = function(summary, latency, requests)
    io.write(string.format(
        "WRK_PCT_US: p50=%.2f p90=%.2f p95=%.2f p99=%.2f p999=%.2f max=%.2f\n",
        latency:percentile(50.0),
        latency:percentile(90.0),
        latency:percentile(95.0),
        latency:percentile(99.0),
        latency:percentile(99.9),
        latency.max
    ))
    io.write(string.format(
        "WRK_ERRORS: connect=%d read=%d write=%d status=%d timeout=%d\n",
        summary.errors.connect,
        summary.errors.read,
        summary.errors.write,
        summary.errors.status,
        summary.errors.timeout
    ))
end
