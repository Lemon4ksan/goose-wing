-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2026 Lemon4ksan

-- route_api.lua - Parameterized API routing + 2 KB JSON body workload (no pipelining)
local counter = 0

request = function()
    counter = counter + 1
    local uid = 1001 + (counter % 64)
    return wrk.format("GET", "/api/v1/users/" .. tostring(uid))
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
