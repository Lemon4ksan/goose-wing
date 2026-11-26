-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2026 Lemon4ksan

-- wrk_report.lua - Standard non-pipelined HTTP/1.1 workload with exact HDRHistogram percentiles
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
