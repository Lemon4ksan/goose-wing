-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2026 Lemon4ksan

-- pipeline_128.lua - 128x pipelined HTTP/1.1 requests for wrk
local r = "GET /plaintext HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n"
local batch = ""
for _ = 1, 128 do
    batch = batch .. r
end

wrk.request = batch

init = function(args)
    wrk.request = batch
end
