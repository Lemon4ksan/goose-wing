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
