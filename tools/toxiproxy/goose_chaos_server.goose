// Standalone Live Goose-Wing HTTP Server for Toxiproxy Chaos Testing.
import std;
import core from "../..";
import wing from "../..";

fn extract_content_length(headers_block: const u8[:]) -> i64, bool {
    var cursor: i64 = 0;
    while cursor < headers_block.len {
        let rel_end = core::index_of_slice(headers_block[cursor..], "\r\n");
        if rel_end < 0 { break; }
        let line = headers_block[cursor .. (cursor + rel_end)];
        let colon = core::index_of_byte(line, ':');
        if colon > 0 {
            let hname = line[..colon];
            if core::eq_ascii_fold(hname, "content-length") {
                let hval = core::trim_lws(line[(colon + 1)..]);
                let cl, ok = core::parse_i64_dec(hval);
                if ok && cl >= 0 {
                    return cl, true;
                }
            }
        }
        cursor += rel_end + 2;
    }
    return 0, false;
}

fn main() {
    let listener = wing::tcp_listen("127.0.0.1", 0, 128);
    if listener <= 0 {
        print("ERROR_FAILED_TO_LISTEN\n");
        return;
    }
    let port = wing::tcp_getsockname_port(listener);
    print("READY_PORT:", port, "\n");

    var is_running = true;
    while is_running {
        let conn = wing::tcp_accept(listener, 500);
        if conn <= 0 {
            continue;
        }

        var in_buf: u8[..65536] = [];
        var got_response = false;

        // Streaming accumulator: handles sliced TCP segments
        while in_buf.len < 65000 {
            var chunk: u8[..4096] = [];
            let recvd = wing::tcp_recv(conn, chunk, 4096, 3000);
            if recvd <= 0 {
                break;
            }
            in_buf.append(chunk[..]);

            let hdr_end = core::index_of_slice(in_buf[..], "\r\n\r\n");
            if hdr_end >= 0 {
                let body_start = hdr_end + 4;
                let cl, has_cl = extract_content_length(in_buf[..body_start]);
                
                // If Content-Length body is not fully arrived yet, keep accumulating!
                if has_cl && in_buf.len < body_start + cl {
                    continue;
                }

                // If chunked transfer, keep reading until terminal chunk (0\r\n\r\n)
                let is_chunked = core::index_of_slice(in_buf[..body_start], "chunked") >= 0;
                if is_chunked && core::index_of_slice(in_buf[body_start..], "0\r\n\r\n") < 0 {
                    continue;
                }

                // Request is complete or has malformed headers
                var req = wing::Request {};
                let ok_req, consumed = wing::parse_http1_wire_request(in_buf[..], req);
                if ok_req {
                    if req.url[..] == "/shutdown" {
                        let resp: const u8[:] = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nBYE\n";
                        wing::tcp_send(conn, resp);
                        is_running = false;
                        got_response = true;
                        break;
                    }

                    var resp_body: u8[..16384] = [];
                    if req.url[..] == "/echo" {
                        resp_body.append("ECHO:");
                        resp_body.append(req.body[..]);
                    } else {
                        resp_body.append("OK");
                    }

                    var resp_wire: u8[..32768] = [];
                    format(
                        resp_wire,
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ",
                        resp_body.len,
                        "\r\nConnection: close\r\n\r\n",
                        resp_body[..]
                    );
                    wing::tcp_send(conn, resp_wire[..]);
                    got_response = true;
                    break;
                } else {
                    // Header syntax / smuggling error detected by Goose wire parser
                    let err_resp: const u8[:] = "HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\nConnection: close\r\n\r\nBAD_REQUEST";
                    wing::tcp_send(conn, err_resp);
                    got_response = true;
                    break;
                }
            }
        }

        wing::tcp_close(conn);
    }

    wing::tcp_close(listener);
}
