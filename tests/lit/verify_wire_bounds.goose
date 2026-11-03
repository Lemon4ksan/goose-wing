// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

// Verification of HTTP/2 wire frame bounds and RFC invariants (RFC 9113, RFC 9218).
import std;
import core from "../..";
import wing from "../..";

fn main() {
    print("=== VERIFY_WIRE_BOUNDS ===\n");

    var buf: u8[..256] = [];

    // Case 1: DATA frame MUST reject stream_id = 0 (RFC 9113 Section 6.1)
    let data_zero_sid = wire::encode_data_frame(0, "payload", true, buf);
    assert(!data_zero_sid);
    print("DATA_ZERO_SID_REJECTED: OK\n");
    // CHECK: DATA_ZERO_SID_REJECTED: OK

    // Case 2: RST_STREAM frame MUST reject stream_id = 0 (RFC 9113 Section 6.4)
    buf.clear();
    let rst_zero_sid = wire::encode_rst_stream_frame(0, 1, buf);
    assert(!rst_zero_sid);
    print("RST_ZERO_SID_REJECTED: OK\n");
    // CHECK: RST_ZERO_SID_REJECTED: OK

    // Case 3: WINDOW_UPDATE frame MUST reject increment = 0 (RFC 9113 Section 6.9)
    buf.clear();
    let win_zero_inc = wire::encode_window_update_frame(1, 0, buf);
    assert(!win_zero_inc);
    print("WINDOW_UPDATE_ZERO_INC_REJECTED: OK\n");
    // CHECK: WINDOW_UPDATE_ZERO_INC_REJECTED: OK

    // Case 4: PRIORITY_UPDATE frame MUST reject prioritized_stream_id = 0 (RFC 9218 Section 7.1)
    buf.clear();
    let prio_zero_psid = wire::encode_priority_update_frame(0, 0, false, buf);
    assert(!prio_zero_psid);
    print("PRIORITY_UPDATE_ZERO_PSID_REJECTED: OK\n");
    // CHECK: PRIORITY_UPDATE_ZERO_PSID_REJECTED: OK

    // Case 5: parse_frame_header returns error code 0 (Incomplete), not 1 (PROTOCOL_ERROR), on buf.len < 9
    let short_buf: const u8[:] = "\x00\x00\x04\x00";
    let hdr, err_code, ok = wire::parse_frame_header(short_buf);
    assert(!ok);
    assert(err_code == 0);
    print("SHORT_HEADER_NO_PROTOCOL_ERROR: OK\n");
    // CHECK: SHORT_HEADER_NO_PROTOCOL_ERROR: OK

    print("ALL_WIRE_BOUNDS_VERIFIED: OK\n");
    // CHECK: ALL_WIRE_BOUNDS_VERIFIED: OK
}
