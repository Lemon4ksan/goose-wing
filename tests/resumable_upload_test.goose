// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for IETF draft-ietf-httpbis-resumable-upload-14:
// - Creation request formatting with Upload-Complete: ?0 and MIME application/partial-upload
// - Server 201 Created response parsing (Location, Upload-Offset)
// - Chunk append with PATCH, Upload-Offset, and final Upload-Complete: ?1
// - Interruption offset query with HEAD request (RFC 8941 Structured Fields parsing)
import std;
import core from "..";
import wing from "..";

fn test_resumable_uploads(t: core::T&) {
    t.run("Upload Session Initialization & Creation Request") { sub =>
        var state = wing::init_resumable_upload(800000, 500000);
        sub.assert_eq(state.total_size, 800000, "Total size is 800KB");
        sub.assert_eq(state.offset, 0, "Initial offset is 0");
        sub.assert_false(state.complete, "Initial complete is false");

        var create_req = wing::Request { .. };
        let chunk1 = "FIRST_CHUNK_DATA_500000_BYTES";
        wing::format_upload_creation_request(create_req, "https://storage.cdn.com/uploads", chunk1, false);

        sub.assert_bytes_eq(create_req.method[..], "POST", "Method is POST");
        sub.assert_bytes_eq(create_req.url[..], "https://storage.cdn.com/uploads", "URL is uploads endpoint");

        sub.assert_true(create_req.has_header("Upload-Complete"), "Upload-Complete present");
        sub.assert_bytes_eq(create_req.header("Upload-Complete"), "?0", "Upload-Complete is ?0 for initial incomplete chunk");
        sub.assert_true(create_req.has_header("Content-Type"), "Content-Type present");
        sub.assert_bytes_eq(create_req.header("Content-Type"), "application/partial-upload", "Content-Type is application/partial-upload");
    };

    t.run("Creation Response Handling & Chunk Append (PATCH)") { sub =>
        var state = wing::init_resumable_upload(800000, 500000);

        // Server responds 201 Created
        var create_resp = wing::Response { status_code: 201, .. };
        create_resp.headers.push(wing::make_header("Location", "https://storage.cdn.com/uploads/session-abc1234"));
        create_resp.headers.push(wing::make_header("Upload-Offset", "500000"));
        create_resp.headers.push(wing::make_header("Upload-Complete", "?0"));

        let ok_handle = wing::handle_creation_response(create_resp, state);
        sub.assert_true(ok_handle, "Creation response handled");
        sub.assert_bytes_eq(state.upload_url[..], "https://storage.cdn.com/uploads/session-abc1234", "Session URL stored");
        sub.assert_eq(state.offset, 500000, "Server offset updated to 500000");
        sub.assert_false(state.complete, "Upload is not complete yet");

        // Format final chunk append (PATCH)
        var patch_req = wing::Request { .. };
        let final_chunk = "FINAL_CHUNK_DATA_300000_BYTES";
        wing::format_upload_chunk_request(patch_req, state, final_chunk, true);

        sub.assert_bytes_eq(patch_req.method[..], "PATCH", "Method is PATCH");
        sub.assert_bytes_eq(patch_req.url[..], "https://storage.cdn.com/uploads/session-abc1234", "PATCH URL is session URL");

        sub.assert_true(patch_req.has_header("Upload-Offset"), "Upload-Offset present");
        sub.assert_bytes_eq(patch_req.header("Upload-Offset"), "500000", "Upload-Offset matches current client state");
        sub.assert_true(patch_req.has_header("Upload-Complete"), "Upload-Complete present");
        sub.assert_bytes_eq(patch_req.header("Upload-Complete"), "?1", "Upload-Complete is ?1 on final chunk");

        // Server responds 204 No Content for PATCH
        var patch_resp = wing::Response { status_code: 204, .. };
        patch_resp.headers.push(wing::make_header("Upload-Offset", "800000"));
        patch_resp.headers.push(wing::make_header("Upload-Complete", "?1"));

        let ok_patch = wing::handle_chunk_response(patch_resp, state);
        sub.assert_true(ok_patch, "Chunk response handled");
        sub.assert_eq(state.offset, 800000, "Offset updated to 800000");
        sub.assert_true(state.complete, "State complete is now true");
    };

    t.run("Interruption Offset Query Recovery (HEAD)") { sub =>
        var state = wing::init_resumable_upload(800000, 500000);
        state.upload_url.append("https://storage.cdn.com/uploads/session-abc1234");
        state.offset = 0; // Simulated connection loss / client restart

        var head_req = wing::Request { .. };
        wing::format_upload_offset_query(head_req, state.upload_url[..]);
        sub.assert_bytes_eq(head_req.method[..], "HEAD", "Offset query is HEAD");

        // Server returns current stored offset 500000
        var head_resp = wing::Response { status_code: 204, .. };
        head_resp.headers.push(wing::make_header("Upload-Offset", "500000"));
        head_resp.headers.push(wing::make_header("Upload-Complete", "?0"));

        let ok_rec = wing::handle_offset_query_response(head_resp, state);
        sub.assert_true(ok_rec, "Offset query response parsed");
        sub.assert_eq(state.offset, 500000, "Offset successfully recovered to 500000");
        sub.assert_false(state.complete, "Complete flag correctly reflects ongoing upload");
    };
}

fn main() {
    var runner = core::new_runner("IETF Resumable Uploads Suite (draft-14)", core::Verbosity.Verbose);
    core::run_case(runner, "1. Resumable Uploads for HTTP", test_resumable_uploads);
    let ok = core::finish(runner);
    assert(ok);
}
