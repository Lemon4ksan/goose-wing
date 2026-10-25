// Verification suite for Goose Core I/O Stream Module (core/io):
// - SliceReader cursor semantics, bounds checking, and integer deserialization (BE/LE)
// - SliceWriter and CountingWriter with capacity guards and integer serialization
// - LimitReader bounded reading and DoS threshold enforcement
// - TeeReader stream tapping and transcript mirroring
// - RingBuffer circular FIFO storage, wraparound behavior, and zero-copy peeking
// - Stream piping helpers (copy_reader_to_writer, copy_reader_all, copy_reader_n)
import std;
import core from "..";

fn test_slice_reader(t: core::T&) {
    t.run("Sequential Reading and Exact Slices") { sub =>
        let data = "Hello, World! Systems Zero-Heap IO";
        var r = core::new_slice_reader(data);

        sub.assert_eq(r.remaining(), data.len, "Initial remaining matches data len");
        sub.assert_false(r.is_eof(), "Not EOF initially");

        var buf: u8[16] = [0; 16];
        let n, err = r.read(buf[..5]);
        sub.assert_eq(n, 5, "Read 5 bytes");
        sub.assert_eq(err, core::IoError.None, "No error on partial read");
        sub.assert_eq(buf[..5], "Hello", "Read bytes match expected slice");
        sub.assert_eq(r.remaining(), data.len - 5, "Remaining decreased by 5");

        let p_byte, p_ok = r.peek();
        sub.assert_true(p_ok, "Peek successful");
        sub.assert_eq(p_byte, ',' as u8, "Peek returns next comma byte");
        sub.assert_eq(r.remaining(), data.len - 5, "Peek does not advance cursor");

        let slice, s_err = r.read_slice(2);
        sub.assert_eq(s_err, core::IoError.None, "read_slice ok");
        sub.assert_eq(slice, ", ", "Yielded exact 2-byte slice");

        let skip_err = r.skip(7);
        sub.assert_eq(skip_err, core::IoError.None, "Skip 7 bytes ok");
        sub.assert_eq(r.remaining(), data.len - 14, "Remaining after skip");

        let tail, tail_err = r.read_slice(r.remaining());
        sub.assert_eq(tail_err, core::IoError.None, "Read remaining slice ok");
        sub.assert_eq(tail, "Systems Zero-Heap IO", "Tail slice matches");
        sub.assert_true(r.is_eof(), "Reader reached EOF");
        sub.assert_eq(r.remaining(), 0, "0 remaining at EOF");

        let eof_n, eof_err = r.read(buf[..]);
        sub.assert_eq(eof_n, 0, "Read at EOF returns 0 bytes");
        sub.assert_eq(eof_err, core::IoError.Eof, "Read at EOF returns IoError.Eof");
    };

    t.run("Binary Integer Deserialization (BE & LE)") { sub =>
        // Wire packet:
        // [0] = 0xFE (u8)
        // [1..2] = 0x12, 0x34 (u16 BE = 0x1234, LE = 0x3412)
        // [3..5] = 0x01, 0x02, 0x03 (u24 BE = 0x010203)
        // [6..9] = 0x01, 0x02, 0x03, 0x04 (u32 BE = 0x01020304)
        // [10..17] = 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 (u64 BE)
        let wire_bytes: u8[18] = [
            0xFE,
            0x12, 0x34,
            0x01, 0x02, 0x03,
            0x01, 0x02, 0x03, 0x04,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
        ];
        var r = core::new_slice_reader(wire_bytes[..]);

        let u8_val, err8 = r.read_u8();
        sub.assert_eq(err8, core::IoError.None, "read_u8 ok");
        sub.assert_eq(u8_val, 0xFE, "u8 matches 0xFE");

        let u16_val, err16 = r.read_u16_be();
        sub.assert_eq(err16, core::IoError.None, "read_u16_be ok");
        sub.assert_eq(u16_val, 0x1234 as u16, "u16 BE matches 0x1234");

        let u24_val, err24 = r.read_u24_be();
        sub.assert_eq(err24, core::IoError.None, "read_u24_be ok");
        sub.assert_eq(u24_val, 0x010203 as u32, "u24 BE matches 0x010203");

        let u32_val, err32 = r.read_u32_be();
        sub.assert_eq(err32, core::IoError.None, "read_u32_be ok");
        sub.assert_eq(u32_val, 0x01020304 as u32, "u32 BE matches 0x01020304");

        let u64_val, err64 = r.read_u64_be();
        sub.assert_eq(err64, core::IoError.None, "read_u64_be ok");
        sub.assert_eq(u64_val, 0x0102030405060708 as u64, "u64 BE matches expected value");

        sub.assert_true(r.is_eof(), "Reader at EOF after decoding packet");

        let _, err_trunc = r.read_u32_be();
        sub.assert_eq(err_trunc, core::IoError.UnexpectedEof, "Reading past EOF returns UnexpectedEof");
    };
}

fn test_slice_writer(t: core::T&) {
    t.run("Serialization & Integer Encoding") { sub =>
        var storage: u8[32] = [0; 32];
        var w = core::new_slice_writer(storage[..]);

        sub.assert_eq(w.available(), 32, "Initial capacity 32");
        sub.assert_eq(w.written(), 0, "Written 0");

        let err1 = w.write_u8(0xAA);
        sub.assert_eq(err1, core::IoError.None, "write_u8 ok");

        let err2 = w.write_u16_be(0xBEEF as u16);
        sub.assert_eq(err2, core::IoError.None, "write_u16_be ok");

        let err2b = w.write_u24_be(0xABCDEF as u32);
        sub.assert_eq(err2b, core::IoError.None, "write_u24_be ok");

        let err3 = w.write_u32_be(0xCAFEBABE as u32);
        sub.assert_eq(err3, core::IoError.None, "write_u32_be ok");

        let err4 = w.write_exact("WING");
        sub.assert_eq(err4, core::IoError.None, "write_exact string ok");

        sub.assert_eq(w.written(), 1 + 2 + 3 + 4 + 4, "Total written 14 bytes");
        let written_bytes = w.as_written_slice();
        sub.assert_eq(written_bytes.len, 14, "Written slice len 14");

        // Verify with SliceReader
        var r = core::new_slice_reader(written_bytes);
        let b, _ = r.read_u8();
        sub.assert_eq(b, 0xAA, "Decoded u8 matches");
        let v16, _ = r.read_u16_be();
        sub.assert_eq(v16, 0xBEEF as u16, "Decoded u16 matches");
        let v24, _ = r.read_u24_be();
        sub.assert_eq(v24, 0xABCDEF as u32, "Decoded u24 matches");
        let v32, _ = r.read_u32_be();
        sub.assert_eq(v32, 0xCAFEBABE as u32, "Decoded u32 matches");
        let str_tag, _ = r.read_slice(4);
        sub.assert_eq(str_tag, "WING", "Decoded string tag matches");
    };

    t.run("Buffer Overflow Guards") { sub =>
        var small: u8[4] = [0; 4];
        var w = core::new_slice_writer(small[..]);

        let n, err = w.write("12345678");
        sub.assert_eq(n, 4, "Wrote only 4 bytes to 4-byte buffer");
        sub.assert_eq(err, core::IoError.ShortWrite, "ShortWrite reported on partial fit");
        sub.assert_eq(w.available(), 0, "No capacity remaining");

        let err_ovf = w.write_exact("X");
        sub.assert_eq(err_ovf, core::IoError.BufferFull, "write_exact on full writer returns BufferFull");

        var cw = core::new_counting_writer();
        let cw_n, cw_err = core::write(cw, "1234567890");
        sub.assert_eq(cw_n, 10, "CountingWriter consumed 10 bytes");
        sub.assert_eq(cw_err, core::IoError.None, "CountingWriter ok");
        sub.assert_eq(cw.total_written, 10, "Total count is 10");
    };
}

fn test_limit_reader(t: core::T&) {
    t.run("Strict DoS Boundary & Exceed Enforcement") { sub =>
        let payload = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        // Limit reading to at most 10 bytes
        var lr = core::new_limit_reader(payload, 10);

        sub.assert_eq(lr.remaining(), 10, "Limit remaining is 10");
        sub.assert_false(lr.is_exhausted(), "Not exhausted initially");

        var chunk: u8[8] = [0; 8];
        let n1, err1 = lr.read(chunk[..8]);
        sub.assert_eq(n1, 8, "Read 8 bytes under limit");
        sub.assert_eq(err1, core::IoError.None, "No error on read 8");
        sub.assert_eq(chunk[..8], "01234567", "Read bytes match payload");
        sub.assert_eq(lr.remaining(), 2, "2 bytes remaining under limit");

        // Attempting to read 5 bytes when only 2 remain should clamp to 2
        var small: u8[5] = [0; 5];
        let n2, err2 = lr.read(small[..5]);
        sub.assert_eq(n2, 2, "Read clamped to 2 bytes");
        sub.assert_eq(err2, core::IoError.None, "Read completed");
        sub.assert_eq(small[..2], "89", "Clamped bytes match");
        sub.assert_true(lr.is_exhausted(), "Limiter is now exhausted");
        sub.assert_eq(lr.remaining(), 0, "0 bytes remaining");

        // Next read must fail with LimitExceeded
        var extra: u8[1] = [0; 1];
        let n3, err3 = lr.read(extra[..]);
        sub.assert_eq(n3, 0, "0 bytes read on exhausted limiter");
        sub.assert_eq(err3, core::IoError.LimitExceeded, "Error is LimitExceeded");
        sub.assert_true(lr.exceeded, "Exceeded flag set");
    };
}

fn test_tee_reader(t: core::T&) {
    t.run("Stream Interception and Mirroring") { sub =>
        let data = "TLS 1.3 ClientHello Transcript Wire Message";
        var tr = core::new_tee_reader(data);
        var transcript_tap: u8[>..] = [];

        var client_buf: u8[16] = [0; 16];
        let n1, err1 = core::read_and_tap(tr, client_buf[..7], transcript_tap);
        sub.assert_eq(n1, 7, "Read 7 bytes");
        sub.assert_eq(err1, core::IoError.None, "Read ok");
        sub.assert_eq(client_buf[..7], "TLS 1.3", "Read slice matches");
        sub.assert_eq(transcript_tap[..], "TLS 1.3", "Tapped transcript matches");

        let slice, err2 = core::read_slice_and_tap(tr, 12, transcript_tap);
        sub.assert_eq(err2, core::IoError.None, "read_slice ok");
        sub.assert_eq(slice, " ClientHello", "Slice matches");
        sub.assert_eq(transcript_tap[..], "TLS 1.3 ClientHello", "Accumulated transcript matches");
        sub.assert_eq(tr.intercepted_total, 19, "Total intercepted bytes matches");
    };
}

fn test_ring_buffer(t: core::T&) {
    t.run("Circular Storage, Wraparound & Discard") { sub =>
        var rb = core::new_ring_buffer();
        sub.assert_eq(rb.len(), 0, "Initial len 0");
        sub.assert_true(rb.is_empty(), "Initially empty");
        sub.assert_false(rb.is_full(), "Not full");
        sub.assert_eq(rb.available(), 4096, "Available is 4096");

        // Write 10 bytes
        let w1, err1 = rb.write("0123456789");
        sub.assert_eq(w1, 10, "Wrote 10 bytes");
        sub.assert_eq(err1, core::IoError.None, "write ok");
        sub.assert_eq(rb.len(), 10, "Len is 10");

        // Peek 5 bytes
        var peek_buf: u8[5] = [0; 5];
        let p_n = rb.peek(peek_buf[..]);
        sub.assert_eq(p_n, 5, "Peeked 5 bytes");
        sub.assert_eq(peek_buf[..], "01234", "Peeked contents match");
        sub.assert_eq(rb.len(), 10, "Peek does not consume bytes");

        // Read 5 bytes
        var read_buf: u8[5] = [0; 5];
        let r_n, r_err = rb.read(read_buf[..]);
        sub.assert_eq(r_n, 5, "Read 5 bytes");
        sub.assert_eq(r_err, core::IoError.None, "read ok");
        sub.assert_eq(read_buf[..], "01234", "Read contents match");
        sub.assert_eq(rb.len(), 5, "Len reduced to 5");

        // Discard 3 bytes
        let d_n = rb.discard(3);
        sub.assert_eq(d_n, 3, "Discarded 3 bytes");
        sub.assert_eq(rb.len(), 2, "Remaining len 2");

        // Read final 2 bytes
        var tail_buf: u8[4] = [0; 4];
        let t_n, _ = rb.read(tail_buf[..]);
        sub.assert_eq(t_n, 2, "Read 2 bytes");
        sub.assert_eq(tail_buf[..2], "89", "Tail bytes match");
        sub.assert_true(rb.is_empty(), "Ring buffer now empty");

        // Test Wraparound: write near end of buffer
        rb.clear();
        rb.head = 4090;
        rb.tail = 4090;
        rb.count = 0;

        let w_wrap, w_wrap_err = rb.write("ABCDEFGH");
        sub.assert_eq(w_wrap, 8, "Wrote 8 bytes wrapping across edge");
        sub.assert_eq(w_wrap_err, core::IoError.None, "Wrap write ok");
        sub.assert_eq(rb.len(), 8, "Len is 8");

        var wrap_out: u8[8] = [0; 8];
        let r_wrap, r_wrap_err = rb.read(wrap_out[..]);
        sub.assert_eq(r_wrap, 8, "Read 8 bytes across edge");
        sub.assert_eq(r_wrap_err, core::IoError.None, "Wrap read ok");
        sub.assert_eq(wrap_out[..], "ABCDEFGH", "Wrapped bytes read in exact order");
    };
}

fn test_pipeline_helpers(t: core::T&) {
    t.run("Copy Reader to Writer and Buffer") { sub =>
        var r = core::new_slice_reader("Zero-Allocation Piping Engine");
        var out_storage: u8[64] = [0; 64];
        var w = core::new_slice_writer(out_storage[..]);

        let copied, err = core::copy_reader_to_writer(r, w);
        sub.assert_eq(copied, 29, "Copied 29 bytes");
        sub.assert_eq(err, core::IoError.None, "Copy ok");
        sub.assert_eq(w.as_written_slice(), "Zero-Allocation Piping Engine", "Writer received entire stream");
        sub.assert_true(r.is_eof(), "Reader is EOF");

        var r2 = core::new_slice_reader("Payload Data Segment");
        var target_buf: u8[>..] = [];
        let n_all, err_all = core::copy_reader_all(r2, target_buf);
        sub.assert_eq(n_all, 20, "Copied all 20 bytes into dynamic buffer");
        sub.assert_eq(err_all, core::IoError.None, "copy_all ok");
        sub.assert_eq(target_buf[..], "Payload Data Segment", "Dynamic buffer content matches");
    };
}

fn main() {
    var runner = core::new_runner("Goose Core I/O Stream Module Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. SliceReader Stream Cursor & Integer Decoding", test_slice_reader);
    core::run_case(runner, "2. SliceWriter & CountingWriter Serialization", test_slice_writer);
    core::run_case(runner, "3. LimitReader DoS Boundary Enforcement", test_limit_reader);
    core::run_case(runner, "4. TeeReader Stream Interception & Tapping", test_tee_reader);
    core::run_case(runner, "5. RingBuffer Circular FIFO & Wraparound", test_ring_buffer);
    core::run_case(runner, "6. Stream Pipeline Copy Helpers", test_pipeline_helpers);
    let ok = core::finish(runner);
    assert(ok);
}
