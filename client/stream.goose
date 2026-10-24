// Incremental streaming, chunked transfer encoding (RFC 9112 Section 7.1),
// and chunked upload/download progress pipeline.
namespace wing;

import std;
import client.profile;
import client.request;
import client.response;

// ---- 1. RFC 9112 Chunked Transfer Framing -----------------------------------

fn format_hex_i64<B>(val: i64, out: B&) {
    let hex_chars: const u8[16] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];
    guard val > 0 else {
        out.push('0');
        return;
    }
    var digits: u8[16] = [0; 16];
    var count = 0;
    var v = val;
    while v > 0 {
        digits[count] = hex_chars[v & 0x0F];
        v = v >> 4;
        count += 1;
    }
    for i in count {
        out.push(digits[count - 1 - i]);
    }
}

// Encodes a single chunk frame: `<hex-size>\r\n<data>\r\n`
fn encode_chunk<B>(data: const u8[:], out: B&) {
    format_hex_i64(data.len, out);
    out.push('\r');
    out.push('\n');
    out.append(data);
    out.push('\r');
    out.push('\n');
}

// Encodes the terminal 0-size chunk: `0\r\n\r\n` (or with trailers)
fn encode_chunk_end<B>(out: B&) {
    out.push('0');
    out.push('\r');
    out.push('\n');
    out.push('\r');
    out.push('\n');
}

// Encodes trailer header: `<name>: <value>\r\n`
fn encode_chunk_trailer<B>(name: const u8[:], val: const u8[:], out: B&) {
    out.append(name);
    out.push(':');
    out.push(' ');
    out.append(val);
    out.push('\r');
    out.push('\n');
}

// ---- 2. Chunk Stream Writer (for Chunked Uploads) ---------------------------

struct ChunkWriter {
    trailers: HeaderItem[..8] = [],
    finished: bool = false,
    buffer: u8[>..] = [],
}

fn new_chunk_writer() -> ChunkWriter {
    return ChunkWriter { .. };
}

fn write_chunk(writer: ChunkWriter&, data: const u8[:]) {
    guard !writer.finished && data.len > 0 else { return; }
    encode_chunk(data, writer.buffer);
}

fn add_trailer(writer: ChunkWriter&, name: const u8[:], val: const u8[:]) {
    guard !writer.finished && writer.trailers.len < writer.trailers.cap else { return; }
    writer.trailers.push(make_header(name, val));
}

fn finish_chunk_writer(writer: ChunkWriter&) {
    guard !writer.finished else { return; }
    writer.finished = true;
    if writer.trailers.len == 0 {
        encode_chunk_end(writer.buffer);
    } else {
        writer.buffer.push('0');
        writer.buffer.push('\r');
        writer.buffer.push('\n');
        for &t in writer.trailers {
            encode_chunk_trailer(t.name[..], t.value[..], writer.buffer);
        }
        writer.buffer.push('\r');
        writer.buffer.push('\n');
    }
}

// ---- 3. Incremental Stream Reader & Progress Tracking -----------------------

struct StreamProgress {
    bytes_processed: u64 = 0,
    total_bytes: i64 = -1,
    percent: f64 = 0.0,
    is_finished: bool = false,
}

struct StreamReader {
    cursor: i64 = 0,
    content_length: i64 = -1,
    is_chunked: bool = false,
    bytes_read: u64 = 0,
    finished: bool = false,
    raw_data: u8[>..] = [],
}

fn new_stream_reader(resp: const Response&) -> StreamReader {
    var reader = StreamReader { .. };
    reader.raw_data.append(resp.body[..]);

    let te = header(resp, "Transfer-Encoding");
    if eq_ascii_fold(te, "chunked") {
        reader.is_chunked = true;
    }

    let cl = header(resp, "Content-Length");
    if cl.len > 0 {
        var num: i64 = 0;
        var has_digit = false;
        for b in cl {
            if b >= '0' && b <= '9' {
                num = num * 10 + (b - '0');
                has_digit = true;
            }
        }
        if has_digit {
            reader.content_length = num;
        }
    }
    return reader;
}

// Reads the next chunk from the stream (up to max_bytes).
// Returns (has_bytes, is_eof).
fn read_chunk<B>(reader: StreamReader&, max_bytes: i64, out: B&) -> bool, bool {
    guard !reader.finished else { return false, true; }

    let remaining = reader.raw_data.len - reader.cursor;
    guard remaining > 0 else {
        reader.finished = true;
        return false, true;
    }

    let to_read = if remaining < max_bytes { remaining } else { max_bytes };
    out.clear();
    out.append(reader.raw_data[reader.cursor..reader.cursor + to_read]);
    reader.cursor += to_read;
    reader.bytes_read += to_read as! u64;

    if reader.cursor >= reader.raw_data.len {
        reader.finished = true;
        return true, true;
    }
    return true, false;
}

// Reads all remaining data from the stream into out buffer
fn read_all<B>(reader: StreamReader&, out: B&) -> u64 {
    guard !reader.finished else { return 0; }
    let remaining = reader.raw_data.len - reader.cursor;
    guard remaining > 0 else {
        reader.finished = true;
        return 0;
    }
    out.append(reader.raw_data[reader.cursor..]);
    reader.cursor = reader.raw_data.len;
    reader.bytes_read += remaining as! u64;
    reader.finished = true;
    return remaining as! u64;
}

// Calculates current stream progress
fn stream_progress(reader: const StreamReader&) -> StreamProgress {
    var p = StreamProgress {
        bytes_processed: reader.bytes_read,
        total_bytes: reader.content_length,
        is_finished: reader.finished,
        ..
    };
    if reader.content_length > 0 {
        p.percent = (reader.bytes_read as! f64 / reader.content_length) * 100.0;
        if p.percent > 100.0 { p.percent = 100.0; }
    }
    return p;
}
