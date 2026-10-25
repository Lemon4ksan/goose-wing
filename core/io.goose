// Goose Core I/O Stream Module.
// Provides zero-heap, compile-time inlined streaming abstractions:
// - types: IoError status codes and buffer sizing constants.
// - reader: SliceReader with bounds-checked BE/LE integer decoding and zero-copy slicing.
// - writer: SliceWriter and CountingWriter for bounded serialization.
// - limit: LimitReader for bounded streaming and DoS defense against infinite payloads.
// - tee: TeeReader for simultaneous stream reading and wire tap / transcript hashing.
// - ring: RingBuffer circular FIFO queue for non-blocking network socket buffering.
namespace core;

import std;

import core.io.types;
import core.io.reader;
import core.io.writer;
import core.io.limit;
import core.io.tee;
import core.io.ring;

// Copies bytes from reader to writer up to capacity or EOF.
fn copy_reader_to_writer(r: SliceReader&, w: SliceWriter&) -> i64, IoError {
    let avail = available(w);
    let rem = remaining(r);
    let to_copy = if rem < avail { rem } else { avail };
    guard to_copy > 0 else {
        if is_eof(r) { return 0, IoError.Eof; }
        return 0, IoError.BufferFull;
    }
    let slice, err = read_slice(r, to_copy);
    if err != IoError.None {
        return 0, err;
    }
    let written_n, w_err = write(w, slice);
    return written_n, w_err;
}

// Copies all remaining bytes from reader into an appendable buffer (like u8[>..]).
fn copy_reader_all<B>(r: SliceReader&, out: B&) -> i64, IoError {
    let rem = remaining(r);
    guard rem > 0 else { return 0, IoError.None; }
    let slice, err = read_slice(r, rem);
    if err == IoError.None {
        out.append(slice);
        return rem, IoError.None;
    }
    return 0, err;
}

// Copies exact count bytes from reader into an appendable buffer.
fn copy_reader_n<B>(r: SliceReader&, out: B&, count: i64) -> i64, IoError {
    guard count >= 0 else { return 0, IoError.InvalidArgument; }
    guard remaining(r) >= count else { return 0, IoError.UnexpectedEof; }
    let slice, err = read_slice(r, count);
    if err == IoError.None {
        out.append(slice);
        return count, IoError.None;
    }
    return 0, err;
}
