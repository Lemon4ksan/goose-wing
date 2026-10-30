// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// The Goose Streaming Compression engine: ZStream, Flush Modes, and Auto-Detection.
namespace core;

import std;
import core.math.bits;
import core.compress.checksum;
import core.compress.deflate;
import core.compress.gzip;
import core.compress.zlib;
import core.compress.zstd;

// ---- flush modes & container formats ---------------------------------------

enum FlushMode {
    NoFlush,
    PartialFlush,
    SyncFlush,
    FullFlush,
    Finish,
}

enum ContainerFormat {
    Raw,
    Zlib,
    Gzip,
    Zstd,
    Auto,
}

// Auto-detects the container format of a compressed byte stream.
fn detect_container_format(src: const u8[:]) -> ContainerFormat {
    if src.len >= 4 {
        let magic = read_le_u32(src, 0);
        if magic == 0xFD2FB528 {
            return ContainerFormat.Zstd;
        }
    }
    if src.len >= 10 && src[0] == 0x1F && src[1] == 0x8B && src[2] == 0x08 && ((src[3] & 0xE0) == 0) {
        return ContainerFormat.Gzip;
    }
    if src.len >= 6 {
        let cmf = src[0] as u32;
        let flg = src[1] as u32;
        let cm = cmf & 0x0F;
        let cinfo = (cmf >> 4) & 0x0F;
        if cm == 8 && cinfo <= 7 && (((cmf * 256 + flg) % 31) == 0) {
            return ContainerFormat.Zlib;
        }
    }
    return ContainerFormat.Raw;
}

// ---- zstream compressor ----------------------------------------------------

struct ZStreamCompressor {
    format:         ContainerFormat = ContainerFormat.Raw,
    level:          i32             = 6,
    w:              BitWriter       = BitWriter { bit_buf: 0, bit_count: 0 },
    window:         u8[32768]       = [0; 32768],
    window_len:     i32             = 0,
    dict:           const u8[:]     = "",
    total_in:       u64             = 0,
    total_out:      u64             = 0,
    adler:          u32             = 1,
    crc:            u32             = 0,
    header_written: bool            = false,
    is_finished:    bool            = false,
}

fn new_zstream_compressor(format: ContainerFormat = ContainerFormat.Raw, level: i32 = 6) -> ZStreamCompressor {
    return ZStreamCompressor {
        format:         format,
        level:          level,
        w:              BitWriter { bit_buf: 0, bit_count: 0 },
        window:         [0; 32768],
        window_len:     0,
        dict:           "",
        total_in:       0,
        total_out:      0,
        adler:          1,
        crc:            0,
        header_written: false,
        is_finished:    false,
    };
}

fn zstream_set_dictionary(s: ZStreamCompressor&, dict: const u8[:]) {
    s.dict = dict;
}

fn write_container_header<B>(s: ZStreamCompressor&, out: B&) {
    if s.header_written { return; }
    if s.format == ContainerFormat.Zlib {
        let cmf: u8 = 0x78;
        var flg: u32 = if s.level >= 6 { 0x80 } else { 0x00 };
        if s.dict.len > 0 {
            flg |= 0x20; // FDICT
        }
        let rem = ((cmf as u32) * 256 + flg) % 31;
        if rem != 0 { flg += 31 - rem; }
        out.push(cmf);
        out.push((flg & 0xFF) as u8);

        if s.dict.len > 0 {
            let dict_adler = adler32(s.dict);
            out.push(((dict_adler >> 24) & 0xFF) as u8);
            out.push(((dict_adler >> 16) & 0xFF) as u8);
            out.push(((dict_adler >> 8) & 0xFF) as u8);
            out.push((dict_adler & 0xFF) as u8);
        }
    } else if s.format == ContainerFormat.Gzip {
        out.push(0x1F);
        out.push(0x8B);
        out.push(0x08);
        out.push(0x00);
        out.push(0x00);
        out.push(0x00);
        out.push(0x00);
        out.push(0x00);
        out.push(0x00);
        out.push(0xFF);
    }
    s.header_written = true;
}

fn update_stream_checksums(s: ZStreamCompressor&, chunk: const u8[:]) {
    if chunk.len == 0 { return; }
    if s.format == ContainerFormat.Zlib {
        s.adler = adler32_update(s.adler, chunk);
    } else if s.format == ContainerFormat.Gzip {
        s.crc = crc32_update(s.crc, chunk);
    }
    s.total_in += chunk.len as u64;
}

fn update_stream_sliding_window(s: ZStreamCompressor&, chunk: const u8[:]) {
    if chunk.len >= 32768 {
        let start = chunk.len - 32768;
        for i in 32768 {
            s.window[i] = chunk[start + i];
        }
        s.window_len = 32768;
    } else if chunk.len > 0 {
        let clen = chunk.len as i32;
        let to_keep = if s.window_len + clen > 32768 { 32768 - clen } else { s.window_len };
        let shift = s.window_len - to_keep;
        if shift > 0 {
            for i in to_keep {
                s.window[i] = s.window[shift + i];
            }
        }
        for i in chunk.len {
            s.window[to_keep + i] = chunk[i];
        }
        s.window_len = to_keep + clen;
    }
}

fn emit_sync_flush_marker<B>(s: ZStreamCompressor&, out: B&) {
    write_bits(s.w, 0, 3, out);
    flush_bits(s.w, out);
    out.push(0x00);
    out.push(0x00);
    out.push(0xFF);
    out.push(0xFF);
}

fn emit_stream_trailer<B>(s: ZStreamCompressor&, out: B&) {
    flush_bits(s.w, out);
    if s.format == ContainerFormat.Zlib {
        out.push(((s.adler >> 24) & 0xFF) as u8);
        out.push(((s.adler >> 16) & 0xFF) as u8);
        out.push(((s.adler >> 8) & 0xFF) as u8);
        out.push((s.adler & 0xFF) as u8);
    } else if s.format == ContainerFormat.Gzip {
        out.push((s.crc & 0xFF) as u8);
        out.push(((s.crc >> 8) & 0xFF) as u8);
        out.push(((s.crc >> 16) & 0xFF) as u8);
        out.push(((s.crc >> 24) & 0xFF) as u8);

        let sz = (s.total_in & 0xFFFFFFFF) as u32;
        out.push((sz & 0xFF) as u8);
        out.push(((sz >> 8) & 0xFF) as u8);
        out.push(((sz >> 16) & 0xFF) as u8);
        out.push(((sz >> 24) & 0xFF) as u8);
    }
    s.is_finished = true;
}

fn zstream_write<B>(s: ZStreamCompressor&, chunk: const u8[:], out: B&, flush: FlushMode = FlushMode.NoFlush) -> bool {
    guard !s.is_finished else { return false; }

    let out_before = out.len;
    write_container_header(s, out);
    update_stream_checksums(s, chunk);

    let is_final = (flush == FlushMode.Finish);
    if chunk.len > 0 || (is_final && !s.is_finished) {
        let hist = if s.window_len > 0 { s.window[..s.window_len] } else { s.dict };
        let ok = deflate_block(chunk, out, s.w, s.level, is_final, hist);
        guard ok else { return false; }
        update_stream_sliding_window(s, chunk);
    }

    if flush == FlushMode.SyncFlush {
        emit_sync_flush_marker(s, out);
    } else if flush == FlushMode.FullFlush {
        emit_sync_flush_marker(s, out);
        s.window_len = 0;
        s.dict = "";
    } else if flush == FlushMode.Finish {
        emit_stream_trailer(s, out);
    }

    s.total_out += (out.len - out_before) as u64;
    return true;
}

fn zstream_sync_flush<B>(s: ZStreamCompressor&, out: B&) -> bool {
    let empty: u8[0] = [];
    return zstream_write(s, empty[..], out, FlushMode.SyncFlush);
}

fn zstream_full_flush<B>(s: ZStreamCompressor&, out: B&) -> bool {
    let empty: u8[0] = [];
    return zstream_write(s, empty[..], out, FlushMode.FullFlush);
}

fn zstream_finish<B>(s: ZStreamCompressor&, out: B&) -> bool {
    let empty: u8[0] = [];
    return zstream_write(s, empty[..], out, FlushMode.Finish);
}

// ---- zstream decompressor --------------------------------------------------

struct ZStreamDecompressor {
    format:           ContainerFormat = ContainerFormat.Auto,
    dict:             const u8[:]     = "",
    window:           u8[32768]       = [0; 32768],
    window_len:       i32             = 0,
    total_in:         u64             = 0,
    total_out:        u64             = 0,
    adler:            u32             = 1,
    crc:              u32             = 0,
    header_parsed:    bool            = false,
    deflate_finished: bool            = false,
    is_finished:      bool            = false,
    in_buf:           u8[>..]         = [],
}

fn new_zstream_decompressor(
    format: ContainerFormat = ContainerFormat.Auto,
    dict:   const u8[:]     = "",
) -> ZStreamDecompressor {
    return ZStreamDecompressor {
        format:           format,
        dict:             dict,
        window:           [0; 32768],
        window_len:       0,
        total_in:         0,
        total_out:        0,
        adler:            1,
        crc:              0,
        header_parsed:    false,
        deflate_finished: false,
        is_finished:      false,
        in_buf:           [],
    };
}

fn zstream_decompress_set_dictionary(d: ZStreamDecompressor&, dict: const u8[:]) {
    d.dict = dict;
}

// Discards consumed bytes from front of internal input buffer.
fn drain_in_buf(d: ZStreamDecompressor&, consumed: i64) {
    if consumed >= d.in_buf.len {
        d.in_buf.clear();
    } else if consumed > 0 {
        let remaining = d.in_buf.len - consumed;
        for i in remaining {
            d.in_buf[i] = d.in_buf[consumed + i];
        }
        d.in_buf.resize(remaining);
    }
}

// Updates the internal 32KB sliding dictionary window with newly decompressed bytes.
fn update_sliding_window(d: ZStreamDecompressor&, temp_out: const u8[:]) {
    if temp_out.len >= 32768 {
        let start = temp_out.len - 32768;
        for i in 32768 {
            d.window[i] = temp_out[start + i];
        }
        d.window_len = 32768;
        return;
    }
    guard temp_out.len > 0 else { return; }
    let nlen = temp_out.len as i32;
    let to_keep = if d.window_len + nlen > 32768 { 32768 - nlen } else { d.window_len };
    let shift = d.window_len - to_keep;
    if shift > 0 {
        for i in to_keep {
            d.window[i] = d.window[shift + i];
        }
    }
    for i in temp_out.len {
        d.window[to_keep + i] = temp_out[i];
    }
    d.window_len = to_keep + nlen;
}

// Parses container header for streaming decompression.
//
// Example:
//   d.format = ContainerFormat.Auto, d.in_buf = [0x1F, 0x8B, ...]
//   returns: CompressError.None
fn parse_stream_header(d: ZStreamDecompressor&) -> CompressError {
    if d.format == ContainerFormat.Auto {
        if d.in_buf.len < 4 {
            return CompressError.None;
        }
        d.format = detect_container_format(d.in_buf[..]);
        if d.format == ContainerFormat.Auto || (d.format == ContainerFormat.Raw && d.in_buf.len < 10) {
            return CompressError.None;
        }
    }

    if d.format == ContainerFormat.Zstd {
        d.header_parsed = true;
        return CompressError.None;
    }
    if d.format == ContainerFormat.Gzip {
        let offset, err = parse_gzip_header_offset(d.in_buf[..], 0);
        if err == CompressError.InputBufferTruncated {
            return CompressError.None;
        }
        guard err == CompressError.None else { return err; }
        drain_in_buf(d, offset);
        d.header_parsed = true;
        return CompressError.None;
    }
    if d.format == ContainerFormat.Zlib {
        if d.in_buf.len < 2 {
            return CompressError.None;
        }
        let cmf: u32 = d.in_buf[0];
        let flg: u32 = d.in_buf[1];
        guard (cmf * 256 + flg) % 31 == 0 && (cmf & 0x0F) == 8 && (cmf >> 4) <= 7 else {
            return CompressError.InvalidHeader;
        }
        var hdr_len: i64 = 2;
        if ((flg >> 5) & 1) != 0 {
            if d.in_buf.len < 6 {
                return CompressError.None;
            }
            guard d.dict.len > 0 else { return CompressError.NeedDictionary; }
            guard adler32(d.dict) == read_be_u32(d.in_buf[..], 2) else {
                return CompressError.DictionaryMismatch;
            }
            hdr_len = 6;
        }
        drain_in_buf(d, hdr_len);
        d.header_parsed = true;
        return CompressError.None;
    }

    d.header_parsed = true;
    return CompressError.None;
}

// Resumable streaming decompression feeding arbitrary byte chunks (from 1 byte to multi-KB TCP slices).
// Buffers incoming data, rolls back partial blocks on truncation, and enforces output quota guard.
fn zstream_decompress_write_limit<B>(
    d:                ZStreamDecompressor&,
    chunk:            const u8[:],
    out:              B&,
    max_output_bytes: i64 = 0,
) -> CompressError {
    if d.is_finished {
        guard chunk.len == 0 else { return CompressError.CorruptedBitstream; }
        return CompressError.None;
    }
    d.in_buf.append(chunk);
    d.total_in += chunk.len as u64;

    // Phase 1: Parse container header
    if !d.header_parsed {
        let hdr_err = parse_stream_header(d);
        guard hdr_err == CompressError.None else { return hdr_err; }
        guard d.header_parsed else { return CompressError.None; }
    }

    // Phase 1.5: Zstandard Frame Streaming
    if d.format == ContainerFormat.Zstd {
        if !d.is_finished {
            var temp_out: u8[>..] = [];
            let z_limit = if max_output_bytes > 0 { max_output_bytes } else { -1 };
            let ok_z, err = zstd_decompress_with_limit(d.in_buf[..], temp_out, z_limit);
            if err == CompressError.InputBufferTruncated {
                return CompressError.None; // Partial frame: wait for more bytes
            }
            guard ok_z else { return err; }

            out.append(temp_out[..]);
            d.total_out += temp_out.len as u64;
            drain_in_buf(d, d.in_buf.len);
            d.deflate_finished = true;
            d.is_finished = true;
            return CompressError.None;
        }
        return CompressError.None;
    }

    // Phase 2: Decompress Deflate payload
    if !d.deflate_finished {
        let hist = if d.window_len > 0 { d.window[..d.window_len] } else { d.dict };
        var temp_out: u8[>..] = [];
        let stream_limit = if max_output_bytes > 0 {
            let produced = d.total_out as i64;
            if produced >= max_output_bytes { return CompressError.OutputBufferOverflow; }
            max_output_bytes - produced
        } else { 0 };
        let err, consumed = inflate_ex(d.in_buf[..], temp_out, hist, stream_limit);
        if err == CompressError.InputBufferTruncated {
            return CompressError.None; // Partial block: wait for more bytes
        }
        guard err == CompressError.None else { return err; }

        let new_len = temp_out.len;
        out.append(temp_out[..]);
        d.total_out += new_len as u64;

        if d.format == ContainerFormat.Zlib {
            d.adler = adler32_update(d.adler, temp_out[..]);
        } else if d.format == ContainerFormat.Gzip {
            d.crc = crc32_update(d.crc, temp_out[..]);
        }

        update_sliding_window(d, temp_out[..]);
        drain_in_buf(d, consumed);
        d.deflate_finished = true;
    }

    // Phase 3: Validate trailer
    if d.deflate_finished && !d.is_finished {
        if d.format == ContainerFormat.Zlib {
            if d.in_buf.len < 4 {
                return CompressError.None; // Wait for Adler-32
            }
            let expected_adler = read_be_u32(d.in_buf[..], 0);
            guard d.adler == expected_adler else { return CompressError.ChecksumMismatch; }
            drain_in_buf(d, 4);
            // RFC 1950 exact finality: Zlib stream trailer ends at Adler-32
            guard d.in_buf.len == 0 else { return CompressError.CorruptedBitstream; }
            d.is_finished = true;
        } else if d.format == ContainerFormat.Gzip {
            if d.in_buf.len < 8 {
                return CompressError.None; // Wait for CRC + ISIZE
            }
            let expected_crc = read_le_u32(d.in_buf[..], 0);
            let expected_isize = read_le_u32(d.in_buf[..], 4);
            guard d.crc == expected_crc else { return CompressError.ChecksumMismatch; }
            let actual_isize = (d.total_out & 0xFFFFFFFF) as u32;
            guard actual_isize == expected_isize else { return CompressError.SizeMismatch; }
            drain_in_buf(d, 8);
            d.is_finished = true;
        } else {
            d.is_finished = true;
        }
    }

    return CompressError.None;
}

fn zstream_decompress_write<B>(d: ZStreamDecompressor&, chunk: const u8[:], out: B&) -> CompressError {
    return zstream_decompress_write_limit(d, chunk, out, 0);
}

// Auto-detects container format (Gzip, Zlib, or raw Deflate) and decompresses src into out.
fn decompress_auto<B>(src: const u8[:], out: B&, dict: const u8[:] = "") -> bool, CompressError {
    let fmt = detect_container_format(src);
    if fmt == ContainerFormat.Zstd {
        return zstd_decompress(src, out);
    } else if fmt == ContainerFormat.Gzip {
        return gzip_decompress(src, out);
    } else if fmt == ContainerFormat.Zlib {
        return zlib_decompress_with_dict(src, out, dict);
    } else {
        return inflate_with_dict(src, out, dict);
    }
}

// ---- native methods & ufcs -------------------------------------------------

fn write<B>(s: ZStreamCompressor&, chunk: const u8[:], out: B&, flush: FlushMode = FlushMode.NoFlush) -> bool {
    return zstream_write(s, chunk, out, flush);
}

fn sync_flush<B>(s: ZStreamCompressor&, out: B&) -> bool {
    return zstream_sync_flush(s, out);
}

fn full_flush<B>(s: ZStreamCompressor&, out: B&) -> bool {
    return zstream_full_flush(s, out);
}

fn finish<B>(s: ZStreamCompressor&, out: B&) -> bool {
    return zstream_finish(s, out);
}

fn set_dictionary(s: ZStreamCompressor&, dict: const u8[:]) {
    zstream_set_dictionary(s, dict);
}

fn write<B>(d: ZStreamDecompressor&, chunk: const u8[:], out: B&) -> CompressError {
    return zstream_decompress_write(d, chunk, out);
}

fn write_with_limit<B>(d: ZStreamDecompressor&, chunk: const u8[:], out: B&, max_output_bytes: i64) -> CompressError {
    return zstream_decompress_write_limit(d, chunk, out, max_output_bytes);
}

fn set_dictionary(d: ZStreamDecompressor&, dict: const u8[:]) {
    zstream_decompress_set_dictionary(d, dict);
}
