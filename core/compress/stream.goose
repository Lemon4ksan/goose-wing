// The Goose Streaming Compression engine: ZStream, Flush Modes, and Auto-Detection.
namespace wing;

import std;
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
        let magic = (src[0]) | ((src[1] as u32) << 8) | ((src[2] as u32) << 16) | ((src[3] as u32) << 24);
        if magic == 0xFD2FB528 {
            return ContainerFormat.Zstd;
        }
    }
    if src.len >= 10 && src[0] == 0x1F && src[1] == 0x8B && src[2] == 0x08 {
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
    format: ContainerFormat = ContainerFormat.Raw,
    level: i32 = 6,
    w: BitWriter = BitWriter { bit_buf: 0, bit_count: 0 },
    window: u8[32768] = [0; 32768],
    window_len: i32 = 0,
    dict: const u8[:] = "",
    total_in: u64 = 0,
    total_out: u64 = 0,
    adler: u32 = 1,
    crc: u32 = 0,
    header_written: bool = false,
    is_finished: bool = false,
}

fn new_zstream_compressor(format: ContainerFormat = ContainerFormat.Raw, level: i32 = 6) -> ZStreamCompressor {
    return ZStreamCompressor {
        format: format,
        level: level,
        w: BitWriter { bit_buf: 0, bit_count: 0 },
        window: [0; 32768],
        window_len: 0,
        dict: "",
        total_in: 0,
        total_out: 0,
        adler: 1,
        crc: 0,
        header_written: false,
        is_finished: false,
    };
}

fn zstream_set_dictionary(s: ZStreamCompressor&, dict: const u8[:]) {
    s.dict = dict;
}

fn zstream_write<B>(s: ZStreamCompressor&, chunk: const u8[:], out: B&, flush: FlushMode = FlushMode.NoFlush) -> bool {
    guard !s.is_finished else { return false; }

    let out_before = out.len;

    // 1. Write container header if not yet written
    if !s.header_written {
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

    // 2. Update rolling checksums
    if chunk.len > 0 {
        if s.format == ContainerFormat.Zlib {
            s.adler = adler32_update(s.adler, chunk);
        } else if s.format == ContainerFormat.Gzip {
            s.crc = crc32_update(s.crc, chunk);
        }
        s.total_in += chunk.len as u64;
    }

    // 3. Compress chunk block
    let is_final = (flush == FlushMode.Finish);
    if chunk.len > 0 || (is_final && !s.is_finished) {
        let hist = if s.window_len > 0 { s.window[..s.window_len] } else { s.dict };
        let ok = deflate_block(chunk, out, s.w, s.level, is_final, hist);
        guard ok else { return false; }

        if chunk.len >= 32768 {
            let start = chunk.len - 32768;
            for i in 32768 {
                s.window[i] = chunk[start + (i as i64)];
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
                s.window[(to_keep as i64) + i] = chunk[i];
            }
            s.window_len = to_keep + clen;
        }
    }

    // 4. Handle flush modes
    if flush == FlushMode.SyncFlush {
        write_bits(s.w, 0, 3, out);
        flush_bits(s.w, out);
        out.push(0x00);
        out.push(0x00);
        out.push(0xFF);
        out.push(0xFF);
    } else if flush == FlushMode.FullFlush {
        write_bits(s.w, 0, 3, out);
        flush_bits(s.w, out);
        out.push(0x00);
        out.push(0x00);
        out.push(0xFF);
        out.push(0xFF);
        s.window_len = 0;
        s.dict = "";
    } else if flush == FlushMode.Finish {
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
    format: ContainerFormat = ContainerFormat.Auto,
    dict: const u8[:] = "",
    window: u8[32768] = [0; 32768],
    window_len: i32 = 0,
    total_in: u64 = 0,
    total_out: u64 = 0,
    adler: u32 = 1,
    crc: u32 = 0,
    header_parsed: bool = false,
    deflate_finished: bool = false,
    is_finished: bool = false,
    in_buf: u8[>..] = [],
}

fn new_zstream_decompressor(format: ContainerFormat = ContainerFormat.Auto, dict: const u8[:] = "") -> ZStreamDecompressor {
    return ZStreamDecompressor {
        format: format,
        dict: dict,
        window: [0; 32768],
        window_len: 0,
        total_in: 0,
        total_out: 0,
        adler: 1,
        crc: 0,
        header_parsed: false,
        deflate_finished: false,
        is_finished: false,
        in_buf: [],
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

// Resumable streaming decompression feeding arbitrary byte chunks (from 1 byte to multi-KB TCP slices).
// Buffers incoming data, rolls back partial blocks on truncation, and enforces output quota guard.
fn zstream_decompress_write_limit<B>(
    d: ZStreamDecompressor&,
    chunk: const u8[:],
    out: B&,
    max_output_bytes: i64 = 0,
) -> CompressError {
    d.in_buf.append(chunk);
    d.total_in += chunk.len as u64;

    if d.is_finished {
        return CompressError.None;
    }

    // Phase 1: Parse container header
    if !d.header_parsed {
        if d.format == ContainerFormat.Auto {
            if d.in_buf.len < 10 {
                return CompressError.None;
            }
            d.format = detect_container_format(d.in_buf[..]);
        }

        if d.format == ContainerFormat.Gzip {
            let offset, err = parse_gzip_header_offset(d.in_buf[..], 0);
            if err == CompressError.InputBufferTruncated {
                return CompressError.None;
            }
            guard err == CompressError.None else { return err; }
            drain_in_buf(d, offset);
            d.header_parsed = true;
        } else if d.format == ContainerFormat.Zlib {
            if d.in_buf.len < 2 {
                return CompressError.None;
            }
            let cmf: u32 = d.in_buf[0];
            let flg: u32 = d.in_buf[1];
            guard (cmf * 256 + flg) % 31 == 0 && (cmf & 0x0F) == 8 else {
                return CompressError.InvalidHeader;
            }
            var hdr_len: i64 = 2;
            if ((flg >> 5) & 1) != 0 {
                if d.in_buf.len < 6 {
                    return CompressError.None;
                }
                guard d.dict.len > 0 else { return CompressError.NeedDictionary; }
                guard adler32(d.dict) == read_zlib_u32_be(d.in_buf[..], 2) else {
                    return CompressError.DictionaryMismatch;
                }
                hdr_len = 6;
            }
            drain_in_buf(d, hdr_len);
            d.header_parsed = true;
        } else {
            d.header_parsed = true;
        }
    }

    // Phase 2: Decompress Deflate payload
    if !d.deflate_finished {
        let hist = if d.window_len > 0 { d.window[..d.window_len] } else { d.dict };
        var temp_out: u8[>..] = [];
        let err, consumed = inflate_ex(d.in_buf[..], temp_out, hist, max_output_bytes);
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

        if temp_out.len >= 32768 {
            let start = temp_out.len - 32768;
            for i in 32768 {
                d.window[i] = temp_out[start + (i as i64)];
            }
            d.window_len = 32768;
        } else if temp_out.len > 0 {
            let nlen = temp_out.len as i32;
            let to_keep = if d.window_len + nlen > 32768 { 32768 - nlen } else { d.window_len };
            let shift = d.window_len - to_keep;
            if shift > 0 {
                for i in to_keep {
                    d.window[i] = d.window[shift + i];
                }
            }
            for i in temp_out.len {
                d.window[(to_keep as i64) + i] = temp_out[i];
            }
            d.window_len = to_keep + nlen;
        }

        drain_in_buf(d, consumed);
        d.deflate_finished = true;
    }

    // Phase 3: Validate trailer
    if d.deflate_finished && !d.is_finished {
        if d.format == ContainerFormat.Zlib {
            if d.in_buf.len < 4 {
                return CompressError.None; // Wait for Adler-32
            }
            let expected_adler = read_zlib_u32_be(d.in_buf[..], 0);
            guard d.adler == expected_adler else { return CompressError.ChecksumMismatch; }
            drain_in_buf(d, 4);
            d.is_finished = true;
        } else if d.format == ContainerFormat.Gzip {
            if d.in_buf.len < 8 {
                return CompressError.None; // Wait for CRC + ISIZE
            }
            let expected_crc = read_gzip_u32_le(d.in_buf[..], 0);
            let expected_isize = read_gzip_u32_le(d.in_buf[..], 4);
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
fn decompress_auto<B>(src: const u8[:], out: B&, dict: const u8[:] = "") -> CompressError {
    let fmt = detect_container_format(src);
    if fmt == ContainerFormat.Zstd {
        return zstd_decompress(src, out);
    } else if fmt == ContainerFormat.Gzip {
        let ok, err = decompress_gzip(src, out);
        return err;
    } else if fmt == ContainerFormat.Zlib {
        return zlib_decompress_with_dict(src, out, dict);
    } else {
        return inflate_with_dict(src, out, dict);
    }
}

// ---- ufcs bridges ----------------------------------------------------------

fn ::write<B>(s: wing::ZStreamCompressor&, chunk: const u8[:], out: B&, flush: wing::FlushMode = wing::FlushMode.NoFlush) -> bool {
    return wing::zstream_write(s, chunk, out, flush);
}

fn ::sync_flush<B>(s: wing::ZStreamCompressor&, out: B&) -> bool {
    return wing::zstream_sync_flush(s, out);
}

fn ::full_flush<B>(s: wing::ZStreamCompressor&, out: B&) -> bool {
    return wing::zstream_full_flush(s, out);
}

fn ::finish<B>(s: wing::ZStreamCompressor&, out: B&) -> bool {
    return wing::zstream_finish(s, out);
}

fn ::set_dictionary(s: wing::ZStreamCompressor&, dict: const u8[:]) {
    wing::zstream_set_dictionary(s, dict);
}

fn ::write<B>(d: wing::ZStreamDecompressor&, chunk: const u8[:], out: B&) -> wing::CompressError {
    return wing::zstream_decompress_write(d, chunk, out);
}

fn ::write_with_limit<B>(d: wing::ZStreamDecompressor&, chunk: const u8[:], out: B&, max_output_bytes: i64) -> wing::CompressError {
    return wing::zstream_decompress_write_limit(d, chunk, out, max_output_bytes);
}

fn ::set_dictionary(d: wing::ZStreamDecompressor&, dict: const u8[:]) {
    wing::zstream_decompress_set_dictionary(d, dict);
}
