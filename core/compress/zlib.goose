// The Goose Zlib compression container: RFC 1950 Specification.
namespace wing;

import std;
import core.compress.checksum;
import core.compress.deflate;

// Compresses src into out using RFC 1950 Zlib format.
fn zlib_compress<B>(src: const u8[:], out: B&, level: i32 = 6) -> bool {
    let cmf: u8 = 0x78; // CM=8 (deflate), CINFO=7 (32K window)
    var flg: u32 = if level >= 6 { 0x80 } else { 0x00 }; // FLEVEL

    // Compute FCHECK such that (CMF * 256 + FLG) is a multiple of 31
    let rem = ((cmf as u32) * 256 + flg) % 31;
    if rem != 0 {
        flg += 31 - rem;
    }

    out.push(cmf);
    out.push((flg & 0xFF) as u8);

    // Deflate compressed payload
    guard deflate(src, out, level) else { return false; }

    // 4-byte Adler-32 in Big-Endian
    let a = adler32(src);
    out.push(((a >> 24) & 0xFF) as u8);
    out.push(((a >> 16) & 0xFF) as u8);
    out.push(((a >> 8) & 0xFF) as u8);
    out.push((a & 0xFF) as u8);

    return true;
}

// Decompresses RFC 1950 Zlib stream from src into out.
// Validates headers, FCHECK, Adler-32 checksum.
fn zlib_decompress<B>(src: const u8[:], out: B&) -> CompressError {
    guard src.len >= 6 else { return CompressError.InputBufferTruncated; }

    let cmf = src[0] as u32;
    let flg = src[1] as u32;

    // Check header checksum
    guard (cmf * 256 + flg) % 31 == 0 else {
        return CompressError.InvalidHeader;
    }

    let cm = cmf & 0x0F;
    guard cm == 8 else {
        return CompressError.InvalidHeader;
    }

    // FDICT (bit 5) indicates preset dictionary (not supported in raw RFC 1950)
    let fdict = (flg >> 5) & 1;
    guard fdict == 0 else {
        return CompressError.InvalidHeader;
    }

    let deflate_end = src.len - 4;
    guard 2 <= deflate_end else { return CompressError.InputBufferTruncated; }

    let deflate_payload = src[2..deflate_end];
    let out_start = out.len;

    let err = inflate(deflate_payload, out);
    guard err == CompressError.None else { return err; }

    let decomp_slice = out[out_start..];

    // Read 4-byte Big-Endian Adler-32
    let expected_adler = ((src[deflate_end] as u32) << 24) |
                         ((src[deflate_end + 1] as u32) << 16) |
                         ((src[deflate_end + 2] as u32) << 8) |
                         (src[deflate_end + 3] as u32);

    let actual_adler = adler32(decomp_slice);
    guard actual_adler == expected_adler else {
        return CompressError.ChecksumMismatch;
    }

    return CompressError.None;
}
