# goose-wing HPACK and QPACK interop vector suite

Conformance and roundtrip verification suite for `http2` HPACK (RFC 7541) and
`http3` QPACK (RFC 9204), compatible with upstream
[`http2jp/hpack-test-case`](https://github.com/http2jp/hpack-test-case) JSON
stories and [`quicwg/qpack`](https://github.com/qpackers/qifs) offline binary
vectors.

## Quick start

### Local bundled RFC vectors

```bash
python tools/hpack_qpack.py --local --suite all
python tools/hpack_qpack.py --local --suite hpack
python tools/hpack_qpack.py --local --suite qpack
```

### Upstream corpus directory or auto-fetch

```bash
python tools/hpack_qpack.py --suite hpack --dir /path/to/hpack-test-case/nghttp2
python tools/hpack_qpack.py --suite qpack --dir /path/to/qifs
python tools/hpack_qpack.py --fetch --suite all
```

### Docker mode

```bash
python tools/hpack_qpack.py --docker --suite all
```

## Verified vectors

| Suite | Coverage | Harnesses |
| :--- | :--- | :--- |
| HPACK (`stories_hpack.json`) | RFC 7541 Appendix C.3, C.4, C.5, C.6, dynamic table size updates (`001xxxxx`), never-indexed (`0x10`), without-indexing (`0x00`), eviction, and error vectors with encoder roundtrip. | `hpack_harness.goose` (`http2::decode_hpack_to_map_with_scratch` and `http2::encode_hpack_field`) |
| QPACK (`stories_qpack.json`) | RFC 9204 Appendix B static/dynamic table inserts, post-base indexing, Huffman literals, `Duplicate`, dynamic name references, blocked stream unblocking, decoder stream instructions, and error vectors with encoder roundtrip. | `qpack_harness.goose` (`http3::qpack_process_encoder_instruction`, `http3::decode_or_block_qpack_section`, and `http3::encode_qpack_field_dynamic`) |
