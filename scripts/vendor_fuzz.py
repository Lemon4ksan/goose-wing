#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""scripts/vendor_fuzz.py.

Reproducible upstream vendor repository bootstrapper, seed corpus harvester,
and end-to-end fuzzing / differential verification runner for goose-wing.

Usage:
  # Clone missing fuzz-corpus repositories into vendor/ and run all fuzz suites:
  python scripts/vendor_fuzz.py --sync

  # Clone all 59 upstream reference repositories into vendor/:
  python scripts/vendor_fuzz.py --sync-all

  # Harvest existing vendor/ corpora and run differential + SanCov + OSS-Fuzz suites:
  python scripts/vendor_fuzz.py
"""

import argparse
import hashlib
import random
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class VendorRepo:
    name: str
    url: str
    category: str
    has_fuzz_corpus: bool = False
    submodules: tuple[str, ...] = ()


VENDOR_REPOS: tuple[VendorRepo, ...] = (
    # Core fuzzing, corpus, and Wycheproof/BoGo reference repositories
    VendorRepo("h2o", "https://github.com/h2o/h2o.git", "http", True),
    VendorRepo("nghttp2", "https://github.com/nghttp2/nghttp2.git", "http", True),
    VendorRepo("nghttp3", "https://github.com/ngtcp2/nghttp3.git", "quic", True),
    VendorRepo("ngtcp2", "https://github.com/ngtcp2/ngtcp2.git", "quic", True),
    VendorRepo("quiche", "https://github.com/cloudflare/quiche.git", "quic", True),
    VendorRepo("quinn", "https://github.com/quinn-rs/quinn.git", "quic", True),
    VendorRepo("rustls", "https://github.com/rustls/rustls.git", "tls", True),
    VendorRepo("picotls", "https://github.com/h2o/picotls.git", "tls", True),
    VendorRepo("s2n-tls", "https://github.com/aws/s2n-tls.git", "tls", True),
    VendorRepo("mbedtls", "https://github.com/Mbed-TLS/mbedtls.git", "tls", True),
    VendorRepo("openssl", "https://github.com/openssl/openssl.git", "tls", True),
    VendorRepo(
        "uWebSockets",
        "https://github.com/uNetworking/uWebSockets.git",
        "ws",
        True,
        submodules=("uSockets",),
    ),
    VendorRepo("tungstenite", "https://github.com/snapview/tungstenite-rs.git", "ws", True),
    VendorRepo("libwebsockets", "https://github.com/warmcat/libwebsockets.git", "ws", True),
    VendorRepo("sfparse", "https://github.com/ngtcp2/sfparse.git", "cookie_sfv", True),
    VendorRepo("libpsl", "https://github.com/rockdaboot/libpsl.git", "cookie_sfv", True),
    VendorRepo("cookie-rs", "https://github.com/rwf2/cookie-rs.git", "cookie_sfv", True),
    VendorRepo("llhttp", "https://github.com/nodejs/llhttp.git", "http", True),
    VendorRepo("httparse", "https://github.com/seanmonstar/httparse.git", "http", True),
    VendorRepo("zstd", "https://github.com/facebook/zstd.git", "compress", True),
    # Additional protocol, transport, and reactor reference repositories
    VendorRepo("bearssl", "https://www.bearssl.org/git/BearSSL", "tls"),
    VendorRepo("cjose", "https://github.com/cisco/cjose.git", "auth"),
    VendorRepo("connect-go", "https://github.com/connectrpc/connect-go.git", "http"),
    VendorRepo("cookie_store", "https://github.com/pfernie/cookie_store.git", "cookie_sfv"),
    VendorRepo("curl", "https://github.com/curl/curl.git", "http"),
    VendorRepo("dpdk", "https://github.com/DPDK/dpdk.git", "io"),
    VendorRepo("fasthttp", "https://github.com/valyala/fasthttp.git", "http"),
    VendorRepo("goostr", "https://github.com/sstadick/goostr", "compress"),
    VendorRepo("governor", "https://github.com/antifuchs/governor.git", "http"),
    VendorRepo("grpc-go", "https://github.com/grpc/grpc-go.git", "http"),
    VendorRepo("h2", "https://github.com/hyperium/h2.git", "http"),
    VendorRepo("haproxy", "https://github.com/haproxy/haproxy.git", "http"),
    VendorRepo("hparse", "https://github.com/nikneym/hparse.git", "http"),
    VendorRepo("jsonwebtoken", "https://github.com/Keats/jsonwebtoken.git", "auth"),
    VendorRepo("libjwt", "https://github.com/benmcollins/libjwt.git", "auth"),
    VendorRepo("liburing", "https://github.com/axboe/liburing.git", "io"),
    VendorRepo("libuv", "https://github.com/libuv/libuv.git", "io"),
    VendorRepo("loopy", "https://github.com/mattsta/loopy.git", "http"),
    VendorRepo("ls-hpack", "https://github.com/litespeedtech/ls-hpack.git", "http"),
    VendorRepo("lsquic", "https://github.com/litespeedtech/lsquic.git", "quic"),
    VendorRepo("miniz", "https://github.com/richgel999/miniz.git", "compress"),
    VendorRepo("mio", "https://github.com/tokio-rs/mio.git", "io"),
    VendorRepo("monoio", "https://github.com/bytedance/monoio.git", "io"),
    VendorRepo("mosquitto", "https://github.com/eclipse-mosquitto/mosquitto.git", "ws"),
    VendorRepo("msquic", "https://github.com/microsoft/msquic.git", "quic"),
    VendorRepo("nginx", "https://github.com/nginx/nginx.git", "http"),
    VendorRepo("oauth2-rs", "https://github.com/ramosbugs/oauth2-rs.git", "auth"),
    VendorRepo("oss-fuzz", "https://github.com/google/oss-fuzz.git", "http"),
    VendorRepo("picohttpparser", "https://github.com/h2o/picohttpparser.git", "http"),
    VendorRepo("picoquic", "https://github.com/private-octopus/picoquic.git", "quic"),
    VendorRepo("pingora", "https://github.com/cloudflare/pingora.git", "http"),
    VendorRepo("rioring", "https://github.com/newbiediver/rioring.git", "io"),
    VendorRepo("tonic", "https://github.com/hyperium/tonic.git", "http"),
    VendorRepo("tough-cookie", "https://github.com/salesforce/tough-cookie.git", "cookie_sfv"),
    VendorRepo("wolfssl", "https://github.com/wolfSSL/wolfssl.git", "tls"),
    VendorRepo("wslay", "https://github.com/tatsuhiro-t/wslay.git", "ws"),
    VendorRepo("wtransport", "https://github.com/BiagioFesta/wtransport.git", "quic"),
    VendorRepo("zlib", "https://github.com/madler/zlib.git", "compress"),
    VendorRepo("zquic", "https://github.com/ericsssan/zquic.git", "quic"),
)

CORPUS_DIRS_BY_CATEGORY: dict[str, tuple[str, ...]] = {
    "http1": (
        "vendor/h2o/fuzz/http1-corpus",
        "vendor/uWebSockets/fuzzing/seed-corpus/Http",
        "vendor/uWebSockets/fuzzing/seed-corpus/HttpWithProxy",
        "vendor/uWebSockets/fuzzing/seed-corpus/MultipartParser",
        "vendor/libwebsockets/fuzz/fuzz-h1/seeds",
        "vendor/libwebsockets/fuzz/fuzz-srv-h1/seeds",
        "vendor/libwebsockets/fuzz/fuzz-cli-h1/seeds",
    ),
    "h2": (
        "vendor/h2o/fuzz/http2-corpus",
        "vendor/nghttp2/fuzz/corpus/h2spec",
        "vendor/nghttp2/fuzz/corpus/nghttp",
        "vendor/libwebsockets/fuzz/fuzz-h2/seeds",
        "vendor/libwebsockets/fuzz/fuzz-srv-h2/seeds",
        "vendor/libwebsockets/fuzz/fuzz-cli-h2/seeds",
    ),
    "h3_quic": (
        "vendor/h2o/fuzz/http3-corpus",
        "vendor/nghttp3/fuzz/corpus/fuzz_http3serverreq",
        "vendor/nghttp3/fuzz/corpus/fuzz_qpackdecoder",
        "vendor/ngtcp2/fuzz/corpus/decode_frame",
        "vendor/ngtcp2/fuzz/corpus/ksl",
        "vendor/ngtcp2/fuzz/corpus/read_write_handshake_pkt",
        "vendor/ngtcp2/fuzz/corpus/read_write_pkt",
        "vendor/quiche/fuzz/corpus/packet_recv_client",
        "vendor/quiche/fuzz/corpus/packet_recv_server",
        "vendor/quiche/fuzz/corpus/packets_posths_server",
        "vendor/quiche/fuzz/corpus/packets_recv_server",
        "vendor/quiche/fuzz/corpus/qpack_decode",
        "vendor/libwebsockets/fuzz/fuzz-qpack/seeds",
        "vendor/libwebsockets/fuzz/fuzz-quic/seeds",
    ),
    "tls13": (
        "vendor/rustls/fuzz/corpus/client",
        "vendor/rustls/fuzz/corpus/message",
        "vendor/rustls/fuzz/corpus/server",
        "vendor/rustls/fuzz/corpus/unbuffered",
        "vendor/picotls/fuzz/fuzz-client-hello-corpus",
        "vendor/picotls/fuzz/fuzz-server-hello-corpus",
        "vendor/s2n-tls/tests/fuzz/corpus/s2n_client_hello_recv_fuzz_test",
        "vendor/s2n-tls/tests/fuzz/corpus/s2n_server_hello_recv_test",
        "vendor/s2n-tls/tests/fuzz/corpus/s2n_encrypted_extensions_recv_test",
        "vendor/s2n-tls/tests/fuzz/corpus/s2n_tls13_cert_req_recv_test",
        "vendor/s2n-tls/tests/fuzz/corpus/s2n_tls13_cert_verify_recv_test",
        "vendor/uWebSockets/uSockets/boringssl/fuzz/client_corpus",
        "vendor/uWebSockets/uSockets/boringssl/fuzz/server_corpus",
        "vendor/uWebSockets/uSockets/boringssl/fuzz/decode_client_hello_inner_corpus",
        "vendor/mbedtls/programs/fuzz/corpuses",
    ),
    "x509": (
        "vendor/uWebSockets/uSockets/boringssl/fuzz/parse_certificate_fuzzer_corpus",
        "vendor/uWebSockets/uSockets/boringssl/fuzz/cert_corpus",
        "vendor/uWebSockets/uSockets/boringssl/fuzz/crl_parse_crl_certificatelist_fuzzer_corpus",
        "vendor/uWebSockets/uSockets/boringssl/fuzz/ocsp_parse_ocsp_response_fuzzer_corpus",
        "vendor/uWebSockets/uSockets/boringssl/fuzz/der_roundtrip_corpus",
        "vendor/uWebSockets/uSockets/boringssl/fuzz/spki_corpus",
        "vendor/s2n-tls/tests/fuzz/corpus/s2n_certificate_extensions_parse_test",
    ),
    "ws_grpc": (
        "vendor/tungstenite/fuzz/seeds/read_message_server",
        "vendor/uWebSockets/fuzzing/seed-corpus/WebSocket",
        "vendor/uWebSockets/fuzzing/seed-corpus/PerMessageDeflate",
        "vendor/uWebSockets/fuzzing/seed-corpus/Extensions",
        "vendor/libwebsockets/fuzz/fuzz-ws/seeds",
        "vendor/libwebsockets/fuzz/fuzz-ws-pmd/seeds",
        "vendor/libwebsockets/fuzz/fuzz-adns/seeds",
    ),
    "url_psl_sfv_jose": (
        "vendor/h2o/fuzz/url-corpus",
        "vendor/uWebSockets/fuzzing/seed-corpus/QueryParser",
        "vendor/sfparse/fuzz/corpus",
        "vendor/libpsl/fuzz/libpsl_fuzzer.in",
        "vendor/libpsl/fuzz/libpsl_idn_fuzzer.in",
        "vendor/libpsl/fuzz/libpsl_idn2_fuzzer.in",
        "vendor/libwebsockets/fuzz/fuzz-jose/seeds",
    ),
}


def clone_or_update_repo(root: Path, repo: VendorRepo, update: bool) -> tuple[str, str]:
    dest = root / "vendor" / repo.name
    if dest.exists():
        if update:
            res = subprocess.run(
                ["git", "-C", str(dest), "pull", "--ff-only"],
                capture_output=True,
                text=True,
            )
            return repo.name, "updated" if res.returncode == 0 else "kept"
        return repo.name, "present"

    dest.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["git", "clone", "--depth", "1", repo.url, str(dest)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        return repo.name, f"failed ({res.stderr.strip()})"

    if repo.name == "uWebSockets":
        subprocess.run(
            ["git", "-C", str(dest), "submodule", "update", "--init", "--depth", "1", "uSockets"],
            capture_output=True,
            text=True,
        )
        usockets_dir = dest / "uSockets"
        if usockets_dir.exists():
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(usockets_dir),
                    "submodule",
                    "update",
                    "--init",
                    "--depth",
                    "1",
                    "boringssl",
                ],
                capture_output=True,
                text=True,
            )

    return repo.name, "cloned"


def sync_vendor_repos(root: Path, sync_all: bool, update: bool, jobs: int) -> bool:
    selected = [r for r in VENDOR_REPOS if sync_all or r.has_fuzz_corpus]
    print(
        f"[vendor] Synchronizing {len(selected)} upstream repositories in vendor/ ...", flush=True
    )
    failures = 0
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        futs = {pool.submit(clone_or_update_repo, root, repo, update): repo for repo in selected}
        for fut in as_completed(futs):
            name, status = fut.result()
            if status.startswith("failed"):
                failures += 1
                sys.stderr.write(f"  [!] {name}: {status}\n")
            elif status != "present":
                print(f"  [+] {name}: {status}", flush=True)
    return failures == 0


def harvest_vendor_corpus(
    root: Path, max_seeds_per_category: int, seed: int
) -> tuple[Path, int, dict[str, int]]:
    rng = random.Random(seed)
    counts_by_cat: dict[str, int] = {}
    selected_paths: list[str] = []
    seen_hashes: set[bytes] = set()

    for cat, rel_dirs in CORPUS_DIRS_BY_CATEGORY.items():
        cat_files: list[Path] = []
        for rel in rel_dirs:
            d = root / rel
            if not d.exists():
                continue
            for p in d.rglob("*"):
                if p.is_file():
                    try:
                        sz = p.stat().st_size
                    except OSError:
                        continue
                    if 0 < sz <= 16384:
                        cat_files.append(p)
        counts_by_cat[cat] = len(cat_files)
        if len(cat_files) > max_seeds_per_category:
            sampled = rng.sample(cat_files, max_seeds_per_category)
        else:
            sampled = cat_files

        for p in sampled:
            try:
                digest = hashlib.sha1(p.read_bytes()).digest()
            except OSError:
                continue
            if digest not in seen_hashes:
                seen_hashes.add(digest)
                selected_paths.append(str(p.resolve()))

    cache_dir = root / ".lit" / "cache" / "fuzz"
    cache_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = cache_dir / "sancov_seeds.lst"
    manifest_path.write_text("\n".join(selected_paths) + "\n", encoding="utf-8")
    return manifest_path, sum(counts_by_cat.values()), counts_by_cat


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bootstrap vendor/ repositories, harvest seed corpora, and run fuzz suites"
    )
    parser.add_argument(
        "--sync",
        action="store_true",
        help="Shallow-clone missing fuzz/corpus repositories into vendor/",
    )
    parser.add_argument(
        "--sync-all",
        action="store_true",
        help="Shallow-clone all 59 upstream reference repositories into vendor/",
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="Run git pull --ff-only on existing vendor/ repositories during sync",
    )
    parser.add_argument("--jobs", type=int, default=4, help="Parallel git clone workers")
    parser.add_argument(
        "--sync-only",
        action="store_true",
        help="Only synchronize vendor/ repositories and harvest corpus without running fuzzers",
    )
    parser.add_argument(
        "--sancov-execs",
        type=int,
        default=5000,
        help="Mutations to run in SanitizerCoverage fuzzer after loading vendor seed manifest",
    )
    parser.add_argument(
        "--oss-fuzz-duration",
        type=int,
        default=10,
        help="Duration in seconds for multi-core OSS-Fuzz runner (0 to skip)",
    )
    parser.add_argument(
        "--max-seeds-per-category",
        type=int,
        default=200,
        help="Max sampled vendor seeds per protocol category for SanCov startup",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent

    if (args.sync or args.sync_all) and not sync_vendor_repos(
        root, args.sync_all, args.update, args.jobs
    ):
        return 1

    manifest_path, total_discovered, counts_by_cat = harvest_vendor_corpus(
        root, args.max_seeds_per_category, 0x2026F00D
    )
    cat_summary = ", ".join(f"{k}={v}" for k, v in counts_by_cat.items())
    print(
        f"[corpus] Discovered {total_discovered:,} seed files in vendor/ ({cat_summary})",
        flush=True,
    )
    print(f"[corpus] Wrote deduplicated SanCov seed manifest: {manifest_path}", flush=True)

    if args.sync_only:
        return 0

    py = sys.executable

    # 1. Differential & Google Wycheproof Oracle
    print("\n[1/4] Running Differential & Wycheproof Oracle (scripts/diff_fuzz.py) ...", flush=True)
    res_diff = subprocess.run([py, "scripts/diff_fuzz.py", "--rounds", "40"], cwd=root)
    if res_diff.returncode != 0:
        return res_diff.returncode

    # 2. Coverage-Guided SanitizerCoverage Fuzzer with harvested vendor seeds
    print(
        "\n[2/4] Running Coverage-Guided SanCov Fuzzer with vendor corpus (scripts/sancov_runner.py) ...",
        flush=True,
    )
    res_sancov = subprocess.run(
        [
            py,
            "scripts/sancov_runner.py",
            "--execs",
            str(args.sancov_execs),
            "--corpus",
            f"@{manifest_path}",
        ],
        cwd=root,
    )
    if res_sancov.returncode != 0:
        return res_sancov.returncode

    # 3. BoringSSL BoGo & Trail of Bits x509-limbo Adversarial Suite
    print(
        "\n[3/4] Running BoringSSL BoGo & x509-limbo Conformance (verify_bogo_x509_limbo.goose) ...",
        flush=True,
    )
    res_bogo = subprocess.run(
        ["goose-lit", "tests/lit/verify_bogo_x509_limbo.goose"],
        cwd=root,
    )
    if res_bogo.returncode != 0:
        return res_bogo.returncode

    # 4. Multi-Core Native OSS-Fuzz Runner
    if args.oss_fuzz_duration > 0:
        print(
            f"\n[4/4] Running Multi-Core Native OSS-Fuzz Runner ({args.oss_fuzz_duration}s) ...",
            flush=True,
        )
        res_oss = subprocess.run(
            [py, "scripts/fuzz_runner.py", "--duration", str(args.oss_fuzz_duration)],
            cwd=root,
        )
        if res_oss.returncode != 0:
            return res_oss.returncode

    print("\nOK VENDOR_FUZZ_ALL_SUITES_PASSED", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
