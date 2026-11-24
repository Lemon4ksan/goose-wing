#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""Multi-core OSS-Fuzz / SanitizerCoverage orchestrator and background daemon.

Supports two execution engines across all 27 protocol, codec, PKI, and crypto targets:
  - ``sancov`` (default): compiles ``c_fuzz_entry.goose`` + ``goose-lit/shim/fuzz_driver.c`` with
    ``-fsanitize-coverage=trace-pc`` for real 64 KB AFL++ edge-transition feedback,
    persistent evolved corpora under ``.lit/cache/fuzz/evolved/<target>/``, constant-RAM
    RSS drift checks, and 50 ms per-input DoS timeout guards.
  - ``native``: compiles ``tests/fuzz/background_runner.goose`` with ``-O2`` and drives
    Goose's built-in libFuzzer mutator directly.
"""

import argparse
import hashlib
import json
import os
import random
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import sancov_runner

RUNNER_SRC = ROOT / "tests" / "fuzz" / "background_runner.goose"
LIT_DIR = ROOT / ".lit" / "cache" / "fuzz"
EXE_NAME = "fuzz_runner.exe" if os.name == "nt" else "fuzz_runner"
RUNNER_EXE = LIT_DIR / EXE_NAME
EVOLVED_DIR = LIT_DIR / "evolved"
MANIFEST_DIR = LIT_DIR / "manifests"
CRASH_DIR = LIT_DIR / "crashes"
STATUS_FILE = LIT_DIR / "fuzz_status.json"
STOP_SIGNAL_FILE = LIT_DIR / "fuzz_stop.signal"
LOG_FILE = LIT_DIR / "fuzz_background.log"

MAX_EVOLVED_PER_TARGET = 512

# Windows process creation flags for zero-console, zero-lag background execution:
# CREATE_NO_WINDOW (0x08000000) prevents flashing console windows.
# IDLE_PRIORITY_CLASS (0x00000040) yields CPU immediately to interactive user apps.
WIN_HEADLESS_IDLE_FLAGS = (subprocess.CREATE_NO_WINDOW | 0x00000040) if os.name == "nt" else 0

# Must match `FUZZ_TARGET_NAMES` order in `tests/fuzz/oss_fuzz.goose` (0..26).
ALL_TARGETS = [
    "http1",
    "h2_hpack",
    "h2_session",
    "h3_qpack",
    "h3_conn",
    "quic_pkt",
    "quic_rob",
    "quic_conn",
    "tls13",
    "x509",
    "ws_grpc",
    "url_cookie_sfv",
    "compress_decoders",
    "dict_roundtrip",
    "crypto_aead_kdf",
    "jose_jwt_jwe_oauth",
    "idna_psl_url_ip",
    "http_ext_headers_trace",
    "multipart_writer",
    "tls_endpoint",
    "stream_flow_control",
    "dst_world",
    "ingress_budget",
    "crypto_pk_kem",
    "hpke_ohttp_privacypass",
    "http_sig_digest_auth",
    "x509_pki_quic_retry",
]

BORINGSSL_FUZZ = ROOT / "vendor" / "uWebSockets" / "uSockets" / "boringssl" / "fuzz"
S2N_FUZZ = ROOT / "vendor" / "s2n-tls" / "tests" / "fuzz" / "corpus"

CORPUS_ROOTS: dict[str, list[Path]] = {
    "h3_conn": [
        ROOT / "vendor" / "nghttp3" / "fuzz" / "corpus" / "fuzz_http3serverreq",
        ROOT / "vendor" / "h2o" / "fuzz" / "http3-corpus",
        ROOT / "vendor" / "quiche" / "fuzz" / "corpus" / "qpack_decode",
    ],
    "h3_qpack": [
        ROOT / "vendor" / "nghttp3" / "fuzz" / "corpus" / "fuzz_qpackdecoder",
        ROOT / "vendor" / "quiche" / "fuzz" / "corpus" / "qpack_decode",
    ],
    "quic_pkt": [
        ROOT / "vendor" / "ngtcp2" / "fuzz" / "corpus",
        ROOT / "vendor" / "h2o" / "deps" / "quicly" / "fuzz" / "packet-corpus",
        ROOT / "vendor" / "quiche" / "fuzz" / "corpus" / "packet_recv_server",
        ROOT / "vendor" / "quiche" / "fuzz" / "corpus" / "packet_recv_client",
    ],
    "quic_rob": [
        ROOT / "vendor" / "ngtcp2" / "fuzz" / "corpus",
        ROOT / "vendor" / "h2o" / "deps" / "quicly" / "fuzz" / "packet-corpus",
    ],
    "quic_conn": [
        ROOT / "vendor" / "ngtcp2" / "fuzz" / "corpus",
        ROOT / "vendor" / "quiche" / "fuzz" / "corpus" / "packet_recv_server",
        ROOT / "vendor" / "quiche" / "fuzz" / "corpus" / "packets_posths_server",
    ],
    "tls13": [
        ROOT / "vendor" / "rustls" / "fuzz" / "corpus",
        ROOT / "vendor" / "picotls" / "fuzz" / "fuzz-client-hello-corpus",
        ROOT / "vendor" / "picotls" / "fuzz" / "fuzz-server-hello-corpus",
        S2N_FUZZ / "s2n_client_hello_recv_fuzz_test",
        S2N_FUZZ / "s2n_server_hello_recv_test",
        BORINGSSL_FUZZ / "client_corpus",
        BORINGSSL_FUZZ / "server_corpus",
    ],
    "x509": [
        BORINGSSL_FUZZ / "parse_certificate_fuzzer_corpus",
        BORINGSSL_FUZZ / "cert_corpus",
        BORINGSSL_FUZZ / "der_roundtrip_corpus",
        BORINGSSL_FUZZ / "verify_name_match_fuzzer_corpus",
    ],
    "ws_grpc": [
        ROOT / "vendor" / "tungstenite" / "fuzz" / "seeds" / "read_message_server",
        ROOT / "vendor" / "uWebSockets" / "fuzzing" / "WebSocket_seed_corpus",
        ROOT
        / "vendor"
        / "libwebsockets"
        / "minimal-examples-lowlevel"
        / "raw"
        / "minimal-raw-vhost"
        / "fuzz",
    ],
    "url_cookie_sfv": [
        ROOT / "vendor" / "sfparse" / "fuzz" / "corpus",
        ROOT / "vendor" / "h2o" / "fuzz" / "url-corpus",
        ROOT / "vendor" / "uWebSockets" / "fuzzing" / "TopicTree_seed_corpus",
    ],
    "http1": [
        ROOT / "vendor" / "sfparse" / "fuzz" / "corpus",
        ROOT / "vendor" / "h2o" / "fuzz" / "http1-corpus",
        ROOT / "vendor" / "uWebSockets" / "fuzzing" / "Http_seed_corpus",
    ],
    "h2_hpack": [
        ROOT / "vendor" / "nghttp3" / "fuzz" / "corpus" / "fuzz_qpackdecoder",
        ROOT / "vendor" / "nghttp2" / "fuzz" / "corpus",
        ROOT / "vendor" / "h2o" / "fuzz" / "http2-corpus",
    ],
    "h2_session": [
        ROOT / "vendor" / "nghttp3" / "fuzz" / "corpus" / "fuzz_http3serverreq",
        ROOT / "vendor" / "h2o" / "fuzz" / "http2-corpus",
        ROOT / "vendor" / "nghttp2" / "fuzz" / "corpus",
    ],
    "compress_decoders": [
        ROOT / "vendor" / "h2o" / "fuzz" / "http1-corpus",
        ROOT / "vendor" / "sfparse" / "fuzz" / "corpus",
    ],
    "dict_roundtrip": [
        ROOT / "vendor" / "sfparse" / "fuzz" / "corpus",
        ROOT / "vendor" / "h2o" / "fuzz" / "url-corpus",
    ],
    "crypto_aead_kdf": [
        ROOT / "vendor" / "picotls" / "fuzz" / "fuzz-client-hello-corpus",
        S2N_FUZZ / "s2n_tls13_client_finished_recv_test",
        S2N_FUZZ / "s2n_tls13_server_finished_recv_test",
    ],
    "jose_jwt_jwe_oauth": [
        ROOT / "vendor" / "sfparse" / "fuzz" / "corpus",
        ROOT / "vendor" / "h2o" / "fuzz" / "url-corpus",
        ROOT / "vendor" / "cjose" / "test",
    ],
    "idna_psl_url_ip": [
        ROOT / "vendor" / "libpsl" / "fuzz" / "libpsl_load_dafsa_fuzzer.in",
        ROOT / "vendor" / "libpsl" / "fuzz" / "libpsl_fuzzer.in",
        ROOT / "vendor" / "h2o" / "fuzz" / "url-corpus",
    ],
    "http_ext_headers_trace": [
        ROOT / "vendor" / "sfparse" / "fuzz" / "corpus",
        ROOT / "vendor" / "h2o" / "fuzz" / "http1-corpus",
    ],
    "multipart_writer": [
        ROOT / "vendor" / "h2o" / "fuzz" / "http1-corpus",
        ROOT / "vendor" / "uWebSockets" / "fuzzing" / "Http_seed_corpus",
    ],
    "tls_endpoint": [
        ROOT / "vendor" / "rustls" / "fuzz" / "corpus",
        BORINGSSL_FUZZ / "client_corpus",
        BORINGSSL_FUZZ / "server_corpus",
        S2N_FUZZ / "s2n_client_fuzz_test",
        S2N_FUZZ / "s2n_server_fuzz_test",
    ],
    "stream_flow_control": [
        ROOT / "vendor" / "ngtcp2" / "fuzz" / "corpus",
        ROOT / "vendor" / "quiche" / "fuzz" / "corpus" / "packets_posths_server",
        ROOT / "vendor" / "h2o" / "fuzz" / "http2-corpus",
    ],
    "dst_world": [
        ROOT / "vendor" / "ngtcp2" / "fuzz" / "corpus",
        ROOT / "vendor" / "quiche" / "fuzz" / "corpus" / "packet_recv_server",
    ],
    "ingress_budget": [
        ROOT / "vendor" / "h2o" / "fuzz" / "http1-corpus",
        ROOT / "vendor" / "h2o" / "fuzz" / "http2-corpus",
        ROOT / "vendor" / "uWebSockets" / "fuzzing" / "Http_seed_corpus",
    ],
    "crypto_pk_kem": [
        BORINGSSL_FUZZ / "spki_corpus",
        BORINGSSL_FUZZ / "privkey_corpus",
        BORINGSSL_FUZZ / "pkcs8_corpus",
        BORINGSSL_FUZZ / "bn_mod_exp_corpus",
        BORINGSSL_FUZZ / "der_roundtrip_corpus",
        S2N_FUZZ / "s2n_extensions_client_key_share_recv_test",
        S2N_FUZZ / "s2n_extensions_server_key_share_recv_test",
    ],
    "hpke_ohttp_privacypass": [
        BORINGSSL_FUZZ / "decode_client_hello_inner_corpus",
        ROOT / "vendor" / "sfparse" / "fuzz" / "corpus",
        ROOT / "vendor" / "h2o" / "fuzz" / "http1-corpus",
        ROOT / "vendor" / "quiche" / "fuzz" / "corpus" / "packet_recv_client",
    ],
    "http_sig_digest_auth": [
        ROOT / "vendor" / "sfparse" / "fuzz" / "corpus",
        ROOT / "vendor" / "h2o" / "fuzz" / "http1-corpus",
        ROOT / "vendor" / "uWebSockets" / "fuzzing" / "Http_seed_corpus",
    ],
    "x509_pki_quic_retry": [
        BORINGSSL_FUZZ / "read_pem_corpus",
        BORINGSSL_FUZZ / "crl_parse_crl_certificatelist_fuzzer_corpus",
        BORINGSSL_FUZZ / "crl_parse_crl_tbscertlist_fuzzer_corpus",
        BORINGSSL_FUZZ / "ocsp_parse_ocsp_response_fuzzer_corpus",
        BORINGSSL_FUZZ / "ocsp_parse_ocsp_response_data_fuzzer_corpus",
        S2N_FUZZ / "s2n_openssl_diff_pem_parsing_test",
        S2N_FUZZ / "s2n_stuffer_pem_fuzz_test",
        ROOT / "vendor" / "grpc-go" / "security" / "advancedtls" / "testdata" / "crl",
        ROOT / "vendor" / "quiche" / "fuzz" / "corpus" / "packet_recv_server",
        ROOT / "vendor" / "ngtcp2" / "fuzz" / "corpus",
    ],
}

SANCOV_LINE_RE = re.compile(
    r"OK SANCOV_EXECS:\s*(\d+)\s+TARGETS:\s*\d+/\d+\s+CORPUS:\s*(\d+)\s+\(\d+\s*B\)"
    r"\s+EDGES:\s*(\d+)\s+NEW_COV:\s*(\d+)\s+MAX_INPUT_MS:\s*([0-9.]+)"
    r"\s+RSS_DRIFT_KB:\s*([0-9.]+)/[0-9.]+(?:\s+SAVED:\s*(\d+))?"
)


def is_pid_alive(pid: int) -> bool:
    if not pid or pid <= 0:
        return False
    if os.name == "nt":
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        k32 = ctypes.windll.kernel32
        handle = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not handle:
            return False
        try:
            exit_code = ctypes.c_ulong(0)
            if not k32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return False
            return exit_code.value == STILL_ACTIVE
        finally:
            k32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def discover_corpus() -> dict[str, list[str]]:
    by_target: dict[str, list[str]] = {t: [] for t in ALL_TARGETS}
    all_files: list[str] = []
    seen: set[str] = set()

    custom_dir = ROOT / "tests" / "fuzz" / "corpus"
    if custom_dir.exists():
        for p in custom_dir.rglob("*"):
            if p.is_file():
                s = str(p)
                all_files.append(s)
                seen.add(s)

    for target, dirs in CORPUS_ROOTS.items():
        for d in dirs:
            if not d.exists():
                continue
            count = 0
            for p in d.rglob("*"):
                if p.is_file():
                    s = str(p)
                    by_target[target].append(s)
                    if s not in seen:
                        all_files.append(s)
                        seen.add(s)
                    count += 1
                    if count >= 400:
                        break

    by_target["all"] = all_files
    return by_target


def prune_evolved_dir(target_dir: Path, max_files: int = MAX_EVOLVED_PER_TARGET) -> int:
    if not target_dir.exists():
        return 0
    files = [p for p in target_dir.iterdir() if p.is_file()]
    if len(files) > max_files:
        files.sort(key=lambda p: p.stat().st_mtime)
        for old in files[: len(files) - max_files]:
            old.unlink(missing_ok=True)
        return max_files
    return len(files)


def build_native_runner(force: bool = False) -> Path:
    LIT_DIR.mkdir(parents=True, exist_ok=True)
    if RUNNER_EXE.exists() and not force:
        src_mtime = max(
            RUNNER_SRC.stat().st_mtime,
            (ROOT / "tests" / "fuzz" / "oss_fuzz.goose").stat().st_mtime,
        )
        if RUNNER_EXE.stat().st_mtime >= src_mtime:
            return RUNNER_EXE

    cmd = ["goose", "build", "--cc", "gcc", "-O2", "-o", str(RUNNER_EXE), str(RUNNER_SRC)]
    print(f"[OSS-Fuzz] Compiling native fuzz runner: {' '.join(cmd)}", flush=True)
    res = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[OSS-Fuzz] Build failed:\n{res.stdout}\n{res.stderr}", file=sys.stderr, flush=True)
        sys.exit(1)
    return RUNNER_EXE


def isolate_native_crash(
    exe: Path, target: str, batch_files: list[str], rng_seed: int, iters: int
) -> None:
    CRASH_DIR.mkdir(parents=True, exist_ok=True)
    for fpath in batch_files:
        cmd = [str(exe), target, str(iters), str(rng_seed), fpath]
        res = subprocess.run(
            cmd,
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=WIN_HEADLESS_IDLE_FLAGS,
        )
        if res.returncode != 0:
            raw = Path(fpath).read_bytes()
            digest = hashlib.sha1(raw).hexdigest()[:12]
            crash_bin = CRASH_DIR / f"crash_{target}_{digest}.bin"
            crash_meta = CRASH_DIR / f"crash_{target}_{digest}.txt"
            crash_bin.write_bytes(raw)
            crash_meta.write_text(
                f"Mode: native\n"
                f"Target: {target}\n"
                f"Source Seed: {fpath}\n"
                f"RNG Seed: {rng_seed}\n"
                f"Iterations: {iters}\n"
                f"Exit Code: {res.returncode}\n"
                f"Stdout: {res.stdout}\n"
                f"Stderr: {res.stderr}\n"
                f'Reproduce: {exe} {target} {iters} {rng_seed} "{crash_bin}"\n',
                encoding="utf-8",
            )
            print(f"\n[!] CRASH ISOLATED in target '{target}' -> {crash_bin}", flush=True)
            return


def record_sancov_crash(
    exe: Path,
    target: str,
    target_id: int,
    rng_seed: int,
    batch_seconds: int,
    manifest_files: list[str],
    returncode: int,
    stdout: str,
    stderr: str,
) -> Path:
    CRASH_DIR.mkdir(parents=True, exist_ok=True)
    stem = f"crash_sancov_{target}_{rng_seed}"
    crash_manifest = CRASH_DIR / f"{stem}.manifest"
    crash_meta = CRASH_DIR / f"{stem}.txt"
    crash_manifest.write_text("\n".join(manifest_files) + "\n", encoding="utf-8")
    repro_cmd = (
        f'"{exe}" {target_id} 0 --seconds {batch_seconds} --seed {rng_seed} "@{crash_manifest}"'
    )
    crash_meta.write_text(
        f"Mode: sancov\n"
        f"Target: {target} (id={target_id})\n"
        f"RNG Seed: {rng_seed}\n"
        f"Batch Seconds: {batch_seconds}\n"
        f"Exit Code: {returncode}\n"
        f"Reproduce: {repro_cmd}\n"
        f"\n--- Stdout ---\n{stdout}\n"
        f"\n--- Stderr ---\n{stderr}\n",
        encoding="utf-8",
    )
    print(f"\n[!] SANCOV FAILURE in target '{target}' -> {crash_meta}", flush=True)
    print(f"    Reproduce: {repro_cmd}", flush=True)
    return crash_meta


def run_native_batch(
    exe: Path, target: str, batch_files: list[str], iters: int, rng_seed: int
) -> dict:
    cmd = [str(exe), target, str(iters), str(rng_seed), *batch_files]
    res = None
    for attempt in range(3):
        try:
            res = subprocess.run(
                cmd,
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                timeout=60,
                creationflags=WIN_HEADLESS_IDLE_FLAGS,
            )
            break
        except subprocess.TimeoutExpired:
            return {
                "ok": False,
                "target": target,
                "rng_seed": rng_seed,
                "batch_files": batch_files,
                "returncode": -1,
                "stdout": "",
                "stderr": "TimeoutExpired",
            }
        except OSError as exc:
            if getattr(exc, "winerror", 0) == 1455 and attempt < 2:
                time.sleep(1.0 * (attempt + 1))
                continue
            return {"ok": True, "target": target, "execs": 0, "seeds": 0, "new_cov": 0}

    if res is None or res.returncode != 0:
        return {
            "ok": False,
            "target": target,
            "rng_seed": rng_seed,
            "batch_files": batch_files,
            "returncode": -1 if res is None else res.returncode,
            "stdout": "" if res is None else res.stdout,
            "stderr": "" if res is None else res.stderr,
        }

    execs = 0
    seeds = 0
    new_states = 0
    for line in res.stdout.splitlines():
        if line.startswith("OK EXECS:"):
            parts = line.split()
            if len(parts) >= 5:
                execs = int(parts[2])
                seeds = int(parts[4])
            if len(parts) >= 7:
                new_states = int(parts[6])
    return {
        "ok": True,
        "target": target,
        "execs": execs,
        "seeds": seeds,
        "edges": 0,
        "new_cov": new_states,
        "saved": 0,
        "max_input_ms": 0.0,
        "rss_drift_kb": 0.0,
    }


def run_sancov_batch(
    exe: Path,
    target: str,
    target_id: int,
    batch_files: list[str],
    batch_seconds: int,
    rng_seed: int,
    batch_num: int,
    max_rss_drift_kb: int,
    max_input_ms: int,
) -> dict:
    evolved_target_dir = EVOLVED_DIR / target
    evolved_target_dir.mkdir(parents=True, exist_ok=True)
    MANIFEST_DIR.mkdir(parents=True, exist_ok=True)

    evolved_files = [str(p) for p in evolved_target_dir.iterdir() if p.is_file()]
    if len(evolved_files) > 64:
        evolved_files = random.sample(evolved_files, 64)
    manifest_files = list(dict.fromkeys([*evolved_files, *batch_files]))

    manifest_path = MANIFEST_DIR / f"batch_{batch_num}_{target}.txt"
    manifest_path.write_text("\n".join(manifest_files) + "\n", encoding="utf-8")

    cmd = [
        str(exe),
        str(target_id),
        "0",
        "--seconds",
        str(batch_seconds),
        "--seed",
        str(rng_seed),
        "--corpus-out",
        str(evolved_target_dir),
        "--max-rss-drift-kb",
        str(max_rss_drift_kb),
        "--max-input-ms",
        str(max_input_ms),
        f"@{manifest_path}",
    ]

    res = None
    timeout_s = max(30, batch_seconds * 4)
    try:
        for attempt in range(3):
            try:
                res = subprocess.run(
                    cmd,
                    cwd=str(ROOT),
                    capture_output=True,
                    text=True,
                    timeout=timeout_s,
                    creationflags=WIN_HEADLESS_IDLE_FLAGS,
                )
                break
            except subprocess.TimeoutExpired:
                return {
                    "ok": False,
                    "target": target,
                    "target_id": target_id,
                    "rng_seed": rng_seed,
                    "batch_files": manifest_files,
                    "returncode": -1,
                    "stdout": "",
                    "stderr": f"TimeoutExpired ({timeout_s}s)",
                }
            except OSError as exc:
                if getattr(exc, "winerror", 0) == 1455 and attempt < 2:
                    time.sleep(1.0 * (attempt + 1))
                    continue
                return {
                    "ok": True,
                    "target": target,
                    "execs": 0,
                    "seeds": len(manifest_files),
                    "edges": 0,
                    "new_cov": 0,
                    "saved": 0,
                    "max_input_ms": 0.0,
                    "rss_drift_kb": 0.0,
                }
    finally:
        manifest_path.unlink(missing_ok=True)

    if res is None or res.returncode != 0:
        return {
            "ok": False,
            "target": target,
            "target_id": target_id,
            "rng_seed": rng_seed,
            "batch_files": manifest_files,
            "returncode": -1 if res is None else res.returncode,
            "stdout": "" if res is None else res.stdout,
            "stderr": "" if res is None else res.stderr,
        }

    execs = 0
    edges = 0
    new_cov = 0
    saved = 0
    max_ms = 0.0
    rss_kb = 0.0
    for line in res.stdout.splitlines():
        m = SANCOV_LINE_RE.search(line)
        if m:
            execs = int(m.group(1))
            edges = int(m.group(3))
            new_cov = int(m.group(4))
            max_ms = float(m.group(5))
            rss_kb = float(m.group(6))
            saved = int(m.group(7)) if m.group(7) else 0
            break

    evolved_count = prune_evolved_dir(evolved_target_dir)
    return {
        "ok": True,
        "target": target,
        "execs": execs,
        "seeds": len(manifest_files),
        "edges": edges,
        "new_cov": new_cov,
        "saved": saved,
        "evolved_count": evolved_count,
        "max_input_ms": max_ms,
        "rss_drift_kb": rss_kb,
    }


def handle_stop() -> None:
    LIT_DIR.mkdir(parents=True, exist_ok=True)
    STOP_SIGNAL_FILE.write_text("stop", encoding="utf-8")
    pid = None
    if STATUS_FILE.exists():
        try:
            st = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
            pid = st.get("pid")
            st["running"] = False
            st["state"] = "stopped"
            STATUS_FILE.write_text(json.dumps(st, indent=2), encoding="utf-8")
        except Exception:
            pass
    if pid and os.name == "nt":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    elif pid and os.name != "nt":
        try:
            os.kill(int(pid), 15)
        except OSError:
            pass
    print(f"[OSS-Fuzz] Background fuzzer stopped (PID {pid}).")


def handle_status() -> None:
    if not STATUS_FILE.exists():
        print("No background fuzzer status found.")
        return
    try:
        st = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
        pid = int(st.get("pid") or 0)
        alive = is_pid_alive(pid)
        st["pid_alive"] = alive
        if st.get("running") and not alive:
            st["running"] = False
            st["state"] = "exited"
        print(json.dumps(st, indent=2))
    except Exception:
        print(STATUS_FILE.read_text(encoding="utf-8"))


def spawn_daemon(args: argparse.Namespace) -> None:
    if STOP_SIGNAL_FILE.exists():
        STOP_SIGNAL_FILE.unlink(missing_ok=True)
    launcher = sys.executable
    daemon_dur = 0 if "--duration" not in sys.argv else args.duration
    daemon_workers = (
        max(1, min(3, (os.cpu_count() or 4) // 4)) if "--workers" not in sys.argv else args.workers
    )
    cmd = [
        launcher,
        str(Path(__file__).resolve()),
        "--mode",
        args.mode,
        "--cc",
        args.cc,
        "--opt",
        args.opt,
        "--target",
        args.target,
        "--workers",
        str(daemon_workers),
        "--duration",
        str(daemon_dur),
        "--mutations",
        str(args.mutations),
        "--batch-size",
        str(args.batch_size),
        "--batch-seconds",
        str(args.batch_seconds),
        "--max-rss-drift-kb",
        str(args.max_rss_drift_kb),
        "--max-input-ms",
        str(args.max_input_ms),
    ]
    if args.rebuild:
        cmd.append("--rebuild")
    if args.debug_no_bce:
        cmd.append("--debug-no-bce")

    LIT_DIR.mkdir(parents=True, exist_ok=True)
    log_f = open(LOG_FILE, "w", encoding="utf-8")  # noqa: SIM115
    # Windows CreateProcess forbids combining CREATE_NO_WINDOW and DETACHED_PROCESS;
    # CREATE_NO_WINDOW alone hides console popups while keeping file log redirection intact.
    creationflags = (
        subprocess.CREATE_NO_WINDOW
        | subprocess.CREATE_NEW_PROCESS_GROUP
        | 0x00000040  # IDLE_PRIORITY_CLASS
        if os.name == "nt"
        else 0
    )
    proc = subprocess.Popen(
        cmd,
        cwd=str(ROOT),
        stdin=subprocess.DEVNULL,
        stdout=log_f,
        stderr=subprocess.STDOUT,
        creationflags=creationflags,
        start_new_session=(os.name != "nt"),
    )
    STATUS_FILE.write_text(
        json.dumps(
            {
                "pid": proc.pid,
                "running": True,
                "mode": args.mode,
                "state": "compiling_or_starting",
                "workers": daemon_workers,
                "target": args.target,
                "targets_total": len(ALL_TARGETS) if args.target == "all" else 1,
                "batch_seconds": args.batch_seconds,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(
        f"[OSS-Fuzz] Started background daemon (PID {proc.pid}, mode={args.mode}, "
        f"priority=IDLE, workers={daemon_workers}, duration={'infinite' if daemon_dur == 0 else f'{daemon_dur}s'})"
    )
    print("           Check status: python scripts/fuzz_runner.py --status")
    print("           Stop daemon:  python scripts/fuzz_runner.py --stop")
    print(f"           Log file:     {LOG_FILE}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="goose-wing Multi-Core SanitizerCoverage & Native OSS-Fuzz Runner"
    )
    parser.add_argument(
        "--mode",
        default="sancov",
        choices=["sancov", "native"],
        help="Fuzzing engine: sancov (64KB edge feedback + RSS/DoS gates) or native (default: sancov)",
    )
    parser.add_argument("--cc", default="gcc", help="C compiler for sancov mode (default: gcc)")
    parser.add_argument("--opt", default="-O2", help="C compiler opt flag (default: -O2)")
    parser.add_argument(
        "--target",
        default="all",
        choices=["all", *ALL_TARGETS],
        help="Target protocol subsystem (default: all 27 targets)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=max(1, min(4, (os.cpu_count() or 4) // 2)),
        help="Parallel worker processes",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=15,
        help="Run duration in seconds (0 = infinite background loop)",
    )
    parser.add_argument(
        "--mutations",
        type=int,
        default=256,
        help="libFuzzer mutations per seed per batch (native mode)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=48,
        help="Vendor seed files sampled per worker invocation",
    )
    parser.add_argument(
        "--batch-seconds",
        type=int,
        default=15,
        help="Wall-clock seconds per SanCov worker batch (default: 15)",
    )
    parser.add_argument(
        "--max-rss-drift-kb",
        type=int,
        default=8192,
        help="Max target RSS drift ceiling in KB in sancov mode (default: 8192)",
    )
    parser.add_argument(
        "--max-input-ms",
        type=int,
        default=50,
        help="Max per-input execution ceiling in ms in sancov mode (default: 50)",
    )
    parser.add_argument(
        "--debug-no-bce",
        action="store_true",
        help="Build SanCov fuzzer with --debug --no-bce bounds traps enabled",
    )
    parser.add_argument("--rebuild", action="store_true", help="Force fuzzer binary recompilation")
    parser.add_argument(
        "--daemon",
        action="store_true",
        help="Spawn invisible headless background daemon (CREATE_NO_WINDOW + IDLE_PRIORITY_CLASS)",
    )
    parser.add_argument(
        "--status", action="store_true", help="Show live status of background fuzzer"
    )
    parser.add_argument(
        "--stop", action="store_true", help="Gracefully stop running background fuzzer daemon"
    )
    args = parser.parse_args(sancov_runner.normalize_argv(sys.argv[1:]))

    if args.stop:
        handle_stop()
        return
    if args.status:
        handle_status()
        return
    if args.daemon:
        spawn_daemon(args)
        return

    LIT_DIR.mkdir(parents=True, exist_ok=True)
    if args.mode == "sancov":
        print(
            f"[OSS-Fuzz] Preparing SanCov fuzzer (cc={args.cc}, opt={args.opt}, "
            f"debug_no_bce={args.debug_no_bce})...",
            flush=True,
        )
        exe = sancov_runner.build_fuzzer(
            ROOT,
            args.cc,
            args.opt,
            use_libfuzzer=False,
            debug_no_bce=args.debug_no_bce,
            force=args.rebuild,
        )
    else:
        exe = build_native_runner(force=args.rebuild)

    if STOP_SIGNAL_FILE.exists():
        STOP_SIGNAL_FILE.unlink(missing_ok=True)

    corpus_map = discover_corpus()
    total_corpus_files = len(corpus_map["all"])
    targets_to_run = ALL_TARGETS if args.target == "all" else [args.target]
    target_id_map = {name: idx for idx, name in enumerate(ALL_TARGETS)}

    batch_desc = f"{args.batch_seconds}s" if args.mode == "sancov" else f"{args.mutations} mut/seed"
    print(
        f"[OSS-Fuzz] Starting mode={args.mode} | workers={args.workers} | "
        f"targets={len(targets_to_run)} | vendor_seeds={total_corpus_files} | "
        f"batch={batch_desc} | "
        f"duration={'infinite' if args.duration == 0 else f'{args.duration}s'}",
        flush=True,
    )

    start_time = time.time()
    total_execs = 0
    total_seeds_processed = 0
    total_new_cov = 0
    total_saved = 0
    total_crashes = 0
    worst_input_ms = 0.0
    max_rss_drift_kb_seen = 0.0
    batch_idx = 0
    per_target: dict[str, dict] = {
        t: {
            "execs": 0,
            "batches": 0,
            "max_edges": 0,
            "new_cov": 0,
            "evolved_seeds": len(list((EVOLVED_DIR / t).glob("*.bin")))
            if (EVOLVED_DIR / t).exists()
            else 0,
            "worst_input_ms": 0.0,
            "crashes": 0,
        }
        for t in targets_to_run
    }

    def write_status(running: bool, state: str) -> None:
        elapsed = max(0.001, time.time() - start_time)
        evolved_total = sum(v["evolved_seeds"] for v in per_target.values())
        payload = {
            "pid": os.getpid(),
            "running": running,
            "state": state,
            "mode": args.mode,
            "elapsed_sec": round(elapsed, 2),
            "total_execs": total_execs,
            "execs_per_sec": int(total_execs / elapsed),
            "seeds_processed": total_seeds_processed,
            "new_cov_events": total_new_cov,
            "evolved_corpus_files": evolved_total,
            "vendor_corpus_size": total_corpus_files,
            "worst_input_ms": round(worst_input_ms, 3),
            "max_rss_drift_kb": round(max_rss_drift_kb_seen, 2),
            "crashes": total_crashes,
            "workers": args.workers,
            "target": args.target,
            "targets_total": len(targets_to_run),
            "targets_covered": sum(1 for v in per_target.values() if v["execs"] > 0),
            "per_target": per_target,
        }
        STATUS_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    write_status(True, "fuzzing")

    try:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = set()

            def submit_next():
                nonlocal batch_idx
                t = targets_to_run[batch_idx % len(targets_to_run)]
                cur_batch_num = batch_idx
                batch_idx += 1
                files = corpus_map.get(t) or corpus_map["all"]
                chosen = random.sample(files, min(args.batch_size, len(files))) if files else []
                rng_seed = random.getrandbits(64)
                if args.mode == "sancov":
                    eff_sec = args.batch_seconds
                    if args.duration > 0:
                        rem = int(args.duration - (time.time() - start_time))
                        eff_sec = max(1, min(args.batch_seconds, max(1, rem)))
                    return pool.submit(
                        run_sancov_batch,
                        exe,
                        t,
                        target_id_map[t],
                        chosen,
                        eff_sec,
                        rng_seed,
                        cur_batch_num,
                        args.max_rss_drift_kb,
                        args.max_input_ms,
                    )
                return pool.submit(run_native_batch, exe, t, chosen, args.mutations, rng_seed)

            initial_slots = args.workers if args.mode == "sancov" else args.workers * 2
            for _ in range(initial_slots):
                futures.add(submit_next())

            while futures:
                fut = next(as_completed(futures))
                futures.remove(fut)

                res = fut.result()
                t = res["target"]
                stats = per_target[t]
                if not res["ok"]:
                    total_crashes += 1
                    stats["crashes"] += 1
                    if args.mode == "sancov":
                        record_sancov_crash(
                            exe,
                            t,
                            res["target_id"],
                            res["rng_seed"],
                            args.batch_seconds,
                            res["batch_files"],
                            res["returncode"],
                            res["stdout"],
                            res["stderr"],
                        )
                    else:
                        print(
                            f"[!] Batch failed on target '{t}' (seed={res['rng_seed']}), isolating...",
                            flush=True,
                        )
                        isolate_native_crash(
                            exe, t, res["batch_files"], res["rng_seed"], args.mutations
                        )
                else:
                    total_execs += res["execs"]
                    total_seeds_processed += res["seeds"]
                    total_new_cov += res["new_cov"]
                    total_saved += res.get("saved", 0)
                    stats["execs"] += res["execs"]
                    stats["batches"] += 1
                    stats["new_cov"] += res["new_cov"]
                    if res.get("edges", 0) > stats["max_edges"]:
                        stats["max_edges"] = res["edges"]
                    if "evolved_count" in res:
                        stats["evolved_seeds"] = res["evolved_count"]
                    if res.get("max_input_ms", 0.0) > stats["worst_input_ms"]:
                        stats["worst_input_ms"] = round(res["max_input_ms"], 3)
                    if res.get("max_input_ms", 0.0) > worst_input_ms:
                        worst_input_ms = res["max_input_ms"]
                    if res.get("rss_drift_kb", 0.0) > max_rss_drift_kb_seen:
                        max_rss_drift_kb_seen = res["rss_drift_kb"]

                elapsed = max(0.001, time.time() - start_time)
                exec_per_sec = int(total_execs / elapsed)
                write_status(True, "fuzzing")

                print(
                    f"[{elapsed:7.1f}s] target={t:<22} | execs={total_execs:,} ({exec_per_sec:,}/s) | "
                    f"edges={stats['max_edges']:,} | new_cov={total_new_cov:,} | "
                    f"max_ms={worst_input_ms:.2f} | rss={max_rss_drift_kb_seen:.1f}KB | crashes={total_crashes}",
                    flush=True,
                )

                if STOP_SIGNAL_FILE.exists():
                    STOP_SIGNAL_FILE.unlink(missing_ok=True)
                    break

                if args.duration == 0 or (time.time() - start_time) < args.duration:
                    futures.add(submit_next())

    except KeyboardInterrupt:
        print("\n[OSS-Fuzz] Stopping on user interrupt...", flush=True)

    write_status(False, "completed")
    elapsed = max(0.001, time.time() - start_time)
    print(
        f"\n[OSS-Fuzz] Completed in {elapsed:.1f}s | mode={args.mode} | "
        f"Total executions: {total_execs:,} ({int(total_execs / elapsed):,} exec/s) | "
        f"New cov events: {total_new_cov:,} | Crashes: {total_crashes}",
        flush=True,
    )
    if total_crashes > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
