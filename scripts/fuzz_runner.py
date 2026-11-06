#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
Multi-core native OSS-Fuzz orchestrator and background daemon for goose-wing.
Compiles `tests/fuzz/background_runner.goose` with `-O2`, discovers all 2,430+ real
OSS-Fuzz binary corpus seeds in `vendor/`, and continuously fuzzes all 12 protocol
targets across CPU cores.
"""

import argparse
import hashlib
import json
import os
import random
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNNER_SRC = ROOT / "tests" / "fuzz" / "background_runner.goose"
LIT_DIR = ROOT / ".lit" / "cache" / "fuzz"
EXE_NAME = "fuzz_runner.exe" if os.name == "nt" else "fuzz_runner"
RUNNER_EXE = LIT_DIR / EXE_NAME
CRASH_DIR = LIT_DIR / "crashes"
STATUS_FILE = LIT_DIR / "fuzz_status.json"
STOP_SIGNAL_FILE = LIT_DIR / "fuzz_stop.signal"
LOG_FILE = LIT_DIR / "fuzz_background.log"

# Windows process creation flags for zero-console, zero-lag background execution:
# CREATE_NO_WINDOW (0x08000000) prevents any flashing console windows.
# IDLE_PRIORITY_CLASS (0x00000040) ensures OS scheduler yields 100% immediately to user apps.
WIN_HEADLESS_IDLE_FLAGS = (subprocess.CREATE_NO_WINDOW | 0x00000040) if os.name == "nt" else 0

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
]

CORPUS_ROOTS = {
    "h3_conn": [ROOT / "vendor" / "nghttp3" / "fuzz" / "corpus" / "fuzz_http3serverreq"],
    "h3_qpack": [ROOT / "vendor" / "nghttp3" / "fuzz" / "corpus" / "fuzz_qpackdecoder"],
    "quic_pkt": [ROOT / "vendor" / "ngtcp2" / "fuzz" / "corpus"],
    "quic_rob": [ROOT / "vendor" / "ngtcp2" / "fuzz" / "corpus"],
    "quic_conn": [ROOT / "vendor" / "ngtcp2" / "fuzz" / "corpus"],
    "tls13": [
        ROOT / "vendor" / "rustls" / "fuzz" / "corpus",
        ROOT / "vendor" / "picotls" / "fuzz" / "fuzz-client-hello-corpus",
        ROOT / "vendor" / "picotls" / "fuzz" / "fuzz-server-hello-corpus",
    ],
    "x509": [
        ROOT
        / "vendor"
        / "uWebSockets"
        / "uSockets"
        / "boringssl"
        / "fuzz"
        / "parse_certificate_fuzzer_corpus",
    ],
    "ws_grpc": [
        ROOT / "vendor" / "tungstenite" / "fuzz" / "seeds" / "read_message_server",
    ],
    "url_cookie_sfv": [
        ROOT / "vendor" / "sfparse" / "fuzz" / "corpus",
    ],
    "http1": [
        ROOT / "vendor" / "sfparse" / "fuzz" / "corpus",
    ],
    "h2_hpack": [
        ROOT / "vendor" / "nghttp3" / "fuzz" / "corpus" / "fuzz_qpackdecoder",
    ],
    "h2_session": [
        ROOT / "vendor" / "nghttp3" / "fuzz" / "corpus" / "fuzz_http3serverreq",
    ],
}


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
            for p in d.rglob("*"):
                if p.is_file():
                    s = str(p)
                    by_target[target].append(s)
                    if s not in seen:
                        all_files.append(s)
                        seen.add(s)

    by_target["all"] = all_files
    return by_target


def build_runner(force: bool = False) -> Path:
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


def isolate_crashing_seed(
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
            print(f'    Reproduce: {exe} {target} {iters} {rng_seed} "{crash_bin}"', flush=True)
            return


def run_batch(
    exe: Path, target: str, batch_files: list[str], iters: int, rng_seed: int
) -> tuple[bool, int, int, int, str, list[str], int]:
    cmd = [str(exe), target, str(iters), str(rng_seed), *batch_files]
    try:
        res = subprocess.run(
            cmd,
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=60,
            creationflags=WIN_HEADLESS_IDLE_FLAGS,
        )
    except subprocess.TimeoutExpired:
        return False, 0, 0, 0, target, batch_files, rng_seed

    if res.returncode != 0:
        return False, 0, 0, 0, target, batch_files, rng_seed

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
    return True, execs, seeds, new_states, target, batch_files, rng_seed


def main() -> None:
    parser = argparse.ArgumentParser(description="goose-wing Native Multi-Core OSS-Fuzz Runner")
    parser.add_argument(
        "--target", default="all", choices=["all", *ALL_TARGETS], help="Target protocol subsystem"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=max(1, (os.cpu_count() or 4) // 2),
        help="Parallel worker threads",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=15,
        help="Run duration in seconds (0 = infinite background loop)",
    )
    parser.add_argument(
        "--mutations", type=int, default=256, help="libFuzzer mutations per seed per batch"
    )
    parser.add_argument(
        "--batch-size", type=int, default=48, help="Number of corpus files per worker invocation"
    )
    parser.add_argument(
        "--rebuild", action="store_true", help="Force recompilation of background_runner.goose"
    )
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
    args = parser.parse_args()

    if args.stop:
        LIT_DIR.mkdir(parents=True, exist_ok=True)
        STOP_SIGNAL_FILE.write_text("stop", encoding="utf-8")
        pid = None
        if STATUS_FILE.exists():
            try:
                st = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
                pid = st.get("pid")
                st["running"] = False
                STATUS_FILE.write_text(json.dumps(st, indent=2), encoding="utf-8")
            except Exception:
                pass
        if pid and os.name == "nt":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        print(f"[OSS-Fuzz] Background fuzzer stopped (PID {pid}).")
        return

    if args.status:
        if STATUS_FILE.exists():
            print(STATUS_FILE.read_text(encoding="utf-8"))
        else:
            print("No background fuzzer status found.")
        return

    exe = build_runner(force=args.rebuild)

    if args.daemon:
        if STOP_SIGNAL_FILE.exists():
            STOP_SIGNAL_FILE.unlink(missing_ok=True)
        py_exe = Path(sys.executable)
        pyw_exe = py_exe.with_name("pythonw.exe")
        launcher = str(pyw_exe if (os.name == "nt" and pyw_exe.exists()) else py_exe)
        # Default daemon duration to 0 (continuous) unless explicitly specified
        daemon_dur = 0 if "--duration" not in sys.argv else args.duration
        daemon_workers = (
            max(1, (os.cpu_count() or 4) // 4) if "--workers" not in sys.argv else args.workers
        )
        cmd = [
            launcher,
            str(Path(__file__).resolve()),
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
        ]
        LIT_DIR.mkdir(parents=True, exist_ok=True)
        log_f = open(LOG_FILE, "w", encoding="utf-8")  # noqa: SIM115
        creationflags = (
            subprocess.CREATE_NO_WINDOW
            | subprocess.CREATE_NEW_PROCESS_GROUP
            | subprocess.DETACHED_PROCESS
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
        print(
            f"[OSS-Fuzz] Started background daemon (PID {proc.pid}, priority=IDLE, workers={daemon_workers})"
        )
        print("           Check status: python scripts/fuzz_runner.py --status")
        print("           Stop daemon:  python scripts/fuzz_runner.py --stop")
        print(f"           Log file:     {LOG_FILE}")
        return

    if STOP_SIGNAL_FILE.exists():
        STOP_SIGNAL_FILE.unlink(missing_ok=True)

    corpus_map = discover_corpus()
    total_corpus_files = len(corpus_map["all"])
    targets_to_run = ALL_TARGETS if args.target == "all" else [args.target]

    print(
        f"[OSS-Fuzz] Starting {args.workers} workers | targets={len(targets_to_run)} | "
        f"vendor corpus={total_corpus_files} binary seeds | mutations/seed={args.mutations} | "
        f"duration={'infinite' if args.duration == 0 else f'{args.duration}s'}",
        flush=True,
    )

    start_time = time.time()
    total_execs = 0
    total_seeds_processed = 0
    total_new_states = 0
    total_crashes = 0
    batch_idx = 0

    try:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = set()

            def submit_next():
                nonlocal batch_idx
                t = targets_to_run[batch_idx % len(targets_to_run)]
                batch_idx += 1
                files = corpus_map.get(t) or corpus_map["all"]
                if files:
                    chosen = random.sample(files, min(args.batch_size, len(files)))
                else:
                    chosen = []
                rng_seed = random.getrandbits(64)
                return pool.submit(run_batch, exe, t, chosen, args.mutations, rng_seed)

            for _ in range(args.workers * 2):
                futures.add(submit_next())

            while futures:
                done_iter = as_completed(futures)
                fut = next(done_iter)
                futures.remove(fut)

                ok, execs, seeds, new_states, t, batch_files, rng_seed = fut.result()
                if not ok:
                    total_crashes += 1
                    print(
                        f"[!] Batch failed on target '{t}' (seed={rng_seed}), isolating...",
                        flush=True,
                    )
                    isolate_crashing_seed(exe, t, batch_files, rng_seed, args.mutations)
                else:
                    total_execs += execs
                    total_seeds_processed += seeds
                    total_new_states += new_states

                elapsed = max(0.001, time.time() - start_time)
                exec_per_sec = int(total_execs / elapsed)

                status_payload = {
                    "pid": os.getpid(),
                    "running": True,
                    "elapsed_sec": round(elapsed, 2),
                    "total_execs": total_execs,
                    "execs_per_sec": exec_per_sec,
                    "seeds_processed": total_seeds_processed,
                    "new_states_discovered": total_new_states,
                    "vendor_corpus_size": total_corpus_files,
                    "crashes": total_crashes,
                    "workers": args.workers,
                    "target": args.target,
                }
                STATUS_FILE.write_text(json.dumps(status_payload, indent=2), encoding="utf-8")

                if batch_idx % max(1, args.workers) == 0:
                    print(
                        f"[{elapsed:6.1f}s] execs: {total_execs:,} ({exec_per_sec:,} exec/s) | "
                        f"seeds: {total_seeds_processed:,} | states: {total_new_states:,} | crashes: {total_crashes}",
                        flush=True,
                    )

                if STOP_SIGNAL_FILE.exists():
                    STOP_SIGNAL_FILE.unlink(missing_ok=True)
                    break

                if args.duration == 0 or (time.time() - start_time) < args.duration:
                    futures.add(submit_next())

    except KeyboardInterrupt:
        print("\n[OSS-Fuzz] Stopping on user interrupt...", flush=True)

    elapsed = max(0.001, time.time() - start_time)
    print(
        f"\n[OSS-Fuzz] Completed in {elapsed:.1f}s | Total executions: {total_execs:,} "
        f"({int(total_execs / elapsed):,} exec/s) | Crashes: {total_crashes}",
        flush=True,
    )
    if total_crashes > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
