#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

# scripts/fetch_missing_rfcs.py
# Batch downloader for missing normative RFC specifications from rfc-editor.org.

import argparse
import concurrent.futures
import os
import re
import sys
import time
import urllib.error
import urllib.request

BASE_URL = "https://www.rfc-editor.org/rfc/rfc{}.txt"
USER_AGENT = "goose-wing-audit/1.0 (systems-protocol-auditor)"


def scan_referenced_rfcs():
    rfc_pattern = re.compile(r"RFC\s*(\d+)", re.IGNORECASE)
    referenced = set()
    for root, _, files in os.walk("."):
        if any(skip in root for skip in [".git", ".ruff_cache", "vendor", ".superpowers"]):
            continue
        for f in files:
            if f.endswith((".goose", ".md", ".py")):
                path = os.path.join(root, f)
                try:
                    with open(path, encoding="utf-8", errors="ignore") as fp:
                        content = fp.read()
                        for match in rfc_pattern.findall(content):
                            num = int(match)
                            if 1 <= num < 30000:
                                referenced.add(num)
                except Exception:
                    pass
    return sorted(list(referenced))


def get_existing_rfcs(rfc_dir):
    os.makedirs(rfc_dir, exist_ok=True)
    existing = set()
    for fname in os.listdir(rfc_dir):
        m = re.match(r"^rfc(\d+)\.txt$", fname, re.IGNORECASE)
        if m:
            path = os.path.join(rfc_dir, fname)
            if os.path.getsize(path) > 1000:
                existing.add(int(m.group(1)))
    return existing


def fetch_single_rfc(num, rfc_dir):
    target_path = os.path.join(rfc_dir, f"rfc{num}.txt")
    temp_path = os.path.join(rfc_dir, f"rfc{num}.txt.tmp")
    url = BASE_URL.format(num)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})

    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                if resp.status == 200:
                    data = resp.read()
                    if len(data) > 500:
                        with open(temp_path, "wb") as out_fp:
                            out_fp.write(data)
                        os.replace(temp_path, target_path)
                        return (num, True, len(data), "OK")
                elif resp.status == 404:
                    return (num, False, 0, "404 Not Found")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return (num, False, 0, "404 Not Found")
            time.sleep(1.0 * (attempt + 1))
        except Exception:
            time.sleep(1.0 * (attempt + 1))
        finally:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass
    return (num, False, 0, "Failed after 3 attempts")


def main():
    parser = argparse.ArgumentParser(
        description="Batch downloader for missing normative RFC specifications"
    )
    parser.add_argument(
        "--dir",
        "-d",
        default=".gemini/rfc",
        help="Destination directory for downloaded RFC files (default: .gemini/rfc, e.g. .claude/rfc)",
    )
    parser.add_argument(
        "--concurrency", "-c", type=int, default=8, help="Maximum concurrent downloads (default: 8)"
    )
    args = parser.parse_args()

    rfc_dir = os.path.abspath(args.dir)
    os.makedirs(rfc_dir, exist_ok=True)

    referenced = scan_referenced_rfcs()
    existing = get_existing_rfcs(rfc_dir)
    missing = [num for num in referenced if num not in existing]

    print(f"Target RFC Directory: {rfc_dir}")
    print(f"Total referenced RFCs in repo: {len(referenced)}")
    print(f"Existing in target directory: {len(existing)}")
    print(f"Missing RFCs to download: {len(missing)}")

    if not missing:
        print("All referenced RFCs are already present in the target directory.")
        return 0

    success_cnt = 0
    fail_cnt = 0
    not_found = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = {executor.submit(fetch_single_rfc, num, rfc_dir): num for num in missing}
        for future in concurrent.futures.as_completed(futures):
            num, ok, size, msg = future.result()
            if ok:
                success_cnt += 1
                if success_cnt % 25 == 0 or success_cnt == len(missing):
                    print(
                        f"  [Downloaded {success_cnt}/{len(missing)}] RFC {num} ({size // 1024} KB)"
                    )
            else:
                fail_cnt += 1
                if "404" in msg:
                    not_found.append(num)
                print(f"  [FAIL] RFC {num}: {msg}")

    print("\nIngestion Summary:")
    print(f"  Successfully downloaded: {success_cnt}")
    print(f"  Failed / Not Found: {fail_cnt}")
    if not_found:
        print(f"  404 Not Found (draft or non-existent numbers): {not_found}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
