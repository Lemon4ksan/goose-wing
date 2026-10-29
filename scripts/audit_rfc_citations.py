#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# scripts/audit_rfc_citations.py
# Static citation and hallucination scanner for goose-wing against canonical RFC corpus.

import argparse
import json
import os
import re
import sys
from collections import defaultdict

DEFAULT_RFC_DIR = os.path.abspath(".gemini/rfc")
DEFAULT_REPORT_PATH = os.path.abspath(".gemini/audit_reports/rfc_citation_discrepancies.json")

# Matches canonical citations:
# // RFC 9113 Section 4.3: Header Compression and Decompression
# // RFC 7616 Section 3.4.2.2: Calculation of the "response" Directive
CITATION_RE = re.compile(
    r"(?:(?:RFC|rfc)\s*(\d+))"
    r"(?:[,\s]+(?:(?:§|Section|sec\.?|part)\s*([\d\.]+)))?"
    r"(?:\s*:\s*([^\n\r]+))?",
    re.IGNORECASE,
)

HEURISTIC_RE = re.compile(
    r"\b(TODO|FIXME|HACK|simplified|assume|heuristic|stub|unimplemented|workaround|mock)\b",
    re.IGNORECASE,
)


def load_rfc_text(rfc_dir, num):
    path = os.path.join(rfc_dir, f"rfc{num}.txt")
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8", errors="ignore") as fp:
            return fp.read()
    except Exception:
        return None


def section_exists_in_rfc(rfc_text, section_str):
    sec_clean = section_str.rstrip(".")
    escaped_sec = re.escape(sec_clean)

    # 1. Section at line start followed by optional dot, spaces, and capital letter title
    pattern1 = re.compile(r"^\s*" + escaped_sec + r"\.?\s+[A-Z]", re.MULTILINE)
    m1 = pattern1.search(rfc_text)
    if m1:
        return True

    # 2. "Section X.Y" or "Section X" in text
    pattern2 = re.compile(r"Section\s+" + escaped_sec + r"\b", re.IGNORECASE)
    if pattern2.search(rfc_text):
        return True

    # 3. Appendix section
    pattern3 = re.compile(r"Appendix\s+" + escaped_sec + r"\b", re.IGNORECASE)
    return bool(pattern3.search(rfc_text))


def audit_codebase(rfc_dir, report_path):
    citations = []
    discrepancies = []
    heuristic_markers = []
    stats = defaultdict(int)

    for root, _, files in os.walk("."):
        if any(skip in root for skip in [".git", ".ruff_cache", "vendor", ".superpowers"]):
            continue
        for f in files:
            if not f.endswith(".goose"):
                continue
            path = os.path.join(root, f)
            rel_path = os.path.relpath(path, ".").replace("\\", "/")
            try:
                with open(path, encoding="utf-8", errors="ignore") as fp:
                    lines = fp.readlines()
            except Exception:
                continue

            for line_idx, line in enumerate(lines, start=1):
                h_match = HEURISTIC_RE.search(line)
                if h_match and ("// " in line or "/*" in line):
                    heuristic_markers.append(
                        {
                            "file": rel_path,
                            "line": line_idx,
                            "marker": h_match.group(1),
                            "text": line.strip(),
                        }
                    )

                for match in CITATION_RE.finditer(line):
                    rfc_num = int(match.group(1))
                    sec = match.group(2) if match.group(2) else None
                    title = match.group(3).strip() if match.group(3) else None
                    stats["total_citations"] += 1

                    citation_entry = {
                        "file": rel_path,
                        "line": line_idx,
                        "rfc": rfc_num,
                        "section": sec,
                        "title": title,
                        "text": line.strip(),
                    }
                    citations.append(citation_entry)

                    rfc_text = load_rfc_text(rfc_dir, rfc_num)
                    if rfc_text is None:
                        stats["missing_rfcs"] += 1
                        discrepancies.append(
                            {
                                "type": "MISSING_RFC_SPEC",
                                "severity": "CRITICAL" if rfc_num < 15000 else "FICTIONAL",
                                "file": rel_path,
                                "line": line_idx,
                                "rfc": rfc_num,
                                "section": sec,
                                "reason": f"RFC {rfc_num} is referenced in code but missing from {rfc_dir}",
                            }
                        )
                        continue

                    if sec:
                        stats["section_citations"] += 1
                        if not section_exists_in_rfc(rfc_text, sec):
                            stats["invalid_sections"] += 1
                            discrepancies.append(
                                {
                                    "type": "NON_EXISTENT_SECTION",
                                    "severity": "HIGH",
                                    "file": rel_path,
                                    "line": line_idx,
                                    "rfc": rfc_num,
                                    "section": sec,
                                    "reason": f"Section {sec} cited in comment was not found in RFC {rfc_num} text",
                                }
                            )
                        else:
                            stats["verified_sections"] += 1

    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    report_data = {
        "stats": dict(stats),
        "discrepancies": discrepancies,
        "heuristic_markers": heuristic_markers,
        "citations_sample_count": len(citations),
    }

    with open(report_path, "w", encoding="utf-8") as fp:
        json.dump(report_data, fp, indent=2)

    print("=" * 70)
    print("  STATIC CITATION & HALLUCINATION AUDIT REPORT")
    print("=" * 70)
    print(f"RFC Corpus Directory: {rfc_dir}")
    print(f"Total RFC citations scanned: {stats['total_citations']}")
    print(f"Citations with specific section numbers: {stats['section_citations']}")
    print(f"Verified accurate sections: {stats['verified_sections']}")
    print(f"Non-existent / mismatched sections: {stats['invalid_sections']}")
    print(f"References to missing or fictional RFCs: {stats['missing_rfcs']}")
    print(f"Code heuristic / TODO / stub markers: {len(heuristic_markers)}")
    print(f"\nDetailed report saved to: {report_path}")
    print("=" * 70)

    if discrepancies:
        print("\nTop Discrepancies Sample (first 15):")
        for d in discrepancies[:15]:
            sec_info = f" §{d['section']}" if d.get("section") else ""
            print(
                f"  [{d['severity']}] {d['file']}:{d['line']} -> RFC {d['rfc']}{sec_info} : {d['reason']}"
            )

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Audit RFC citations and hallucinations in codebase"
    )
    parser.add_argument(
        "--rfc-dir",
        "-d",
        default=DEFAULT_RFC_DIR,
        help="Path to directory containing downloaded RFC txt files (default: .gemini/rfc, e.g. .claude/rfc)",
    )
    parser.add_argument(
        "--report",
        "-r",
        default=DEFAULT_REPORT_PATH,
        help="Path to output JSON report (default: .gemini/audit_reports/rfc_citation_discrepancies.json)",
    )
    args = parser.parse_args()
    return audit_codebase(os.path.abspath(args.rfc_dir), os.path.abspath(args.report))


if __name__ == "__main__":
    sys.exit(main())
