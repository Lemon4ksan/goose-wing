#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
Automated regression exporter from external protocol tools (h2spec, autobahn, tls)
to in-memory Gosling REPL verification scripts (.repl).

Captures wire-level payloads and transforms them into page-edge memory tests
with deterministic assertions and hardware trap validations.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def bytes_to_hex_str(data: bytes) -> str:
    """Formats raw bytes as uppercase hexadecimal string."""
    return data.hex().upper()


def generate_repl_regression(
    name: str,
    payload: bytes | str,
    parser_call: str,
    expected_result: int | None = None,
    expected_trap: str | None = None,
    description: str = "",
    use_page_edge: bool = True,
) -> str:
    """
    Generates a reproducible .repl regression block.

    Args:
        name: Name or case identifier of the regression.
        payload: Wire payload (bytes, hex string, or escaped string).
        parser_call: Function call expression, e.g. 'parse_and_validate_h2_frame(EDGE_ADDR, 1)'.
        expected_result: Expected return value (if positive assertion).
        expected_trap: Expected Wasm Trap (if negative assertion, e.g. 'OutOfBoundsMemoryAccess').
        description: Informational comment or RFC reference.
        use_page_edge: If True, uses :pkt_edge to place bytes flush against Wasm 64KB page boundary.
    """
    lines: list[str] = [
        "# -----------------------------------------------------------------------------",
        f"# Regression Vector: {name}",
    ]
    if description:
        lines.append(f"# Context: {description}")
    lines.append("# -----------------------------------------------------------------------------")

    if isinstance(payload, bytes):
        payload_str = bytes_to_hex_str(payload)
    else:
        payload_str = payload.strip()

    if use_page_edge:
        lines.append(f':pkt_edge "{payload_str}"' if '"' in payload_str else f":pkt_edge {payload_str}")
        lines.append(":mem EDGE_ADDR EDGE_LEN")
    else:
        lines.append(f":pkt 2048 {payload_str}")
        lines.append(":mem 2048 32")

    if expected_trap:
        lines.append(f":assert_trap {parser_call} {expected_trap}")
    elif expected_result is not None:
        lines.append(f":assert {parser_call} == {expected_result}")
    else:
        lines.append(f":eval {parser_call}")

    lines.append("")
    return "\n".join(lines)


def append_to_repl_file(
    repl_path: Path,
    name: str,
    payload: bytes | str,
    parser_call: str,
    expected_result: int | None = None,
    expected_trap: str | None = None,
    description: str = "",
) -> None:
    """Appends a new regression block to an existing or new .repl file."""
    content = generate_repl_regression(
        name=name,
        payload=payload,
        parser_call=parser_call,
        expected_result=expected_result,
        expected_trap=expected_trap,
        description=description,
        use_page_edge=True,
    )
    with repl_path.open("a", encoding="utf-8") as f:
        f.write("\n" + content + "\n")
    print(f"[+] Appended regression vector '{name}' to {repl_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Gosling REPL Regression Exporter for protocol crash reproduction"
    )
    parser.add_argument("--name", required=True, help="Test case or vector name")
    parser.add_argument("--payload", required=True, help="Raw hex payload or string")
    parser.add_argument("--parser", required=True, help="Parser function call (e.g. 'parse_frame(EDGE_ADDR, EDGE_LEN)')")
    parser.add_argument("--expected", type=int, default=None, help="Expected return integer code")
    parser.add_argument("--trap", default=None, help="Expected Wasm trap (e.g. 'OutOfBoundsMemoryAccess')")
    parser.add_argument("--desc", default="", help="Description or RFC reference")
    parser.add_argument("--output", type=Path, default=None, help="Target .repl file to write or append to")

    args = parser.parse_args()

    if args.output:
        append_to_repl_file(
            args.output,
            name=args.name,
            payload=args.payload,
            parser_call=args.parser,
            expected_result=args.expected,
            expected_trap=args.trap,
            description=args.desc,
        )
    else:
        output_txt = generate_repl_regression(
            name=args.name,
            payload=args.payload,
            parser_call=args.parser,
            expected_result=args.expected,
            expected_trap=args.trap,
            description=args.desc,
            use_page_edge=True,
        )
        sys.stdout.write(output_txt + "\n")


if __name__ == "__main__":
    main()
