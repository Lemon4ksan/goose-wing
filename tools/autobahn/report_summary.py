#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
Summarizes Autobahn RFC 6455 compliance report from reports/autobahn/index.json.
"""

import sys
from pathlib import Path

cur_dir = Path(__file__).resolve().parent
if str(cur_dir) not in sys.path:
    sys.path.insert(0, str(cur_dir))

from runner import print_summary_table


def main():
    root = cur_dir.parent.parent
    reports_dir = root / "reports" / "autobahn"
    if len(sys.argv) > 1:
        reports_dir = Path(sys.argv[1])

    total, _passed, failed = print_summary_table(reports_dir)
    sys.exit(0 if failed == 0 and total > 0 else 1)


if __name__ == "__main__":
    main()
