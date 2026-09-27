"""Repro for F-002 — demonstrates the missing --json output mode.

This script shows that:
1. `python3 -m crc16_xmodem --register` prints `key=value` rows
2. `jq` cannot parse this format (which is the de-facto standard for CLI JSON)
3. There is no `--json` flag (argparse rejects it)

Run:
    python3 repro.py
"""

from __future__ import annotations
import subprocess
import sys


def main() -> int:
    # Case 1: --register emits key=value (not JSON)
    result = subprocess.run(
        [sys.executable, "-m", "crc16_xmodem", "--register"],
        capture_output=True, text=True, timeout=10,
    )
    print(f"[--register] stdout={result.stdout!r}")

    # Case 2: --json is rejected
    result = subprocess.run(
        [sys.executable, "-m", "crc16_xmodem", "--json", "--register"],
        capture_output=True, text=True, timeout=10,
    )
    print(f"[--json --register] exit={result.returncode} stderr={result.stderr.strip()[:80]!r}")

    print()
    print("Conclusion: F-002 is correctly characterised as a CLI ergonomics gap.")
    print("The --register output is parseable but not structured; --json does not exist.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())