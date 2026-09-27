"""Repro for F-001 — demonstrates the missing --quiet CLI flag.

This script shows that:
1. `python3 -m crc16_xmodem --data 31 32 33 34 35 36 37 38 39` always prints `0x31C3`
2. There is no `--quiet` flag (argparse rejects it)
3. The user has no opt-out for piping-only use

Run:
    python3 repro.py
"""

from __future__ import annotations
import subprocess
import sys


def main() -> int:
    # Case 1: normal invocation always prints the CRC
    result = subprocess.run(
        [sys.executable, "-m", "crc16_xmodem", "--data",
         "31", "32", "33", "34", "35", "36", "37", "38", "39"],
        capture_output=True, text=True, timeout=10,
    )
    print(f"[normal] exit={result.returncode} stdout={result.stdout.strip()!r}")

    # Case 2: --quiet is rejected
    result = subprocess.run(
        [sys.executable, "-m", "crc16_xmodem", "--quiet", "--data", "31"],
        capture_output=True, text=True, timeout=10,
    )
    print(f"[--quiet] exit={result.returncode} stderr={result.stderr.strip()!r}")

    print()
    print("Conclusion: F-001 is correctly characterised as a CLI ergonomics gap.")
    print("The --quiet flag does not exist; users who want silence must filter stdout.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())