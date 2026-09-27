"""Repro for F-004 — demonstrates the missing --version CLI flag.

This script shows that:
1. `python3 -m crc16_xmodem --version` is rejected by argparse
2. `python3 -m crc16_xmodem -V` is rejected by argparse
3. The version IS available via the Python API (`crc16_xmodem.__version__`)

Run:
    python3 repro.py
"""

from __future__ import annotations
import subprocess
import sys


def main() -> int:
    # Case 1: --version rejected
    result = subprocess.run(
        [sys.executable, "-m", "crc16_xmodem", "--version"],
        capture_output=True, text=True, timeout=10,
    )
    print(f"[--version] exit={result.returncode} stderr={result.stderr.strip()[:80]!r}")

    # Case 2: -V rejected
    result = subprocess.run(
        [sys.executable, "-m", "crc16_xmodem", "-V"],
        capture_output=True, text=True, timeout=10,
    )
    print(f"[-V] exit={result.returncode} stderr={result.stderr.strip()[:80]!r}")

    # Case 3: Python API exposes the version
    code = "import crc16_xmodem; print(crc16_xmodem.__version__)"
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True, timeout=10,
    )
    print(f"[python api] exit={result.returncode} stdout={result.stdout.strip()!r}")

    print()
    print("Conclusion: F-004 is correctly characterised as a CLI ergonomics gap.")
    print("The version IS available via Python API but not exposed as a CLI flag.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())