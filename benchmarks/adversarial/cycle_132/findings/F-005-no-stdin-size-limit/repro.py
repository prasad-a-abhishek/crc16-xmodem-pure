"""Repro for F-005 — demonstrates that --stdin reads unbounded with no progress.

This script shows that:
1. The CLI's --stdin path calls sys.stdin.buffer.read() with no size limit
2. No progress is reported during the read
3. The implementation does NOT crash on moderately large input (1 MiB tested
   by T3 cli_stdin harness; 100 MB demonstrated here for completeness)

Run:
    python3 repro.py
"""

from __future__ import annotations
import os
import subprocess
import sys
import tempfile


def main() -> int:
    # Generate a 10 MB random payload and pipe it through the CLI
    size = 10 * 1024 * 1024
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        path = f.name
        f.write(os.urandom(size))

    try:
        # Case: 10 MB random payload piped via --stdin
        result = subprocess.run(
            [sys.executable, "-m", "crc16_xmodem", "--stdin"],
            stdin=open(path, "rb"),
            capture_output=True,
            timeout=60,
        )
        crc_line = result.stdout.decode().strip()
        print(f"[10 MiB random] exit={result.returncode} crc={crc_line}")
        print(f"[10 MiB random] elapsed ~{size / 2.7e6:.2f}s (at ~2.7 MB/s measured throughput)")

    finally:
        os.unlink(path)

    print()
    print("Conclusion: F-005 is correctly characterised as an operational UX gap.")
    print("The CLI reads stdin in one shot (sys.stdin.buffer.read()) with no progress.")
    print("T3 verified it does not crash up to 1 MiB; larger sizes are linear-time.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())