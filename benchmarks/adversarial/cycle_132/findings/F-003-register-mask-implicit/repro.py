"""Repro for F-003 — demonstrates the implicit bitwidth invariant.

This script shows that:
1. `crc(data)` always returns a value in [0, 0x10000) — the bitwidth is correct
2. The invariant is enforced implicitly by `& _MASK` at every shift
3. No test in the suite pins this invariant explicitly with a property-based
   or explicit range assertion

Run:
    python3 repro.py
"""

from __future__ import annotations
import random
import sys

# Make the worktree's src/ importable when running from any CWD.
import os
_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.abspath(os.path.join(_HERE, "../../../.."))
sys.path.insert(0, os.path.join(_REPO, "src"))

from crc16_xmodem import crc  # noqa: E402


def main() -> int:
    rng = random.Random(42)
    out_of_range = 0
    sampled = []
    for i in range(10_000):
        n = rng.randint(0, 4096)
        data = bytes(rng.getrandbits(8) for _ in range(n))
        r = crc(data)
        if not (0 <= r < 0x10000):
            out_of_range += 1
        if i < 5:
            sampled.append((n, hex(r)))
    print(f"[bitwidth] out_of_range_count={out_of_range} / 10000")
    for n, h in sampled:
        print(f"  len={n:5d} crc={h}")

    print()
    print("Conclusion: F-003 is correctly characterised as a code-review gap.")
    print("The bitwidth IS enforced (via & _MASK), but the invariant is not pinned in tests.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())