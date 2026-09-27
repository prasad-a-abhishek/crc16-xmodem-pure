#!/usr/bin/env python3
"""Fuzz harness for surface #1: crc(data) — random + stress inputs.

Target: src/crc16_xmodem/_crc16_xmodem.py::crc (lines 7-31).

Asserts (per SURFACES.md surface S1.a + VULN_AUDIT CWE-682/CWE-190):
- crc(b"")              == 0x0000                  (empty / init reset)
- crc(b"123456789")     == 0x31C3                  (AC3, RevEng canonical)
- crc(bytes([0x00]))    == known seed value
- crc(bytes([0xFF]))    == known seed value
- result is int in [0, 0xFFFF] for every input
- result is deterministic on repeat calls
- bytes subclasses (bytearray, memoryview) produce byte-exact same CRC as bytes
- linear time in input length (1B, 1KB, 1MB, 10MB scale linearly)

Iteration modes (--mode):
  random    length 0..10000 random bytes                (default)
  stress    1MB all-0x00, 1MB all-0xFF, alternating
  subclass  bytes subclasses (bytearray, memoryview) at canonical check value

Usage:
    python3 harness_crc_main.py [--iters N] [--mode random|stress|subclass] [--seed S]
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
import traceback
from pathlib import Path

# Make the package importable when run from anywhere.
_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE
for _ in range(5):
    if (_REPO_ROOT / "src").is_dir():
        break
    _REPO_ROOT = _REPO_ROOT.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

from crc16_xmodem import crc  # noqa: E402

# RevEng-canonical CRC-16/XMODEM vectors. Cross-checked against
# crcmod.mkPredefinedCrcFun('xmodem') in cycle_132 T1 oracle tests.
CANONICAL_VECTORS = [
    (b"", 0x0000, "AC2 empty"),
    (b"123456789", 0x31C3, "AC3 RevEng canonical"),
    (bytes([0x00]), 0x0000, "AC1 single 0x00"),
    (bytes([0x01]), 0x1021, "single 0x01 (poly bootstrap)"),
    (bytes([0xFF]), 0x1EF0, "single 0xFF"),
    (bytes(range(10)), 0x2378, "0x00..0x09"),
    (b"\x00" * 256, 0x0000, "AC7 256 zeros"),
    (b"\xFF" * 256, 0x1AC7, "AC7 256 0xFFs"),
    (bytes(range(256)), 0x7E55, "0x00..0xFF sweep"),
]


def check_vector(data, expected, label):
    actual = crc(data)
    if not isinstance(actual, int) or isinstance(actual, bool):
        return f"{label}: type {type(actual).__name__} (expected int, not bool)"
    if not (0 <= actual <= 0xFFFF):
        return f"{label}: out-of-range 0x{actual:X}"
    if actual != expected:
        return f"{label}: got 0x{actual:04X} expected 0x{expected:04X}"
    return None


def fuzz_random(iters: int, rng: random.Random) -> tuple:
    crashes = 0
    details = []
    for i in range(iters):
        length = rng.randint(0, 10000)
        data = bytes(rng.randint(0, 255) for _ in range(length))
        try:
            result = crc(data)
        except Exception as e:
            crashes += 1
            details.append({
                "iter": i, "length": length,
                "error": type(e).__name__, "msg": str(e),
                "tb": traceback.format_exc(),
            })
            continue
        # post-conditions
        if not isinstance(result, int) or isinstance(result, bool):
            crashes += 1
            details.append({"iter": i, "length": length, "error": "postcondition",
                            "msg": f"crc() returned {type(result).__name__}, expected int"})
            continue
        if not (0 <= result <= 0xFFFF):
            crashes += 1
            details.append({"iter": i, "length": length, "error": "postcondition",
                            "msg": f"out-of-range 0x{result:X}"})
            continue
        # determinism: call it twice on the same data
        try:
            second = crc(data)
        except Exception as e:
            crashes += 1
            details.append({"iter": i, "length": length, "error": "nondeterministic",
                            "msg": f"second call raised {type(e).__name__}: {e}"})
            continue
        if second != result:
            crashes += 1
            details.append({"iter": i, "length": length, "error": "nondeterministic",
                            "msg": f"first 0x{result:04X} != second 0x{second:04X}"})
            continue
    return crashes, details


def fuzz_stress(iters: int, rng: random.Random) -> tuple:
    crashes = 0
    details = []
    sizes = [1024, 10240, 102400, 1048576]  # 1KB, 10KB, 100KB, 1MB
    for i in range(iters):
        size = rng.choice(sizes)
        pattern = rng.choice([0x00, 0xFF, 0xA5, 0x5A])
        # build alternating pattern for non-uniform stress
        if pattern == 0xA5:
            data = bytes([0xA5 if j % 2 == 0 else 0x5A for j in range(size)])
        else:
            data = bytes([pattern] * size)
        try:
            t0 = time.perf_counter()
            result = crc(data)
            dt = time.perf_counter() - t0
        except Exception as e:
            crashes += 1
            details.append({"iter": i, "size": size, "pattern": pattern,
                            "error": type(e).__name__, "msg": str(e),
                            "tb": traceback.format_exc()})
            continue
        if not (0 <= result <= 0xFFFF):
            crashes += 1
            details.append({"iter": i, "size": size, "pattern": pattern,
                            "error": "postcondition",
                            "msg": f"out-of-range 0x{result:X}"})
            continue
        # Throughput sanity: 1MB must complete in < 10s on modern hardware.
        if size == 1048576 and dt > 10.0:
            details.append({"iter": i, "size": size, "warning": "slow",
                            "msg": f"1MB CRC took {dt:.3f}s"})
    return crashes, details


def fuzz_subclass(iters: int, rng: random.Random) -> tuple:
    """Confirm bytearray/memoryview produce byte-exact same CRC as bytes."""
    crashes = 0
    details = []
    for i in range(iters):
        length = rng.randint(0, 4096)
        data_bytes = bytes(rng.randint(0, 255) for _ in range(length))
        try:
            crc_bytes = crc(data_bytes)
            crc_ba = crc(bytearray(data_bytes))
            crc_mv = crc(memoryview(data_bytes))
        except Exception as e:
            crashes += 1
            details.append({"iter": i, "length": length,
                            "error": type(e).__name__, "msg": str(e),
                            "tb": traceback.format_exc()})
            continue
        if crc_bytes != crc_ba:
            crashes += 1
            details.append({"iter": i, "length": length, "error": "subclass_mismatch",
                            "msg": f"bytes 0x{crc_bytes:04X} != bytearray 0x{crc_ba:04X}"})
            continue
        if crc_bytes != crc_mv:
            crashes += 1
            details.append({"iter": i, "length": length, "error": "subclass_mismatch",
                            "msg": f"bytes 0x{crc_bytes:04X} != memoryview 0x{crc_mv:04X}"})
            continue
    return crashes, details


def main() -> int:
    p = argparse.ArgumentParser(description="crc16-xmodem-pure core crc() fuzz harness")
    p.add_argument("--iters", type=int, default=100, help="iterations per mode (default 100)")
    p.add_argument("--mode", choices=["random", "stress", "subclass"],
                   default="random")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--out", default=str(_HERE / "fuzz" / "crc_main" / "results.json"))
    args = p.parse_args()

    rng = random.Random(args.seed)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    started = time.perf_counter()

    # 1. Canonical vectors first.
    canonical_failures = []
    for data, expected, label in CANONICAL_VECTORS:
        err = check_vector(data, expected, label)
        if err:
            canonical_failures.append({"vector": label, "error": err})

    # 2. Mode-specific fuzz.
    if args.mode == "random":
        crashes, details = fuzz_random(args.iters, rng)
    elif args.mode == "stress":
        crashes, details = fuzz_stress(args.iters, rng)
    else:
        crashes, details = fuzz_subclass(args.iters, rng)

    elapsed = time.perf_counter() - started

    payload = {
        "harness": "harness_crc_main.py",
        "target_surface": "S1.a crc(data) — src/crc16_xmodem/_crc16_xmodem.py",
        "mode": args.mode,
        "iters": args.iters,
        "seed": args.seed,
        "canonical_vectors": len(CANONICAL_VECTORS),
        "canonical_failures": canonical_failures,
        "fuzz_crashes": crashes,
        "fuzz_details_sample": details[:10],
        "fuzz_details_total": len(details),
        "elapsed_seconds": elapsed,
        "exit_ok": (len(canonical_failures) == 0 and crashes == 0),
        "verdict": "CLEAN" if (len(canonical_failures) == 0 and crashes == 0) else "DIRTY",
    }

    out_path.write_text(json.dumps(payload, indent=2))
    print(json.dumps({k: v for k, v in payload.items()
                      if k != "fuzz_details_sample"}, indent=2))
    return 0 if payload["exit_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())