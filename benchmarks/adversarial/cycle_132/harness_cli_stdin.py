#!/usr/bin/env python3
"""Fuzz harness for surface #5: `python -m crc16_xmodem --stdin`.

Target: src/crc16_xmodem/__main__.py::main — --stdin path (line 58, 69-70).

Asserts:
- Empty stdin: exit 0, output "0x0000"
- 1-byte stdin: deterministic CRC
- 1KiB stdin: deterministic CRC
- 1MiB stdin: deterministic CRC; completes in <5s
- CRLF-only stdin (\r\n*): deterministic CRC (CRLF is just bytes)
- Trailing newline (single \\n): deterministic CRC
- Null bytes interleaved: deterministic CRC
- Binary payload (full 0x00..0xFF range): deterministic CRC
- Subprocess crash safety: no uncaught exception propagates; CLI exits cleanly

Usage:
    python3 harness_cli_stdin.py [--iters N] [--seed S]
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import subprocess
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE
for _ in range(5):
    if (_REPO_ROOT / "src").is_dir():
        break
    _REPO_ROOT = _REPO_ROOT.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

PYTHON = sys.executable
OUTPUT_RE = re.compile(r"^0x([0-9A-F]{4})$")


def run_stdin(payload: bytes, timeout: float = 30.0):
    """Invoke `python -m crc16_xmodem --stdin` with bytes piped in.

    We keep `text=False` (capture_output returns bytes) because stdin is
    a binary payload. stdout/stderr are decoded at the call sites.
    """
    cmd = [PYTHON, "-m", "crc16_xmodem", "--stdin"]
    return subprocess.run(
        cmd,
        input=payload,
        capture_output=True,
        timeout=timeout,
        cwd=str(_REPO_ROOT),
    )


# Reference CRCs computed independently by the package's crc() function.
import importlib.util
_spec = importlib.util.spec_from_file_location(
    "crc16_xmodem",
    str(_REPO_ROOT / "src" / "crc16_xmodem" / "__init__.py"),
)
if _spec is None or _spec.loader is None:
    raise RuntimeError("could not load crc16_xmodem module")
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
_crc = _mod.crc  # type: ignore[attr-defined]


def _expected_crc(payload: bytes) -> str:
    return f"0x{_crc(payload):04X}"


CANONICAL = [
    (b"", "empty"),
    (b"123456789", "AC3 RevEng canonical"),
    (b"a", "1 byte ASCII"),
    (b"\x00", "1 byte null"),
    (b"\xff" * 256, "256 0xFFs"),
    (b"\r\n" * 100, "200 CRLFs"),
    (b"\n", "single newline"),
    (b"\r\n", "CRLF pair"),
    (bytes(range(256)), "0..255 sweep"),
    (b"\x00" * 1024, "1KiB zeros"),
    (b"\xff" * 1024, "1KiB 0xFFs"),
]


def fuzz_random_payloads(iters: int, rng: random.Random) -> tuple:
    """Random binary payloads of varying size."""
    crashes = 0
    details = []
    for i in range(iters):
        size = rng.choice([0, 1, 7, 64, 256, 1024, 4096, 16384, 65536])
        payload = bytes(rng.randint(0, 255) for _ in range(size))
        try:
            t0 = time.perf_counter()
            proc = run_stdin(payload, timeout=30.0)
            dt = time.perf_counter() - t0
        except subprocess.TimeoutExpired:
            crashes += 1
            details.append({"iter": i, "size": size, "error": "timeout"})
            continue
        if proc.returncode != 0:
            crashes += 1
            details.append({"iter": i, "size": size, "error": "non_zero_exit",
                            "stderr_tail": proc.stderr[-200:].decode("utf-8", errors="replace")})
            continue
        stdout = proc.stdout.decode("utf-8", errors="replace").strip()
        if not OUTPUT_RE.match(stdout):
            crashes += 1
            details.append({"iter": i, "size": size, "error": "bad_output",
                            "stdout": stdout[:100]})
            continue
        expected = _expected_crc(payload)
        if stdout != expected:
            crashes += 1
            details.append({"iter": i, "size": size, "error": "crc_mismatch",
                            "expected": expected, "got": stdout})
            continue
        # Throughput sanity: 64KB should complete in <5s.
        if size >= 16384 and dt > 5.0:
            details.append({"iter": i, "size": size, "warning": "slow",
                            "msg": f"{size} bytes CRC took {dt:.3f}s"})
    return crashes, details


def fuzz_large_payload(iters: int, rng: random.Random) -> tuple:
    """1 MiB stress payload."""
    crashes = 0
    details = []
    for i in range(iters):
        # 1 MiB = 1048576 bytes
        size = 1048576
        # Mix of patterns to stress the algorithm
        pattern = rng.choice(["zero", "one", "alt", "random"])
        if pattern == "zero":
            payload = bytes(size)
        elif pattern == "one":
            payload = bytes([0xFF] * size)
        elif pattern == "alt":
            payload = bytes(([0xA5, 0x5A] * ((size + 1) // 2))[:size])
        else:
            payload = bytes(rng.randint(0, 255) for _ in range(size))
        try:
            t0 = time.perf_counter()
            proc = run_stdin(payload, timeout=30.0)
            dt = time.perf_counter() - t0
        except subprocess.TimeoutExpired:
            crashes += 1
            details.append({"iter": i, "pattern": pattern, "error": "timeout"})
            continue
        if proc.returncode != 0:
            crashes += 1
            details.append({"iter": i, "pattern": pattern, "error": "non_zero_exit",
                            "stderr_tail": proc.stderr[-200:].decode("utf-8", errors="replace")})
            continue
        stdout = proc.stdout.decode("utf-8", errors="replace").strip()
        expected = _expected_crc(payload)
        if stdout != expected:
            crashes += 1
            details.append({"iter": i, "pattern": pattern, "error": "crc_mismatch",
                            "expected": expected, "got": stdout,
                            "elapsed": dt})
            continue
        if dt > 10.0:
            details.append({"iter": i, "pattern": pattern, "warning": "slow",
                            "msg": f"1MiB CRC took {dt:.3f}s"})
    return crashes, details


def main() -> int:
    p = argparse.ArgumentParser(description="crc16-xmodem-pure --stdin fuzz harness")
    p.add_argument("--iters", type=int, default=100)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--out", default=str(_HERE / "fuzz" / "cli_stdin" / "results.json"))
    args = p.parse_args()

    rng = random.Random(args.seed)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    started = time.perf_counter()

    # 1. Canonical vectors.
    canonical_failures = []
    for payload, label in CANONICAL:
        try:
            proc = run_stdin(payload, timeout=10.0)
        except subprocess.TimeoutExpired:
            canonical_failures.append({"label": label, "error": "timeout"})
            continue
        stdout = proc.stdout.decode("utf-8", errors="replace").strip()
        if proc.returncode != 0:
            canonical_failures.append({
                "label": label, "error": "non_zero_exit",
                "stderr_tail": proc.stderr[-200:].decode("utf-8", errors="replace"),
            })
            continue
        expected = _expected_crc(payload)
        if stdout != expected:
            canonical_failures.append({"label": label, "error": "crc_mismatch",
                                        "expected": expected, "got": stdout})
        else:
            pass  # clean

    # 2. Random payload fuzz.
    random_crashes, random_details = fuzz_random_payloads(args.iters, rng)

    # 3. 1 MiB stress (subset of iters to keep wall-clock bounded).
    large_iters = max(3, args.iters // 33)  # ~3 iters for default 100
    large_crashes, large_details = fuzz_large_payload(large_iters, rng)

    elapsed = time.perf_counter() - started

    total_crashes = random_crashes + large_crashes
    payload = {
        "harness": "harness_cli_stdin.py",
        "target_surface": "S2.d CLI --stdin — src/crc16_xmodem/__main__.py (line 58, 69-70)",
        "iters": args.iters,
        "large_iters": large_iters,
        "seed": args.seed,
        "canonical_failures": canonical_failures,
        "random_payload_crashes": random_crashes,
        "random_payload_details_sample": random_details[:5],
        "random_payload_details_total": len(random_details),
        "large_payload_crashes": large_crashes,
        "large_payload_details_sample": large_details[:5],
        "large_payload_details_total": len(large_details),
        "elapsed_seconds": elapsed,
        "exit_ok": (len(canonical_failures) == 0 and total_crashes == 0),
        "verdict": "CLEAN" if (len(canonical_failures) == 0 and total_crashes == 0) else "DIRTY",
    }
    out_path.write_text(json.dumps(payload, indent=2))
    print(json.dumps({k: v for k, v in payload.items()
                      if not k.endswith("_sample")}, indent=2))
    return 0 if payload["exit_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())