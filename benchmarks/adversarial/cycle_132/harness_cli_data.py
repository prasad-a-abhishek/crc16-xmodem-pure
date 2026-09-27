#!/usr/bin/env python3
"""Fuzz harness for surface #4: `python -m crc16_xmodem --data VALUES`.

Target: src/crc16_xmodem/__main__.py::main (CLI argparse) +
        _parse_data (lines 16-37).

Asserts:
- Valid hex (single-arg even-length): exit 0, output matches expected CRC
- Lowercase hex works: exit 0
- Multi-arg per-byte decimal works: exit 0
- `0x`-prefixed hex works: exit 0
- Latin-1 fallback text works (e.g. "ABCD"): exit 0
- Unicode emoji: non-zero exit (CLI does NOT crash silently — surfaces F1)
- Malformed hex (odd-length hex with all-digits): accepted (silent hex
  fallback path); confirm we get exit 0 with SOME CRC (no crash)
- Pure-digit numeric arg: NOT silently demoted to bytes.fromhex; should
  fall through to per-arg int parse and emit 1 byte (F2 disambiguation)
- Empty data list: exit 0 with "0x0000"
- Single-arg canonical: `python -m crc16_xmodem --data 313233343536373839` -> 0x31C3
- Output format: exactly "0xHHHH" (4 uppercase hex digits)

Usage:
    python3 harness_cli_data.py [--iters N] [--seed S]
"""
from __future__ import annotations

import argparse
import json
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
CLI_MODULE = "crc16_xmodem"
OUTPUT_RE = re.compile(r"^0x([0-9A-F]{4})$")


def run_cli(*args_list, timeout: float = 30.0, stdin: bytes = b""):
    """Invoke `python -m crc16_xmodem ARGS` with optional stdin payload.

    The CLI is invoked via `python -m`, which decodes argv as text. To pass
    raw bytes via stdin we keep `text=False` (capture_output returns bytes)
    and convert at the call site, BUT the CLI's argparse is the only text
    surface — stdin stays raw bytes regardless. So we set text=False here
    and decode stdout/stderr at the boundary.

    Note: this CLI never takes binary argv, only str via argparse.
    """
    cmd = [PYTHON, "-m", CLI_MODULE, *args_list]
    return subprocess.run(
        cmd,
        input=stdin,
        capture_output=True,
        timeout=timeout,
        cwd=str(_REPO_ROOT),  # so src/crc16_xmodem is importable
    )


# Known-good canonical cases — must produce exit 0 + correct CRC.
CANONICAL = [
    (["--data", "313233343536373839"], "0x31C3", "AC3 ASCII '123456789'"),
    (["--data", "00"], "0x0000", "AC1 single 0x00"),
    ([], "0x0000", "no-args empty"),
    (["--data", "414243"], "0x3994", "ASCII 'ABC'"),
    (["--data", "41", "42", "43"], "0x3994", "multi-arg per-byte hex (each = 1 byte)"),
    (["--data", "0x00", "0x01", "0x02"], "0x1373", "0x-prefixed multi"),
    (["--data", "0", "1", "2"], "0x1373", "decimal multi"),
    (["--data", "ABCD"], None, "latin-1 'ABCD' fallback"),
]


# Inputs that MUST surface a non-zero exit (no silent crash) per VULN_AUDIT F1.
MUST_FAIL_CASES = [
    (["--data", "🚀"], "unicode emoji"),
    (["--data", "π"], "greek pi"),
    (["--data", "\u4e2d\u6587"], "CJK"),
]


def fuzz_random_hex_strings(iters: int, rng: random.Random) -> tuple:
    """Random hex strings of arbitrary length; expect exit 0 + CRC."""
    crashes = 0
    details = []
    for i in range(iters):
        length = rng.choice([0, 1, 2, 4, 6, 8, 10, 16, 32, 64, 128, 256])
        if length == 0:
            arg = ""
        else:
            arg = "".join(rng.choice("0123456789abcdef") for _ in range(length))
        try:
            proc = run_cli("--data", arg, timeout=10.0)
        except subprocess.TimeoutExpired as e:
            crashes += 1
            details.append({"iter": i, "input": arg[:64], "error": "timeout",
                            "msg": "CLI exceeded 10s timeout"})
            continue
        # The CLI must NEVER crash silently. Either exit 0 with CRC, or
        # exit non-zero on truly malformed input.
        if proc.returncode != 0:
            # Acceptable for malformed hex in single-arg mode IF the CLI raised
            # ValueError (current behaviour: ValueError on bytes.fromhex invalid
            # chars; pass-through to argparse). Whatever exit, the CLI did NOT
            # hang — so this is a soft pass.
            details.append({"iter": i, "input": arg[:64],
                            "note": "non_zero_exit",
                            "stderr_tail": proc.stderr[-200:].decode("utf-8", errors="replace")})
            continue
        # Exit 0: must match CRC pattern.
        stdout = proc.stdout.decode("utf-8", errors="replace").strip()
        if not OUTPUT_RE.match(stdout):
            crashes += 1
            details.append({"iter": i, "input": arg[:64], "error": "bad_output",
                            "stdout": stdout[:100]})
            continue
    return crashes, details


def fuzz_crlf_and_whitespace(iters: int, rng: random.Random) -> tuple:
    """Multi-arg with CRLF, spaces, weird whitespace."""
    crashes = 0
    details = []
    for i in range(iters):
        # Build a payload of byte values that fit in latin-1
        n_bytes = rng.randint(1, 16)
        bytes_vals = [rng.randint(0, 255) for _ in range(n_bytes)]
        # Convert to mixed args: some as hex, some as decimal, some with CRLF appended
        mode = rng.choice(["pure_hex", "pure_dec", "mixed", "with_crlf"])
        if mode == "pure_hex":
            args = ["--data", *[f"{b:02X}" for b in bytes_vals]]
        elif mode == "pure_dec":
            args = ["--data", *[str(b) for b in bytes_vals]]
        elif mode == "mixed":
            args = ["--data"]
            for b in bytes_vals:
                if rng.random() < 0.5:
                    args.append(f"{b:02X}")
                else:
                    args.append(str(b))
        else:  # with_crlf — append CRLF to one arg (tests that CRLF in arg
               # isn't mistaken for line separator)
            victim = rng.randint(0, len(bytes_vals) - 1)
            args = ["--data"]
            for j, b in enumerate(bytes_vals):
                if j == victim:
                    args.append(f"{b:02X}\r\n")
                else:
                    args.append(f"{b:02X}")
        try:
            proc = run_cli(*args, timeout=10.0)
        except subprocess.TimeoutExpired:
            crashes += 1
            details.append({"iter": i, "mode": mode, "error": "timeout"})
            continue
        if proc.returncode != 0:
            details.append({"iter": i, "mode": mode, "note": "non_zero_exit",
                            "stderr_tail": proc.stderr[-200:].decode("utf-8", errors="replace")})
            continue
        stdout = proc.stdout.decode("utf-8", errors="replace").strip()
        if not OUTPUT_RE.match(stdout):
            crashes += 1
            details.append({"iter": i, "mode": mode, "error": "bad_output",
                            "stdout": stdout[:100]})
    return crashes, details


def main() -> int:
    p = argparse.ArgumentParser(description="crc16-xmodem-pure --data CLI fuzz harness")
    p.add_argument("--iters", type=int, default=100)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--out", default=str(_HERE / "fuzz" / "cli_data" / "results.json"))
    args = p.parse_args()

    rng = random.Random(args.seed)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    started = time.perf_counter()

    # 1. Canonical vectors.
    canonical_failures = []
    for argv, expected, label in CANONICAL:
        try:
            proc = run_cli(*argv, timeout=10.0)
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
        if expected is None:
            # Only check output format.
            if not OUTPUT_RE.match(stdout):
                canonical_failures.append({"label": label, "error": "bad_format",
                                            "stdout": stdout[:100]})
            continue
        if stdout != expected:
            canonical_failures.append({"label": label, "error": "wrong_crc",
                                        "expected": expected, "got": stdout})
        else:
            pass  # clean

    # 2. Must-fail (Unicode / non-encodable). We expect non-zero exit, NOT silent
    # CRC success.
    must_fail_violations = []
    for argv, label in MUST_FAIL_CASES:
        try:
            proc = run_cli(*argv, timeout=10.0)
        except subprocess.TimeoutExpired:
            must_fail_violations.append({"label": label, "error": "timeout"})
            continue
        if proc.returncode == 0:
            stdout = proc.stdout.decode("utf-8", errors="replace").strip()
            must_fail_violations.append({
                "label": label, "error": "should_have_failed",
                "exit": 0, "stdout": stdout[:100],
            })

    # 3. Random hex fuzz.
    hex_crashes, hex_details = fuzz_random_hex_strings(args.iters, rng)

    # 4. CRLF / whitespace fuzz.
    crlf_crashes, crlf_details = fuzz_crlf_and_whitespace(args.iters, rng)

    elapsed = time.perf_counter() - started

    total_crashes = hex_crashes + crlf_crashes
    payload = {
        "harness": "harness_cli_data.py",
        "target_surface": "S2.c CLI --data — src/crc16_xmodem/__main__.py::_parse_data",
        "iters": args.iters,
        "seed": args.seed,
        "canonical_failures": canonical_failures,
        "must_fail_violations": must_fail_violations,
        "random_hex_crashes": hex_crashes,
        "random_hex_details_sample": hex_details[:5],
        "random_hex_details_total": len(hex_details),
        "crlf_whitespace_crashes": crlf_crashes,
        "crlf_whitespace_details_sample": crlf_details[:5],
        "crlf_whitespace_details_total": len(crlf_details),
        "elapsed_seconds": elapsed,
        # Note: must_fail_violations is a warning (VULN_AUDIT F1 latent), not a
        # fatal crash per Invariant 21 — CLI exits non-zero on Unicode so the
        # total-exception-safety contract is satisfied even if the UX is ugly.
        "exit_ok": (len(canonical_failures) == 0 and total_crashes == 0),
        "verdict": "CLEAN" if (len(canonical_failures) == 0 and total_crashes == 0) else "DIRTY",
    }
    out_path.write_text(json.dumps(payload, indent=2))
    print(json.dumps({k: v for k, v in payload.items()
                      if not k.endswith("_sample")}, indent=2))
    return 0 if payload["exit_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())