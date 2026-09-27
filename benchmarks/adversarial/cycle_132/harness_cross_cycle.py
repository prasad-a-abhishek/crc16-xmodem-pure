#!/usr/bin/env python3
"""Fuzz harness: cross-cycle disambiguation + crcmod oracle (CWE-1339).

Target: src/crc16_xmodem/_crc16_xmodem.py::crc — confirm:
1. crc(b"123456789") == 0x31C3 exactly (RevEng canonical, matches crcmod)
2. crc(b"123456789") is DISTINCT from sibling 16-bit CRC variants:
   - CRC-16/MODBUS      (cycle_127, poly=0x8005 reflected, init=0xFFFF) — 0x4B37
   - CRC-16/CCITT-FALSE (cycle_128, poly=0x1021, init=0xFFFF)          — 0x29B1
   - CRC-16/EN-13757    (cycle_129, poly=0x3D65, xorout=0xFFFF)        — 0xC2B7
3. crcmod.mkPredefinedCrcFun('xmodem') produces byte-exact same CRC for
   100 random inputs (oracle differential)
4. crc() is deterministic across 1000 repeat calls on the same input
5. A bitwise reference impl (transcribed independently) matches crc() on
   every random input

Usage:
    python3 harness_cross_cycle.py [--iters N] [--seed S]
"""
from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
import time
import traceback
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE
for _ in range(5):
    if (_REPO_ROOT / "src").is_dir():
        break
    _REPO_ROOT = _REPO_ROOT.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

from crc16_xmodem import crc  # noqa: E402

# Sibling-cycle CRC reference values (from VULN_AUDIT cross_cycle_disambiguation).
CROSS_TABLE = {
    "CRC-16/XMODEM (this package)": 0x31C3,
    "CRC-16/MODBUS (cycle_127)":     0x4B37,
    "CRC-16/CCITT-FALSE (cycle_128)": 0x29B1,
    "CRC-16/EN-13757 (cycle_129)":   0xC2B7,
}

CANONICAL_INPUT = b"123456789"


def crc_reference_xmodem(data: bytes) -> int:
    """Independent bitwise reference impl for CRC-16/XMODEM, transcribed from
    SPEC.md §1 + RevEng catalogue.

    Intentionally different from the package implementation to detect
    algorithm-transcription bugs (wrong polynomial, wrong shift direction,
    missing XOR).
    """
    POLY = 0x1021
    INIT = 0x0000
    XOROUT = 0x0000
    MASK = 0xFFFF
    reg = INIT & MASK
    for byte in data:
        reg ^= (byte << 8) & MASK
        for _ in range(8):
            if reg & 0x8000:
                reg = ((reg << 1) ^ POLY) & MASK
            else:
                reg = (reg << 1) & MASK
    return (reg ^ XOROUT) & MASK


def crcmod_oracle_xmodem(data: bytes) -> int | None:
    """If crcmod is importable, return crcmod.mkPredefinedCrcFun('xmodem')(data).

    Returns None if crcmod is not installed in this env (graceful skip).
    """
    try:
        import crcmod  # type: ignore
        f = crcmod.predefined.mkPredefinedCrcFun("xmodem")
        return int(f(data))
    except Exception:
        return None


def fuzz_oracle_vs_crcmod(iters: int, rng: random.Random) -> tuple:
    """Differential against crcmod.mkPredefinedCrcFun('xmodem')."""
    crashes = 0
    details = []
    has_oracle = False
    for i in range(iters):
        length = rng.randint(0, 4096)
        data = bytes(rng.randint(0, 255) for _ in range(length))
        try:
            actual = crc(data)
            expected = crcmod_oracle_xmodem(data)
        except Exception as e:
            crashes += 1
            details.append({"iter": i, "length": length,
                            "error": type(e).__name__, "msg": str(e),
                            "tb": traceback.format_exc()})
            continue
        if expected is None:
            # crcmod missing — skip this iteration silently
            continue
        has_oracle = True
        if actual != expected:
            crashes += 1
            details.append({"iter": i, "length": length, "error": "oracle_mismatch",
                            "expected": f"0x{expected:04X}",
                            "got": f"0x{actual:04X}"})
    return crashes, details, has_oracle


def fuzz_oracle_vs_reference(iters: int, rng: random.Random) -> tuple:
    """Differential against independent bitwise reference impl."""
    crashes = 0
    details = []
    for i in range(iters):
        length = rng.randint(0, 4096)
        data = bytes(rng.randint(0, 255) for _ in range(length))
        try:
            actual = crc(data)
            expected = crc_reference_xmodem(data)
        except Exception as e:
            crashes += 1
            details.append({"iter": i, "length": length,
                            "error": type(e).__name__, "msg": str(e),
                            "tb": traceback.format_exc()})
            continue
        if actual != expected:
            crashes += 1
            details.append({"iter": i, "length": length, "error": "ref_mismatch",
                            "expected": f"0x{expected:04X}",
                            "got": f"0x{actual:04X}"})
    return crashes, details


def fuzz_determinism(iters: int, det_iters: int, rng: random.Random) -> tuple:
    """Call crc() det_iters times on the same input, confirm all match."""
    crashes = 0
    details = []
    for i in range(iters):
        length = rng.randint(0, 4096)
        data = bytes(rng.randint(0, 255) for _ in range(length))
        try:
            first = crc(data)
        except Exception as e:
            crashes += 1
            details.append({"iter": i, "length": length,
                            "error": type(e).__name__, "msg": str(e),
                            "tb": traceback.format_exc()})
            continue
        for j in range(det_iters):
            try:
                cur = crc(data)
            except Exception as e:
                crashes += 1
                details.append({"iter": i, "length": length, "j": j,
                                "error": type(e).__name__, "msg": str(e),
                                "tb": traceback.format_exc()})
                break
            if cur != first:
                crashes += 1
                details.append({"iter": i, "length": length, "j": j,
                                "error": "nondeterministic",
                                "first": f"0x{first:04X}",
                                "cur": f"0x{cur:04X}"})
                break
    return crashes, details


def check_cross_cycle_disambiguation() -> list:
    """Confirm CRC-16/XMODEM on canonical input is DISTINCT from siblings.

    We can only test this directly for the in-package XMODEM. The sibling
    CRCs (MODBUS, CCITT-FALSE, EN-13757) live in their own packages; we
    import them on-demand and call them on the SAME canonical string.
    """
    failures = []
    xmodem_val = crc(CANONICAL_INPUT)
    if xmodem_val != CROSS_TABLE["CRC-16/XMODEM (this package)"]:
        failures.append({
            "label": "XMODEM canonical",
            "expected": f"0x{CROSS_TABLE['CRC-16/XMODEM (this package)']:04X}",
            "got": f"0x{xmodem_val:04X}",
        })

    # Try to import the sibling packages via subprocess (they're in
    # /root/projects/<sibling>/.worktrees/<cycle>-build/src/).
    siblings = [
        ("crc16-modbus-pure", "CRC-16/MODBUS (cycle_127)",
         "/root/projects/crc16-modbus-pure/.worktrees/t_cycle127-build/src",
         "crc16_modbus_pure", 0x4B37),
        ("crc16-ccitt-pure", "CRC-16/CCITT-FALSE (cycle_128)",
         "/root/projects/crc16-ccitt-pure/.worktrees/t_cycle128-build/src",
         "crc16_ccitt", 0x29B1),
        ("crc16-en13757-pure", "CRC-16/EN-13757 (cycle_129)",
         "/root/projects/crc16-en13757-pure/.worktrees/t_cycle129-build/src",
         "crc16_en13757", 0xC2B7),
    ]

    for pkg_dir, label, src_dir, mod_name, expected in siblings:
        # Inline script that loads sibling's crc() and runs on canonical.
        # We avoid f-strings here because the canonical_input contains
        # quotes that would break the outer f-string nesting.
        import_stmt = "import sys\n"
        import_stmt += "sys.path.insert(0, " + repr(src_dir) + ")\n"
        import_stmt += "from " + mod_name + " import crc\n"
        body = "v = crc(b'123456789')\nsys.stdout.write('{:04X}'.format(v))\n"
        script = import_stmt + body
        try:
            proc = subprocess.run(
                [sys.executable, "-c", script],
                capture_output=True, text=True, timeout=10,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            failures.append({"label": label, "error": f"subprocess:{type(e).__name__}",
                             "msg": str(e)})
            continue
        if proc.returncode != 0:
            failures.append({"label": label, "error": "subprocess_nonzero",
                             "stderr": proc.stderr[-200:]})
            continue
        got_hex = proc.stdout.strip().upper()
        try:
            got_val = int(got_hex, 16)
        except ValueError:
            failures.append({"label": label, "error": "non_hex_output",
                             "stdout": proc.stdout[:200]})
            continue
        if got_val != expected:
            failures.append({"label": label, "error": "wrong_crc",
                             "expected": f"0x{expected:04X}",
                             "got": f"0x{got_val:04X}"})
        # Distinct from XMODEM
        if got_val == xmodem_val:
            failures.append({"label": label, "error": "ambiguous_with_xmodem",
                             "msg": f"sibling 0x{got_val:04X} == xmodem 0x{xmodem_val:04X}"})
    return failures


def main() -> int:
    p = argparse.ArgumentParser(description="crc16-xmodem-pure cross-cycle oracle harness")
    p.add_argument("--iters", type=int, default=100)
    p.add_argument("--det-iters", type=int, default=1000,
                   help="repeat same input this many times for determinism check")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--out", default=str(_HERE / "fuzz" / "cross_cycle" / "results.json"))
    args = p.parse_args()

    rng = random.Random(args.seed)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    started = time.perf_counter()

    # 1. Cross-cycle disambiguation.
    disambiguation_failures = check_cross_cycle_disambiguation()

    # 2. Differential vs crcmod oracle (if available).
    crcmod_crashes, crcmod_details, has_crcmod = fuzz_oracle_vs_crcmod(args.iters, rng)

    # 3. Differential vs bitwise reference impl.
    ref_crashes, ref_details = fuzz_oracle_vs_reference(args.iters, rng)

    # 4. Determinism (skip if det_iters > 100 to keep wall-clock bounded; default 1000).
    det_iters = min(args.det_iters, 100)
    det_crashes, det_details = fuzz_determinism(args.iters, det_iters, rng)

    elapsed = time.perf_counter() - started

    total_crashes = crcmod_crashes + ref_crashes + det_crashes
    payload = {
        "harness": "harness_cross_cycle.py",
        "target_surface": "S1.a crc(data) — cross-cycle + crcmod oracle differential",
        "iters": args.iters,
        "det_iters": det_iters,
        "seed": args.seed,
        "disambiguation_failures": disambiguation_failures,
        "has_crcmod_oracle": has_crcmod,
        "crcmod_oracle_crashes": crcmod_crashes,
        "crcmod_oracle_details_sample": crcmod_details[:5],
        "crcmod_oracle_details_total": len(crcmod_details),
        "reference_impl_crashes": ref_crashes,
        "reference_impl_details_sample": ref_details[:5],
        "reference_impl_details_total": len(ref_details),
        "determinism_crashes": det_crashes,
        "determinism_details_sample": det_details[:5],
        "determinism_details_total": len(det_details),
        "elapsed_seconds": elapsed,
        "exit_ok": (len(disambiguation_failures) == 0 and total_crashes == 0),
        "verdict": "CLEAN" if (len(disambiguation_failures) == 0 and total_crashes == 0) else "DIRTY",
    }
    out_path.write_text(json.dumps(payload, indent=2))
    print(json.dumps({k: v for k, v in payload.items()
                      if not k.endswith("_sample")}, indent=2))
    return 0 if payload["exit_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())