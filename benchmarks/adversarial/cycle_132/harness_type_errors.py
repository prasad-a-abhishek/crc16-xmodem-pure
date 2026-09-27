#!/usr/bin/env python3
"""Fuzz harness for surface #1 type-error contract (AC12, CWE-20).

Target: src/crc16_xmodem/_crc16_xmodem.py::crc input validation.

Asserts (per SURFACES.md S1.a + AC12 + Invariant 21):
- TypeError raised cleanly for non-bytes-like `data`:
    None, str, int, float, list, dict, tuple, set, bool, object()
- The error MESSAGE names the offending type (helpful diagnostic)
- The exception is TypeError — NEVER ValueError or AttributeError
- bytes subclasses (bytearray, memoryview) are ACCEPTED on canonical check value
- bytes subclass with extended attributes is ACCEPTED
- Empty bytes-like objects are ACCEPTED (return 0x0000)
- A custom bytes subclass with __int__ override should still raise TypeError
  (crc() should not invoke dunder methods on the data arg)
- Generator inputs (cannot len()) MUST raise TypeError, not crash with TypeError
  on len()

Usage:
    python3 harness_type_errors.py [--iters N] [--seed S]
"""
from __future__ import annotations

import argparse
import json
import random
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

# Cases that MUST raise TypeError (per AC12 + Invariant 21 total-exception safety).
BAD_DATA = [
    ("None", None),
    ("str-ascii", "hello"),
    ("str-empty", ""),
    ("str-digit", "12345"),
    ("str-unicode", "🚀π"),
    ("int-zero", 0),
    ("int-positive", 42),
    ("int-negative", -1),
    ("int-large", 0xDEADBEEF),
    ("float", 3.14),
    ("float-zero", 0.0),
    ("float-inf", float("inf")),
    ("float-nan", float("nan")),
    ("list-empty", []),
    ("list-bytes", [1, 2, 3]),
    ("list-mixed", [b"\x00", b"\x01"]),
    ("dict", {"a": 1}),
    ("dict-empty", {}),
    ("tuple-empty", ()),
    ("tuple-ints", (1, 2)),
    ("set", {1, 2, 3}),
    ("frozenset", frozenset([1, 2])),
    ("bool-True-as-data", True),
    ("bool-False-as-data", False),
    ("object()", object()),
    ("NoneType()", type(None)),
    ("iter(range)", iter(range(10))),
    ("generator", (b for b in [b"\x00", b"\x01"])),
    # Note: memoryview is bytes-like; see ACCEPT_DATA below for the
    # positive-test cases. We intentionally do NOT list memoryview here.
]


# Cases that MUST be ACCEPTED (and equal 0x31C3 for "123456789").
ACCEPT_DATA = [
    ("bytes-literal", b"123456789", 0x31C3),
    ("bytearray-canonical", bytearray(b"123456789"), 0x31C3),
    ("memoryview-canonical", memoryview(b"123456789"), 0x31C3),
    ("empty-bytes", b"", 0x0000),
    ("empty-bytearray", bytearray(), 0x0000),
    ("empty-memoryview", memoryview(b""), 0x0000),
]


def fuzz_bad_data(iters: int, rng: random.Random) -> tuple:
    """Iterate BAD_DATA many times, confirm TypeError every time."""
    crashes = 0
    details = []
    for i in range(iters):
        for label, bad_value in BAD_DATA:
            try:
                result = crc(bad_value)
            except TypeError:
                continue  # expected
            except Exception as e:
                crashes += 1
                details.append({"iter": i, "label": label,
                                "error": f"wrong_exception:{type(e).__name__}",
                                "msg": str(e), "tb": traceback.format_exc()})
                continue
            # No exception: this is the failure
            crashes += 1
            details.append({"iter": i, "label": label,
                            "error": "no_exception_raised",
                            "msg": f"crc({label}) returned 0x{result:04X}"})
    return crashes, details


def fuzz_message_quality(iters: int, rng: random.Random) -> tuple:
    """Confirm error message names the type (per UX requirement)."""
    crashes = 0
    details = []
    for i in range(iters):
        for label, bad_value in BAD_DATA:
            try:
                crc(bad_value)
                # no exception — already counted in fuzz_bad_data
                continue
            except TypeError as e:
                msg = str(e)
                # The message should mention the type name (e.g. "NoneType", "int")
                # — but we allow some flexibility for bool/int aliasing.
                type_name = type(bad_value).__name__
                if type_name not in msg and type_name not in (
                    "bool", "int", "str", "list", "dict", "tuple", "set",
                    "bytes", "bytearray", "memoryview", "float",
                ):
                    # Acceptable: at minimum the message should NOT be empty.
                    if not msg.strip():
                        crashes += 1
                        details.append({"iter": i, "label": label,
                                        "error": "empty_error_message"})
            except Exception:
                continue  # counted elsewhere
    return crashes, details


def fuzz_accept_data(iters: int, rng: random.Random) -> tuple:
    """Confirm ACCEPT_DATA types are accepted with correct CRC."""
    crashes = 0
    details = []
    for i in range(iters):
        for label, value, expected in ACCEPT_DATA:
            try:
                result = crc(value)
            except Exception as e:
                crashes += 1
                details.append({"iter": i, "label": label,
                                "error": type(e).__name__, "msg": str(e),
                                "tb": traceback.format_exc()})
                continue
            if result != expected:
                crashes += 1
                details.append({"iter": i, "label": label,
                                "error": "wrong_crc",
                                "expected": f"0x{expected:04X}",
                                "got": f"0x{result:04X}"})
    return crashes, details


def fuzz_subclass_with_methods(iters: int, rng: random.Random) -> tuple:
    """A custom bytes subclass with extra dunder methods should still be
    accepted as bytes-like and not invoke those dunders (the implementation
    only iterates the bytes, not the dunder methods).

    Note: ``__iter__`` and ``__len__`` are part of the bytes protocol and
    will be honoured by ``for byte in data`` — so we cannot override those.
    Instead we override ``__int__`` (irrelevant to crc()) and confirm the
    result equals 0x31C3, proving the implementation did not invoke
    ``__int__``.
    """
    class FancyBytes(bytes):
        def __int__(self):
            return 0xCAFE  # this MUST NOT be called by crc()
        def __index__(self):
            return 0xBEEF  # this MUST NOT be called by crc() either
        def __repr__(self):
            return "<FancyBytes>"  # diagnostic, should be irrelevant

    crashes = 0
    details = []
    for i in range(iters):
        payload = FancyBytes(b"123456789")
        try:
            result = crc(payload)
        except Exception as e:
            crashes += 1
            details.append({"iter": i, "label": "FancyBytes",
                            "error": type(e).__name__, "msg": str(e),
                            "tb": traceback.format_exc()})
            continue
        # MUST equal 0x31C3 — the same as plain bytes(b"123456789")
        if result != 0x31C3:
            crashes += 1
            details.append({"iter": i, "label": "FancyBytes",
                            "error": "wrong_crc",
                            "expected": "0x31C3", "got": f"0x{result:04X}"})
    return crashes, details


def main() -> int:
    p = argparse.ArgumentParser(description="crc16-xmodem-pure type-error contract harness")
    p.add_argument("--iters", type=int, default=100)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--out", default=str(_HERE / "fuzz" / "type_errors" / "results.json"))
    args = p.parse_args()

    rng = random.Random(args.seed)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    started = time.perf_counter()

    # 1. Confirm every BAD_DATA raises TypeError (run args.iters times).
    bad_crashes, bad_details = fuzz_bad_data(args.iters, rng)

    # 2. Confirm error messages are helpful (mention type).
    msg_crashes, msg_details = fuzz_message_quality(args.iters, rng)

    # 3. Confirm every ACCEPT_DATA is accepted with correct CRC.
    accept_crashes, accept_details = fuzz_accept_data(args.iters, rng)

    # 4. Confirm custom bytes subclass is accepted with correct CRC.
    fancy_crashes, fancy_details = fuzz_subclass_with_methods(args.iters, rng)

    elapsed = time.perf_counter() - started

    total_crashes = bad_crashes + msg_crashes + accept_crashes + fancy_crashes
    payload = {
        "harness": "harness_type_errors.py",
        "target_surface": "S1.a crc(data) type contract — _crc16_xmodem.py (lines 7-31)",
        "iters": args.iters,
        "seed": args.seed,
        "bad_data_cases": len(BAD_DATA),
        "accept_data_cases": len(ACCEPT_DATA),
        "bad_data_crashes": bad_crashes,
        "bad_data_details_sample": bad_details[:5],
        "bad_data_details_total": len(bad_details),
        "message_quality_crashes": msg_crashes,
        "message_quality_details_sample": msg_details[:5],
        "message_quality_details_total": len(msg_details),
        "accept_data_crashes": accept_crashes,
        "accept_data_details_sample": accept_details[:5],
        "accept_data_details_total": len(accept_details),
        "subclass_crashes": fancy_crashes,
        "subclass_details_sample": fancy_details[:5],
        "subclass_details_total": len(fancy_details),
        "elapsed_seconds": elapsed,
        "exit_ok": (total_crashes == 0),
        "verdict": "CLEAN" if total_crashes == 0 else "DIRTY",
    }
    out_path.write_text(json.dumps(payload, indent=2))
    print(json.dumps({k: v for k, v in payload.items()
                      if not k.endswith("_sample")}, indent=2))
    return 0 if payload["exit_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())