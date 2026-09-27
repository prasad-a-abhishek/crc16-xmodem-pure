#!/usr/bin/env python3
"""Build deterministic seed corpus for all 6 fuzz surfaces.

Per cycle_132/adversary/T3 spec, populate
benchmarks/adversarial/cycle_132/fuzz/<surface>/corpus/ with diverse inputs:

- crc_main/: empty bytes, 1-byte, 1KiB, 1MiB, all-0xFF, all-0x00, random bytes,
  ASCII strings, CRLF data, unicode UTF-8 (binary-safe)
- crc_register/: 0, 1, 0xFF, 0xFFFF (max 16-bit), 0xFFFFFFFF (out-of-range,
  expect mask)
- cli_data/: "123456789" canonical, empty, malformed hex, CRLF in hex, unicode
- cli_stdin/: 0B, 1B, 1KiB, 1MiB, CRLF-terminated, null bytes
- type_errors/: None, 0, "", [], {}
- cross_cycle/: 100 random byte sequences for oracle differential vs crcmod

Outputs are committed to disk so the corpus is reproducible across runs.
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FUZZ_ROOT = HERE / "fuzz"
SEED = 0xC132  # cycle_132 — reproducible corpus

CORPORA = {}  # surface -> list[(label, bytes_or_special)]


def build_crc_main():
    rng = random.Random(SEED)
    items = []
    items.append(("empty", b""))
    items.append(("one_byte_0x00", bytes([0x00])))
    items.append(("one_byte_0x01", bytes([0x01])))
    items.append(("one_byte_0xFF", bytes([0xFF])))
    items.append(("ascii_123456789", b"123456789"))
    items.append(("ascii_hello_world", b"hello world"))
    items.append(("1KiB_zeros", b"\x00" * 1024))
    items.append(("1KiB_ones", b"\xFF" * 1024))
    items.append(("1KiB_random", bytes(rng.randint(0, 255) for _ in range(1024))))
    items.append(("1MiB_zeros", b"\x00" * (1024 * 1024)))
    items.append(("1MiB_random", bytes(rng.randint(0, 255) for _ in range(1024 * 1024))))
    items.append(("crlf_data", b"\r\n" * 100))
    items.append(("unicode_utf8", "héllo wörld 你好 🚀".encode("utf-8")))
    items.append(("all_byte_values", bytes(range(256))))
    items.append(("alternating_0xA5_0x5A", bytes([0xA5, 0x5A] * 512)))
    return items


def build_crc_register():
    # These are the input DATA bytes used to drive crc() through register path.
    # The spec says 0, 1, 0xFF, 0xFFFF, 0xFFFFFFFF; those are byte patterns that
    # feed register-style tests.
    items = []
    items.append(("zero_data", b""))
    items.append(("one_byte", b"\x01"))
    items.append(("0xFF_byte", b"\xFF"))
    items.append(("0xFFFF_two_bytes", b"\xFF\xFF"))
    items.append(("0xFFFFFFFF_four_bytes", b"\xFF\xFF\xFF\xFF"))
    items.append(("all_byte_values", bytes(range(256))))
    items.append(("alternating", bytes([0xA5, 0x5A] * 64)))
    items.append(("1KiB_random", bytes(random.Random(SEED).randint(0, 255) for _ in range(1024))))
    items.append(("1MiB_random", bytes(random.Random(SEED).randint(0, 255) for _ in range(1024))))
    items.append(("ascii_canonical", b"123456789"))
    return items


def build_cli_data():
    # Hex string arguments to crc16-xmodem --data (space-joined).
    items = []
    items.append(("canonical_123456789_hex", "313233343536373839"))
    items.append(("empty_input", ""))
    items.append(("malformed_hex_odd", "0A0B0C0"))  # odd length
    items.append(("malformed_hex_letter", "ZZ"))      # bad chars
    items.append(("hex_with_crlf", "313233343536373839\r\n"))
    items.append(("hex_unicode_emoji", "😀"))
    items.append(("hex_unicode_chinese", "中文"))
    items.append(("hex_unicode_greek", "αβγ"))
    items.append(("hex_negative_signed", "-1"))
    items.append(("hex_out_of_byte_range", "1FFFF"))   # > 0xFF single token
    items.append(("hex_decimal_mixed", "65 66 67"))    # ASCII decimal mix
    items.append(("hex_zero", "00"))
    return items


def build_cli_stdin():
    rng = random.Random(SEED)
    items = []
    items.append(("empty", b""))
    items.append(("one_byte_null", b"\x00"))
    items.append(("one_byte_a", b"a"))
    items.append(("ascii_canonical", b"123456789"))
    items.append(("1KiB_zeros", b"\x00" * 1024))
    items.append(("1KiB_ones", b"\xFF" * 1024))
    items.append(("1MiB_zeros", b"\x00" * (1024 * 1024)))
    items.append(("crlf_terminated", b"123456789\r\n"))
    items.append(("null_bytes_interleaved", b"\x00\x01\x02\x00\xFF\x00"))
    items.append(("all_byte_values", bytes(range(256))))
    items.append(("1KiB_random", bytes(rng.randint(0, 255) for _ in range(1024))))
    return items


def build_type_errors():
    # Special placeholders: written as JSON descriptors, not raw bytes — the
    # type_errors harness already enumerates 28 BAD_DATA + 6 ACCEPT_DATA
    # in-process. The "corpus" here is the list of labels we expect to test.
    items = [
        ("None", None),
        ("zero_int", 0),
        ("empty_string", ""),
        ("empty_list", []),
        ("empty_dict", {}),
        ("nonempty_string", "abc"),
        ("nonempty_int", 42),
        ("nonempty_list", [1, 2, 3]),
        ("nonempty_dict", {"a": 1}),
        ("true_bool", True),
        ("false_bool", False),
    ]
    return items


def build_cross_cycle():
    rng = random.Random(SEED)
    items = []
    items.append(("canonical_123456789", b"123456789"))
    items.append(("empty", b""))
    items.append(("single_byte_0x00", b"\x00"))
    items.append(("single_byte_0x01", b"\x01"))
    items.append(("single_byte_0xFF", b"\xFF"))
    # 100 random byte sequences (spec requirement)
    for i in range(100):
        size = rng.randint(0, 4096)
        data = bytes(rng.randint(0, 255) for _ in range(size))
        items.append((f"random_{i:03d}_len{size}", data))
    return items


SURFACE_BUILDERS = {
    "crc_main":     build_crc_main,
    "crc_register": build_crc_register,
    "cli_data":     build_cli_data,
    "cli_stdin":    build_cli_stdin,
    "type_errors":  build_type_errors,
    "cross_cycle":  build_cross_cycle,
}


def write_corpus(surface: str, items: list):
    out_dir = FUZZ_ROOT / surface / "corpus"
    out_dir.mkdir(parents=True, exist_ok=True)
    index = []
    for i, (label, payload) in enumerate(items):
        # Filename-safe label
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in label)
        if isinstance(payload, bytes):
            fpath = out_dir / f"{i:03d}_{safe}.bin"
            fpath.write_bytes(payload)
            index.append({"i": i, "label": label, "file": fpath.name, "kind": "bytes",
                         "size": len(payload)})
        elif isinstance(payload, str):
            fpath = out_dir / f"{i:03d}_{safe}.txt"
            fpath.write_text(payload)
            index.append({"i": i, "label": label, "file": fpath.name, "kind": "str",
                         "size": len(payload)})
        else:
            # special: write JSON descriptor
            fpath = out_dir / f"{i:03d}_{safe}.json"
            fpath.write_text(json.dumps({"label": label, "type": type(payload).__name__,
                                         "repr": repr(payload)}))
            index.append({"i": i, "label": label, "file": fpath.name, "kind": "descriptor",
                         "size": 0})
    (out_dir / "index.json").write_text(json.dumps(index, indent=2))
    return len(items)


def main():
    summary = {}
    for surface, builder in SURFACE_BUILDERS.items():
        items = builder()
        n = write_corpus(surface, items)
        summary[surface] = {"inputs": n, "types": sorted(set(
            "bytes" if isinstance(p, bytes) else "str" if isinstance(p, str) else "descriptor"
            for _, p in items))}
        print(f"[corpus] {surface}: wrote {n} inputs to {FUZZ_ROOT / surface / 'corpus'}")
    (HERE / "CORPUS_INDEX.json").write_text(json.dumps(summary, indent=2))
    print(f"\nTotal surfaces: {len(summary)}")
    total_inputs = sum(s["inputs"] for s in summary.values())
    print(f"Total inputs across all surfaces: {total_inputs}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())