"""CLI for crc16-xmodem: compute CRC-16/XMODEM over bytes from stdin or --data argument.

Usage:
    python3 -m crc16_xmodem --data 31 32 33 34 35 36 37 38 39
    python3 -m crc16_xmodem --self-test
    echo -n "123456789" | python3 -m crc16_xmodem --stdin
"""
from __future__ import annotations

import argparse
import sys

from ._crc16_xmodem import crc, register


def _parse_data(values: list[str]) -> bytes:
    """Parse list of hex strings (or integers) into bytes."""
    if not values:
        return b""
    if len(values) == 1 and len(values[0]) % 2 == 0:
        try:
            return bytes.fromhex(values[0])
        except ValueError:
            pass
    out = bytearray()
    for v in values:
        if v.startswith("0x"):
            out.append(int(v, 16) & 0xFF)
        else:
            try:
                out.append(int(v, 16) & 0xFF)
            except ValueError:
                try:
                    out.append(int(v) & 0xFF)
                except ValueError:
                    out.extend(v.encode("latin-1"))
    return bytes(out)


def _self_test() -> int:
    """Run the RevEng canonical check; exit 0 on pass, 1 on fail."""
    expected = 0x31C3
    actual = crc(b"123456789")
    if actual != expected:
        print(f"FAIL: crc(b'123456789') = 0x{actual:04X}, expected 0x{expected:04X}", file=sys.stderr)
        return 1
    print(f"PASS: crc(b'123456789') = 0x{actual:04X}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint. Returns 0 on success, 1 on error."""
    p = argparse.ArgumentParser(
        prog="crc16-xmodem",
        description="Pure-Python CRC-16/XMODEM (XMODEM file-transfer protocol).",
    )
    p.add_argument("--data", nargs="+", default=[], help="bytes to CRC (hex or decimal)")
    p.add_argument("--stdin", action="store_true", help="read bytes from stdin")
    p.add_argument("--self-test", action="store_true", help="run RevEng canonical check")
    p.add_argument("--register", action="store_true", help="print RevEng parameter table")
    args = p.parse_args(argv)

    if args.self_test:
        return _self_test()
    if args.register:
        for k, v in register().items():
            print(f"{k}={v}")
        return 0
    if args.stdin:
        data = sys.stdin.buffer.read()
    else:
        data = _parse_data(args.data)

    print(f"0x{crc(data):04X}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
