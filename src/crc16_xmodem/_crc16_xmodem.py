"""CRC-16/XMODEM algorithm — verbatim RevEng pseudocode (MSB-first, 16-bit state)."""
_MASK = 0xFFFF
_POLY = 0x1021
_XOROUT = 0x0000


def crc(data: "bytes | bytearray | memoryview") -> int:
    """Compute CRC-16/XMODEM over `data` per the XMODEM file-transfer protocol.

    Parameters (RevEng catalogue):
        width=16, poly=0x1021, init=0x0000,
        refin=false, refout=false, xorout=0x0000, check=0x31C3.

    Returns the masked 16-bit CRC value in [0, 65536).

    Raises:
        TypeError: if `data` is not a bytes-like object.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"crc16_xmodem.crc() expected bytes-like, got {type(data).__name__}"
        )
    crc_reg = 0x0000
    for byte in data:
        crc_reg ^= (byte << 8) & _MASK
        for _ in range(8):
            if crc_reg & 0x8000:
                crc_reg = ((crc_reg << 1) ^ _POLY) & _MASK
            else:
                crc_reg = (crc_reg << 1) & _MASK
    return crc_reg ^ _XOROUT


def register() -> dict:
    """Return RevEng parameter table for the CRC-16/XMODEM algorithm."""
    return {
        "width": 16,
        "poly": _POLY,
        "init": 0x0000,
        "refin": False,
        "refout": False,
        "xorout": _XOROUT,
        "check": 0x31C3,
    }
