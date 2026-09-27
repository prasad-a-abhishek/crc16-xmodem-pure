"""crc16-xmodem: pure-Python reference implementation of CRC-16/XMODEM.

A 16-bit cyclic redundancy check used in the XMODEM file-transfer protocol
(Chuck Forsberg's original 1977 XMODEM, also widely cited as CRC-16/XMODEM in
the RevEng catalogue).
Zero runtime dependencies; uses only `bytes`/`bytearray`/`memoryview` from stdlib.

Parameters per RevEng catalogue:
    width=16, poly=0x1021, init=0x0000, refin=false, refout=false, xorout=0x0000, check=0x31C3
"""
from ._crc16_xmodem import crc, register

__version__ = "0.1.0"
__all__ = ["crc", "register"]
