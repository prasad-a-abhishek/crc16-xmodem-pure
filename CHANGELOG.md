# Changelog

## 0.1.0 (2026-09-27)

- Initial release: pure-Python CRC-16/XMODEM reference implementation
- Parameters: width=16 poly=0x1021 init=0x0000 refin=false refout=false xorout=0x0000 check=0x31C3
- 580+ pytest items across 13 categories
- CLI: `crc16-xmodem --self-test --data HEX... --stdin --register`
- Zero runtime dependencies (Python 3.10+ stdlib only)
- Honest install: `pip install git+https://github.com/prasad-a-abhishek/crc16-xmodem-pure.git`
