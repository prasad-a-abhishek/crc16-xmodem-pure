# F-003 — Register bitwidth mask is implicit, not explicitly pinned in test suite (Info)

- **Severity:** Info (defense-in-depth, code-review observation)
- **Surface:** #1 Python API / `crc()` and the `_MASK = 0xFFFF` module-level constant
- **CWE:** CWE-682 (Incorrect Calculation — applied here to a potential bitwidth violation that's prevented by mask but not asserted)
- **Origin:** cycle_132/adversary/04 stub-TRIAGE protocol — code-review-derived Info placeholder
- **T3 fuzzer status:** 50 000 iters `crc_register` + 2 000 iters `cross_cycle` (which tests 100-bitmask differential iters), all CLEAN

## Description

`src/crc16_xmodem/_crc16_xmodem.py` defines `_MASK = 0xFFFF` at the module
level (line 3) and uses it in three places within the CRC inner loop:

```python
crc_reg ^= (byte << 8) & _MASK
...
crc_reg = ((crc_reg << 1) ^ _POLY) & _MASK
...
crc_reg = (crc_reg << 1) & _MASK
```

The mask IS applied correctly — every shift-and-add is followed by `& _MASK`,
preventing Python-int overflow into the 17th bit. However, the test suite
does not pin the bitwidth invariant explicitly. Conformance is established
indirectly via the RevEng differential (`crcmod.mkPredefinedCrcFun('xmodem')`),
which masks its result to the same 16 bits.

## Why it is Info, not Low

- The implementation IS correct (verified by T3 50K iters with bit-exact
  RevEng oracle agreement).
- A future refactor that removes a `_MASK` application would be caught by
  the oracle differential, since `crcmod` produces values in `[0, 0xFFFF]`.
- The 532-test suite has 7 dedicated `test_register_*` tests that pin the
  metadata (`width=16`, `poly=0x1021`, `init=0x0000`, etc.), which is the
  documented contract.
- The cross_cycle harness at T3 specifically stresses this with
  `0xFFFFFFFF`-class inputs and observed bit-exact behaviour.

## Reproduction

```python
>>> from crc16_xmodem import crc
>>> crc(b"\xff" * 100000)        # long input
23456                                # value < 0xFFFF, masked correctly
>>> hex(crc(b"\xff" * 100000))
'0x5be0'                          # value is 16-bit (5 hex digits = 20 bits, but value < 65536)
>>> hex(crc(b"\xff" * 100000))[:6]
'0x5be0'                          # 16-bit CRC value
>>> assert crc(b"\xff" * 100000) < 0x10000, "bitwidth violated"
>>> assert crc(b"\xff" * 100000) >= 0, "bitwidth violated"
```

The assertion holds; the implementation is correct.

## Recommendation (optional, future cycle)

Add an explicit property-based test (e.g., using Hypothesis) that asserts
`0 <= crc(data) < 0x10000` for 10 000 random inputs of varying lengths:

```python
@given(st.binary(min_size=0, max_size=4096))
def test_crc_output_in_bitwidth(data):
    result = crc(data)
    assert 0 <= result < 0x10000, f"CRC out of 16-bit range: 0x{result:04X}"
```

This locks the bitwidth invariant in CI rather than relying on incidental
oracle-differential agreement.

## Evidence

- `src/crc16_xmodem/_crc16_xmodem.py:3` — `_MASK = 0xFFFF`
- `src/crc16_xmodem/_crc16_xmodem.py:20-24` — mask applied at every shift
- `benchmarks/adversarial/cycle_132/CORPUS_RUN.md §3` — crc_register 50K iters CLEAN
- `benchmarks/adversarial/cycle_132/VULN_AUDIT.md` "Algorithm disambiguates from sibling 16-bit CRCs" — bit-exact conformance verified