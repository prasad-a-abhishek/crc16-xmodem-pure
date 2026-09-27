# SPEC — crc16-xmodem (cycle_132)

> **Repo slug:** `crc16-xmodem-pure`   |   **Package name:** `crc16_xmodem`   |   **Cycle:** 132
> **Algorithm:** CRC-16/XMODEM   |   **Spec authority:** XMODEM-CRC protocol (Ward Christensen, 1977)
> **Reference:** RevEng CRC Catalogue, "CRC-16/XMODEM" entry
> **Author:** Hermes Repo Factory   |   **Date:** 2026-09-27

This SPEC is the contract for `crc16-xmodem`. The discoverer, builder, and QA
worker all read this file before producing artifacts. If a change is needed,
edit this SPEC first and reference it in the commit message.

---

## §0 — Discovery Audit

**`check_existing.py` output:**

`python3 /root/.hermes/repo_factory/scripts/check_existing.py --name crc16_xmodem --concept "CRC-16/XMODEM XMODEM protocol polynomial 0x1021 init 0x0000 refin false xorout 0x0000"` — full output:

```
============================================================
NOVELTY & NON-EXISTENCE AUDIT: crc16_xmodem (CRC-16/XMODEM XMODEM protocol polynomial 0x1021 init 0x0000 refin false xorout 0x0000)
============================================================
1. Python Stdlib Check:   [PASS] No Python standard library collision.
2. Local Repo Check:       [PASS] No local project collision.
3. PyPI Collision Check:   [PASS] No obvious PyPI package collisions among common naming variations.
4. GitHub Collision Check: [PASS] No dominant high-star existing pure-Python repos found.
------------------------------------------------------------
FINAL VERDICT: APPROVED
============================================================
```

(Structured-JSON variant of the same call returned the same APPROVED verdict
with `details.pypi.passed: true` and `details.github.passed: true`.)

**Primary sources (≥3 HTTP-200, fetched 2026-09-27):**

1. RevEng CRC Catalogue — `https://reveng.sourceforge.io/crc-catalogue/all.htm`
   — "CRC-16/XMODEM" row: width=16, poly=0x1021, init=0x0000, refin=false,
   refout=false, xorout=0x0000, check=0x31C3. This is the canonical parameter
   table that every test vector in `seed_evidence.json` is derived from, and
   the cross-validation oracle every implementation is measured against.

2. XMODEM protocol specification — Ward Christensen, 1977 (the original
   MODEM protocol used for CP/M file transfer; "XMODEM-CRC" replaced the
   1-byte checksum of the original XMODEM with a 16-bit CRC and adopted
   polynomial 0x1021 with init=0x0000, no reflection, no final XOR).
   Documented in `https://en.wikipedia.org/wiki/XMODEM` and the
   MODEM.ASM / XMCRC*.ASM source listings archived at the
   Computer History Museum. The MODEM7 / YMODEM / ZMODEM families all
   re-use the same CRC-16/XMODEM polynomial; the "XMODEM" name is the
   canonical attribution.

3. Wikipedia — Cyclic redundancy check, "Common CRC parameter tables" —
   `https://en.wikipedia.org/wiki/Cyclic_redundancy_check#Common_crc_parameter_tables`
   — confirms CRC-16/XMODEM is the default 16-bit CRC for the XMODEM-CRC,
   MODEM7, YMODEM, and ZMODEM file-transfer protocols, and that polynomial
   0x1021 (un-reflected) with init=0x0000 and xorout=0x0000 is distinct
   from the better-known CCITT 0x1021 family (which uses init=0xFFFF or
   0x0001 depending on variant and xorout=0x0000 or 0xFFFF).

**Target user (one sentence):** an embedded-systems engineer, hobbyist
serial-port tool author, or file-transfer-protocol implementer writing a
pure-Python XMODEM-CRC / YMODEM / ZMODEM frame verifier or test harness
(slim container, no `gcc`, no `crcmod` wheel for the target platform) who
needs a byte-exact CRC-16/XMODEM reference whose test vectors match
Ward Christensen's MODEM7 reference implementation and the RevEng catalogue
down to the bit.

**Named competitors (≥1):**

- `crcmod` — Python C-extension, the de-facto reference for CRCs in Python.
  It works but ships a C build step (not always available in slim container
  images, alpine, PyPy, or read-only filesystems) and exposes the parameter
  table as opaque runtime strings (`mkCrcFun('xmodem')`) that are not
  greppable, not lintable, and not auditable for SLSA provenance. Our
  package: pure Python, no compile, parameter-locked at import time,
  ~25 LOC total.
- `crcany` — pure-Python multi-CRC tool. It covers hundreds of CRC variants
  in one package, which is great if you need breadth. We are not that. We
  are the *single-CRC reference* — easier to read, easier to fuzz, easier
  to certify for a regulated metering stack, and every test vector traces
  to a single RevEng parameter row.
- The "CRC-16/XMODEM" entry on Wikipedia and assorted GitHub gists —
  useful as a reference, but not a packaged library with ≥100 unit tests,
  not on PyPI, and not auditable for correctness the way a self-contained
  package is.

---

## §1 — Target User & Pain

**Concrete workflow today:**

1. Engineer writes an XMODEM-CRC file-transfer receiver in pure Python
   (slim container, no `gcc` available, no `crcmod` wheel for the platform).
2. They need CRC-16/XMODEM for the per-block 128-byte frame checksum. They
   copy a 6-line StackOverflow snippet.
3. The snippet uses polynomial `0x1021` and *looks* correct, but it sets
   `init = 0xFFFF` (the CCITT-FALSE convention) and adds a final XOR
   `^ 0xFFFF`. For ASCII `"123456789"` the two variants disagree by 8 bits:
   CCITT-FALSE yields `0x29B1`, XMODEM yields `0x31C3`. The unit test passes
   against a hard-coded `0x29B1` (the wrong one), and the receiver silently
   rejects every real XMODEM-CRC sender in production as "CRC mismatch".
4. They ship. Field reports: "no YMODEM batches decoded; every firmware
   update push over the serial link fails acceptance."

**What breaks:** an init/xorout mismatch produces wrong-but-plausible CRCs
that pass unit tests against a *partial* oracle but fail against any
XMODEM-CRC-compliant sender. For a firmware-distribution pipeline the
failure is catastrophic — the bootloader says "block N received, CRC OK",
the host silently drops the block as "bad CRC", and the device bricks.

**What our package replaces:** a copy-pasted-from-StackOverflow loop with a
25-LOC loop whose every parameter (poly, init, refin, refout, xorout) is
exactly what RevEng says it is, with 100+ RevEng-checked pytest vectors
attached to the commit and a single byte-exact reference oracle against
which any future "improvement" can be diffed.

---

## §2 — Algorithm Specification

CRC-16/XMODEM is a 16-bit cyclic-redundancy check defined by the XMODEM-CRC
file-transfer protocol (Ward Christensen, 1977) and re-used unchanged by
the MODEM7, YMODEM, and ZMODEM families. The polynomial 0x1021 (=
x^16 + x^12 + x^5 + 1) is the same polynomial as CRC-CCITT, but the
*parameter* configuration (init=0x0000, no reflection, no final XOR) is
distinct and NOT compatible with the CCITT family despite the identical
generator polynomial.

**Parameter table (verbatim from RevEng catalogue):**

| Parameter | Value     | Notes                                                 |
|-----------|-----------|-------------------------------------------------------|
| Width     | 16        | CRC register is 16 bits.                             |
| Polynomial| 0x1021    | Normal (un-reflected) form. Same polynomial as CCITT 0x1021, but the surrounding params differ. |
| Init      | 0x0000    | Register starts at zero, NOT 0xFFFF (CCITT-FALSE) or 0x0001 (X-25). |
| RefIn     | false     | Input bytes are NOT bit-reflected before processing. |
| RefOut    | false     | Final 16-bit register is NOT bit-reflected before XOR. |
| XorOut    | 0x0000    | Final XOR is identity (the CRC is returned as-is). Distinct from CCITT 0xFFFF or X-25 0xFFFF. |
| Check     | 0x31C3    | CRC of ASCII "123456789" — RevEng check value.       |

The RevEng "Check" value is a self-test: the canonical 9-byte input
`"123456789"` (hex `31 32 33 34 35 36 37 38 39`) must produce CRC `0x31C3`
when run through the parameter table above. Any implementation that returns
a different value is wrong.

---

## §3 — Acceptance Criteria

**12 LOCKED, testable acceptance criteria.** Every criterion must have ≥1
pytest item attached. The AC numbers below are the spec IDs the builder and
QA worker reference in their test names and their commit messages.

- **AC1 — RevEng check value (positive):** `crc(b"123456789") == 0x31C3`.
  This is THE single most important test — it cross-validates every
  parameter in §2 in one shot.

- **AC2 — Zero-length input:** `crc(b"") == 0x0000`. With no bytes consumed,
  the CRC register equals init (0x0000), and xorout=0x0000 means the
  empty-input CRC equals init exactly. This documents the empty-input
  convention explicitly.

- **AC3 — Single-byte check (0x00):** `crc(bytes([0x00])) == 0x0000`.
  One byte of zero fed through init=0x0000 with xorout=0x0000 also
  collapses to 0x0000.

- **AC4 — Single-byte check (0xFF):** `crc(bytes([0xFF])) == 0x1EF0`.

- **AC5 — Width conformance:** `crc` always returns an `int` in `[0, 0xFFFF]`
  (16-bit unsigned). Verified across 1000 random inputs ≥1 byte.

- **AC6 — Polynomial conformance:** the polynomial is 0x1021 (NOT 0x8005
  from the IBM/ARC family, NOT the reflected 0x8408 used by KERMIT). A test
  asserts `crc(b"123456789")` is *not* the CCITT-FALSE value 0x29B1 (the
  most common wrong-init/wrong-xorout copy-paste bug in XMODEM parsers) and
  *not* the KERMIT value 0x2189 (which shares the 0x1021 polynomial but
  uses refin=true refout=true and xorout=0x0000).

- **AC7 — Determinism:** calling `crc` twice on the same input produces the
  same output. Verified across 100 random inputs (no internal state leak).

- **AC8 — RefIn = false (input bytes NOT bit-reflected):** the high bit of
  the first input byte affects the high bit of the internal state after the
  first update step, NOT the low bit (which would be the case under
  refin=true). Verified by a closed-form calculation against a known
  RevEng vector.

- **AC9 — RefOut = false (final register NOT bit-reflected):** a one-byte
  input `b"\xA5"` produces a CRC whose high bit is the high bit of the
  internal state at the end (NOT the low bit, which would be the case
  under refout=true). Verified by a closed-form calculation.

- **AC10 — XorOut = 0x0000 (final XOR is identity):** for init=0x0000
  and xorout=0x0000, the empty-input CRC equals `init ^ xorout == 0x0000`,
  and the single-byte 0x00 CRC also equals 0x0000. Verified by AC2 + AC3 +
  a dedicated init/xorout cross-check (compare to CCITT-FALSE's 0xFFFF
  result for the same inputs).

- **AC11 — Oracle differential (vs `crcmod`):** when `crcmod` is installed,
  `crc(b) == crcmod.mkCrcFun('xmodem')(b)` for ≥100 random byte strings
  of length ∈ [1, 1000]. The differential test runs `crcmod` only if it is
  importable; if absent, this AC is skipped (not failed).

- **AC12 — Type-error safety:** calling `crc(None)`, `crc("hello")`,
  `crc(123)`, or `crc([1, 2, 3])` raises `TypeError` with a message naming
  the offending argument type. Passing a non-`bytes`-like object must NEVER
  raise `ValueError`, `AttributeError`, or return a silent garbage CRC.

---

## §4 — Canonical Reference Implementation

The reference is the verbatim RevEng pseudocode transcribed to Python.
~25 LOC, no external state, no hidden parameters. Every parameter in §2 is
named explicitly so future readers can diff against the RevEng row.

```python
# src/crc16_xmodem/core.py  (planned; not yet written — build phase only)
POLY  = 0x1021
INIT  = 0x0000
XOROT = 0x0000

def crc(data: bytes, init: int = INIT) -> int:
    """Return the CRC-16/XMODEM of `data` (16-bit unsigned int).

    Conforms to the XMODEM-CRC protocol (Ward Christensen, 1977) and the
    RevEng catalogue "CRC-16/XMODEM" entry: width=16 poly=0x1021 init=0x0000
    refin=false refout=false xorout=0x0000 check=0x31C3.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"crc() expected bytes-like, got {type(data).__name__}"
        )
    crc = init & 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ POLY) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc ^ XOROT
```

The `init` parameter is exposed for callers feeding multi-block streams
who need to chain CRCs across blocks (YMODEM batch mode); the default is
the XMODEM-CRC init `0x0000`. A higher-level `crc_bytes(data)` wraps
`crc(data) ^ XOROT` for the common single-shot case.

---

## §5 — Test Categories

**Target: ≥100 pytest items, organized into 7+ categories.** The builder
MUST cover every category below; the QA worker re-runs the full suite and
adds adversarial cases.

1. **Canonical RevEng vectors (≥10 items):** every vector in
   `seed_evidence.json` (empty, 00, 01, ff, 0..9, 123456789) is one test,
   plus 4 additional canonical inputs (e.g., `"a"`, `"abc"`,
   `"The quick brown fox"`, a known XMODEM-CRC 128-byte block with the
   trailing CRC bytes).

2. **Byte-range sweep (≥40 items):** for each byte value `b` in `[0x00,
   0xFF]`, assert `crc(bytes([b]))` equals the precomputed reference value
   (tabulated in the test module from the same reference implementation;
   cross-validated against `crcmod` if available).

3. **Length sweep (≥20 items):** for each length `n` in `[1, 2, 4, 8, 16,
   32, 64, 128, 256, 512, 1024, 2048]` and for 3 deterministic byte-fill
   patterns (`0x00`, `0xFF`, `0xA5`), assert `crc(b * n)` matches the
   reference value computed at write-time.

4. **Determinism (≥5 items):** call `crc(b)` 100× in a tight loop with the
   same input, assert all 100 outputs equal.

5. **Type-error safety (≥10 items):** one test per non-bytes argument type
   (`None`, `str`, `int`, `float`, `list`, `tuple`, `dict`, `set`,
   `bytearray` of length 0, `memoryview` of length 0). Each must raise
   `TypeError` (or succeed for `bytearray`/`memoryview` — those ARE
   bytes-like).

6. **Oracle differential vs `crcmod` (≥5 items):** when `crcmod` is
   importable, generate ≥100 random byte strings of length ∈ [1, 1000],
   assert `crc(s) == crcmod.mkCrcFun('xmodem')(s)` for every sample.
   Skip (not fail) the whole category if `crcmod` is missing.

7. **Edge cases (≥10 items):** empty input, single zero byte, single
   0xFF byte, all-zero input of length 1MB, all-0xFF input of length 1MB,
   alternating-bit pattern `0xAA 0x55 ...`, two-byte input, the largest
   possible single-shot input the test runner can fit in memory, an
   XMODEM-CRC 128-byte block + 2-byte CRC self-roundtrip (compute CRC,
   append, verify).

8. **RefIn/RefOut/XorOut cross-check (≥4 items):** three small tests that
   prove each of the three flags in the parameter table actually does
   what RevEng says (input bytes are not reflected, output register is
   not reflected, final XOR is identity). These are the "did you flip the
   right switch?" tests.

Total budget: ≥104 pytest items.

---

## §6 — Out-of-Scope / Non-Goals

- **NOT cryptographic.** CRC-16 is for error detection, not authentication.
  Do not use this package to "sign" data or defend against an active
  attacker. (See §7 — `hashlib` covers that use case.)

- **NOT a generic CRC library.** We do not expose `crc16/ccitt-false`,
  `crc16/kermit`, `crc16/en-13757`, etc. Each of those would be a separate
  repo (and several are already shipped as `*-pure` siblings).

- **NOT optimized for speed.** The reference loop is bit-by-bit (~8x
  per byte). For throughput-sensitive pipelines, use `crcmod`
  (C-extension) or a table-driven implementation. Our value is correctness
  and clarity, not throughput.

- **NOT cross-platform.** Pure Python 3.10+ stdlib only. No native
  extensions, no Cython, no mypyc, no PyPy-specific tricks. This is a
  deliberate trade-off — see §1.

- **NOT a streaming API.** `crc` consumes a complete `bytes`-like object
  in one call. For multi-megabyte streams (YMODEM batch mode), chunk the
  input and chain the `init` parameter yourself (the builder MUST expose
  `init` for this).

---

## §7 — Dependencies & Constraints

- **`dependencies = []`** (zero runtime dependencies; verified by
  `pip install --dry-run` in the QA smoke test).
- **Python ≥3.10.** Required for the `(bytes, bytearray, memoryview)`
  union-type isinstance check syntax.
- **No C extensions, no native code, no build step.** `pip install .`
  from a clean checkout must succeed without `gcc`, `cc`, `make`, or any
  platform-specific compiler.
- **No global mutable state.** `crc()` is a pure function of its inputs.
- **No I/O.** `crc()` does not read files, do not touch the network,
  does not import platform-specific modules.

---

## §8 — Honest Install + Verification

**Install command (per Invariant 9 — not on PyPI):**

```bash
pip install git+https://github.com/prasad-a-abhishek/crc16-xmodem.git
```

**Quick verify (3 lines):**

```python
>>> from crc16_xmodem import crc
>>> crc(b"123456789")                    # doctest: RevEng check value
12739
>>> hex(crc(b"123456789"))
'0x31c3'
```

(The hex form `0x31C3` is the RevEng check value and the canonical
contract; the decimal form `12739` is shown for reader convenience.
Both must match the RevEng catalogue.)

**Test command:**

```bash
pytest -q          # expect: ≥100 passed in <2s
```

The README MUST claim a specific test count that matches
`pytest --collect-only -q` output. Claiming "100+ tests" when the suite has
97 items is a contract violation.

**Smoke test (clean-venv reproduction):**

```bash
python3 -m venv /tmp/crc16-xmodem-verify
/tmp/crc16-xmodem-verify/bin/pip install git+https://github.com/prasad-a-abhishek/crc16-xmodem.git
/tmp/crc16-xmodem-verify/bin/python -c "from crc16_xmodem import crc; assert crc(b'123456789') == 0x31C3, 'RevEng check failed'"
/tmp/crc16-xmodem-verify/bin/python -m pytest --pyargs crc16_xmodem -q
```

If any of the four steps fails, the package is not shippable.

---

## §9 — Change Log

- **2026-09-27 — cycle_132/discover:** initial SPEC authored. 12 LOCKED ACs,
  9 sections, check_existing APPROVED. Awaiting builder hand-off.