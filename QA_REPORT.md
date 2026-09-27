# QA Report — crc16-xmodem-pure (cycle_132)

tests_passing: true

## 1. README audit (Invariant 16)

Verified at `/root/projects/crc16-xmodem-pure/.worktrees/t_cycle132-build/README.md`
(2170 bytes, 60 lines after the post-build badge correction).

**Section ordering (canonical Invariant 16 sequence, all 6 present):**

| Line | Header                                    |
|------|-------------------------------------------|
| 1    | `# crc16-xmodem` (Title / badges / quote) |
| 9    | `## ⚡ Quick Start`                       |
| 25   | `## ⚡ Performance & Benchmarks`          |
| 34   | `## Why crc16-xmodem?`                    |
| 50   | `## Key Features & API`                   |
| 57   | `## License`                              |

`grep -c '^# \|^## ' README.md` = **6** (canonical count).

- Install command is `pip install git+https://github.com/prasad-a-abhishek/crc16-xmodem-pure.git`
  (line 12) — git-URL, NOT pipy — per Invariant 24 (repo not on PyPI).
- `## ⚡ Performance & Benchmarks` positioned **immediately after** Quick Start
  (line 25, line after Quick Start at line 9) — confirms canonical positioning.
- Honest fix applied during QA: badge corrected from `tests-580+` to
  `tests-532/532`; CHANGELOG entry corrected from `580+` to `532` to match
  the real `pytest --collect-only -q` count.

## 2. AC regression (all 12 LOCKED ACs)

Live execution with `PYTHONPATH=src`, run from the worktree:

| AC  | Description                          | Result                         |
|-----|--------------------------------------|--------------------------------|
| AC1 | `crc(b'123456789') == 0x31C3`        | 0x31c3 — **PASS** (RevEng)     |
| AC2 | `crc(b'') == 0x0000`                 | 0x0 — **PASS** (init^xorout)   |
| AC3 | `crc(bytes([0x00])) == 0x0000`       | 0x0 — **PASS**                  |
| AC4 | `crc(bytes([0xFF])) == 0x1EF0`       | 0x1ef0 — **PASS**               |
| AC5 | CRC in `[0, 0xFFFF]`                 | 0x7c87 — **PASS** (16-bit int)  |
| AC6 | NOT 0x29B1 / NOT 0x2189              | ≠0x29b1, ≠0x2189 — **PASS**     |
| AC7 | Determinism on 100× same input       | identical — **PASS**            |
| AC8 | RefIn=false verified by suite        | **PASS** (crc(0x80)=0x9188)     |
| AC9 | RefOut=false verified by suite       | **PASS** (crc(0xA5)=0xe54f)     |
| AC10| XorOut=0x0000 (init^xorout identity) | crc(b'')=0x0000 — **PASS**      |
| AC11| crcmod byte-exact differential       | 100/100 + 9 deterministic — see §8 |
| AC12| TypeError on `None/str/int/list`     | 4/4 TypeError — **PASS**        |

## 3. Full pytest

`PYTHONPATH=src pytest --collect-only -q`:
```
tests/test_crc16_xmodem.py: 532
```

`PYTHONPATH=src pytest -q`:
```
........................................................................ [ 27%]
........................................................................ [ 40%]
........................................................................ [ 54%]
........................................................................ [ 67%]
........................................................................ [ 81%]
........................................................................ [ 94%]
............................                                             [100%]
532 passed in 3.48s
```

Result: **532 collected / 532 passed / 0 failed / exit 0**.

## 4. Fresh-venv smoke

Isolated venv at `/tmp/crc16-xmodem-smoke-XXXX` (mktemp), non-interactive
flags `PIP_NO_INPUT=1 CI=true` per Invariant 24.

```
$ python3 -m venv $SMOKE
$ $SMOKE/bin/pip install /root/projects/crc16-xmodem-pure/.worktrees/t_cycle132-build
   (success; 0 runtime deps installed besides setuptools build prereq)
$ $SMOKE/bin/crc16-xmodem --self-test
   PASS: crc(b'123456789') = 0x31C3     (exit code 0)
$ $SMOKE/bin/python -c "from crc16_xmodem import crc; print(hex(crc(b'123456789')))"
   0x31c3                               (RevEng byte-exact)
$ rm -rf $SMOKE
```

Outcome: **PASS** — Honest pillar satisfied; install cmd matches README claim
and works from a clean venv.

## 5. Fuzz / boundary (≥3 inputs)

Executed inside the smoke venv after `pip install crcmod`:

| Input                                    | Result | Verdict |
|------------------------------------------|--------|---------|
| `b""` (empty)                            | 0x0000 | PASS (matches RevEng empty-input = init^xorout) |
| `b"\xff" * 1000` (1KB of 0xFF)           | 0xf754 | PASS (no crash, valid 16-bit) |
| `b"\x00"` (single zero)                  | 0x0000 | PASS (matches AC3) |
| `b"\x80\x01\x02\x03\x04\x05\x06\x07\x08\x09"` (non-ASCII mixed) | 0xc74c | PASS (no crash) |
| `b"\x00" * (5*1024*1024)` (5MB linear perf) | 0x0000 in 1.278s | PASS (linear, no quadratic blowup) |

Five inputs exercised across the standard fuzz list (exceeds the ≥3 mandate).
All return 16-bit values consistent with the parameter table; no crash, no
quadratic blowup, no oracle mismatch.

## 6. Secret scan

```
$ git grep -nE 'ghp_|pypi-AgEI|sk-|AKIA|BEGIN PRIVATE KEY' -- ':!*.lock'
   (no output)
```

Result: **CLEAN**.

## 7. Dependencies audit

```
$ cat pyproject.toml
[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "crc16_xmodem"
version = "0.1.0"
...
dependencies = []

[project.optional-dependencies]
test = ["pytest>=7.0"]
bench = ["crcmod"]

[project.scripts]
crc16-xmodem = "crc16_xmodem.__main__:main"
```

- `dependencies = []` — zero runtime dependencies (Invariant 9).
- `[project.optional-dependencies]` contains only `test` (pytest) and `bench`
  (crcmod), both declared optional.

Result: **PASS**.

## 8. Cross-cycle oracle

Live test in the smoke venv with `crcmod` installed alongside crc16-xmodem-pure:

**8A — Deterministic crcmod differential (9 canonical cases):**
`empty, 0x00, 0xff, 0x00*16, "123456789", "a", "abc", bytes(range(256)),
"The quick brown fox jumps over the lazy dog"` → **0 mismatches** vs
`crcmod.predefined.mkPredefinedCrcFun('xmodem')`. Byte-exact across all 9.

**8B — 100 random inputs (lengths 1..1000 bytes, seeded RNG 20260927):**
**0 mismatches** vs the same crcmod oracle. Byte-exact across all 100.

**8C — Cross-cycle algorithm disambiguation:**
```
crc(b'123456789')                     = 0x31C3   (XMODEM,     init=0x0000 xorout=0x0000,    refin=false)
crcmod.modbus(b'123456789')           = 0x4B37   (MODBUS,     poly=0x8005  init=0xFFFF xorout=0x0000, refin=true)
crcmod.ccitt_false(b'123456789')      = 0x29B1   (CCITT-FALSE,poly=0x1021  init=0xFFFF xorout=0x0000, refin=false)
```

`xmodem == modbus`? False. `xmodem == ccitt_false`? False. The three
algorithms are **distinct** byte-exactly on the canonical check input. Even
though XMODEM shares the 0x1021 polynomial with CCITT-FALSE, the *parameter
combination* (init=0x0000 xorout=0x0000) makes the result diverge — the
exact bug §1 of SPEC.md warns against.

**8D — 5MB linear perf:** `b'\x00' * 5MB` processed in 1.278s. Linear, no
quadratic blowup.

**8E — Bytearray + memoryview support:**
- `crc(bytearray(b'123456789'))` = 0x31c3 — PASS
- `crc(memoryview(b'123456789'))` = 0x31c3 — PASS

Result: **PASS** — cross-cycle byte-exact against crcmod oracle; algorithm
distinct from sibling modbus / ccitt-false implementations.

## Summary

All 8 mandatory checks PASS. The repository meets the three-pillar contract:

- **Useful** — targets XMODEM-CRC file-transfer implementers; named competitors
  (`crcmod`, `crcany`) acknowledged; solves the real init/xorout copy-paste
  bug documented in SPEC.md §1.
- **Proven** — 532/532 pytest items pass (exit 0); fresh-venv smoke (pip
  install + CLI `--self-test` + import + RevEng 0x31C3 check) PASSES; linear
  perf verified at 5MB; crcmod external oracle byte-exact match for 100+
  random inputs.
- **Honest** — README test badge + CHANGELOG count corrected during QA from
  the overstretched "580+" to the real "532" found by `pytest --collect-only
  -q`. Install cmd is git-URL (no PyPI claim). `dependencies = []`; secret
  scan CLEAN.

QA side-correction: README badge (`tests-580+` → `tests-532/532`) and CHANGELOG
bullet (`580+` → `532`) committed in this QA commit. No functional code
changes; algorithm, CLI, tests, and oracle match untouched.

VERDICT: SHIP
