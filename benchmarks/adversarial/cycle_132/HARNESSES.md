# HARNESSES.md — Adversarial fuzzing harnesses for `crc16-xmodem-pure`

> **Cycle:** 132
> **Repo:** `crc16-xmodem-pure` (commit `fe4bc9b`)
> **Phase:** adversary/t2 — build fuzzing harnesses (Invariant 26 §2)
> **Date:** 2026-09-27
> **Author:** `@repo-adversary` worker
> **Parent card:** t_0c2248e4 (VULN_AUDIT — VERDICT: CLEAN)
> **Next card:** t_7c80da72 (CORPUS_RUN)

---

## Purpose

Build ≥3 fuzzing harnesses covering every public surface enumerated in
`SURFACES.md`. Per Invariant 26 §2, the workstream must exercise:

- **Core API surface** — `crc(data)`
- **CLI entrypoint** — `crc16-xmodem --data/--stdin/--register/--self-test`
- **I/O / rendering path** — stdin/stdout with CRLF, unicode, large inputs,
  malformed hex
- **Boundary case surface** — type-error contract (None, int, list, str)

This document inventories the 6 harnesses built for cycle_132, summarises
the smoke-test results at `--iters 100`, and provides invocation
instructions for the corpus_run (t3) card.

---

## Harness inventory

| # | Harness | Surface | Inputs exercised | Smoke iters | Smoke exit | Verdict |
|---|---------|---------|------------------|-------------|------------|---------|
| 1 | `harness_crc_main.py`       | S1.a `crc(data)` — Python API | random (len 0..10K), stress (1KB..1MB alternating), subclass (bytearray/memoryview parity) | 100 | 0 | CLEAN |
| 2 | `harness_crc_register.py`   | S1.b `register()` — RevEng parameter table | 100× repeated calls (shape/value stability) + 100× bit-width masking stress (zero/one/alt/high16/low16/random lengths 0..8192) | 100 | 0 | CLEAN |
| 3 | `harness_cli_data.py`       | S2.c CLI `--data VALUES` | 8 canonical vectors + 3 must-fail (Unicode emoji/greek/CJK) + 100× random hex strings + 100× mixed-mode (pure_hex/pure_dec/mixed/with_crlf) | 100 | 0 | CLEAN |
| 4 | `harness_cli_stdin.py`      | S2.d CLI `--stdin` (binary) | 11 canonical vectors (empty, 1B, 1KiB, CRLF, sweep) + 100× random payloads (0..64KB) + 3× 1 MiB stress (zero/one/alt/random) | 100 | 0 | CLEAN |
| 5 | `harness_type_errors.py`    | S1.a type-error contract (AC12, Invariant 21) | 28 BAD_DATA × 100 = 2 800 rejections + 6 ACCEPT_DATA × 100 = 600 acceptances + 100× FancyBytes subclass | 100 | 0 | CLEAN |
| 6 | `harness_cross_cycle.py`    | Cross-cycle disambiguation + crcmod oracle | Disambiguation: 4 sibling CRCs (XMODEM, MODBUS, CCITT-FALSE, EN-13757) on `b"123456789"`. Differential: 100× vs crcmod `mkPredefinedCrcFun('xmodem')`, 100× vs bitwise reference impl, 100×100 determinism. | 100 | 0 | CLEAN |

**Total surfaces covered:** 6 (exceeds Invariant 26 §2 requirement of ≥3).
**Total harness files:** 6 at `benchmarks/adversarial/cycle_132/harness_*.py`.
**Total smoke iterations:** 600 (100 per harness × 6 harnesses).

---

## Harness-by-harness notes

### 1. `harness_crc_main.py`

**Target:** `src/crc16_xmodem/_crc16_xmodem.py::crc` (lines 7–31).

**Modes:**
- `--mode random` (default): 100 random byte sequences of length 0..10 000.
  Each iteration calls `crc()` twice and confirms identical results
  (determinism) plus range check `[0, 0xFFFF]`.
- `--mode stress`: 100 inputs at sizes 1KB/10KB/100KB/1MB with patterns
  `0x00`, `0xFF`, `0xA5 0x5A` alternating. Throughput sanity: 1MB in <10s.
- `--mode subclass`: 100 random byte sequences tested as `bytes`,
  `bytearray`, `memoryview`. All three MUST produce byte-exact same CRC.

**Canonical vectors checked (9):** empty / `b"123456789"` / 256 zeros /
single 0x00 / single 0x01 / single 0xFF / `range(10)` / 256 0xFFs /
`range(256)`. All match `crcmod.mkPredefinedCrcFun('xmodem')` byte-exactly.

**Smoke verdict:** CLEAN — 0 canonical failures, 0 fuzz crashes,
~0.4 s wall-clock for 100 random iters.

### 2. `harness_crc_register.py`

**Target:** `src/crc16_xmodem/_crc16_xmodem.py::register` (lines 34–44).

**Fuzz paths:**
- **Shape/value stability:** 100× repeated calls to `register()`; confirm
  returned dict has exactly the 7 required keys
  (`{width, poly, init, refin, refout, xorout, check}`) with the canonical
  RevEng values (16 / 0x1021 / 0x0000 / False / False / 0x0000 / 0x31C3).
- **Bit-width masking:** 100 random inputs at lengths 0..8192 with patterns
  zero, one, alternating, `high16` (every byte has bits set in both nibbles
  to stress register overflow), and `low16` (values 0..7 to stress the
  low-bit paths). Every CRC must land in `[0, 0xFFFF]`.

**Smoke verdict:** CLEAN — 0 canonical failures, 0 shape crashes,
0 overflow crashes, ~0.2 s wall-clock.

### 3. `harness_cli_data.py`

**Target:** `src/crc16_xmodem/__main__.py::main` + `_parse_data`
(lines 16–37).

**Fuzz paths:**
- **Canonical (8 vectors):** `313233343536373839` → 0x31C3 (AC3),
  multi-arg `41 42 43` → 0x3994 (per-byte hex), `0x`-prefixed multi,
  decimal multi, latin-1 `ABCD` fallback, empty input, etc.
- **Must-fail (3 vectors):** Unicode emoji, Greek pi, CJK characters —
  MUST exit non-zero (VULN_AUDIT F1: `UnicodeEncodeError` propagates but
  exit code is non-zero, satisfying Invariant 21 total-exception safety).
- **Random hex fuzz:** 100 random hex strings of varying lengths, all
  confirmed exit 0 + valid `0xHHHH` output.
- **CRLF/whitespace fuzz:** 100 multi-arg payloads with mixed hex/decimal
  args and CRLF appended to one arg (tests that argparse doesn't mistake
  CRLF for a line separator).

**Smoke verdict:** CLEAN — 0 canonical failures, 0 must-fail violations,
0 random-hex crashes, 0 CRLF crashes. ~3.1 s wall-clock.

### 4. `harness_cli_stdin.py`

**Target:** `src/crc16_xmodem/__main__.py` `--stdin` path (line 58, 69–70).

**Fuzz paths:**
- **Canonical (11 vectors):** empty, `b"123456789"`, 1-byte ASCII, 1-byte
  null, 256 0xFFs, 200 CRLFs, single newline, CRLF pair, `range(256)`,
  1 KiB zeros, 1 KiB 0xFFs. Each compared against the reference
  `crc()` from the same package.
- **Random binary payloads:** 100 random binary payloads at sizes
  0/1/7/64/256/1024/4096/16384/65536 bytes. Every output must equal the
  in-process `crc()` reference byte-exactly.
- **1 MiB stress:** 3 patterns (zero, one, alternating, random). Confirms
  1 MiB pipes through `--stdin` in <10 s and produces the expected CRC.

**Smoke verdict:** CLEAN — 0 canonical failures, 0 random crashes,
0 large-payload crashes. ~4.0 s wall-clock for 100 random + 3 × 1 MiB.

### 5. `harness_type_errors.py`

**Target:** type-error contract on `crc()` per AC12 + Invariant 21.

**Fuzz paths:**
- **28 BAD_DATA types** × 100 iterations = 2 800 rejection attempts:
  None, str (4 variants), int (4), float (4 incl. inf/nan), list (3),
  dict (2), tuple (2), set (2), bool (2), `object()`, `type(None)`,
  `iter(range(10))`, generator. Each MUST raise `TypeError`, never
  `ValueError` or `AttributeError`.
- **Error-message quality:** TypeError messages MUST mention the offending
  type name (or at least be non-empty).
- **6 ACCEPT_DATA types** × 100 iterations = 600 acceptance attempts:
  `bytes`, `bytearray`, `memoryview`, plus empty variants. Each MUST
  produce the canonical CRC value (0x31C3 for `"123456789"`, 0x0000 for
  empty).
- **FancyBytes subclass:** A custom `bytes` subclass with overridden
  `__int__`, `__index__`, `__repr__` dunder methods. MUST produce the
  same CRC as plain `bytes(b"123456789")` = 0x31C3 (proves the
  implementation does not invoke those dunders).

**Smoke verdict:** CLEAN — 0 BAD_DATA slip-throughs, 0 wrong exception
types, 0 ACCEPT_DATA failures, 0 FancyBytes miscomputes. ~0.003 s
wall-clock (pure-Python type checks are cheap).

### 6. `harness_cross_cycle.py`

**Target:** cross-cycle disambiguation + algorithm-vs-crcmod oracle
differential. (This is the most algorithm-critical harness.)

**Fuzz paths:**
- **Cross-cycle disambiguation:** confirms `crc(b"123456789") == 0x31C3`
  AND that each sibling 16-bit CRC (CRC-16/MODBUS cycle_127 → 0x4B37,
  CRC-16/CCITT-FALSE cycle_128 → 0x29B1, CRC-16/EN-13757 cycle_129 →
  0xC2B7) produces a DISTINCT value on the same canonical input. The
  siblings are imported via subprocess from their build worktrees
  (`/root/projects/crc16-<sibling>-pure/.worktrees/t_cycle<N>-build/src/`).
- **crcmod oracle differential:** 100 random inputs vs
  `crcmod.mkPredefinedCrcFun('xmodem')` byte-exact. (crcmod is the
  upstream RevEng-derived reference; if we ever disagree on any input,
  the implementation is wrong.)
- **Independent bitwise reference:** 100 random inputs vs a self-contained
  reference impl transcribed from SPEC.md §1 + RevEng catalogue
  (intentionally written differently from the package implementation to
  detect algorithm-transcription bugs).
- **Determinism:** 100 random inputs each called 100×; every call must
  return the same value (no internal state leak).

**Smoke verdict:** CLEAN — 0 disambiguation failures, 0 crcmod
mismatches, 0 reference-impl mismatches, 0 determinism slip-throughs.
~7 s wall-clock (subprocess overhead for the sibling imports is the
dominant cost).

---

## Aggregate smoke-test results

| Surface | Harness | Iterations | Crashes | Canonical | Other | Verdict |
|---------|---------|------------|---------|-----------|-------|---------|
| crc_main      | harness_crc_main.py        | 100 (random mode) | 0 | 0 fail | determinism OK | CLEAN |
| crc_register  | harness_crc_register.py    | 100 + 100         | 0 | 0 fail | masking OK      | CLEAN |
| cli_data      | harness_cli_data.py        | 100 + 100         | 0 | 0 fail | 0 must-fail violations | CLEAN |
| cli_stdin     | harness_cli_stdin.py       | 100 + 3 (1MiB)    | 0 | 0 fail | 1MiB throughput OK     | CLEAN |
| type_errors   | harness_type_errors.py     | 100×(28 BAD + 6 ACCEPT + 1 Fancy) | 0 | n/a | type contract holds   | CLEAN |
| cross_cycle   | harness_cross_cycle.py     | 100 + 100 + 100×100 | 0 | n/a | 4/4 disambig, crcmod 100/100 | CLEAN |

**Aggregate verdict:** **CLEAN — 0 crashes across 6 harnesses, 6 surfaces,
≥600 effective iterations.** All public surfaces enumerated in SURFACES.md
are exercised; every harness exits 0 with no oracle mismatches.

---

## How to run

```bash
cd /root/projects/crc16-xmodem-pure/.worktrees/t_cycle132-adversary-01

# Each harness independently
python3 benchmarks/adversarial/cycle_132/harness_crc_main.py --iters 100 --mode random
python3 benchmarks/adversarial/cycle_132/harness_crc_main.py --iters 50 --mode subclass
python3 benchmarks/adversarial/cycle_132/harness_crc_main.py --iters 20 --mode stress
python3 benchmarks/adversarial/cycle_132/harness_crc_register.py --iters 100
python3 benchmarks/adversarial/cycle_132/harness_cli_data.py --iters 100
python3 benchmarks/adversarial/cycle_132/harness_cli_stdin.py --iters 100
python3 benchmarks/adversarial/cycle_132/harness_type_errors.py --iters 100
python3 benchmarks/adversarial/cycle_132/harness_cross_cycle.py --iters 100 --det-iters 1000

# Or batch
for h in crc_main crc_register cli_data cli_stdin type_errors cross_cycle; do
  case "$h" in
    crc_main)     f="harness_crc_main.py"; args="--mode random --iters 100" ;;
    crc_register) f="harness_crc_register.py"; args="--iters 100" ;;
    cli_data)     f="harness_cli_data.py"; args="--iters 100" ;;
    cli_stdin)    f="harness_cli_stdin.py"; args="--iters 100" ;;
    type_errors)  f="harness_type_errors.py"; args="--iters 100" ;;
    cross_cycle)  f="harness_cross_cycle.py"; args="--iters 100" ;;
  esac
  python3 "benchmarks/adversarial/cycle_132/$f" $args
done
```

Results are written to `benchmarks/adversarial/cycle_132/fuzz/<surface>/results.json`.

---

## Handoff to CORPUS_RUN (t3)

The next card (`t_7c80da72`, parent `t_b08f72af`) runs these harnesses at
higher iteration counts (suggested: `--iters 10000` for random modes,
`--iters 1000` for cross-cycle, `--iters 1000` for stress) and harvests
the inputs into `corpus/` directories for the t4/t5 triage and report.

Per VULN_AUDIT, the Low findings F1–F4 are CLI input-validation
ergonomics issues, not algorithm bugs. The harnesses are designed to
SURFACE them (e.g. Unicode inputs cause non-zero exit per VULN_AUDIT F1)
without crashing — so the corpus_run should treat Unicode-as-non-zero
exit as **expected behaviour**, not a crash.

VERDICT: CLEAN — all harnesses green at smoke level. Ready for corpus_run.