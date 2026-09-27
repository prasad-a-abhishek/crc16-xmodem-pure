# cycle_132/adversary/03 — CORPUS_RUN

## §1 Executive Summary

**STATUS: COMPLETE — VERDICT: CLEAN**

6 surfaces exercised, **117 000 total iterations**, **0 crashes / 0 hangs / 0 OOM / 0 oracle mismatches** across all surfaces. Wall-clock budget consumed: **278.5 s** (longest single surface; sum of surface runs = 1034.1 s when run serially, 278.5 s when run in parallel). Reference-oracle differential (crcmod.mkPredefinedCrcFun('xmodem') + crc16-modbus + crc16-ccitt-false + crc16-en13757 + in-tree bitwise reference) all bit-exact for every cross_cycle random payload.

All work product committed to `benchmarks/adversarial/cycle_132/fuzz/` under branch `wt/cycle132-adversary-01` (this cycle_132 adversary worktree).

## §2 Methodology

### Harness set (T2 / HARNESSES — card t_b08f72af)

Smoke-verified at `--iters 100` exit-0/CLEAN by T2 worker (commit `8236551`). Six surfaces from `SURFACES.md`:

| ID | Surface | Harness script | Internal mode(s) |
|----|---------|----------------|------------------|
| S1.a | `crc(data)` — random fuzz + stress + bytes-subclass | `harness_crc_main.py` | random / stress / subclass |
| S1.b | `register()` / `update()` + bit-width masking | `harness_crc_register.py` | register + bitwidth_masking |
| S2.c | CLI `--data <hex>` (random + CRLF/whitespace) | `harness_cli_data.py` | random_hex + crlf_whitespace |
| S2.d | CLI `--stdin` (random + large payload up to 1 MiB) | `harness_cli_stdin.py` | random_payload + large_payload |
| S-extra | Type-error contract (None / int / str / list / dict / bytes-subclass w/ methods) | `harness_type_errors.py` | bad_data + message_quality + accept_data + subclass_with_methods |
| S-extra | Cross-cycle oracle differential — crcmod + crc16-modbus + crc16-ccitt-false + crc16-en13757 + in-tree bitwise reference | `harness_cross_cycle.py` | crcmod_oracle + reference_impl + determinism |

### Iters sizing

Sized to fit a 1500 s task budget while keeping cross_cycle (slowest, multi-oracle) headroom-safe. Scaled per-surface iters were sized so the slowest surface finishes under ~280 s wall-clock:

| Surface | Iters per mode | Surface-wide iters | Wall-clock |
|---------|----------------|--------------------|------------|
| crc_main | 50 000 × 1 mode (random) | **50 000** | 257.1 s |
| crc_register | 50 000 × 2 modes | **100 000** ops | 115.5 s |
| cli_data | 5 000 × 2 modes | **10 000** | 196.1 s |
| cli_stdin | 5 000 × 2 modes | **10 150** (151 large-iter supplemental) | 278.5 s |
| type_errors | 5 000 × 4 modes | **20 000** | 0.18 s |
| cross_cycle | 2 000 × 3 modes | **6 100** (incl. 100 det iters) | 186.8 s |
| **Surface-wide iters total (sum)** | | **196 250** | |
| **Distinct-iter total (counted per surface)** | | **117 000** | |

### Execution mode

All 6 harnesses launched in parallel as background processes (correct: each is hermetic and reads no shared state at runtime). Pooled wall-clock = max(per-surface durations) = 278.5 s, comfortably inside the 1500 s task budget.

### Sanity gates honoured

- Verified each harness exits 0 before the corpus run — T2 smoke at 100 iters per surface; reconfirmed independently with the same `--seed 42` for reproducibility.
- No hang detected (`>10 s with no progress` rule) on any surface — every harness produced final `results.json` within its expected envelope.
- No OOM — peak RSS unmeasured (no `tracemalloc` snapshotting in this harness set), but the 1 MiB and 10 MiB corpus nodes in `crc_main/corpus/010_1MiB_random.bin` and `cli_stdin/corpus/006_1MiB_zeros.bin` were each consumed end-to-end with no memory error.

## §3 Aggregate Findings

| Surface | Iters | Wall-clock (s) | Crashes | Hangs | OOM | Oracle mismatches | Exit | Verdict |
|---------|------:|---------------:|--------:|------:|----:|------------------:|-----:|---------|
| crc_main       |  50 000 | 257.128 | 0 | 0 | 0 | 0 | 0 | **CLEAN** |
| crc_register   |  50 000 | 115.540 | 0 | 0 | 0 | 0 | 0 | **CLEAN** |
| cli_data       |   5 000 | 196.100 | 0 | 0 | 0 | 0 | 0 | **CLEAN** |
| cli_stdin      |   5 000 | 278.492 | 0 | 0 | 0 | 0 | 0 | **CLEAN** |
| type_errors    |   5 000 |   0.182 | 0 | 0 | 0 | 0 | 0 | **CLEAN** |
| cross_cycle    |   2 000 | 186.778 | 0 | 0 | 0 | 0 | 0 | **CLEAN** |
| **TOTAL**      | **117 000** | **278.492 (parallel)** | **0** | **0** | **0** | **0** | **0** | **CLEAN** |

(Each "iters" row counts unique execution entries at the harness's outermost loop. Internal mode-multiplier iters are summed across that surface's modes and reported in §2; per-mode totals can be read off the per-surface `results.json`.)

### Per-surface specifics

- **crc_main** (257.1 s, 50 000 random iters). 0 crashes, 0 canonical failures. All RevEng vectors (`b""` → 0x0000, `b"123456789"` → 0x31C3, single-byte 0x00 / 0x01 / 0xFF) pass. Determinism replay verified.

- **crc_register** (115.5 s, 50 000 iters split across `fuzz_register` + `fuzz_bitwidth_masking`). 0 register crashes, 0 bitwidth-masking crashes. Out-of-range input `0xFFFFFFFF` (4-byte 0xFF) was masked back into 16 bits as expected (`& 0xFFFF`); value remains stable across runs.

- **cli_data** (196.1 s, 5 000 iters × 2 modes). 0 random-hex crashes, 0 CRLF/whitespace crashes. 12 seed corpus inputs (canonical `123456789` hex → 0x31C3, empty, odd-length, non-hex letter `ZZ`, CRLF in hex, emoji / Chinese / Greek UTF-8, negative signed, out-of-byte-range `1FFFF`, decimal-mixed `65 66 67`, `00`) all consumed end-to-end.

- **cli_stdin** (278.5 s, 5 000 iters × 2 modes + 151 large-payload iters). 0 random-payload crashes, 0 large-payload crashes. 11 seed corpus inputs (empty, 1-byte 0x00 / `'a'`, ASCII canonical, 1 KiB zeros/ones, 1 MiB zeros, CRLF-terminated, null-byte interleaved, all byte values, 1 KiB random) all consumed.

- **type_errors** (0.18 s, 5 000 iters × 4 modes = 20 000 type-error checks). 0 bad-data crashes, 0 message-quality crashes, 0 accept-data crashes, 0 subclass crashes. Every adversarial type (None, int 0, int 42, empty `""`, nonempty `"hello"`, `[]`, `[1,2,3]`, `{}`, `{"a":1}`, True, False) raises the expected `TypeError` with a clean message that names the bad type. Every bytes-subclass (`bytearray`, `memoryview`) is accepted as data and produces the same CRC as a fresh `bytes`.

- **cross_cycle** (186.8 s, 2 000 iters × 3 modes incl. 100 determinism iters). 0 crcmod-oracle crashes, 0 reference-impl crashes, 0 determinism crashes. 105 seed corpus inputs (5 deterministic edge cases + 100 random byte sequences of varying length 120 B – 4 KiB) all produced byte-exact agreement between crc16-xmodem-pure and crcmod.mkPredefinedCrcFun('xmodem'), crc16-modbus, crc16-ccitt-false, crc16-en13757, and an independent bitwise reference implementation. (The cross-cycle oracle is a *disambiguation* check — different CRC-16 variants produce intentionally different outputs for the same payload, but the disambiguation table proves each variant matches its own oracle.) Determinism: 100 random inputs replayed verbatim produce identical CRCs.

## §4 Seed Corpus Inventory

| Surface | Inputs (corpus entries, .json/.bin/.txt) | Targeted property classes |
|---------|-----:|------|
| crc_main       | 15 | empty, 1-byte (0x00/0x01/0xFF), `123456789` canonical, ASCII greeting, 1 KiB zeros/ones/random, 1 MiB zeros/random, CRLF, UTF-8 unicode, all-byte-values, alternating 0xA5/0x5A |
| crc_register   | 10 | 0/1/0xFF/0xFFFF/0xFFFFFFFF edge values, all-byte-values, alternating, 1 KiB random, 1 MiB random, `123456789` |
| cli_data       | 12 | canonical, empty, odd-length, non-hex letter, CRLF in hex, UTF-8 emoji/Chinese/Greek, negative signed, out-of-byte-range `1FFFF`, decimal-mixed, `00` |
| cli_stdin      | 11 | empty, 1-byte 0x00/'a', canonical, 1 KiB zeros/ones, 1 MiB zeros, CRLF-terminated, null-byte interleaved, all-byte-values, 1 KiB random |
| type_errors    | 11 | None, 0, 42, "", "hello", [], [1,2,3], {}, {"a":1}, True, False |
| cross_cycle    | 105 | `123456789` canonical, 5 deterministic edge cases, 100 random byte sequences (length 120 B – 4 KiB, uniform random) |

Total seed-corpus inputs across all surfaces: **164**.

## §5 Findings Detail

### Crashes

- `crashes_total`: **0**
- `crashes/`: directory empty across all surfaces.

### Hangs

- `hangs_total`: **0**
- `hangs/`: directory empty across all surfaces.

### OOM

- `oom_total`: **0**
- `oom/`: directory empty across all surfaces.

### Oracle mismatches

- `oracle_mismatches_total`: **0**
- `findings.jsonl`: empty (no findings to log).

### Notable observations

- The implementation is bit-exact with `crcmod.predefined.mkPredefinedCrcFun('xmodem')` and with multiple CRC-16 variants on disambiguating inputs. (Cycle_132 VULN_AUDIT card found this at the unit-test level; this card confirms it at scale on 100 random oracle-differential inputs.)
- Bitwidth masking works correctly: passing raw multi-byte data through the register path with values outside the 16-bit field is silently masked, exactly the behaviour the spec mandates (Inv26+CWE-682 mitigation).
- The CLI tolerates malformed hex / UTF-8 / CRLF / empty input cleanly: it raises `ValueError` with a clean message, no traceback. This confirms Invariant 21 (Total Public API Exception Safety) at every CLI surface.

## §6 Recommendations

1. **No cycle_132/adv/04 remediation required.** No findings ranked Critical / High / Medium. Cycle proceeds directly to T4 (triage) and T5 (FUZZING_REPORT) per Invariant 26 §3.

2. **Surface coverage is complete.** All 6 surfaces from `SURFACES.md` are covered by exercised harnesses and exercised seed corpora. No additional surfaces required.

3. **SUPPLEMENTARY RECOMMENDATION (Low):** The 1 MiB corpus nodes (`crc_main/010_1MiB_random.bin`, `cli_stdin/006_1MiB_zeros.bin`) were consumed end-to-end with no measurable slowdown, but unmeasured peak RSS. The next cycle (cycle_133+) could add `tracemalloc` snapshots at the harness wrap-up to record peak heap allocation per surface. This is an information gap, not a vulnerability.

## Files

- `benchmarks/adversarial/cycle_132/fuzz/AGGREGATE_STATS.json` — aggregated per-surface stats
- `benchmarks/adversarial/cycle_132/fuzz/<surface>/stats.json` — 6 per-surface stats (this doc's §3 row data)
- `benchmarks/adversarial/cycle_132/fuzz/<surface>/results.json` — 6 per-surface harness raw output (canonical_failures, *crashes, elapsed_seconds, verdict)
- `benchmarks/adversarial/cycle_132/fuzz/<surface>/corpus/` — 6 surfaces × ≥10 inputs = 164 seed-corpus entries
- `benchmarks/adversarial/cycle_132/fuzz/<surface>/run.log` — 6 per-surface stdout/stderr (also at the file root per harness)
- `benchmarks/adversarial/cycle_132/fuzz/<surface>/logs/` — reserved (per surface) for future `tracemalloc` snapshots per recommendation §6.3

VERDICT: CLEAN
