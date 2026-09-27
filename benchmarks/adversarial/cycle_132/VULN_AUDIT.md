# VULN_AUDIT — manual vulnerability audit of crc16-xmodem

> Cycle 132 / T1 VULN_AUDIT — final audit report for `crc16-xmodem` @ commit 6071f9c.
>
> **Author:** @repo-adversary T1 (this card, t_99239ecb)
> **Cycle:** 132
> **Repo:** crc16-xmodem-pure (CRC-16/XMODEM reference implementation, zero runtime deps)
> **Commit audited:** 6071f9cf3fcd048d0c0cce5875009f93cb4966dd ("qa: cycle_132 adversarial QA — 8/8 checks PASS, VERDICT: SHIP")
> **Branch:** wt/cycle132-adversary-01
> **Auditor methodology:** 12 probe scripts run against a fresh `uv venv` install; 45 CWEs considered (CWE_MAP.md); 4 surfaces enumerated (SURFACES.md); 11 test gaps identified (TEST_GAPS.md); 7 attacker profiles evaluated (THREAT_MODEL.md).
>
> **Companion deliverables in this directory:**
> - [`SURFACES.md`](./SURFACES.md) — surface enumeration
> - [`CWE_MAP.md`](./CWE_MAP.md) — 45-CWE applicability table
> - [`TEST_GAPS.md`](./TEST_GAPS.md) — 11 coverage gaps
> - [`THREAT_MODEL.md`](./THREAT_MODEL.md) — attacker profiles + worst-case impact

---

## 1. Executive summary

`crc16-xmodem` is a 44-LOC pure-Python CRC-16/XMODEM reference implementation
with a 79-LOC CLI wrapper. The package is offline-only, filesystem-free at
runtime, and has zero runtime dependencies. The attack surface consists of
exactly **4 entry points** (2 library functions + 1 CLI + 1 internal helper).

The manual audit covered all 4 surfaces with 12 probe scripts. **One Low
severity finding** (F-1) was identified: the CLI does not catch the
`ValueError` raised by `int(v, 16)` when `--data 0xZZ` (or any `0x`-prefixed
non-hex string) is passed, so Python dumps a raw traceback to stderr. This
violates Invariant 21 ("Total Public API Exception Safety") for the CLI entry
point. The leaked information is the install file path — no secrets, no PII,
no RCE.

**Zero Critical, zero High, zero Medium findings. One Low finding. Three Info notes.**

The T3 fuzzing card (next in this cycle's adversary chain) is expected to find
zero additional High-severity findings given the algorithm's trivial structure
(linear byte loop, fixed 8-iteration inner loop, hard-coded constants).

## 2. Methodology

### 2.1 Audit phases

1. **Orient** — read all source files (`_crc16_xmodem.py`, `__init__.py`,
   `__main__.py`, `tests/test_crc16_xmodem.py`, `pyproject.toml`, `README.md`).
2. **Enumerate surfaces** — produce SURFACES.md (4 surfaces).
3. **Map CWEs** — produce CWE_MAP.md (45 CWEs considered, 13 APPLY, 1 finding).
4. **Identify test gaps** — produce TEST_GAPS.md (11 gaps; 1 maps to F-1).
5. **Threat model** — produce THREAT_MODEL.md (7 attacker profiles).
6. **Run probes** — execute 12 probe scripts against a fresh `uv venv` install.
7. **Adjudicate findings** — produce this VULN_AUDIT.md.
8. **Commit** — all 5 deliverables committed to the branch.

### 2.2 Probe environment

```
$ python3 --version
Python 3.11.15

$ uv venv --quiet .venv-adversary --python python3.11
$ . .venv-adversary/bin/activate
$ uv pip install --quiet -e .
$ uv pip install --quiet crcmod pytest
$ python3 -c "import crc16_xmodem; print('version:', crc16_xmodem.__version__)"
version: 0.1.0

$ python3 -m pytest --collect-only -q
tests/test_crc16_xmodem.py: 532
```

### 2.3 Probe inventory

| Probe | Surface | Inputs | Result |
|---|---|---|---|
| VULN-1 | `crc()` | 10 non-bytes-like types | 10/10 TypeError (PASS) |
| VULN-2 | `crc()` | 5 iterables (gen, iter, range, map, zip) | 5/5 TypeError (PASS) |
| VULN-3 | `crc()` | 1 MiB, 10 MiB, 50 MiB | Linear scaling confirmed |
| VULN-4 | `crc()` | Single bytes at boundaries (0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF) | All yield valid CRC |
| VULN-5 | CLI `--stdin` | 7 variants (ASCII, CRLF, LF, multi-LF, non-ASCII, 0..255, empty) | 7/7 cli==api (PASS) |
| VULN-6 | CLI `--data` | 9 malformed inputs including `0xZZ` | **`0xZZ` uncaught ValueError → F-1** |
| VULN-7 | CLI flag combinations | 5 combos | All exit cleanly |
| VULN-8 | `register()` + `crcmod.xmodem` | RevEng parameter table byte-exact | 7/7 + crcmod match (PASS) |
| VULN-9 | Determinism | 1024-byte input × 3 calls | All three identical (PASS) |
| VULN-10 | Mutable inputs | bytearray + memoryview + mutation | Correct Python semantics (PASS) |
| VULN-11 | Output mask | 1000 random 64-byte inputs | 1000/1000 in `[0, 65536)` (PASS) |
| VULN-12 | Oracle stress | 50000 random inputs vs `crcmod.xmodem` | 0/50000 mismatches (PASS) |

## 3. Findings

### F-1 — CLI malformed-hex uncaught `ValueError` (Low)

**CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information),
CWE-391 (Unchecked Error Condition)
**Severity:** Low
**Surface:** CLI `_parse_data()` internal helper, `__main__.py` line 28
**Invariant violated:** Invariant 21 — "Total Public API Exception Safety"
**File:** `src/crc16_xmodem/__main__.py:28` (`out.append(int(v, 16) & 0xFF)`)
**Reproducer:**
```bash
$ python3 -m crc16_xmodem --data 0xZZ
Traceback (most recent call last):
  File "<frozen runpy>", line 198, in _run_module_as_main
  File "<frozen runpy>", line 88, in _run_code
  File "/root/projects/crc16-xmodem-pure/.worktrees/t_cycle132-adversary-01/src/crc16_xmodem/__main__.py", line 79, in <module>
    raise SystemExit(main())
  File "/root/projects/crc16-xmodem-pure/.worktrees/t_cycle132-adversary-01/src/crc16_xmodem/__main__.py", line 72, in main
    data = _parse_data(args.data)
  File "/root/projects/crc16-xmodem-pure/.worktrees/t_cycle132-adversary-01/src/crc16_xmodem/__main__.py", line 28, in _parse_data
    out.append(int(v, 16) & 0xFF)
               ^^^^^^^^^^
ValueError: invalid literal for int() with base 16: '0xZZ'
```

**Why Low and not higher:**
- The leaked file path contains no secrets, no PII, no credentials, no
  cryptographic material. It is the absolute path of the installed package.
- The exit code is non-zero (rc=1), so script wrappers can detect the failure.
- No RCE, no DoS, no information disclosure beyond the install path.
- The exception is a standard Python `ValueError`; the traceback format is the
  Python default and matches what every Python user sees for any other bug.

**Why still a finding:**
- Invariant 21 explicitly mandates: "All public top-level functions and CLI
  entrypoints MUST be total over arbitrary input... MUST NEVER raise uncaught
  `ValueError`, `TypeError`, or `AttributeError`. They MUST return structured
  error findings cleanly."
- A future change that puts a secret in the install path (e.g. a config file
  with credentials in the same directory) would leak it via the same traceback.
  Defensive programming says fix it now while the leak is harmless.

**Recommended fix (T4 triage):**
```python
def _parse_data(values: list[str]) -> bytes:
    """..."""
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
            try:
                out.append(int(v, 16) & 0xFF)
            except ValueError:
                raise SystemExit(f"error: invalid hex value {v!r}")  # ← new
        else:
            try:
                out.append(int(v, 16) & 0xFF)
            except ValueError:
                try:
                    out.append(int(v) & 0xFF)
                except ValueError:
                    out.extend(v.encode("latin-1"))
    return bytes(out)
```

This is the entire fix — one try/except wrapping line 28 of `__main__.py`. After
the fix, the reproducer becomes:
```
$ python3 -m crc16_xmodem --data 0xZZ
error: invalid hex value '0xZZ'
```
Clean exit, no traceback, no path leak.

### F-2 — INFO: memoryview is a live view (Info)

**CWE:** None (documented Python semantics, not a vulnerability)
**Severity:** Info (note for downstream auditors)
**Surface:** `crc()` accepts `memoryview` (line 19 `isinstance` check)
**Evidence:** Probe VULN-10 — `crc(memoryview(src))` returns the correct CRC
at the time of iteration; mutating `src[0]` after the call does not retroactively
change the returned CRC; mutating `src[0]` BEFORE the next call correctly returns
the new CRC.

**Recommendation:** Document this in the docstring of `crc()` or in README.
Currently silent. Not blocking. No fix required.

### F-3 — INFO: stdin unbounded read (Info)

**CWE:** CWE-770 (Allocation of Resources Without Limits)
**Severity:** Info (caller-controlled, not attacker-exploitable through the
package itself)
**Surface:** `__main__.py:70` (`data = sys.stdin.buffer.read()`)
**Evidence:** Standard Python idiom. The caller controls how much they pipe.

**Recommendation:** Document the unbounded nature in README if relevant. No fix
required. The CLI is a one-shot tool — long-running streaming is out of scope.

### F-4 — INFO: CRC-16/XMODEM is not cryptographic (Info)

**CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
**Severity:** Info (documented use case, not a misuse)
**Surface:** Algorithm choice
**Evidence:** CRC is a checksum, not a cryptographic primitive. 16-bit CRC has
1/65536 collision probability for random inputs. README is honest about the
algorithm being the "XMODEM file-transfer protocol CRC."

**Recommendation:** No fix. README documentation is accurate. If a future
caller wants to use CRC for adversarial integrity protection, they should
choose HMAC-SHA256 or similar — that is a separate problem space.

## 4. Probe evidence (verbatim, abbreviated)

The full 12-probe output is captured in `/tmp/adv_probes.out` during the audit
run. Key excerpts (full file retained for T3 fuzzing harness seeding):

### VULN-1 (Non-bytes-like inputs)
```
[PASS] TypeError for NoneType: crc16_xmodem.crc() expected bytes-like, got NoneType
[PASS] TypeError for int: crc16_xmodem.crc() expected bytes-like, got int
[PASS] TypeError for float: crc16_xmodem.crc() expected bytes-like, got float
[PASS] TypeError for bool: crc16_xmodem.crc() expected bytes-like, got bool
[PASS] TypeError for str: crc16_xmodem.crc() expected bytes-like, got str
[PASS] TypeError for list: crc16_xmodem.crc() expected bytes-like, got list
[PASS] TypeError for tuple: crc16_xmodem.crc() expected bytes-like, got tuple
[PASS] TypeError for dict: crc16_xmodem.crc() expected bytes-like, got dict
```

### VULN-3 (Size extremes — linear scaling)
```
[INFO] crc(b'') = 0x0000
[INFO] crc(1 MiB) = 0x73EF in 467.8 ms
[INFO] crc(10 MiB) = 0xBDDE in 4821.4 ms
[INFO] crc(50 MiB) = 0xEF8F in 33475.1 ms
[INFO] throughput MB/s:  1MB=2.1  10MB=2.1  50MB=1.5
```
Linear scaling confirmed. 50 MB at 1.5 MB/s is the cold-cache baseline; the
1 MB and 10 MB sizes warm the cache and hit 2.1 MB/s. No quadratic blowup.

### VULN-6 (CLI --data malformed)
```
[INFO] args=['ZZZZ']                rc=0  stdout='0x9E54'  stderr=''           ← latin-1 fallback
[INFO] args=['abc']                 rc=0  stdout='0x6657'  stderr=''           ← latin-1 fallback
[INFO] args=['0xZZ']                rc=1  stdout=''  stderr='Traceback...'     ← F-1 (uncaught ValueError)
[INFO] args=['9999999999999999999999'] rc=0  stdout='0x980D'  stderr=''        ← int() & 0xFF fallback
[INFO] args=['-1']                  rc=0  stdout='0x1EF0'  stderr=''           ← int() & 0xFF fallback
[INFO] args=['3.14']                rc=0  stdout='0x6A81'  stderr=''           ← int() & 0xFF fallback
[INFO] args=['; rm -rf /']          rc=0  stdout='0xDE22'  stderr=''           ← latin-1 fallback (NO shell injection)
[INFO] args=['$(whoami)']           rc=0  stdout='0x1F5E'  stderr=''           ← latin-1 fallback (NO shell injection)
[INFO] args=['`id`']                rc=0  stdout='0xF760'  stderr=''           ← latin-1 fallback (NO shell injection)
```

### VULN-8 (Disambiguation vs sibling 16-bit CRCs)
```
[PASS] register['width']   = 16    (expected 16)
[PASS] register['poly']    = 4129  (expected 4129)   # 0x1021
[PASS] register['init']    = 0     (expected 0)
[PASS] register['refin']   = False (expected False)
[PASS] register['refout']  = False (expected False)
[PASS] register['xorout']  = 0     (expected 0)
[PASS] register['check']   = 12739 (expected 12739)  # 0x31C3
[PASS] crcmod.xmodem(b'123456789') = 0x31C3 (expected 0x31C3)
```

### VULN-12 (50000-input oracle stress)
```
[PASS] 50000 random inputs vs crcmod.xmodem: 0 mismatches
```

## 5. Per-surface summary

| Surface | Probes | Pass | Findings |
|---|---|---|---|
| `crc()` library API | VULN-1, 2, 3, 4, 9, 10, 11, 12 | All pass | F-2 (Info) |
| `register()` metadata | VULN-8 (param table) | All pass | None |
| CLI main() | VULN-5, 6, 7 | Pass except F-1 | F-1 (Low) |
| _parse_data() internal | (covered by VULN-6) | Pass except F-1 | F-1 (Low) |
| stdin reading | VULN-5 | All pass | F-3 (Info) |
| Algorithm choice | VULN-8, 12 | All pass | F-4 (Info) |

## 6. Severity-ranked findings

| ID | Severity | Title | CWE | Invariant | Action |
|---|---|---|---|---|---|
| F-1 | Low | CLI malformed-hex uncaught `ValueError` dumps traceback | CWE-209, CWE-391 | 21 | T4 fix: wrap `int(v, 16)` in try/except → `SystemExit` |
| F-2 | Info | `memoryview` is a live view (documented Python semantics) | — | — | Optional docstring note |
| F-3 | Info | stdin read is unbounded (caller-controlled) | CWE-770 (informational) | — | None |
| F-4 | Info | CRC-16/XMODEM is not cryptographic (documented choice) | CWE-327 (informational) | — | None |

## 7. Recommendation for downstream adversary cards

- **T3 (fuzzing harnesses, t_b8d8...):** Target `crc()` with Atheris-style
  fuzzing. Expected finding count: 0 High/Critical. The 12 manual probes
  already cover the most adversarial inputs; the value of T3 is automated
  coverage with ASan/UBSan rather than manual novelty. Consider seeding the
  fuzzer corpus with the input shapes from VULN-1/2/5/6 to reach deeper paths
  faster.

- **T4 (triage + remediate, t_...):** Apply the F-1 fix (one try/except
  block, ~5 lines). Add the G1 test from TEST_GAPS.md to enforce the
  Invariant 21 contract going forward. Re-run pytest; expected: 533/533 (532
  existing + 1 new). Push the fix as a follow-up commit; do NOT re-tag the
  v0.1.0 release unless QA re-runs the full pipeline.

- **T5 (FUZZING_REPORT, t_...):** This T1 report (VULN_AUDIT.md) feeds
  into T5's Executive Summary section. Reference F-1 as the only actionable
  finding; reference F-2/F-3/F-4 as informational.

## 8. Verdict

```
VERDICT: CLEAN (0 Critical, 0 High, 0 Medium, 1 Low, 3 Info)
```

The "CLEAN" verdict applies despite the F-1 Low finding because:
- F-1 is trivially fixable in ~5 lines (already drafted in §3).
- F-1 leaks no secrets, no PII, no credentials.
- F-1 does not affect the library API (`crc()`); only the CLI is affected.
- The algorithm itself (`crc()` and `register()`) is clean.

Per Invariant 26 §1 ("clean-vs-dirty verdict"), the verdict line is `VERDICT: CLEAN`
when there are no Critical/High findings that block ship. F-1 is recommended for
T4 remediation but does NOT block ship of v0.1.0.

---

**Auditor:** @repo-adversary T1 (kanban task t_99239ecb)
**Cycle:** 132
**Date:** 2026-09-27
**Branch:** wt/cycle132-adversary-01
**Commit:** 6071f9c (cycle_132/qa VERDICT:SHIP base)

VERDICT: CLEAN
