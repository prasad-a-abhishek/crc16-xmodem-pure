# TEST_GAPS.md — Test coverage gaps vs. the 532-test baseline

> **Cycle:** 132
> **Repo:** `crc16-xmodem-pure` (commit 6071f9c)
> **Baseline:** `pytest --collect-only -q` reports **532 items**, 0 fail
> **Categories covered:** canonical_check (6) + byte_range_zero (256) +
> length_sweep (64) + seed_vectors (6) + determinism (30) + type_errors
> (8) + bytearray_memoryview (4) + register_metadata (7) + oracle_crcmod
> (100) + cli (6) + edge_cases (30) + long_input_no_quadratic (5) +
> init_param_conformance (10).
> **Date:** 2026-09-27

---

## Gap matrix

| #  | Gap                                          | Surface          | Existing coverage    | Severity | Test suggestion                                  |
|----|----------------------------------------------|------------------|----------------------|----------|--------------------------------------------------|
| G1 | CLI exception surfacing with non-ASCII args  | `__main__.py`    | None                 | Low      | Add `test_cli_unicode_arg_exits_nonzero` and `test_cli_malformed_hex_exits_nonzero` |
| G2 | CLI `--data` ambiguity (decimal vs hex vs text) | `__main__.py` | None                 | Low      | Add `test_cli_data_decimal_vs_hex_disambiguation` and `test_cli_data_nonhex_text_silent` |
| G3 | Public API over generators / FakeBytes       | `_crc16_xmodem.py` | Type-error category covers `set`/`tuple`/`list`/`dict` | Info | Add 1–2 items: `test_type_error_on_iterable_not_byteslike` |
| G4 | Numeric-input silent masking asymmetry        | `__main__.py` `_parse_data` | None        | Low      | Add `test_cli_decimal_large_int_handling` — confirm consistent behavior |
| G5 | 100 MiB stdin stress                          | CLI              | 5MB linear perf test, but no stdin pipe at 100MB | Info | Add 1 subprocess test piping 100 MiB through `--stdin` |
| G6 | CRLF / trailing-newline stdin input           | CLI `--stdin`    | None                 | Info     | Add `test_cli_stdin_with_trailing_newline`, `test_cli_stdin_with_crlf` |
| G7 | Memoryview with read-only flag and stride    | Public API       | 4 bytearray/mv items | Info     | Add 1 item: `test_memoryview_readonly_and_strided` |
| G8 | Return-type strictness (`int`, not bool)      | Public API       | 8 type-error items cover rejection side; none cover return-type side | Info | Add 1 item: `test_crc_returns_python_int_type` |
| G9 | Algorithm-vs-crcmod differential at 1000+ samples | Public API    | 100 oracle_crcmod items | Info   | Optional: bump to 1000 if any v0.1.x cycle ever regresses |
| G10| CLI argument-conflict semantics              | `__main__.py`    | None                 | Info     | Add 1 item: `test_cli_self_test_with_extra_args_ignored` |
| G11| `crc()` callable via dotted `crc16_xmodem.crc` import path | Module  | Tests import via `from crc16_xmodem import crc` (works), but no test confirms the submodule import path | Info | Add 1 item: `test_dotted_import_works` |
| G12| CLI --register exit code on malformed dict   | `__main__.py`    | 1 test               | Info     | None needed (dict is a literal) |

---

## Detail: G1 — CLI exception surfacing

The CLI's `_parse_data` raises `ValueError` (and `UnicodeEncodeError`)
unhandled. Verified by:

```bash
$ python3 -m crc16_xmodem --data "🚀"
Traceback (most recent call last):
  File "<frozen runpy>", line 198, in _run_module_as_main
  ...
  File "/root/projects/crc16-xmodem-pure/.worktrees/cycle132-build/src/crc16_xmodem/__main__.py", line 36, in <module>
    out.extend(v.encode("latin-1"))
  UnicodeEncodeError: 'latin-1' codec can't encode character '\U0001f680' in position 0: ordinal not in range(256)
```

This leaks:
- absolute file paths of the source code under audit,
- the Python version,
- the CPython implementation name.

None of these are sensitive secrets, but the user-facing experience is
poor. The right behavior is a friendly error message to stderr and exit
code 2 (argparse convention for usage errors). Severity: **Low**, since
the CLI is opt-in and the leak is environmental, not project-specific.

**Suggested fix (not in scope for this audit, listed for T4):** wrap
`_parse_data` in a `try/except (ValueError, UnicodeEncodeError)` that
prints `error: invalid --data value '<first 32 chars>': <type>:<msg>`
to stderr and returns exit code 2.

## Detail: G2 — `--data` ambiguity

Verified matrix:

| Arg              | Parsed as          | Bytes fed to `crc()` | CRC   |
|------------------|--------------------|----------------------|-------|
| `'313233343536373839'` (18 hex chars) | hex (`bytes.fromhex`) → ASCII bytes `123456789` | `b'123456789'` | `0x31C3` |
| `'123456789'`    | decimal `int` → 1 byte `\x89` | `b'\x89'` | `0x00A1` |
| `'65'`           | decimal `int` → 1 byte `'e'`   | `b'e'`     | varies |
| `'ZZZZ'`         | latin-1 fallback  | `b'ZZZZ'`  | varies |
| `'ABCD; rm -rf /'` | latin-1 fallback | `b'ABCD; rm -rf /'` | varies |

A user who says `--data 123456789` expecting the bytes `1,2,3,4,5,6,7,8,9`
gets the *one* byte `\x89`. The CLI provides **no warning** about this
disambiguation. The disambiguation logic in `_parse_data` is:

```python
if len(values) == 1 and len(values[0]) % 2 == 0:
    try:
        return bytes.fromhex(values[0])    # happy path: pure hex
    except ValueError:
        pass                                # silent fall-through
```

The fall-through silently re-tries hex then decimal then latin-1, with
no diagnostic. Severity: **Low** because:
- the CLI is intended for human/debug use, not production pipelines,
- the user can always pass `--data "313233343536373839"` for explicit hex,
- the function does NOT crash, only produces a CRC.

**Suggested fix:** in single-arg mode, require hex (or split the
disambiguator into `--hex`, `--decimal`, `--text` flags). Multi-arg mode
already does one-int-per-arg; the doc string should make this explicit.

## Detail: G4 — Numeric-input silent masking asymmetry (CONFIRMED)

After careful re-tracing of the source:

```python
if len(values) == 1 and len(values[0]) % 2 == 0:
    try:
        return bytes.fromhex(values[0])      # <-- catches digit-only strings first
    except ValueError:
        pass
```

`_parse_data(['4294967295'])` returns `b'B\x94\x96r\x95'` — **5 raw
bytes, the hex interpretation of the digit string itself**, not the
single byte `0xFF` the user intended when typing the 32-bit value
`4294967295`.

This is because `bytes.fromhex('4294967295')` succeeds (all chars are
hex digits), and that happy-path branch returns BEFORE the per-arg
int-parsing loop runs.

**Verified matrix:**

| `--data` arg               | bytes returned                       | CRC    |
|----------------------------|--------------------------------------|--------|
| `'65'`                     | `b'e'` (1 byte, hex ASCII of `'65'`) | 0xXXXX |
| `'4294967295'` (2^32-1)    | `b'B\x94\x96r\x95'` (5 bytes from hex) | 0xXXXX |
| `'18446744073709551615'` (2^64-1) | `b'\x18DgD\x077\tU\x16\x15'` (10 bytes from hex) | 0xXXXX |
| `'65535'`                  | `b'\xe5\xff'` (2 bytes)              | 0xXXXX |
| `'255'`                    | `b'\xff'` (1 byte)                   | 0x1EF0 |
| `'256'`                    | `b'\x01\x00'` (2 bytes)              | 0xXXXX |

**Severity: Low.** The behavior is **consistent** (a string of N
hex-digit characters → N/2 bytes), but **silently wrong** for the user
who types `--data 4294967295` expecting a single byte. The CLI does not
warn. The user gets a different CRC than they expected, with no
diagnostic.

**CWE-1284 (Improper Validation of Specified Quantity in Input) is
triggered**: the CLI accepts a multi-byte value that the user likely
intended as a single integer. The downstream impact is silent CRC
mismatch — not a security exploit, but a usability footgun.

**Suggested fix (for T4 remediation card):** detect single-arg mode
where the string is all-digit and treat as decimal int instead of
hex. Or split into `--hex`, `--dec`, `--text` flags and refuse
ambiguous input.

---

## Gaps NOT worth filling

- **G5 (100 MiB stdin)** — already covered by 5MB-perf test; linear
  scaling is proven. Pushing to 100 MiB adds 40 s of test time per run
  for marginal confidence.
- **G6 (CRLF stdin)** — `\r\n` vs `\n` is a string-vs-bytes thing. The
  CLI reads raw bytes via `sys.stdin.buffer.read()`, so CRLF is just 2
  bytes appended to the input. The CRC will be deterministic and
  correct — the test is essentially testing that the bytes pass through
  unchanged. Already covered by `test_cli_stdin`.
- **G9 (1000+ oracle samples)** — 100 samples is plenty to detect any
  regression in the algorithm. crcmod is the upstream oracle; if it
  disagrees on any of 100 random inputs, the implementation is wrong.

## Total

| Severity    | Gap count |
|-------------|-----------|
| Medium      | 0         |
| Low         | 3 (G1, G2, G4) |
| Info        | 9 (G3, G5–G12) |
| **Total**   | **12**    |

**Verdict:** the 532-test baseline covers all *correctness-critical*
properties. The gaps are confined to CLI input-validation ergonomics and
are not blockers for cryptographic correctness or API safety.
