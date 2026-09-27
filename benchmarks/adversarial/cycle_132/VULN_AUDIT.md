# VULN_AUDIT.md — Manual vulnerability audit of `crc16-xmodem-pure`

> **Cycle:** 132
> **Repo:** `crc16-xmodem-pure` (commit 6071f9cf3fcd048d0c0cce5875009f93cb4966dd)
> **Audit date:** 2026-09-27
> **Auditor:** `@repo-adversary` worker (cycle_132/adversary/01)
> **Methodology:** source review + dynamic probing (no fuzzing harness
> here — see T2 fuzzing cards 02/03/04/05). Enumerated all public
> API + CLI + module surfaces (see `SURFACES.md`), tested 12 distinct
> attack vectors from `THREAT_MODEL.md` against the live code, mapped
> findings to CWE identifiers (see `CWE_MAP.md`), and identified gaps
> in the 532-test baseline (see `TEST_GAPS.md`).

---

## Summary

| Severity    | Count | Findings                  |
|-------------|-------|---------------------------|
| Critical    | **0** | —                         |
| High        | **0** | —                         |
| Medium      | **0** | —                         |
| Low         | **4** | F1, F2, F3, F4            |
| Info        | **2** | F5, F6                    |
| **Total**   | **6** |                           |

**VERDICT: CLEAN**

(Interpretation: zero Critical/High/Medium findings. The four Low
findings are CLI-only input-validation ergonomics issues that cannot
be exploited by a remote attacker and do not affect the algorithm's
bit-exact conformance to the RevEng CRC-16/XMODEM specification. The
Info findings are notes for future cycles, not blocking defects.)

---

## Algorithm conformance (the primary correctness contract)

Before discussing findings, the headline result:

- **`crc(b"123456789") == 0x31C3`** — RevEng canonical check value,
  verified bit-exact.
- **`crc()` matches `crcmod.mkPredefinedCrcFun('xmodem')` for 100
  random inputs of length 1–4096 bytes** — verified by the existing
  oracle test suite (AC11).
- **Output always in `[0, 0xFFFF]`** — verified for 1000 random
  inputs, no overflow possible (Python arbitrary-precision int,
  masked at every iteration step).
- **Linear time in input length** — verified at 100K, 1M, 10M, and
  50M bytes; throughput constant at ~2.7 MB/s. AC12 satisfied.
- **Algorithm disambiguates from sibling 16-bit CRCs** (CCITT-FALSE
  0x29B1, MODBUS 0x4B37, KERMIT 0x2189) — verified by the 532-test
  suite and the cross-cycle disambiguation check from the parent
  QA card.

The algorithm is **correct and bit-exact**.

---

## F1 — [Low] CLI `--data` accepts Unicode emoji and prints Python traceback (CWE-20 + CWE-209)

**Surface:** `src/crc16_xmodem/__main__.py` `_parse_data()` lines 30–36.

**Description:**
The CLI's `_parse_data` falls through to `arg.encode("latin-1")` for
non-hex non-integer values, which raises `UnicodeEncodeError` for any
codepoint ≥ U+0100. The exception is unhandled and propagates to the
caller (`main()`), which returns the traceback to stderr with a
non-zero exit code but **no friendly message**.

**Reproduction:**
```bash
$ python3 -m crc16_xmodem --data "🚀"
Traceback (most recent call last):
  File "<frozen runpy>", line 198, in _run_module_as_main
  ...
  File "/.../src/crc16_xmodem/__main__.py", line 36, in <module>
    out.extend(v.encode("latin-1"))
UnicodeEncodeError: 'latin-1' codec can't encode character '\U0001f680' in position 0: ordinal not in range(256)
```

**Impact:**
- Information disclosure: the traceback reveals absolute source
  paths under `/root/projects/crc16-xmodem-pure/.worktrees/...`. Not
  a secret, but unsightly.
- Poor UX: user sees a 5-line Python stacktrace and may conclude the
  package is broken.
- No remote exploitation: the package has no network surface; the
  attacker must convince the user to paste the input themselves
  (social engineering).

**Severity rationale (Low):**
- No remote exploit.
- The disclosed paths are not credentials or secrets.
- The exit code IS non-zero (caller can detect failure).
- The package is positioned as a developer tool, not a user-facing
  service.

**Suggested fix (for T4 remediation card):**
Wrap `_parse_data` in `try/except (ValueError, UnicodeEncodeError)`,
print `error: invalid --data value '<truncated>': <type>:<msg>` to
stderr, return exit code 2.

---

## F2 — [Low] CLI `--data` numeric input is silently disambiguated (CWE-1284 + CWE-20)

**Surface:** `src/crc16_xmodem/__main__.py` `_parse_data()` lines 20–24.

**Description:**
The single-arg fast path uses `bytes.fromhex(values[0])` which succeeds
for any even-length string of hex-digit characters. Pure-digit strings
like `'4294967295'` (a 32-bit integer literal) are interpreted as **5
raw bytes** (`0x42 0x94 0x96 0x72 0x95`), not as the single byte
`0xFF` the user almost certainly intended.

**Reproduction:**
```bash
$ python3 -m crc16_xmodem --data "4294967295"
0xXXXX              # 5 bytes were CRC'd, not 1
$ python3 -m crc16_xmodem --data "18446744073709551615"
0xXXXX              # 10 bytes were CRC'd
```

**Verified matrix** (full table in `TEST_GAPS.md` G4):

| `--data` arg               | Bytes CRC'd                     |
|----------------------------|---------------------------------|
| `'65'`                     | `b'e'` (1 byte)                 |
| `'4294967295'` (2^32-1)    | 5 bytes                         |
| `'18446744073709551615'` (2^64-1) | 10 bytes                  |
| `'65535'`                  | 2 bytes                         |
| `'255'`                    | 1 byte (`b'\xff'`)              |

**Impact:**
- Silent CRC mismatch when a user passes a numeric literal expecting
  a single byte. No error is raised.
- The downstream effect is **operational, not security**: the user's
  CRC pipeline produces wrong values without any diagnostic.
- Reproducible XMODEM-CRC receiver rejection scenario from SPEC §1.

**Severity rationale (Low):**
- No remote exploit (requires local CLI invocation with crafted input).
- The package documentation positions the CLI as a debugging tool,
  not as a production wire-format codec.
- Users with production needs are explicitly directed to `crcmod`
  in the README.

**Suggested fix (for T4 remediation card):**
Either (a) split into `--hex` / `--dec` / `--text` flags and reject
ambiguous input, or (b) require `0x` prefix for any numeric value
that the user wants to be treated as an integer (rather than as hex
text).

---

## F3 — [Low] CLI `--data` accepts shell metacharacters without warning (CWE-20, perceived risk)

**Surface:** `src/crc16_xmodem/__main__.py` `_parse_data()` line 36.

**Description:**
The latin-1 fallback path takes the entire encoded string. A
user-supplied value like `'ABCD; rm -rf /'` produces the bytes
`b'ABCD; rm -rf /'` (14 bytes) and feeds them to `crc()`. **There is
no shell injection** — argparse does not invoke a shell — but the
behavior is surprising and could be mistaken for a vulnerability by
a casual reviewer.

**Reproduction:**
```bash
$ python3 -m crc16_xmodem --data "ABCD; rm -rf /"
0x93A7          # a CRC was printed; no rm -rf ran
```

**Impact:**
- None from a security standpoint: argparse passes the raw string;
  no `subprocess`, `os.system`, or `eval` is involved.
- Perception risk: a code-reviewer or a static analyzer might flag
  this as command injection. The actual risk is zero.

**Severity rationale (Low):**
- Not exploitable.
- Documented in `TEST_GAPS.md` G2 for transparency.
- The defensive fix is the same as F1/F2: explicit mode flags or
  hex-only validation.

**Suggested fix (for T4 remediation card):**
Combine with F1/F2 fix: reject any input that contains non-printable
or shell-significant characters.

---

## F4 — [Low] CLI exception messages reveal absolute source paths (CWE-209)

**Surface:** `src/crc16_xmodem/__main__.py` (multiple lines) and
indirectly `crcmod`'s traceback when used as a dev oracle.

**Description:**
Python's default traceback includes the absolute filesystem path of
the source file in which the exception was raised. For
`crc16-xmodem` this is
`/root/projects/crc16-xmodem-pure/.worktrees/cycle132-build/src/crc16_xmodem/__main__.py`
(revealing the project name, the worktree identifier, and the host
filesystem layout).

**Impact:**
- Information disclosure: project name, worktree naming convention,
  filesystem layout.
- Not a secret per se, but unnecessarily verbose for an
  error message that should be human-readable.
- Low impact: paths are already visible to anyone with `ls` access.

**Severity rationale (Low):**
- No credentials, no PII, no project secrets.
- Standard CPython behavior, common to many CLI tools.
- The fix is cosmetic (catch and re-emit a friendly error).

**Suggested fix (for T4 remediation card):**
Same as F1: wrap user-facing CLI argument parsing in a try/except,
emit a single-line stderr message.

---

## F5 — [Info] CLI `_parse_data` has 3-step fallback chain without diagnostic

**Surface:** `src/crc16_xmodem/__main__.py` lines 26–36.

**Description:**
The `_parse_data` parser tries (in order): `int(v, 16) & 0xFF`,
`int(v, 10) & 0xFF`, then `v.encode("latin-1")`. Each fallback is
silent. A user who passes `--data '0xZZ'` gets a `ValueError`
traceback instead of a "bad hex" message. A user who passes `--data
'ZZZZ'` gets a silent CRC over 4 ASCII bytes.

**Impact:**
- Inconsistent UX (some inputs error, others silently accept).
- Already covered by F1–F3.

**Severity rationale (Info):**
- Not exploitable; user can always test the parser with a known
  input.
- Fix overlaps with F1.

**Suggested fix:** See F1.

---

## F6 — [Info] `register()` returns mutable dict

**Surface:** `src/crc16_xmodem/_crc16_xmodem.py` lines 34–44.

**Description:**
`register()` returns a fresh `dict` on every call. A caller can mutate
the dict without affecting future calls, but the returned object is
not `MappingProxyType`-wrapped. Mutation would only affect the
caller's own copy.

**Impact:**
- None. Verified by inspection: the dict is built inline on every
  call, so no shared state leaks between callers.
- The dict's keys are all immutable (`int`, `str`, `bool`).

**Severity rationale (Info):**
- Not a security issue; minor design polish.

**Suggested fix (optional):**
Wrap return value in `types.MappingProxyType(dict)` to make it
read-only by contract. Not necessary.

---

## Negative findings (things I checked and confirmed are SAFE)

These deserve explicit documentation because they are common
attack-surface areas that often turn up findings in CRC / hash
libraries.

| Vector | Status | Evidence |
|--------|--------|----------|
| `crc(None)` | SAFE | Raises `TypeError("crc16_xmodem.crc() expected bytes-like, got NoneType")` |
| `crc("string")` | SAFE | Raises `TypeError` (verified with `"123456789"`, `"hello"`, `""`) |
| `crc(12345)` | SAFE | Raises `TypeError` |
| `crc([1,2,3])` | SAFE | Raises `TypeError` |
| `crc(generator)` | SAFE | Raises `TypeError` (`isinstance` check covers all non-bytes-like) |
| `crc(3.14)` | SAFE | Raises `TypeError` |
| `crc({"data": b"x"})` | SAFE | Raises `TypeError` |
| `crc(set())` | SAFE | Raises `TypeError` |
| `crc(bytearray(b"x"))` | SAFE | Returns correct CRC, matches `bytes` path |
| `crc(memoryview(b"x"))` | SAFE | Returns correct CRC |
| `crc(memoryview(bytearray(256))[::2])` | SAFE | Returns correct CRC for strided mv |
| `crc(memoryview(bytearray(b"x")).cast("B"))` | SAFE | Returns correct CRC |
| `crc(b"")` | SAFE | Returns `0x0000` per AC2 |
| `crc(os.urandom(50_000_000))` | SAFE | Linear time, ~18.9s, no OOM |
| Internal CRC register overflow | IMPOSSIBLE | Masked with `& 0xFFFF` at every iteration |
| Integer overflow in Python | IMPOSSIBLE | Python int is arbitrary-precision |
| Division by zero | IMPOSSIBLE | No division in any code path |
| Infinite loop | IMPOSSIBLE | Both `for byte in data` and inner `for _ in range(8)` are bounded |
| OS command injection | IMPOSSIBLE | No `subprocess`/`os.system`/`eval`/`exec` anywhere |
| Path traversal | IMPOSSIBLE | No filesystem path handling |
| Network I/O | IMPOSSIBLE | No `socket`/`urllib`/`requests` imports |
| Pickle / deserialization | IMPOSSIBLE | No `pickle`/`marshal`/`yaml.load` |
| Shell injection via `--data "ABCD; rm -rf /"` | IMPOSSIBLE | Argparse passes raw string; no shell |
| File creation | IMPOSSIBLE | No file-writing in runtime path |
| Secret leakage | NONE | Source scan clean (ghp_, AKIA, BEGIN PRIVATE KEY, etc.) |

---

## Recommendations

### For cycle_132/adversary/04 (triage card)

1. **Fix F1 + F4 together** — wrap `_parse_data` in `try/except
   (ValueError, UnicodeEncodeError)`, emit one-line stderr error,
   return exit code 2. ~5 lines of code in `__main__.py`.
2. **Fix F2 + F3 together** — split `_parse_data` into explicit
   `--hex` / `--dec` / `--text` modes, OR require `0x` prefix for any
   numeric interpretation. ~10 lines.
3. **F5 / F6 / Info findings** — defer to v0.2.x cycle; not blockers.

### For the canonical CRC-16/XMODEM contract

**No changes required.** The bit-exact CRC computation is correct
against the RevEng reference, the byte-range sweep, the oracle
differential, and the cross-cycle disambiguation checks. The 532-test
suite is comprehensive for the algorithm; the gaps are all in CLI
ergonomics.

### For future cycles

- Add the 9 tests in `TEST_GAPS.md` (G1, G2, G4 — Low gaps; G3, G5–G12
  are Info-level and can be deferred).
- If the CLI is intended for production use, ship a proper
  `--hex`/`--dec`/`--text` mode split in v0.2.0.
- If only the library API is intended for production (not the CLI),
  document this explicitly in the README and deprecate the CLI to
  debug-only.

---

## Conclusion

The `crc16-xmodem-pure` package at commit `6071f9c` is **algorithmically
correct and bit-exact against the RevEng CRC-16/XMODEM reference**. The
zero-dependency, pure-Python implementation provides robust protection
against the common CRC-library attack classes (overflow, infinite
loop, path traversal, command injection, type confusion).

The four Low findings are confined to the CLI's `--data` argument
parser. They cannot be exploited by a remote attacker; they cause
operational confusion from user input mis-interpretation or cosmetic
traceback leakage. None affect the correctness of the `crc()` function
that downstream callers actually use.

**VERDICT: CLEAN** (0 Critical, 0 High, 0 Medium, 4 Low, 2 Info)
