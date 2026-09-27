# THREAT_MODEL.md — Attacker model and worst-case impact

> **Cycle:** 132
> **Repo:** `crc16-xmodem-pure` (commit 6071f9c)
> **Date:** 2026-09-27

This document enumerates plausible attacker models for a pure-Python
CRC-16/XMODEM reference implementation, identifies the worst-case
impact in each model, and rates the realistic exploitability of the
findings recorded in `VULN_AUDIT.md`.

---

## T0 — What this package is

`crc16-xmodem-pure` is a **pure-Python, zero-dependency** implementation
of the CRC-16/XMODEM algorithm. Its public API consists of two
functions:

- `crc(data) -> int` — compute the 16-bit CRC over bytes-like input.
- `register() -> dict` — return the RevEng parameter table.

The CLI (`crc16-xmodem`) wraps these for command-line use. Total
runtime LOC: ~25 (algorithm) + ~40 (CLI).

CRC-16/XMODEM is a **non-cryptographic** error-detecting code. It is
suitable for catching accidental bit-flips in transit (XMODEM file
transfer, MODEM7/YMODEM/ZMODEM families), but **is not suitable for
authentication or tamper detection** (see SPEC §6 — "NOT
cryptographic"). The threat model below respects that boundary.

---

## T1 — Attacker models

### T1.1 — Honest user with a typo
**Description:** A developer copy-pastes or hand-types a CLI invocation
like `--data 123456789`, expecting either 9 bytes `[1,2,3,4,5,6,7,8,9]`
or 9 ASCII hex bytes. Instead, the CLI silently interprets the string
either as the bytes `\x89` (single-byte decimal 123456789) or as 5 raw
bytes (single-arg hex interpretation). The CRC produced is **wrong for
their intent**.

- **Worst-case impact:** silent corruption of a file checksum; an
  XMODEM-CRC receiver rejects every legitimate sender (because the
  sender's CRC matches the input bytes but the receiver's CRC matches
  the disambiguated interpretation). Field symptoms are the same as
  the SPEC §1 failure scenario ("no YMODEM batches decoded").
- **Attack vector:** none — this is purely user error, not adversarial.
- **Severity:** Low (operational, not security).
- **Affected surface:** CLI `--data` only.
- **Mitigation:** SPEC §6 disclaims throughput / single-utility scope;
  the README explicitly tells users to use `crcmod` for production.
  The CLI doc string could be improved, but the algorithm itself is
  correct.

### T1.2 — Malicious input fed to the CLI by a script
**Description:** A shell pipeline or CI step invokes `crc16-xmodem
--stdin < untrusted_file` where `untrusted_file` contains up to
multiple GiB of attacker-controlled bytes.

- **Worst-case impact:** the CLI reads all bytes via
  `sys.stdin.buffer.read()`, allocates one Python `bytes` object,
  iterates over it. Measured throughput: 2.7 MB/s → 6+ minutes for
  1 GiB. CPU-bound, no network egress, no subprocess spawn. Memory
  ceiling = input size + Python overhead (~3×). A 100 GiB input would
  OOM a typical container before the process completes.
- **Attack vector:** DoS via resource exhaustion (CWE-400). Requires
  the attacker to control a pipe / file that the victim CLI reads.
- **Severity:** Low. The package is single-purpose, opt-in, and has no
  network listening surface. DoS requires local write access to the
  pipe/file. The 532-test suite includes a 5 MiB linear-time test that
  proves O(N) scaling.
- **Mitigation:** none required. If a deployment ingests untrusted
  input, it should wrap the CLI in a `timeout`/`ulimit` shell guard,
  not rely on the library to self-throttle.

### T1.3 — Crafted input fed to the Python API directly
**Description:** An attacker calls `crc(bad_input)` from Python code
where `bad_input` is something pathological (non-bytes-like, a
generator, a custom object, a file handle, etc.).

- **Verified behavior:** `crc(None)` raises `TypeError("crc16_xmodem.crc()
  expected bytes-like, got NoneType")` with NO stack trace and NO
  side effect. Verified for `None`, `str`, `int`, `float`, `bool`,
  `list`, `tuple`, `dict`, `set`, `frozenset`, `object()`, and arbitrary
  iterables (e.g. `FakeBytes` class with `__iter__`/`__len__`). All
  reject with `TypeError` cleanly.
- **Worst-case impact:** None. The `isinstance` guard at line 19 of
  `_crc16_xmodem.py` short-circuits before any iteration.
- **Attack vector:** none.
- **Severity:** None.

### T1.4 — Unicode / encoding attack on CLI `--data`
**Description:** A user invokes `crc16-xmodem --data "🚀"` or `--data
"0xZZ"`. The CLI's `_parse_data` raises `UnicodeEncodeError` or
`ValueError` that propagates unhandled.

- **Verified behavior:** the Python interpreter prints a full
  traceback including:
  - Absolute source paths under `/root/projects/crc16-xmodem-pure/.worktrees/cycle132-build/src/...`
  - The Python version
  - The CPython implementation name
  - The exact `int()` / `fromhex()` / `encode()` call that failed
- **Worst-case impact:** information disclosure (CWE-209). The leaked
  paths are not secrets (anyone with `ls` access can see them), but the
  traceback is unsightly and could mislead a less-technical user into
  thinking the package is broken.
- **Attack vector:** trick a user into pasting a Unicode emoji or
  malformed hex into a CLI invocation. Social engineering, low effort.
- **Severity:** Low. No exploitation of the disclosed information is
  documented. The fix is cosmetic (catch and pretty-print).
- **Mitigation:** wrap `_parse_data` in a `try/except` that emits a
  friendly stderr message and exits 2.

### T1.5 — Algorithmic confusion with sibling 16-bit CRCs
**Description:** A user copy-pastes a CRC-16/XMODEM snippet from
StackOverflow and accidentally picks the CRC-CCITT-FALSE variant
(same polynomial 0x1021, but init=0xFFFF, xorout=0x0000 — same
xorout but different init) or CRC-MODBUS (poly=0x8005, refin=true).

- **Verified disambiguation:** the canonical RevEng check value is
  `0x31C3` for `crc(b"123456789")`. CCITT-FALSE would give `0x29B1`,
  MODBUS would give `0x4B37`. The 532-test suite explicitly asserts
  the XMODEM value AND the negative case (cycle_132/qa confirms
  cross-cycle disambiguation against MODBUS and CCITT-FALSE).
- **Worst-case impact:** the package, as shipped, is correct. The
  disambiguation concern is about **users who confuse algorithms**,
  not about the library producing wrong CRCs.
- **Severity:** None for the library; user-error-mitigated via SPEC
  §1's "concrete workflow today" narrative and the README's
  parameter-table printout via `--register`.

### T1.6 — Supply-chain attack via runtime dependencies
**Description:** A malicious package is uploaded to PyPI and a
dependency-update tool pulls it in transitively.

- **Mitigation in place:** `pyproject.toml` line 11: `dependencies = []`.
  Zero runtime dependencies means zero attack surface. Verified by QA
  in cycle_132.
- **Severity:** None.

### T1.7 — Tampering with the package itself
**Description:** A malicious actor modifies the source after release,
or substitutes a backdoored package on PyPI / GitHub.

- **Mitigation in place:** package is published only via `pip install
  git+https://github.com/prasad-a-abhishek/crc16-xmodem.git` (per
  Invariant 9 — not on PyPI). Source is auditable, ~25 LOC of
  algorithm. Bit-exact match against `crcmod`'s
  `mkPredefinedCrcFun('xmodem')` is verified on every QA run.
- **Severity:** Low (typical supply-chain risk for any small library).
  Out of scope for this audit.

---

## T2 — Worst-case aggregate impact

The most damaging plausible scenario combining T1.1 + T1.4:

1. An operations engineer sets up a CI step that ingests firmware
   updates via XMODEM-CRC and computes the per-block CRC with the
   `crc16-xmodem` CLI.
2. They pass the block contents via `--data "$hex_of_block"` where
   `$hex_of_block` is sometimes an odd number of characters (a real
   possibility if the firmware toolchain strips leading zeros).
3. The CLI silently interprets the hex string as multiple bytes
   (single-arg even-length happy path) or rejects (odd-length falls
   through to the int-parsing loop).
4. The CI step emits a CRC that does NOT match the firmware's
   embedded CRC. The firmware appears "bad", the field deployment
   is blocked, engineering escalates.

**No exploit. No data exfiltration. No privilege escalation. Just
operational confusion from silent input disambiguation.**

This is consistent with SPEC §6 ("NOT a streaming API", "NOT
optimized for speed") — the package is positioned as a reference, not
as a production wire-format codec. Users with high-reliability needs
are pointed at `crcmod`.

---

## T3 — Out-of-scope concerns (acknowledged but not addressed here)

- **Active-bit-flip detection.** A CRC-16 has 65,536 possible outputs;
  any 16-bit CRC has a 1/65,536 chance of a random error passing. Use
  a longer CRC for higher coverage. Out of scope for the library.
- **Side-channel analysis (timing).** The CRC loop is data-dependent
  only in the inner XOR/shift branch; both branches take constant
  time (no memory access, no multiplication, no division). A skilled
  attacker with a timing oracle could in principle distinguish
  branches, but for CRC input (which is meant to be public) this is
  not exploitable.
- **Quantum-computer resistance.** N/A; CRC is not cryptography.

---

## T4 — Realistic summary

| Attacker model | Realistic? | Worst-case impact                  | Library mitigates? |
|----------------|------------|------------------------------------|--------------------|
| Honest user typo (T1.1)   | High | Operational confusion       | Partially (SPEC, README); CLI footgun |
| Untrusted CLI input (T1.2) | Medium | DoS / OOM                  | Yes (O(N), no network) |
| Bad Python API input (T1.3) | High | None                       | Yes (`isinstance` guard) |
| Unicode CLI attack (T1.4) | Low  | Information disclosure      | No (cosmetic issue) |
| Algorithmic confusion (T1.5) | High | Wrong CRC                | Yes (parameters pinned, tests) |
| Supply chain (T1.6)       | Medium | Backdoor                  | Yes (zero deps) |
| Tampering (T1.7)          | Medium | Backdoor                  | Yes (auditable LOC) |

**Overall:** the library is robust against all realistic attacks
against a CRC reference implementation. The remaining findings (CLI
input ergonomics) are **operational, not security** — they cause
incorrect CRCs through user misunderstanding, not through any
attacker-controlled mechanism. Severity ceiling across the audit is
**Low**.
