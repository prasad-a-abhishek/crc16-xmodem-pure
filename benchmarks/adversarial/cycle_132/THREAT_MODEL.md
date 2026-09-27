# THREAT_MODEL — crc16-xmodem attacker model and worst-case impact

> Cycle 132 / T1 VULN_AUDIT — narrative threat model for `crc16-xmodem` @ 6071f9c.
>
> Source: `SURFACES.md` (4 surfaces), `CWE_MAP.md` (45 CWEs considered),
> probe script `/tmp/adv_probes.py`.

## TM1 — System context

`crc16-xmodem` is a pure-Python CRC-16/XMODEM reference implementation
(Ward Christensen 1977 XMODEM file-transfer protocol). The package is:

- **Offline only.** No network code. No HTTP client. No socket. No DNS.
- **Filesystem-free at runtime.** No file reads/writes outside of pip's
  one-time install hooks (which run as the installing user, not as the
  CRC-computing process).
- **Zero runtime dependencies.** No third-party packages linked at install
  or runtime.
- **Stateless.** No global mutable state. Multiple threads / processes can
  call `crc()` concurrently without any data race.

The deployment surface is:
1. **Library API** — `from crc16_xmodem import crc` in a Python process.
2. **CLI** — `python3 -m crc16_xmodem [--data | --stdin | --self-test | --register]`.
3. **Console script** — `crc16-xmodem` (same code path as the CLI).

## TM2 — Attacker model

There are three plausible attacker profiles. Each is evaluated against the
attack surface and given a worst-case impact rating.

### TM2.1 — Attacker controls the input bytes (`crc(attacker_bytes)`)

**Capability:** Full control over the `data` argument to `crc()`.
**Constraints:** Cannot control the algorithm constants (no `init`/`poly`/`refin`
parameters exist on the public API — only the fixed `register()` exposes them
read-only).
**Goal:** Cause denial of service, memory exhaustion, integer overflow,
algorithmic confusion, or uncaught exceptions that crash the host process.

**Worst-case impact assessment:**

| Attack | Feasible? | Impact |
|---|---|---|
| Cause OOM via multi-GB input | Yes (caller controls size) | Low — Python OOM raises `MemoryError`, not a crash-vuln. Documented Python behavior. |
| Cause quadratic blowup | No — algorithm is `O(8 * len(data))` per byte. Probe VULN-3 confirms 50 MiB in 33s linear scaling. | None |
| Cause infinite loop | No — both inner loops have fixed iteration counts. Probe VULN-3 + VULN-12 confirm termination. | None |
| Cause integer overflow | No — Python ints are arbitrary precision; `& 0xFFFF` masks the result to 16 bits regardless. Probe VULN-11 confirms 1000 random inputs all in `[0, 65536)`. | None |
| Cause TypeError crash | Yes — but TypeError is a documented, clean exception, not a vulnerability. Probe VULN-1 covers 10 invalid types. | None (clean) |
| Cause the result to exceed 16 bits | No — `& 0xFFFF` mask at every shift and XOR. Probe VULN-11 confirms. | None |
| Cause confusion with a sibling CRC | No — algorithm constants are hard-coded in module; `register()` returns the constants but caller cannot inject them. Probe VULN-8 confirms RevEng byte-exact match. | None |

**Verdict for TM2.1:** No exploitable vulnerabilities. Maximum impact is a
TypeError from the caller's own misuse (raising is the safe, correct behavior).

### TM2.2 — Attacker controls CLI arguments (`python3 -m crc16_xmodem --data <attacker>`)

**Capability:** Full control over the `--data` positional argument list.
**Constraints:** Argparse does NOT pass values to a shell. The values flow
through `_parse_data()` which only does hex/int/latin-1 decoding.
**Goal:** Achieve shell injection, file system damage, arbitrary code execution,
or denial of service via the CLI.

**Worst-case impact assessment:**

| Attack | Feasible? | Impact |
|---|---|---|
| Shell injection via `; rm -rf /` | No — argparse + Python never invokes a shell. Probe VULN-6 confirms the literal string is latin-1 encoded to bytes and CRC'd. | None |
| Command substitution `$(whoami)`, `` `id` `` | No — same as above. | None |
| Path traversal via `--data ../../etc/passwd` | No — values are never used as file paths. | None |
| Eval injection | No — no `eval()` in code. | None |
| Resource exhaustion via massive `--data` list | Yes — caller controls the list length. Each arg produces 1 byte, so 10M args = 10MB in memory. Linear, not exponential. | Low — bounded by attacker's CLI argv size (typically 128 KiB on Linux). |
| Cause uncaught exception / raw traceback | Yes — `0xZZ` raises uncaught `ValueError`. Probe VULN-6 confirms. | Low — leaks install path; no secrets. **Finding F-1.** |

**Verdict for TM2.2:** One Low finding (F-1: uncaught `ValueError` on malformed
`0x`-prefixed `--data`). Trivially fixable in `_parse_data()` by wrapping the
`int(v, 16)` call in a `try/except ValueError` that raises `SystemExit` with
a clean error message.

### TM2.3 — Attacker controls stdin bytes (`echo attacker | crc16-xmodem --stdin`)

**Capability:** Full control over the bytes piped to stdin.
**Constraints:** CLI reads `sys.stdin.buffer.read()` into memory; caller
controls how much they pipe.
**Goal:** Cause OOM, infinite loop, wrong CRC result, or uncaught exception.

**Worst-case impact assessment:**

| Attack | Feasible? | Impact |
|---|---|---|
| OOM via multi-GB pipe | Yes (caller controls size) | Low — `MemoryError` raised, not a crash-vuln. Documented behavior. |
| CRLF injection / unicode confusion | No — probe VULN-5 confirms CLI and API agree on all 7 stdin cases (CRLF, LF, multi-LF, non-ASCII, 0..255 sweep, empty). | None |
| Cause the CLI to print a different CRC than the API | No — probe VULN-5 confirms `cli_out == f"0x{crc(inp):04X}".encode()` for all 7 cases. | None |
| Cause uncaught exception on malformed stdin | No — `sys.stdin.buffer.read()` is binary-safe; no decoding is attempted. | None |

**Verdict for TM2.3:** No exploitable vulnerabilities. stdin handling is binary-clean.

## TM3 — Non-attacker failure modes (operator-induced)

These are not "vulnerabilities" but document how the package fails when used
incorrectly.

| Misuse | Failure mode | Probe evidence |
|---|---|---|
| `crc(12345)` (int) | `TypeError: expected bytes-like, got int` | VULN-1 |
| `crc(b"")` (empty) | Returns `0x0000` (no exception) | VULN-3 |
| `crc(b"\x00" * 1_000_000)` (1 MB) | Returns CRC, takes ~470 ms | VULN-3 |
| `crc(memoryview(buf))` then mutate `buf` then `crc(memoryview(buf))` | Second call sees mutated bytes (live view semantics) | VULN-10 |
| `python3 -m crc16_xmodem --data 0xZZ` | Uncaught `ValueError`, raw traceback to stderr | VULN-6 (Finding F-1) |
| `python3 -m crc16_xmodem --data "; rm -rf /"` | Silent CRC over the literal 9-byte latin-1 string | VULN-6 |
| `python3 -m crc16_xmodem --stdin < 10 GiB file` | OOM or long blocking read, depending on RAM | Documented Python behavior |
| Use CRC-16/XMODEM for adversarial integrity protection | Trivially forgeable (16-bit, no key) | Info — not a vuln for the documented use case (XMODEM file-transfer checksum, not crypto) |

## TM4 — Adversary chain cross-validation

For the @repo-adversary audit card's downstream phases (T3 fuzzing, T4 triage,
T5 report), the threat model narrows the fuzzing surface to:

1. **`crc()` with adversarial bytes** — focus on (a) type-confusion inputs
   (covered by VULN-1/2); (b) algorithmic confusion vectors (covered by
   VULN-8); (c) extreme sizes (covered by VULN-3); (d) edge byte values
   (covered by VULN-4 + 50K oracle stress in VULN-12).
2. **`register()`** — zero-arg, deterministic, no fuzz value.
3. **CLI main()** — focus on (a) `--data` malformed values (covered by VULN-6);
   (b) stdin variants (covered by VULN-5); (c) flag-conflict precedence
   (covered by VULN-7).
4. **`_parse_data()`** — covered transitively by CLI fuzzing.

The T3 harness should target `crc()` with a LibFuzzer / Atheris harness that
mutates bytes, type-variants, and sizes. Expected findings: zero High/Critical.

## TM5 — Worst-case impact summary

Across all attacker profiles, the maximum realistic impact is:

- **CLI malformed-hex uncaught ValueError** (Finding F-1, Low). Leaks Python
  install path in a traceback. No secrets, no PII, no RCE. Exit code is
  non-zero so wrappers can detect. Trivial fix in T4.
- **Memory exhaustion on multi-GB stdin/argv** (Documented behavior). Caller-
  controlled, not attacker-exploitable through the package itself.

No Critical, no High, no Medium vulnerabilities identified.

## TM6 — Out-of-scope (justified)

- **Cryptographic weakness of CRC itself.** A 16-bit CRC has 1/65536 collision
  probability for random inputs and ~2^16 work for a targeted preimage attack.
  This is NOT a vulnerability for the documented use case (XMODEM file-transfer
  checksum over a single packet) and would NOT be a vulnerability for any use
  case where the caller has chosen CRC-16/XMODEM with informed consent. The
  README is honest about this: it describes the algorithm as a "cyclic
  redundancy check used in the XMODEM file-transfer protocol." No security
  claim is made.
- **Slow performance.** ~2 MB/s is ~4x slower than `crcmod` C extension. This
  is documented in the README ("~4x slower than crcmod C extension; acceptable
  for control-plane workloads") and is a trade-off, not a vulnerability.
- **Lack of `init`/`refin`/`refout` configurability.** The public API only
  exposes CRC-16/XMODEM. Callers needing a different CRC variant should use a
  different package. This is a design choice, not a vulnerability.

## TM7 — Conclusion

The threat model confirms a clean audit with one Low finding (F-1: uncaught
`ValueError` on `0x`-prefixed malformed hex). All higher-severity CWEs
considered in `CWE_MAP.md` either DO NOT APPLY to the implementation or
APPLY with zero findings. The package is safe to ship as-is, with the
recommendation that F-1 be addressed in a follow-up patch (T4 triage card).
