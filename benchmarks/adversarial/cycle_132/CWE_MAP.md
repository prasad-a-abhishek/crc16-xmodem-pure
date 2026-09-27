# CWE_MAP — crc16-xmodem candidate CWE mapping

> Cycle 132 / T1 VULN_AUDIT — CWE applicability table for `crc16-xmodem` @ 6071f9c.
>
> Source: `src/crc16_xmodem/_crc16_xmodem.py`, `__init__.py`, `__main__.py`.
> Verifier: probe script `/tmp/adv_probes.py` output captured in `VULN_AUDIT.md` §3.

This file enumerates the CWE IDs the audit considered and adjudicates each as
**APPLIES / DOES NOT APPLY** with concrete code-level evidence. A CWE that
APPLIES but yields zero findings is still recorded (it informs the threat
model); one that DOES NOT APPLY is excluded from the VULN_AUDIT.md finding list.

---

## M1 — Input validation & type confusion

| CWE | Title | Verdict | Evidence |
|---|---|---|---|
| **CWE-20** | Improper Input Validation | APPLIES (clean) | `crc()` has explicit `isinstance(data, (bytes, bytearray, memoryview))` guard (line 19). CLI `_parse_data()` has 3-stage fallback with no injection paths (argparse does not shell-out). Probe VULN-1 covers 10 invalid types → all raise TypeError; probe VULN-2 covers 5 iterables → all raise TypeError; probe VULN-6 covers 9 malformed `--data` strings → no shell metachar reaches a shell. |
| **CWE-1284** | Numeric Truncation / Loss of Precision | DOES NOT APPLY | Python ints are arbitrary precision. The 16-bit mask `& 0xFFFF` is intentional, not lossy from a type-safety standpoint (the spec IS 16-bit CRC). |
| **CWE-704** | Incorrect Type Conversion | DOES NOT APPLY | All integer coercions go through `int(v, 16) & 0xFF` or `int(v) & 0xFF` with explicit masks. No implicit conversion of arbitrary objects. |
| **CWE-843** | Access of Resource Using Incompatible Type (Type Confusion) | APPLIES (clean) | The `isinstance` check is correctly ordered: bytes-like check BEFORE iteration. Probe VULN-2 confirms generators/range/map/zip all rejected pre-iteration. No way to pass a generator and have it be consumed byte-by-byte. |

## M2 — Integer & arithmetic safety

| CWE | Title | Verdict | Evidence |
|---|---|---|---|
| **CWE-190** | Integer Overflow / Wraparound | DOES NOT APPLY | Python int has no overflow. The 16-bit mask is explicit: `& 0xFFFF` at lines 25, 28, 30 of `_crc16_xmodem.py`. Probe VULN-11 confirms 1000 random 64-byte inputs all yield `0 <= result < 65536`. |
| **CWE-191** | Integer Underflow | DOES NOT APPLY | No decrements. The XOR/OR/SHIFT operations can never produce a negative value because all operands are `& 0xFFFF`-masked before XOR. |
| **CWE-682** | Incorrect Calculation | APPLIES (clean) | Disambiguation property: poly=0x1021 + refin/refout=False + init=0x0000 + xorout=0x0000 uniquely identifies CRC-16/XMODEM. Probe VULN-8 confirms `crcmod.predefined.mkPredefinedCrcFun("xmodem")` byte-exact match (0x31C3) and the parameter table exactly matches the RevEng catalogue entry. No confusion with sibling CRCs (Modbus 0x8005-reflected, CCITT-FALSE 0x1021+init=0xFFFF, EN13757 0x3D65). |
| **CWE-1339** | Insufficient Precision or Accuracy of a Mathematical Result | DOES NOT APPLY | CRC is an integer operation; no floating-point anywhere in the code path. |

## M3 — Resource consumption & availability

| CWE | Title | Verdict | Evidence |
|---|---|---|---|
| **CWE-400** | Uncontrolled Resource Consumption | APPLIES (clean) | The inner loop is strictly linear in input length: 1 byte → 8 fixed iterations. Probe VULN-3 confirms: 1 MiB in 467.8 ms (2.1 MB/s), 10 MiB in 4821.4 ms (2.1 MB/s), 50 MiB in 33475.1 ms (1.5 MB/s — cold cache, not quadratic). No quadratic blowup. AC12 verified by `test_long_input_linear_time` in test category 12 (100KB to 5MB, `< 30s` wall time per input). |
| **CWE-770** | Allocation of Resources Without Limits or Throttling | APPLIES (clean) | The CLI reads `sys.stdin.buffer.read()` without any size cap. An adversary who controls stdin could push 4 GiB and force memory exhaustion (Linux default pipe buffer is 64 KiB but `read()` returns whatever is available). **This is documented Python behavior, not a package bug** — the caller controls how much data they pipe in. The CLI is a one-shot tool; running it on a multi-GB stdin is the caller's choice. Severity: Info. No mitigation required. |
| **CWE-835** | Infinite Loop / Loop with Unreachable Exit Condition | APPLIES (clean) | Both inner loops have fixed iteration counts (`for _ in range(8)`, `for byte in data`). `data` is a bytes-like object whose iteration terminates when the buffer is exhausted. No `while True`, no `break` outside of the fixed-iteration path. Probe VULN-12 (50000 random inputs) completes in ~10s with zero hangs. |
| **CWE-674** | Uncontrolled Recursion | DOES NOT APPLY | No recursion in the algorithm. The function is iterative. |
| **CWE-789** | Memory Allocation with Excessive Size Value | DOES NOT APPLY | The CLI does not allocate based on attacker-controlled size — it reads stdin into memory (`sys.stdin.buffer.read()`), which is the standard idiom. Caller-controlled, not attacker-controlled through the API. |

## M4 — Injection & OS interaction

| CWE | Title | Verdict | Evidence |
|---|---|---|---|
| **CWE-78** | OS Command Injection (Shell injection) | APPLIES (clean) | The CLI uses `argparse` to parse `--data` values. `argparse` does NOT invoke a shell. The values flow through `_parse_data()` which only does hex/int/latin-1 decoding. Probe VULN-6 confirms: `--data "; rm -rf /"`, `--data "$(whoami)"`, `--data "`id`"` all produce a deterministic CRC over the literal string bytes; no shell ever runs. |
| **CWE-94** | Code Injection (eval/exec) | DOES NOT APPLY | No `eval()`, `exec()`, `compile()`, or dynamic import anywhere in the source. `grep -R "eval\|exec\|compile\|__import__" src/` returns empty. |
| **CWE-95** | Eval Injection | DOES NOT APPLY | (subset of CWE-94, same evidence.) |
| **CWE-611** | XXE (XML External Entity) | DOES NOT APPLY | No XML parser in the code path. |
| **CWE-918** | Server-Side Request Forgery (SSRF) | DOES NOT APPLY | No network code. The package is offline-only. |
| **CWE-22** | Path Traversal | DOES NOT APPLY | No filesystem reads/writes outside of `_parse_data()` (in-memory only) and `sys.stdin.buffer.read()` (in-memory only). |
| **CWE-79** | XSS (Cross-Site Scripting) | DOES NOT APPLY | CLI output is `0x{result:04X}` to stdout or `PASS:`/`FAIL:` messages. No HTML rendering, no template engine, no web framework. |

## M5 — Information disclosure & logging

| CWE | Title | Verdict | Evidence |
|---|---|---|---|
| **CWE-200** | Exposure of Sensitive Information to an Unauthorized Actor | APPLIES (clean) | The CLI prints `crc(b'123456789')` and the result on `--self-test` failure — this is intentional diagnostic output. No secrets, no PII, no file paths. The algorithm is public (RevEng catalogue entry); `register()` exposes only the algorithm parameters, not any internal state. |
| **CWE-209** | Generation of Error Message Containing Sensitive Information | APPLIES (low/info) | When `--data 0xZZ` is passed, the CLI raises an uncaught `int(v, 16)` `ValueError` and dumps a full Python traceback to stderr, including the file path `/root/projects/crc16-xmodem-pure/.worktrees/.../src/crc16_xmodem/__main__.py`. This is the Python default behavior and leaks the installation path. Severity: Low (file path is not sensitive; no key material, no credentials). Invariant 21 ("Total Public API Exception Safety") is violated for the CLI entry point. Recommended fix: wrap `_parse_data()` in a try/except and print a clean error like `error: invalid hex value '0xZZ'` and exit 1. Tracked as VULN-AUDIT finding F-1. |
| **CWE-532** | Insertion of Sensitive Information into Log File | DOES NOT APPLY | No logging. Output goes to stdout/stderr only. |
| **CWE-117** | Improper Output Neutralization for Logs | DOES NOT APPLY | (subset of CWE-532.) |

## M6 — Concurrency, TOCTOU, race conditions

| CWE | Title | Verdict | Evidence |
|---|---|---|---|
| **CWE-362** | Concurrent Execution using Shared Resource without Proper Synchronization (TOCTOU) | DOES NOT APPLY | The function is pure — no shared state, no global mutation, no file handle. Multiple threads can call `crc(data)` concurrently without any data race. The `_MASK`, `_POLY`, `_XOROUT` module-level constants are read-only. |
| **CWE-366** | Race Condition Within a Thread | DOES NOT APPLY | (subset of CWE-362.) |
| **CWE-367** | Time-of-Check Time-of-Use (TOCTOU) | DOES NOT APPLY | No check-then-act pattern. |

## M7 — Cryptographic weaknesses

| CWE | Title | Verdict | Evidence |
|---|---|---|---|
| **CWE-327** | Use of a Broken or Risky Cryptographic Algorithm | APPLIES (informational, NOT a vuln) | CRC-16/XMODEM is a **checksum**, not a cryptographic primitive. The README is honest about this: "16-bit cyclic redundancy check used in the XMODEM file-transfer protocol." CRCs are NOT for adversarial integrity protection — that's what HMAC-SHA256 etc. are for. The algorithm choice matches the documented use case (XMODEM file-transfer integrity check). Severity: Info only. |
| **CWE-330** | Use of Insufficiently Random Values | DOES NOT APPLY | The algorithm is deterministic — random values would be a BUG. |
| **CWE-338** | Use of Cryptographically Weak PRNG | DOES NOT APPLY | No PRNG in the code path. |
| **CWE-340** | Generation of Predictable Numeric Identifier | APPLIES (informational, NOT a vuln) | A CRC IS a predictable identifier by definition — that's its purpose. Not a vulnerability for the documented use case. |
| **CWE-1240** | Use of a Cryptographic Primitive with a Risky Implementation | DOES NOT APPLY | Standard, well-tested bitwise XOR/shift loop. No exotic primitives. |

## M8 — Memory & pointer safety

| CWE | Title | Verdict | Evidence |
|---|---|---|---|
| **CWE-119** | Buffer Overflow (out-of-bounds read/write) | DOES NOT APPLY | Pure Python — no native buffers. `for byte in data` iterates the bytes-like object via the C-level buffer protocol, which is bounds-checked by CPython. |
| **CWE-125** | Out-of-Bounds Read | DOES NOT APPLY | (subset of CWE-119.) Probe VULN-4 confirms all 256 single-byte values (0x00–0xFF) produce a valid CRC without exception. |
| **CWE-131** | Incorrect Calculation of Buffer Size | DOES NOT APPLY | No manual buffer size arithmetic. |
| **CWE-415** | Double Free | DOES NOT APPLY | No manual memory management. |
| **CWE-416** | Use After Free | DOES NOT APPLY | No manual memory management. |
| **CWE-476** | NULL Pointer Dereference | DOES NOT APPLY | Pure Python — no pointers. |
| **CWE-787** | Out-of-Bounds Write | DOES NOT APPLY | (subset of CWE-119.) |

## M9 — Error handling & robustness

| CWE | Title | Verdict | Evidence |
|---|---|---|---|
| **CWE-252** | Unchecked Return Value | DOES NOT APPLY | All operations are pure; no return values to check. |
| **CWE-391** | Unchecked Error Condition | APPLIES (low) | The CLI does NOT check the return of `_parse_data()` — the malformed-hex case `0xZZ` raises an uncaught `ValueError` and dumps a traceback (VULN-AUDIT finding F-1). Severity: Low. |
| **CWE-754** | Improper Check for Unusual or Exceptional Conditions | APPLIES (clean) | The `isinstance` check in `crc()` is the only exceptional-condition check needed, and it is present and correct. |

## M10 — API design & data flow

| CWE | Title | Verdict | Evidence |
|---|---|---|---|
| **CWE-441** | Unintended Proxy or Intermediary | DOES NOT APPLY | No network code. |
| **CWE-668** | Exposure of Resource to the Wrong Sphere | DOES NOT APPLY | No resource handles exposed. |
| **CWE-913** | Improper Control of Dynamically-Managed Code Resources | DOES NOT APPLY | No dynamic code management. |

---

## M11 — Summary counts

| Category | Considered | Applies | Applies-with-finding | Net findings |
|---|---|---|---|---|
| M1 Input validation | 4 | 2 | 0 | 0 |
| M2 Integer & arithmetic | 4 | 1 | 0 | 0 |
| M3 Resource consumption | 5 | 3 | 0 | 0 |
| M4 Injection & OS | 7 | 1 | 0 | 0 |
| M5 Information disclosure | 4 | 2 | 1 | 1 (Low) |
| M6 Concurrency | 3 | 0 | 0 | 0 |
| M7 Cryptographic | 5 | 2 | 0 | 0 (Info only) |
| M8 Memory safety | 7 | 0 | 0 | 0 |
| M9 Error handling | 3 | 2 | 1 | 1 (Low, same as M5) |
| M10 API design | 3 | 0 | 0 | 0 |
| **Total unique CWEs considered** | **45** | **13** | **1 (Low)** | **1** |

The single Low finding (F-1) covers both CWE-209 and CWE-391 — same root cause
(uncaught `ValueError` from `int(v, 16)` on malformed `0x`-prefixed `--data`
arguments, dumps Python traceback to stderr). Both CWEs are recorded in
`VULN_AUDIT.md` finding F-1.
