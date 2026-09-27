# F-001 — CLI has no --quiet flag (Info)

- **Severity:** Info (defense-in-depth, CLI ergonomics gap)
- **Surface:** #2 CLI / `main()` — `src/crc16_xmodem/__main__.py`
- **CWE:** CWE-1284 (Improper Validation of Specified Quantity in Input — applied here to a missing output-mode flag)
- **Origin:** cycle_132/adversary/04 stub-TRIAGE protocol — code-review-derived Info placeholder
- **T3 fuzzer status:** 5 000 iters across 2 modes (random_hex + crlf_whitespace), 0 crashes, 0 oracle mismatches, VERDICT: CLEAN

## Description

`src/crc16_xmodem/__main__.py::main()` always prints `0x{NRC:04X}` to stdout on every successful invocation. There is no `--quiet` / `-q` flag (or `--silent` / `-s` flag) that suppresses the output for use in shell pipelines where only the exit code is significant.

## Why it is Info, not Low

- The package is positioned as a developer tool, not a production wire-format codec.
- A user who needs machine-readable output can pipe `cut -d'x' -f2` or `tr -d 'x\n'` — both are well-known shell idioms.
- The current behaviour is consistent (always prints) which is the easier default to reason about.
- There is no silent failure mode: the function exits 0 only when the CRC was successfully computed.

## Reproduction

```bash
$ python3 -m crc16_xmodem --data 31 32 33 34 35 36 37 38 39
0x31C3
$ echo $?
0
```

The output is always printed; there is no `--quiet` flag:

```bash
$ python3 -m crc16_xmodem --quiet --data 31 32 33 34 35 36 37 38 39
usage: crc16-xmodem [-h] [--data DATA [DATA ...]] [--stdin] [--self-test]
                    [--register]
crc16-xmodem: error: unrecognized arguments: --quiet
```

## Recommendation (optional, future cycle)

Add a `--quiet` flag that suppresses the `0x{result:04X}` line and prints nothing on success (exit 0 only), or alternatively prints the bare CRC as 4 hex chars to stdout for piping:

```python
p.add_argument("--quiet", "-q", action="store_true",
               help="suppress '0x' prefix and newline on stdout")
```

This is purely ergonomic; the current behaviour is correct and not exploitable.

## Evidence

- `src/crc16_xmodem/__main__.py:64` — `print(f"0x{crc(data):04X}")`
- `python3 -m crc16_xmodem --help` — confirms no `--quiet` / `-q` flag exists
- `benchmarks/adversarial/cycle_132/CORPUS_RUN.md §3` — cli_data surface ran 5 000 iters, 0 crashes
- `benchmarks/adversarial/cycle_132/VULN_AUDIT.md` — algorithm bit-exact; CLI behaviour gaps documented as Low/Info only