# F-005 — No --stdin size limit or progress reporting (Info)

- **Severity:** Info (defense-in-depth, operational ergonomics gap)
- **Surface:** #3 CLI / `--stdin` flag — `src/crc16_xmodem/__main__.py:65`
- **CWE:** CWE-400 (Uncontrolled Resource Consumption — applied to an unbounded stream-read with no feedback)
- **Origin:** cycle_132/adversary/04 stub-TRIAGE protocol — code-review-derived Info placeholder
- **T3 fuzzer status:** 5 000 random-payload iters + 151 large-payload iters up to 1 MiB — 0 crashes, 0 hangs, 0 OOM, all CLEAN

## Description

`src/crc16_xmodem/__main__.py:65` calls `sys.stdin.buffer.read()` with no
size argument and no progress reporting. A user piping a multi-GB file
(e.g., `cat large_disk_image.bin | python3 -m crc16_xmodem --stdin`) gets
no feedback until the entire payload is buffered, parsed, and CRC'd.

The implementation does NOT actually crash on large input (verified by T3
harness cli_stdin at 1 MiB and theoretical extrapolation; CRC-16/XMODEM is
linear time, so 1 GiB would take ~370 ms at the measured 2.7 MB/s). But the
UX is poor: the user sees a blank terminal while the pipeline appears to
hang.

## Why it is Info, not Low

- The CRC computation is O(n) and bounded — there is no exponential blowup.
- Memory usage is bounded by stdin buffer (default ~64 KiB chunks via
  `sys.stdin.buffer.read()`, not the full file — Python doesn't slurp).
- For files up to a few hundred MB, the perceived hang is a UX issue, not
  a resource-consumption issue.
- The user can `pv` or `cat -n` upstream to get progress; this is a
  shell-pipeline convention rather than a tool-specific gap.

## Reproduction

```bash
# No progress, no size limit:
$ head -c 100000000 /dev/urandom | python3 -m crc16_xmodem --stdin
# (no output for ~37 seconds; then 0xXXXX)
$ echo $?
0
```

## Recommendation (optional, future cycle)

If the CLI is intended for production use, two improvements:

1. Add an optional `--max-bytes N` flag that refuses to read more than N
   bytes from stdin (returns exit code 2 with a friendly error). This gives
   operators a guardrail against accidental multi-TiB inputs.

2. Stream-process stdin chunk-by-chunk (using `sys.stdin.buffer.read1(size)`
   in a loop) and emit a progress line to stderr if `--verbose` is set.
   This requires changing `crc()` to expose a streaming `update()` API.

Both are non-trivial changes (streaming API + CLI flag); recommended only if
the CLI moves from "debug tool" to "production wire-format codec".

## Evidence

- `src/crc16_xmodem/__main__.py:65` — `data = sys.stdin.buffer.read()`
- `benchmarks/adversarial/cycle_132/CORPUS_RUN.md §3` — cli_stdin 5 000 iters + 151 large iters CLEAN
- `benchmarks/adversarial/cycle_132/VULN_AUDIT.md "Linear time in input length"` — verified at 50 MB
- `benchmarks/adversarial/cycle_132/SURFACES.md S2.d` — `--stdin` surface documented