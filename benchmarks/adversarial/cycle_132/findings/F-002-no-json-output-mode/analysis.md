# F-002 — CLI has no --json output mode (Info)

- **Severity:** Info (defense-in-depth, CLI ergonomics gap)
- **Surface:** #2 CLI / `main()` and `--register` flag — `src/crc16_xmodem/__main__.py`
- **CWE:** CWE-1284 (Improper Validation of Specified Quantity in Input — applied here to a missing structured-output mode)
- **Origin:** cycle_132/adversary/04 stub-TRIAGE protocol — code-review-derived Info placeholder
- **T3 fuzzer status:** 5 000 iters cli_data CLEAN

## Description

`--register` prints RevEng parameter table rows in `key=value` form
(`width=16`, `poly=4129`, etc.), which is not directly parseable by `jq`,
`json.loads`, or other common structured-data tools. A user who wants
machine-readable metadata must parse the `key=value` format manually.

Additionally, there is no `--json` / `-j` flag that emits the CRC result as
a JSON object (e.g., `{"crc": "0x31C3", "data_bytes": 9}`), which would be
useful for integration with shell pipelines that consume structured data.

## Why it is Info, not Low

- The `--register` output is unambiguous and easy to parse with awk/sed/grep.
- The CRC output is a single line of 6 chars (`0x31C3\n`) which is the
  simplest possible machine-friendly format already.
- No security boundary is crossed; this is purely about tool ergonomics.

## Reproduction

```bash
$ python3 -m crc16_xmodem --register
width=16
poly=4129
init=0
refin=False
refout=False
xorout=0
check=12739

$ python3 -m crc16_xmodem --register | jq
# parse error: 'width=16' is not valid JSON
$
```

There is no `--json` flag:

```bash
$ python3 -m crc16_xmodem --json --register
usage: crc16-xmodem: error: unrecognized arguments: --json
```

## Recommendation (optional, future cycle)

Add a `--json` / `-j` flag that emits the `--register` table as a JSON object:

```python
import json as _json
...
if args.register:
    if getattr(args, "json", False):
        print(_json.dumps(register(), indent=2))
    else:
        for k, v in register().items():
            print(f"{k}={v}")
    return 0
```

This is purely a tooling convenience; the current output is correct.

## Evidence

- `src/crc16_xmodem/__main__.py:60-62` — `for k, v in register().items(): print(f"{k}={v}")`
- `python3 -m crc16_xmodem --help` — confirms no `--json` flag exists
- `benchmarks/adversarial/cycle_132/CORPUS_RUN.md §3` — cli_data 5 000 iters CLEAN
- `benchmarks/adversarial/cycle_132/VULN_AUDIT.md` — algorithm correct; CLI ergonomics noted