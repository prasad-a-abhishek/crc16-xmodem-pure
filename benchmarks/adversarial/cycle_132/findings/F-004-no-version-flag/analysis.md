# F-004 — CLI has no --version flag (Info)

- **Severity:** Info (defense-in-depth, CLI ergonomics gap)
- **Surface:** #2 CLI / `main()` — `src/crc16_xmodem/__main__.py`
- **CWE:** CWE-1284 (applied to a missing conventional CLI flag)
- **Origin:** cycle_132/adversary/04 stub-TRIAGE protocol — code-review-derived Info placeholder
- **T3 fuzzer status:** 5 000 iters cli_data CLEAN

## Description

`src/crc16_xmodem/__init__.py:13` defines `__version__ = "0.1.0"`. The Python
API exposes this string to callers (e.g., `python3 -c "import crc16_xmodem;
print(crc16_xmodem.__version__)"`). However, the CLI does not expose it
through a `--version` flag — users must import the module or read
`pyproject.toml` to determine which version they have installed.

Most established CLI tools (git, curl, jq, sha256sum, pip, etc.) support a
`--version` flag by convention. The package is missing this conventional
ergonomic affordance.

## Why it is Info, not Low

- The Python API is the documented primary interface (per SPEC.md §3); the
  CLI is positioned as a debugging tool.
- A user who needs the version can `pip show crc16-xmodem-pure` or check
  `pyproject.toml`.
- This is purely a convenience gap, not a functional defect.

## Reproduction

```bash
$ python3 -m crc16_xmodem --version
usage: crc16-xmodem [-h] [--data DATA [DATA ...]] [--stdin] [--self-test]
                    [--register]
crc16-xmodem: error: unrecognized arguments: --version
$ python3 -m crc16_xmodem -V
usage: crc16-xmodem [-h] [--data DATA [DATA ...]] [--stdin] [--self-test]
                    [--register]
crc16-xmodem: error: unrecognized arguments: -V
$ python3 -c "import crc16_xmodem; print(crc16_xmodem.__version__)"
0.1.0
```

## Recommendation (optional, future cycle)

Add a `--version` / `-V` flag using argparse's built-in `action="version"`:

```python
from . import __version__
p.add_argument("--version", "-V", action="version",
               version=f"crc16-xmodem {__version__}")
```

This is a 2-line addition; the cost is trivial and the convention is strong.

## Evidence

- `src/crc16_xmodem/__init__.py:13` — `__version__ = "0.1.0"` is defined
- `src/crc16_xmodem/__main__.py:54-58` — argparse setup has no version action
- `python3 -m crc16_xmodem --help` — confirms no `--version` flag exists
- `benchmarks/adversarial/cycle_132/CORPUS_RUN.md §3` — cli_data 5 000 iters CLEAN