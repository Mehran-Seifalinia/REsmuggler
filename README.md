# Resmuggler

A redesign and major refactor of [defparam/smuggler](https://github.com/defparam/smuggler) —
an HTTP Request Smuggling / Desync testing tool written in Python 3.
This project reuses the original mutation engine and CLI shape while adding
canary-based verification, differential confirmation, timing heuristics,
and single-packet attack support.

## Credits

- Original tool: **defparam/smuggler** — https://github.com/defparam/smuggler
- Research foundation: **James Kettle** — HTTP Desync Attacks / Request Smuggling Reborn
- Beta testing on the original: **Ben Sadeghipour** (nahamsec)

## Features

- **Canary probes** for `TE.CL`, `CL.TE`, `CL.0`, `0.CL`
- **Timing probes** that treat fast `503` + `Connection: close` as a signal, not a failure
- **Differential confirmation** that escalates heuristic timing signals to confirmed findings
- **Single-packet attack** with `TCP_CORK` and response splitting
- **Parser discrepancy** and **connection-locked** desync detection
- **H2C upgrade**, **TE.0**, and **HTTP/2 downgrade** probes (H2.CL / H2.TE / H2.CRLF)
- **Funky chunk** mutation engine with 25+ edge-case variants
- JSON and CSV output with separate heuristic vs confirmed findings
- PoC payload export per confirmed finding

## Requirements

- Python 3.8+
- `h2>=4.3.0`

```bash
pip install -r requirements.txt
```

## Usage

```bash
python REsmuggler.py -u https://target.example/path
```

### Common options

| Flag | Description |
|------|-------------|
| `-u, --url` | Target URL (e.g. `https://host/path`) |
| `-m, --method` | HTTP method (default: `POST`) |
| `-c, --config` | Mutation profile: `default`, `exhaustive`, `doubles`, `cl0`, `h2` |
| `-t, --timeout` | Socket timeout in seconds (default: `5.0`) |
| `-r, --rate` | Minimum delay between probes |
| `-x, --exit-early` | Stop on first confirmed finding |
| `-v, --verbose` | Show progress for every step |
| `-j, --json` | Output findings as JSON |
| `-l, --log` | Write a plaintext log to this file |

### Skip specific probe families

```bash
--no-canary        # skip TE.CL / CL.TE / CL.0 / 0.CL
--no-cl0           # skip only CL.0 / 0.CL
--no-single-packet # skip single-packet attack
--no-parser        # skip parser discrepancy
--no-funky         # skip funky chunk probes
--no-timing        # skip timing probes
--no-h2c           # skip H2C probes
--no-te0           # skip TE.0 probes
--no-h2            # skip HTTP/2 downgrade probes
--mutations        # legacy mutation-loop testing (from original smuggler)
```

### Batch mode

```bash
cat targets.txt | python REsmuggler.py -j > results.json
```

## What changed from the original smuggler

| Aspect | defparam/smuggler | Resmuggler |
|--------|-------------------|------------|
| Verification | Mutation-loop only | Canary + differential + single-packet |
| Timing signals | Not present | Stall + fast-reject heuristic |
| Heuristic findings | N/A | Recorded separately, excluded from exit code |
| Confirmation phase | None | Escalates timing to differential proof |
| Output | Plaintext / CSV | JSON / CSV with `heuristic` flag |
| PoC export | No | Raw request bytes per confirmed finding |

## Output model

Findings are separated into two categories:

- **Confirmed** (`●`): verified via canary reflection, differential response,
  or single-packet response splitting. These set the process exit code to `1`.
- **Heuristic** (`?`): timing-based or connection-behavior signals that were
  not confirmed. These are recorded in the JSON output but do not affect the
  exit code.

Example JSON summary:

```json
{
  "summary": {
    "total_findings": 2,
    "confirmed_findings": 1,
    "heuristic_findings": 1,
    "vulnerable_targets": 1
  }
}
```

## PoC export

Confirmed findings write the raw request bytes to `payloads/` next to the
scanner for manual reproduction (e.g. with `curl --raw` or Burp Repeater).

## Project structure

```
smuggler.py
lib/
├── canary.py                  # canary generation and validation
├── canary_probes.py           # TE.CL / CL.TE / CL.0 / 0.CL
├── scanner.py                 # orchestration and escalation
├── timing_detector.py         # stall + fast-reject signals
├── single_packet.py           # single-packet attack
├── parser_discrepancy.py      # duplicate-CL, CL.TE, TE.CL discrepancies
├── connection_analyzer.py     # connection-locked classification
├── funky_chunks.py            # chunk extension mutations
├── h2_probes.py               # HTTP/2 downgrade
├── h2c_probes.py              # H2C upgrade
├── te0_probes.py              # TE.0
├── http_client.py             # raw-socket HTTP client
├── mutations.py               # mutation profiles
├── output_formatter.py        # JSON / CSV output
└── ui.py                      # console output
```

## Disclaimer

This tool is intended for authorized security testing and research only.
Do not use it against systems you do not own or have explicit permission to
test. The authors are not responsible for any misuse or damage caused by this
tool.
