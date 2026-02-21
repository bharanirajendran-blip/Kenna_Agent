# Kenna-to-Jira Remediation Orchestration Agent

**Course:** GRAD 5900 — Applied Agentic AI  
**Student:** Bharani Rajendran  
**Domain:** UConn IT Infrastructure / Server Operations

## Overview
This project converts Kenna vulnerability export data into policy-compliant remediation outputs.

It is implemented as a hybrid agent:
- Deterministic policy engine in Python for all risk decisions
- LLM narrative generation for human-facing text
- ReAct-style reasoning loop with bounded retries and validation

## What Is Agentic Here
The runtime follows an Observe → Reason → Act loop with explicit tool-like steps during Reason:
- `load_context`
- `invoke_llm`
- `parse_narrative`
- `build_candidate`
- `validate_output`

Each step is logged in `outputs/audit_log.json` as `reason_tool_call`.

## Architecture
```text
OBSERVE                              REASON (ReAct loop)                      ACT
Load + validate input source      -> Tool steps + retry/repair loop       -> Write outputs
(csv JSON or API normalized JSON)    LLM narrative only                      report.md
Deterministic policy compute          Strict compliance checks                structured.json
                                                                                audit_log.json
```

## Deterministic Policy Ownership
The following are computed in Python (not by the LLM):
- `priority_score`
- `priority_level` (including High overrides)
- `owner_group` routing
- `change_window_required`
- `confidence`
- summary metrics and sorted order

## Compliance Guarantees
Before writing outputs, validators enforce:
- Structured schema validity
- Full fix coverage in `prioritized_fixes`
- `recommended_action == "Create Jira Ticket"`
- Required report section order
- One Priority Fix entry per fix
- One Action Packet entry per High/Medium fix

On violation, the run retries with repair instructions. If retries are exhausted, the run fails explicitly.

## Quick Start
1. Setup
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Configure key
```bash
cp .env.example .env
# set OPENAI_API_KEY=...
```

3. Run
```bash
python agent/run_agent.py
```

4. Inspect outputs
```bash
cat outputs/report.md
cat outputs/structured.json
cat outputs/audit_log.json
```

## Data Inputs
The agent supports two source modes:
- `KENNA_SOURCE=csv` (default): reads normalized Kenna input JSON from `KENNA_INPUT_PATH`.
- `KENNA_SOURCE=api`: fetches normalized JSON from `KENNA_API_NORMALIZED_URL` using `X-Risk-Token`.

In both modes, downstream policy/report logic uses the same normalized schema.

Default input selection:
- `data/kenna_input.json` if present (real data)
- else `data/kenna_input_sanitized.json` (safe sample)

### Build sanitized dataset (professor-safe)
```bash
python data/build_sanitized_data.py
```

### Build real dataset (private use)
```bash
python data/build_real_data.py
```

Both builders now use a comprehensive 3-CSV join pipeline:
- `asset_export*.csv`
- `vulnerability_export*.csv`
- `fix_export*.csv`

## Project Structure
```text
kenna-agent/
├── README.md
├── Spec.md
├── prompt_template.md
├── requirements.txt
├── agent/
│   ├── input_source.py
│   ├── run_agent.py
│   ├── policy_engine.py
│   ├── report_builder.py
│   └── validators.py
├── data/
│   ├── build_dataset_common.py
│   ├── build_real_data.py
│   ├── build_sanitized_data.py
│   └── kenna_input_sanitized.json
└── outputs/
    ├── report.md
    ├── structured.json
    └── audit_log.json
```

## Environment Variables
| Variable | Default | Purpose |
|---|---|---|
| `OPENAI_API_KEY` | required | OpenAI API key |
| `OPENAI_MODEL` | `gpt-4o` | model for narrative generation |
| `OPENAI_TEMPERATURE` | `0.1` | narrative variability |
| `KENNA_SOURCE` | `csv` | input source mode (`csv` or `api`) |
| `KENNA_INPUT_PATH` | auto-detected | input JSON path |
| `KENNA_API_NORMALIZED_URL` | unset | API endpoint returning normalized JSON |
| `KENNA_API_TOKEN` | unset | Kenna API token for `X-Risk-Token` header |
| `KENNA_API_TIMEOUT` | `20` | API request timeout in seconds |
| `KENNA_API_SNAPSHOT_PATH` | unset | offline API simulation JSON path |
| `PROMPT_PATH` | `prompt_template.md` | narrative prompt path |
| `LLM_RETRY_ATTEMPTS` | `3` | bounded repair retries |
| `REACT_MAX_STEPS` | `8` | max tool steps per reason attempt |

## Troubleshooting
- `OPENAI_API_KEY is not set`: set key in `.env`.
- Validation retries/failure: review `validation_failed` entries in `outputs/audit_log.json`.
- Missing CSV export files: place Kenna export CSVs in `data/` with names containing `asset`/`vulnerability`/`fix` and `export`.

## Roadmap
As course labs progress, this base can evolve to:
- live Kenna API adapter
- multi-agent role split
- MCP-backed tool integrations
- optional Jira ticket creation mode

*Academic use only — UConn GRAD 5900*
