# Kenna-to-Jira Remediation Orchestration Agent

**Course:** GRAD 5900 — Applied Agentic AI
**Student:** Bharani Rajendran
**Domain:** UConn IT Infrastructure / Server Operations

---

## Overview

This agent transforms static Kenna Security vulnerability reports into policy-aware, ownership-aligned Jira ticket recommendations. It demonstrates core agentic AI patterns:

| Pattern | Implementation |
|---|---|
| **Tool Use** | Processes structured vulnerability data |
| **Structured Reasoning** | Applies governance policies via LLM |
| **Real-World Action** | Generates actionable ticket recommendations |
| **Controlled Autonomy** | Human-in-the-loop design (no auto-remediation) |
| **Audit Trail** | Full execution trace for compliance |

### Architecture — 3-Node LangGraph Pipeline

```
OBSERVE             REASON (LLM)           ACT
──────────         ─────────────          ──────────────────
Load & validate → GPT-4o reasoning    → Write outputs
KennaInput JSON   Apply policy rules    outputs/report.md
(Pydantic v2)     3-attempt retry       outputs/structured.json
                  with schema repair    outputs/audit_log.json
                                        [optional: email]
```

---

## Quick Start (Professor Instructions)

### 1. Clone & Setup

```bash
git clone https://github.com/<your-handle>/kenna-agent.git
cd kenna-agent

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

### 2. Configure API Key

```bash
cp .env.example .env
# Open .env and set: OPENAI_API_KEY=sk-...
```

### 3. Run the Agent

```bash
python agent/run_agent.py
```

### 4. View Outputs

```bash
cat outputs/report.md        # Human-readable executive report
cat outputs/structured.json  # Machine-readable prioritized fixes
cat outputs/audit_log.json   # Timestamped execution trace
```

---

## Project Structure

```
kenna-agent/
├── README.md                        ← You are here
├── SPEC.md                          ← Detailed project specification
├── requirements.txt                 ← Python dependencies
├── .env.example                     ← Configuration template (safe to commit)
├── .gitignore
│
├── prompt_template.md               ← LLM system prompt & policy rules
│
├── data/
│   ├── build_sanitized_data.py      ← Anonymizer for real Kenna CSVs
│   └── kenna_input_sanitized.json   ← Safe sample dataset (committed)
│
├── agent/
│   ├── __init__.py
│   └── run_agent.py                 ← Main entrypoint (LangGraph pipeline)
│
└── outputs/                         ← Generated at runtime (gitignored)
    ├── report.md
    ├── structured.json
    └── audit_log.json
```

---

## Prioritization Policy

The agent applies this composite scoring formula:

```
Priority Score = (Kenna Score / 100 × 0.4)
              + (CVSS / 10 × 0.2)
              + (Exploit Known × 0.2)
              + (Asset Criticality weight × 0.1)
              + (min(Affected Hosts / 100, 1.0) × 0.1)
```

**High Priority triggers** (any one of):
- Active exploit + production environment
- Priority Score ≥ 0.75
- Kenna Score ≥ 80

**Confidence Score:**
- Base 0.5 + up to 0.5 from: high Kenna score, active exploit, production assets, scale

---

## Sample Dataset

`data/kenna_input_sanitized.json` contains **10 high-impact fixes** with:
- Deterministically anonymized hostnames (SHA-256 hashing)
- Realistic Kenna and CVSS scores
- Exploit flags and reboot requirements
- Safe for GitHub and classroom use

---

## Configuration Options

| Variable | Default | Description |
|---|---|---|
| `OPENAI_API_KEY` | *(required)* | Your OpenAI API key |
| `OPENAI_MODEL` | `gpt-4o` | LLM model to use |
| `OPENAI_TEMPERATURE` | `0.1` | Determinism (0 = fully deterministic) |
| `KENNA_INPUT_PATH` | `data/kenna_input_sanitized.json` | Input data file |
| `PROMPT_PATH` | `prompt_template.md` | System prompt file |

### Optional: Email Notifications

Set these in `.env` to receive the report by email:

```bash
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_STARTTLS=1
SMTP_USER=you@example.com
SMTP_PASS=yourpassword
REPORT_SENDER=agent@example.com
REPORT_RECIPIENTS=manager@example.com
```

---

## Rebuilding from Real Kenna Data

To regenerate the sanitized dataset from live Kenna exports:

1. Export from Kenna: **Assets**, **Vulnerabilities**, **Fixes** → CSV
2. Place files in `data/` (filenames must match `*_export_*.csv`)
3. Run:
   ```bash
   python data/build_sanitized_data.py
   ```
4. Verify `data/kenna_input_sanitized.json` was updated
5. Run the agent: `python agent/run_agent.py`

---

## Output Files

### `outputs/report.md` — Executive Report
Markdown report with:
- Executive summary (risk posture, estimated risk reduction)
- Ranked fix list with justifications
- Ownership routing (tickets per team)
- Governance notes (production impact, change windows, active exploits)

### `outputs/structured.json` — Machine-Readable Output
JSON conforming to the `AgentOutput` Pydantic schema — suitable for downstream integration (Jira API, dashboards, etc.)

### `outputs/audit_log.json` — Execution Trace
Timestamped log of every pipeline step including:
- Data loaded, model used, temperature
- LLM retry attempts and errors
- Email delivery status

---

## Evaluation Metrics (for Grading)

| Criterion | Evidence |
|---|---|
| Agentic loop | 3-node LangGraph: Observe → Reason → Act |
| Tool use | Kenna JSON parsing, structured output |
| Policy enforcement | Scoring formula applied by LLM |
| Structured output | Pydantic v2 schema validation |
| Resilience | 3-attempt LLM retry with schema repair |
| Audit trail | `audit_log.json` with timestamps |
| Real-world grounding | Built from live UConn Kenna exports |

---

*Academic use only — UConn GRAD 5900*
