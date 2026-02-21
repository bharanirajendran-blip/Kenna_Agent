# Policy-Aware Vulnerability Remediation Orchestration Agent

**Course:** Applied Agentic AI (Graduate Level)  
**Student:** Bharani  
**Domain:** UConn IT Infrastructure – Server Operations

## 1. Problem Statement
Kenna data is rich but operationally incomplete by itself. Teams need:
- deterministic prioritization
- ownership-aligned routing
- governance-safe action recommendations
- auditable output generation

## 2. Objective
Build a hybrid agent that transforms Kenna vulnerability/fix data into:
1. structured remediation JSON for downstream automation
2. complete Markdown remediation report for human operations
3. full execution audit trace

## 3. Current System Architecture

### 3.1 Pipeline
`observe -> reason_llm -> act` (LangGraph)

### 3.2 Node responsibilities
- `observe`
  - load and validate input via Pydantic
  - compute deterministic policy output
- `reason_llm`
  - run bounded ReAct-style loop for narrative generation
  - validate candidate output and retry on violations
- `act`
  - persist `report.md`, `structured.json`, `audit_log.json`
  - optional email send (dry-run default)

## 4. Agentic Behavior Definition
The Reason node implements explicit stepwise tool behavior:
1. `load_context`
2. `invoke_llm`
3. `parse_narrative`
4. `build_candidate`
5. `validate_output`

Properties:
- bounded with `REACT_MAX_STEPS`
- bounded retries with `LLM_RETRY_ATTEMPTS`
- compliance-gated completion
- all tool steps audited (`reason_tool_call`)

## 5. Deterministic Policy Engine
Implemented in `agent/policy_engine.py`.

### 5.1 Priority score
`(kenna/100*0.4) + (cvss/10*0.2) + (exploit*0.2) + (criticality*0.1) + (min(hosts/100,1.0)*0.1)`

### 5.2 Priority rules
High override when any true:
- exploit known + production exposure
- active breach
- malware present

Else:
- `>= 0.80` High
- `>= 0.55` Medium
- otherwise Low

### 5.3 Additional deterministic fields
- owner routing by most-frequent sampled `owner_group`
- change window from `requires_reboot`
- confidence score with cap
- summary counts and risk reduction tier
- deterministic sorting

## 6. LLM Role and Prompt Contract
LLM is restricted to narrative fields only:
- executive summary text
- fix justifications
- action packet ticket summary + verification text

Prompt explicitly forbids changing policy numbers, priorities, routing, and actions.

## 7. Validation Contract
Implemented in `agent/validators.py`.

### 7.1 Structured validation
- Pydantic schema conformance
- full fix coverage
- no duplicate/unexpected titles
- correct action literal
- score-based order check

### 7.2 Report validation
- required section headers and order
- exact Priority Fix entry count
- exact Action Packet entry count for High/Medium fixes
- no duplicate/missing/extra titles

## 8. Data Pipeline
Input JSON is generated from Kenna CSV exports by:
- `data/build_real_data.py`
- `data/build_sanitized_data.py`

Both use shared logic in `data/build_dataset_common.py` and join all three sources:
- fix export
- vulnerability export
- asset export

Sanitized builder anonymizes asset identifiers while preserving risk-relevant fields.

## 9. Output Schema
External output interface remains:
- `structured.asset_group`
- `structured.summary`
- `structured.prioritized_fixes[]`
- `report` (full markdown)

Backward compatibility is maintained for existing consumers.

## 10. Audit and Governance
Audit log captures:
- observe start/end
- policy computation
- reason start
- each ReAct tool step
- validation failures
- retry reasons
- final validation pass
- output write
- email sent/skipped/failed

No automated remediation actions are performed.

## 11. Configuration
Primary runtime controls:
- `OPENAI_API_KEY`
- `OPENAI_MODEL`
- `OPENAI_TEMPERATURE`
- `KENNA_INPUT_PATH`
- `PROMPT_PATH`
- `LLM_RETRY_ATTEMPTS`
- `REACT_MAX_STEPS`

## 12. Evolution Path
Planned progression aligned to course labs:
1. live Kenna API source adapter
2. optional Jira action mode behind validation gate
3. multi-agent role split (policy/report/compliance)
4. MCP-based external tool integration

## 13. Success Criteria
- deterministic policy correctness independent of LLM variability
- complete and compliant report generation
- explicit fail-fast on unresolved compliance violations
- auditable, reproducible reasoning traces
