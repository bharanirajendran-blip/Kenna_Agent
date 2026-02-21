"""
run_agent.py
============
Kenna Remediation Orchestration Agent
GRAD 5900 — Applied Agentic AI

Three-node LangGraph pipeline:
  observe  →  reason_llm  →  act

Run:
    python agent/run_agent.py

Required env vars (set in .env):
    OPENAI_API_KEY
"""

from __future__ import annotations

import json
import os
import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any, Dict, List, Literal, Optional

from dotenv import load_dotenv
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import END, StateGraph
from pydantic import BaseModel, ConfigDict, Field

try:
    from agent.policy_engine import PolicyComputationResult, compute_policy
    from agent.report_builder import NarrativeFragments, build_report
    from agent.validators import (
        ValidationViolation,
        validate_report_markdown,
        validate_structured_payload,
    )
except ModuleNotFoundError:
    # Supports running as: python agent/run_agent.py
    from policy_engine import PolicyComputationResult, compute_policy
    from report_builder import NarrativeFragments, build_report
    from validators import ValidationViolation, validate_report_markdown, validate_structured_payload

# Load .env from project root (one level up from agent/)
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"))

# ---------------------------------------------------------------------------
# Input Schemas (Pydantic v2)
# ---------------------------------------------------------------------------
Env = Literal["production", "non-production"]
Criticality = Literal["high", "medium", "low"]


class Asset(BaseModel):
    hostname: str
    owner_group: str
    environment: Env
    criticality: Criticality


class Fix(BaseModel):
    fix_title: str
    kenna_score: float = Field(ge=0, le=100)
    cvss: float = Field(ge=0, le=10)
    exploit_known: bool
    active_breach: bool = False
    has_malware: bool = False
    affected_hosts: int = Field(ge=0)
    requires_reboot: bool
    assets: List[Asset] = Field(default_factory=list)


class KennaInput(BaseModel):
    asset_group: str
    fixes: List[Fix]


# ---------------------------------------------------------------------------
# Output Schemas
# ---------------------------------------------------------------------------
PriorityLevel = Literal["High", "Medium", "Low"]
EstimatedRiskReduction = Literal["low", "moderate", "high"]


class PrioritizedFix(BaseModel):
    fix_title: str
    priority_score: float = Field(ge=0, le=1)
    priority_level: PriorityLevel
    owner_group: str
    recommended_action: Literal["Create Jira Ticket"] = "Create Jira Ticket"
    change_window_required: bool
    confidence: float = Field(ge=0, le=1)


class OutputSummary(BaseModel):
    total_fixes: int = Field(ge=0)
    high_priority_fixes: int = Field(ge=0)
    estimated_risk_reduction: EstimatedRiskReduction


class StructuredOutput(BaseModel):
    asset_group: str
    summary: OutputSummary
    prioritized_fixes: List[PrioritizedFix]


class AgentOutput(BaseModel):
    structured: StructuredOutput
    report: str


# ---------------------------------------------------------------------------
# LangGraph State
# ---------------------------------------------------------------------------
class AgentState(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    input_path: str
    prompt_path: str

    kenna_input: Optional[KennaInput] = None
    policy_result: Optional[PolicyComputationResult] = None
    narrative: Optional[NarrativeFragments] = None
    llm_raw: Optional[str] = None
    final: Optional[AgentOutput] = None
    audit: List[Dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------
def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _save_text(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _save_json(path: str, data: object) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _send_email(
    subject: str,
    body: str,
    recipients: List[str],
    sender: str,
    smtp_host: str,
    smtp_port: int = 25,
    use_starttls: bool = False,
    smtp_user: Optional[str] = None,
    smtp_pass: Optional[str] = None,
) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg.set_content(body)
    with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as s:
        s.ehlo()
        if use_starttls:
            s.starttls()
            s.ehlo()
        if smtp_user and smtp_pass:
            s.login(smtp_user, smtp_pass)
        s.send_message(msg)


def _preflight_paths(input_path: str, prompt_path: str) -> None:
    missing: List[str] = []
    if not os.path.exists(input_path):
        missing.append(f"Missing input file: {input_path}")
    if not os.path.exists(prompt_path):
        missing.append(f"Missing prompt file: {prompt_path}")
    if missing:
        msg = "\n".join(missing)
        msg += "\n\nExpected repo layout:\n"
        msg += "  - data/kenna_input_sanitized.json\n"
        msg += "  - prompt_template.md\n"
        msg += "\nTip: set KENNA_INPUT_PATH and PROMPT_PATH in .env (see .env.example).\n"
        raise RuntimeError(msg)


def _email_config_summary() -> Dict[str, Any]:
    recipients_env = os.getenv("REPORT_RECIPIENTS", "").strip()
    return {
        "SMTP_HOST": os.getenv("SMTP_HOST", "").strip() or None,
        "SMTP_PORT": int(os.getenv("SMTP_PORT", "25")),
        "SMTP_STARTTLS": os.getenv("SMTP_STARTTLS", "0"),
        "REPORT_SENDER": os.getenv("REPORT_SENDER", "").strip() or None,
        "REPORT_RECIPIENTS_SET": bool(recipients_env),
        "SMTP_AUTH_SET": bool(os.getenv("SMTP_USER")) and bool(os.getenv("SMTP_PASS")),
        "EMAIL_DRY_RUN": os.getenv("EMAIL_DRY_RUN", "1"),
    }


def _strip_markdown_fences(raw: str) -> str:
    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(lines[1:])
    if text.endswith("```"):
        lines = text.splitlines()
        text = "\n".join(lines[:-1])
    return text.strip()


def _parse_narrative(content: str) -> NarrativeFragments:
    raw = _strip_markdown_fences(content)
    payload = json.loads(raw)

    executive_summary = str(payload.get("executive_summary", "")).strip()

    fix_justifications: Dict[str, str] = {}
    for item in payload.get("fix_justifications", []):
        if not isinstance(item, dict):
            continue
        title = str(item.get("fix_title", "")).strip()
        justification = str(item.get("justification", "")).strip()
        if title and justification:
            fix_justifications[title] = justification

    action_packets: Dict[str, Dict[str, str]] = {}
    for item in payload.get("action_packets", []):
        if not isinstance(item, dict):
            continue
        title = str(item.get("fix_title", "")).strip()
        if not title:
            continue
        ticket_summary = str(item.get("ticket_summary", "")).strip()
        verification = str(item.get("verification", "")).strip()
        action_packets[title] = {
            "ticket_summary": ticket_summary,
            "verification": verification,
        }

    return NarrativeFragments(
        executive_summary=executive_summary,
        fix_justifications=fix_justifications,
        action_packets=action_packets,
    )


def _build_narrative_context(policy_result: PolicyComputationResult) -> Dict[str, object]:
    return {
        "asset_group": policy_result.asset_group,
        "summary": {
            "total_fixes": policy_result.total_fixes,
            "high_priority_fixes": policy_result.high_priority_fixes,
            "medium_priority_fixes": policy_result.medium_priority_fixes,
            "low_priority_fixes": policy_result.low_priority_fixes,
            "total_affected_hosts": policy_result.total_affected_hosts,
            "estimated_risk_reduction": policy_result.estimated_risk_reduction,
        },
        "fixes": [
            {
                "fix_title": fix.fix_title,
                "priority_level": fix.priority_level,
                "priority_score": fix.priority_score,
                "owner_group": fix.owner_group,
                "affected_hosts": fix.affected_hosts,
                "production_count": fix.production_count,
                "kenna_score": fix.kenna_score,
                "cvss": fix.cvss,
                "exploit_known": fix.exploit_known,
                "active_breach": fix.active_breach,
                "has_malware": fix.has_malware,
                "change_window_required": fix.change_window_required,
                "confidence": fix.confidence,
            }
            for fix in policy_result.computed_fixes
        ],
        "action_packet_titles": policy_result.action_packet_titles(),
    }


def _validate_candidate(
    candidate: AgentOutput,
    policy_result: PolicyComputationResult,
) -> List[ValidationViolation]:
    violations = validate_structured_payload(
        structured_model=StructuredOutput,
        structured_payload=candidate.structured.model_dump(),
        expected_fix_titles=policy_result.prioritized_titles(),
    )
    violations.extend(
        validate_report_markdown(
            report_markdown=candidate.report,
            expected_fix_titles=policy_result.prioritized_titles(),
            expected_action_titles=policy_result.action_packet_titles(),
        )
    )
    return violations


def _violations_text(violations: List[ValidationViolation]) -> str:
    return "; ".join(f"{v.code}: {v.message}" for v in violations)


def _audit_tool_call(
    state: AgentState,
    attempt: int,
    step_idx: int,
    tool: str,
    observation: str,
) -> None:
    state.audit.append(
        {
            "step": "reason_tool_call",
            "ts": _now(),
            "attempt": attempt,
            "tool_step": step_idx,
            "tool": tool,
            "observation": observation[:600],
        }
    )


# ---------------------------------------------------------------------------
# Node 1 — OBSERVE  (load, validate input, deterministic policy computation)
# ---------------------------------------------------------------------------
def node_observe(state: AgentState) -> AgentState:
    state.audit.append({"step": "observe_start", "ts": _now(), "path": state.input_path})

    raw = _load(state.input_path)
    payload = json.loads(raw)
    state.kenna_input = KennaInput.model_validate(payload)

    state.audit.append(
        {
            "step": "observe_done",
            "ts": _now(),
            "asset_group": state.kenna_input.asset_group,
            "fixes_loaded": len(state.kenna_input.fixes),
        }
    )

    state.policy_result = compute_policy(state.kenna_input.model_dump())
    state.audit.append(
        {
            "step": "policy_compute_done",
            "ts": _now(),
            "total_fixes": state.policy_result.total_fixes,
            "high_priority_fixes": state.policy_result.high_priority_fixes,
            "action_packet_fixes": len(state.policy_result.action_packet_titles()),
        }
    )
    return state


# ---------------------------------------------------------------------------
# Node 2 — REASON  (LLM narrative generation + strict validation)
# ---------------------------------------------------------------------------
def node_reason_llm(state: AgentState) -> AgentState:
    if state.policy_result is None:
        raise RuntimeError("node_observe must run before node_reason_llm")

    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key or api_key == "YOUR_KEY_HERE":
        raise RuntimeError(
            "OPENAI_API_KEY is not set.\n"
            "  1. Copy .env.example → .env\n"
            "  2. Add your OpenAI API key\n"
            "  3. Re-run the agent"
        )

    system_prompt = _load(state.prompt_path)
    narrative_context = _build_narrative_context(state.policy_result)

    model_name = os.getenv("OPENAI_MODEL", "gpt-4o")
    temperature = float(os.getenv("OPENAI_TEMPERATURE", "0.1"))
    max_attempts = int(os.getenv("LLM_RETRY_ATTEMPTS", "3"))

    llm = ChatOpenAI(model=model_name, temperature=temperature)

    state.audit.append(
        {
            "step": "reason_start",
            "ts": _now(),
            "provider": "openai",
            "model": model_name,
            "temperature": temperature,
            "max_attempts": max_attempts,
            "react_max_steps": int(os.getenv("REACT_MAX_STEPS", "8")),
        }
    )

    react_max_steps = int(os.getenv("REACT_MAX_STEPS", "8"))
    repair_instruction = ""
    last_error = "Unknown validation failure"

    for attempt in range(1, max_attempts + 1):
        step_idx = 0
        tool = "load_context"
        llm_response = ""
        parsed_narrative: Optional[NarrativeFragments] = None
        candidate: Optional[AgentOutput] = None
        violations: List[ValidationViolation] = []

        retry_required = False
        try:
            while step_idx < react_max_steps:
                step_idx += 1
                if tool == "load_context":
                    _audit_tool_call(
                        state=state,
                        attempt=attempt,
                        step_idx=step_idx,
                        tool=tool,
                        observation=f"context_fixes={len(narrative_context['fixes'])}",
                    )
                    tool = "invoke_llm"
                    continue

                if tool == "invoke_llm":
                    user_prompt = (
                        "NARRATIVE_CONTEXT_JSON:\n"
                        + json.dumps(narrative_context, indent=2)
                        + "\n\nReturn JSON only."
                    )
                    if repair_instruction:
                        user_prompt += "\n\nREPAIR_REQUEST:\n" + repair_instruction

                    response = llm.invoke(
                        [
                            SystemMessage(content=system_prompt),
                            HumanMessage(content=user_prompt),
                        ]
                    )
                    llm_response = str(response.content)
                    state.llm_raw = llm_response
                    _audit_tool_call(
                        state=state,
                        attempt=attempt,
                        step_idx=step_idx,
                        tool=tool,
                        observation=f"response_chars={len(llm_response)}",
                    )
                    tool = "parse_narrative"
                    continue

                if tool == "parse_narrative":
                    parsed_narrative = _parse_narrative(llm_response)
                    _audit_tool_call(
                        state=state,
                        attempt=attempt,
                        step_idx=step_idx,
                        tool=tool,
                        observation=(
                            "parsed_fields="
                            f"{len(parsed_narrative.fix_justifications)}_fix_justifications,"
                            f"{len(parsed_narrative.action_packets)}_action_packets"
                        ),
                    )
                    tool = "build_candidate"
                    continue

                if tool == "build_candidate":
                    if parsed_narrative is None:
                        raise RuntimeError("Narrative must be parsed before building candidate")
                    report = build_report(state.policy_result, parsed_narrative)
                    candidate = AgentOutput.model_validate(
                        {
                            "structured": state.policy_result.as_structured_payload(),
                            "report": report,
                        }
                    )
                    _audit_tool_call(
                        state=state,
                        attempt=attempt,
                        step_idx=step_idx,
                        tool=tool,
                        observation=f"report_chars={len(report)}",
                    )
                    tool = "validate_output"
                    continue

                if tool == "validate_output":
                    if candidate is None:
                        raise RuntimeError("Candidate output missing before validation")
                    violations = _validate_candidate(
                        candidate=candidate,
                        policy_result=state.policy_result,
                    )
                    _audit_tool_call(
                        state=state,
                        attempt=attempt,
                        step_idx=step_idx,
                        tool=tool,
                        observation=f"violations={len(violations)}",
                    )
                    if violations:
                        violation_dicts = [v.as_dict() for v in violations]
                        state.audit.append(
                            {
                                "step": "validation_failed",
                                "ts": _now(),
                                "attempt": attempt,
                                "violations": violation_dicts,
                            }
                        )
                        last_error = _violations_text(violations)
                        repair_instruction = (
                            "Fix these validation issues exactly and return JSON only: "
                            + last_error
                        )
                        retry_required = True
                    else:
                        state.narrative = parsed_narrative
                        state.final = candidate
                    break

                raise RuntimeError(f"Unknown ReAct tool step: {tool}")

            if retry_required:
                state.audit.append(
                    {
                        "step": "reason_retry",
                        "ts": _now(),
                        "attempt": attempt,
                        "reason": last_error,
                    }
                )
                continue

            if state.final is not None:
                state.audit.append({"step": "reason_done", "ts": _now(), "attempt": attempt})
                state.audit.append(
                    {
                        "step": "final_validation_passed",
                        "ts": _now(),
                        "attempt": attempt,
                    }
                )
                return state

            last_error = "ReAct loop reached step bound without producing output"
            state.audit.append(
                {
                    "step": "reason_retry",
                    "ts": _now(),
                    "attempt": attempt,
                    "reason": last_error,
                }
            )

        except Exception as exc:
            last_error = str(exc)
            state.audit.append(
                {
                    "step": "reason_retry",
                    "ts": _now(),
                    "attempt": attempt,
                    "reason": last_error,
                }
            )
            repair_instruction = (
                "Previous response was invalid. Return strict JSON only using the requested schema. "
                f"Error: {last_error}"
            )

    raise RuntimeError(f"LLM failed after {max_attempts} attempts. Last error: {last_error}")


# ---------------------------------------------------------------------------
# Node 3 — ACT  (persist outputs + optional email)
# ---------------------------------------------------------------------------
def node_act(state: AgentState) -> AgentState:
    if state.final is None:
        raise RuntimeError("No final output to write — node_reason_llm may have failed")

    _save_json("outputs/structured.json", state.final.structured.model_dump())
    _save_text("outputs/report.md", state.final.report)
    _save_json("outputs/audit_log.json", state.audit)

    state.audit.append({"step": "outputs_written", "ts": _now()})

    recipients_env = os.getenv("REPORT_RECIPIENTS", "").strip()
    smtp_host = os.getenv("SMTP_HOST", "").strip()
    sender = os.getenv("REPORT_SENDER", "").strip()

    dry_run = os.getenv("EMAIL_DRY_RUN", "1") == "1"

    if recipients_env and smtp_host and sender and not dry_run:
        recipients = [r.strip() for r in recipients_env.split(",") if r.strip()]
        subject = f"[Kenna Agent] Remediation Report — {state.final.structured.asset_group}"
        try:
            _send_email(
                subject=subject,
                body=state.final.report,
                recipients=recipients,
                sender=sender,
                smtp_host=smtp_host,
                smtp_port=int(os.getenv("SMTP_PORT", "25")),
                use_starttls=(os.getenv("SMTP_STARTTLS", "0") == "1"),
                smtp_user=os.getenv("SMTP_USER") or None,
                smtp_pass=os.getenv("SMTP_PASS") or None,
            )
            state.audit.append({"step": "email_sent", "ts": _now(), "recipients": recipients})
        except Exception as exc:
            state.audit.append({"step": "email_failed", "ts": _now(), "error": str(exc)})
    else:
        reason = "EMAIL_DRY_RUN=1" if dry_run else "SMTP not configured"
        state.audit.append({"step": "email_skipped", "ts": _now(), "reason": reason})

    _save_json("outputs/audit_log.json", state.audit)
    return state


# ---------------------------------------------------------------------------
# Build & run graph
# ---------------------------------------------------------------------------
def build_graph():
    g = StateGraph(AgentState)
    g.add_node("observe", node_observe)
    g.add_node("reason_llm", node_reason_llm)
    g.add_node("act", node_act)
    g.set_entry_point("observe")
    g.add_edge("observe", "reason_llm")
    g.add_edge("reason_llm", "act")
    g.add_edge("act", END)
    return g.compile()


def main() -> None:
    print("=" * 70)
    print("🛡️  Kenna Remediation Orchestration Agent  (GRAD 5900)")
    print("=" * 70)
    print()

    real_input = "data/kenna_input.json"
    sanitized_input = "data/kenna_input_sanitized.json"
    default_input = real_input if os.path.exists(real_input) else sanitized_input
    input_path = os.getenv("KENNA_INPUT_PATH", default_input)
    prompt_path = os.getenv("PROMPT_PATH", "prompt_template.md")

    _preflight_paths(input_path=input_path, prompt_path=prompt_path)

    source_label = "⚠️  REAL DATA" if input_path == real_input else "✅ sanitized"
    print(f"   Input  : {input_path}  [{source_label}]")
    print(f"   Prompt : {prompt_path}")
    print(f"   Model  : {os.getenv('OPENAI_MODEL', 'gpt-4o')}")
    print(f"   Email  : {_email_config_summary()}")
    print()

    graph = build_graph()
    init = AgentState(input_path=input_path, prompt_path=prompt_path)

    try:
        graph.invoke(init)
        print("✅  Done!  Generated:")
        print("     outputs/report.md        ← executive report")
        print("     outputs/structured.json  ← machine-readable output")
        print("     outputs/audit_log.json   ← full execution trace")
        print()
    except Exception as exc:
        print(f"\n❌  Error: {exc}")
        raise


if __name__ == "__main__":
    main()
