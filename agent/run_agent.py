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

# Load .env from project root (one level up from agent/)
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"))

# ---------------------------------------------------------------------------
# Input Schemas (Pydantic v2)
# ---------------------------------------------------------------------------
Env          = Literal["production", "non-production"]
Criticality  = Literal["high", "medium", "low"]


class Asset(BaseModel):
    hostname:    str
    owner_group: str
    environment: Env
    criticality: Criticality


class Fix(BaseModel):
    fix_title:      str
    kenna_score:    float = Field(ge=0, le=100)
    cvss:           float = Field(ge=0, le=10)
    exploit_known:  bool
    affected_hosts: int   = Field(ge=0)
    requires_reboot: bool
    assets:         List[Asset] = Field(default_factory=list)


class KennaInput(BaseModel):
    asset_group: str
    fixes:       List[Fix]


# ---------------------------------------------------------------------------
# Output Schemas
# ---------------------------------------------------------------------------
PriorityLevel        = Literal["High", "Medium", "Low"]
EstimatedRiskReduction = Literal["low", "moderate", "high"]


class PrioritizedFix(BaseModel):
    fix_title:             str
    priority_score:        float = Field(ge=0, le=1)
    priority_level:        PriorityLevel
    owner_group:           str
    recommended_action:    Literal["Create Jira Ticket"] = "Create Jira Ticket"
    change_window_required: bool
    confidence:            float = Field(ge=0, le=1)


class OutputSummary(BaseModel):
    total_fixes:              int = Field(ge=0)
    high_priority_fixes:      int = Field(ge=0)
    estimated_risk_reduction: EstimatedRiskReduction


class StructuredOutput(BaseModel):
    asset_group:      str
    summary:          OutputSummary
    prioritized_fixes: List[PrioritizedFix]


class AgentOutput(BaseModel):
    structured: StructuredOutput
    report:     str


# ---------------------------------------------------------------------------
# LangGraph State
# ---------------------------------------------------------------------------
class AgentState(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    input_path:  str
    prompt_path: str

    kenna_input: Optional[KennaInput]  = None
    llm_raw:     Optional[str]         = None
    final:       Optional[AgentOutput] = None
    audit:       List[Dict[str, Any]]  = Field(default_factory=list)


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
    msg["From"]    = sender
    msg["To"]      = ", ".join(recipients)
    msg.set_content(body)
    with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as s:
        s.ehlo()
        if use_starttls:
            s.starttls()
            s.ehlo()
        if smtp_user and smtp_pass:
            s.login(smtp_user, smtp_pass)
        s.send_message(msg)


# ---------------------------------------------------------------------------
# Node 1 — OBSERVE  (load & validate input)
# ---------------------------------------------------------------------------
def node_observe(state: AgentState) -> AgentState:
    state.audit.append({"step": "observe_start", "ts": _now(), "path": state.input_path})

    raw     = _load(state.input_path)
    payload = json.loads(raw)
    state.kenna_input = KennaInput.model_validate(payload)

    state.audit.append({
        "step":         "observe_done",
        "ts":           _now(),
        "asset_group":  state.kenna_input.asset_group,
        "fixes_loaded": len(state.kenna_input.fixes),
    })
    return state


# ---------------------------------------------------------------------------
# Node 2 — REASON  (LLM reasoning + output validation)
# ---------------------------------------------------------------------------
def node_reason_llm(state: AgentState) -> AgentState:
    if state.kenna_input is None:
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
    user_payload  = state.kenna_input.model_dump()
    user_prompt   = "INPUT_JSON:\n" + json.dumps(user_payload, indent=2)

    model_name    = os.getenv("OPENAI_MODEL", "gpt-4o")
    temperature   = float(os.getenv("OPENAI_TEMPERATURE", "0.1"))

    llm = ChatOpenAI(model=model_name, temperature=temperature)

    state.audit.append({
        "step":        "reason_start",
        "ts":          _now(),
        "provider":    "openai",
        "model":       model_name,
        "temperature": temperature,
    })

    last_err: Optional[str] = None
    for attempt in range(1, 4):
        try:
            response      = llm.invoke([
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_prompt),
            ])
            state.llm_raw = response.content

            # Strip accidental markdown fences
            raw = state.llm_raw.strip()
            if raw.startswith("```"):
                raw = "\n".join(raw.split("\n")[1:])
            if raw.endswith("```"):
                raw = "\n".join(raw.split("\n")[:-1])

            data        = json.loads(raw)
            state.final = AgentOutput.model_validate(data)

            state.audit.append({"step": "reason_done", "ts": _now(), "attempt": attempt})
            return state

        except Exception as exc:
            last_err = str(exc)
            state.audit.append({
                "step":    "reason_retry",
                "ts":      _now(),
                "attempt": attempt,
                "error":   last_err,
            })
            # Augment prompt with repair instruction
            user_prompt = (
                "INPUT_JSON:\n"
                + json.dumps(user_payload, indent=2)
                + "\n\n⚠️ REPAIR REQUIRED: Return ONLY valid JSON — no markdown fences, "
                "no extra text. Match the schema exactly.\n"
                f"Previous parse error: {last_err}"
            )

    raise RuntimeError(f"LLM failed after 3 attempts. Last error: {last_err}")


# ---------------------------------------------------------------------------
# Node 3 — ACT  (persist outputs + optional email)
# ---------------------------------------------------------------------------
def node_act(state: AgentState) -> AgentState:
    if state.final is None:
        raise RuntimeError("No final output to write — node_reason_llm may have failed")

    # ---- Persist structured outputs ----
    _save_json("outputs/structured.json", state.final.structured.model_dump())
    _save_text("outputs/report.md",        state.final.report)
    _save_json("outputs/audit_log.json",   state.audit)

    state.audit.append({"step": "outputs_written", "ts": _now()})

    # ---- Optional email ----
    recipients_env = os.getenv("REPORT_RECIPIENTS", "").strip()
    smtp_host      = os.getenv("SMTP_HOST",          "").strip()
    sender         = os.getenv("REPORT_SENDER",       "").strip()

    if recipients_env and smtp_host and sender:
        recipients = [r.strip() for r in recipients_env.split(",") if r.strip()]
        subject    = (
            f"[Kenna Agent] Remediation Report — "
            f"{state.final.structured.asset_group}"
        )
        try:
            _send_email(
                subject    = subject,
                body       = state.final.report,
                recipients = recipients,
                sender     = sender,
                smtp_host  = smtp_host,
                smtp_port  = int(os.getenv("SMTP_PORT",     "25")),
                use_starttls=(os.getenv("SMTP_STARTTLS", "0") == "1"),
                smtp_user  = os.getenv("SMTP_USER") or None,
                smtp_pass  = os.getenv("SMTP_PASS") or None,
            )
            state.audit.append({"step": "email_sent", "ts": _now(), "recipients": recipients})
        except Exception as exc:
            state.audit.append({"step": "email_failed", "ts": _now(), "error": str(exc)})
    else:
        state.audit.append({"step": "email_skipped", "ts": _now(), "reason": "SMTP not configured"})

    # Write final audit (with email step recorded)
    _save_json("outputs/audit_log.json", state.audit)

    return state


# ---------------------------------------------------------------------------
# Build & run graph
# ---------------------------------------------------------------------------
def build_graph():
    g = StateGraph(AgentState)
    g.add_node("observe",    node_observe)
    g.add_node("reason_llm", node_reason_llm)
    g.add_node("act",        node_act)
    g.set_entry_point("observe")
    g.add_edge("observe",    "reason_llm")
    g.add_edge("reason_llm", "act")
    g.add_edge("act",        END)
    return g.compile()


def main() -> None:
    print("=" * 70)
    print("🛡️  Kenna Remediation Orchestration Agent  (GRAD 5900)")
    print("=" * 70)
    print()

    input_path  = os.getenv("KENNA_INPUT_PATH", "data/kenna_input_sanitized.json")
    prompt_path = os.getenv("PROMPT_PATH",      "prompt_template.md")

    print(f"   Input  : {input_path}")
    print(f"   Prompt : {prompt_path}")
    print(f"   Model  : {os.getenv('OPENAI_MODEL', 'gpt-4o')}")
    print()

    graph = build_graph()
    init  = AgentState(input_path=input_path, prompt_path=prompt_path)

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
