from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable

try:
    from agent.policy_engine import ComputedFix, PolicyComputationResult
except ModuleNotFoundError:
    from policy_engine import ComputedFix, PolicyComputationResult


@dataclass(frozen=True)
class NarrativeFragments:
    executive_summary: str
    fix_justifications: Dict[str, str]
    action_packets: Dict[str, Dict[str, str]]


DEFAULT_IMPLICATION = "Prioritize remediation based on combined exposure, exploitability, and production impact."


def _risk_implication(fix: ComputedFix) -> str:
    if fix.active_breach:
        return "Active breach signal increases urgency for immediate containment and patch scheduling."
    if fix.has_malware:
        return "Malware association increases urgency due to potential active compromise paths."
    if fix.exploit_known and fix.production_count > 0 and fix.affected_hosts >= 100:
        return "Broad production exposure with known exploit creates the largest immediate attack surface."
    if fix.exploit_known and fix.production_count > 0:
        return "Known exploit on production assets elevates near-term exploitation risk."
    if fix.change_window_required:
        return "Reboot requirement introduces operational coordination risk that should be scheduled promptly."
    if fix.affected_hosts >= 100:
        return "Large affected host volume increases blast radius if left unaddressed."
    return DEFAULT_IMPLICATION


def deterministic_justification(fix: ComputedFix) -> str:
    exploit_text = "Exploit known." if fix.exploit_known else "No exploit known."
    breach_text = "yes" if fix.active_breach else "no"
    return (
        f"{fix.affected_hosts} hosts affected across {fix.production_count} production asset(s) sampled. "
        f"Kenna score {fix.kenna_score}, CVSS {fix.cvss}. "
        f"{exploit_text} Active breach: {breach_text}. "
        f"{_risk_implication(fix)}"
    )


def _clean_line(value: str) -> str:
    return " ".join(value.replace("\n", " ").split()).strip()


def _effective_justification(fix: ComputedFix, narrative: NarrativeFragments) -> str:
    candidate = _clean_line(narrative.fix_justifications.get(fix.fix_title, ""))
    if candidate:
        return candidate
    return deterministic_justification(fix)


def _action_packet_value(
    fix: ComputedFix,
    narrative: NarrativeFragments,
    key: str,
    fallback: str,
) -> str:
    payload = narrative.action_packets.get(fix.fix_title, {})
    candidate = _clean_line(payload.get(key, ""))
    return candidate or fallback


def _list_titles(titles: Iterable[str]) -> str:
    values = [title for title in titles if title]
    return ", ".join(values) if values else "None"


def build_report(result: PolicyComputationResult, narrative: NarrativeFragments) -> str:
    lines = [
        "# Vulnerability Remediation Report",
        "",
        "## Executive Summary",
        "",
        f"**Asset Group:** {result.asset_group}",
        f"**Total Fixes:** {result.total_fixes}",
        f"**High Priority Fixes:** {result.high_priority_fixes}",
        f"**Estimated Risk Reduction:** {result.estimated_risk_reduction}",
        "",
    ]

    if narrative.executive_summary.strip():
        lines.append(narrative.executive_summary.strip())
    else:
        lines.append(
            ""
            f"The report identifies {result.high_priority_fixes} high-priority fixes, "
            f"{result.medium_priority_fixes} medium-priority fixes, and {result.low_priority_fixes} low-priority fixes "
            f"affecting a total of {result.total_affected_hosts} hosts. Immediate action should begin with the "
            f"highest-ranked production-exposed items."
        )
    lines.extend(["", "## Priority Fixes", ""])

    for idx, fix in enumerate(result.computed_fixes, start=1):
        lines.extend(
            [
                f"### {idx}. [{fix.priority_level}] {fix.fix_title}",
                "",
                f"- **Owner Team:** {fix.owner_group}",
                f"- **Affected Hosts:** {fix.affected_hosts}",
                f"- **Priority Score:** {fix.priority_score}",
                f"- **Kenna Score:** {fix.kenna_score} | **CVSS:** {fix.cvss}",
                f"- **Exploit Known:** {'Yes' if fix.exploit_known else 'No'}",
                "- **Action Required:** Create Jira Ticket",
                f"- **Change Window:** {'Required' if fix.change_window_required else 'Not Required'}",
                f"- **Confidence:** {round(fix.confidence * 100)}%",
                "",
                _effective_justification(fix=fix, narrative=narrative),
                "",
            ]
        )

    lines.extend(["## Ownership Routing", "", "Tickets will be created and assigned to:"])
    for owner, count in sorted(result.owner_ticket_counts.items(), key=lambda x: (-x[1], x[0])):
        lines.append(f"- {owner}: {count} ticket(s)")

    lines.extend(
        [
            "",
            "## Governance Notes",
            "",
            f"- **Total affected hosts (sum across all fixes):** {result.total_affected_hosts}",
            f"- **Production systems affected:** {result.production_fixes_count}",
            f"- **Change windows required:** {len(result.change_window_titles)} fix(es) — "
            f"{_list_titles(result.change_window_titles)}",
            f"- **Active exploits detected:** {len(result.exploit_titles)} fix(es) — "
            f"{_list_titles(result.exploit_titles)}",
            f"- **High-confidence urgent items (confidence >= 0.90):** "
            f"{_list_titles(result.high_confidence_titles)}",
            "",
            "## Action Packet (Phase 1 / Future AAP)",
            "",
        ]
    )

    for fix in result.computed_fixes:
        if fix.priority_level not in {"High", "Medium"}:
            continue

        lines.extend(
            [
                f"### Action Packet — {fix.fix_title}",
                "",
                "- **Recommended Immediate Action (Phase 1):** Create Jira Ticket",
                "- **Ticket Summary:** "
                + _action_packet_value(
                    fix,
                    narrative,
                    key="ticket_summary",
                    fallback=(
                        f"Patch {fix.fix_title} affecting {fix.affected_hosts} host(s) "
                        f"with priority {fix.priority_level}."
                    ),
                ),
                f"- **Owner Group:** {fix.owner_group}",
                f"- **Priority Level:** {fix.priority_level}",
                f"- **Change Window Required:** {str(fix.change_window_required).lower()}",
                "- **Evidence (from input only): "
                f"kenna_score={fix.kenna_score}, cvss={fix.cvss}, "
                f"exploit_known={str(fix.exploit_known).lower()}, "
                f"active_breach={str(fix.active_breach).lower()}, "
                f"has_malware={str(fix.has_malware).lower()}, "
                f"affected_hosts={fix.affected_hosts}",
                "- **Verification (Read-only): "
                + _action_packet_value(
                    fix,
                    narrative,
                    key="verification",
                    fallback=(
                        f"Confirm affected host count ({fix.affected_hosts}) and production sample "
                        f"coverage ({fix.production_count}) before ticket dispatch."
                    ),
                ),
                "- **Future Automation Hook (Phase 2):** AAP Job Template: <TBD>",
                "",
            ]
        )

    return "\n".join(lines).strip() + "\n"
