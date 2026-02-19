
# Policy-Aware Vulnerability Remediation Orchestration Agent

**Course:** Applied Agentic AI (Graduate Level)  
**Student:** Bharani  
**Domain:** UConn IT Infrastructure – Server Operations  

---

# 1. Problem Statement

Cisco Kenna (Vulnerability Management) provides risk scores, vulnerability findings, and remediation groupings. However:

- Reports are static and descriptive.
- Prioritization is not aligned with internal ownership structures.
- Remediation requires manual ticket creation.
- Risk intelligence is not automatically converted into governance-aligned operational workflows.

There exists a gap between vulnerability intelligence and operational execution.

---

# 2. Project Objective

Design and implement a policy-aware AI agent that:

1. Retrieves vulnerability fix data from Kenna API.
2. Enriches assets using Jira Assets ownership records.
3. Applies structured decision policies to prioritize remediation.
4. Generates both:
   - Human-readable remediation report
   - Structured JSON remediation plan
5. Automatically creates Jira ticket(s) assigned to the appropriate owner group.

The system transforms static vulnerability reporting into actionable, ownership-aware remediation workflows.

---

# 3. System Architecture

## High-Level Flow

```
Kenna API
   ↓
Agent Core (Reasoning + Policy Engine)
   ↓
Jira Assets (Ownership Lookup)
   ↓
Jira Ticket Creation API
```

---

# 4. Agentic Framework

The system follows an Observe → Reason → Act loop.

## 4.1 Observe
- Retrieve open fixes from Kenna API.
- Retrieve affected assets per fix.
- Retrieve ownership metadata from Jira Assets.

## 4.2 Reason
- Rank fixes using defined prioritization model.
- Evaluate governance constraints:
  - Production vs non-production
  - Exploitability
  - Reboot requirement
  - Asset criticality
- Assign:
  - Priority level
  - Recommended action
  - Confidence score

## 4.3 Act
- Generate structured remediation output.
- Create Jira ticket(s) assigned to Windows Management Team (Server Group).

---

# 5. Data Sources

## 5.1 Kenna API
- Open fixes
- Risk scores
- CVSS values
- Exploitability indicators
- Affected assets

## 5.2 Jira Assets
- Asset ownership mapping
- Team/group assignment
- Asset classification

## 5.3 Jira Ticketing API
- Create issue
- Assign owner group
- Set priority

---

# 6. Phase 1 – Baseline Agent Implementation (Assignment 1)

The baseline implementation includes:

- Retrieval of top N fixes for a selected asset group (e.g., Windows Servers).
- Ownership enrichment via Jira Assets.
- Priority ranking using defined scoring model.
- Generation of:
  - Human-readable remediation report (Markdown)
  - Structured JSON output
- Automatic creation of Jira ticket(s) for Windows Management Team.

The system will not execute automated remediation in this phase.

---

# 7. Prioritization Model

## Composite Priority Score

Priority Score =
  (Kenna Score × 0.4)
+ (CVSS × 0.2)
+ (Exploitability Flag × 0.2)
+ (Asset Criticality × 0.1)
+ (Affected Host Count Normalized × 0.1)

## Policy Rules

| Condition | Action |
|------------|--------|
| Exploit known + Production | High Priority Ticket |
| Medium risk | Standard Priority Ticket |
| Low risk | Include in backlog summary |
| Reboot required | Mark as "Change Window Required" |

---

# 8. Structured Output Schema

```json
{
  "asset_group": "Windows Servers",
  "summary": {
    "total_assets": 34,
    "total_vulnerabilities": 1284,
    "unique_fixes": 5
  },
  "prioritized_fixes": [
    {
      "fix_title": "KB503xxxx Security Update",
      "priority_score": 0.87,
      "priority_level": "High",
      "owner_group": "Windows Management Team",
      "recommended_action": "Create Jira Ticket",
      "change_window_required": true,
      "confidence": 0.81
    }
  ]
}
```

---

# 9. Human-Readable Report Format

## Executive Summary
- Total affected assets
- Number of high-priority fixes
- Recommended immediate actions

## Priority Fixes
- Fix title
- Affected hosts
- Owner group
- Required action
- Change window requirement

## Governance Notes
- Production systems impacted
- Approval or scheduling considerations

---

# 10. Agent Prompt Specification

## System Role

The agent operates as a policy-aware vulnerability remediation assistant in an enterprise IT environment.

It must:
- Analyze Kenna fix data.
- Apply prioritization policy.
- Assign owner group.
- Recommend Jira ticket creation.
- Produce structured JSON and Markdown report.

It must not:
- Invent teams or playbooks.
- Perform remediation actions.
- Output reasoning trace.

Temperature: 0–0.2 behavior.

---

## Required Output Structure

```json
{
  "structured": {
    "asset_group": "...",
    "summary": {
      "total_fixes": number,
      "high_priority_fixes": number,
      "estimated_risk_reduction": "low|moderate|high"
    },
    "prioritized_fixes": [
      {
        "fix_title": "...",
        "priority_score": number,
        "priority_level": "High|Medium|Low",
        "owner_group": "...",
        "recommended_action": "Create Jira Ticket",
        "change_window_required": true/false,
        "confidence": number
      }
    ]
  },
  "report": "Markdown formatted remediation report"
}
```

---

# 11. Real-World Action Definition

The agent will:

- Create Jira issue(s) via API.
- Assign to Windows Management Team.
- Populate structured remediation details.
- Set priority according to policy score.

No automated system changes will occur in Phase 1.

---

# 12. Evaluation Metrics

To measure improvement across the semester:

- Fix prioritization accuracy vs human baseline.
- Ticket modification rate after agent creation.
- False prioritization rate.
- Estimated reduction in manual triage time.
- Weekly Kenna score delta after remediation.

---

# 13. Governance and Risk Controls

- No automated remediation in production.
- All decisions logged for auditability.
- Structured output validated before ticket creation.
- Action set limited to Jira ticket creation.

---

# 14. Future Enhancements

- Zabbix operational alert correlation.
- AAP workflow approval integration.
- Confidence-based automation thresholds.
- Multi-team routing.
- Self-evaluation feedback loop.
- Risk trend dashboard.

---

# 15. Summary

This project develops a policy-aware, ownership-aware vulnerability remediation orchestration agent that integrates Kenna intelligence with enterprise asset data to produce structured, governance-aligned remediation workflows.

It demonstrates:

- Tool-based reasoning
- Structured decision-making
- Policy enforcement
- Controlled real-world action
- Iterative improvement capability
"""

output_path = "/mnt/data/spec.md"
pypandoc.convert_text(spec_content, 'md', format='md', outputfile=output_path, extra_args=['--standalone'])

output_path
