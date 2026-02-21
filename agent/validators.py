from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List

from pydantic import ValidationError


@dataclass(frozen=True)
class ValidationViolation:
    code: str
    message: str

    def as_dict(self) -> Dict[str, str]:
        return {"code": self.code, "message": self.message}


def validate_structured_payload(
    structured_model,
    structured_payload: Dict[str, object],
    expected_fix_titles: List[str],
) -> List[ValidationViolation]:
    violations: List[ValidationViolation] = []

    try:
        validated = structured_model.model_validate(structured_payload)
    except ValidationError as exc:
        violations.append(
            ValidationViolation(code="structured_schema", message=str(exc))
        )
        return violations

    fixes = list(validated.prioritized_fixes)
    if len(fixes) != len(expected_fix_titles):
        violations.append(
            ValidationViolation(
                code="structured_count",
                message=(
                    f"prioritized_fixes count={len(fixes)} does not match expected={len(expected_fix_titles)}"
                ),
            )
        )

    titles = [fix.fix_title for fix in fixes]
    duplicates = sorted({title for title in titles if titles.count(title) > 1})
    if duplicates:
        violations.append(
            ValidationViolation(
                code="structured_duplicate_titles",
                message=f"duplicate fix titles in structured output: {duplicates}",
            )
        )

    missing = sorted(set(expected_fix_titles) - set(titles))
    extras = sorted(set(titles) - set(expected_fix_titles))
    if missing:
        violations.append(
            ValidationViolation(
                code="structured_missing_titles",
                message=f"missing titles in structured output: {missing}",
            )
        )
    if extras:
        violations.append(
            ValidationViolation(
                code="structured_extra_titles",
                message=f"unexpected titles in structured output: {extras}",
            )
        )

    for fix in fixes:
        if fix.recommended_action != "Create Jira Ticket":
            violations.append(
                ValidationViolation(
                    code="structured_action",
                    message=(
                        f"recommended_action for '{fix.fix_title}' is '{fix.recommended_action}' "
                        "but must be 'Create Jira Ticket'"
                    ),
                )
            )

    scores = [fix.priority_score for fix in fixes]
    if scores != sorted(scores, reverse=True):
        violations.append(
            ValidationViolation(
                code="structured_sort_order",
                message="prioritized_fixes are not sorted by priority_score descending",
            )
        )

    return violations


def validate_report_markdown(
    report_markdown: str,
    expected_fix_titles: List[str],
    expected_action_titles: List[str],
) -> List[ValidationViolation]:
    violations: List[ValidationViolation] = []

    required_headers = [
        "## Executive Summary",
        "## Priority Fixes",
        "## Ownership Routing",
        "## Governance Notes",
        "## Action Packet (Phase 1 / Future AAP)",
    ]

    positions = []
    for header in required_headers:
        idx = report_markdown.find(header)
        if idx < 0:
            violations.append(
                ValidationViolation(
                    code="report_missing_header",
                    message=f"missing required header: {header}",
                )
            )
        positions.append(idx)

    valid_positions = [pos for pos in positions if pos >= 0]
    if valid_positions and valid_positions != sorted(valid_positions):
        violations.append(
            ValidationViolation(
                code="report_header_order",
                message="report headers are not in required order",
            )
        )

    priority_matches = re.findall(
        r"^###\s+\d+\.\s+\[(?:High|Medium|Low)\]\s+(.+)$",
        report_markdown,
        flags=re.MULTILINE,
    )
    priority_titles = [title.strip() for title in priority_matches]

    if len(priority_titles) != len(expected_fix_titles):
        violations.append(
            ValidationViolation(
                code="report_priority_count",
                message=(
                    f"priority entries count={len(priority_titles)} does not match expected={len(expected_fix_titles)}"
                ),
            )
        )

    duplicates = sorted({title for title in priority_titles if priority_titles.count(title) > 1})
    if duplicates:
        violations.append(
            ValidationViolation(
                code="report_priority_duplicates",
                message=f"duplicate Priority Fixes titles: {duplicates}",
            )
        )

    missing_priority = sorted(set(expected_fix_titles) - set(priority_titles))
    extra_priority = sorted(set(priority_titles) - set(expected_fix_titles))
    if missing_priority:
        violations.append(
            ValidationViolation(
                code="report_priority_missing",
                message=f"missing Priority Fixes entries: {missing_priority}",
            )
        )
    if extra_priority:
        violations.append(
            ValidationViolation(
                code="report_priority_extra",
                message=f"unexpected Priority Fixes entries: {extra_priority}",
            )
        )

    action_matches = re.findall(
        r"^### Action Packet — (.+)$",
        report_markdown,
        flags=re.MULTILINE,
    )
    action_titles = [title.strip() for title in action_matches]

    if len(action_titles) != len(expected_action_titles):
        violations.append(
            ValidationViolation(
                code="report_action_count",
                message=(
                    f"action packet entries count={len(action_titles)} does not match expected={len(expected_action_titles)}"
                ),
            )
        )

    action_duplicates = sorted({title for title in action_titles if action_titles.count(title) > 1})
    if action_duplicates:
        violations.append(
            ValidationViolation(
                code="report_action_duplicates",
                message=f"duplicate Action Packet titles: {action_duplicates}",
            )
        )

    missing_action = sorted(set(expected_action_titles) - set(action_titles))
    extra_action = sorted(set(action_titles) - set(expected_action_titles))
    if missing_action:
        violations.append(
            ValidationViolation(
                code="report_action_missing",
                message=f"missing Action Packet entries: {missing_action}",
            )
        )
    if extra_action:
        violations.append(
            ValidationViolation(
                code="report_action_extra",
                message=f"unexpected Action Packet entries: {extra_action}",
            )
        )

    return violations
