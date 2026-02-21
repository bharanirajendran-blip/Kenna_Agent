from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Literal

PriorityLevel = Literal["High", "Medium", "Low"]
EstimatedRiskReduction = Literal["low", "moderate", "high"]

CRITICALITY_WEIGHTS = {
    "high": 1.0,
    "medium": 0.5,
    "low": 0.2,
}


@dataclass(frozen=True)
class ComputedFix:
    fix_title: str
    kenna_score: float
    cvss: float
    exploit_known: bool
    active_breach: bool
    has_malware: bool
    affected_hosts: int
    requires_reboot: bool
    owner_group: str
    production_count: int
    priority_score: float
    priority_level: PriorityLevel
    change_window_required: bool
    confidence: float


@dataclass(frozen=True)
class PolicyComputationResult:
    asset_group: str
    computed_fixes: List[ComputedFix]
    total_fixes: int
    high_priority_fixes: int
    estimated_risk_reduction: EstimatedRiskReduction
    owner_ticket_counts: Dict[str, int]
    total_affected_hosts: int
    production_fixes_count: int
    change_window_titles: List[str]
    exploit_titles: List[str]
    high_confidence_titles: List[str]
    medium_priority_fixes: int
    low_priority_fixes: int

    def prioritized_titles(self) -> List[str]:
        return [fix.fix_title for fix in self.computed_fixes]

    def action_packet_titles(self) -> List[str]:
        return [
            fix.fix_title
            for fix in self.computed_fixes
            if fix.priority_level in {"High", "Medium"}
        ]

    def as_structured_payload(self) -> Dict[str, object]:
        return {
            "asset_group": self.asset_group,
            "summary": {
                "total_fixes": self.total_fixes,
                "high_priority_fixes": self.high_priority_fixes,
                "estimated_risk_reduction": self.estimated_risk_reduction,
            },
            "prioritized_fixes": [
                {
                    "fix_title": fix.fix_title,
                    "priority_score": fix.priority_score,
                    "priority_level": fix.priority_level,
                    "owner_group": fix.owner_group,
                    "recommended_action": "Create Jira Ticket",
                    "change_window_required": fix.change_window_required,
                    "confidence": fix.confidence,
                }
                for fix in self.computed_fixes
            ],
        }


def _owner_group_for_fix(assets: List[Dict[str, object]]) -> str:
    if not assets:
        return "Unassigned"

    owner_groups: List[str] = []
    for asset in assets:
        owner = str(asset.get("owner_group", "")).strip()
        if owner:
            owner_groups.append(owner)

    if not owner_groups:
        return "Unassigned"

    counts = Counter(owner_groups)
    max_count = max(counts.values())
    tied = {owner for owner, count in counts.items() if count == max_count}

    for owner in owner_groups:
        if owner in tied:
            return owner

    return owner_groups[0]


def _production_count(assets: List[Dict[str, object]]) -> int:
    return sum(
        1
        for asset in assets
        if str(asset.get("environment", "")).strip().lower() == "production"
    )


def _criticality_weight(assets: List[Dict[str, object]]) -> float:
    highest = 0.5
    for asset in assets:
        criticality = str(asset.get("criticality", "medium")).strip().lower()
        highest = max(highest, CRITICALITY_WEIGHTS.get(criticality, 0.5))
    return highest


def _priority_level(
    score: float,
    exploit_known: bool,
    production_count: int,
    active_breach: bool,
    has_malware: bool,
) -> PriorityLevel:
    if (exploit_known and production_count > 0) or active_breach or has_malware:
        return "High"
    if score >= 0.80:
        return "High"
    if score >= 0.55:
        return "Medium"
    return "Low"


def _confidence(
    kenna_score: float,
    exploit_known: bool,
    production_count: int,
    affected_hosts: int,
) -> float:
    value = 0.45
    if kenna_score >= 80:
        value += 0.20
    if exploit_known:
        value += 0.15
    if production_count > 0:
        value += 0.10
    if affected_hosts >= 20:
        value += 0.10
    return round(min(value, 0.95), 2)


def _estimated_risk_reduction(total_fixes: int, high_priority_fixes: int) -> EstimatedRiskReduction:
    if total_fixes <= 0:
        return "low"
    ratio = high_priority_fixes / total_fixes
    if ratio >= 0.30:
        return "high"
    if ratio >= 0.10:
        return "moderate"
    return "low"


def compute_policy(input_payload: Dict[str, object]) -> PolicyComputationResult:
    asset_group = str(input_payload.get("asset_group", "Unknown Asset Group"))
    raw_fixes = list(input_payload.get("fixes", []))

    computed_fixes: List[ComputedFix] = []
    for raw in raw_fixes:
        if not isinstance(raw, dict):
            continue

        assets = list(raw.get("assets", []))
        owner_group = _owner_group_for_fix(assets)
        production_count = _production_count(assets)

        kenna_score = float(raw.get("kenna_score", 0.0))
        cvss = float(raw.get("cvss", 0.0))
        exploit_known = bool(raw.get("exploit_known", False))
        active_breach = bool(raw.get("active_breach", False))
        has_malware = bool(raw.get("has_malware", False))
        affected_hosts = int(raw.get("affected_hosts", 0))
        requires_reboot = bool(raw.get("requires_reboot", False))

        normalized_host_count = min(max(affected_hosts, 0) / 100.0, 1.0)
        score = (
            (kenna_score / 100.0) * 0.4
            + (cvss / 10.0) * 0.2
            + (1.0 if exploit_known else 0.0) * 0.2
            + _criticality_weight(assets) * 0.1
            + normalized_host_count * 0.1
        )
        score = round(score, 2)

        priority_level = _priority_level(
            score=score,
            exploit_known=exploit_known,
            production_count=production_count,
            active_breach=active_breach,
            has_malware=has_malware,
        )

        computed_fixes.append(
            ComputedFix(
                fix_title=str(raw.get("fix_title", "")),
                kenna_score=round(kenna_score, 2),
                cvss=round(cvss, 2),
                exploit_known=exploit_known,
                active_breach=active_breach,
                has_malware=has_malware,
                affected_hosts=affected_hosts,
                requires_reboot=requires_reboot,
                owner_group=owner_group,
                production_count=production_count,
                priority_score=score,
                priority_level=priority_level,
                change_window_required=requires_reboot,
                confidence=_confidence(
                    kenna_score=kenna_score,
                    exploit_known=exploit_known,
                    production_count=production_count,
                    affected_hosts=affected_hosts,
                ),
            )
        )

    computed_fixes.sort(key=lambda fix: (-fix.priority_score, fix.fix_title.lower()))

    owner_ticket_counts = dict(Counter(fix.owner_group for fix in computed_fixes))
    high_priority_fixes = sum(1 for fix in computed_fixes if fix.priority_level == "High")
    medium_priority_fixes = sum(1 for fix in computed_fixes if fix.priority_level == "Medium")
    low_priority_fixes = sum(1 for fix in computed_fixes if fix.priority_level == "Low")

    return PolicyComputationResult(
        asset_group=asset_group,
        computed_fixes=computed_fixes,
        total_fixes=len(computed_fixes),
        high_priority_fixes=high_priority_fixes,
        medium_priority_fixes=medium_priority_fixes,
        low_priority_fixes=low_priority_fixes,
        estimated_risk_reduction=_estimated_risk_reduction(
            total_fixes=len(computed_fixes),
            high_priority_fixes=high_priority_fixes,
        ),
        owner_ticket_counts=owner_ticket_counts,
        total_affected_hosts=sum(fix.affected_hosts for fix in computed_fixes),
        production_fixes_count=sum(1 for fix in computed_fixes if fix.production_count > 0),
        change_window_titles=[
            fix.fix_title for fix in computed_fixes if fix.change_window_required
        ],
        exploit_titles=[fix.fix_title for fix in computed_fixes if fix.exploit_known],
        high_confidence_titles=[
            fix.fix_title for fix in computed_fixes if fix.confidence >= 0.90
        ],
    )
