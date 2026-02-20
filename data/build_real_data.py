"""
build_real_data.py
==================
Converts real Kenna CSV exports → kenna_input.json (NO anonymization).

Run this ONLY on your private workstation — do NOT commit the output JSON.
The output file (kenna_input.json) is already in .gitignore.

Usage:
    python data/build_real_data.py

Place the 3 Kenna CSV exports in the same folder as this script (data/).
"""

from __future__ import annotations

import json
import re
from typing import Dict, List, Optional
from pathlib import Path

import pandas as pd

# ---------------------------------------------------------------------------
# CSV filenames — update if your export filenames differ
# ---------------------------------------------------------------------------
DATA_DIR = Path(__file__).parent

ASSET_CSV = DATA_DIR / "asset_export_20260220031753.csv"
VULN_CSV  = DATA_DIR / "vulnerability_export_20260220032028.csv"
FIX_CSV   = DATA_DIR / "fix_export_20260220032413.csv"


def parse_cves(cves_str: str) -> List[str]:
    """Kenna 'CVEs' field is space-separated."""
    if not isinstance(cves_str, str) or not cves_str.strip():
        return []
    tokens = re.split(r"\s+", cves_str.strip())
    return [t for t in tokens if t.upper().startswith("CVE-")]


def pick_hostname(asset_row: pd.Series) -> str:
    """Prefer FQDN, fall back to Hostname, then ID."""
    fqdn = asset_row.get("FQDN")
    if isinstance(fqdn, str) and fqdn.strip():
        return fqdn.strip()
    hn = asset_row.get("Hostname")
    if isinstance(hn, str) and hn.strip():
        return hn.strip()
    return str(asset_row.get("ID"))


def infer_environment_from_tags(tags: str) -> str:
    """Heuristic from tags. Replace with Jira Assets integration later."""
    if not isinstance(tags, str):
        return "production"
    t = tags.lower()
    if any(x in t for x in ["non-prod", "nonprod", "dev", "test", "qa", "stage"]):
        return "non-production"
    return "production"


def infer_criticality_from_priority(priority: Optional[float]) -> str:
    """Map Kenna priority (1-10) to high/medium/low."""
    try:
        p = float(priority)
    except Exception:
        return "medium"
    if p >= 9:
        return "high"
    if p >= 5:
        return "medium"
    return "low"


def compute_fix_enrichment(
    fix_id: int,
    fix_rows: pd.DataFrame,
    assets_df: pd.DataFrame,
    vulns_df: pd.DataFrame,
) -> Dict:
    """Build one Fix object for the agent input."""

    title = str(fix_rows["Title"].iloc[0])

    # Affected hosts
    asset_ids = fix_rows["Asset ID"].dropna().astype(int).unique().tolist()
    affected_hosts = len(asset_ids)

    # CVEs
    cves = []
    for s in fix_rows["CVEs"].dropna().tolist():
        cves.extend(parse_cves(str(s)))
    cves = sorted(set(cves))

    # Enrich from vulnerability export
    exploit_known = False
    cvss_max = 0.0
    if cves:
        subset = vulns_df[vulns_df["Vulnerability"].isin(cves)].copy()
        if not subset.empty:
            if "Has Exploit" in subset.columns:
                exploit_known = bool(subset["Has Exploit"].fillna(False).astype(bool).any())
            candidates = []
            if "CVSS V3 Score" in subset.columns:
                candidates.append(pd.to_numeric(subset["CVSS V3 Score"], errors="coerce"))
            if "CVSS V2 Score" in subset.columns:
                candidates.append(pd.to_numeric(subset["CVSS V2 Score"], errors="coerce"))
            if candidates:
                cvss_max = float(pd.concat(candidates).max(skipna=True) or 0.0)

    # Kenna score from fix export
    highest_vuln_score = pd.to_numeric(fix_rows.get("Highest Vuln Score"), errors="coerce")
    kenna_score = float(highest_vuln_score.max(skipna=True) or 0.0)

    # Build assets list (real hostnames — keep private)
    assets_subset = assets_df[assets_df["ID"].isin(asset_ids)].copy()
    assets_list = []
    for _, arow in assets_subset.iterrows():
        tags = arow.get("Tags", "")
        assets_list.append({
            "hostname":    pick_hostname(arow),
            "owner_group": "Windows Management Team",  # update with Jira Assets later
            "environment": infer_environment_from_tags(tags),
            "criticality": infer_criticality_from_priority(arow.get("Priority")),
        })

    # requires_reboot: Phase 1 default False (no reliable signal yet)
    requires_reboot = False

    return {
        "fix_title":      title,
        "kenna_score":    round(kenna_score, 2),
        "cvss":           round(cvss_max, 2),
        "exploit_known":  exploit_known,
        "affected_hosts": affected_hosts,
        "requires_reboot": requires_reboot,
        "assets":         assets_list,
    }


def main(asset_group_name: str = "Kenna Export (Phase 1)", top_n: int = 20) -> None:
    print("📥 Loading Kenna exports...")
    assets_df = pd.read_csv(ASSET_CSV)
    vulns_df  = pd.read_csv(VULN_CSV, low_memory=False)
    fixes_df  = pd.read_csv(FIX_CSV)

    print(f"   Assets: {len(assets_df)}  Vulns: {len(vulns_df)}  Fixes: {len(fixes_df)}")

    fixes_df["Fix ID"] = pd.to_numeric(fixes_df["Fix ID"], errors="coerce")
    fixes_df = fixes_df.dropna(subset=["Fix ID"])
    fixes_df["Fix ID"] = fixes_df["Fix ID"].astype(int)

    # Top N fixes by affected host count
    fix_sizes      = fixes_df.groupby("Fix ID")["Asset ID"].nunique().sort_values(ascending=False)
    selected_ids   = fix_sizes.head(top_n).index.tolist()

    print(f"\n🔍 Building {top_n} fixes...\n")
    fixes_out = []
    for fid in selected_ids:
        rows = fixes_df[fixes_df["Fix ID"] == fid]
        fix  = compute_fix_enrichment(fid, rows, assets_df, vulns_df)
        fixes_out.append(fix)
        print(f"  ✅ {fix['fix_title'][:60]}  (hosts={fix['affected_hosts']})")

    payload = {"asset_group": asset_group_name, "fixes": fixes_out}

    out_path = DATA_DIR / "kenna_input.json"
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(f"\n✅ Wrote {out_path}")
    print(f"   ⚠️  Do NOT commit kenna_input.json — it contains real hostnames!")
    print(f"   Run: OPENAI_API_KEY=sk-... python agent/run_agent.py")


if __name__ == "__main__":
    main(asset_group_name="Kenna Export (Phase 1)", top_n=20)
