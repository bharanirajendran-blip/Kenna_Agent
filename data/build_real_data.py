"""
build_real_data.py
==================
Converts real Kenna CSV exports → kenna_input.json (NO anonymization).

Improvements over v1:
  - Joins Fix → Vulnerability via Fix ID column (not fragile CVE string matching)
  - Extracts real owner_group from Asset Tags (CLAS, ITS, HPC, UITS, etc.)
  - Uses Active Breach + Has Malware as additional exploit signals
  - Detects requires_reboot from OS field + title keywords
  - Environment detection from Tags + FQDN domain patterns

Run this ONLY on your private workstation — do NOT commit the output JSON.
kenna_input.json is already in .gitignore.

Usage:
    python data/build_real_data.py

Place the 3 Kenna CSV exports in the data/ folder before running.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd

# ---------------------------------------------------------------------------
# CSV paths — update if filenames differ
# ---------------------------------------------------------------------------
DATA_DIR = Path(__file__).parent

ASSET_CSV = DATA_DIR / "asset_export_20260220031753.csv"
VULN_CSV  = DATA_DIR / "vulnerability_export_20260220032028.csv"
FIX_CSV   = DATA_DIR / "fix_export_20260220032413.csv"

TOP_N              = 20
MAX_ASSETS_PER_FIX = 15


# ---------------------------------------------------------------------------
# Owner group extraction from Tags
# Priority order: first match wins
# ---------------------------------------------------------------------------
OWNER_TAG_MAP = [
    (r"\bHPC\b",                          "HPC Team"),
    (r"ITS Managed Windows",              "ITS Windows Team"),
    (r"ITS VMware",                       "ITS VMware Team"),
    (r"\bCLAS\b",                         "CLAS Team"),
    (r"\bUITS\b",                         "UITS Team"),
    (r"\bITS\b",                          "ITS Team"),
    (r"\bInfoSec\b",                      "InfoSec Team"),
    (r"\bLibrary\b",                      "Library IT Team"),
    (r"\bHealth\b|\bUCONN Health\b",      "UConn Health IT"),
    (r"\bAthletics\b",                    "Athletics IT"),
]

def extract_owner_group(tags: str, owner: str) -> str:
    """Derive owner_group from Tags field using priority mapping."""
    text = str(tags or "")
    for pattern, group in OWNER_TAG_MAP:
        if re.search(pattern, text, re.IGNORECASE):
            return group
    # Fall back to Owner field if present
    if isinstance(owner, str) and owner.strip():
        return owner.strip()
    return "Windows Management Team"


# ---------------------------------------------------------------------------
# Environment detection
# ---------------------------------------------------------------------------
def detect_environment(fqdn: str, hostname: str, tags: str) -> str:
    """Detect prod vs non-prod from FQDN, hostname, and tags."""
    combined = f"{fqdn} {hostname} {tags}".lower()
    if any(x in combined for x in ["non-prod", "nonprod", "dev", "test",
                                    "qa", "stage", "uat", "sandbox"]):
        return "non-production"
    return "production"


# ---------------------------------------------------------------------------
# Criticality from asset Priority (1–10 scale in Kenna)
# ---------------------------------------------------------------------------
def asset_criticality(priority) -> str:
    try:
        p = float(priority)
    except Exception:
        return "medium"
    if p >= 9:
        return "high"
    if p >= 5:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Requires-reboot heuristic
# ---------------------------------------------------------------------------
REBOOT_KEYWORDS = [
    "kernel", "windows update", "security update", r"\bkb\d{6,7}\b",
    "reboot", "restart required", "glibc", "libc",
]

def needs_reboot(title: str, os_field: str) -> bool:
    text = f"{title} {os_field}".lower()
    return any(re.search(kw, text) for kw in REBOOT_KEYWORDS)


# ---------------------------------------------------------------------------
# Pick best hostname
# ---------------------------------------------------------------------------
def pick_hostname(row: pd.Series) -> str:
    for col in ("FQDN", "Hostname", "IP Address"):
        val = row.get(col)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return str(row.get("ID", "unknown"))


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------
def main() -> None:
    print("=" * 60)
    print("  Kenna Real Data Builder  (no anonymization)")
    print("=" * 60)

    print("\n📥 Loading CSVs...")
    assets_df = pd.read_csv(ASSET_CSV)
    vulns_df  = pd.read_csv(VULN_CSV,  low_memory=False)
    fixes_df  = pd.read_csv(FIX_CSV)

    print(f"   Assets: {len(assets_df)}  Vulns: {len(vulns_df)}  Fixes: {len(fixes_df)}")

    # ---- Normalize Fix ID across all three CSVs ----
    for df in (fixes_df, vulns_df):
        df["Fix ID"] = pd.to_numeric(df["Fix ID"], errors="coerce")
    fixes_df = fixes_df.dropna(subset=["Fix ID"])
    fixes_df["Fix ID"] = fixes_df["Fix ID"].astype(int)
    vulns_df = vulns_df.dropna(subset=["Fix ID"])
    vulns_df["Fix ID"] = vulns_df["Fix ID"].astype(int)

    # ---- Normalize Asset ID ----
    fixes_df["Asset ID"] = pd.to_numeric(fixes_df["Asset ID"], errors="coerce")
    if "Asset ID" in vulns_df.columns:
        vulns_df["Asset ID"] = pd.to_numeric(vulns_df["Asset ID"], errors="coerce")
    assets_df["ID"] = pd.to_numeric(assets_df["ID"], errors="coerce")

    # ---- Select top N fixes by unique affected assets ----
    fix_sizes    = fixes_df.groupby("Fix ID")["Asset ID"].nunique().sort_values(ascending=False)
    selected_ids = fix_sizes.head(TOP_N).index.tolist()

    print(f"\n🔍 Building top {TOP_N} fixes...\n")
    out_fixes = []

    for fid in selected_ids:
        fix_rows = fixes_df[fixes_df["Fix ID"] == fid].copy()
        title    = str(fix_rows["Title"].iloc[0])

        # Affected host count (all assets in fix export)
        asset_ids_all = fix_rows["Asset ID"].dropna().astype(int).unique().tolist()
        affected_hosts = len(asset_ids_all)

        # ── Vulnerability enrichment via Fix ID join (reliable!) ──────────
        vuln_rows = vulns_df[vulns_df["Fix ID"] == fid].copy()

        exploit_known  = False
        active_breach  = False
        has_malware    = False
        cvss_max       = 0.0

        if not vuln_rows.empty:
            # Exploit flag
            if "Has Exploit" in vuln_rows.columns:
                exploit_known = bool(vuln_rows["Has Exploit"].fillna(False).astype(bool).any())

            # Active breach flag (stronger signal than exploit)
            if "Active Breach" in vuln_rows.columns:
                active_breach = bool(vuln_rows["Active Breach"].fillna(False).astype(bool).any())

            # Malware flag
            if "Has Malware" in vuln_rows.columns:
                has_malware = bool(vuln_rows["Has Malware"].fillna(False).astype(bool).any())

            # If active breach or malware, treat as exploit_known
            if active_breach or has_malware:
                exploit_known = True

            # CVSS: prefer V3, fallback V2
            for col in ("CVSS V3 Score", "CVSS V2 Score"):
                if col in vuln_rows.columns:
                    v = pd.to_numeric(vuln_rows[col], errors="coerce")
                    mx = v.max(skipna=True)
                    if pd.notna(mx) and float(mx) > cvss_max:
                        cvss_max = float(mx)

        # ── Kenna score from fix export ───────────────────────────────────
        hvs_col = next((c for c in fix_rows.columns
                        if "highest vuln score" in c.lower()), None)
        kenna_score = 0.0
        if hvs_col:
            v = pd.to_numeric(fix_rows[hvs_col], errors="coerce")
            kenna_score = float(v.max(skipna=True) or 0.0)

        # ── OS for reboot detection ───────────────────────────────────────
        os_col = next((c for c in fix_rows.columns
                       if c.lower() == "operating system"), None)
        os_val = str(fix_rows[os_col].iloc[0]) if os_col else ""

        requires_reboot_flag = needs_reboot(title, os_val)

        # ── Asset details (sampled) ───────────────────────────────────────
        sample_ids    = asset_ids_all[:MAX_ASSETS_PER_FIX]
        assets_subset = assets_df[assets_df["ID"].isin(sample_ids)].copy()

        asset_list = []
        for _, arow in assets_subset.iterrows():
            tags  = str(arow.get("Tags", "") or "")
            owner = str(arow.get("Owner", "") or "")
            fqdn  = str(arow.get("FQDN",  "") or "")
            hn    = str(arow.get("Hostname", "") or "")

            asset_list.append({
                "hostname":    pick_hostname(arow),
                "owner_group": extract_owner_group(tags, owner),
                "environment": detect_environment(fqdn, hn, tags),
                "criticality": asset_criticality(arow.get("Priority")),
            })

        out_fixes.append({
            "fix_title":      title,
            "kenna_score":    round(kenna_score, 2),
            "cvss":           round(cvss_max, 2),
            "exploit_known":  exploit_known,
            "active_breach":  active_breach,
            "has_malware":    has_malware,
            "affected_hosts": affected_hosts,
            "requires_reboot": requires_reboot_flag,
            "assets":         asset_list,
        })

        flags = []
        if exploit_known:  flags.append("💥exploit")
        if active_breach:  flags.append("🔥breach")
        if has_malware:    flags.append("☠️malware")
        flag_str = " ".join(flags) or "  clean"

        print(f"  [{len(out_fixes):02d}] {title[:52]}")
        print(f"       hosts={affected_hosts}  kenna={kenna_score:.0f}"
              f"  cvss={cvss_max:.1f}  reboot={requires_reboot_flag}  {flag_str}")

    payload = {
        "asset_group": "Kenna Export (Phase 1)",
        "fixes": out_fixes,
    }

    out_path = DATA_DIR / "kenna_input.json"
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(f"\n✅ Wrote: {out_path}")
    print(f"   Fixes:  {len(out_fixes)}")
    print(f"   ⚠️  kenna_input.json contains real hostnames — do NOT commit!")
    print(f"\n   Run agent:")
    print(f"   OPENAI_API_KEY=sk-... python3 agent/run_agent.py")


if __name__ == "__main__":
    main()
