"""
build_sanitized_data.py
=======================
Converts real Kenna CSV exports into a sanitized JSON dataset safe for
classroom / GitHub use.

Usage:
    python data/build_sanitized_data.py

Expects these files relative to the PROJECT ROOT (not data/):
    data/asset_export_*.csv
    data/vulnerability_export_*.csv
    data/fix_export_*.csv

Outputs:
    data/kenna_input_sanitized.json
"""

from __future__ import annotations

import glob
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import List

import pandas as pd

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
DATA_DIR   = Path(__file__).parent          # …/data/
ROOT_DIR   = DATA_DIR.parent               # project root

SALT       = "uconn-class-salt-change-this"  # Keep private locally
TOP_FIXES          = 20   # more fixes = richer dataset for professor
MAX_ASSETS_PER_FIX = 15   # more assets = better env/criticality representation


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _h(text: str) -> str:
    """Deterministic SHA-256 hash for anonymization."""
    return hashlib.sha256((SALT + "|" + text).encode()).hexdigest()


def fake_hostname(real: str) -> str:
    return f"host-{_h(real)[:10]}.example.internal"


def fake_ip(real: str) -> str:
    d = _h(real)
    a = int(d[0:2], 16) % 255
    b = int(d[2:4], 16) % 255
    c = int(d[4:6], 16) % 255
    return f"10.{a}.{b}.{max(1, min(254, c))}"


def parse_cves(s: str) -> List[str]:
    if not isinstance(s, str) or not s.strip():
        return []
    return [t for t in re.split(r"[\s,;]+", s.strip()) if t.upper().startswith("CVE-")]


def determine_environment(hostname: str) -> str:
    hn = hostname.lower()
    if any(x in hn for x in ["prod", "prd", "p-", "-p0", "-p1"]):
        return "production"
    elif any(x in hn for x in ["dev", "test", "qa", "stage", "uat", "sit"]):
        return "non-production"
    return "production"   # default to production (safer assumption)


def determine_criticality(kenna_score: float, cvss: float, exploit: bool) -> str:
    if exploit and cvss >= 7.0:
        return "high"
    if kenna_score >= 70 or cvss >= 8.0:
        return "high"
    if kenna_score >= 50 or cvss >= 6.0:
        return "medium"
    return "low"


def _find_csv(pattern: str) -> Path:
    """Glob for a CSV file matching pattern inside data/; abort if not found."""
    matches = sorted((DATA_DIR).glob(pattern))
    if not matches:
        print(f"\n❌  Could not find a file matching: data/{pattern}")
        print("    Place your Kenna CSV exports in the data/ folder and re-run.")
        sys.exit(1)
    return matches[0]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    print("=" * 60)
    print("  Kenna → Sanitized JSON builder")
    print("=" * 60)

    # Locate CSVs (flexible glob so filenames can vary slightly)
    asset_path = _find_csv("asset_export*.csv")
    vuln_path  = _find_csv("vulnerability_export*.csv")
    fix_path   = _find_csv("fix_export*.csv")

    print(f"\n📥 Loading exports …")
    print(f"   Assets: {asset_path.name}")
    print(f"   Vulns:  {vuln_path.name}")
    print(f"   Fixes:  {fix_path.name}")

    assets = pd.read_csv(asset_path)
    vulns  = pd.read_csv(vuln_path, low_memory=False)
    fixes  = pd.read_csv(fix_path)

    print(f"\n   Rows — assets:{len(assets)}  vulns:{len(vulns)}  fixes:{len(fixes)}")

    # ---- Clean Fix IDs ----
    fixes["Fix ID"] = pd.to_numeric(fixes["Fix ID"], errors="coerce")
    fixes = fixes.dropna(subset=["Fix ID"])
    fixes["Fix ID"] = fixes["Fix ID"].astype(int)

    # Normalize Fix ID in vulns too (needed for direct Fix ID join)
    if "Fix ID" in vulns.columns:
        vulns["Fix ID"] = pd.to_numeric(vulns["Fix ID"], errors="coerce")
        vulns = vulns.dropna(subset=["Fix ID"])
        vulns["Fix ID"] = vulns["Fix ID"].astype(int)

    # ---- Select top fixes by affected-asset count ----
    fix_sizes   = fixes.groupby("Fix ID")["Asset ID"].nunique().sort_values(ascending=False)
    selected_ids = fix_sizes.head(TOP_FIXES).index.tolist()

    print(f"\n🔍 Processing top {TOP_FIXES} fixes by impact …\n")

    out_fixes = []

    for fid in selected_ids:
        rows = fixes[fixes["Fix ID"] == fid].copy()

        title    = str(rows["Title"].iloc[0])
        all_aids = rows["Asset ID"].dropna().astype(int).unique().tolist()
        sample_aids = all_aids[:MAX_ASSETS_PER_FIX]

        # Enrich from vuln table via Fix ID (reliable direct join)
        exploit_known  = False
        active_breach  = False
        has_malware    = False
        cvss_max       = 0.0

        vuln_subset = vulns[vulns["Fix ID"] == fid].copy() if "Fix ID" in vulns.columns else pd.DataFrame()

        if not vuln_subset.empty:
            if "Has Exploit" in vuln_subset.columns:
                exploit_known = bool(vuln_subset["Has Exploit"].fillna(False).astype(bool).any())
            if "Active Breach" in vuln_subset.columns:
                active_breach = bool(vuln_subset["Active Breach"].fillna(False).astype(bool).any())
            if "Has Malware" in vuln_subset.columns:
                has_malware = bool(vuln_subset["Has Malware"].fillna(False).astype(bool).any())
            if active_breach or has_malware:
                exploit_known = True
            for score_col in ["CVSS V3 Score", "CVSS V2 Score"]:
                if score_col in vuln_subset.columns:
                    v = pd.to_numeric(vuln_subset[score_col], errors="coerce")
                    mx = v.max(skipna=True)
                    if pd.notna(mx):
                        cvss_max = max(cvss_max, float(mx))

        # Kenna risk score
        score_col = next(
            (c for c in rows.columns if "vuln score" in c.lower() or "risk score" in c.lower()),
            None
        )
        kenna_score = 0.0
        if score_col:
            v = pd.to_numeric(rows[score_col], errors="coerce")
            kenna_score = float(v.max(skipna=True) or 0.0)

        # Asset detail
        aset = assets[assets["ID"].isin(sample_aids)].copy()
        asset_list = []
        for _, a in aset.iterrows():
            fqdn_col = next(
                (c for c in a.index if c.upper() in ("FQDN", "HOSTNAME", "HOST_NAME")),
                None
            )
            real_host = str(a[fqdn_col] if fqdn_col else a["ID"])
            environment  = determine_environment(real_host)
            criticality  = determine_criticality(kenna_score, cvss_max, exploit_known)

            asset_list.append({
                "hostname":    fake_hostname(real_host),
                "owner_group": "Windows Management Team",
                "environment": environment,
                "criticality": criticality,
            })

        requires_reboot = any(
            kw in title.lower()
            for kw in ["kernel", "windows update", "security update", "kb", "reboot", "restart"]
        )

        out_fixes.append({
            "fix_title":      title,
            "kenna_score":    round(kenna_score, 2),
            "cvss":           round(cvss_max, 2),
            "exploit_known":  exploit_known,
            "active_breach":  active_breach,
            "has_malware":    has_malware,
            "affected_hosts": len(all_aids),
            "requires_reboot": requires_reboot,
            "assets":         asset_list,
        })

        flag = "💥" if exploit_known else "  "
        print(f"  {flag} [{len(out_fixes):02d}] {title[:60]}")
        print(f"         hosts={len(all_aids)}  kenna={kenna_score:.0f}  cvss={cvss_max:.1f}  "
              f"exploit={exploit_known}  reboot={requires_reboot}")

    payload = {
        "asset_group": "Windows Servers (Sanitized Dataset)",
        "fixes": out_fixes,
    }

    out_path = DATA_DIR / "kenna_input_sanitized.json"
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    total_assets = sum(len(f["assets"]) for f in out_fixes)
    print(f"\n✅  Wrote: {out_path}")
    print(f"   Fixes:  {len(out_fixes)}")
    print(f"   Sample assets: {total_assets}")
    print()


if __name__ == "__main__":
    main()
