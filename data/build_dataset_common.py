"""
Common dataset builder for Kenna exports.

This module builds a comprehensive fix-centric JSON payload by joining:
  - fix_export*.csv
  - vulnerability_export*.csv
  - asset_export*.csv
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd


OWNER_TAG_MAP: List[Tuple[str, str]] = [
    (r"\bHPC\b", "HPC Team"),
    (r"ITS Managed Windows", "ITS Windows Team"),
    (r"ITS VMware", "ITS VMware Team"),
    (r"\bCLAS\b", "CLAS Team"),
    (r"\bUITS\b", "UITS Team"),
    (r"\bITS\b", "ITS Team"),
    (r"\bInfoSec\b", "InfoSec Team"),
    (r"\bLibrary\b", "Library IT Team"),
    (r"\bHealth\b|\bUCONN Health\b", "UConn Health IT"),
    (r"\bAthletics\b", "Athletics IT"),
]

NON_PROD_MARKERS = ["non-prod", "nonprod", "dev", "test", "qa", "stage", "uat", "sandbox"]
REBOOT_KEYWORDS = [
    "kernel",
    "windows update",
    "security update",
    r"\bkb\d{6,7}\b",
    "reboot",
    "restart required",
    "glibc",
    "libc",
]
TRUE_STRINGS = {"true", "1", "yes", "y", "t"}
FALSE_STRINGS = {"false", "0", "no", "n", "f"}


@dataclass(frozen=True)
class BuildStats:
    assets_rows: int
    vulnerabilities_rows: int
    fixes_rows: int
    selected_fixes: int
    fix_ids_with_no_vuln_rows: int
    sampled_assets_missing_join: int
    total_sampled_assets: int


def _norm_col(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", name.strip().lower())


def _resolve_col(df: pd.DataFrame, *candidates: str) -> Optional[str]:
    mapping = {_norm_col(c): c for c in df.columns}
    for candidate in candidates:
        found = mapping.get(_norm_col(candidate))
        if found:
            return found
    return None


def _to_numeric(series: pd.Series) -> pd.Series:
    return pd.to_numeric(series, errors="coerce")


def _to_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return False
    text = str(value).strip().lower()
    if text in TRUE_STRINGS:
        return True
    if text in FALSE_STRINGS:
        return False
    return False


def _extract_owner_group(tags: str, owner: str) -> str:
    text = str(tags or "")
    for pattern, group in OWNER_TAG_MAP:
        if re.search(pattern, text, re.IGNORECASE):
            return group
    if isinstance(owner, str) and owner.strip():
        return owner.strip()
    return "Unassigned"


def _detect_environment(fqdn: str, hostname: str, tags: str) -> str:
    combined = f"{fqdn} {hostname} {tags}".lower()
    if any(marker in combined for marker in NON_PROD_MARKERS):
        return "non-production"
    return "production"


def _asset_criticality(priority_value) -> str:
    try:
        priority = float(priority_value)
    except Exception:
        return "medium"
    if priority >= 9:
        return "high"
    if priority >= 5:
        return "medium"
    return "low"


def _needs_reboot(title: str, os_field: str, category: str) -> bool:
    text = f"{title} {os_field} {category}".lower()
    return any(re.search(keyword, text) for keyword in REBOOT_KEYWORDS)


def _parse_cves_from_text(text: str) -> List[str]:
    if not isinstance(text, str) or not text.strip():
        return []
    return sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text.upper())))


def _safe_float(value, default: float = 0.0) -> float:
    try:
        v = float(value)
        if pd.isna(v):
            return default
        return v
    except Exception:
        return default


def _safe_int(value, default: int = 0) -> int:
    try:
        v = int(value)
        return v
    except Exception:
        return default


def _hash(text: str, salt: str) -> str:
    return hashlib.sha256((salt + "|" + text).encode("utf-8")).hexdigest()


def _fake_hostname(real: str, salt: str) -> str:
    return f"host-{_hash(real, salt)[:10]}.example.internal"


def _pick_hostname(row: pd.Series, fqdn_col: Optional[str], hostname_col: Optional[str], ip_col: Optional[str]) -> str:
    for col in [fqdn_col, hostname_col, ip_col]:
        if not col:
            continue
        value = row.get(col)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return str(row.get("asset_id", "unknown"))


def _load_csvs(data_dir: Path) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    csv_files = sorted(data_dir.glob("*.csv"))
    asset_files = [p for p in csv_files if "asset" in p.name.lower() and "export" in p.name.lower()]
    vuln_files = [p for p in csv_files if "vulnerability" in p.name.lower() and "export" in p.name.lower()]
    fix_files = [p for p in csv_files if "fix" in p.name.lower() and "export" in p.name.lower()]
    if not asset_files or not vuln_files or not fix_files:
        missing = []
        if not asset_files:
            missing.append("data/asset_export*.csv")
        if not vuln_files:
            missing.append("data/vulnerability_export*.csv")
        if not fix_files:
            missing.append("data/fix_export*.csv")
        raise FileNotFoundError("Missing required CSV export(s): " + ", ".join(missing))
    return (
        pd.read_csv(asset_files[0], low_memory=False),
        pd.read_csv(vuln_files[0], low_memory=False),
        pd.read_csv(fix_files[0], low_memory=False),
    )


def build_payload(
    *,
    data_dir: Path,
    top_n: int,
    max_assets_per_fix: int,
    asset_group_label: str,
    anonymize_assets: bool = False,
    anonymize_salt: str = "change-me",
) -> Tuple[Dict[str, object], BuildStats]:
    assets_df, vulns_df, fixes_df = _load_csvs(data_dir)

    # Resolve source columns.
    fix_id_fix_col = _resolve_col(fixes_df, "Fix ID")
    asset_id_fix_col = _resolve_col(fixes_df, "Asset ID")
    title_col = _resolve_col(fixes_df, "Title")
    kenna_col = _resolve_col(fixes_df, "Highest Vuln Score", "Highest Vulnerability Score", "Risk Score")
    os_fix_col = _resolve_col(fixes_df, "Operating System")
    category_col = _resolve_col(fixes_df, "Category")
    cves_fix_col = _resolve_col(fixes_df, "CVEs")
    diagnosis_col = _resolve_col(fixes_df, "Diagnosis")
    solution_col = _resolve_col(fixes_df, "Solution")
    patch_date_col = _resolve_col(fixes_df, "Patch Publication Date")

    fix_id_vuln_col = _resolve_col(vulns_df, "Fix ID")
    asset_id_vuln_col = _resolve_col(vulns_df, "Asset ID")
    exploit_col = _resolve_col(vulns_df, "Has Exploit")
    breach_col = _resolve_col(vulns_df, "Active Breach")
    malware_col = _resolve_col(vulns_df, "Has Malware")
    cvss_v3_col = _resolve_col(vulns_df, "CVSS V3 Score")
    cvss_v2_col = _resolve_col(vulns_df, "CVSS V2 Score")
    risk_score_col = _resolve_col(vulns_df, "Risk Score")
    identifiers_col = _resolve_col(vulns_df, "Identifiers")
    vuln_title_col = _resolve_col(vulns_df, "Vulnerability")

    asset_id_asset_col = _resolve_col(assets_df, "ID", "Asset ID")
    fqdn_col = _resolve_col(assets_df, "FQDN", "Fully Qualified Domain Name")
    hostname_col = _resolve_col(assets_df, "Hostname")
    ip_col = _resolve_col(assets_df, "IP Address")
    tags_col = _resolve_col(assets_df, "Tags")
    owner_col = _resolve_col(assets_df, "Owner")
    priority_col = _resolve_col(assets_df, "Priority")
    os_asset_col = _resolve_col(assets_df, "Operating System")

    required_cols = [
        ("fixes", "Fix ID", fix_id_fix_col),
        ("fixes", "Asset ID", asset_id_fix_col),
        ("fixes", "Title", title_col),
        ("vulnerabilities", "Fix ID", fix_id_vuln_col),
        ("assets", "ID", asset_id_asset_col),
    ]
    missing_required = [f"{table}.{col}" for table, col, resolved in required_cols if not resolved]
    if missing_required:
        raise RuntimeError("Missing required CSV columns: " + ", ".join(missing_required))

    fixes = fixes_df.copy()
    vulns = vulns_df.copy()
    assets = assets_df.copy()

    fixes["fix_id"] = _to_numeric(fixes[fix_id_fix_col]).astype("Int64")
    fixes["asset_id"] = _to_numeric(fixes[asset_id_fix_col]).astype("Int64")
    fixes = fixes.dropna(subset=["fix_id"])
    fixes["fix_id"] = fixes["fix_id"].astype(int)

    vulns["fix_id"] = _to_numeric(vulns[fix_id_vuln_col]).astype("Int64")
    vulns = vulns.dropna(subset=["fix_id"])
    vulns["fix_id"] = vulns["fix_id"].astype(int)
    if asset_id_vuln_col:
        vulns["asset_id"] = _to_numeric(vulns[asset_id_vuln_col]).astype("Int64")
    else:
        vulns["asset_id"] = pd.Series([pd.NA] * len(vulns), dtype="Int64")

    assets["asset_id"] = _to_numeric(assets[asset_id_asset_col]).astype("Int64")
    assets = assets.dropna(subset=["asset_id"]).copy()
    assets["asset_id"] = assets["asset_id"].astype(int)

    fix_sizes = fixes.groupby("fix_id")["asset_id"].nunique().sort_values(ascending=False)
    selected_fix_ids = fix_sizes.head(top_n).index.tolist()

    out_fixes: List[Dict[str, object]] = []
    fix_ids_with_no_vuln_rows = 0
    sampled_assets_missing_join = 0
    total_sampled_assets = 0

    for fix_id in selected_fix_ids:
        fix_rows = fixes[fixes["fix_id"] == fix_id].copy()
        vuln_rows = vulns[vulns["fix_id"] == fix_id].copy()
        if vuln_rows.empty:
            fix_ids_with_no_vuln_rows += 1

        title = str(fix_rows[title_col].iloc[0]).strip() if title_col else f"Fix ID {fix_id}"
        all_asset_ids = (
            fix_rows["asset_id"].dropna().astype(int).unique().tolist()
            if not fix_rows["asset_id"].isna().all()
            else []
        )
        if not all_asset_ids:
            all_asset_ids = vuln_rows["asset_id"].dropna().astype(int).unique().tolist()

        affected_hosts = len(all_asset_ids)
        sample_asset_ids = all_asset_ids[:max_assets_per_fix]
        total_sampled_assets += len(sample_asset_ids)

        asset_subset = assets[assets["asset_id"].isin(sample_asset_ids)].copy()
        sampled_assets_missing_join += max(0, len(sample_asset_ids) - len(asset_subset))

        exploit_known = bool(vuln_rows[exploit_col].map(_to_bool).any()) if exploit_col else False
        active_breach = bool(vuln_rows[breach_col].map(_to_bool).any()) if breach_col else False
        has_malware = bool(vuln_rows[malware_col].map(_to_bool).any()) if malware_col else False
        if active_breach or has_malware:
            exploit_known = True

        cvss_v3_max = _safe_float(_to_numeric(vuln_rows[cvss_v3_col]).max()) if cvss_v3_col else 0.0
        cvss_v2_max = _safe_float(_to_numeric(vuln_rows[cvss_v2_col]).max()) if cvss_v2_col else 0.0
        cvss_max = round(max(cvss_v3_max, cvss_v2_max), 2)

        if kenna_col:
            kenna_score = round(_safe_float(_to_numeric(fix_rows[kenna_col]).max()), 2)
        elif risk_score_col:
            kenna_score = round(_safe_float(_to_numeric(vuln_rows[risk_score_col]).max()), 2)
        else:
            kenna_score = 0.0

        fix_cves = _parse_cves_from_text(str(fix_rows[cves_fix_col].iloc[0])) if cves_fix_col else []
        vuln_cves = []
        if identifiers_col and not vuln_rows.empty:
            for value in vuln_rows[identifiers_col].dropna().astype(str).tolist():
                vuln_cves.extend(_parse_cves_from_text(value))
        combined_cves = sorted(set(fix_cves + vuln_cves))

        category = str(fix_rows[category_col].iloc[0]).strip() if category_col else ""
        os_value = str(fix_rows[os_fix_col].iloc[0]).strip() if os_fix_col else ""
        requires_reboot = _needs_reboot(title, os_value, category)

        asset_list: List[Dict[str, object]] = []
        for _, row in asset_subset.iterrows():
            fqdn = str(row.get(fqdn_col, "") if fqdn_col else "")
            hostname = str(row.get(hostname_col, "") if hostname_col else "")
            ip_addr = str(row.get(ip_col, "") if ip_col else "")
            tags = str(row.get(tags_col, "") if tags_col else "")
            owner = str(row.get(owner_col, "") if owner_col else "")

            chosen_name = _pick_hostname(row, fqdn_col, hostname_col, ip_col)
            if anonymize_assets:
                chosen_name = _fake_hostname(chosen_name, anonymize_salt)

            asset_list.append(
                {
                    "hostname": chosen_name,
                    "owner_group": _extract_owner_group(tags, owner),
                    "environment": _detect_environment(fqdn=fqdn, hostname=hostname, tags=tags),
                    "criticality": _asset_criticality(row.get(priority_col) if priority_col else None),
                    "asset_os": str(row.get(os_asset_col, "") if os_asset_col else ""),
                }
            )

        risk_series = _to_numeric(vuln_rows[risk_score_col]) if risk_score_col and not vuln_rows.empty else pd.Series(dtype="float64")
        vulnerability_titles = (
            sorted(set(vuln_rows[vuln_title_col].dropna().astype(str).tolist()))
            if vuln_title_col and not vuln_rows.empty
            else []
        )

        out_fixes.append(
            {
                "fix_id": fix_id,
                "fix_title": title,
                "kenna_score": kenna_score,
                "cvss": cvss_max,
                "exploit_known": exploit_known,
                "active_breach": active_breach,
                "has_malware": has_malware,
                "affected_hosts": affected_hosts,
                "requires_reboot": requires_reboot,
                "assets": asset_list,
                "metadata": {
                    "category": category,
                    "patch_publication_date": str(fix_rows[patch_date_col].iloc[0]).strip() if patch_date_col else "",
                    "diagnosis": str(fix_rows[diagnosis_col].iloc[0]).strip() if diagnosis_col else "",
                    "solution": str(fix_rows[solution_col].iloc[0]).strip() if solution_col else "",
                    "operating_system": os_value,
                    "cves": combined_cves,
                    "vulnerability_count": int(len(vuln_rows)),
                    "risk_score_max": round(_safe_float(risk_series.max()), 2) if not risk_series.empty else 0.0,
                    "risk_score_avg": round(_safe_float(risk_series.mean()), 2) if not risk_series.empty else 0.0,
                    "vulnerability_titles_sample": vulnerability_titles[:5],
                },
            }
        )

    payload = {
        "asset_group": asset_group_label,
        "fixes": out_fixes,
    }

    stats = BuildStats(
        assets_rows=len(assets_df),
        vulnerabilities_rows=len(vulns_df),
        fixes_rows=len(fixes_df),
        selected_fixes=len(out_fixes),
        fix_ids_with_no_vuln_rows=fix_ids_with_no_vuln_rows,
        sampled_assets_missing_join=sampled_assets_missing_join,
        total_sampled_assets=total_sampled_assets,
    )
    return payload, stats
