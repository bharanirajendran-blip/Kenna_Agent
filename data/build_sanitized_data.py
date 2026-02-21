"""
build_sanitized_data.py
=======================
Converts real Kenna CSV exports into a sanitized JSON dataset safe for
classroom / GitHub use.

Expected files in data/:
  - asset_export*.csv
  - vulnerability_export*.csv
  - fix_export*.csv

Usage:
  python data/build_sanitized_data.py
"""

from __future__ import annotations

import json
from pathlib import Path

from build_dataset_common import build_payload

DATA_DIR = Path(__file__).parent
OUT_PATH = DATA_DIR / "kenna_input_sanitized.json"
TOP_FIXES = 20
MAX_ASSETS_PER_FIX = 15
SALT = "uconn-class-salt-change-this"


def main() -> None:
    print("=" * 64)
    print(" Kenna Sanitized Data Builder (comprehensive 3-CSV join)")
    print("=" * 64)

    payload, stats = build_payload(
        data_dir=DATA_DIR,
        top_n=TOP_FIXES,
        max_assets_per_fix=MAX_ASSETS_PER_FIX,
        asset_group_label="Windows Servers (Sanitized Dataset)",
        anonymize_assets=True,
        anonymize_salt=SALT,
    )

    OUT_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(f"\n✅ Wrote: {OUT_PATH}")
    print(f"   Source rows: assets={stats.assets_rows}, vulns={stats.vulnerabilities_rows}, fixes={stats.fixes_rows}")
    print(f"   Output fixes: {stats.selected_fixes}")
    print(f"   Fixes with no vuln rows: {stats.fix_ids_with_no_vuln_rows}")
    print(
        "   Sampled assets missing asset-join: "
        f"{stats.sampled_assets_missing_join}/{stats.total_sampled_assets}"
    )


if __name__ == "__main__":
    main()
