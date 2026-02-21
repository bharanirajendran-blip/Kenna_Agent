from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

InputSourceMode = Literal["csv", "api"]


@dataclass(frozen=True)
class InputLoadResult:
    payload: Dict[str, Any]
    descriptor: str
    source_mode: InputSourceMode


def resolve_source_mode() -> InputSourceMode:
    mode = os.getenv("KENNA_SOURCE", "csv").strip().lower()
    if mode not in {"csv", "api"}:
        raise RuntimeError(
            "KENNA_SOURCE must be one of: csv, api "
            f"(received: '{mode or '<empty>'}')"
        )
    return mode  # type: ignore[return-value]


def default_csv_input_path(real_input: str, sanitized_input: str) -> str:
    return real_input if os.path.exists(real_input) else sanitized_input


def source_descriptor(mode: InputSourceMode, csv_input_path: str) -> str:
    if mode == "csv":
        return csv_input_path

    snapshot_path = os.getenv("KENNA_API_SNAPSHOT_PATH", "").strip()
    if snapshot_path:
        return snapshot_path

    normalized_url = os.getenv("KENNA_API_NORMALIZED_URL", "").strip()
    return normalized_url or "KENNA_API_NORMALIZED_URL"


def load_kenna_payload(mode: InputSourceMode, csv_input_path: str) -> InputLoadResult:
    if mode == "csv":
        with open(csv_input_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        return InputLoadResult(
            payload=payload,
            descriptor=csv_input_path,
            source_mode=mode,
        )

    snapshot_path = os.getenv("KENNA_API_SNAPSHOT_PATH", "").strip()
    if snapshot_path:
        with open(snapshot_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        return InputLoadResult(
            payload=_normalize_payload(raw),
            descriptor=snapshot_path,
            source_mode=mode,
        )

    raw = _fetch_api_payload()
    return InputLoadResult(
        payload=_normalize_payload(raw),
        descriptor=os.getenv("KENNA_API_NORMALIZED_URL", "").strip() or "kenna_api",
        source_mode=mode,
    )


def _fetch_api_payload() -> Dict[str, Any]:
    url = os.getenv("KENNA_API_NORMALIZED_URL", "").strip()
    token = os.getenv("KENNA_API_TOKEN", "").strip()
    timeout_seconds = float(os.getenv("KENNA_API_TIMEOUT", "20"))
    if not url:
        raise RuntimeError(
            "KENNA_SOURCE=api requires KENNA_API_NORMALIZED_URL "
            "(or KENNA_API_SNAPSHOT_PATH for offline testing)."
        )
    if not token:
        raise RuntimeError("KENNA_SOURCE=api requires KENNA_API_TOKEN.")

    req = Request(
        url=url,
        headers={
            "Accept": "application/json",
            "X-Risk-Token": token,
        },
        method="GET",
    )
    try:
        with urlopen(req, timeout=timeout_seconds) as resp:
            body = resp.read().decode("utf-8")
    except HTTPError as exc:
        raise RuntimeError(f"Kenna API request failed with HTTP {exc.code}: {exc.reason}") from exc
    except URLError as exc:
        raise RuntimeError(f"Kenna API request failed: {exc.reason}") from exc

    try:
        loaded = json.loads(body)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Kenna API response was not valid JSON") from exc

    if not isinstance(loaded, dict):
        raise RuntimeError("Kenna API response must be a JSON object")
    return loaded


def _normalize_payload(raw: Dict[str, Any]) -> Dict[str, Any]:
    if _is_normalized(raw):
        return raw

    raw_fixes = raw.get("fixes")
    if not isinstance(raw_fixes, list):
        raise RuntimeError(
            "API payload is not in expected format. Expected normalized fields "
            "asset_group + fixes[], or a mappable fixes[] object."
        )

    normalized_fixes: List[Dict[str, Any]] = []
    for item in raw_fixes:
        if not isinstance(item, dict):
            continue
        title = _first_str(item, ["fix_title", "title", "name", "fix"])
        if not title:
            continue
        assets_raw = _first_list(item, ["assets", "affected_assets", "hosts"])
        assets = [_normalize_asset(a) for a in assets_raw if isinstance(a, dict)]
        normalized_fixes.append(
            {
                "fix_title": title,
                "kenna_score": _first_float(item, ["kenna_score", "risk_meter_score", "risk_score"], 0.0),
                "cvss": _first_float(item, ["cvss", "cvss_score", "cvss_v3_score"], 0.0),
                "exploit_known": _first_bool(item, ["exploit_known", "exploitable", "known_exploit"], False),
                "active_breach": _first_bool(item, ["active_breach", "in_active_breach"], False),
                "has_malware": _first_bool(item, ["has_malware", "malware"], False),
                "affected_hosts": _first_int(item, ["affected_hosts", "vulnerability_count", "host_count"], len(assets)),
                "requires_reboot": _first_bool(item, ["requires_reboot", "reboot_required"], False),
                "assets": assets,
            }
        )

    payload = {
        "asset_group": _first_str(raw, ["asset_group", "asset_group_name", "group_name"]) or "Kenna API Import",
        "fixes": normalized_fixes,
    }
    return payload


def _is_normalized(raw: Dict[str, Any]) -> bool:
    return isinstance(raw.get("asset_group"), str) and isinstance(raw.get("fixes"), list)


def _normalize_asset(raw_asset: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "hostname": _first_str(raw_asset, ["hostname", "host", "name"]) or "unknown-host",
        "owner_group": _first_str(raw_asset, ["owner_group", "owner", "team"]) or "Unassigned",
        "environment": _normalize_env(
            _first_str(raw_asset, ["environment", "env"]) or "non-production"
        ),
        "criticality": _normalize_criticality(
            _first_str(raw_asset, ["criticality", "asset_criticality"]) or "medium"
        ),
    }


def _normalize_env(value: str) -> str:
    lowered = value.strip().lower()
    if lowered == "production":
        return "production"
    return "non-production"


def _normalize_criticality(value: str) -> str:
    lowered = value.strip().lower()
    if lowered in {"high", "medium", "low"}:
        return lowered
    return "medium"


def _first_str(data: Dict[str, Any], keys: List[str]) -> str:
    for key in keys:
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _first_list(data: Dict[str, Any], keys: List[str]) -> List[Any]:
    for key in keys:
        value = data.get(key)
        if isinstance(value, list):
            return value
    return []


def _first_float(data: Dict[str, Any], keys: List[str], default: float) -> float:
    for key in keys:
        value = data.get(key)
        if value is None:
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    return default


def _first_int(data: Dict[str, Any], keys: List[str], default: int) -> int:
    for key in keys:
        value = data.get(key)
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return default


def _first_bool(data: Dict[str, Any], keys: List[str], default: bool) -> bool:
    for key in keys:
        value = data.get(key)
        if value is None:
            continue
        return _coerce_bool(value)
    return default


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "y"}:
            return True
        if lowered in {"0", "false", "no", "n"}:
            return False
    return bool(value)
