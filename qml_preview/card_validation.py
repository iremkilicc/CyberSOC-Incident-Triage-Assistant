"""Deterministic validation for model-authored card payloads."""

from __future__ import annotations

import re
from typing import Any

CARD_KEYS = {
    "evidence": "evidenceRows",
    "mitre": "techniqueRows",
    "actions": "actionRows",
    "analysis": "incidentSummary",
    "sources": "sourceRows",
    "timeline": "timelineRows",
}
VALID_RISKS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
MITRE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
FABRICATED_IDS = {"T0000", "T9999"}


def validate_card_payloads(payloads: dict[str, Any]) -> tuple[dict[str, dict], list[str], list[str]]:
    """Normalize shapes and report conservative, model-free inconsistencies."""
    normalized: dict[str, dict] = {}
    warnings: list[str] = []
    missing: list[str] = []

    for card_id, required_key in CARD_KEYS.items():
        value = payloads.get(card_id)
        if not isinstance(value, dict):
            value = {}
        normalized[card_id] = dict(value)
        required_value = value.get(required_key)
        if required_key.endswith("Rows"):
            if not isinstance(required_value, list) or not required_value:
                missing.append(card_id)
        elif not str(required_value or "").strip():
            missing.append(card_id)

    risks = []
    for card_id in ("analysis", "evidence"):
        risk = str(normalized[card_id].get("activeRisk") or "").upper()
        if risk in VALID_RISKS:
            risks.append((card_id, risk))
    if len({risk for _, risk in risks}) > 1:
        warnings.append("Risk levels conflict between analysis cards.")

    technique_rows = normalized["mitre"].get("techniqueRows")
    clean_techniques = []
    if isinstance(technique_rows, list):
        for row in technique_rows:
            if not isinstance(row, dict):
                continue
            clean = dict(row)
            technique_id = str(clean.get("id") or "").strip().upper()
            if technique_id in FABRICATED_IDS or (technique_id and not MITRE_ID.fullmatch(technique_id)):
                warnings.append("An invalid MITRE ATT&CK identifier was removed.")
                technique_id = ""
            clean["id"] = technique_id
            if not technique_id:
                clean["name"] = "MITRE ATT&CK mapping unavailable"
                clean["tactic"] = "Unmapped"
            clean_techniques.append(clean)
    normalized["mitre"]["techniqueRows"] = clean_techniques

    evidence_rows = normalized["evidence"].get("evidenceRows")
    if clean_techniques and not (isinstance(evidence_rows, list) and evidence_rows):
        warnings.append("MITRE mapping is present without structured evidence.")

    return normalized, list(dict.fromkeys(warnings)), missing
