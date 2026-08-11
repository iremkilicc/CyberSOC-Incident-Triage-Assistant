"""Map RAG / per-card model outputs into the six QML analysis cards."""

from __future__ import annotations

import json
import re
from typing import Any


SECTION_ALIASES = {
    "olay sınıflandırması": "classification",
    "ön değerlendirme": "assessment",
    "risk ve gerekçe": "risk",
    "doğrulanmış bulgular": "evidence",
    "toplanacak kanıtlar": "collect",
    "önerilen aksiyonlar": "actions",
    "eksik bilgiler / takip soruları": "questions",
    "kullanılan kaynaklar": "sources",
}

RISK_EN = {
    "Kritik": ("CRITICAL", "#ff3e52", 92),
    "Yüksek": ("HIGH", "#ff7a3d", 81),
    "Orta": ("MEDIUM", "#ffb22e", 64),
    "Düşük": ("LOW", "#52d889", 34),
    "Belirsiz": ("MEDIUM", "#ffb22e", 50),
}

SEVERITY_COLORS = {
    "CRITICAL": "#ff4055",
    "HIGH": "#ff7a3d",
    "MEDIUM": "#ffb22e",
    "LOW": "#52d889",
    "INFO": "#20d7ff",
}

EVIDENCE_ACCENT = "#20d7ff"
SOURCE_ACCENT = "#25d9ff"
TIMELINE_ACCENTS = ("#20d7ff", "#398dff", "#ff8a3d", "#52d889")


def _clean_markdown(value: str) -> str:
    return value.replace("**", "").replace("__", "").replace("`", "").strip()


def parse_response_sections(content: str) -> dict[str, str]:
    sections: dict[str, list[str]] = {"intro": []}
    current = "intro"

    for raw_line in content.splitlines():
        stripped = raw_line.strip()
        if stripped.startswith("## "):
            heading = _clean_markdown(stripped[3:]).casefold()
            current = SECTION_ALIASES.get(heading, f"other:{heading}")
            sections.setdefault(current, [])
            continue
        sections.setdefault(current, []).append(raw_line)

    return {
        key: "\n".join(lines).strip()
        for key, lines in sections.items()
        if "\n".join(lines).strip()
    }


def extract_risk_tr(content: str) -> str:
    normalized = _clean_markdown(content)
    patterns = (
        r"Risk ve Gerekçe\s*\n+\s*(Kritik|Yüksek|Orta|Düşük|Belirsiz)\s*:",
        r"\*\*(Kritik|Yüksek|Orta|Düşük|Belirsiz)\*\*\s*:",
        r"(?:Risk|Öncelik)\s*:\s*(Kritik|Yüksek|Orta|Düşük|Belirsiz)\b",
    )
    for pattern in patterns:
        match = re.search(pattern, normalized, flags=re.IGNORECASE)
        if match:
            value = match.group(1).casefold()
            return {
                "kritik": "Kritik",
                "yüksek": "Yüksek",
                "orta": "Orta",
                "düşük": "Düşük",
                "belirsiz": "Belirsiz",
            }.get(value, "Orta")
    return "Orta"


def _split_lines(section: str) -> list[str]:
    return [_clean_markdown(line) for line in section.splitlines() if _clean_markdown(line)]


def _bullets(section: str, *, limit: int = 6) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    for line in _split_lines(section):
        text = line[2:].strip() if line.startswith("- ") else line
        if not text:
            continue
        if ":" in text and len(text.split(":", 1)[0]) < 40:
            label, detail = text.split(":", 1)
            items.append((label.strip(), detail.strip()))
        else:
            items.append(("Finding", text))
        if len(items) >= limit:
            break
    return items


def _guess_title(query: str, classification: str) -> str:
    seed = classification or query
    seed = _clean_markdown(seed).split("\n")[0].strip()
    if not seed:
        return "NEW SECURITY EVENT"
    lowered = f"{query}\n{seed}".lower()
    if "powershell" in lowered:
        return "SUSPICIOUS POWERSHELL ACTIVITY"
    if "phish" in lowered or "oltalama" in lowered:
        return "PHISHING EMAIL DETECTED"
    if "brute" in lowered or "failed" in lowered or "başarısız" in lowered:
        return "BRUTE FORCE ATTACK"
    if "oauth" in lowered:
        return "OAUTH ABUSE"
    if "exfil" in lowered or "exfiltration" in lowered:
        return "DATA EXFILTRATION"
    if "credential" in lowered or "lsass" in lowered:
        return "CREDENTIAL DUMPING"
    return seed[:72].upper()


def _techniques(content: str, *, limit: int = 4) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    risk = "HIGH"
    color = SEVERITY_COLORS["HIGH"]
    for match in re.finditer(r"(T\d{4}(?:\.\d{3})?)", content):
        technique = match.group(1)
        if technique in seen:
            continue
        seen.add(technique)
        window = content[max(0, match.start() - 80) : match.end() + 80].lower()
        name = "Technique mapping"
        tactic = "Execution"
        if "phish" in window:
            name, tactic = "Phishing", "Initial Access"
        elif "powershell" in window or "script" in window:
            name, tactic = "PowerShell", "Execution"
        elif "credential" in window or "password" in window:
            name, tactic = "Credential Access", "Credential Access"
        elif "exfil" in window or "cloud" in window:
            name, tactic = "Exfiltration", "Exfiltration"
        rows.append(
            {
                "id": technique,
                "name": name,
                "tactic": tactic,
                "risk": risk,
                "color": color,
            }
        )
        if len(rows) >= limit:
            break
    if not rows:
        rows.append(
            {
                "id": "",
                "name": "MITRE ATT&CK mapping unavailable",
                "tactic": "Unmapped",
                "risk": "MEDIUM",
                "color": SEVERITY_COLORS["MEDIUM"],
            }
        )
    return rows


def _evidence_rows(section: str, risk_en: str) -> list[dict[str, str]]:
    color = SEVERITY_COLORS.get(risk_en, SEVERITY_COLORS["MEDIUM"])
    rows: list[dict[str, str]] = []
    for label, detail in _bullets(section, limit=6):
        kind = label.upper()[:18] if label != "Finding" else "FINDING"
        rows.append(
            {
                "kind": kind,
                "indicator": detail[:64] if label == "Finding" else label[:64],
                "detail": detail[:120] if label != "Finding" else "Observed indicator",
                "severity": risk_en if risk_en != "MEDIUM" else "HIGH",
                "color": color,
                "accent": "#20d7ff",
            }
        )
    if not rows:
        rows.append(
            {
                "kind": "ALERT",
                "indicator": "Security event received",
                "detail": "Awaiting richer telemetry",
                "severity": "INFO",
                "color": SEVERITY_COLORS["INFO"],
                "accent": "#20d7ff",
            }
        )
    return rows


def _action_rows(section: str) -> list[dict[str, str]]:
    priorities = ["P1", "P1", "P2", "P2", "P3"]
    rows: list[dict[str, str]] = []
    for index, (label, detail) in enumerate(_bullets(section, limit=5)):
        title = label if label != "Finding" else detail[:70]
        body = detail if label != "Finding" else "Recommended analyst response"
        rows.append(
            {
                "p": priorities[index] if index < len(priorities) else "P3",
                "title": title[:90],
                "detail": body[:120],
            }
        )
    if not rows:
        rows.append(
            {
                "p": "P2",
                "title": "Continue investigation",
                "detail": "Collect more evidence before containment",
            }
        )
    return rows


def _source_rows(sources: list[Any], section: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for source in sources[:5]:
        path = getattr(source, "source_path", None) or str(source)
        heading = getattr(source, "heading", "") or "Knowledge base"
        similarity = float(getattr(source, "similarity", 0.72) or 0.72)
        name = path.replace("\\", "/").split("/")[-1]
        rows.append(
            {
                "name": name[:40],
                "meta": f"{heading[:48]} · score {similarity:.2f}",
                "relevance": max(0.2, min(0.98, similarity)),
                "color": "#25d9ff",
            }
        )
    if rows:
        return rows
    for label, detail in _bullets(section, limit=4):
        rows.append(
            {
                "name": (label if label != "Finding" else detail)[:40],
                "meta": detail[:52],
                "relevance": 0.7,
                "color": "#25d9ff",
            }
        )
    if not rows:
        rows.append(
            {
                "name": "Local knowledge base",
                "meta": "Playbook / MITRE correlation",
                "relevance": 0.65,
                "color": "#25d9ff",
            }
        )
    return rows


def _timeline_rows(query: str, sections: dict[str, str]) -> list[dict[str, str]]:
    title = _guess_title(query, sections.get("classification", ""))
    return [
        {
            "time": "T0",
            "title": "Alert received",
            "detail": (query[:90] + ("…" if len(query) > 90 else "")) or title,
            "color": "#20d7ff",
        },
        {
            "time": "T1",
            "title": "Local retrieval",
            "detail": "Knowledge base chunks correlated for this scenario",
            "color": "#398dff",
        },
        {
            "time": "T2",
            "title": "Structured triage",
            "detail": _clean_markdown(sections.get("assessment", "Model assessment generated"))[:110],
            "color": "#ff8a3d",
        },
        {
            "time": "T3",
            "title": "Analyst actions prepared",
            "detail": "Defensive next steps listed for human approval",
            "color": "#52d889",
        },
    ]


def map_rag_to_cards(
    *,
    query: str,
    answer: str,
    sources: list[Any] | None = None,
    grounded: bool = True,
) -> dict[str, Any]:
    """One shared RAG answer → six-card payload for QML."""
    sources = sources or []
    formatted = answer
    sections = parse_response_sections(formatted)
    risk_tr = extract_risk_tr(formatted)
    risk_en, risk_color, score = RISK_EN.get(risk_tr, RISK_EN["Orta"])
    title = _guess_title(query, sections.get("classification", ""))

    summary = _clean_markdown(
        sections.get("classification")
        or sections.get("intro")
        or "Local model produced a structured triage summary."
    )
    assessment = _clean_markdown(
        sections.get("assessment") or "Additional confirmation is recommended."
    )
    path = _clean_markdown(
        sections.get("risk")
        or "Likely path depends on confirmed identity, endpoint and mail/cloud signals."
    )
    missing = _clean_markdown(
        sections.get("questions")
        or sections.get("collect")
        or "Provide timestamps, affected identity and supporting log fields."
    )

    return {
        "activeTitle": title,
        "activeRisk": risk_en,
        "activeRiskColor": risk_color,
        "activeScore": score,
        "grounded": grounded,
        "incidentSummary": summary[:600],
        "incidentAssessment": assessment[:600],
        "likelyAttackPath": path[:600],
        "missingInformation": missing[:600],
        "evidenceRows": _evidence_rows(
            sections.get("evidence") or sections.get("collect") or "",
            risk_en,
        ),
        "techniqueRows": _techniques(formatted),
        "actionRows": _action_rows(sections.get("actions") or ""),
        "sourceRows": _source_rows(sources, sections.get("sources") or ""),
        "timelineRows": _timeline_rows(query, sections),
        "rawAnswer": formatted,
        "strategy": "shared_prompt_legacy",
    }


def _normalize_risk_en(value: Any) -> str:
    text = str(value or "MEDIUM").strip().upper()
    if text in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return text
    mapping = {
        "KRITIK": "CRITICAL",
        "KRİTİK": "CRITICAL",
        "YUKSEK": "HIGH",
        "YÜKSEK": "HIGH",
        "ORTA": "MEDIUM",
        "DUSUK": "LOW",
        "DÜŞÜK": "LOW",
    }
    return mapping.get(text, "MEDIUM")


def _risk_color_for(risk_en: str) -> tuple[str, int]:
    table = {
        "CRITICAL": ("#ff3e52", 92),
        "HIGH": ("#ff7a3d", 81),
        "MEDIUM": ("#ffb22e", 64),
        "LOW": ("#52d889", 34),
    }
    return table.get(risk_en, table["MEDIUM"])


def _severity_color(value: Any, fallback: str) -> str:
    text = str(value or "").strip().upper()
    if text in SEVERITY_COLORS:
        return SEVERITY_COLORS[text]
    return SEVERITY_COLORS.get(_normalize_risk_en(text), fallback)


def _dict_rows(payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
    """Copy payload[key] into plain dict rows, write them back and return them."""
    source = payload.get(key)
    if not isinstance(source, list):
        return []
    rows = [dict(row) for row in source if isinstance(row, dict)]
    payload[key] = rows
    return rows


def _ensure_row_colors(payload: dict[str, Any], *, risk_en: str) -> dict[str, Any]:
    """Fill the color fields the QML row delegates bind to.

    Model-authored card JSON omits them and a QML color property rejects
    undefined, so rows are normalized before they can reach a delegate.
    """
    fallback = SEVERITY_COLORS.get(risk_en, SEVERITY_COLORS["MEDIUM"])

    for row in _dict_rows(payload, "evidenceRows"):
        if not row.get("severity"):
            row["severity"] = risk_en
        if not row.get("color"):
            row["color"] = _severity_color(row.get("severity"), fallback)
        if not row.get("accent"):
            row["accent"] = EVIDENCE_ACCENT

    for row in _dict_rows(payload, "techniqueRows"):
        if not row.get("risk"):
            row["risk"] = risk_en
        if not row.get("color"):
            row["color"] = _severity_color(row.get("risk"), fallback)

    for row in _dict_rows(payload, "sourceRows"):
        if not row.get("color"):
            row["color"] = SOURCE_ACCENT

    for index, row in enumerate(_dict_rows(payload, "timelineRows")):
        if not row.get("color"):
            row["color"] = TIMELINE_ACCENTS[index % len(TIMELINE_ACCENTS)]

    return payload


def assemble_from_card_payloads(
    *,
    query: str,
    card_payloads: dict[str, Any],
    sources: list[Any] | None = None,
    grounded: bool = True,
) -> dict[str, Any]:
    """Merge six per-card JSON payloads into the QML result object."""
    sources = sources or []
    evidence = card_payloads.get("evidence") or {}
    mitre = card_payloads.get("mitre") or {}
    actions = card_payloads.get("actions") or {}
    analysis = card_payloads.get("analysis") or {}
    sources_card = card_payloads.get("sources") or {}
    timeline = card_payloads.get("timeline") or {}

    risk_en = _normalize_risk_en(
        analysis.get("activeRisk") or evidence.get("activeRisk") or "MEDIUM"
    )
    risk_color, default_score = _risk_color_for(risk_en)
    try:
        score = int(analysis.get("activeScore", default_score))
    except (TypeError, ValueError):
        score = default_score
    score = max(0, min(100, score))

    title = str(evidence.get("activeTitle") or "").strip()
    if not title:
        title = _guess_title(query, str(analysis.get("incidentSummary") or ""))

    evidence_rows = evidence.get("evidenceRows")
    if not isinstance(evidence_rows, list) or not evidence_rows:
        evidence_rows = _evidence_rows("", risk_en)

    technique_rows = mitre.get("techniqueRows")
    if not isinstance(technique_rows, list) or not technique_rows:
        technique_rows = _techniques(query)

    action_rows = actions.get("actionRows")
    if not isinstance(action_rows, list) or not action_rows:
        action_rows = _action_rows("")

    source_rows = sources_card.get("sourceRows")
    if not isinstance(source_rows, list) or not source_rows:
        source_rows = _source_rows(sources, "")

    timeline_rows = timeline.get("timelineRows")
    if not isinstance(timeline_rows, list) or not timeline_rows:
        timeline_rows = _timeline_rows(query, {})

    mapped = {
        "activeTitle": title[:72].upper(),
        "activeRisk": risk_en,
        "activeRiskColor": risk_color,
        "activeScore": score,
        "grounded": grounded,
        "incidentSummary": str(analysis.get("incidentSummary") or "")[:600],
        "incidentAssessment": str(analysis.get("incidentAssessment") or "")[:600],
        "likelyAttackPath": str(analysis.get("likelyAttackPath") or "")[:600],
        "missingInformation": str(analysis.get("missingInformation") or "")[:600],
        "evidenceRows": evidence_rows[:6],
        "techniqueRows": technique_rows[:4],
        "actionRows": action_rows[:5],
        "sourceRows": source_rows[:5],
        "timelineRows": timeline_rows[:6],
        "cardPayloads": card_payloads,
        "strategy": "per_card_prompts",
    }
    return _ensure_row_colors(mapped, risk_en=risk_en)


def load_assistant_payload(query: str, raw: str) -> dict[str, Any]:
    """Load either per-card JSON history or legacy markdown answers."""
    text = (raw or "").strip()
    if text.startswith("{"):
        try:
            payload = json.loads(text)
            if isinstance(payload, dict) and "evidenceRows" in payload:
                payload.setdefault("strategy", "per_card_prompts")
                return _ensure_row_colors(
                    payload,
                    risk_en=_normalize_risk_en(payload.get("activeRisk")),
                )
        except json.JSONDecodeError:
            pass
    return map_rag_to_cards(query=query, answer=raw, sources=[], grounded=True)
