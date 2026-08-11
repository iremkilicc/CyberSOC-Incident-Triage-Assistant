"""Run one retrieval + six per-card model calls for the QML frontend."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from card_prompts import CARD_LABELS, CARD_ORDER, build_card_messages
from card_validation import validate_card_payloads
from rag_service import build_context, format_history


ProgressCallback = Callable[[str], None]


class AnalysisCancelled(RuntimeError):
    """Raised when the analyst cancels between two card prompts."""


def _extract_json_object(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        payload = json.loads(text)
        if isinstance(payload, dict):
            return payload
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not match:
        return {}
    try:
        payload = json.loads(match.group(0))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _history_block(history: list[dict[str, str]] | None) -> str:
    formatted = format_history(history or [])
    if not formatted:
        return ""
    return (
        "\n\nPREVIOUS CONVERSATION (context only, not evidence):\n"
        f"{formatted}"
    )


def _source_list_text(chunks: list) -> str:
    lines: list[str] = []
    for index, chunk in enumerate(chunks, start=1):
        path = getattr(chunk, "source_path", "unknown")
        heading = getattr(chunk, "heading", "")
        score = float(getattr(chunk, "similarity", 0.0) or 0.0)
        lines.append(f"{index}. {path} — {heading} (score {score:.3f})")
    return "\n".join(lines) if lines else "No retrieved sources."


def _fallback_card(card_id: str, query: str) -> dict[str, Any]:
    if card_id == "evidence":
        return {
            "activeTitle": "NEW SECURITY EVENT",
            "activeRisk": "MEDIUM",
            "evidenceRows": [
                {
                    "kind": "ALERT",
                    "indicator": query[:64] or "Security event",
                    "detail": "Model card response unavailable; showing alert text",
                    "severity": "INFO",
                    "color": "#20d7ff",
                    "accent": "#20d7ff",
                }
            ],
        }
    if card_id == "mitre":
        return {
            "techniqueRows": [
                {
                    "id": "",
                    "name": "MITRE ATT&CK mapping unavailable",
                    "tactic": "Unmapped",
                    "risk": "MEDIUM",
                    "color": "#ffb22e",
                }
            ]
        }
    if card_id == "actions":
        return {
            "actionRows": [
                {
                    "p": "P2",
                    "title": "Continue investigation",
                    "detail": "Collect more evidence before containment",
                }
            ]
        }
    if card_id == "analysis":
        return {
            "incidentSummary": "Local model could not fill this card reliably.",
            "incidentAssessment": "Retry Analyze or regenerate after models are ready.",
            "likelyAttackPath": "Insufficient structured output for path reconstruction.",
            "missingInformation": "Provide richer alert fields and retry.",
            "activeRisk": "MEDIUM",
            "activeScore": 50,
        }
    if card_id == "sources":
        return {
            "sourceRows": [
                {
                    "name": "Local knowledge base",
                    "meta": "Fallback source row",
                    "relevance": 0.5,
                    "color": "#25d9ff",
                }
            ]
        }
    return {
        "timelineRows": [
            {
                "time": "T0",
                "title": "Alert received",
                "detail": query[:90] or "Security event",
                "color": "#20d7ff",
            }
        ]
    }


def analyze_with_card_prompts(
    engine,
    query: str,
    *,
    history: list[dict[str, str]] | None = None,
    progress_callback: ProgressCallback | None = None,
    should_cancel: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Retrieve once, then call the chat model once per card prompt."""

    def check_cancelled() -> None:
        if should_cancel is not None and should_cancel():
            raise AnalysisCancelled("Analysis cancelled by the analyst.")

    check_cancelled()
    chunks = engine.retrieve_chunks(query, history=history, top_k=3)
    context, sources = build_context(chunks) if chunks else ("", [])
    if not context:
        context = (
            "No strongly matching knowledge chunks were retrieved. "
            "Stay conservative and ask for missing fields."
        )

    history_block = _history_block(history)
    source_list = _source_list_text(chunks)
    card_payloads: dict[str, Any] = {}
    degraded: list[str] = []

    for index, card_id in enumerate(CARD_ORDER, start=1):
        check_cancelled()
        label = CARD_LABELS[card_id]
        if progress_callback:
            progress_callback(f"CARD {index}/6 · {label}")

        messages = build_card_messages(
            card_id=card_id,
            query=query,
            context=context[:3600],
            history_block=history_block,
            source_list=source_list,
        )
        try:
            raw = engine.complete_chat_messages(messages)
            parsed = _extract_json_object(raw)
            if not parsed:
                parsed = _fallback_card(card_id, query)
                degraded.append(label)
        except Exception as error:
            print(f"Card {card_id} failed: {error}")
            parsed = _fallback_card(card_id, query)
            degraded.append(label)
        card_payloads[card_id] = parsed

    from card_mapper import assemble_from_card_payloads

    card_payloads, validation_warnings, missing_cards = validate_card_payloads(card_payloads)

    mapped = assemble_from_card_payloads(
        query=query,
        card_payloads=card_payloads,
        sources=sources,
        grounded=bool(chunks),
    )
    mapped["degradedCards"] = degraded
    mapped["validationWarnings"] = validation_warnings
    mapped["missingCards"] = missing_cards
    return mapped
