"""Per-card prompt lenses for CyberSOC QML analysis.

Each card gets its own system+task prompt. Analyze runs one shared retrieval,
then one model call per card (six calls total).
"""

from __future__ import annotations

CARD_ORDER = (
    "evidence",
    "mitre",
    "actions",
    "analysis",
    "sources",
    "timeline",
)

CARD_LABELS = {
    "evidence": "KEY EVIDENCE",
    "mitre": "MITRE ATT&CK",
    "actions": "ANALYST ACTIONS",
    "analysis": "AI INCIDENT ANALYSIS",
    "sources": "CORRELATED SOURCES",
    "timeline": "TIMELINE",
}

SHARED_RULES = """
You are a defensive SOC triage assistant for CyberSOC.
Rules:
- Use only the user alert and the provided knowledge context.
- Do not invent IOCs, hosts, users, or MITRE IDs that are not supported.
- Do not suggest automatic blocking, account disable, or malware creation.
- Prefer cautious language and human approval for containment.
- Reply with JSON only. No markdown fences. No extra text.
""".strip()

CARD_PROMPTS: dict[str, str] = {
    "evidence": """
CARD FOCUS: Key Evidence
Extract confirmed or strongly suggested indicators from the alert.

Return JSON:
{
  "activeTitle": "SHORT ENGLISH TITLE",
  "activeRisk": "CRITICAL|HIGH|MEDIUM|LOW",
  "evidenceRows": [
    {
      "kind": "PROCESS|PARENT|NETWORK|USER|EMAIL|IP|FILE|ALERT",
      "indicator": "short indicator",
      "detail": "one-line detail",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "color": "#ff4055",
      "accent": "#20d7ff"
    }
  ]
}
Use at most 6 evidenceRows. activeRisk must match evidence severity.
""".strip(),
    "mitre": """
CARD FOCUS: MITRE ATT&CK Mapping
Map the activity to likely ATT&CK techniques.

Return JSON:
{
  "techniqueRows": [
    {
      "id": "T1059.001",
      "name": "PowerShell",
      "tactic": "Execution",
      "risk": "HIGH",
      "color": "#ff7a3d"
    }
  ]
}
Use at most 4 techniques. Prefer techniques mentioned in the knowledge context.
If unsure, use broader technique IDs and say so in the name.
""".strip(),
    "actions": """
CARD FOCUS: Analyst Actions
Propose defensive next steps for a human analyst.

Return JSON:
{
  "actionRows": [
    {
      "p": "P1",
      "title": "short action",
      "detail": "why / how, require approval if containment"
    }
  ]
}
Use at most 5 actions. Priorities: P1 most urgent, then P2, P3.
No automatic blocking language.
""".strip(),
    "analysis": """
CARD FOCUS: AI Incident Analysis
Write a concise triage narrative.

Return JSON:
{
  "incidentSummary": "2-4 sentences",
  "incidentAssessment": "2-4 sentences",
  "likelyAttackPath": "1-3 sentences",
  "missingInformation": "what to ask or collect next",
  "activeRisk": "CRITICAL|HIGH|MEDIUM|LOW",
  "activeScore": 0
}
activeScore is an integer 0-100.
""".strip(),
    "sources": """
CARD FOCUS: Correlated Sources
Summarize which knowledge-base sources are most relevant.

Return JSON:
{
  "sourceRows": [
    {
      "name": "filename or short title",
      "meta": "why relevant",
      "relevance": 0.0,
      "color": "#25d9ff"
    }
  ]
}
Use the provided source list. relevance is 0.0-1.0. At most 5 rows.
""".strip(),
    "timeline": """
CARD FOCUS: Timeline
Build a short chronological reconstruction.

Return JSON:
{
  "timelineRows": [
    {
      "time": "T0",
      "title": "event title",
      "detail": "one-line detail",
      "color": "#20d7ff"
    }
  ]
}
Use 3-5 rows (T0..Tn). Keep it grounded in the alert.
""".strip(),
}


def build_card_messages(
    *,
    card_id: str,
    query: str,
    context: str,
    history_block: str,
    source_list: str = "",
) -> list[dict[str, str]]:
    card_prompt = CARD_PROMPTS[card_id]
    extra = ""
    if card_id == "sources" and source_list:
        extra = f"\n\nRETRIEVED SOURCE LIST:\n{source_list}\n"

    user_prompt = f"""
USER ALERT / FINDING:
{query}
{history_block}

KNOWLEDGE CONTEXT:
{context}
{extra}

CARD TASK:
{card_prompt}
""".strip()

    return [
        {"role": "system", "content": SHARED_RULES},
        {"role": "user", "content": user_prompt},
    ]
