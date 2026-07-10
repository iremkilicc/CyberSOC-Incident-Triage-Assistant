import base64
import json
import re
import sys
from pathlib import Path

import streamlit as st


st.set_page_config(
    page_title="CyberSOC Incident Triage Assistant",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


PROJECT_ROOT = Path(__file__).parent
SRC_DIR = PROJECT_ROOT / "src"
SAMPLE_ALERTS_DIR = PROJECT_ROOT / "knowledge_base" / "sample_alerts"
OUTPUT_DIR = PROJECT_ROOT / "outputs"
ASSETS_DIR = PROJECT_ROOT / "assets"

HERO_IMAGE_PATH = ASSETS_DIR / "cybersoc_hero.png"
LOGO_IMAGE_PATH = ASSETS_DIR / "cybersoc_logo.png"

sys.path.append(str(SRC_DIR))

from build_context import retrieve, build_context, detect_query_category
from build_answer_prompt import build_answer_prompt
from query_builder import build_query_from_alert


IMPORTANT_FIELDS = [
    "alert_id",
    "category",
    "risk_level",
    "title",
    "description",
    "user",
    "account_type",
    "destination_system",
    "source_ip",
    "source_ip_type",
    "failed_attempt_count",
    "time_window_minutes",
    "success_after_failures",
    "login_status",
    "mfa_status",
    "geo_location",
    "user_agent",
    "business_hours",
    "post_login_activity",
    "sender_email",
    "sender_display_name",
    "reply_to",
    "recipient",
    "subject",
    "delivery_status",
    "spf_result",
    "dkim_result",
    "dmarc_result",
    "url_present",
    "url",
    "visible_link_text",
    "landing_page_behavior",
    "attachment_present",
    "user_clicked",
    "credentials_entered",
    "attachment_opened",
    "suspicious_login_after_click",
    "same_email_seen_in_other_mailboxes",
    "affected_mailboxes_count",
    "hostname",
    "user_type",
    "process_name",
    "command_line",
    "parent_process",
    "encoded_command_present",
    "network_connection",
    "destination_ip",
    "destination_domain",
    "file_created",
    "file_path",
    "registry_change",
    "scheduled_task_created",
    "edr_alert",
    "related_phishing_alert",
]


def asset_to_base64(path):
    if not path.exists():
        return None

    with path.open("rb") as file:
        encoded = base64.b64encode(file.read()).decode("utf-8")

    return f"data:image/png;base64,{encoded}"


def apply_custom_css():
    st.markdown(
        """
        <style>
        :root {
            --bg-main: #050812;
            --panel: #07111F;
            --panel-soft: #0B1627;
            --panel-deep: #040A14;
            --cyan: #00E5FF;
            --cyan-soft: rgba(0, 229, 255, 0.18);
            --green: #00FF9C;
            --blue: #38BDF8;
            --purple: #A855F7;
            --red: #EF4444;
            --amber: #F59E0B;
            --success: #22C55E;
            --text: #E6EDF3;
            --muted: #94A3B8;
        }

        .stApp {
            background:
                radial-gradient(circle at 18% 8%, rgba(0, 229, 255, 0.16), transparent 28%),
                radial-gradient(circle at 88% 5%, rgba(0, 255, 156, 0.08), transparent 26%),
                linear-gradient(180deg, #050812 0%, #08111F 52%, #040812 100%);
            color: var(--text);
        }

        .block-container {
            padding-top: 0.8rem;
            max-width: 1520px;
        }

        section[data-testid="stSidebar"] {
            background: linear-gradient(180deg, #050812, #07111F);
            border-right: 1px solid rgba(0, 229, 255, 0.18);
        }

        section[data-testid="stSidebar"] * {
            color: var(--text);
        }

        .topbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 14px;
            border: 1px solid rgba(0, 229, 255, 0.15);
            background: rgba(7, 17, 31, 0.82);
            border-radius: 16px;
            margin-bottom: 14px;
        }

        .topbar-left {
            display: flex;
            gap: 20px;
            font-size: 0.88rem;
            color: var(--muted);
        }

        .topbar-active {
            color: var(--cyan);
            font-weight: 800;
            border-bottom: 2px solid var(--cyan);
            padding-bottom: 3px;
        }

        .topbar-right {
            display: flex;
            gap: 16px;
            color: var(--muted);
            font-size: 0.85rem;
        }

        .healthy-dot {
            display: inline-block;
            width: 8px;
            height: 8px;
            background: var(--green);
            border-radius: 999px;
            box-shadow: 0 0 12px var(--green);
            margin-right: 6px;
        }

        .sidebar-brand {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 10px 0 18px 0;
        }

        .sidebar-logo {
            width: 58px;
            height: 58px;
            border-radius: 18px;
            object-fit: cover;
            border: 1px solid rgba(0, 229, 255, 0.40);
            box-shadow: 0 0 22px rgba(0, 229, 255, 0.22);
        }

        .sidebar-logo-fallback {
            width: 58px;
            height: 58px;
            border-radius: 18px;
            display: flex;
            justify-content: center;
            align-items: center;
            background: rgba(0, 229, 255, 0.08);
            border: 1px solid rgba(0, 229, 255, 0.40);
            font-size: 1.7rem;
        }

        .brand-title {
            font-size: 1.35rem;
            font-weight: 900;
            color: #F8FAFC;
            line-height: 1.05;
        }

        .brand-subtitle {
            font-size: 0.78rem;
            color: var(--cyan);
            font-weight: 700;
            margin-top: 4px;
        }

        .sidebar-card {
            padding: 14px;
            background: rgba(11, 22, 39, 0.72);
            border: 1px solid rgba(0, 229, 255, 0.16);
            border-radius: 16px;
            margin: 14px 0;
        }

        .sidebar-title {
            font-weight: 900;
            color: #CBD5E1;
            font-size: 0.78rem;
            letter-spacing: 0.08em;
            margin-bottom: 10px;
        }

        .side-link {
            padding: 10px 12px;
            border-radius: 12px;
            background: linear-gradient(90deg, rgba(0, 229, 255, 0.18), rgba(56, 189, 248, 0.08));
            border: 1px solid rgba(0, 229, 255, 0.28);
            margin-bottom: 10px;
            font-weight: 800;
            color: #F8FAFC;
            box-shadow: 0 0 20px rgba(0, 229, 255, 0.10);
        }

        .scenario-chip {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 10px 11px;
            border-radius: 12px;
            margin: 9px 0;
            background: rgba(4, 10, 20, 0.82);
            font-size: 0.87rem;
            font-weight: 800;
        }

        .bf-chip { border: 1px solid rgba(0, 229, 255, 0.35); }
        .ph-chip { border: 1px solid rgba(168, 85, 247, 0.45); }
        .ps-chip { border: 1px solid rgba(34, 197, 94, 0.45); }

        .mini-code {
            padding: 2px 7px;
            border-radius: 8px;
            font-size: 0.72rem;
            font-weight: 900;
        }

        .bf-code { color: var(--cyan); border: 1px solid rgba(0, 229, 255, 0.5); }
        .ph-code { color: var(--purple); border: 1px solid rgba(168, 85, 247, 0.55); }
        .ps-code { color: var(--success); border: 1px solid rgba(34, 197, 94, 0.55); }

        .safe-card {
            padding: 15px;
            border-radius: 16px;
            background: rgba(0, 255, 156, 0.06);
            border: 1px solid rgba(0, 255, 156, 0.30);
            box-shadow: 0 0 24px rgba(0, 255, 156, 0.08);
        }

        .safe-title {
            color: var(--green);
            font-weight: 900;
            margin-bottom: 10px;
        }

        .safe-item {
            color: #D1FAE5;
            font-size: 0.82rem;
            margin: 6px 0;
        }

        .hero {
            position: relative;
            display: grid;
            grid-template-columns: 0.95fr 1.15fr;
            align-items: center;
            gap: 24px;
            padding: 26px;
            min-height: 265px;
            border-radius: 22px;
            border: 1px solid rgba(0, 229, 255, 0.22);
            background:
                linear-gradient(135deg, rgba(7, 17, 31, 0.96), rgba(4, 10, 20, 0.92));
            overflow: hidden;
            box-shadow: 0 0 40px rgba(0, 229, 255, 0.10);
            margin-bottom: 16px;
        }

        .hero:before {
            content: "";
            position: absolute;
            inset: 0;
            background:
                linear-gradient(rgba(0,229,255,0.05) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0,229,255,0.04) 1px, transparent 1px);
            background-size: 34px 34px;
            opacity: 0.6;
            pointer-events: none;
        }

        .hero-copy {
            position: relative;
            z-index: 2;
        }

        .kicker {
            color: var(--green);
            font-weight: 900;
            font-size: 0.78rem;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            margin-bottom: 10px;
        }

        .hero-title {
            color: #F8FAFC;
            font-size: 2.25rem;
            font-weight: 950;
            line-height: 1.05;
            text-shadow: 0 0 18px rgba(0,229,255,0.28);
            margin-bottom: 13px;
        }

        .hero-desc {
            color: #CBD5E1;
            font-size: 1rem;
            line-height: 1.55;
            margin-bottom: 15px;
        }

        .hero-badges {
            display: flex;
            flex-wrap: wrap;
            gap: 9px;
        }

        .hero-badge {
            padding: 8px 11px;
            border-radius: 999px;
            background: rgba(15, 23, 42, 0.75);
            border: 1px solid rgba(0, 229, 255, 0.24);
            color: #E2E8F0;
            font-size: 0.78rem;
            font-weight: 800;
        }

        .hero-img-wrap {
            position: relative;
            z-index: 2;
            border-radius: 18px;
            overflow: hidden;
            border: 1px solid rgba(0, 229, 255, 0.18);
            box-shadow: 0 0 32px rgba(0,229,255,0.16);
            background: #040A14;
        }

        .hero-img-wrap img {
            width: 100%;
            height: 245px;
            object-fit: cover;
            display: block;
            opacity: 0.94;
        }

        .hero-placeholder {
            height: 245px;
            display: flex;
            justify-content: center;
            align-items: center;
            color: var(--cyan);
            font-size: 4rem;
            background: radial-gradient(circle, rgba(0,229,255,0.18), transparent 55%);
        }

        .input-card,
        .panel-card {
            background: linear-gradient(180deg, rgba(7, 17, 31, 0.96), rgba(4, 10, 20, 0.96));
            border: 1px solid rgba(0, 229, 255, 0.18);
            border-radius: 18px;
            padding: 18px;
            box-shadow: 0 0 30px rgba(0,229,255,0.07);
            margin-bottom: 14px;
        }

        .section-title {
            display: flex;
            align-items: center;
            gap: 9px;
            color: #F8FAFC;
            font-weight: 950;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            font-size: 0.88rem;
            margin-bottom: 8px;
        }

        .number-dot {
            width: 27px;
            height: 27px;
            border-radius: 999px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            color: var(--cyan);
            border: 1px solid var(--cyan);
            box-shadow: 0 0 15px rgba(0,229,255,0.35);
            font-size: 0.78rem;
            font-weight: 950;
        }

        .muted {
            color: var(--muted);
            font-size: 0.87rem;
            line-height: 1.5;
        }

        .pipeline-step {
            display: flex;
            justify-content: space-between;
            padding: 10px 12px;
            margin: 8px 0;
            border-radius: 12px;
            background: rgba(15, 23, 42, 0.62);
            border: 1px solid rgba(148, 163, 184, 0.13);
        }

        .pipeline-step span:first-child {
            color: #E2E8F0;
            font-weight: 750;
        }

        .pipeline-step span:last-child {
            color: var(--cyan);
            font-weight: 900;
        }

        .status-strip {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
            margin: 15px 0;
        }

        .status-card {
            padding: 15px;
            border-radius: 16px;
            background: linear-gradient(180deg, rgba(11, 22, 39, 0.95), rgba(4, 10, 20, 0.95));
            border: 1px solid rgba(0, 229, 255, 0.18);
            box-shadow: 0 0 24px rgba(0,229,255,0.06);
        }

        .status-label {
            color: var(--muted);
            font-size: 0.72rem;
            font-weight: 900;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            margin-bottom: 7px;
        }

        .status-value {
            color: #F8FAFC;
            font-size: 1.12rem;
            font-weight: 950;
        }

        .risk-badge {
            display: inline-flex;
            padding: 7px 12px;
            border-radius: 999px;
            font-size: 0.78rem;
            font-weight: 950;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .risk-low {
            color: var(--success);
            border: 1px solid rgba(34,197,94,0.78);
            background: rgba(34,197,94,0.12);
        }

        .risk-medium {
            color: var(--amber);
            border: 1px solid rgba(245,158,11,0.78);
            background: rgba(245,158,11,0.12);
        }

        .risk-high {
            color: var(--red);
            border: 1px solid rgba(239,68,68,0.78);
            background: rgba(239,68,68,0.12);
        }

        .risk-unknown {
            color: #CBD5E1;
            border: 1px solid rgba(148,163,184,0.45);
            background: rgba(148,163,184,0.10);
        }

        .confidence-wrap {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .confidence-bar {
            height: 8px;
            flex: 1;
            border-radius: 999px;
            background: rgba(148, 163, 184, 0.16);
            overflow: hidden;
        }

        .confidence-fill {
            height: 100%;
            border-radius: 999px;
            background: linear-gradient(90deg, var(--green), var(--cyan));
            box-shadow: 0 0 14px rgba(0,229,255,0.5);
        }

        .assistant-panel {
            background: #07111F;
            border: 1px solid rgba(0,229,255,0.24);
            border-radius: 16px;
            padding: 18px;
            color: #E6EDF3;
            font-family: Consolas, Monaco, "Courier New", monospace;
            font-size: 0.94rem;
            line-height: 1.65;
            white-space: pre-wrap;
            box-shadow: inset 0 0 22px rgba(0,229,255,0.04), 0 0 28px rgba(0,229,255,0.06);
        }

        .stButton > button {
            background: linear-gradient(90deg, #00FF9C, #00E5FF);
            color: #020617;
            border: none;
            border-radius: 14px;
            font-weight: 950;
            padding: 0.75rem 1.2rem;
            box-shadow: 0 0 25px rgba(0,229,255,0.24);
        }

        .stButton > button:hover {
            color: #020617;
            transform: translateY(-1px);
            box-shadow: 0 0 38px rgba(0,229,255,0.38);
        }

        .stDownloadButton > button {
            background: rgba(15, 23, 42, 0.85);
            color: #E6EDF3;
            border: 1px solid rgba(0,229,255,0.55);
            border-radius: 12px;
            font-weight: 800;
        }

        .stTextArea textarea {
            background-color: #07111F !important;
            color: #E6EDF3 !important;
            -webkit-text-fill-color: #E6EDF3 !important;
            border: 1px solid rgba(0,229,255,0.24) !important;
            border-radius: 14px !important;
            caret-color: #00E5FF !important;
            font-family: Consolas, Monaco, "Courier New", monospace !important;
            font-size: 0.92rem !important;
            line-height: 1.52 !important;
        }

        .stTextArea textarea::placeholder {
            color: #64748B !important;
            opacity: 1 !important;
        }

        .stSelectbox div[data-baseweb="select"] > div {
            background-color: #07111F !important;
            color: #E6EDF3 !important;
            border-color: rgba(0,229,255,0.24) !important;
        }

        div[data-testid="stDataFrame"] {
            border: 1px solid rgba(0,229,255,0.20);
            border-radius: 14px;
            overflow: hidden;
            box-shadow: 0 0 25px rgba(0,229,255,0.07);
        }

        .stExpander {
            border: 1px solid rgba(0,229,255,0.18) !important;
            border-radius: 14px !important;
            background: rgba(7,17,31,0.72) !important;
        }

        hr {
            border-color: rgba(148, 163, 184, 0.12) !important;
        }

        @media (max-width: 1050px) {
            .hero { grid-template-columns: 1fr; }
            .status-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        }

        @media (max-width: 700px) {
            .status-strip { grid-template-columns: 1fr; }
            .hero-title { font-size: 1.75rem; }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def value_to_text(value):
    if isinstance(value, list):
        return " | ".join(str(item) for item in value)
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "none"
    return str(value)


def alert_json_to_text(alert_data):
    text_parts = []

    for field in IMPORTANT_FIELDS:
        if field in alert_data:
            text_parts.append(f"{field}: {value_to_text(alert_data[field])}")

    notes = alert_data.get("notes", [])

    if notes:
        text_parts.append("notes: " + value_to_text(notes))

    return "\n".join(text_parts)


def detect_input_language(text):
    text_lower = text.lower()

    turkish_chars = "çğıöşüÇĞİÖŞÜ"
    turkish_keywords = [
        "şüpheli",
        "giriş",
        "mail",
        "e-posta",
        "kullanıcı",
        "hesap",
        "neden",
        "çok",
        "fazla",
        "parola",
        "şifre",
        "başarısız",
        "başarılı",
        "olay",
        "uyarı",
        "tıklama",
        "tıklamış",
        "mailler",
    ]

    if any(char in text for char in turkish_chars):
        return "Turkish"

    if any(keyword in text_lower for keyword in turkish_keywords):
        return "Turkish"

    return "English"


def get_source_type(path):
    path_text = str(path).replace("\\", "/")

    if "/mitre/" in path_text:
        return "MITRE ATT&CK"
    if "/playbooks/" in path_text:
        return "SOC Playbook"
    if "/investigation_notes/" in path_text:
        return "Investigation Notes"
    if "/nist/" in path_text:
        return "NIST Incident Response"

    return "Knowledge Source"


def load_sample_alerts():
    if not SAMPLE_ALERTS_DIR.exists():
        return {}

    sample_alerts = {}

    for path in sorted(SAMPLE_ALERTS_DIR.glob("*.json")):
        with path.open("r", encoding="utf-8") as file:
            sample_alerts[path.name] = json.load(file)

    return sample_alerts


def save_outputs(context, answer_prompt, analyst_recommendation):
    OUTPUT_DIR.mkdir(exist_ok=True)

    retrieved_context_path = OUTPUT_DIR / "retrieved_context.txt"
    answer_prompt_path = OUTPUT_DIR / "answer_prompt.txt"
    analyst_answer_path = OUTPUT_DIR / "analyst_recommendation.txt"

    retrieved_context_path.write_text(context, encoding="utf-8")
    answer_prompt_path.write_text(answer_prompt, encoding="utf-8")
    analyst_answer_path.write_text(analyst_recommendation, encoding="utf-8")

    return retrieved_context_path, answer_prompt_path, analyst_answer_path


def normalize_category(category, alert_text):
    text = alert_text.lower()

    if category and category != "unknown":
        return category

    if any(word in text for word in ["mail", "e-posta", "phishing", "link", "sender", "dkim", "dmarc", "spf"]):
        return "phishing"

    if any(word in text for word in ["powershell", "encoded", "process", "edr", "parent process"]):
        return "suspicious_powershell"

    if any(word in text for word in ["login", "giriş", "ssh", "vpn", "failed", "başarısız", "parola", "şifre"]):
        return "brute_force"

    return "unknown"


def category_display_name(category):
    mapping = {
        "brute_force": "Brute Force",
        "phishing": "Phishing",
        "suspicious_powershell": "PowerShell",
        "unknown": "Unknown",
        None: "Unknown",
    }

    return mapping.get(category, str(category))


def extract_risk_level(alert_text, selected_alert_data=None):
    if selected_alert_data:
        return selected_alert_data.get("risk_level", "unknown")

    match = re.search(
        r"risk[_\s-]*level\s*:\s*(low|medium|high)",
        alert_text,
        flags=re.IGNORECASE,
    )

    if match:
        return match.group(1).lower()

    text_lower = alert_text.lower()

    high_terms = ["high", "critical", "admin", "başarılı giriş", "success_after_failures", "credentials_entered: true"]
    medium_terms = ["medium", "unknown", "bilinmeyen", "tıklamış", "clicked"]
    low_terms = ["low", "blocked", "engellendi", "user_clicked: false"]

    if any(term in text_lower for term in high_terms):
        return "high"
    if any(term in text_lower for term in medium_terms):
        return "medium"
    if any(term in text_lower for term in low_terms):
        return "low"

    return "unknown"


def risk_badge_html(risk_level):
    risk = str(risk_level or "unknown").lower()

    if risk not in ["low", "medium", "high"]:
        risk = "unknown"

    return f'<span class="risk-badge risk-{risk}">{risk.upper()}</span>'


def compute_triage_confidence(category, alert_text, risk_level):
    text = alert_text.lower()
    score = 45

    if category == "brute_force":
        signals = [
            "failed",
            "başarısız",
            "login",
            "giriş",
            "vpn",
            "ssh",
            "admin",
            "source_ip",
            "failed_attempt_count",
            "success_after_failures",
            "başarılı",
            "mfa",
        ]
    elif category == "phishing":
        signals = [
            "mail",
            "e-posta",
            "phishing",
            "link",
            "url",
            "sender",
            "reply_to",
            "spf",
            "dkim",
            "dmarc",
            "clicked",
            "tıkl",
            "credential",
            "parola",
            "şifre",
        ]
    elif category == "suspicious_powershell":
        signals = [
            "powershell",
            "encoded",
            "command",
            "parent_process",
            "process",
            "edr",
            "network",
            "destination_ip",
            "registry",
            "scheduled_task",
        ]
    else:
        signals = []

    for signal in signals:
        if signal in text:
            score += 5

    if risk_level == "high":
        score += 8
    elif risk_level == "medium":
        score += 4
    elif risk_level == "low":
        score -= 4

    return max(35, min(score, 92))


def build_source_rows(results):
    rows = []

    for score, document in results:
        path = document["path"]

        rows.append(
            {
                "Source": path.name,
                "Type": get_source_type(path),
                "Score": score,
            }
        )

    return rows


def append_language_instruction(answer_prompt, detected_language):
    if detected_language == "Turkish":
        instruction = """
LANGUAGE INSTRUCTION:
The user's input appears to be Turkish.
Produce the final SOC Analyst Coach answer in Turkish.
Keep technical terms such as MITRE ATT&CK, brute force, phishing, PowerShell, IOC, MFA, SIEM, EDR, and incident response in common technical form when appropriate.
"""
    else:
        instruction = """
LANGUAGE INSTRUCTION:
The user's input appears to be English.
Produce the final SOC Analyst Coach answer in English.
Keep the response clear, professional, and suitable for a junior SOC analyst.
"""

    return answer_prompt.strip() + "\n\n" + instruction.strip() + "\n"


def build_analyst_recommendation(category, risk_level, confidence, language):
    if language == "Turkish":
        if category == "brute_force":
            return f"""Bu olay brute force veya suspicious login davranışı olabilir.

Triage confidence: %{confidence}
Risk seviyesi: {risk_level.upper() if risk_level != "unknown" else "UNKNOWN"}

İlk yorum:
Bu olayda temel soru şu: Aynı kullanıcıya veya aynı sisteme kısa sürede çok sayıda başarısız giriş denemesi var mı? Eğer başarısız denemelerden sonra başarılı bir giriş varsa risk belirgin şekilde artar.

Önce şunlara bak:
1. Kaç başarısız giriş denemesi var?
2. Bu denemeler kaç dakika içinde olmuş?
3. Denemeler aynı source IP’den mi geliyor?
4. Hedef hesap normal kullanıcı mı, admin/yetkili hesap mı?
5. Başarısız denemelerden sonra başarılı login var mı?
6. MFA aktif mi ve MFA sonucu ne?
7. Başarılı girişten sonra kullanıcı ne yapmış?
8. Aynı IP başka hesapları da denemiş mi?

Risk artar eğer:
- Admin veya privileged account hedeflenmişse
- VPN, SSH, RDP gibi dış erişim noktası hedeflenmişse
- Çok sayıda başarısız deneme kısa sürede olmuşsa
- Denemelerden sonra başarılı login oluşmuşsa
- MFA yoksa veya MFA durumu bilinmiyorsa
- Başarılı giriş sonrası anormal aktivite varsa

False positive olabilir eğer:
- Kullanıcı şifresini yanlış girip sonra doğru girmişse
- Eski parola kullanan telefon/VPN client otomatik deniyorsa
- Kurumsal servis veya script yanlış credential ile tekrar tekrar deniyorsa

Sonraki adım:
Bu olayı hemen “kesin saldırı” diye etiketleme. Önce login timeline, source IP geçmişi, MFA durumu ve successful login sonrası aktiviteleri kontrol et. Eğer başarılı giriş kullanıcı tarafından doğrulanmıyorsa incident seviyesine yükselt."""

        if category == "phishing":
            return f"""Bu olay phishing veya suspicious email davranışı olabilir.

Triage confidence: %{confidence}
Risk seviyesi: {risk_level.upper() if risk_level != "unknown" else "UNKNOWN"}

İlk yorum:
Kullanıcıya şüpheli mail gelmesi tek başına kesin phishing değildir. Asıl kritik nokta mailin link/attachment içerip içermediği, kullanıcının tıklayıp tıklamadığı ve credential girip girmediğidir.

Önce şunlara bak:
1. Mail kimden gelmiş? Sender domain güvenilir mi?
2. Reply-To adresi sender ile uyumlu mu?
3. SPF, DKIM ve DMARC sonucu ne?
4. Mailde link var mı?
5. Link gerçek domain’e mi gidiyor, yoksa taklit domain mi?
6. Attachment var mı?
7. Kullanıcı linke tıklamış mı?
8. Kullanıcı parola/MFA kodu girmiş mi?
9. Aynı mail başka kullanıcılara da gitmiş mi?
10. Tıklama sonrası suspicious login oluşmuş mu?

Risk artar eğer:
- Kullanıcı linke tıkladıysa
- Kullanıcı credential girdiyse
- SPF/DKIM/DMARC fail ise
- Link bilinmeyen veya taklit domain’e gidiyorsa
- Aynı mail birçok kişiye gittiyse
- Tıklama sonrası şüpheli login varsa

False positive olabilir eğer:
- Mail gateway maili zaten engellediyse
- Kullanıcı maili tıklamadan raporladıysa
- Mail gerçek bir servis bildirimi ise
- Link kurumsal güvenlik redirect’i ise

Sonraki adım:
Mail header, URL reputation, user click durumu ve login loglarını kontrol et. Credential girişi veya suspicious login varsa olayı incident seviyesine yükselt."""

        if category == "suspicious_powershell":
            return f"""Bu olay suspicious PowerShell veya endpoint execution davranışı olabilir.

Triage confidence: %{confidence}
Risk seviyesi: {risk_level.upper() if risk_level != "unknown" else "UNKNOWN"}

İlk yorum:
PowerShell tek başına zararlı değildir. Risk, komutun nasıl çalıştığına bağlıdır. Encoded command, bilinmeyen parent process, dış network bağlantısı veya EDR alert varsa olay daha kritik olur.

Önce şunlara bak:
1. PowerShell’i hangi kullanıcı çalıştırmış?
2. Parent process nedir?
3. Command line içinde encoded command var mı?
4. Komut ne yapıyor?
5. Child process oluşmuş mu?
6. Dış IP/domain bağlantısı var mı?
7. Dosya oluşturma, registry değişikliği veya scheduled task var mı?
8. EDR/AV/AMSI alert üretmiş mi?
9. Olay phishing tıklaması sonrası mı olmuş?
10. Aynı komut başka endpointlerde görülmüş mü?

Risk artar eğer:
- EncodedCommand kullanılmışsa
- Parent process Office, browser veya mail client ise
- PowerShell dış IP/domain’e bağlandıysa
- Komut dosya indirip çalıştırıyorsa
- Persistence izi varsa
- EDR/AV/AMSI alarm verdiyse

False positive olabilir eğer:
- IT management tool çalıştırdıysa
- Monitoring veya deployment script’i ise
- Parent process güvenilir agent ise
- Network bağlantısı yoksa veya internal/güvenilir hedef ise

Sonraki adım:
Process tree, command line, parent/child process, network connection ve EDR loglarını incele. Kanıt olmadan process kill veya dosya silme önermemelisin."""

        return f"""Bu olay için kategori net değil.

Triage confidence: %{confidence}
Risk seviyesi: {risk_level.upper() if risk_level != "unknown" else "UNKNOWN"}

Önce olayın türünü netleştir:
1. Bu bir login/authentication olayı mı?
2. Bu bir mail/phishing olayı mı?
3. Bu bir endpoint/PowerShell olayı mı?
4. Hangi kullanıcı, hangi sistem, hangi zaman aralığı etkilenmiş?
5. Kullanıcı etkileşimi var mı?
6. Başarılı giriş, tıklama veya komut çalıştırma gibi kritik sonuç var mı?

Sonraki adım:
Daha net log alanları ekle: user, source_ip, timestamp, status, mfa_status, sender, url, process_name, command_line gibi alanlar analizi güçlendirir."""

    if category == "brute_force":
        return f"""This event may indicate brute force or suspicious login behavior.

Triage confidence: {confidence}%
Risk level: {risk_level.upper() if risk_level != "unknown" else "UNKNOWN"}

First interpretation:
Check whether there are many failed login attempts against the same user or system within a short time window. Risk increases significantly if a successful login appears after repeated failures.

Check first:
1. Number of failed login attempts
2. Time window of the attempts
3. Whether attempts came from the same source IP
4. Whether the target account is privileged
5. Whether a successful login followed the failures
6. MFA status and result
7. Post-login activity
8. Whether the same IP tried other accounts

Escalate if successful login is not confirmed by the user or if post-login activity is suspicious."""

    if category == "phishing":
        return f"""This event may indicate phishing or suspicious email activity.

Triage confidence: {confidence}%
Risk level: {risk_level.upper() if risk_level != "unknown" else "UNKNOWN"}

First interpretation:
A suspicious email alone is not always an incident. The key questions are whether the message contained a link or attachment, whether the user clicked it, and whether credentials were entered.

Check first:
1. Sender and Reply-To alignment
2. SPF, DKIM, and DMARC results
3. URL destination and reputation
4. Attachment presence
5. User click status
6. Credential submission
7. Similar emails in other mailboxes
8. Suspicious login after click

Escalate if credentials were entered, a suspicious login followed, or the same email affected multiple users."""

    if category == "suspicious_powershell":
        return f"""This event may indicate suspicious PowerShell or endpoint execution behavior.

Triage confidence: {confidence}%
Risk level: {risk_level.upper() if risk_level != "unknown" else "UNKNOWN"}

First interpretation:
PowerShell is not malicious by itself. Risk depends on how it was launched, what the command does, whether it is encoded, and whether network or persistence behavior exists.

Check first:
1. User context
2. Parent process
3. Full command line
4. Encoded command usage
5. Child processes
6. Network connections
7. File, registry, or scheduled task changes
8. EDR/AV/AMSI detections

Escalate if PowerShell was launched by Office/browser/email client, connected externally, downloaded payloads, or triggered EDR alerts."""

    return f"""The event category is not clear yet.

Triage confidence: {confidence}%
Risk level: {risk_level.upper() if risk_level != "unknown" else "UNKNOWN"}

First clarify:
1. Is this an authentication event?
2. Is this an email/phishing event?
3. Is this an endpoint/PowerShell event?
4. Which user, system, and time window are involved?
5. Was there a successful login, click, credential submission, or command execution?

Add more structured fields to improve the analysis."""


def run_triage(alert_text, selected_alert_data=None):
    query = build_query_from_alert(alert_text)
    detected_category = detect_query_category(query)
    detected_category = normalize_category(detected_category, alert_text)

    detected_language = detect_input_language(alert_text)
    risk_level = extract_risk_level(alert_text, selected_alert_data)
    confidence = compute_triage_confidence(detected_category, alert_text, risk_level)

    results = retrieve(query, top_k=4)
    context, sources = build_context(results)

    answer_prompt = build_answer_prompt(alert_text, context)
    answer_prompt = append_language_instruction(answer_prompt, detected_language)

    analyst_recommendation = build_analyst_recommendation(
        detected_category,
        risk_level,
        confidence,
        detected_language,
    )

    retrieved_context_path, answer_prompt_path, analyst_answer_path = save_outputs(
        context,
        answer_prompt,
        analyst_recommendation,
    )

    return {
        "query": query,
        "detected_category": detected_category,
        "detected_language": detected_language,
        "risk_level": risk_level,
        "confidence": confidence,
        "results": results,
        "context": context,
        "sources": sources,
        "answer_prompt": answer_prompt,
        "analyst_recommendation": analyst_recommendation,
        "retrieved_context_path": retrieved_context_path,
        "answer_prompt_path": answer_prompt_path,
        "analyst_answer_path": analyst_answer_path,
    }


def render_sidebar():
    logo_data = asset_to_base64(LOGO_IMAGE_PATH)

    if logo_data:
        logo_html = f'<img class="sidebar-logo" src="{logo_data}" alt="CyberSOC logo">'
    else:
        logo_html = '<div class="sidebar-logo-fallback">🛡️</div>'

    st.sidebar.markdown(
        f"""
        <div class="sidebar-brand">
            {logo_html}
            <div>
                <div class="brand-title">CyberSOC</div>
                <div class="brand-subtitle">Incident Triage Assistant</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.sidebar.markdown('<div class="side-link">🏠 Home</div>', unsafe_allow_html=True)

    input_mode = st.sidebar.radio(
        "Input Mode",
        ["Write custom alert", "Use sample alert"],
    )

    st.sidebar.markdown(
        """
        <div class="sidebar-card">
            <div class="sidebar-title">SUPPORTED SCENARIOS</div>
            <div class="scenario-chip bf-chip">
                <span>🎯 Brute Force</span><span class="mini-code bf-code">BF</span>
            </div>
            <div class="scenario-chip ph-chip">
                <span>✉️ Phishing</span><span class="mini-code ph-code">PH</span>
            </div>
            <div class="scenario-chip ps-chip">
                <span>⌁ PowerShell</span><span class="mini-code ps-code">PS</span>
            </div>
        </div>

        <div class="safe-card">
            <div class="safe-title">🛡️ SAFETY BOUNDARY</div>
            <div class="safe-item">✓ Defensive triage guidance only</div>
            <div class="safe-item">✓ No account disabling</div>
            <div class="safe-item">✓ No IP blocking</div>
            <div class="safe-item">✓ No file deletion</div>
            <div class="safe-item">✓ Analyst decision support only</div>
            <hr style="border-color: rgba(0,255,156,0.22);">
            <div style="color:#00FF9C; font-weight:900; font-size:0.82rem;">
                Status: SECURE • LOCAL ONLY
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    return input_mode


def render_topbar():
    st.markdown(
        """
        <div class="topbar">
            <div class="topbar-left">
                <span class="topbar-active">Dashboard</span>
                <span>Investigations</span>
                <span>Playbooks</span>
                <span>Reports</span>
            </div>
            <div class="topbar-right">
                <span>🕒 Local Session</span>
                <span><span class="healthy-dot"></span>System Healthy</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_hero():
    hero_data = asset_to_base64(HERO_IMAGE_PATH)

    if hero_data:
        hero_html = f'<img src="{hero_data}" alt="CyberSOC hero">'
    else:
        hero_html = '<div class="hero-placeholder">🛡️</div>'

    st.markdown(
        f"""
        <div class="hero">
            <div class="hero-copy">
                <div class="kicker">● Local SOC triage console</div>
                <div class="hero-title">CyberSOC Incident Triage Assistant</div>
                <div class="hero-desc">
                    Enter suspicious login, phishing, or PowerShell alerts.
                    The assistant retrieves trusted local SOC knowledge and guides the analyst through the next checks.
                </div>
                <div class="hero-badges">
                    <span class="hero-badge">MITRE ATT&CK</span>
                    <span class="hero-badge">NIST IR</span>
                    <span class="hero-badge">Playbooks</span>
                    <span class="hero-badge">Investigation Notes</span>
                    <span class="hero-badge">Local Only</span>
                </div>
            </div>
            <div class="hero-img-wrap">
                {hero_html}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_pipeline_panel():
    st.markdown(
        """
        <div class="panel-card">
            <div class="section-title">
                <span class="number-dot">i</span>
                Pipeline
            </div>
            <div class="muted">
                This assistant guides investigation. It does not perform automatic remediation.
            </div>
            <div class="pipeline-step"><span>Alert Input</span><span>01</span></div>
            <div class="pipeline-step"><span>Category Detection</span><span>02</span></div>
            <div class="pipeline-step"><span>Knowledge Retrieval</span><span>03</span></div>
            <div class="pipeline-step"><span>Analyst Guidance</span><span>04</span></div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_custom_input():
    st.markdown(
        """
        <div class="section-title">
            <span class="number-dot">1</span>
            Alert Input
        </div>
        <div class="muted">
            Paste an alert, log snippet, suspicious email report, or endpoint event.
            Turkish and English inputs are accepted.
        </div>
        """,
        unsafe_allow_html=True,
    )

    return st.text_area(
        "Alert / Log / Incident Text",
        height=245,
        placeholder=(
            "Türkçe örnek:\n"
            "Kullanıcıya çok fazla şüpheli mail geliyor. Mail içinde bilinmeyen link var. "
            "Kullanıcı tıklayıp tıklamadığını bilmiyor.\n\n"
            "English example:\n"
            "Multiple failed VPN login attempts followed by successful login for admin account."
        ),
    )


def render_sample_input():
    sample_alerts = load_sample_alerts()

    if not sample_alerts:
        st.error("No sample alert files found.")
        return "", None, None

    st.markdown(
        """
        <div class="section-title">
            <span class="number-dot">1</span>
            Sample Alert
        </div>
        <div class="muted">
            Select one of the prepared sample alerts.
        </div>
        """,
        unsafe_allow_html=True,
    )

    selected_name = st.selectbox(
        "Sample alerts",
        list(sample_alerts.keys()),
        label_visibility="collapsed",
    )

    selected_data = sample_alerts[selected_name]
    alert_text = alert_json_to_text(selected_data)

    st.markdown(
        f"""
        <div style="display:flex; justify-content:space-between; align-items:center; margin-top:12px;">
            <div>
                <div style="font-weight:900; color:#F8FAFC;">{selected_data.get("title", selected_name)}</div>
                <div class="muted">{selected_name}</div>
            </div>
            {risk_badge_html(selected_data.get("risk_level", "unknown"))}
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.expander("Show sample JSON", expanded=False):
        st.json(selected_data)

    return alert_text, selected_name, selected_data


def render_input_area(input_mode):
    left, right = st.columns([1.8, 1], gap="large")

    selected_name = None
    selected_data = None

    with left:
        st.markdown('<div class="input-card">', unsafe_allow_html=True)

        if input_mode == "Write custom alert":
            alert_text = render_custom_input()
        else:
            alert_text, selected_name, selected_data = render_sample_input()

        st.markdown("</div>", unsafe_allow_html=True)

    with right:
        render_pipeline_panel()

    analyze_clicked = st.button("Analyze Alert", type="primary", use_container_width=True)

    return analyze_clicked, alert_text, selected_name, selected_data


def render_status_strip(result):
    confidence = result["confidence"]
    fill_width = f"{confidence}%"

    st.markdown(
        f"""
        <div class="status-strip">
            <div class="status-card">
                <div class="status-label">Detected Category</div>
                <div class="status-value">{category_display_name(result["detected_category"])}</div>
            </div>
            <div class="status-card">
                <div class="status-label">Risk Level</div>
                <div class="status-value">{risk_badge_html(result["risk_level"])}</div>
            </div>
            <div class="status-card">
                <div class="status-label">Triage Confidence</div>
                <div class="confidence-wrap">
                    <div class="status-value">{confidence}%</div>
                    <div class="confidence-bar">
                        <div class="confidence-fill" style="width:{fill_width};"></div>
                    </div>
                </div>
            </div>
            <div class="status-card">
                <div class="status-label">Response Language</div>
                <div class="status-value">{result["detected_language"]}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_results(result):
    st.success("Analysis completed.")

    render_status_strip(result)

    left, right = st.columns([1.15, 1], gap="large")

    with left:
        st.markdown(
            """
            <div class="section-title">
                <span class="number-dot">2</span>
                Retrieved Sources
            </div>
            <div class="muted">
                These are the most relevant local knowledge-base documents.
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.dataframe(
            build_source_rows(result["results"]),
            use_container_width=True,
            hide_index=True,
        )

    with right:
        st.markdown(
            """
            <div class="section-title">
                <span class="number-dot">3</span>
                What To Check Next
            </div>
            <div class="muted">
                The assistant focuses on what the analyst should verify before escalation.
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.text_area(
            "Generated Retrieval Query",
            value=result["query"],
            height=165,
            label_visibility="collapsed",
        )

    st.divider()

    st.markdown(
        """
        <div class="section-title">
            <span class="number-dot">4</span>
            Triage Assistant — Analysis & Recommendation
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        f"""
        <div class="assistant-panel">
        {result["analyst_recommendation"]}
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.download_button(
        "Download analyst_recommendation.txt",
        data=result["analyst_recommendation"],
        file_name="analyst_recommendation.txt",
        mime="text/plain",
        use_container_width=True,
    )

    with st.expander("Advanced: Generated LLM Prompt", expanded=False):
        st.text_area(
            "Prompt",
            value=result["answer_prompt"],
            height=380,
            label_visibility="collapsed",
        )

        st.download_button(
            "Download answer_prompt.txt",
            data=result["answer_prompt"],
            file_name="answer_prompt.txt",
            mime="text/plain",
        )

    with st.expander("Advanced: Retrieved Context", expanded=False):
        st.text_area(
            "Context",
            value=result["context"],
            height=380,
            label_visibility="collapsed",
        )

        st.download_button(
            "Download retrieved_context.txt",
            data=result["context"],
            file_name="retrieved_context.txt",
            mime="text/plain",
        )

    st.markdown(
        """
        <div class="muted">
        Output files saved locally:
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.code(str(result["analyst_answer_path"]))
    st.code(str(result["answer_prompt_path"]))
    st.code(str(result["retrieved_context_path"]))


def main():
    apply_custom_css()

    input_mode = render_sidebar()

    render_topbar()
    render_hero()

    analyze_clicked, alert_text, selected_name, selected_data = render_input_area(input_mode)

    if analyze_clicked:
        if not alert_text.strip():
            st.error("Please enter or select an alert first.")
            return

        with st.spinner("Analyzing alert with local SOC knowledge base..."):
            result = run_triage(alert_text, selected_data)

        render_results(result)


if __name__ == "__main__":
    main()