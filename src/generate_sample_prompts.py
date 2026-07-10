import json
from pathlib import Path

from build_context import retrieve, build_context
from build_answer_prompt import build_answer_prompt
from query_builder import build_query_from_alert


SAMPLE_ALERTS_DIR = Path("knowledge_base/sample_alerts")
OUTPUT_DIR = Path("outputs/sample_prompts")


IMPORTANT_FIELDS = [
    "alert_id",
    "category",
    "risk_level",
    "title",
    "description",

    # Brute force fields
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

    # Phishing fields
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

    # PowerShell fields
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


def load_json_file(path):
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def value_to_text(value):
    """
    JSON içindeki list, bool, None gibi değerleri okunabilir metne çevirir.
    """

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
    """
    Sample alert JSON bilgisini LLM promptuna girecek okunabilir alert metnine çevirir.
    """

    text_parts = []

    for field in IMPORTANT_FIELDS:
        if field in alert_data:
            value = value_to_text(alert_data[field])
            text_parts.append(f"{field}: {value}")

    notes = alert_data.get("notes", [])

    if notes:
        text_parts.append("notes: " + value_to_text(notes))

    return "\n".join(text_parts)


def write_text_file(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def process_sample_alert(alert_path):
    alert_data = load_json_file(alert_path)

    alert_text = alert_json_to_text(alert_data)
    query = build_query_from_alert(alert_text)

    results = retrieve(query, top_k=4)
    context, sources = build_context(results)

    answer_prompt = build_answer_prompt(alert_text, context)

    output_file = OUTPUT_DIR / f"{alert_path.stem}_answer_prompt.txt"
    write_text_file(output_file, answer_prompt)

    print(f"\nProcessed: {alert_path.name}")
    print(f"Output: {output_file}")
    print("Sources:")

    for source in sources:
        print(f"- {source['path']} | retrieval score: {source['score']}")


def main():
    print("CyberSOC Sample Prompt Generator")
    print("=" * 70)

    if not SAMPLE_ALERTS_DIR.exists():
        print(f"Hata: {SAMPLE_ALERTS_DIR} klasörü bulunamadı.")
        return

    alert_files = sorted(SAMPLE_ALERTS_DIR.glob("*.json"))

    if not alert_files:
        print("Hata: sample alert JSON dosyası bulunamadı.")
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    for alert_path in alert_files:
        process_sample_alert(alert_path)

    print("=" * 70)
    print(f"Done. Generated prompts: {len(alert_files)}")
    print(f"Output directory: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()