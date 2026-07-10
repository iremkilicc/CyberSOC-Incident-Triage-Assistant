import json
from pathlib import Path

from build_context import retrieve
from query_builder import build_query_from_alert


SAMPLE_ALERTS_DIR = Path("knowledge_base/sample_alerts")


EXPECTED_FILES_BY_CATEGORY = {
    "brute_force": [
        "T1110_brute_force.md",
        "login_log_fields.md",
        "brute_force_playbook.md",
    ],
    "phishing": [
        "T1566_phishing.md",
        "email_investigation_fields.md",
        "phishing_playbook.md",
    ],
    "suspicious_powershell": [
        "T1059_command_and_scripting_interpreter.md",
        "endpoint_investigation_fields.md",
        "suspicious_powershell_playbook.md",
    ],
}


def load_json_file(path):
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def alert_json_to_text(alert_data):
    """
    JSON sample alert bilgisini retrieval için okunabilir metne çevirir.

    Amaç:
    - JSON içindeki title, description, category, notes ve alanları tek metne toplamak
    - Query builder'ın daha iyi sorgu üretmesini sağlamak
    """

    text_parts = []

    important_fields = [
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
        "sender_email",
        "sender_display_name",
        "reply_to",
        "recipient",
        "subject",
        "delivery_status",
        "spf_result",
        "dkim_result",
        "dmarc_result",
        "url",
        "visible_link_text",
        "landing_page_behavior",
        "attachment_present",
        "user_clicked",
        "credentials_entered",
        "attachment_opened",
        "suspicious_login_after_click",
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

    for field in important_fields:
        if field in alert_data:
            text_parts.append(f"{field}: {alert_data[field]}")

    notes = alert_data.get("notes", [])

    if isinstance(notes, list):
        text_parts.append("notes: " + " | ".join(str(note) for note in notes))
    elif notes:
        text_parts.append(f"notes: {notes}")

    post_login_activity = alert_data.get("post_login_activity", [])

    if isinstance(post_login_activity, list):
        text_parts.append(
            "post_login_activity: "
            + " | ".join(str(activity) for activity in post_login_activity)
        )

    return "\n".join(text_parts)


def run_sample_alert_test(alert_path):
    alert_data = load_json_file(alert_path)

    category = alert_data.get("category", "unknown")
    risk_level = alert_data.get("risk_level", "unknown")
    title = alert_data.get("title", alert_path.name)

    print("=" * 80)
    print(f"Sample Alert: {alert_path.name}")
    print(f"Category: {category}")
    print(f"Risk Level: {risk_level}")
    print(f"Title: {title}")

    if category not in EXPECTED_FILES_BY_CATEGORY:
        print("\nSonuç: FAIL")
        print(f"Bilinmeyen category: {category}")
        return False

    alert_text = alert_json_to_text(alert_data)
    query = build_query_from_alert(alert_text)
    results = retrieve(query, top_k=5)

    found_files = [document["path"].name for score, document in results]

    print("\nBulunan kaynaklar:")

    for score, document in results:
        print(f"- {document['path'].name} | kaynak eşleşme skoru: {score}")

    missing_files = []

    for expected_file in EXPECTED_FILES_BY_CATEGORY[category]:
        if expected_file not in found_files:
            missing_files.append(expected_file)

    if missing_files:
        print("\nSonuç: FAIL")
        print("Eksik beklenen dosyalar:")

        for missing_file in missing_files:
            print(f"- {missing_file}")

        return False

    print("\nSonuç: PASS")
    return True


def main():
    print("CyberSOC Sample Alert Retrieval Test Suite")
    print("=" * 80)

    if not SAMPLE_ALERTS_DIR.exists():
        print(f"Hata: {SAMPLE_ALERTS_DIR} klasörü bulunamadı.")
        return

    alert_files = sorted(SAMPLE_ALERTS_DIR.glob("*.json"))

    if not alert_files:
        print("Hata: sample alert JSON dosyası bulunamadı.")
        return

    passed = 0
    total = len(alert_files)

    for alert_path in alert_files:
        if run_sample_alert_test(alert_path):
            passed += 1

    print("=" * 80)
    print(f"Genel Sonuç: {passed}/{total} sample alert testi geçti.")

    if passed == total:
        print("Tüm sample alert retrieval testleri başarılı.")
    else:
        print("Bazı sample alert testleri başarısız. Query builder veya knowledge base kontrol edilmeli.")


if __name__ == "__main__":
    main()