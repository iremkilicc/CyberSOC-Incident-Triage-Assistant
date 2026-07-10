import json
from pathlib import Path

from build_context import retrieve, build_context
from build_answer_prompt import build_answer_prompt
from query_builder import build_query_from_alert


SAMPLE_ALERTS_DIR = Path("knowledge_base/sample_alerts")


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


def get_source_type(path):
    path_text = str(path).replace("\\", "/")

    if "/mitre/" in path_text:
        return "MITRE ATT&CK tekniği özeti"

    if "/playbooks/" in path_text:
        return "SOC playbook / kontrol adımları"

    if "/investigation_notes/" in path_text:
        return "Investigation notes / bakılacak alanlar"

    if "/nist/" in path_text:
        return "NIST incident response özeti"

    return "Bilgi kaynağı"


def get_user_alert():
    print("\nAlert / log / olay açıklamasını yaz.")
    print("Bitirmek için boş satırda Enter'a bas.\n")

    lines = []

    while True:
        line = input("> ")

        if line.strip() == "":
            break

        lines.append(line)

    return "\n".join(lines).strip()


def get_sample_alert_files():
    if not SAMPLE_ALERTS_DIR.exists():
        return []

    return sorted(SAMPLE_ALERTS_DIR.glob("*.json"))


def choose_sample_alert():
    sample_files = get_sample_alert_files()

    if not sample_files:
        print("Sample alert dosyası bulunamadı.")
        return None, None

    print("\nSample alert seç:")

    for index, sample_file in enumerate(sample_files, start=1):
        print(f"{index}. {sample_file.name}")

    choice = input("\nNumara gir: ").strip()

    if not choice.isdigit():
        print("Geçersiz seçim.")
        return None, None

    selected_index = int(choice)

    if selected_index < 1 or selected_index > len(sample_files):
        print("Geçersiz seçim.")
        return None, None

    selected_file = sample_files[selected_index - 1]

    with selected_file.open("r", encoding="utf-8") as file:
        alert_data = json.load(file)

    alert_text = alert_json_to_text(alert_data)

    return selected_file.name, alert_text


def choose_input_mode():
    print("CyberSOC Incident Triage Assistant")
    print("=" * 50)
    print("\n1. Kendi alert metnimi gireceğim")
    print("2. Sample alert seçeceğim")

    choice = input("\nSeçim yap (1/2): ").strip()

    if choice == "1":
        alert_text = get_user_alert()
        return "custom_alert", alert_text

    if choice == "2":
        sample_name, alert_text = choose_sample_alert()

        if alert_text is None:
            return None, None

        return sample_name, alert_text

    print("Geçersiz seçim.")
    return None, None


def write_outputs(alert_text, context):
    output_dir = Path("outputs")
    output_dir.mkdir(exist_ok=True)

    retrieved_context_path = output_dir / "retrieved_context.txt"
    answer_prompt_path = output_dir / "answer_prompt.txt"

    retrieved_context_path.write_text(context, encoding="utf-8")

    answer_prompt = build_answer_prompt(alert_text, context)
    answer_prompt_path.write_text(answer_prompt, encoding="utf-8")

    return retrieved_context_path, answer_prompt_path


def main():
    alert_name, alert_text = choose_input_mode()

    if not alert_text:
        print("Alert metni alınamadı. Program durduruldu.")
        return

    print("\n[1] Alert alındı.")
    print(f"Kaynak: {alert_name}")

    print("\n[2] Arama sorgusu oluşturuluyor...")
    query = build_query_from_alert(alert_text)

    print("\n[3] Knowledge base içinde ilgili kaynaklar aranıyor...")
    results = retrieve(query, top_k=4)

    if not results:
        print("İlgili kaynak bulunamadı.")
        return

    print("\n[4] İlgili bilgi kaynakları bulundu:")

    for score, document in results:
        path = document["path"]
        source_type = get_source_type(path)

        print(f"\n- {path.name}")
        print(f"  Yol: {path}")
        print(f"  Tür: {source_type}")
        print(f"  Kaynak eşleşme skoru: {score}")

    print("\nNot: Bu skor saldırı olasılığı değildir.")
    print("Sadece alert metniyle kaynak dosya arasındaki retrieval eşleşme skorudur.")

    print("\n[5] Context oluşturuluyor...")
    context, sources = build_context(results)

    print("\n[6] Answer prompt oluşturuluyor...")
    retrieved_context_path, answer_prompt_path = write_outputs(alert_text, context)

    print("\n[7] İşlem tamamlandı.")
    print("Oluşturulan dosyalar:")
    print(f"- {retrieved_context_path}")
    print(f"- {answer_prompt_path}")
    print("\nSonraki adım:")
    print("answer_prompt.txt içeriği bir LLM'e verilerek final SOC Analyst Coach cevabı üretilebilir.")


if __name__ == "__main__":
    main()