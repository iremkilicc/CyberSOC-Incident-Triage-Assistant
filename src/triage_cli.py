from pathlib import Path

from build_context import retrieve, build_context
from build_answer_prompt import build_answer_prompt


def get_user_alert():
    """
    Kullanıcıdan terminal üzerinden alert metni alır.
    Kullanıcı boş satır girene kadar metin almaya devam eder.
    """

    print("CyberSOC Incident Triage Assistant")
    print("=" * 45)
    print("\nAlert / log / olay açıklamasını yaz.")
    print("Bitirmek için boş satırda Enter'a bas.\n")

    lines = []

    while True:
        line = input("> ")

        if line.strip() == "":
            break

        lines.append(line)

    alert_text = "\n".join(lines).strip()

    return alert_text


def build_query_from_alert(alert_text):
    """
    Şimdilik query olarak alert metninin kendisini kullanıyoruz.
    Daha sonra bunu daha akıllı hale getirebiliriz.
    """

    return alert_text


def get_source_type(path):
    """
    Kaynak dosyanın hangi bilgi türüne ait olduğunu açıklar.
    Bu sadece terminal çıktısını daha anlaşılır yapmak içindir.
    """

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


def main():
    alert_text = get_user_alert()

    if not alert_text:
        print("Alert metni girilmedi. Program durduruldu.")
        return

    query = build_query_from_alert(alert_text)

    print("\n[1] Alert alındı.")
    print("\n[2] Knowledge base içinde ilgili kaynaklar aranıyor...")

    results = retrieve(query, top_k=4)

    if not results:
        print("İlgili kaynak bulunamadı.")
        return

    print("\n[3] İlgili bilgi kaynakları bulundu:")

    for score, document in results:
        path = document["path"]
        source_type = get_source_type(path)

        print(f"\n- {path.name}")
        print(f"  Yol: {path}")
        print(f"  Tür: {source_type}")
        print(f"  Kaynak eşleşme skoru: {score}")

    print("\nNot: Bu skor saldırı olasılığı değildir.")
    print("Sadece alert metniyle kaynak dosya arasındaki kelime eşleşme skorudur.")

    print("\n[4] Context oluşturuluyor...")
    context, sources = build_context(results)

    output_dir = Path("outputs")
    output_dir.mkdir(exist_ok=True)

    retrieved_context_path = output_dir / "retrieved_context.txt"
    retrieved_context_path.write_text(context, encoding="utf-8")

    print(f"Context yazıldı: {retrieved_context_path}")

    print("\n[5] Answer prompt oluşturuluyor...")
    answer_prompt = build_answer_prompt(alert_text, context)

    answer_prompt_path = output_dir / "answer_prompt.txt"
    answer_prompt_path.write_text(answer_prompt, encoding="utf-8")

    print(f"Answer prompt yazıldı: {answer_prompt_path}")

    print("\n[6] İşlem tamamlandı.")
    print("Şimdi şu dosyayı açabilirsin:")
    print(answer_prompt_path)


if __name__ == "__main__":
    main()