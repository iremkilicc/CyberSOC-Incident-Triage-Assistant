from pathlib import Path

from build_context import retrieve, build_context
from build_answer_prompt import build_answer_prompt
from query_builder import build_query_from_alert


ALERT_TEXT = """
Multiple failed login attempts were detected for the admin user on the vpn-gateway.
There were 35 failed login attempts within 5 minutes.
After the failed attempts, a successful login was observed.
Source IP: 192.168.1.25
Severity: medium
"""


def get_source_type(path):
    """
    Kaynak dosyanın hangi bilgi türüne ait olduğunu açıklar.
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
    print("CyberSOC Incident Triage Assistant - Demo Pipeline")
    print("=" * 60)

    print("\n[1] Demo alert alındı:")
    print(ALERT_TEXT.strip())

    print("\n[2] Alert metninden arama sorgusu oluşturuluyor...")
    query = build_query_from_alert(ALERT_TEXT)

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
    print("Sadece alert metniyle kaynak dosya arasındaki kelime eşleşme skorudur.")

    print("\n[5] Context oluşturuluyor...")
    context, sources = build_context(results)

    output_dir = Path("outputs")
    output_dir.mkdir(exist_ok=True)

    retrieved_context_path = output_dir / "retrieved_context.txt"
    retrieved_context_path.write_text(context, encoding="utf-8")

    print(f"Context yazıldı: {retrieved_context_path}")

    print("\n[6] Answer prompt oluşturuluyor...")
    answer_prompt = build_answer_prompt(ALERT_TEXT, context)

    answer_prompt_path = output_dir / "answer_prompt.txt"
    answer_prompt_path.write_text(answer_prompt, encoding="utf-8")

    print(f"Answer prompt yazıldı: {answer_prompt_path}")

    print("\n[7] Demo tamamlandı.")
    print("Şu dosyaları kontrol edebilirsin:")
    print(f"- {retrieved_context_path}")
    print(f"- {answer_prompt_path}")
    print("- outputs/sample_answer_bruteforce.md")


if __name__ == "__main__":
    main()