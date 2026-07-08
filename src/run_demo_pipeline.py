from pathlib import Path

from build_context import retrieve, build_context
from build_answer_prompt import build_answer_prompt


ALERT_TEXT = """
Multiple failed login attempts were detected for the admin user on the vpn-gateway.
There were 35 failed login attempts within 5 minutes.
After the failed attempts, a successful login was observed.
Source IP: 192.168.1.25
Severity: medium
"""


QUERY = "Multiple failed login attempts admin vpn successful login"


def main():
    print("CyberSOC Incident Triage Assistant - Demo Pipeline")
    print("=" * 55)

    print("\n[1] Alert alındı:")
    print(ALERT_TEXT.strip())

    print("\n[2] Knowledge base içinde ilgili kaynaklar aranıyor...")
    results = retrieve(QUERY, top_k=4)

    if not results:
        print("İlgili kaynak bulunamadı.")
        return

    print("\n[3] Seçilen kaynaklar:")

    for score, document in results:
        print(f"- Skor {score} | {document['path']}")

    print("\n[4] Context oluşturuluyor...")
    context, sources = build_context(results)

    output_dir = Path("outputs")
    output_dir.mkdir(exist_ok=True)

    retrieved_context_path = output_dir / "retrieved_context.txt"
    retrieved_context_path.write_text(context, encoding="utf-8")

    print(f"Context yazıldı: {retrieved_context_path}")

    print("\n[5] Answer prompt oluşturuluyor...")
    answer_prompt = build_answer_prompt(ALERT_TEXT, context)

    answer_prompt_path = output_dir / "answer_prompt.txt"
    answer_prompt_path.write_text(answer_prompt, encoding="utf-8")

    print(f"Answer prompt yazıldı: {answer_prompt_path}")

    print("\n[6] Demo tamamlandı.")
    print("Şu dosyaları kontrol edebilirsin:")
    print(f"- {retrieved_context_path}")
    print(f"- {answer_prompt_path}")
    print("- outputs/sample_answer_bruteforce.md")


if __name__ == "__main__":
    main()