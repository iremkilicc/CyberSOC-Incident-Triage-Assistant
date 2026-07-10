from pathlib import Path


ALERT_TEXT = """
Multiple failed login attempts were detected for the admin user on the vpn-gateway.
There were 35 failed login attempts within 5 minutes.
After the failed attempts, a successful login was observed.
Source IP: 192.168.1.25
Severity: medium
"""


def build_answer_prompt(alert_text, context):
    """
    Alert metni ve retrieved context bilgisini birleştirerek
    LLM'e verilecek SOC Analyst Coach tarzı final promptu oluşturur.
    """

    prompt = f"""
You are a cybersecurity SOC analyst coach assistant.

Your task is to help a junior SOC analyst understand and triage the given security alert.

Use ONLY the provided knowledge base context.
Do not invent facts that are not supported by the alert or the context.
Do not claim that the event is definitely malicious unless the evidence clearly supports it.
If there is not enough information, clearly say which evidence is missing.
Do not recommend automatic blocking, account disabling, malware removal, or destructive actions.
You are only giving triage guidance to a human analyst.

Important:
- Source scores in the context are retrieval matching scores, not attack probability.
- Explain the event like you are coaching a beginner SOC analyst.
- Prefer cautious language such as "benzeyebilir", "değerlendirilmeli", "kontrol edilmeli".
- Mention multiple possible scenarios when appropriate.
- Focus on what the analyst should check next.

SECURITY ALERT:
{alert_text}

KNOWLEDGE BASE CONTEXT:
{context}

Now produce the answer in Turkish using this exact SOC Analyst Coach format:

# 1. Olayı İnsan Dilinde Açıklama

Bu alertin ne anlattığını teknik olmayan, sade bir dille açıkla.

# 2. İlk İzlenim

Bu olay ilk bakışta neye benziyor? Kesin konuşmadan yorumla.

# 3. Olası Senaryolar

Bu olayın birkaç farklı açıklamasını yaz.

Örnek yaklaşım:
- Saldırı ihtimali
- Geçerli hesap kullanımı ihtimali
- Kullanıcı hatası / yanlış yapılandırma / false positive ihtimali

# 4. MITRE ATT&CK Eşleşmesi

İlgili MITRE tekniğini veya tekniklerini yaz.
Emin değilsen "olası eşleşme" olarak belirt.

# 5. Bu Yorumu Destekleyen Kanıtlar

Alert içindeki somut kanıtları madde madde yaz.

# 6. Risk Artıran Durumlar

Bu olayda riski artıran noktaları yaz.

# 7. Risk Düşüren veya False Positive Olabilecek Durumlar

Bu olayın saldırı dışı nedenlerini açıkla.

# 8. Eksik Bilgiler

Kesin karar vermek için hangi bilgiler eksik, madde madde yaz.

# 9. SOC Analyst İçin Adım Adım Kontrol Planı

Junior SOC analyst'in sırayla neye bakması gerektiğini adım adım yaz.
Adımlar pratik ve uygulanabilir olsun.

# 10. Ne Zaman Incident'a Yükseltilir?

Bu olay hangi şartlarda gerçek incident olarak yükseltilmeli, açıkla.

# 11. Önerilen İlk Müdahale

Temkinli ve güvenli öneriler ver.
Otomatik engelleme, hesap kapatma veya silme gibi aksiyonlar önerme.

# 12. Kullanılan Kaynaklar

Context içinde verilen kaynak dosya adlarını yaz.

# 13. Güven Düzeyi

Düşük, orta veya yüksek şeklinde belirt.
Nedenini kısa ve kanıta dayalı açıkla.
"""

    return prompt.strip()


def main():
    context_path = Path("outputs/retrieved_context.txt")

    if not context_path.exists():
        print("Hata: outputs/retrieved_context.txt bulunamadı.")
        print("Önce şu komutu çalıştır:")
        print("python src/build_context.py")
        return

    context = context_path.read_text(encoding="utf-8", errors="ignore")

    answer_prompt = build_answer_prompt(ALERT_TEXT, context)

    output_dir = Path("outputs")
    output_dir.mkdir(exist_ok=True)

    output_path = output_dir / "answer_prompt.txt"
    output_path.write_text(answer_prompt, encoding="utf-8")

    print("Answer prompt oluşturuldu:")
    print(output_path)


if __name__ == "__main__":
    main()