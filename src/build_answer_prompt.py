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
    LLM'e verilecek final SOC triage promptunu oluşturur.
    """

    prompt = f"""
You are a cybersecurity SOC analyst assistant.

Your task is to analyze the given security alert by using ONLY the provided knowledge base context.

Do not claim that the event is definitely malicious unless the context and evidence clearly support it.
If there is not enough information, say that more evidence is needed.
Do not recommend automatic blocking, account disabling, malware removal, or destructive actions.
You are only giving triage guidance to a human analyst.

SECURITY ALERT:
{alert_text}

KNOWLEDGE BASE CONTEXT:
{context}

Now produce the answer in Turkish using this exact format:

# Olay Özeti

Kısa ve sade şekilde olayın ne olduğunu açıkla.

# Olası Yorum / Hipotez

Bu olayın neye benzeyebileceğini açıkla. Kesin konuşma.

# MITRE ATT&CK Eşleşmesi

İlgili MITRE tekniğini yaz. Emin değilsen olası eşleşme olarak belirt.

# Bu Yorumu Destekleyen Kanıtlar

Alert içindeki kanıtları madde madde yaz.

# Eksik Bilgiler

Kesin karar için hangi bilgilerin eksik olduğunu yaz.

# İlk Kontrol Adımları

SOC analyst’in ilk bakması gereken adımları yaz.

# Önerilen İlk Müdahale

Temkinli ve güvenli öneriler ver. Otomatik engelleme veya hesap kapatma önerme.

# False Positive İhtimali

Bu olayın saldırı dışı açıklamalarını yaz.

# Kullanılan Kaynaklar

Context içinde verilen kaynak dosya adlarını yaz.

# Güven Düzeyi

Düşük, orta veya yüksek şeklinde belirt. Nedenini kısa açıkla.
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