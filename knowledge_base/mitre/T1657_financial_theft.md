# MITRE ATT&CK T1657 — Financial Theft

## Teknik Özet

Financial Theft, saldırganın sosyal mühendislik, hesap ele geçirme veya teknik yöntemlerle hedefin parasal kaynaklarını kendi çıkarına yönlendirmesidir. Business Email Compromise olaylarında saldırgan güvenilen bir kişi veya kurum kimliğini kullanarak mağduru saldırgan kontrollü banka hesabına para göndermeye ikna edebilir.

## BEC Bağlamındaki Bulgular

- Finans veya yönetici posta kutusunun ele geçirilmesi
- Tedarikçi ve ödeme yazışmalarının incelenmesi
- Mevcut mesaj zincirine yanıt verilmesi veya güvenilen kimliğin taklit edilmesi
- Yeni IBAN, banka hesabı ya da acil ödeme talebi
- `Send`, `SendAs` veya `SendOnBehalf` ile sahte mesaj gönderimi
- Alıcının banka bilgisi değiştirmesi veya para transferi yapması

## Risk ve Etki

Sahte ödeme mesajının gönderilmesi henüz para transferi yapılmamış olsa bile aktif finansal dolandırıcılık girişimidir. Hassas yazışma erişimiyle birlikte görülmesi halinde olay Kritiktir. Ödeme tamamlandıysa finansal kayıp, banka geri çağırma süreci, hukuk ve düzenleyici bildirim kapsamı ayrıca belirlenmelidir.

## SOC İçin Öncelikler

1. Sahte mesajın `Message-ID`, alıcı, zaman, oturum ve gönderim audit kanıtlarını koruyun.
2. Yeni banka bilgilerini ve saldırgan kontrollü hedefleri IOC olarak kapsamlandırın.
3. Finans ekibi ve hedef tarafla e-posta dışı doğrulanmış kanaldan iletişim kurun.
4. Bekleyen ödemeleri durdurup tamamlanmış transferler için kurum prosedüründeki geri çağırma sürecini başlatın.
5. Aynı mesaj, kural ve hesap göstergelerini başka kullanıcı ve posta kutularında araştırın.

## Kaynaklar

- MITRE ATT&CK T1657: https://attack.mitre.org/techniques/T1657/
- Microsoft, Respond to a compromised email account: https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account

