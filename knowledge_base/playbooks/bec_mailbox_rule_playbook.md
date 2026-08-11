# BEC ve Yetkisiz Mailbox Rule Playbook

## Amaç

Bu playbook; finans kullanıcısının posta kutusunda görülen şüpheli inbox rule, kurum dışı otomatik yönlendirme, finans yazışmalarına erişim ve sahte ödeme mesajlarını tek bir Business Email Compromise olay zaman çizelgesinde değerlendirmek için kullanılır.

## Aşama 1 — Şüpheli Inbox Manipulation Rule

Saldırganlar ele geçirilmiş posta kutusunda iletileri silen, okundu işaretleyen veya RSS Feeds, RSS Subscriptions, Notes ve Junk Email gibi görünürlüğü düşük klasörlere taşıyan kurallar oluşturabilir. Finans, invoice, payment, fatura veya IBAN gibi anahtar kelimeleri hedefleyen yeni bir kuralın iş amacı ve aktörü doğrulanmalıdır.

Toplanacak temel alanlar:

- Mailbox ve etkilenen kullanıcı
- Kural adı, durumu, koşulları ve aksiyonları
- `New-InboxRule`, `Set-InboxRule` ve `Remove-InboxRule` audit olayları
- Oluşturma zamanı, aktör, kaynak IP, client, SessionId ve UserId
- `MoveToFolder`, `DeleteMessage`, `MarkAsRead`, `ForwardTo` ve `RedirectTo` değerleri
- Kullanıcının kuralı ve koşullarını doğrulaması

Yalnızca tanınmayan bir gizleme veya taşıma kuralı varsa, dış yönlendirme ve posta erişimi henüz doğrulanmadığı için risk Orta seviyede tutulabilir.

## Aşama 2 — Kurum Dışı Otomatik Yönlendirme

Finans iletilerini kullanıcıya veya kuruma ait olmayan bir dış adrese yönlendiren kural veri toplama ve kalıcılık sağlayabilir. Hedef adresin kurum içi, kullanıcıya ait ikinci bir kurumsal mailbox veya onaylı iş akışı olup olmadığı kontrol edilmelidir.

Kullanıcının tanımadığı bir dış hedefe `ForwardTo` veya `RedirectTo` işlemi Yüksek riskli kabul edilir. Message trace ile eşleşen iletilerin dış hedefe gerçekten teslim edilip edilmediği doğrulanmalıdır.

## Aşama 3 — Finans Yazışması Erişimi ve Sahte Ödeme

`MailItemsAccessed` kayıtları kötü aktörün eriştiği finans iletilerinin kapsamını belirlemek için kullanılır. Bind erişiminde `InternetMessageId`; sync erişiminde klasör, `ClientIPAddress`, `SessionId`, istemci ve protokol alanları incelenmelidir.

Finans yazışmalarına yetkisiz erişim sonrasında tedarikçi veya müşteriye yeni IBAN, banka hesabı ya da ödeme talebi içeren sahte mesaj gönderilmesi aktif BEC ve finansal dolandırıcılık girişimini doğrular. Bu durumda risk Kritiktir.

## Aşama 4 — Tenant Geneli Kapsam

Aynı kural adı, koşul, hedef adres, aktör IP, SessionId veya gönderim örüntüsü başka posta kutularında aranmalıdır. Birden fazla finans posta kutusunda aynı göstergelerin görülmesi kurum geneli BEC kampanyası olarak ele alınır.

Kapsam şunları içermelidir:

- Etkilenen toplam mailbox ve kullanıcılar
- İlk ve son kötü amaçlı etkinlik zamanı
- Dış hedefe yönlendirilen ileti sayısı ve hassasiyeti
- Erişilen finans yazışmaları ve sahte mesaj alıcıları
- Para transferi, banka bilgisi değişikliği veya gerçekleşmiş mali kayıp

## Öncelikli SOC Aksiyonları

1. Sign-in, Unified Audit Log, mailbox audit, message trace ve kural yapılandırma kanıtlarını koruyun.
2. Kural değişikliği, posta erişimi, dış yönlendirme ve gönderim olaylarını aynı zaman çizelgesinde birleştirin.
3. Kanıt koruma sonrasında yetkisiz kuralı, aktif oturumları ve tokenları kurum prosedürüyle yetkili onay altında etkisizleştirin.
4. Finans ekibi ile hedef tedarikçileri doğrulanmış alternatif kanaldan uyarıp bekleyen ödeme ve banka değişikliklerini durdurun.
5. Aynı göstergeleri tenant genelinde araştırıp olayın finansal, hukuki ve veri ifşası kapsamını eskale edin.

## Yanlış Pozitif Kontrolleri

- Kullanıcının doğruladığı meşru mailbox organizasyon kuralı
- Kuruma veya kullanıcıya ait onaylı ikinci posta kutusu
- Yetkili transport rule veya belgelenmiş iş akışı
- Normal çalışma saatleri, bilinen cihaz, IP ve yönetim oturumu
- Kural koşullarıyla uyumlu ve onaylı finans otomasyonu

## Kaynaklar

- Microsoft, Alert classification for suspicious inbox forwarding rules: https://learn.microsoft.com/en-us/defender-xdr/alert-grading-playbook-inbox-forwarding-rules
- Microsoft, Alert classification for suspicious inbox manipulation rules: https://learn.microsoft.com/en-us/defender-xdr/alert-grading-playbook-inbox-manipulation-rules
- Microsoft, Respond to a compromised email account: https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account
- MITRE ATT&CK T1114.003: https://attack.mitre.org/techniques/T1114/003/
- MITRE ATT&CK T1657: https://attack.mitre.org/techniques/T1657/

