# BEC ve Mailbox Rule İnceleme Alanları

## Kural Değişikliği Alanları

- `mailbox`: Etkilenen posta kutusu ve UPN
- `operation`: `New-InboxRule`, `Set-InboxRule` veya `Remove-InboxRule`
- `rule_name`: Kural adı
- `enabled`: Kuralın etkinlik durumu
- `rule_conditions`: Subject, body, sender, recipient veya anahtar kelime koşulları
- `move_to_folder`: İletilerin taşındığı klasör
- `delete_message`: Silme aksiyonu
- `mark_as_read`: Okundu işaretleme aksiyonu
- `forward_to`: Yönlendirme hedefi
- `redirect_to`: Redirect hedefi
- `creation_time`: Audit olay zamanı
- `user_id`: İşlemi yapan kimlik
- `client_ip`: İşlemin kaynak IP'si
- `client_info`: Kullanılan client veya protokol
- `session_id`: İlişkili oturum kimliği

## Dış Yönlendirme ve Message Trace Alanları

- Hedef adresin domain'i, sahipliği ve kurum ilişkisi
- İletinin özgün alıcısı ve dış yönlendirme hedefi
- `Message-ID` ve `InternetMessageId`
- Gönderim, yönlendirme ve teslim zamanı
- Teslim sonucu, connector ve transport rule bilgisi
- Yönlendirilen iletinin konusu, sınıflandırması ve hassasiyet etiketi
- Aynı dış hedefe yönlendiren diğer mailboxlar

## MailItemsAccessed Alanları

- `MailAccessType`: Bind veya Sync
- `InternetMessageId`: Bind erişimindeki ileti kimliği
- `OperationCount`: Birleştirilen erişim sayısı
- `Folders`: Sync veya bind kapsamındaki klasör ve ileti verileri
- `ClientIPAddress`: Erişim kaynağı
- `ClientInfoString`: Protokol ve istemci
- `SessionId`: Kötü aktör etkinliğini normal kullanıcı etkinliğinden ayıran oturum
- `UserId`: Postayı okuyan veya erişen kimlik
- Finans, ödeme, fatura ve banka bilgisi içeren iletilerin hassasiyeti

## Sahte Ödeme Mesajı Alanları

- `Send`, `SendAs` ve `SendOnBehalf` audit olayları
- Gönderen mailbox ve kullanılan oturum
- Alıcı tedarikçi, müşteri veya finans kullanıcısı
- `Message-ID`, konu, gövde ve yanıt zinciri
- Yeni veya değiştirilmiş IBAN, banka adı ve hesap sahibi
- Gönderim zamanı, kaynak IP, client ve user-agent
- Mesajın teslim, okunma ve yanıt durumu
- Ödeme yapıldıysa tutar, para birimi, banka ve işlem zamanı

## Tenant Geneli Kapsam Alanları

- Aynı rule name, condition ve action görülen diğer mailboxlar
- Aynı dış hedef, aktör IP, SessionId ve user-agent
- Etkilenen toplam kullanıcı ve posta kutusu
- İlk ve son kötü amaçlı etkinlik zamanı
- Yönlendirilen ve erişilen toplam ileti sayısı
- Sahte mesaj alıcıları ve gerçekleşen finansal işlem durumu

## Incident'a Yükseltme Göstergeleri

- Kullanıcının kuralı veya hedef adresi tanımaması
- Finans anahtar kelimelerini hedefleyen gizleme veya yönlendirme kuralı
- Kurum dışı adrese başarılı otomatik yönlendirme
- Yetkisiz `MailItemsAccessed` ve finans yazışması erişimi
- Yeni IBAN veya banka hesabı içeren sahte ödeme mesajı
- Aynı göstergelerin birden fazla finans posta kutusunda görülmesi

## Kaynaklar

- Microsoft, Identify who modified mailbox rules: https://learn.microsoft.com/en-us/purview/audit-log-identify-mailbox-rules
- Microsoft, Use MailItemsAccessed to investigate compromised accounts: https://learn.microsoft.com/en-us/purview/audit-log-investigate-accounts
- Microsoft, Respond to a compromised email account: https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account

