# MITRE ATT&CK T1114.003 — Email Forwarding Rule

## Teknik Özet

Saldırganlar mağdurun etkinliğini izlemek, hassas bilgileri toplamak ve sonraki operasyonlar için istihbarat elde etmek amacıyla e-posta yönlendirme kurallarını kötüye kullanabilir. Kural tabanlı yönlendirme, parola değiştirildikten sonra bile gelen postaların saldırganın kontrol ettiği hedefe iletilmesini sürdürebildiği için kalıcılık ve veri toplama etkisi yaratabilir.

Kurallar yerel e-posta istemcisi, web arayüzü, Exchange yönetim aracı veya komut satırı üzerinden oluşturulabilir. İletiler gönderene, konuya, gövdeye veya anahtar kelimelere göre iç ya da dış hedefe yönlendirilebilir. Kural özellikleri görünmez hâle getirilmiş olabilir; bu nedenle yalnızca Outlook arayüzüyle kontrol yeterli değildir.

## SOC İçin Ana Bulgular

- Beklenmeyen `New-InboxRule` veya `Set-InboxRule` audit olayı
- Finans, invoice, payment, fatura veya IBAN koşulları
- `ForwardTo` veya `RedirectTo` alanında kurum dışı hedef
- RSS, Notes veya Junk gibi görünürlüğü düşük klasöre taşıma
- Mesajları silme veya okundu işaretleme
- Kural oluşturma zamanında olağandışı IP, cihaz, client veya oturum
- Aynı kural ve hedefin birden fazla mailbox üzerinde görülmesi

## Risk Yükseltme Mantığı

Tek başına yeni bir inbox rule meşru kullanıcı otomasyonu olabilir. Kuralın aktörü, iş amacı, koşulları ve kullanıcı doğrulaması incelenmelidir.

Kullanıcının tanımadığı kurum dışı otomatik yönlendirme Yüksek riskli kabul edilmelidir. Yönlendirme sonrasında hassas finans yazışmalarına erişim veya sahte ödeme mesajı doğrulanırsa aktif BEC ve veri etkisi nedeniyle olay Kritik seviyeye yükseltilmelidir.

## Toplanacak Kanıtlar

- Unified Audit Log kural operasyonları ve tam parametreleri
- Mailbox rule adı, koşulları, aksiyonları ve gizli kural durumu
- Message trace, hedef adres, teslim sonucu ve ileti kimlikleri
- Sign-in, token, client IP, SessionId ve kullanıcı doğrulaması
- `MailItemsAccessed`, `Send`, `SendAs` ve `SendOnBehalf` olayları
- Aynı rule, IP, hedef ve oturumun tenant geneli kapsamı

## Kaynaklar

- MITRE ATT&CK T1114.003: https://attack.mitre.org/techniques/T1114/003/
- Microsoft, Suspicious inbox forwarding rules: https://learn.microsoft.com/en-us/defender-xdr/alert-grading-playbook-inbox-forwarding-rules
- Microsoft, Identify who modified mailbox rules: https://learn.microsoft.com/en-us/purview/audit-log-identify-mailbox-rules

