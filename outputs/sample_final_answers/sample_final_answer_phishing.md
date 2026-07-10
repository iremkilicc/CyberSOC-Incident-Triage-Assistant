# Sample Final Answer - Phishing / Suspicious Email

## 1. Olayı İnsan Dilinde Açıklama

Bu olayda kullanıcıya şüpheli bir e-posta gelmiş. E-posta acil parola sıfırlama teması taşıyor ve bilinmeyen bir link içeriyor.

Basitçe: Kullanıcı kandırılarak sahte bir sayfaya yönlendirilmeye çalışılmış olabilir.

## 2. İlk İzlenim

Bu olay credential phishing ihtimaline benzeyebilir.

Ancak kesin karar için kullanıcının linke tıklayıp tıklamadığı, credential girip girmediği, URL reputation sonucu ve email authentication bilgileri kontrol edilmelidir.

## 3. Olası Senaryolar

- Credential phishing girişimi olabilir.
- Gerçek bir servis parola sıfırlama maili göndermiş olabilir.
- Mail spam veya pazarlama otomasyonu olabilir.
- Kullanıcı maili şüpheli sanmış ama tıklamamış olabilir.
- Gönderen domain veya mail altyapısı yanlış yapılandırılmış olabilir.

## 4. MITRE ATT&CK Eşleşmesi

Olası MITRE ATT&CK eşleşmesi:

- T1566 - Phishing

Eğer kullanıcı credential girdiyse credential phishing ve account compromise ihtimali ayrıca değerlendirilmelidir.

## 5. Bu Yorumu Destekleyen Kanıtlar

- E-posta password reset / account verification teması taşıyor.
- Bilinmeyen link içeriyor.
- Kullanıcı etkileşimi bilinmiyor.
- Sender ve reply-to bilgileri kontrol gerektiriyor.
- SPF, DKIM veya DMARC sorunları varsa risk artar.
- Mail kullanıcıyı hızlı aksiyon almaya yönlendiriyor olabilir.

## 6. Risk Artıran Durumlar

- Acil parola sıfırlama teması.
- Bilinmeyen link.
- Display name ile sender domain uyumsuzluğu ihtimali.
- Reply-to adresinin farklı olması.
- SPF, DKIM veya DMARC fail sonucu.
- Kullanıcının linke tıklamış olması.
- Kullanıcının credential girmiş olması.
- Aynı mailin başka kullanıcılara da gitmiş olması.

## 7. Risk Düşüren veya False Positive Olabilecek Durumlar

- Mail gerçek bir servis tarafından gönderilmiş olabilir.
- Kullanıcı maili tıklamadan raporlamış olabilir.
- Mail gateway tarafından karantinaya alınmış olabilir.
- Kullanıcı credential girmemiş olabilir.
- Link güvenlik servisi veya kurumsal redirect içeriyor olabilir.
- Üçüncü taraf meşru servis farklı mail altyapısı kullanıyor olabilir.

## 8. Eksik Bilgiler

- Mail kullanıcıya ulaştı mı?
- Kullanıcı linke tıkladı mı?
- Kullanıcı credential girdi mi?
- URL reputation sonucu nedir?
- Landing page sahte login sayfası mı?
- SPF, DKIM ve DMARC sonuçları ne?
- Aynı mail başka kullanıcılara da gitti mi?
- Tıklama sonrası suspicious login oluştu mu?
- Attachment var mıydı?
- Kullanıcı bu e-postayı bekliyor muydu?

## 9. SOC Analyst İçin Adım Adım Kontrol Planı

1. Mailin delivery status bilgisini kontrol et.
2. Sender, display name, reply-to ve return-path bilgilerini incele.
3. SPF, DKIM ve DMARC sonuçlarını kontrol et.
4. Subject ve body içinde sosyal mühendislik göstergesi var mı bak.
5. Linkin gerçek hedefini ve reputation sonucunu kontrol et.
6. Landing page login formu gösteriyor mu incele.
7. Kullanıcının tıklama durumunu kontrol et.
8. Credential girilip girilmediğini doğrula.
9. Aynı mail başka mailboxlarda var mı araştır.
10. Tıklama sonrası login ve MFA loglarını incele.

## 10. Ne Zaman Incident'a Yükseltilir?

- Kullanıcı credential girdiyse.
- Kullanıcı MFA kodu girdiyse veya onayladıysa.
- Tıklama sonrası suspicious successful login varsa.
- Aynı mail çok sayıda kullanıcıya ulaştıysa.
- Birden fazla kullanıcı linke tıkladıysa.
- URL veya attachment malicious çıkarsa.
- Kullanıcı hesabında mailbox rule veya forwarding rule oluştuysa.

## 11. Önerilen İlk Müdahale

İlk aşamada e-posta, link, kullanıcı etkileşimi ve kapsam bilgileri doğrulanmalıdır.

Önerilen güvenli adımlar:

- Mail metadata bilgisini topla.
- URL ve domain reputation kontrolü yap.
- Kullanıcıya linke tıklayıp tıklamadığını sor.
- Tıklama sonrası login loglarını incele.
- Aynı IOC’lerin başka kullanıcı ve sistemlerde görülüp görülmediğini araştır.
- Gerekirse incident response ekibine yükselt.

Kanıt olmadan otomatik hesap kapatma, domain engelleme veya yıkıcı aksiyon önerilmemelidir.

## 12. Kullanılan Kaynaklar

- T1566_phishing.md
- phishing_playbook.md
- email_investigation_fields.md
- nist_incident_response_summary.md

## 13. Güven Düzeyi

Güven düzeyi: Orta

Çünkü phishing göstergeleri var ancak kullanıcı tıklama, credential girişi, URL reputation ve post-click login bilgileri olmadan kesin incident kararı verilemez.
