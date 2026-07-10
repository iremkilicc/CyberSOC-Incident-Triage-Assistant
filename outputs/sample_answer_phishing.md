# Sample Answer - Phishing Alert

## 1. Olayı İnsan Dilinde Açıklama

Bu alert, bir kullanıcının acil parola sıfırlama konulu şüpheli bir e-posta bildirdiğini gösteriyor. E-postada bilinmeyen bir link var. Kullanıcının linke tıklayıp tıklamadığı ve kimlik bilgisi girip girmediği henüz bilinmiyor.

Basitçe: Kullanıcı kandırılarak sahte bir parola sıfırlama sayfasına yönlendirilmeye çalışılmış olabilir.

## 2. İlk İzlenim

Bu olay ilk bakışta phishing şüphesine benzeyebilir. Çünkü e-posta acil aksiyon istiyor, parola sıfırlama teması kullanıyor ve bilinmeyen bir link içeriyor.

Ancak kesin saldırı demek doğru değildir. E-posta yasal bir bildirim, spam veya yanlış anlaşılmış bir otomatik mesaj da olabilir.

## 3. Olası Senaryolar

- **Phishing girişimi:** Kullanıcı sahte bir linke yönlendirilmek istenmiş olabilir.
- **Credential Harvesting ihtimali:** Kullanıcı linke tıklayıp parola veya MFA kodu girdiyse hesap riski artar.
- **Spam / Reklam / Yanlış Alarm:** Mail zararlı değil, sadece kullanıcıya şüpheli görünmüş olabilir.
- **Gerçek parola sıfırlama bildirimi:** Mail gerçekten yasal bir sistemden gelmiş olabilir.

## 4. MITRE ATT&CK Eşleşmesi

Olası MITRE ATT&CK eşleşmesi:

- T1566 - Phishing

Kullanıcı kimlik bilgisi girdiyse Valid Accounts ihtimali de sonradan değerlendirilebilir.

## 5. Bu Yorumu Destekleyen Kanıtlar

- Kullanıcı şüpheli e-posta bildirmiş.
- E-postanın konusu acil parola sıfırlama ile ilgili.
- E-postada bilinmeyen link var.
- `user_clicked` durumu bilinmiyor.
- `credentials_entered` durumu bilinmiyor.

## 6. Risk Artıran Durumlar

- E-postanın aciliyet hissi oluşturması.
- Parola sıfırlama teması kullanması.
- Bilinmeyen link içermesi.
- Kullanıcının linke tıklayıp tıklamadığının bilinmemesi.
- Kullanıcının parola veya MFA kodu girip girmediğinin bilinmemesi.

## 7. Risk Düşüren veya False Positive Olabilecek Durumlar

- E-posta gerçek bir kurumdan gelen yasal bildirim olabilir.
- Kullanıcı spam veya reklam mailini phishing sanmış olabilir.
- Link güvenli ama kullanıcı tarafından bilinmeyen bir servis olabilir.
- Kurum içi otomatik bildirim dışarıdan gelmiş gibi görünebilir.
- Güvenlik aracı yanlış pozitif üretmiş olabilir.

## 8. Eksik Bilgiler

- Kullanıcı linke tıkladı mı?
- Kullanıcı parola, MFA kodu veya başka hassas bilgi girdi mi?
- Gönderen adresi gerçek mi?
- Reply-to adresi farklı mı?
- Link hangi domaine gidiyor?
- Domain yeni, bilinmeyen veya taklit domain mi?
- Mail header bilgileri ne gösteriyor?
- Aynı mail başka kullanıcılara da gönderilmiş mi?
- Kullanıcının hesabında sonrasında şüpheli login var mı?

## 9. SOC Analyst İçin Adım Adım Kontrol Planı

1. Kullanıcıyla iletişime geçip linke tıklayıp tıklamadığını öğren.
2. Kullanıcı kimlik bilgisi veya MFA kodu girdi mi doğrula.
3. Gönderen adresini ve reply-to bilgisini kontrol et.
4. Link domainini incele.
5. Mail header bilgilerini kontrol et.
6. Ekte dosya var mı bak.
7. Aynı e-posta başka kullanıcılara gitmiş mi araştır.
8. Kullanıcının hesabında sonrasında şüpheli login var mı kontrol et.
9. Mail gateway veya güvenlik aracında bu mail/link için uyarı var mı bak.
10. Kanıtlar güçlüyse olayı incident olarak yükseltmeyi değerlendir.

## 10. Ne Zaman Incident'a Yükseltilir?

- Kullanıcı linke tıkladıysa ve kimlik bilgisi girdiyse.
- Kullanıcının hesabında sonrasında şüpheli login görüldüyse.
- Aynı mail çok sayıda kullanıcıya gönderildiyse.
- Link veya domain zararlı/şüpheli görünüyorsa.
- Mail ekinde şüpheli dosya varsa.
- Kullanıcı kritik yetkilere sahipse.

## 11. Önerilen İlk Müdahale

Öncelikle kullanıcı aksiyonu doğrulanmalıdır. Kullanıcı linke tıklamadıysa olay izlenebilir ve mail bilgisi kaydedilebilir. Kullanıcı kimlik bilgisi girdiyse parola sıfırlama, MFA kontrolü ve hesap aktivitelerinin incelenmesi önerilir.

Otomatik hesap kapatma, toplu mail silme veya domain engelleme bu aşamada doğrudan önerilmemelidir. İnsan analistin kanıtları doğrulaması gerekir.

## 12. Kullanılan Kaynaklar

- knowledge_base/mitre/T1566_phishing.md
- knowledge_base/investigation_notes/email_investigation_fields.md
- knowledge_base/playbooks/phishing_playbook.md
- knowledge_base/nist/nist_incident_response_summary.md

## 13. Güven Düzeyi

**Orta.**

Phishing şüphesini destekleyen göstergeler var: acil parola sıfırlama teması ve bilinmeyen link. Ancak kullanıcının linke tıklayıp tıklamadığı, kimlik bilgisi girip girmediği, sender/domain/header bilgileri bilinmediği için kesin karar için ek kanıt gerekir.
