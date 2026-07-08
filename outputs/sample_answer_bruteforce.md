# Sample Answer - Brute Force Alert

## Olay Özeti

Admin kullanıcısı için vpn-gateway üzerinde 5 dakika içinde 35 başarısız giriş denemesi tespit edilmiş. Bu başarısız denemelerden sonra başarılı bir giriş görülmüş. Kaynak IP adresi 192.168.1.25 olarak belirtilmiş ve alert seviyesi medium olarak verilmiş.

## Olası Yorum / Hipotez

Bu olay brute force veya password guessing davranışına benzeyebilir. Çünkü kısa zaman aralığında aynı kullanıcı hesabına çok sayıda başarısız giriş denemesi yapılmış ve sonrasında başarılı giriş oluşmuş.

Ancak bu olay kesin saldırı olarak yorumlanmamalıdır. Kullanıcı şifresini unutmuş olabilir, eski şifreyle otomatik giriş deneyen bir cihaz olabilir veya yanlış yapılandırılmış bir servis tekrar tekrar login deniyor olabilir.

## MITRE ATT&CK Eşleşmesi

Olası MITRE ATT&CK eşleşmesi:

- T1110 - Brute Force

Başarısız girişlerden sonra başarılı login görülmesi nedeniyle geçerli hesap kullanımı ihtimali de ayrıca değerlendirilebilir. Ancak mevcut kaynaklara göre ana eşleşme T1110 Brute Force olarak görünmektedir.

## Bu Yorumu Destekleyen Kanıtlar

- Admin kullanıcısı hedeflenmiş.
- 5 dakika içinde 35 başarısız giriş denemesi var.
- Başarısız denemelerden sonra başarılı giriş görülmüş.
- Hedef sistem vpn-gateway.
- Olay login/authentication davranışıyla ilgili.
- Source IP bilgisi mevcut: 192.168.1.25.
- Alert seviyesi medium olarak belirtilmiş.

## Eksik Bilgiler

Kesin karar için aşağıdaki bilgiler eksiktir:

- Başarılı giriş sonrası kullanıcı hangi işlemleri yaptı?
- Source IP daha önce görülmüş mü?
- Aynı source IP başka kullanıcı hesaplarını da denemiş mi?
- Kullanıcı normalde bu VPN sistemine giriş yapar mı?
- Kullanıcı normalde bu lokasyon veya cihazdan giriş yapar mı?
- MFA aktif mi?
- Account lockout politikası çalışmış mı?
- Aynı zaman aralığında başka güvenlik alertleri var mı?
- Kullanıcı bu giriş denemelerini kendisinin yaptığını doğruluyor mu?

## İlk Kontrol Adımları

1. Başarılı giriş sonrası aktiviteleri incele.
2. Source IP adresinin geçmişini kontrol et.
3. Aynı IP adresinin başka kullanıcı hesaplarını deneyip denemediğine bak.
4. Admin hesabının kritik veya yetkili hesap olup olmadığını doğrula.
5. Kullanıcının normal login davranışıyla bu olayın uyumlu olup olmadığını kontrol et.
6. MFA durumunu kontrol et.
7. Account lockout veya benzer koruma mekanizmalarının çalışıp çalışmadığını incele.
8. Aynı zaman aralığında başka alert olup olmadığını araştır.
9. Kullanıcıyla iletişime geçip giriş denemelerini kendisinin yapıp yapmadığını doğrula.

## Önerilen İlk Müdahale

Olay orta-yüksek öncelikle incelenmelidir. Öncelikle başarılı giriş sonrası aktiviteler, source IP geçmişi, kullanıcının normal davranışı ve MFA durumu kontrol edilmelidir.

Kullanıcı bu girişleri kendisinin yapmadığını söylerse veya başarılı giriş sonrası şüpheli aktiviteler görülürse olay incident olarak yükseltilebilir.

Otomatik IP engelleme, hesap kapatma veya benzer aksiyonlar doğrudan önerilmemelidir. İnsan analistin kanıtları doğrulaması gerekir.

## False Positive İhtimali

Bu olay saldırı dışı nedenlerle de oluşmuş olabilir:

- Kullanıcı şifresini unutup tekrar tekrar denemiş olabilir.
- Bir cihaz veya uygulama eski şifreyle otomatik giriş deniyor olabilir.
- Bir servis hesabı yanlış parola ile tekrar tekrar bağlantı kurmaya çalışıyor olabilir.
- VPN veya authentication sisteminde geçici bir problem olabilir.
- Yanlış yapılandırılmış bir uygulama login denemeleri üretiyor olabilir.

## Kullanılan Kaynaklar

- knowledge_base/investigation_notes/login_log_fields.md
- knowledge_base/mitre/T1110_brute_force.md
- knowledge_base/playbooks/brute_force_playbook.md
- knowledge_base/nist/nist_incident_response_summary.md

## Güven Düzeyi

Orta-yüksek.

Çünkü alertte brute force davranışını destekleyen güçlü kanıtlar var: kısa sürede çok sayıda başarısız giriş denemesi, admin hesabı, vpn-gateway hedefi ve başarısız denemelerden sonra başarılı giriş.

Ancak kesin karar için source IP geçmişi, MFA durumu, kullanıcı doğrulaması ve başarılı giriş sonrası aktiviteler incelenmelidir.