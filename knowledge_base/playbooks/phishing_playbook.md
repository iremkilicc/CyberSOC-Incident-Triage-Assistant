# Phishing SOC Playbook

## Amaç

Bu playbook, phishing, suspicious email, malicious link, malicious attachment, credential theft ve business email compromise şüphesi olan e-posta olaylarında SOC analyst'in nasıl düşünmesi gerektiğini açıklar.

Phishing alerti tek başına kesin saldırı anlamına gelmez. Bazı e-postalar spam, meşru bildirim, yanlış yapılandırılmış kurumsal servis veya kullanıcı tarafından yanlış anlaşılmış mesaj olabilir.

Amaç, e-postayı kanıta dayalı şekilde incelemek, kullanıcının etkilenip etkilenmediğini anlamak ve olayın spam mi, phishing mi, credential theft mı, yoksa incident mı olduğunu belirlemektir.

---

## Kapsam

Bu playbook şu olaylarda kullanılabilir:

- Kullanıcının şüpheli e-posta raporlaması
- Şifre sıfırlama veya hesap doğrulama temalı e-postalar
- Bilinmeyen link içeren e-postalar
- Bilinmeyen veya riskli attachment içeren e-postalar
- Kullanıcıdan parola, MFA kodu veya kişisel bilgi isteyen mesajlar
- Sahte Microsoft, Google, banka, kargo, fatura veya kurum içi servis taklidi
- Mail gateway tarafından suspicious veya malicious olarak işaretlenen e-postalar
- Aynı e-postanın birden fazla kullanıcıya gönderilmesi
- Linke tıklama sonrası suspicious login
- Attachment açılması sonrası endpoint alerti

---

## Temel Kavramlar

### Phishing

Phishing, saldırganın kullanıcıyı kandırarak linke tıklatmaya, dosya açtırmaya veya kimlik bilgisi girdirmeye çalışmasıdır.

Tipik özellikler:

- Aciliyet hissi
- Güvenilir kurum veya kişi taklidi
- Linke tıklama isteği
- Parola veya MFA kodu isteme
- Beklenmeyen dosya eki
- Sahte login sayfası

---

### Credential Phishing

Credential phishing, kullanıcının kimlik bilgilerini çalmayı hedefleyen phishing türüdür.

Tipik özellikler:

- Password reset
- Account verification
- Login required
- MFA verification
- Session expired
- Hesabınız askıya alınacak
- Parolanızı doğrulayın

En kritik soru:

- Kullanıcı linke tıkladı mı ve credential girdi mi?

---

### Malicious Attachment

E-postadaki ek dosyanın zararlı davranış üretme ihtimalidir.

Riskli durumlar:

- Makro içeren Office dosyası
- Script dosyası
- Arşiv içinde çalıştırılabilir dosya
- LNK, ISO, IMG, HTA, JS, VBS, PS1 gibi uzantılar
- Attachment açıldıktan sonra PowerShell, cmd veya wscript çalışması

---

### Business Email Compromise

Business Email Compromise, saldırganın güvenilir kişi veya kurum taklidiyle para transferi, fatura değişikliği veya hassas bilgi istemesidir.

Tipik özellikler:

- CEO, yönetici, finans veya tedarikçi taklidi
- Acil ödeme isteği
- Banka hesap bilgisinin değiştirilmesi
- Fatura veya ödeme teması
- Normal dışı gizlilik veya acele baskısı

---

## Alert İlk Geldiğinde Sorulacak Ana Sorular

Bir SOC analyst phishing alerti gördüğünde önce şu soruları sormalıdır:

1. E-posta kullanıcıya ulaştı mı?
2. E-posta kimden gelmiş?
3. Gönderen adres gerçek domainle uyumlu mu?
4. Display name ile sender email uyumlu mu?
5. Reply-to farklı mı?
6. SPF, DKIM ve DMARC sonuçları ne?
7. Subject sosyal mühendislik içeriyor mu?
8. Link var mı?
9. Attachment var mı?
10. Kullanıcı linke tıkladı mı?
11. Kullanıcı credential girdi mi?
12. Kullanıcı eki açtı mı?
13. Aynı e-posta başka kullanıcılara da gitmiş mi?
14. URL, domain veya attachment hash başka loglarda görülmüş mü?
15. Tıklama sonrası suspicious login var mı?
16. Eki açma sonrası endpoint alerti var mı?

---

## Toplanması Gereken Kanıtlar

### Email Metadata

Toplanacak bilgiler:

- sender_email
- sender_display_name
- reply_to
- return_path
- recipient
- subject
- message_id
- received_headers
- timestamp

Risk artıran durumlar:

- Sender domainin bilinmeyen olması
- Display name güvenilir görünüp sender emailin farklı olması
- Reply-to adresinin farklı domain olması
- Return-path ile sender uyumsuzluğu
- Message-ID domaininin şüpheli olması
- Beklenmeyen mail altyapısından gelmesi

---

### Authentication Sonuçları

Toplanacak bilgiler:

- SPF result
- DKIM result
- DMARC result
- alignment bilgisi

Risk artıran durumlar:

- SPF fail
- DKIM fail
- DMARC fail
- Sender domain spoofing ihtimali
- Kurumsal marka taklidiyle gelen authentication fail sonucu

Risk düşüren durumlar:

- SPF, DKIM ve DMARC pass
- Sender domain ve mail altyapısının beklenen servisle uyumlu olması

Ancak authentication pass sonucu tek başına mailin tamamen güvenli olduğunu kanıtlamaz. Saldırgan gerçek bir domain veya ele geçirilmiş bir hesap da kullanabilir.

---

### İçerik ve Sosyal Mühendislik

Kontrol edilecekler:

- Subject
- body_text
- aciliyet dili
- tehdit dili
- ödül vaadi
- güvenilir kurum taklidi
- kullanıcıdan istenen aksiyon

Risk artıran ifadeler:

- urgent
- action required
- password reset
- verify your account
- account locked
- final warning
- invoice attached
- payment failed
- security alert
- document shared
- MFA verification
- hesabınız askıya alındı
- parolanızı sıfırlayın
- acil işlem gerekli

---

### Link Analizi

Toplanacak bilgiler:

- URL
- visible link text
- real destination URL
- redirect chain
- landing page domain
- URL reputation
- domain age
- HTTPS durumu

Risk artıran durumlar:

- Görünen link ile gerçek URL'nin farklı olması
- Bilinmeyen domain
- Marka taklidi yapan domain
- URL shortener kullanımı
- IP adresiyle başlayan URL
- Yeni kayıt edilmiş domain
- Login formu gösteren landing page
- Kullanıcıdan parola veya MFA kodu istemesi
- Çoklu redirect kullanımı
- URL içinde kullanıcının email adresi veya token bulunması

---

### Attachment Analizi

Toplanacak bilgiler:

- attachment_name
- file extension
- file size
- attachment hash
- sandbox result
- macro/script davranışı
- child process bilgisi

Risk artıran uzantılar:

- .exe
- .scr
- .bat
- .cmd
- .js
- .vbs
- .ps1
- .hta
- .lnk
- .iso
- .img
- .docm
- .xlsm
- .zip
- .rar
- .7z

Risk artıran davranışlar:

- Makro çalıştırma
- PowerShell başlatma
- cmd başlatma
- wscript veya mshta başlatma
- Dış domain/IP bağlantısı
- Payload indirme
- Credential theft davranışı
- Persistence davranışı

---

### Kullanıcı Etkileşimi

Toplanacak bilgiler:

- user_clicked
- credentials_entered
- attachment_opened
- user_reported
- click_time
- click_source_ip
- click_device

Risk artıran durumlar:

- Kullanıcının linke tıklaması
- Kullanıcının credential girmesi
- Kullanıcının MFA kodu paylaşması
- Kullanıcının eki açması
- Tıklama sonrası suspicious login
- Eki açma sonrası endpoint alerti

Risk düşüren durumlar:

- Kullanıcının maili tıklamadan raporlaması
- Linke tıklama kaydı olmaması
- Credential girişi olmaması
- Attachment açılmamış olması
- Mailin quarantine veya block edilmiş olması

---

### Kapsam Analizi

Kontrol edilecekler:

- Aynı sender başka kullanıcılara mail atmış mı?
- Aynı subject başka mailboxlarda var mı?
- Aynı URL başka kullanıcılara gitmiş mi?
- Aynı attachment hash başka sistemlerde görülmüş mü?
- Aynı campaign_id altında başka e-postalar var mı?
- Başka kullanıcılar tıklamış mı?
- Başka kullanıcılar credential girmiş mi?

Risk artıran durumlar:

- Çok sayıda alıcı
- Birden fazla tıklama
- Birden fazla credential girişi
- Aynı IOC'lerin proxy, DNS, endpoint veya SIEM loglarında görülmesi
- Aynı mailin kurum içinde yayılmış kampanya olması

---

## Phishing ve False Positive Ayrımı

### Gerçek Phishing'e Benzeyen Durumlar

Aşağıdaki bulgular varsa olay phishing'e daha çok benzeyebilir:

- Bilinmeyen sender domain
- Display name ve sender email uyumsuzluğu
- Reply-to farklı domain
- SPF, DKIM veya DMARC fail
- Aciliyet veya tehdit dili
- Şifre sıfırlama veya hesap doğrulama teması
- Bilinmeyen link
- Sahte login sayfası
- Riskli attachment
- Kullanıcının linke tıklaması
- Kullanıcının credential girmesi
- Aynı mailin birçok kullanıcıya gitmesi
- URL veya attachment'ın malicious olarak işaretlenmesi

---

### False Positive Olabilecek Durumlar

Aşağıdaki durumlar saldırı dışı açıklama olabilir:

- Gerçek bir servis şifre sıfırlama maili göndermiş olabilir
- Kullanıcı beklediği bir belge paylaşımı almış olabilir
- Kurumsal üçüncü taraf servis farklı mail altyapısı kullanıyor olabilir
- SPF/DKIM/DMARC meşru serviste yanlış yapılandırılmış olabilir
- Link güvenlik kontrolü nedeniyle redirect içeriyor olabilir
- E-posta pazarlama veya otomasyon platformundan gelmiş olabilir
- Dosya eki normal iş sürecine ait olabilir
- Kullanıcı maili şüpheli sanmış ama mail meşru olabilir

---

## Severity Değerlendirme Mantığı

Severity sadece alertin verdiği seviyeye göre değil, kanıtlara göre değerlendirilmelidir.

### Düşük Risk

Şu durumlarda düşük risk düşünülebilir:

- Mail kullanıcıya ulaşmadan block veya quarantine edilmiş
- Kullanıcı tıklamamış
- Attachment açılmamış
- SPF/DKIM/DMARC sonuçları normal
- URL veya attachment zararlı görünmüyor
- Mail tek kullanıcıya gitmiş ve kullanıcı raporlamış

---

### Orta Risk

Şu durumlarda orta risk düşünülebilir:

- Mail kullanıcıya ulaşmış
- Link veya attachment var
- Kullanıcı etkileşimi bilinmiyor
- URL reputation belirsiz
- Sender domain tam güven vermiyor
- Ek kanıt gerekiyor

---

### Orta-Yüksek Risk

Şu durumlarda orta-yüksek risk düşünülebilir:

- Kullanıcı linke tıklamış
- Landing page login formu gösteriyor
- Credential girişi bilinmiyor
- Aynı mail başka kullanıcılara da gitmiş
- SPF/DKIM/DMARC sorunlu
- URL veya attachment suspicious görünüyor

---

### Yüksek Risk

Şu durumlarda yüksek risk düşünülebilir:

- Kullanıcı credential girmiş
- Kullanıcı MFA kodu paylaşmış
- Tıklama sonrası suspicious successful login var
- Attachment malicious olarak tespit edilmiş
- Eki açma sonrası endpointte suspicious process oluşmuş
- Aynı kampanya çok sayıda kullanıcıyı etkilemiş
- Finansal dolandırıcılık veya hesap ele geçirme şüphesi var

---

## SOC Analyst İçin Adım Adım Triage Planı

### Adım 1: E-postanın Teslim Durumunu Kontrol Et

Kontrol et:

- Mail delivered mı?
- Quarantine mı?
- Block edilmiş mi?
- Junk klasörüne mi gitmiş?
- Kaç kullanıcıya ulaşmış?

Amaç:

Kullanıcıların gerçekten risk altında olup olmadığını anlamak.

---

### Adım 2: Gönderen Bilgisini İncele

Kontrol et:

- sender_email
- sender_display_name
- reply_to
- return_path
- sender domain

Amaç:

Gönderenin meşru mu, taklit mi olduğunu anlamak.

---

### Adım 3: Email Authentication Sonuçlarını Kontrol Et

Kontrol et:

- SPF
- DKIM
- DMARC
- alignment

Amaç:

Mail spoofing veya domain taklidi ihtimalini değerlendirmek.

---

### Adım 4: Subject ve Body İçeriğini Değerlendir

Kontrol et:

- Aciliyet var mı?
- Tehdit dili var mı?
- Linke tıklama baskısı var mı?
- Credential isteniyor mu?
- Marka veya kurum taklidi var mı?

Amaç:

Sosyal mühendislik davranışını anlamak.

---

### Adım 5: Linkleri İncele

Kontrol et:

- Görünen link ile gerçek URL aynı mı?
- Domain güvenilir mi?
- URL shortener var mı?
- Landing page login formu mu?
- URL reputation sonucu ne?
- Redirect zinciri var mı?

Amaç:

Credential theft veya malicious link riskini değerlendirmek.

---

### Adım 6: Attachment Varsa İncele

Kontrol et:

- Dosya adı ve uzantısı
- Hash bilgisi
- Reputation sonucu
- Sandbox sonucu
- Macro veya script davranışı
- Attachment açıldıktan sonra endpointte process oluşmuş mu?

Amaç:

Zararlı dosya ihtimalini değerlendirmek.

---

### Adım 7: Kullanıcı Etkileşimini Kontrol Et

Kontrol et:

- Kullanıcı linke tıkladı mı?
- Kullanıcı credential girdi mi?
- Kullanıcı MFA kodu verdi mi?
- Kullanıcı eki açtı mı?
- Kullanıcı maili raporladı mı?

Amaç:

Olayın sadece mail seviyesinde mi kaldığını, yoksa kullanıcıyı etkileyip etkilemediğini anlamak.

---

### Adım 8: Tıklama Sonrası Logları İncele

Linke tıklama varsa kontrol et:

- Proxy logları
- DNS logları
- Browser veya endpoint logları
- Identity provider login logları
- MFA logları
- VPN veya cloud login logları

Amaç:

Tıklama sonrası hesap ele geçirme veya zararlı aktivite olup olmadığını anlamak.

---

### Adım 9: Attachment Açıldıysa Endpoint Loglarını İncele

Attachment açıldıysa kontrol et:

- Parent process
- Child process
- PowerShell/cmd/wscript/mshta çalışmış mı?
- Network connection oluşmuş mu?
- Dosya oluşturma veya indirme var mı?
- Endpoint güvenlik alerti oluşmuş mu?

Amaç:

Malware veya suspicious execution ihtimalini değerlendirmek.

---

### Adım 10: Kapsamı Belirle

Kontrol et:

- Aynı mail başka kimlere gitmiş?
- Aynı URL başka kullanıcılar tarafından açılmış mı?
- Aynı attachment başka endpointlerde görülmüş mü?
- Aynı sender başka kampanyalarda var mı?

Amaç:

Olayın tek kullanıcı mı, yoksa yaygın kampanya mı olduğunu anlamak.

---

### Adım 11: Olayı Sınıflandır

Olası sınıflandırmalar:

- Benign / meşru mail
- Spam
- Suspicious email
- Phishing attempt
- Credential phishing
- Malicious attachment
- Business email compromise suspicion
- Confirmed credential compromise
- Confirmed malware execution

Amaç:

Olayı doğru risk kategorisine koymak.

---

## Ne Zaman Incident'a Yükseltilir?

Aşağıdaki durumlarda olay incident olarak yükseltilmelidir:

- Kullanıcı credential girdiyse
- Kullanıcı MFA kodu girdiyse veya onayladıysa
- Tıklama sonrası şüpheli başarılı login oluştuysa
- Kullanıcı hesabında olağan dışı aktivite varsa
- Mailbox rule veya forwarding rule oluşturulduysa
- Attachment malicious olarak tespit edildiyse
- Attachment açıldıktan sonra endpointte suspicious process oluştuysa
- Aynı phishing maili çok sayıda kullanıcıya ulaştıysa
- Birden fazla kullanıcı linke tıkladıysa
- URL veya attachment hash malicious olarak işaretlendiyse
- Finansal işlem, fatura değişikliği veya veri sızıntısı şüphesi varsa
- Olay endpoint, identity veya network alertleriyle ilişkiliyse

---

## Önerilen İlk Müdahale Yaklaşımı

Bu playbook otomatik aksiyon önermek için değil, insan analiste güvenli triage rehberi vermek için kullanılır.

Temkinli ilk müdahale önerileri:

- Mail metadata bilgisini topla
- Link ve attachment göstergelerini çıkar
- Kullanıcı etkileşimini doğrula
- Aynı IOC'leri diğer loglarda ara
- Tıklama sonrası login aktivitelerini incele
- Attachment açıldıysa endpoint aktivitelerini kontrol et
- Etkilenen kullanıcı ve sistemleri belirle
- Eksik kanıtları not et
- Gerekirse incident response ekibine yükselt

Önerilmemesi gereken otomatik aksiyonlar:

- Kanıt olmadan otomatik hesap kapatma
- Kanıt olmadan otomatik IP veya domain engelleme
- Dosya silme
- Process sonlandırma
- Kullanıcı hesabında yıkıcı değişiklik yapma
- Doğrulanmamış IOC'leri kesin zararlı ilan etme

---

## Kullanıcıya Sorulabilecek Güvenli Sorular

Kullanıcı doğrulaması gerekiyorsa şu sorular sorulabilir:

- Bu e-postayı bekliyor muydunuz?
- Linke tıkladınız mı?
- Açılan sayfaya parola veya MFA kodu girdiniz mi?
- Eki açtınız mı?
- Eki açtıktan sonra bir uyarı veya garip davranış gördünüz mü?
- Bu e-postadaki göndericiyi tanıyor musunuz?
- Bu işlem normal iş sürecinizin parçası mıydı?

Amaç kullanıcıyı suçlamak değil, teknik kanıtları tamamlamaktır.

---

## Raporlama İçin Örnek Analist Notu

Örnek not:

Bu olayda kullanıcıya şüpheli bir e-posta gönderildiği görülmektedir. E-posta aciliyet teması ve bilinmeyen link içerdiği için phishing ihtimali değerlendirilmelidir. Kesin karar için sender bilgisi, SPF/DKIM/DMARC sonuçları, URL reputation, kullanıcı tıklama durumu ve credential girilip girilmediği kontrol edilmelidir. Kullanıcı etkileşimi veya tıklama sonrası suspicious login görülürse olay incident olarak yükseltilmelidir.

---

## Kullanılan MITRE ATT&CK Eşleşmesi

Bu playbook için ana MITRE eşleşmesi:

- T1566 - Phishing

İlgili olabilecek ek davranışlar:

- Credential phishing
- Malicious attachment
- Valid account abuse
- Initial access
- User execution

Bu ek davranışlar kesin olarak söylenmemeli, sadece kanıt varsa değerlendirilmelidir.

---

## Kısa Özet

Phishing alertinde en kritik nokta şudur:

E-postanın şüpheli olması tek başına incident anlamına gelmez. Kullanıcının linke tıklayıp tıklamadığı, credential girip girmediği, attachment açıp açmadığı ve aynı mailin başka kullanıcılara gidip gitmediği olayın riskini belirler.

SOC analyst önce mail metadata, link, attachment, kullanıcı etkileşimi ve kapsam bilgilerini toplamalıdır.