# T1566 - Phishing

## Kısa Açıklama

T1566 - Phishing, saldırganın kullanıcıyı kandırarak zararlı linke tıklatmaya, zararlı dosya açtırmaya veya kimlik bilgisi girdirmeye çalıştığı sosyal mühendislik tekniğidir.

Phishing saldırıları genellikle e-posta üzerinden görülür, ancak mesajlaşma uygulamaları, SMS, sosyal medya veya sahte bildirimler üzerinden de gerçekleşebilir.

SOC açısından phishing alerti tek başına kesin başarılı saldırı anlamına gelmez. Önemli olan şudur:

- E-posta kullanıcıya ulaştı mı?
- Kullanıcı linke tıkladı mı?
- Kullanıcı credential girdi mi?
- Kullanıcı attachment açtı mı?
- Tıklama veya dosya açma sonrası başka şüpheli aktivite oluştu mu?
- Aynı phishing mesajı başka kullanıcılara da gönderildi mi?

---

## SOC Açısından Neden Önemlidir?

Phishing, birçok siber saldırının başlangıç noktası olabilir.

Başarılı bir phishing olayı şu risklere yol açabilir:

- Kullanıcı hesabının ele geçirilmesi
- Parola veya MFA bilgisinin çalınması
- Zararlı dosya çalıştırılması
- Endpoint üzerinde suspicious process oluşması
- Mailbox rule veya forwarding rule eklenmesi
- Kurum içi başka kullanıcılara yayılım
- Finansal dolandırıcılık
- Veri sızıntısı
- VPN, cloud veya email hesabına yetkisiz erişim

SOC analyst için amaç, sadece mailin şüpheli olup olmadığını anlamak değildir. Asıl amaç şunu belirlemektir:

- Kullanıcı etkilendi mi?
- Hesap veya cihaz ele geçirilmiş olabilir mi?
- Olay tek kullanıcıyla mı sınırlı, yoksa kampanya mı?
- Hangi kanıtlar incident seviyesine yükseltmeyi destekliyor?

---

## Bu Teknik Ne Zaman Düşünülür?

Aşağıdaki durumlarda T1566 Phishing düşünülebilir:

- Kullanıcı şüpheli e-posta raporladıysa
- Mail acil aksiyon istiyorsa
- Mail şifre sıfırlama, hesap doğrulama veya güvenlik uyarısı teması içeriyorsa
- Mail bilinmeyen link içeriyorsa
- Mail kullanıcıdan parola, MFA kodu veya kişisel bilgi istiyorsa
- Gönderen adres güvenilir bir kurum gibi görünüp domain farklıysa
- Display name ile sender email uyumsuzsa
- Reply-to adresi farklı veya şüpheliyse
- SPF, DKIM veya DMARC sonuçları başarısızsa
- Ekte riskli dosya varsa
- Link sahte login sayfasına gidiyorsa
- Mail çok sayıda kullanıcıya gönderildiyse
- Kullanıcı tıkladıktan sonra suspicious login oluştuysa
- Attachment açıldıktan sonra endpoint alerti oluştuysa

---

## İlgili Alt Davranışlar

### Credential Phishing

Credential phishing, kullanıcının parola, MFA kodu veya oturum bilgisini çalmayı hedefler.

Tipik ipuçları:

- Password reset teması
- Account verification teması
- MFA verification teması
- Login required mesajı
- Session expired mesajı
- Hesabınız kilitlendi veya askıya alınacak uyarısı
- Sahte Microsoft, Google, banka, kargo veya kurum login sayfası

SOC açısından en kritik sorular:

- Kullanıcı linke tıkladı mı?
- Kullanıcı açılan sayfaya parola girdi mi?
- Kullanıcı MFA kodu veya push onayı verdi mi?
- Tıklama sonrası aynı kullanıcı hesabında başarılı login oluştu mu?
- Başarılı login normal IP, cihaz ve lokasyondan mı geldi?

---

### Spearphishing Link

Saldırgan, kullanıcıyı zararlı veya sahte bir linke tıklatmaya çalışır.

Tipik ipuçları:

- Bilinmeyen URL
- URL shortener
- Görünen link ile gerçek hedef URL'nin farklı olması
- Marka taklidi yapan domain
- Sahte login sayfası
- Kullanıcı email adresini URL parametresi içinde taşıyan link
- Çoklu redirect zinciri

Risk artar:

- Kullanıcı linke tıklarsa
- Link login formu gösterirse
- Kullanıcı credential girerse
- Tıklama sonrası suspicious login oluşursa

---

### Spearphishing Attachment

Saldırgan, kullanıcıyı zararlı ek dosya açmaya ikna etmeye çalışır.

Tipik ipuçları:

- Beklenmeyen attachment
- Fatura, ödeme, CV, teklif veya rapor teması
- Makro içeren Office dosyası
- Arşiv dosyası içinde çalıştırılabilir dosya
- Riskli dosya uzantıları
- Attachment açıldıktan sonra PowerShell, cmd, wscript veya mshta çalışması

Risk artar:

- Kullanıcı eki açarsa
- Attachment sandbox sonucunda malicious çıkarsa
- Endpointte suspicious process veya network connection oluşursa

---

### Business Email Compromise

Saldırgan, güvenilir kişi veya kurum taklidiyle para transferi, fatura değişikliği veya hassas bilgi istemeye çalışır.

Tipik ipuçları:

- CEO veya yönetici taklidi
- Finans veya muhasebe hedefi
- Tedarikçi taklidi
- Banka hesap bilgisinin değiştiği iddiası
- Acil ödeme isteği
- Gizlilik baskısı
- Normal iş sürecinden farklı talep

Risk artar:

- Finansal işlem yapıldıysa
- Hassas veri paylaşıldıysa
- Tedarikçi bilgisi değiştirildiyse
- Kullanıcı talebi doğrulamadan aksiyon aldıysa

---

## Tipik Kanıtlar

Phishing şüphesinde aranabilecek kanıtlar:

- suspicious email alert
- user reported email
- suspicious sender
- sender domain mismatch
- display name spoofing
- reply-to mismatch
- SPF fail
- DKIM fail
- DMARC fail
- urgent subject
- password reset subject
- unknown link
- suspicious URL
- URL shortener
- fake login page
- suspicious attachment
- malicious attachment hash
- sandbox malicious result
- user_clicked true
- credentials_entered true
- attachment_opened true
- suspicious login after click
- endpoint alert after attachment open
- same email sent to multiple users

---

## Risk Artıran Göstergeler

Aşağıdaki bulgular phishing riskini artırır:

- Bilinmeyen dış gönderen
- Display name ile sender email uyumsuzluğu
- Reply-to adresinin farklı domain olması
- SPF, DKIM veya DMARC fail
- Aciliyet, tehdit veya panik dili
- Şifre sıfırlama veya hesap doğrulama teması
- Bilinmeyen link
- URL shortener kullanımı
- Marka taklidi yapan domain
- Landing page üzerinde login formu
- Kullanıcıdan parola veya MFA kodu istenmesi
- Riskli attachment
- Attachment hash değerinin malicious çıkması
- Sandbox malicious sonucu
- Kullanıcının linke tıklaması
- Kullanıcının credential girmesi
- Kullanıcının eki açması
- Aynı mailin çok sayıda kullanıcıya gitmesi
- Tıklama sonrası suspicious successful login
- Attachment açılması sonrası suspicious PowerShell veya endpoint alerti

---

## Risk Düşüren veya False Positive Olabilecek Durumlar

Aşağıdaki durumlar saldırı dışı açıklama olabilir:

- Mail gerçek bir servis tarafından gönderilmiş olabilir
- Kullanıcı gerçekten beklediği bir belge paylaşımı almış olabilir
- Kurumsal üçüncü taraf servis farklı mail altyapısı kullanıyor olabilir
- SPF, DKIM veya DMARC bazı meşru servislerde yanlış yapılandırılmış olabilir
- URL güvenlik ürünü nedeniyle redirect içeriyor olabilir
- Mail pazarlama veya otomasyon platformundan gelmiş olabilir
- Attachment normal iş sürecine ait olabilir
- Kullanıcı maili şüpheli sanmış ancak tıklamamış olabilir
- Mail kullanıcıya ulaşmadan quarantine edilmiş olabilir
- Gateway maili block etmiş olabilir

Bu durumlar riski düşürebilir ancak tek başına güvenli olduğunu kanıtlamaz. Özellikle link, attachment ve kullanıcı etkileşimi yine kontrol edilmelidir.

---

## SOC Analyst İlk Neye Bakar?

SOC analyst ilk aşamada şu alanlara bakmalıdır:

1. Mail kullanıcıya ulaştı mı?
2. Gönderen kim?
3. Sender domain güvenilir mi?
4. Display name ve sender email uyumlu mu?
5. Reply-to farklı mı?
6. SPF, DKIM ve DMARC sonuçları ne?
7. Subject aciliyet veya sosyal mühendislik içeriyor mu?
8. Link var mı?
9. Linkin gerçek hedefi ne?
10. Attachment var mı?
11. Attachment uzantısı ve hash değeri ne?
12. Kullanıcı linke tıkladı mı?
13. Kullanıcı credential girdi mi?
14. Kullanıcı attachment açtı mı?
15. Aynı mail başka kullanıcılara da gitmiş mi?
16. Tıklama sonrası login veya endpoint alerti oluşmuş mu?

---

## İncelenecek Log Kaynakları

Phishing triage sırasında şu log kaynakları faydalı olabilir:

- Email security gateway logs
- Mailbox logs
- User reported email queue
- Message trace logs
- Email header information
- SPF/DKIM/DMARC results
- URL protection logs
- Proxy logs
- DNS logs
- Browser activity logs
- Identity provider logs
- Cloud login logs
- MFA logs
- Endpoint detection logs
- EDR telemetry
- Sandbox reports
- SIEM correlation logs

---

## Önemli Email Alanları

Aşağıdaki alanlar özellikle önemlidir:

- sender_email
- sender_display_name
- reply_to
- return_path
- recipient
- subject
- body_text
- url
- visible_link_text
- attachment_name
- attachment_hash
- spf_result
- dkim_result
- dmarc_result
- received_headers
- message_id
- user_clicked
- credentials_entered
- attachment_opened
- delivery_status
- campaign_id
- detection_source

Bu alanlar olmadan phishing olayı hakkında kesin yorum yapmak zordur.

---

## Link Varsa Özellikle Kontrol Edilecekler

E-postada link varsa şu kontroller yapılmalıdır:

- Link görünen metinle aynı hedefe mi gidiyor?
- Domain güvenilir mi?
- Domain marka taklidi yapıyor mu?
- URL shortener kullanılmış mı?
- Link IP adresiyle mi başlıyor?
- HTTPS var mı?
- Redirect zinciri var mı?
- Landing page login formu gösteriyor mu?
- Kullanıcıdan parola veya MFA kodu istiyor mu?
- URL reputation sonucu nedir?
- Kullanıcı bu linke tıklamış mı?
- Tıklama sonrası suspicious login oluşmuş mu?

---

## Attachment Varsa Özellikle Kontrol Edilecekler

E-postada attachment varsa şu kontroller yapılmalıdır:

- Dosya adı nedir?
- Dosya uzantısı nedir?
- Dosya beklenen iş sürecine ait mi?
- Dosyanın hash değeri var mı?
- Hash güvenlik araçlarında görülmüş mü?
- Sandbox sonucu nedir?
- Dosya makro veya script çalıştırıyor mu?
- Dosya PowerShell, cmd, wscript veya mshta başlatıyor mu?
- Dosya dış IP veya domaine bağlanıyor mu?
- Kullanıcı dosyayı açmış mı?
- Açıldıktan sonra endpoint alerti oluşmuş mu?

---

## Kullanıcı Etkileşimi Varsa Özellikle Kontrol Edilecekler

Kullanıcı linke tıkladıysa veya eki açtıysa olay daha dikkatli incelenmelidir.

Kontrol edilecekler:

- Tıklama zamanı
- Tıklanan URL
- Tıklama source IP
- Tıklama cihazı
- Açılan sayfa login formu mu?
- Kullanıcı credential girdi mi?
- Kullanıcı MFA kodu verdi mi?
- Tıklama sonrası login denemeleri
- Tıklama sonrası başarılı login
- Attachment açıldıysa parent process
- Attachment açıldıysa child process
- Endpointte suspicious process
- Endpointte network connection
- Aynı kullanıcıda başka alertler

---

## Olay Sınıflandırma Yaklaşımı

Bu teknikle ilişkili olaylar şu şekilde sınıflandırılabilir:

### Benign / Meşru Mail

Mail beklenen bir kaynaktan gelmiştir, link ve attachment güvenilirdir, kullanıcı etkileşimi riskli değildir.

### Spam

Mail istenmeyen veya düşük kaliteli mesajdır ancak credential theft, malicious link veya malicious attachment kanıtı yoktur.

### Suspicious Email

Mailde bazı şüpheli göstergeler vardır ancak malicious olduğuna dair yeterli kanıt yoktur.

### Phishing Attempt

Mail kullanıcıyı kandırmaya çalışıyor gibi görünmektedir. Link, attachment veya sosyal mühendislik göstergeleri vardır.

### Credential Phishing

Mail kullanıcıdan parola, MFA kodu veya login bilgisi almaya yöneliktir.

### Malicious Attachment

Attachment zararlı davranış gösterebilir veya sandbox/reputation sonucu şüphelidir.

### Business Email Compromise Suspicion

Mail finansal işlem, fatura değişikliği veya hassas bilgi talebi içerir.

### Confirmed Credential Compromise

Kullanıcı credential girmiştir veya tıklama sonrası şüpheli başarılı login kanıtı vardır.

### Confirmed Malware Execution

Attachment açıldıktan sonra endpointte zararlı veya şüpheli process/network davranışı görülmüştür.

---

## Incident'a Yükseltme Koşulları

Aşağıdaki bulgular varsa olay incident olarak yükseltilebilir:

- Kullanıcı credential girdiyse
- Kullanıcı MFA kodu girdiyse veya MFA onayı verdiyse
- Tıklama sonrası şüpheli başarılı login varsa
- Kullanıcı hesabında olağan dışı aktivite varsa
- Mailbox rule veya forwarding rule oluşturulduysa
- Attachment malicious olarak tespit edildiyse
- Attachment açıldıktan sonra PowerShell, cmd veya suspicious process oluştuysa
- Endpointte zararlı davranış veya dış bağlantı görülüyorsa
- Aynı phishing maili çok sayıda kullanıcıya ulaştıysa
- Birden fazla kullanıcı linke tıkladıysa
- URL veya attachment hash malicious olarak biliniyorsa
- Finansal işlem, veri sızıntısı veya hesap ele geçirme şüphesi varsa
- Olay identity, endpoint veya network alertleriyle ilişkiliyse

---

## Güven Düzeyi Değerlendirme Mantığı

### Düşük Güven

Şu durumlarda analiz güveni düşük olur:

- Sadece kullanıcı şüphesi vardır
- Link, attachment veya header bilgisi eksiktir
- Kullanıcı tıklama durumu bilinmiyordur
- SPF/DKIM/DMARC sonucu yoktur
- Ek kanıt yoktur

### Orta Güven

Şu durumlarda analiz güveni orta olabilir:

- Mail şüpheli içerik taşır
- Bilinmeyen link veya attachment vardır
- Kullanıcı etkileşimi bilinmiyordur
- URL veya attachment sonucu belirsizdir
- Ek kanıt gerekir

### Orta-Yüksek Güven

Şu durumlarda analiz güveni orta-yüksek olabilir:

- Mail sosyal mühendislik göstergeleri taşır
- Sender veya authentication sonuçları şüphelidir
- Link sahte login sayfasına benzer
- Kullanıcı tıklamış olabilir
- Ancak credential girişi veya post-click aktivite henüz bilinmiyordur

### Yüksek Güven

Şu durumlarda analiz güveni yüksek olabilir:

- Kullanıcı credential girmiştir
- Kullanıcı MFA kodu paylaşmıştır
- Tıklama sonrası şüpheli başarılı login vardır
- Attachment malicious çıkmıştır
- Attachment açıldıktan sonra endpointte suspicious execution vardır
- Aynı kampanya birden fazla kullanıcıyı etkilemiştir

---

## SOC Analyst İçin Güvenli Triage Notu

Bu teknik incelenirken otomatik yıkıcı aksiyon önerilmemelidir.

Önerilebilecek güvenli triage adımları:

- Mail metadata bilgisini topla
- Header ve authentication sonuçlarını incele
- Link ve attachment IOC'lerini çıkar
- Kullanıcı etkileşimini doğrula
- URL ve attachment reputation sonuçlarını değerlendir
- Aynı IOC'leri diğer loglarda ara
- Tıklama sonrası identity loglarını incele
- Attachment açıldıysa endpoint loglarını incele
- Kapsamı belirle
- Eksik kanıtları not et
- Olayı insan analiste veya incident response ekibine yükseltmeyi değerlendir

Önerilmemesi gerekenler:

- Kanıt olmadan otomatik hesap kapatma
- Kanıt olmadan otomatik IP/domain engelleme
- Dosya silme
- Process sonlandırma
- Kullanıcı hesabında yıkıcı değişiklik yapma
- Doğrulanmamış IOC'leri kesin zararlı ilan etme

---

## Kısa Özet

T1566 - Phishing, kullanıcıyı sosyal mühendislik yoluyla kandırmayı hedefleyen bir tekniktir.

Bu teknik özellikle şu kombinasyonlarda ciddi risk oluşturur:

- Şüpheli sender
- Acil veya tehdit içeren subject
- Bilinmeyen link
- Sahte login sayfası
- Riskli attachment
- Kullanıcının tıklaması
- Kullanıcının credential girmesi
- Tıklama sonrası suspicious login
- Attachment sonrası endpoint alerti
- Aynı mailin birçok kullanıcıya yayılması

Kesin saldırı kararı için mail header bilgileri, URL/attachment analizi, kullanıcı etkileşimi ve tıklama sonrası aktiviteler incelenmelidir.