# Email Investigation Fields

## Amaç

Bu dosya, phishing, suspicious email, credential theft, malicious link, malicious attachment ve business email compromise şüphesi olan e-posta olaylarında hangi alanlara bakılması gerektiğini açıklar.

Bir phishing alerti tek başına kesin saldırı anlamına gelmez. SOC analyst önce e-postanın teknik göstergelerini, kullanıcı etkileşimini, link veya ek davranışını ve kurum içindeki yayılımı incelemelidir.

Amaç, junior SOC analyst'in şu sorulara cevap bulmasını sağlamaktır:

- E-posta gerçekten şüpheli mi?
- Kullanıcı linke tıklamış mı?
- Kullanıcı kimlik bilgisi girmiş mi?
- Ekte zararlı dosya ihtimali var mı?
- Aynı e-posta başka kullanıcılara da gitmiş mi?
- Olay sadece spam mi, phishing mi, credential theft mi, yoksa daha ciddi incident mı?

---

## Temel Email Alanları

### sender_email

E-postayı gönderen görünen e-posta adresidir.

Kontrol soruları:
- Gönderen adres kurum içinden mi, dış kaynaktan mı?
- Domain bilinen ve güvenilir bir domain mi?
- Gönderen adres daha önce görülmüş mü?
- Gönderen adres gerçek kuruma benziyor ama küçük fark içeriyor mu?
- Adreste harf değişimi, fazla karakter veya sahte domain var mı?

Risk artıran durumlar:
- Bilinmeyen dış gönderen
- Markaya benzeyen ama farklı domain
- Yeni oluşturulmuş veya daha önce görülmemiş domain
- Free mail servisinden gelen kurumsal görünümlü mesaj
- Gönderen adresin reply-to adresiyle uyuşmaması

---

### sender_display_name

E-postada görünen gönderen adıdır.

Örnekler:
- IT Support
- Microsoft Security Team
- Human Resources
- Finance Department
- CEO
- Bank Notification

Kontrol soruları:
- Display name güvenilir bir kişi veya departman gibi mi görünüyor?
- Display name ile gerçek e-posta adresi uyumlu mu?
- Gönderen adı kurumdaki bir kişiyi taklit ediyor olabilir mi?
- Üst yönetim, IT veya finans taklidi var mı?

Risk artıran durumlar:
- Display name güvenilir görünüyor ama e-posta domaini farklı
- CEO, HR, IT, Security, Finance gibi güven uyandıran isimler kullanılması
- Kullanıcının hızlı aksiyon almasını hedefleyen isimlendirme

---

### reply_to

Kullanıcının cevap verdiğinde mesajın gideceği adrestir.

Kontrol soruları:
- Reply-to adresi sender_email ile aynı mı?
- Reply-to farklı ve bilinmeyen bir domain mi?
- Reply-to kişisel e-posta adresi mi?
- Reply-to adresi dış kaynak mı?

Risk artıran durumlar:
- Sender güvenilir görünürken reply-to farklı domain olması
- Reply-to adresinin ücretsiz mail servisinde olması
- Reply-to adresinin şüpheli veya yeni domain içermesi

---

### return_path

E-postanın teknik dönüş yolunu gösterir.

Kontrol soruları:
- Return-path sender ile uyumlu mu?
- Return-path domaini güvenilir mi?
- Return-path farklı bir altyapıya mı işaret ediyor?

Risk artıran durumlar:
- Sender ile return-path arasında uyumsuzluk
- Şüpheli mail altyapısı
- Beklenmeyen üçüncü taraf sistemlerden gönderim

---

### recipient

E-postanın gönderildiği kullanıcı veya kullanıcı grubudur.

Kontrol soruları:
- E-posta tek kullanıcıya mı gönderilmiş?
- Çok sayıda kullanıcıya mı gönderilmiş?
- Kritik departmanlar hedeflenmiş mi?
- Kullanıcı finans, insan kaynakları, IT veya yönetim gibi hassas rolde mi?

Risk artıran durumlar:
- Birden fazla çalışana aynı mesajın gitmesi
- Finans, HR, IT, yönetim gibi kritik ekiplerin hedeflenmesi
- Kurum içi dağıtım listelerine gönderim yapılması

---

### subject

E-postanın konu başlığıdır.

Kontrol soruları:
- Konu aciliyet hissi yaratıyor mu?
- Şifre sıfırlama, hesap kapanması, fatura, ödeme veya güvenlik uyarısı gibi ifadeler var mı?
- Kullanıcıyı linke tıklamaya veya ek açmaya zorluyor mu?
- Konu, bilinen bir servis veya marka taklidi yapıyor mu?

Risk artıran ifadeler:
- urgent
- password reset
- account locked
- verify your account
- invoice
- payment failed
- security alert
- action required
- final warning
- document shared
- MFA verification
- hesabınız askıya alındı
- parolanızı sıfırlayın
- acil işlem gerekli

---

### body_text

E-posta gövdesindeki yazılı içeriktir.

Kontrol soruları:
- Kullanıcıdan acil aksiyon isteniyor mu?
- Linke tıklaması isteniyor mu?
- Kimlik bilgisi girmesi isteniyor mu?
- Dil bilgisi hataları veya garip ifadeler var mı?
- Tehdit, ödül, panik veya otorite baskısı kullanılmış mı?
- Mesaj kurum içi yazışma tarzına uyuyor mu?

Risk artıran durumlar:
- Acil işlem baskısı
- Hesap kapanacak tehdidi
- Kullanıcıdan parola, MFA kodu veya kişisel bilgi istemesi
- Linke tıklamadan sorunun çözülemeyeceğini söylemesi
- Beklenmeyen dosya veya belge paylaşımı

---

## Link ve URL Alanları

### url

E-posta içindeki bağlantıdır.

Kontrol soruları:
- URL görünen metinle aynı yere mi gidiyor?
- Domain güvenilir mi?
- Domain gerçek servise benziyor ama farklı mı?
- URL kısa link servisi kullanıyor mu?
- URL içinde rastgele karakterler, encoded parametreler veya redirect var mı?
- URL login sayfasına mı yönlendiriyor?
- URL dosya indirme bağlantısı mı?

Risk artıran durumlar:
- Bilinmeyen domain
- Marka taklidi yapan domain
- URL shortener kullanımı
- Şüpheli redirect zinciri
- Login formu içeren sayfa
- Kullanıcı adı veya email parametresi içeren link
- IP adresiyle başlayan URL
- HTTPS olmaması
- Yeni kayıt edilmiş domain

---

### visible_link_text

Kullanıcının e-postada gördüğü link yazısıdır.

Örnekler:
- Reset Password
- View Document
- Verify Account
- Download Invoice
- Click Here
- Güvenlik doğrulaması yap

Kontrol soruları:
- Görünen link güvenilir bir servis gibi mi görünüyor?
- Gerçek URL ile görünen link uyumlu mu?
- Kullanıcıyı kandıracak şekilde mi yazılmış?

Risk artıran durumlar:
- Görünen link microsoft.com gibi dururken gerçek URL farklı domain olması
- “Click here” gibi belirsiz link metinleri
- Şifre sıfırlama veya hesap doğrulama temalı linkler

---

### url_reputation

URL veya domain hakkında güvenlik araçlarından gelen itibar bilgisidir.

Kontrol soruları:
- URL daha önce zararlı olarak işaretlenmiş mi?
- Domain yeni mi?
- Domain daha önce phishing kampanyalarında görülmüş mü?
- Güvenlik ürünleri URL'yi blocked, suspicious veya malicious olarak işaretlemiş mi?

Risk artıran durumlar:
- Malicious veya phishing kategorisi
- Yeni domain
- Düşük reputation
- Çok sayıda redirect
- Bilinmeyen hosting sağlayıcısı

---

### landing_page_behavior

Link açıldığında kullanıcıyı götürdüğü sayfanın davranışıdır.

Kontrol soruları:
- Sayfa login formu gösteriyor mu?
- Kurumsal veya bilinen servis taklidi var mı?
- Kullanıcıdan parola, MFA kodu veya kişisel bilgi istiyor mu?
- Dosya indirtiyor mu?
- Tarayıcı exploit veya zararlı script davranışı var mı?
- Sayfa artık erişilemiyor mu?

Risk artıran durumlar:
- Sahte Microsoft, Google, banka veya kurum login sayfası
- Parola veya MFA kodu isteyen form
- Dosya indirme başlatması
- Çoklu redirect
- Kullanıcı email bilgisini URL içinde hazır göstermesi

---

## Attachment Alanları

### attachment_name

E-postaya eklenen dosya adıdır.

Kontrol soruları:
- Dosya beklenen bir dosya mı?
- Dosya adı kullanıcıyı açmaya teşvik ediyor mu?
- Fatura, ödeme, CV, teklif, rapor gibi sosyal mühendislik teması var mı?
- Dosya uzantısı riskli mi?

Riskli uzantı örnekleri:
- .exe
- .scr
- .bat
- .cmd
- .js
- .vbs
- .ps1
- .iso
- .img
- .lnk
- .hta
- .docm
- .xlsm
- .zip
- .rar
- .7z

Risk artıran durumlar:
- Beklenmeyen ek
- Makro içeren Office dosyası
- Arşiv dosyası içinde çalıştırılabilir dosya
- Dosya adının çift uzantılı olması
- Dosya adının kullanıcıyı acele ettirmesi

---

### attachment_hash

Dosya ekinin hash bilgisidir.

Örnekler:
- SHA256
- SHA1
- MD5

Kontrol soruları:
- Hash güvenlik araçlarında zararlı olarak görülmüş mü?
- Hash daha önce kurumda görülmüş mü?
- Aynı hash başka kullanıcılara gelen e-postalarda da var mı?

Risk artıran durumlar:
- Hash malicious olarak işaretlenmişse
- Aynı zararlı ekin birçok kullanıcıya gitmesi
- Hash'in daha önce bilinen kampanyalarla ilişkili olması

---

### attachment_sandbox_result

Ekin sandbox veya analiz sonucu bilgisidir.

Kontrol soruları:
- Dosya çalıştırıldığında network bağlantısı kuruyor mu?
- Makro veya script çalıştırıyor mu?
- PowerShell, cmd veya wscript başlatıyor mu?
- Persistence veya credential access davranışı var mı?
- Dosya zararlı davranış göstermiş mi?

Risk artıran durumlar:
- Makro çalıştırma
- PowerShell veya cmd başlatma
- Şüpheli domain/IP bağlantısı
- Credential theft davranışı
- Dosya indirme veya payload çekme

---

## Authentication ve Header Alanları

### spf_result

Sender Policy Framework sonucudur.

Örnek değerler:
- pass
- fail
- softfail
- neutral
- none

Kontrol soruları:
- SPF pass mi fail mi?
- Gönderen IP domain adına yetkili mi?
- SPF fail varsa gönderici sahte olabilir mi?

Risk artıran durumlar:
- SPF fail
- SPF softfail
- SPF none ve dış domain
- Sender domainiyle gönderici altyapının uyumsuz olması

---

### dkim_result

DomainKeys Identified Mail sonucudur.

Örnek değerler:
- pass
- fail
- none

Kontrol soruları:
- DKIM imzası geçerli mi?
- DKIM domaini sender domain ile uyumlu mu?
- DKIM yoksa bu domain için normal mi?

Risk artıran durumlar:
- DKIM fail
- DKIM none ve şüpheli sender
- DKIM domain uyumsuzluğu

---

### dmarc_result

DMARC sonucudur.

Örnek değerler:
- pass
- fail
- none

Kontrol soruları:
- DMARC pass mi fail mi?
- SPF veya DKIM ile alignment var mı?
- DMARC fail varsa mail spoofing ihtimali var mı?

Risk artıran durumlar:
- DMARC fail
- Kurumsal marka taklidiyle gelen DMARC fail sonucu
- Sender domain spoofing ihtimali

---

### received_headers

E-postanın geçtiği mail sunucularını gösteren header zinciridir.

Kontrol soruları:
- Mail beklenen mail altyapısından mı gelmiş?
- Arada bilinmeyen veya şüpheli mail sunucuları var mı?
- İlk gönderen IP güvenilir mi?
- Header zincirinde tutarsızlık var mı?

Risk artıran durumlar:
- Şüpheli ilk hop
- Beklenmeyen ülke veya hosting IP'si
- Header manipulation izlenimi
- Sender ile mail altyapısının uyuşmaması

---

### message_id

E-postanın benzersiz mesaj kimliğidir.

Kontrol soruları:
- Message-ID domaini sender domain ile uyumlu mu?
- Aynı Message-ID başka mailboxlarda var mı?
- Message-ID formatı normal mi?

Risk artıran durumlar:
- Message-ID'nin şüpheli domain içermesi
- Aynı mesajın çok kullanıcıya yayılması
- Message-ID formatının garip olması

---

## Kullanıcı Etkileşimi Alanları

### user_clicked

Kullanıcının e-postadaki linke tıklayıp tıklamadığını gösterir.

Örnek değerler:
- true
- false
- unknown

Kontrol soruları:
- Kullanıcı linke tıklamış mı?
- Tıklama zamanı nedir?
- Tıklama hangi cihazdan ve IP'den yapılmış?
- Tıklama sonrası login denemesi veya endpoint alerti oluşmuş mu?

Risk artıran durumlar:
- Kullanıcının linke tıklaması
- Tıklama sonrası credential entry
- Tıklama sonrası endpoint alerti
- Tıklama sonrası şüpheli login

---

### credentials_entered

Kullanıcının sahte sayfaya kimlik bilgisi girip girmediğini gösterir.

Örnek değerler:
- true
- false
- unknown

Kontrol soruları:
- Kullanıcı parola veya MFA kodu girmiş mi?
- Form submission logu var mı?
- Tıklama sonrası aynı kullanıcı hesabıyla başarısız veya başarılı login denemeleri oluşmuş mu?
- Kullanıcı bunu doğruluyor mu?

Risk artıran durumlar:
- Kullanıcının parola girdiğini doğrulaması
- Tıklama sonrası farklı lokasyondan login
- MFA push denemeleri
- Hesapla olağan dışı aktivite

---

### attachment_opened

Kullanıcının e-posta ekini açıp açmadığını gösterir.

Kontrol soruları:
- Kullanıcı eki açmış mı?
- Ek açıldıktan sonra endpointte yeni process oluşmuş mu?
- Office dosyası makro çalıştırmış mı?
- PowerShell, cmd, wscript veya mshta başlatılmış mı?

Risk artıran durumlar:
- Ekin açılması sonrası PowerShell/cmd çalışması
- Endpoint alert oluşması
- Dosya indirme veya dış bağlantı
- Credential dump veya persistence davranışı

---

### user_reported

Kullanıcının e-postayı şüpheli olarak raporlayıp raporlamadığını gösterir.

Kontrol soruları:
- Kullanıcı maili kendi mi raporladı?
- Kullanıcı herhangi bir aksiyon aldı mı?
- Kullanıcı linke tıklamadan mı raporladı?
- Kullanıcı bilgilerini paylaştı mı?

Risk düşüren durumlar:
- Kullanıcının tıklamadan raporlaması
- Kullanıcının ek açmadığını doğrulaması
- Mail gateway tarafından zaten karantinaya alınmış olması

---

## Delivery ve Mail Gateway Alanları

### delivery_status

E-postanın kullanıcı mailboxına ulaşıp ulaşmadığını gösterir.

Örnek değerler:
- delivered
- quarantined
- blocked
- junk
- removed
- pending

Kontrol soruları:
- Mail kullanıcıya ulaşmış mı?
- Gateway maili karantinaya almış mı?
- Mail sonradan mailboxlardan kaldırılmış mı?
- Kaç kullanıcıya teslim edilmiş?

Risk artıran durumlar:
- Mailin çok sayıda kullanıcıya teslim edilmesi
- Mailin filtrelerden geçip inboxa düşmesi
- Kullanıcıların linke tıklamış olması

Risk düşüren durumlar:
- Mailin karantinaya alınması
- Mailin kullanıcıya ulaşmadan engellenmesi
- Mailboxlardan başarıyla kaldırılmış olması

---

### detection_source

Alertin hangi sistem tarafından üretildiğini gösterir.

Örnekler:
- Email Security Gateway
- Microsoft Defender for Office
- Google Workspace Alert
- SIEM
- User Report
- SOAR
- Sandbox

Kontrol soruları:
- Alert otomatik güvenlik sistemi tarafından mı geldi?
- Kullanıcı raporu mu?
- Gateway hangi nedeni göstermiş?
- SIEM başka loglarla korelasyon yapmış mı?

Risk artıran durumlar:
- Birden fazla güvenlik aracının aynı maili şüpheli görmesi
- Sandbox malicious sonucu
- User click + suspicious login korelasyonu

---

### campaign_id

Aynı phishing kampanyasına ait e-postaları gruplamak için kullanılan alandır.

Kontrol soruları:
- Bu mail tekil mi yoksa kampanya parçası mı?
- Aynı sender, subject, URL veya attachment başka kullanıcılarda var mı?
- Kampanya kurum içinde yayılmış mı?

Risk artıran durumlar:
- Çok sayıda alıcı
- Aynı URL veya ekin birçok kullanıcıya gitmesi
- Birden fazla kullanıcının tıklaması

---

## IOC Alanları

Phishing olaylarında çıkarılabilecek IOC'ler:

- sender_email
- sender_domain
- reply_to
- return_path
- source sending IP
- URL
- landing page domain
- redirect domainleri
- attachment hash
- attachment filename
- message_id
- subject
- IP adresleri
- sandbox bağlantıları

Kontrol soruları:
- IOC'ler başka loglarda görülüyor mu?
- Aynı domain veya URL firewall/proxy loglarında var mı?
- Aynı hash endpointlerde görülmüş mü?
- Aynı sender başka kullanıcılara mail atmış mı?

---

## SOC Analyst İçin Temel Kontrol Mantığı

Bir phishing alerti incelenirken şu sırayla düşünülmelidir:

1. E-posta kullanıcıya ulaştı mı?
2. Gönderen adres ve display name güvenilir mi?
3. Reply-to ve return-path sender ile uyumlu mu?
4. SPF, DKIM ve DMARC sonuçları ne?
5. Subject aciliyet veya sosyal mühendislik içeriyor mu?
6. Mail gövdesinde link veya ek var mı?
7. Linkin gerçek domaini güvenilir mi?
8. URL reputation sonucu nedir?
9. Ek varsa dosya türü, hash ve sandbox sonucu nedir?
10. Kullanıcı linke tıklamış mı?
11. Kullanıcı kimlik bilgisi girmiş mi?
12. Kullanıcı eki açmış mı?
13. Aynı mail başka kullanıcılara da gitmiş mi?
14. Aynı URL, domain veya hash başka loglarda görülmüş mü?
15. Tıklama sonrası suspicious login, MFA alerti veya endpoint alerti oluşmuş mu?
16. Olay spam seviyesinde mi, phishing mi, credential theft mı, yoksa incident mı?

---

## False Positive İhtimalleri

Bu tür alertler şu nedenlerle saldırı olmadan da oluşabilir:

- Gerçek bir servis şifre sıfırlama maili göndermiş olabilir.
- Kullanıcı gerçekten beklediği bir belge paylaşımı almış olabilir.
- Kurumsal üçüncü taraf servisler farklı mail altyapısı kullanıyor olabilir.
- SPF/DKIM/DMARC bazı meşru servislerde yanlış yapılandırılmış olabilir.
- Link güvenlik kontrolü nedeniyle redirect içeriyor olabilir.
- E-posta pazarlama veya otomasyon aracı kullanılmış olabilir.
- Kullanıcı maili şüpheli sanmış ama mail meşru olabilir.
- Dosya eki beklenen iş sürecine ait olabilir.

---

## Risk Artıran Göstergeler

Aşağıdaki bulgular phishing riskini artırır:

- Acil aksiyon isteyen subject
- Şifre sıfırlama veya hesap doğrulama teması
- Bilinmeyen sender domain
- Display name ile sender adresinin uyumsuz olması
- Reply-to adresinin farklı olması
- SPF, DKIM veya DMARC fail
- Bilinmeyen veya yeni domain içeren link
- URL shortener kullanımı
- Sahte login sayfası
- Kullanıcının linke tıklaması
- Kullanıcının credential girmesi
- Riskli attachment
- Sandbox malicious sonucu
- Aynı mailin birçok kullanıcıya gönderilmesi
- Tıklama sonrası suspicious login
- Tıklama sonrası endpoint alerti

---

## Incident'a Yükseltme Göstergeleri

Aşağıdaki bulgular görülürse olay incident olarak yükseltilebilir:

- Kullanıcı kimlik bilgisi girdiyse
- Kullanıcı MFA kodu girdiyse
- Tıklama sonrası şüpheli başarılı login görüldüyse
- Ekte zararlı dosya tespit edildiyse
- Ek açıldıktan sonra endpointte PowerShell, cmd veya zararlı process oluştuysa
- Aynı phishing maili çok sayıda kullanıcıya ulaştıysa
- Birden fazla kullanıcı linke tıkladıysa
- Mail güvenlik ürünleri tarafından malicious olarak işaretlendiyse
- URL veya attachment hash zararlı olarak biliniyorsa
- Kullanıcı hesabında mailbox rule, forwarding rule veya olağan dışı aktivite oluştuysa
- Finansal işlem, veri sızıntısı veya yetki kötüye kullanımı şüphesi varsa

---

## Önerilen İlk Triage Yaklaşımı

İlk aşamada SOC analyst şu güvenli ve temkinli adımları izlemelidir:

1. E-postanın başlık, gönderen, alıcı, link ve ek bilgilerini topla.
2. Mailin kullanıcıya ulaşıp ulaşmadığını kontrol et.
3. Kullanıcı etkileşimini kontrol et: tıklama, credential girişi, ek açma.
4. Link ve ekleri reputation/sandbox sonuçlarıyla değerlendir.
5. Aynı IOC'lerin başka kullanıcı veya sistemlerde görülüp görülmediğini ara.
6. Tıklama sonrası login ve endpoint loglarını incele.
7. Eksik kanıtları not et.
8. Olayı spam, phishing, credential theft veya incident adayı olarak sınıflandır.
9. Gerekirse insan analiste veya incident response ekibine yükselt.

Otomatik hesap kapatma, otomatik IP engelleme, dosya silme veya yıkıcı müdahale önerilmemelidir. Önce kanıtlar doğrulanmalıdır.

---

## Kısa Özet

Phishing incelemesinde en kritik sorular şunlardır:

- Mail kime geldi?
- Gönderen gerçekten güvenilir mi?
- Link veya ek var mı?
- Kullanıcı tıkladı mı?
- Kullanıcı credential girdi mi?
- Ekte zararlı dosya var mı?
- Aynı mail başka kullanıcılara da gitmiş mi?
- Tıklama sonrası suspicious login veya endpoint alerti oluştu mu?

Bu sorulara cevap verilmeden olay kesin saldırı olarak değerlendirilmemelidir.