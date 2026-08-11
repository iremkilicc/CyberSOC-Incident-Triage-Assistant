# T1110 - Brute Force

## Kısa Açıklama

T1110 - Brute Force, saldırganın geçerli kullanıcı adı, parola veya kimlik doğrulama bilgisini bulmak için tekrar eden giriş denemeleri yapmasıdır.

Bu davranış login sistemlerinde, VPN girişlerinde, SSH, RDP, web uygulamaları, email portalları, cloud panelleri ve diğer authentication noktalarında görülebilir.

Brute force davranışı tek başına kesin hesap ele geçirilmesi anlamına gelmez. Ancak kısa sürede çok sayıda başarısız giriş denemesi, kritik hesapların hedeflenmesi ve başarısız denemelerden sonra başarılı login görülmesi ciddi risk oluşturur.

---

## SOC Açısından Neden Önemlidir?

Brute force saldırıları genellikle şu risklere yol açabilir:

- Geçerli kullanıcı hesabının ele geçirilmesi
- VPN veya uzak erişim sistemine yetkisiz giriş
- Privileged account kullanım riski
- İç ağa ilk erişim ihtimali
- Kimlik bilgisi deneme kampanyası
- Password spraying veya credential stuffing davranışı
- Başarılı login sonrası lateral movement veya veri erişimi riski

SOC analyst için amaç, sadece başarısız deneme sayısına bakmak değildir. Asıl amaç şunu anlamaktır:

- Denemeler normal kullanıcı hatası mı?
- Yanlış yapılandırılmış servis mi?
- Parola tahmin saldırısı mı?
- Başarılı giriş gerçekten kullanıcıya mı ait?
- Başarılı giriş sonrası şüpheli hareket var mı?

---

## Bu Teknik Ne Zaman Düşünülür?

Aşağıdaki durumlarda T1110 Brute Force düşünülebilir:

- Kısa sürede çok sayıda başarısız giriş denemesi varsa
- Aynı kullanıcıya tekrar tekrar parola deneniyorsa
- Aynı source IP adresi birden fazla kullanıcı hesabını deniyorsa
- Başarısız giriş denemelerinden sonra başarılı giriş oluşuyorsa
- Kritik kullanıcı hesapları hedefleniyorsa
- Admin, root, domain admin veya privileged account hedefleniyorsa
- VPN, RDP, SSH, email portal veya web login üzerinde tekrar eden denemeler varsa
- Mesai dışında olağan dışı login denemeleri görülüyorsa
- MFA başarısızlıkları login denemeleriyle beraber görülüyorsa
- Aynı parola birçok kullanıcıda denenmiş gibi görünüyorsa
- Kullanıcı normal lokasyonundan farklı bir yerden deneniyorsa

---

## İlgili Alt Davranışlar

### Password Guessing

Saldırganın tek veya birkaç kullanıcı hesabı üzerinde tahmin edilebilir parolaları denemesidir.

SOC açısından ipuçları:

- Aynı kullanıcıda çok sayıda başarısız deneme
- Kısa zaman aralığında tekrar eden login hataları
- Başarısız denemelerden sonra başarılı giriş
- Kullanıcının kritik hesap olması
- Source IP'nin bilinmeyen veya şüpheli olması

---

### Password Spraying

Saldırganın aynı parolayı veya az sayıda parolayı birçok kullanıcı hesabında denemesidir.

SOC açısından ipuçları:

- Birden fazla kullanıcı hedeflenir
- Her kullanıcıda az sayıda başarısız deneme olabilir
- Account lockout tetiklenmemesi için denemeler yavaş yapılabilir
- Aynı source IP veya benzer IP aralığı birçok hesabı deneyebilir
- Çok sayıda kullanıcıda benzer failure_reason görülebilir

---

### Credential Stuffing

Saldırganın başka veri sızıntılarından elde edilmiş kullanıcı adı/parola çiftlerini denemesidir.

SOC açısından ipuçları:

- Çok sayıda kullanıcı hesabı hedeflenebilir
- Bazı hesaplarda hızlı başarılı login görülebilir
- Denemeler farklı IP adreslerinden gelebilir
- Kullanıcılar aynı parolayı başka servislerde kullanmış olabilir
- Başarılı login sonrası olağan dışı aktiviteler görülebilir

---

### Valid Account Abuse

Başarısız denemelerden sonra başarılı login varsa, geçerli hesap kullanımı ihtimali değerlendirilmelidir.

SOC açısından sorulacak sorular:

- Başarılı giriş kullanıcının normal davranışına uyuyor mu?
- Source IP kullanıcı için normal mi?
- Başarılı giriş sonrası ne yapılmış?
- Kullanıcı bu girişi kendisinin yaptığını doğruluyor mu?
- MFA onayı kullanıcı tarafından mı verilmiş?

---

## Tipik Kanıtlar

Brute force veya password guessing şüphesinde aranabilecek kanıtlar:

- failed_login kayıtları
- repeated authentication failure
- aynı source_ip bilgisinin tekrar etmesi
- aynı user alanının tekrar etmesi
- kısa time_window içinde çok sayıda deneme
- failed_attempt_count değerinin yüksek olması
- successful_login_after_failures bilgisi
- VPN, RDP, SSH veya web login üzerinde tekrar eden başarısız denemeler
- failure_reason olarak wrong password tekrarları
- account lockout olayları
- MFA failed veya MFA denied kayıtları
- aynı IP'nin başka hesapları da denemesi
- olağan dışı lokasyon veya yeni cihaz bilgisi
- başarılı login sonrası şüpheli işlem

---

## Risk Artıran Göstergeler

Aşağıdaki bulgular olayın riskini artırır:

- Hedef hesabın admin veya privileged account olması
- Hedef sistemin VPN gateway, firewall, domain controller veya cloud admin panel olması
- Başarısız denemelerden sonra başarılı login görülmesi
- Başarılı loginin aynı source IP üzerinden yapılması
- Source IP'nin daha önce kullanıcı için görülmemiş olması
- Aynı IP'nin farklı kullanıcı hesaplarını da denemesi
- Denemelerin mesai dışında gerçekleşmesi
- MFA başarısızlıkları veya şüpheli MFA onayı
- Kullanıcının login denemelerini kendisinin yapmadığını söylemesi
- Başarılı login sonrası yetki değişikliği, veri erişimi veya güvenlik ayarı değişikliği
- Aynı zaman aralığında endpoint, email veya network alertleri görülmesi

---

## Risk Düşüren veya False Positive Olabilecek Durumlar

Aşağıdaki durumlar saldırı dışı açıklama olabilir:

- Kullanıcı şifresini unutmuş olabilir
- Kullanıcı birkaç kez yanlış yazıp sonra doğru şifreyle giriş yapmış olabilir
- VPN istemcisi eski şifreyle otomatik giriş deniyor olabilir
- Mobil cihaz eski kimlik bilgileriyle tekrar tekrar authentication denemesi yapıyor olabilir
- Yanlış yapılandırılmış servis hesabı login hatası üretiyor olabilir
- Kullanıcı parola değiştirdikten sonra eski oturumlar başarısız deneme üretiyor olabilir
- SSO veya authentication servisinde geçici hata olabilir
- Kullanıcı yeni cihaz veya yeni lokasyondan meşru giriş yapmış olabilir
- Account lockout politikası nedeniyle çok sayıda log oluşmuş olabilir

---

## SOC Analyst İlk Neye Bakar?

SOC analyst ilk aşamada şu alanlara bakmalıdır:

1. Başarılı giriş var mı?
2. Başarılı giriş olduysa sonrasında ne yapılmış?
3. Kaynak IP başka hesapları da denemiş mi?
4. Hedef kullanıcı kritik veya yetkili hesap mı?
5. Login denemeleri kısa zaman aralığında mı olmuş?
6. Source IP daha önce kullanıcı için görülmüş mü?
7. MFA aktif mi ve MFA sonucu nedir?
8. Kullanıcı normalde bu sistemden giriş yapar mı?
9. Giriş normal cihaz, saat ve lokasyonla uyumlu mu?
10. Aynı zaman aralığında başka alertler var mı?

---

## İncelenecek Log Kaynakları

Brute force triage sırasında şu log kaynakları faydalı olabilir:

- Authentication logs
- VPN logs
- Firewall logs
- Identity provider logs
- Active Directory logs
- Cloud identity logs
- RDP veya SSH login logs
- Web application login logs
- MFA logs
- SIEM correlation logs
- Endpoint activity logs
- EDR telemetry
- Proxy veya network logs

---

## Önemli Log Alanları

Aşağıdaki alanlar özellikle önemlidir:

- user
- source_ip
- destination_system
- timestamp
- login_status
- failed_attempt_count
- success_after_failures
- failure_reason
- mfa_status
- user_agent
- device_id
- hostname
- geo_location
- auth_method
- session_id
- account_lockout_status

Bu alanlar olmadan olay hakkında kesin yorum yapmak zordur.

---

## Başarılı Login Varsa Özellikle Kontrol Edilecekler

Başarısız denemelerden sonra başarılı login varsa olay daha dikkatli incelenmelidir.

Kontrol edilmesi gerekenler:

- Başarılı login hangi IP'den geldi?
- Başarılı login başarısız denemelerden hemen sonra mı oldu?
- Başarılı login normal cihazdan mı yapıldı?
- Başarılı login normal lokasyondan mı yapıldı?
- Kullanıcı bu loginin kendisine ait olduğunu doğruluyor mu?
- Başarılı login sonrası hangi sistemlere erişildi?
- Parola veya MFA ayarı değiştirildi mi?
- Yetki değişikliği yapıldı mı?
- Mailbox rule veya forwarding rule oluşturuldu mu?
- VPN sonrası iç ağda bağlantı yapıldı mı?
- Hassas dosya veya veri erişimi var mı?

---

## Olay Sınıflandırma Yaklaşımı

Bu teknikle ilişkili olaylar şu şekilde sınıflandırılabilir:

### False Positive / Kullanıcı Hatası

Kullanıcı yanlış parola denemiş ve sonra doğru giriş yapmış olabilir. Source IP, cihaz, lokasyon ve kullanıcı doğrulaması normaldir.

### Misconfigured Service or Device

Bir servis, cihaz veya VPN client eski şifreyle tekrar tekrar giriş deniyor olabilir.

### Brute Force Attempt

Aynı kullanıcıya çok sayıda parola denenmiştir. Başarılı login olmayabilir.

### Password Spraying

Aynı source IP veya benzer kaynaklar birçok kullanıcıyı az sayıda denemiştir.

### Credential Stuffing

Birden fazla kullanıcı hesabında sızdırılmış olabilecek credential kombinasyonları denenmiştir.

### Suspicious Successful Login

Başarısız denemelerden sonra başarılı login vardır ancak henüz hesap ele geçirme kesin değildir.

### Confirmed Account Compromise

Kullanıcı başarılı girişi reddeder veya başarılı login sonrası şüpheli aktivite görülür.

---

## Incident'a Yükseltme Koşulları

Aşağıdaki bulgular varsa olay incident olarak yükseltilebilir:

- Başarısız denemelerden sonra başarılı login varsa ve kullanıcı bunu reddediyorsa
- Admin veya privileged account için başarılı login varsa
- Başarılı login sonrası şüpheli aktivite görülüyorsa
- MFA bypass, MFA fatigue veya onaylanmamış MFA kabulü varsa
- Aynı IP birçok kullanıcıyı denemişse
- Hassas sisteme erişim gerçekleşmişse
- Parola, MFA, mailbox rule veya security setting değiştirilmişse
- Veri erişimi, veri indirme veya olağan dışı network bağlantısı varsa
- Aynı olay başka endpoint veya email alertleriyle ilişkiliyse
- Birden fazla kullanıcı etkilenmişse

---

## Güven Düzeyi Değerlendirme Mantığı

### Düşük Güven

Şu durumlarda analiz güveni düşük olur:

- Sadece birkaç başarısız login vardır
- Source IP bilgisi eksiktir
- Başarılı login olup olmadığı bilinmiyordur
- Kullanıcı veya MFA bilgisi yoktur
- Ek kanıt yoktur

### Orta Güven

Şu durumlarda analiz güveni orta olabilir:

- Çok sayıda başarısız login vardır
- Source IP ve kullanıcı bilgisi vardır
- Başarılı login yoktur veya belirsizdir
- MFA ve post-login aktivite bilgisi eksiktir

### Orta-Yüksek Güven

Şu durumlarda analiz güveni orta-yüksek olabilir:

- Kısa sürede çok sayıda başarısız login vardır
- Kritik hesap hedeflenmiştir
- VPN veya dış erişim sistemi hedeflenmiştir
- Başarısız denemelerden sonra başarılı login vardır
- Ancak başarılı login sonrası aktiviteler henüz bilinmiyordur

### Yüksek Güven

Şu durumlarda analiz güveni yüksek olabilir:

- Kullanıcı başarılı girişi reddetmiştir
- Başarılı login sonrası şüpheli aktivite vardır
- Source IP birden fazla hesabı denemiştir
- MFA bypass veya şüpheli MFA onayı vardır
- Hesap ele geçirilmesini destekleyen birden fazla kanıt vardır

---

## SOC Analyst İçin Güvenli Triage Notu

Bu teknik incelenirken otomatik yıkıcı aksiyon önerilmemelidir.

Önerilebilecek güvenli triage adımları:

- Logları doğrula
- Başarılı login sonrası aktiviteleri incele
- Source IP geçmişini kontrol et
- Aynı IP'nin başka hesapları deneyip denemediğine bak
- MFA durumunu kontrol et
- Kullanıcı doğrulaması yap
- Eksik kanıtları not et
- Olayı uygun risk seviyesinde insan analiste veya IR ekibine yükselt

Önerilmemesi gerekenler:

- Kanıt olmadan otomatik hesap kapatma
- Kanıt olmadan otomatik IP engelleme
- Sistemden dosya silme
- Process sonlandırma
- Kullanıcı hesabında yıkıcı değişiklik yapma

---

## Kısa Özet

T1110 - Brute Force, kimlik doğrulama noktalarında tekrar eden parola veya credential denemelerini ifade eder.

Bu teknik özellikle şu kombinasyonlarda ciddi risk oluşturur:

- Çok sayıda başarısız giriş
- Kritik hesap
- VPN veya dış erişim noktası
- Başarısız denemelerden sonra başarılı login
- Şüpheli source IP
- MFA problemi
- Başarılı login sonrası olağan dışı aktivite

Kesin saldırı kararı için source IP geçmişi, MFA durumu, kullanıcı doğrulaması ve başarılı login sonrası aktiviteler incelenmelidir.