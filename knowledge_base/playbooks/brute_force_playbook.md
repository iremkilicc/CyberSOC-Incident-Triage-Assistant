# Brute Force SOC Playbook

## Amaç

Bu playbook, kısa sürede çok sayıda başarısız giriş denemesi, password guessing, suspicious login, VPN login anomaly ve başarısız denemelerden sonra başarılı login görülen olaylarda SOC analyst'in nasıl düşünmesi gerektiğini açıklar.

Brute force alerti tek başına kesin saldırı anlamına gelmez. Kullanıcı şifresini unutmuş olabilir, yanlış yapılandırılmış bir servis eski şifreyle tekrar tekrar giriş deniyor olabilir veya gerçekten bir saldırgan parola tahmini yapıyor olabilir.

Bu yüzden amaç doğrudan kesin hüküm vermek değil, kanıtları toplayarak olayın riskini belirlemektir.

---

## Kapsam

Bu playbook şu olaylarda kullanılabilir:

- Kısa sürede çok sayıda başarısız login denemesi
- Aynı kullanıcıya tekrar tekrar parola denenmesi
- Aynı source IP'nin birden fazla kullanıcıyı denemesi
- Başarısız girişlerden sonra başarılı login görülmesi
- VPN, RDP, SSH, web login veya cloud console üzerinde tekrar eden giriş denemeleri
- Kritik kullanıcı hesabına yönelik login denemeleri
- Mesai dışı veya olağan dışı lokasyondan login denemeleri
- MFA başarısızlıklarıyla beraber gelen login olayları
- Password spraying veya credential stuffing şüphesi

---

## Temel Kavramlar

### Brute Force

Brute force, saldırganın doğru parolayı bulmak için aynı kullanıcı veya sistem üzerinde çok sayıda parola denemesi yapmasıdır.

Tipik özellikler:

- Aynı kullanıcıya çok sayıda başarısız giriş denemesi
- Kısa zaman aralığı
- Aynı source IP veya benzer IP aralığı
- Başarısız denemelerden sonra başarılı login görülebilir

---

### Password Guessing

Password guessing, saldırganın tahmin edilebilir parolaları denemesidir.

Örnekler:

- Password123
- Welcome2026
- CompanyName2026
- Summer2026
- Kullanıcı adıyla benzer parola

Bu olay brute force kadar yoğun olmayabilir ama yine de risklidir.

---

### Password Spraying

Password spraying, saldırganın aynı veya az sayıda parolayı birçok kullanıcı hesabında denemesidir.

Tipik özellikler:

- Çok sayıda farklı kullanıcı
- Her kullanıcıda az sayıda deneme
- Account lockout tetiklenmesin diye yavaş yapılabilir
- Aynı parola birçok hesapta denenmiş olabilir

Riskli bir davranıştır çünkü tek bir zayıf parola tüm saldırıyı başarılı yapabilir.

---

### Credential Stuffing

Credential stuffing, başka bir veri sızıntısından elde edilen kullanıcı adı/parola kombinasyonlarının denenmesidir.

Tipik özellikler:

- Birden fazla kullanıcı hesabına deneme
- Bazı hesaplarda hızlı başarılı login
- Denemeler farklı IP'lerden gelebilir
- Kullanıcılar aynı parolayı farklı servislerde kullanmış olabilir

---

### Valid Account Abuse

Başarılı login görüldüyse, saldırgan gerçekten doğru kimlik bilgileriyle giriş yapmış olabilir.

Bu durumda asıl soru şudur:

- Başarılı login gerçekten kullanıcıya mı ait?
- Başarılı login sonrası ne yapılmış?
- Bu oturumda olağan dışı hareket var mı?

---

## Alert İlk Geldiğinde Bakılacak Ana Sorular

Bir SOC analyst brute force benzeri alert gördüğünde önce şu soruları sormalıdır:

1. Hangi kullanıcı hedeflenmiş?
2. Kullanıcı kritik veya yetkili hesap mı?
3. Hangi sistem hedeflenmiş?
4. Kaç başarısız giriş denemesi var?
5. Denemeler hangi zaman aralığında gerçekleşmiş?
6. Başarısız denemelerden sonra başarılı login var mı?
7. Source IP aynı mı, farklı mı?
8. Source IP daha önce görülmüş mü?
9. Aynı IP başka hesapları da denemiş mi?
10. Kullanıcı normalde bu sistemden giriş yapar mı?
11. Giriş normal saat, cihaz ve lokasyondan mı yapılmış?
12. MFA aktif mi ve MFA sonucu ne?
13. Başarılı login sonrası hangi aktiviteler var?
14. Kullanıcı bu login denemelerini kendisinin yaptığını doğruluyor mu?

---

## Toplanması Gereken Kanıtlar

### Kullanıcı Bilgisi

Toplanacak bilgiler:

- user
- account type
- privilege level
- department
- normal login behavior
- normal login hours
- normal login locations
- normal device or hostname

Risk artıran durumlar:

- Admin veya privileged account olması
- Kullanıcının normalde hedef sisteme giriş yapmaması
- Kullanıcının normal davranışından sapma
- Kullanıcının login denemelerini reddetmesi

---

### Sistem Bilgisi

Toplanacak bilgiler:

- destination system
- system type
- exposure
- criticality
- authentication method

Örnek sistemler:

- vpn-gateway
- firewall
- domain controller
- cloud admin panel
- email portal
- SSH server
- RDP server
- web application login

Risk artıran durumlar:

- VPN gateway üzerinde başarılı login
- Domain controller veya cloud admin panel hedeflenmesi
- Dışarıdan erişilebilen sistemler
- Başarılı login sonrası kurum ağına erişim sağlanabilmesi

---

### Source IP Bilgisi

Toplanacak bilgiler:

- source_ip
- source country
- ASN / ISP
- internal or external
- previous history
- reputation
- same IP targeting other accounts

Risk artıran durumlar:

- Aynı IP'nin birçok kullanıcıyı denemesi
- IP'nin daha önce saldırı veya abuse kayıtlarında görülmesi
- Beklenmeyen ülke veya hosting sağlayıcısı
- TOR, proxy, VPN veya cloud hosting IP izlenimi
- Aynı IP'den başarılı login görülmesi

---

### Zaman Bilgisi

Toplanacak bilgiler:

- first failed login time
- last failed login time
- successful login time
- time window
- business hours or after hours

Risk artıran durumlar:

- Çok kısa sürede çok sayıda deneme
- Mesai dışında login denemesi
- Başarısız denemelerden hemen sonra başarılı login
- Aynı zamanda farklı hesaplarda benzer olaylar

---

### Login Sonucu

Toplanacak bilgiler:

- failed login count
- success count
- denied count
- locked count
- success_after_failures
- failure reason

Risk artıran durumlar:

- Başarısız denemelerden sonra başarılı login
- Çok sayıda wrong password hatası
- Hesap kilitlenmeden çok sayıda deneme yapılabilmesi
- Başarılı login sonrası şüpheli aktivite

---

### MFA Bilgisi

Toplanacak bilgiler:

- MFA enabled or disabled
- MFA success
- MFA failed
- MFA push denied
- MFA push accepted
- MFA fatigue indicators

Risk artıran durumlar:

- MFA kapalı olması
- Çok sayıda MFA başarısızlığı
- Kullanıcının onaylamadığı MFA kabulü
- Başarılı login öncesi çok sayıda MFA push denemesi

---

### Başarılı Login Sonrası Aktivite

Başarılı login varsa en kritik bölüm burasıdır.

Kontrol edilecekler:

- Kullanıcı hangi kaynaklara erişti?
- Yetki değişikliği yaptı mı?
- Parola değiştirdi mi?
- MFA ayarlarını değiştirdi mi?
- Yeni cihaz ekledi mi?
- VPN üzerinden iç ağda bağlantı başlattı mı?
- Uzak masaüstü, SSH veya admin panel erişimi yaptı mı?
- Büyük veri indirme veya dosya erişimi var mı?
- Mailbox rule veya forwarding rule oluşturdu mu?
- Yeni oturumlar açıldı mı?

Risk artıran durumlar:

- Başarılı login sonrası privilege change
- Şüpheli IP'lere bağlantı
- Hassas veri erişimi
- Yeni forwarding rule
- Güvenlik ayarı değişikliği
- Kullanıcının normalde yapmadığı işlemler

---

## Brute Force ve False Positive Ayrımı

### Gerçek Saldırıya Benzeyen Durumlar

Aşağıdaki bulgular varsa olay saldırıya daha çok benzeyebilir:

- Kısa sürede çok sayıda başarısız giriş
- Kritik hesap hedeflenmiş
- VPN veya dış erişim noktası hedeflenmiş
- Başarısız denemelerden sonra başarılı giriş
- Source IP bilinmeyen veya şüpheli
- Aynı IP başka hesapları da denemiş
- MFA başarısızlıkları var
- Başarılı login sonrası olağan dışı aktivite var
- Kullanıcı girişleri kendisinin yapmadığını söylüyor

---

### False Positive Olabilecek Durumlar

Aşağıdaki durumlar saldırı dışı açıklama olabilir:

- Kullanıcı şifresini unutmuş olabilir
- Kullanıcı birkaç kez yanlış yazıp sonra doğru şifreyle girmiş olabilir
- VPN istemcisi eski şifreyle otomatik deneme yapıyor olabilir
- Mobil cihaz eski kimlik bilgisiyle tekrar tekrar deniyor olabilir
- Yanlış yapılandırılmış servis hesabı login denemesi yapıyor olabilir
- SSO veya authentication sisteminde geçici hata olabilir
- Kullanıcı yeni cihazdan veya yeni lokasyondan normal giriş yapmış olabilir
- Kullanıcı parola değiştirdikten sonra eski oturumlar başarısız deneme üretmiş olabilir

---

## Severity Değerlendirme Mantığı

Severity sadece alertin verdiği seviyeye göre değil, kanıtlara göre değerlendirilmelidir.

### Düşük Risk

Şu durumlarda düşük risk düşünülebilir:

- Az sayıda başarısız deneme
- Başarılı login yok
- Kullanıcı kritik değil
- Source IP bilinen ve normal
- Kullanıcı olayı doğruluyor
- Başka alert yok

---

### Orta Risk

Şu durumlarda orta risk düşünülebilir:

- Kısa sürede çok sayıda başarısız deneme
- Kritik olmayan kullanıcı
- Başarılı login yok veya belirsiz
- Source IP hakkında yeterli bilgi yok
- MFA durumu bilinmiyor
- Ek kanıt gerekiyor

---

### Orta-Yüksek Risk

Şu durumlarda orta-yüksek risk düşünülebilir:

- Admin veya yetkili hesap hedeflenmiş
- VPN gateway veya dış erişim noktası hedeflenmiş
- Başarısız denemelerden sonra başarılı login var
- Source IP bilinmeyen
- Başarılı login sonrası aktivite henüz bilinmiyor
- MFA durumu belirsiz

---

### Yüksek Risk

Şu durumlarda yüksek risk düşünülebilir:

- Kullanıcı başarılı girişi kendisinin yapmadığını doğruluyor
- Başarılı login sonrası şüpheli aktivite var
- Aynı IP birçok hesabı denemiş
- MFA bypass veya şüpheli MFA kabulü var
- Privileged account ele geçirilmiş olabilir
- Hassas veri erişimi veya yetki değişikliği var
- Başka endpoint, email veya network alertleriyle ilişkili

---

## SOC Analyst İçin Adım Adım Triage Planı

### Adım 1: Alert Bilgisini Doğrula

Kontrol et:

- Alert hangi sistemden geldi?
- Hangi kullanıcı hedeflenmiş?
- Kaç başarısız giriş var?
- Zaman aralığı nedir?
- Başarılı login var mı?

Amaç:

Olayın gerçekten login anomaly olduğunu doğrulamak.

---

### Adım 2: Kullanıcı Riskini Değerlendir

Kontrol et:

- Kullanıcı admin mi?
- Privileged account mu?
- Servis hesabı mı?
- Normalde bu sisteme giriş yapar mı?
- Kullanıcının normal login saatleri ne?

Amaç:

Hedef hesabın önemini anlamak.

---

### Adım 3: Source IP'yi İncele

Kontrol et:

- IP iç ağ mı dış ağ mı?
- Daha önce görülmüş mü?
- Aynı IP başka hesapları denemiş mi?
- IP'nin reputation bilgisi var mı?
- Kullanıcının normal lokasyonuyla uyumlu mu?

Amaç:

Denemelerin normal kullanıcı davranışı mı, saldırı mı olabileceğini anlamak.

---

### Adım 4: Zaman Çizelgesi Oluştur

Kontrol et:

- İlk başarısız giriş ne zaman?
- Son başarısız giriş ne zaman?
- Başarılı giriş ne zaman?
- Başarılı giriş başarısız denemelerden hemen sonra mı?
- Aynı zaman aralığında başka alertler var mı?

Amaç:

Olayın akışını anlamak.

---

### Adım 5: MFA Durumunu Kontrol Et

Kontrol et:

- MFA aktif mi?
- MFA başarısızlıkları var mı?
- MFA push denemesi var mı?
- Kullanıcı MFA onayı verdi mi?
- Kullanıcı bu MFA talebini bekliyor muydu?

Amaç:

Hesabın ek korumadan geçip geçmediğini anlamak.

---

### Adım 6: Başarılı Login Sonrası Aktiviteyi İncele

Başarılı login varsa şunlara bak:

- Oturum süresi
- Erişilen sistemler
- Dosya erişimleri
- VPN sonrası iç ağ bağlantıları
- Admin işlemleri
- Parola değişikliği
- MFA ayarı değişikliği
- Mailbox rule oluşturma
- Yeni cihaz ekleme
- Olağan dışı indirme veya veri erişimi

Amaç:

Hesap ele geçirilmişse saldırganın ne yaptığını anlamak.

---

### Adım 7: Kapsamı Araştır

Kontrol et:

- Aynı source IP başka hesapları denemiş mi?
- Aynı kullanıcı farklı IP'lerden denenmiş mi?
- Aynı zaman aralığında diğer kullanıcılar etkilenmiş mi?
- Aynı pattern VPN, RDP veya web login üzerinde var mı?

Amaç:

Olay tek kullanıcı mı, yoksa daha geniş kampanya mı anlamak.

---

### Adım 8: Kullanıcı Doğrulaması Yap

Kullanıcıya sorulabilecek güvenli sorular:

- Bu saatlerde VPN'e girmeye çalıştınız mı?
- Şifrenizi birkaç kez yanlış girdiniz mi?
- Yeni cihaz veya yeni lokasyondan giriş yaptınız mı?
- MFA bildirimi aldınız mı?
- Size ait olmayan bir başarılı giriş görüyor musunuz?

Amaç:

Teknik loglarla kullanıcı beyanını karşılaştırmak.

---

### Adım 9: Olayı Sınıflandır

Olası sınıflandırmalar:

- False positive / kullanıcı hatası
- Misconfigured service/device
- Brute force attempt
- Password spraying
- Credential stuffing
- Valid account compromise suspicion
- Confirmed account compromise

Amaç:

Olayın hangi kategoriye daha yakın olduğunu belirlemek.

---

## Ne Zaman Incident'a Yükseltilir?

Aşağıdaki durumlarda olay incident olarak yükseltilmelidir:

- Kullanıcı başarılı girişi kendisinin yapmadığını söylüyorsa
- Başarısız denemelerden sonra başarılı login varsa ve kaynak IP şüpheliyse
- Admin veya privileged account hedeflenmişse
- Başarılı login sonrası anormal aktivite varsa
- Aynı source IP başka hesapları da denemişse
- MFA bypass veya onaylanmamış MFA kabulü varsa
- Hesap ayarlarında değişiklik yapılmışsa
- Parola, MFA, mailbox rule veya forwarding ayarları değiştirilmişse
- Hassas sistem veya verilere erişim görülmüşse
- Olay başka endpoint, email veya network alertleriyle ilişkiliyse
- Birden fazla kullanıcı etkilenmişse

---

## Önerilen İlk Müdahale Yaklaşımı

Bu playbook otomatik aksiyon önermek için değil, insan analiste güvenli triage rehberi vermek için kullanılır.

Temkinli ilk müdahale önerileri:

- Başarılı login sonrası aktiviteleri incele
- Source IP geçmişini kontrol et
- Aynı IP'nin başka hesapları deneyip denemediğini araştır
- MFA ve account lockout durumunu kontrol et
- Kullanıcıyla doğrulama yap
- Eksik kanıtları not et
- Risk seviyesini kanıta göre yeniden değerlendir
- Gerekirse incident response ekibine yükselt

Önerilmemesi gereken otomatik aksiyonlar:

- Kanıt olmadan otomatik hesap kapatma
- Kanıt olmadan otomatik IP engelleme
- Sistemden dosya silme
- Process sonlandırma
- Kullanıcı hesabında yıkıcı değişiklik yapma

---

## Raporlama İçin Örnek Analist Notu

Örnek not:

Bu olayda admin kullanıcısı için VPN gateway üzerinde kısa sürede çok sayıda başarısız login denemesi görülmüştür. Başarısız denemelerden sonra başarılı login oluşması nedeniyle brute force veya password guessing ihtimali değerlendirilmelidir. Ancak kesin saldırı kararı için source IP geçmişi, MFA durumu, başarılı login sonrası aktiviteler ve kullanıcı doğrulaması gereklidir.

---

## Kullanılan MITRE ATT&CK Eşleşmesi

Bu playbook için ana MITRE eşleşmesi:

- T1110 - Brute Force

İlgili olabilecek ek davranışlar:

- Valid Accounts davranışı
- Credential access şüphesi
- Initial access şüphesi

Bu ek davranışlar kesin olarak söylenmemeli, sadece kanıt varsa değerlendirilmelidir.

---

## Kısa Özet

Brute force alertinde en kritik nokta şudur:

Başarısız giriş denemesi tek başına kesin saldırı değildir. Ama kısa sürede çok sayıda deneme, kritik hesap, VPN gibi dış erişim noktası ve denemelerden sonra başarılı login görülmesi riski ciddi şekilde artırır.

SOC analyst önce kanıtları toplamalı, başarılı login sonrası aktiviteleri incelemeli ve kullanıcı doğrulaması yapmalıdır.