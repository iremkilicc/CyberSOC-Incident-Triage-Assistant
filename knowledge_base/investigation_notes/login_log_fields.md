# Login Log Fields

## Amaç

Bu dosya, login ve authentication olaylarını incelerken hangi log alanlarına bakılması gerektiğini açıklar.

Brute force, password guessing, suspicious login, valid account abuse ve VPN login anomaly gibi olaylarda bu alanlar SOC analyst için önemlidir.

Bir login alerti tek başına kesin saldırı anlamına gelmez. SOC analyst önce kanıtları toplamalı, normal kullanıcı davranışıyla karşılaştırmalı ve eksik bilgileri belirlemelidir.

---

## Temel Alanlar

### user

Giriş denemesi yapılan kullanıcı hesabıdır.

Kontrol soruları:
- Kullanıcı kritik veya yetkili bir hesap mı?
- Kullanıcı normalde bu sisteme giriş yapar mı?
- Kullanıcı bu saatlerde aktif olur mu?
- Kullanıcı servis hesabı mı, insan kullanıcı mı?
- Kullanıcı daha önce benzer login hataları yaşamış mı?

Risk artıran durumlar:
- Admin, root, domain admin, privileged user gibi yetkili hesap olması
- Kullanıcının normalde VPN kullanmaması
- Kullanıcının mesai dışı giriş yapması
- Kullanıcının kısa sürede çok fazla başarısız giriş denemesi alması

---

### source_ip

Giriş denemesinin geldiği IP adresidir.

Kontrol soruları:
- IP daha önce görülmüş mü?
- Aynı IP başka hesapları da denemiş mi?
- IP beklenen lokasyondan mı geliyor?
- IP dış kaynak mı, iç ağ mı?
- IP VPN, proxy, TOR veya hosting sağlayıcısı gibi görünüyor mu?
- IP kurum içinde bilinen bir sistem mi?

Risk artıran durumlar:
- Aynı IP'nin birden fazla kullanıcıyı denemesi
- IP'nin daha önce tehdit istihbaratında görülmesi
- Kullanıcının normal lokasyonundan farklı olması
- IP'nin kısa sürede çok sayıda login denemesi üretmesi

---

### destination_system

Giriş denemesinin yapıldığı sistemdir.

Örnekler:
- vpn-gateway
- firewall
- domain controller
- email portal
- cloud console
- RDP server
- SSH server
- web application login

Kontrol soruları:
- Sistem dış erişime açık mı?
- Sistem kritik mi?
- Bu sistemde başarılı login sonrası hangi kaynaklara erişilebilir?
- Kullanıcı normalde bu sisteme giriş yapar mı?

Risk artıran durumlar:
- VPN gateway, domain controller, cloud admin panel gibi kritik sistemler
- Dışarıdan erişilebilen sistemler
- Başarılı giriş sonrası kurum ağına erişim sağlanabilmesi

---

### timestamp

Olayın gerçekleştiği zamandır.

Kontrol soruları:
- Giriş denemeleri kısa zaman aralığında mı olmuş?
- Olay mesai dışında mı gerçekleşmiş?
- Başarısız denemeden sonra başarılı giriş ne zaman olmuş?
- Aynı zamanda başka alertler oluşmuş mu?

Risk artıran durumlar:
- Çok kısa sürede çok sayıda deneme
- Mesai dışı login
- Başarısız denemelerden hemen sonra başarılı giriş
- Aynı dakikalarda farklı hesaplarda da login hataları

---

### login_status

Girişin başarılı mı başarısız mı olduğunu gösterir.

Örnek değerler:
- failed
- success
- denied
- locked
- MFA_failed
- MFA_success

Kontrol soruları:
- Sadece başarısız deneme mi var?
- Başarısız denemelerden sonra başarılı giriş var mı?
- Başarılı giriş sonrası kullanıcı ne yapmış?
- Hesap kilitlenmiş mi?

Risk artıran durumlar:
- successful_login_after_failures görülmesi
- Başarılı giriş sonrası olağan dışı işlem yapılması
- Başarılı girişin yeni cihaz veya yeni lokasyondan olması

---

### failed_attempt_count

Belirli zaman aralığındaki başarısız giriş denemesi sayısıdır.

Kontrol soruları:
- Sayı normal kullanıcı hatasını aşacak kadar yüksek mi?
- Denemeler tek kullanıcıya mı yapılmış?
- Denemeler birçok kullanıcıya mı yayılmış?
- Deneme sayısı kısa zaman aralığında mı artmış?

Risk artıran durumlar:
- 5 dakika içinde çok sayıda deneme
- Aynı kullanıcıya tekrar tekrar deneme
- Aynı source IP üzerinden çok sayıda deneme
- Başarısız denemelerden sonra başarılı login görülmesi

---

## Genişletilmiş Alanlar

### success_after_failures

Başarısız giriş denemelerinden sonra başarılı giriş olup olmadığını gösterir.

Bu alan brute force veya password guessing olaylarında çok önemlidir.

Kontrol soruları:
- Başarılı giriş başarısız denemelerden hemen sonra mı olmuş?
- Başarılı giriş aynı source IP üzerinden mi olmuş?
- Başarılı giriş sonrası kullanıcı hangi işlemleri yapmış?
- Başarılı giriş normal cihaz veya lokasyondan mı yapılmış?

Risk artıran durumlar:
- Başarılı girişin aynı IP'den yapılması
- Başarılı giriş sonrası privilege change, data access veya configuration change görülmesi
- Kullanıcının bu girişi kendisinin yapmadığını söylemesi

---

### mfa_status

Multi-factor authentication durumunu gösterir.

Örnek değerler:
- MFA not enabled
- MFA success
- MFA failed
- MFA push denied
- MFA push accepted
- MFA bypass suspected

Kontrol soruları:
- MFA aktif mi?
- MFA denemeleri başarılı mı başarısız mı?
- Kullanıcı MFA bildirimi aldığını doğruluyor mu?
- MFA push bombardımanı olabilir mi?

Risk artıran durumlar:
- MFA kapalı olması
- Çok sayıda MFA başarısızlığı
- Kullanıcının onaylamadığı MFA kabulü
- Başarılı login öncesi çok sayıda MFA push denemesi

---

### user_agent

Login denemesini yapan istemci veya tarayıcı bilgisidir.

Kontrol soruları:
- User agent kullanıcının normal cihazına benziyor mu?
- Daha önce bu kullanıcıda görülmüş mü?
- Otomasyon veya script izlenimi veriyor mu?
- Farklı login denemelerinde aynı user agent mı kullanılmış?

Risk artıran durumlar:
- Daha önce görülmemiş user agent
- Çok eski veya anormal user agent
- Aynı user agent ile çok sayıda hesap denenmesi

---

### device_id veya hostname

Login denemesinin geldiği cihaz bilgisidir.

Kontrol soruları:
- Cihaz kuruma ait mi?
- Cihaz daha önce kullanıcı tarafından kullanılmış mı?
- Cihaz endpoint güvenlik aracı tarafından izleniyor mu?
- Cihazda aynı zamanda başka şüpheli olay var mı?

Risk artıran durumlar:
- Bilinmeyen cihaz
- Yeni cihazdan başarılı login
- Cihazda malware veya suspicious PowerShell alerti olması

---

### geo_location

Login denemesinin coğrafi konum bilgisidir.

Kontrol soruları:
- Kullanıcı normalde bu ülkeden veya şehirden giriş yapar mı?
- Kısa sürede farklı ülkelerden login var mı?
- Impossible travel ihtimali var mı?

Risk artıran durumlar:
- Kullanıcının normal lokasyonundan farklı ülke
- Çok kısa sürede iki uzak lokasyondan giriş
- Daha önce görülmemiş lokasyon

---

### failure_reason

Başarısız login denemesinin neden başarısız olduğunu gösterir.

Örnekler:
- wrong password
- unknown user
- account locked
- expired password
- MFA failed
- access denied

Kontrol soruları:
- Denemeler yanlış parola nedeniyle mi başarısız?
- Kullanıcı adı hatalı mı?
- Hesap kilitlenmiş mi?
- MFA başarısızlığı mı var?

Risk artıran durumlar:
- Çok sayıda wrong password
- Birden fazla kullanıcı için unknown user
- MFA failed tekrarları

---

### session_id

Başarılı login sonrası oluşan oturum kimliğidir.

Kontrol soruları:
- Başarılı giriş sonrası aynı session ile hangi işlemler yapılmış?
- Session süresi normal mi?
- Session farklı IP veya cihazla ilişkilendirilmiş mi?

Risk artıran durumlar:
- Başarılı login sonrası hassas kaynak erişimi
- Session içinde yetki değişikliği
- Session içinde veri indirme veya anormal hareket

---

### auth_method

Kimlik doğrulama yöntemini gösterir.

Örnekler:
- password
- SSO
- VPN
- Kerberos
- NTLM
- RADIUS
- OAuth

Kontrol soruları:
- Hangi authentication yöntemi kullanılmış?
- Bu yöntem kullanıcı için normal mi?
- Başarısızlıklar aynı auth yöntemi üzerinden mi geliyor?

Risk artıran durumlar:
- Eski veya zayıf authentication yöntemi
- Beklenmeyen auth yöntemi
- Aynı source IP'nin farklı auth yöntemlerini denemesi

---

### account_lockout_status

Hesabın kilitlenip kilitlenmediğini gösterir.

Kontrol soruları:
- Hesap lockout olmuş mu?
- Lockout politikası çalışmış mı?
- Lockout sonrası başarılı giriş var mı?

Risk artıran durumlar:
- Lockout olmadan çok sayıda deneme yapılabilmesi
- Lockout sonrası başarılı giriş
- Kritik hesaplarda tekrar eden lockout olayları

---

## SOC Analyst İçin Temel Kontrol Mantığı

Bir login alerti incelenirken şu sırayla düşünülmelidir:

1. Hangi kullanıcı etkilenmiş?
2. Kullanıcı kritik veya yetkili mi?
3. Hangi sistem hedeflenmiş?
4. Kaç başarısız giriş denemesi var?
5. Denemeler ne kadar kısa sürede olmuş?
6. Başarısız denemelerden sonra başarılı giriş var mı?
7. Source IP daha önce görülmüş mü?
8. Aynı source IP başka hesapları da denemiş mi?
9. Giriş normal cihaz, lokasyon ve saatten mi yapılmış?
10. MFA durumu nedir?
11. Başarılı login sonrası kullanıcı ne yapmış?
12. Kullanıcı bu girişleri kendisi yaptığını doğruluyor mu?

---

## False Positive İhtimalleri

Bu tür alertler şu nedenlerle saldırı olmadan da oluşabilir:

- Kullanıcı şifresini unutmuş olabilir.
- Kullanıcı birkaç kez yanlış şifre girip sonra doğru şifreyi hatırlamış olabilir.
- Mobil cihaz veya VPN istemcisi eski şifreyle otomatik deneme yapıyor olabilir.
- Yanlış yapılandırılmış servis hesabı sürekli login deniyor olabilir.
- SSO veya authentication servisinde geçici hata olabilir.
- Kullanıcı yeni cihazdan veya yeni lokasyondan normal giriş yapmış olabilir.

---

## Incident'a Yükseltme Göstergeleri

Aşağıdaki bulgular görülürse olay incident olarak yükseltilebilir:

- Kullanıcı başarılı girişi kendisinin yapmadığını söylerse
- Başarılı login sonrası şüpheli aktivite görülürse
- Aynı IP başka hesapları da denemişse
- Admin veya privileged account hedeflenmişse ve başarılı giriş varsa
- MFA bypass veya şüpheli MFA onayı varsa
- Yeni cihaz veya yeni lokasyondan başarılı giriş varsa
- Aynı zaman aralığında endpoint, email veya network alertleri de varsa
- Başarılı login sonrası veri erişimi, yetki değişikliği veya konfigürasyon değişikliği görülürse

---

## Kısa Özet

Login log analizi brute force ve suspicious login triage sürecinin temelidir.

En kritik sorular şunlardır:

- Hangi kullanıcı hedeflendi?
- Kaç başarısız deneme var?
- Başarılı giriş oldu mu?
- Source IP normal mi?
- MFA durumu ne?
- Başarılı giriş sonrası ne yapıldı?
- Kullanıcı bunu doğruluyor mu?

Bu sorulara cevap verilmeden olay kesin saldırı olarak değerlendirilmemelidir.