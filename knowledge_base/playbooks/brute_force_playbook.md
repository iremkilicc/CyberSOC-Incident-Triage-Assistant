# Brute Force SOC Playbook

## Amaç

Bu playbook, kısa sürede çok sayıda başarısız giriş denemesi görüldüğünde SOC analyst’in hangi kontrolleri yapması gerektiğini açıklar.

Brute force alerti tek başına kesin saldırı anlamına gelmez. Kullanıcı şifresini unutmuş olabilir, yanlış yapılandırılmış bir servis tekrar tekrar giriş deniyor olabilir veya gerçekten bir saldırgan parola denemesi yapıyor olabilir. Bu yüzden önce kanıtlar kontrol edilmelidir.

## Bu Olay Ne Zaman Düşünülür?

Aşağıdaki durumlar brute force veya password guessing şüphesi oluşturabilir:

- Kısa sürede aynı kullanıcıya çok sayıda başarısız giriş denemesi yapılması
- Aynı kaynak IP adresinden farklı kullanıcılara giriş denenmesi
- Kritik hesapların hedeflenmesi
- Başarısız denemelerden sonra başarılı giriş görülmesi
- VPN, RDP, SSH veya web login gibi dış erişim noktalarında tekrar eden giriş denemeleri
- Normal çalışma saatleri dışında olağan dışı login denemeleri görülmesi

## Tipik Kanıtlar

Brute force şüphesinde aşağıdaki kanıtlar aranır:

- failed login sayısının normalden yüksek olması
- aynı source IP adresinin tekrar etmesi
- aynı kullanıcı hesabına tekrar tekrar deneme yapılması
- farklı kullanıcı hesaplarına aynı IP’den deneme yapılması
- kısa zaman aralığında çok sayıda başarısız deneme olması
- başarısız denemelerden sonra başarılı giriş olması
- hedef hesabın admin veya yetkili bir hesap olması
- giriş denemelerinin alışılmadık ülke, şehir veya cihazdan gelmesi

## İlk Kontrol Adımları

SOC analyst aşağıdaki kontrolleri yapmalıdır:

1. Başarılı giriş olmuş mu kontrol et.
2. Başarılı giriş olduysa, girişten sonra kullanıcı hangi işlemleri yaptı kontrol et.
3. Kaynak IP adresi daha önce görülmüş mü kontrol et.
4. Aynı IP adresi başka kullanıcı hesaplarını da denemiş mi bak.
5. Hedef kullanıcı hesabı kritik veya yetkili bir hesap mı kontrol et.
6. Kullanıcı normalde bu lokasyon veya cihazdan giriş yapıyor mu incele.
7. Giriş denemeleri hangi sistem üzerinde gerçekleşmiş kontrol et.
8. MFA aktif mi kontrol et.
9. Account lockout politikası çalışmış mı kontrol et.
10. Aynı zaman aralığında başka güvenlik alertleri var mı bak.

## Risk Artıran Durumlar

Aşağıdaki durumlar olayın riskini artırır:

- Admin, root veya privileged account hedeflenmişse
- Çok sayıda başarısız denemeden sonra başarılı giriş varsa
- Kaynak IP daha önce zararlı veya şüpheli olarak görülmüşse
- Denemeler dış erişim noktası olan VPN, RDP veya SSH üzerinde gerçekleşmişse
- Aynı IP birden fazla kullanıcı hesabını denemişse
- Başarılı giriş sonrası olağan dışı işlem yapılmışsa
- MFA devre dışıysa
- Kullanıcı normalde bu lokasyondan giriş yapmıyorsa

## False Positive İhtimali

Brute force alerti her zaman saldırı değildir. Aşağıdaki durumlar false positive olabilir:

- Kullanıcı şifresini unutmuş ve tekrar tekrar denemiş olabilir.
- Mobil cihaz veya e-posta istemcisi eski şifreyle tekrar tekrar giriş deniyor olabilir.
- Bir servis hesabı yanlış parola ile otomatik bağlantı deniyor olabilir.
- Yanlış yapılandırılmış uygulama sürekli login denemesi oluşturuyor olabilir.
- VPN veya SSO tarafında geçici kimlik doğrulama problemi olabilir.

## Önerilen İlk Müdahale

Kesin karar vermeden önce kanıtlar kontrol edilmelidir.

Şüphe düşükse:

- Kullanıcıyla iletişime geç.
- Şifre hatası veya yanlış yapılandırma ihtimalini kontrol et.
- Olayı izlemeye devam et.

Şüphe orta veya yüksekse:

- Başarılı giriş sonrası aktiviteleri incele.
- Kullanıcının aktif oturumlarını kontrol et.
- Gerekirse kullanıcı parolasını sıfırla.
- MFA durumunu kontrol et.
- Kaynak IP adresini incele.
- Aynı IP’den gelen diğer aktiviteleri araştır.
- Olayı incident olarak yükseltmeyi değerlendir.

Otomatik IP engelleme veya hesap kapatma bu projenin kapsamında değildir. Asistan sadece analiste öneri sunar.

## Asistanın Kullanacağı Cevap İpuçları

Asistan brute force şüphesi gördüğünde kesin konuşmamalıdır.

Doğru ifade örneği:

"Bu olay brute force veya password guessing davranışına benzeyebilir. Çünkü kısa sürede aynı kullanıcıya çok sayıda başarısız giriş denemesi görülüyor. Başarılı giriş varsa risk artar. Kesin karar için başarılı giriş sonrası aktiviteler, kaynak IP geçmişi, hedef hesabın kritikliği ve MFA durumu kontrol edilmelidir."

Yanlış ifade örneği:

"Bu kesin brute force saldırısıdır ve IP hemen engellenmelidir."

## Kullanılabilecek MITRE Eşleşmeleri

- T1110 - Brute Force
- T1078 - Valid Accounts, eğer başarısız denemelerden sonra başarılı giriş varsa ve geçerli hesap kullanımı şüphesi oluşuyorsa

## Kaynak Notu

Bu playbook eğitim amaçlı hazırlanmıştır. Gerçek bir SOC ortamında kurumun kendi güvenlik politikaları, log kaynakları ve incident response prosedürleri dikkate alınmalıdır.