# Sample Final Answer - Brute Force / Suspicious Login

## 1. Olayı İnsan Dilinde Açıklama

Bu olayda `admin` hesabı için VPN gateway üzerinde kısa süre içinde çok sayıda başarısız giriş denemesi görülüyor. 5 dakika içinde 35 başarısız deneme yapılmış ve ardından başarılı bir giriş oluşmuş.

Basitçe: Birisi admin hesabına tekrar tekrar girmeyi denemiş ve sonunda giriş başarılı olmuş olabilir.

## 2. İlk İzlenim

Bu olay brute force, password guessing veya geçerli hesap kullanımı ihtimaline benzeyebilir.

Ancak tek başına kesin saldırı demek doğru değildir. Kullanıcı şifresini unutmuş, eski bir cihaz otomatik deneme yapmış veya bir servis yanlış yapılandırılmış olabilir.

## 3. Olası Senaryolar

- Gerçek brute force / password guessing denemesi olabilir.
- Başarısız denemelerden sonra başarılı login olduğu için valid account abuse ihtimali değerlendirilebilir.
- Kullanıcı şifresini birkaç kez yanlış girip sonra doğru girmiş olabilir.
- VPN client veya mobil cihaz eski parola ile otomatik deneme yapıyor olabilir.
- Yanlış yapılandırılmış servis hesabı tekrar tekrar login deniyor olabilir.

## 4. MITRE ATT&CK Eşleşmesi

Olası MITRE ATT&CK eşleşmesi:

- T1110 - Brute Force

Başarılı giriş sonrası aktiviteler şüpheliyse valid account abuse ihtimali de ayrıca değerlendirilmelidir.

## 5. Bu Yorumu Destekleyen Kanıtlar

- Hedef kullanıcı `admin`.
- Hedef sistem `vpn-gateway`.
- 5 dakika içinde 35 başarısız giriş denemesi var.
- Başarısız denemelerden sonra başarılı giriş görülmüş.
- Olay authentication/login davranışıyla ilgili.
- Source IP bilgisi mevcut.
- Alert seviyesi medium olarak belirtilmiş.

## 6. Risk Artıran Durumlar

- Hedef hesabın admin olması.
- VPN gateway gibi dış erişim noktasının hedeflenmesi.
- Kısa sürede çok sayıda başarısız deneme olması.
- Başarısız denemelerden sonra başarılı giriş olması.
- MFA durumunun bilinmemesi.
- Başarılı login sonrası aktivitelerin henüz bilinmemesi.

## 7. Risk Düşüren veya False Positive Olabilecek Durumlar

- Kullanıcı şifresini unutmuş olabilir.
- Kullanıcı sonunda doğru parolayı hatırlamış olabilir.
- VPN istemcisi eski parola ile otomatik deneme yapmış olabilir.
- Mobil cihaz eski credential ile tekrar tekrar authentication deniyor olabilir.
- SSO veya authentication servisinde geçici hata oluşmuş olabilir.
- Kullanıcı normal cihaz ve lokasyondan giriş yapmış olabilir.

## 8. Eksik Bilgiler

- Başarılı giriş sonrası kullanıcı ne yaptı?
- Source IP daha önce görülmüş mü?
- Source IP başka hesapları da denemiş mi?
- Kullanıcı normalde VPN kullanıyor mu?
- Giriş normal saat, cihaz ve lokasyondan mı?
- MFA aktif mi?
- MFA başarılı mı, başarısız mı?
- Kullanıcı bu girişleri kendisinin yaptığını doğruluyor mu?
- Aynı zaman aralığında başka alert var mı?

## 9. SOC Analyst İçin Adım Adım Kontrol Planı

1. Kullanıcının kritik/yetkili hesap olup olmadığını kontrol et.
2. Başarısız deneme sayısını ve zaman aralığını doğrula.
3. Başarılı girişin aynı source IP üzerinden olup olmadığını kontrol et.
4. Source IP geçmişine bak.
5. Aynı IP başka hesapları denemiş mi kontrol et.
6. MFA durumunu incele.
7. Başarılı login sonrası aktiviteleri kontrol et.
8. Kullanıcının normal cihaz, lokasyon ve saat bilgisiyle karşılaştır.
9. Kullanıcı doğrulaması yap.
10. Başka endpoint, email veya network alerti var mı bak.

## 10. Ne Zaman Incident'a Yükseltilir?

- Kullanıcı başarılı girişi reddederse.
- Başarılı giriş sonrası şüpheli aktivite varsa.
- Aynı IP başka hesapları da denemişse.
- MFA bypass veya onaylanmamış MFA kabulü varsa.
- Admin hesabıyla yetki değişikliği veya hassas veri erişimi varsa.
- Aynı olay başka güvenlik alertleriyle ilişkiliyse.

## 11. Önerilen İlk Müdahale

İlk aşamada kanıt toplanmalı ve olay doğrulanmalıdır.

Önerilen güvenli adımlar:

- Başarılı login sonrası aktiviteleri incele.
- Source IP ve MFA durumunu kontrol et.
- Kullanıcı doğrulaması yap.
- Aynı IP’nin başka hesapları deneyip denemediğini araştır.
- Gerekirse insan analiste veya incident response ekibine yükselt.

Otomatik hesap kapatma, IP engelleme veya yıkıcı aksiyon önerilmemelidir.

## 12. Kullanılan Kaynaklar

- T1110_brute_force.md
- brute_force_playbook.md
- login_log_fields.md
- nist_incident_response_summary.md

## 13. Güven Düzeyi

Güven düzeyi: Orta-yüksek

Çünkü brute force davranışını destekleyen güçlü kanıtlar var. Ancak kesin saldırı kararı için source IP geçmişi, MFA durumu, kullanıcı doğrulaması ve başarılı login sonrası aktiviteler eksik.
