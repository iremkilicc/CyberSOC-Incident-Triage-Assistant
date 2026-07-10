# Sample Answer - Brute Force Alert

## 1. Olayı İnsan Dilinde Açıklama

Bu alert, `admin` kullanıcısı için `vpn-gateway` üzerinde kısa sürede çok sayıda başarısız giriş denemesi olduğunu gösteriyor. 5 dakika içinde 35 başarısız giriş denemesi yapılmış ve bu denemelerden sonra başarılı bir giriş görülmüş.

Basitçe: Birisi admin hesabına tekrar tekrar giriş denemiş ve sonunda giriş başarılı olmuş olabilir. Bu yüzden olay normal bir kullanıcı hatasından daha dikkatli incelenmelidir.

## 2. İlk İzlenim

Bu olay ilk bakışta brute force veya password guessing davranışına benzeyebilir. Ancak kesin saldırı demek doğru değildir. Kullanıcı şifresini unutmuş olabilir, bir cihaz eski şifreyle otomatik giriş deniyor olabilir veya yanlış yapılandırılmış bir servis sürekli login denemesi üretiyor olabilir.

Başarısız denemelerden sonra başarılı giriş görülmesi riski artırır.

## 3. Olası Senaryolar

- **Brute Force / Password Guessing:** Kısa sürede 35 başarısız giriş denemesi yapılması parola deneme davranışına benzeyebilir.
- **Valid Account Kullanımı:** Başarısız girişlerden sonra başarılı login görülmesi doğru parolanın bulunmuş veya geçerli hesabın kullanılmış olabileceğini düşündürür.
- **Kullanıcı Hatası / False Positive:** Kullanıcı şifresini unutmuş, tekrar tekrar denemiş ve sonunda doğru şifreyi hatırlamış olabilir.
- **Yanlış Yapılandırılmış Sistem veya Cihaz:** Bir servis, VPN istemcisi, mobil cihaz veya otomatik uygulama eski şifreyle tekrar tekrar giriş deniyor olabilir.

## 4. MITRE ATT&CK Eşleşmesi

Olası MITRE ATT&CK eşleşmesi:

- T1110 - Brute Force

Başarısız girişlerden sonra başarılı giriş görülmesi nedeniyle Valid Accounts ihtimali de ayrıca değerlendirilebilir. Ancak mevcut kaynaklara göre ana eşleşme T1110 Brute Force davranışıdır.

## 5. Bu Yorumu Destekleyen Kanıtlar

- Hedef kullanıcı `admin`.
- Hedef sistem `vpn-gateway`.
- 5 dakika içinde 35 başarısız giriş denemesi var.
- Başarısız giriş denemelerinden sonra başarılı giriş görülmüş.
- Olay login/authentication davranışıyla ilgili.
- Source IP bilgisi mevcut: `192.168.1.25`.
- Alert seviyesi `medium`.

## 6. Risk Artıran Durumlar

- Hedef hesabın `admin` olması.
- VPN gateway üzerinde gerçekleşmesi.
- Kısa sürede çok sayıda başarısız deneme olması.
- Başarısız denemelerden sonra başarılı giriş görülmesi.
- Başarılı giriş sonrası aktivitenin henüz bilinmemesi.

## 7. Risk Düşüren veya False Positive Olabilecek Durumlar

- Kullanıcı şifresini unutmuş olabilir.
- Kullanıcı sonunda doğru şifreyi hatırlamış olabilir.
- Bir cihaz eski şifreyle otomatik giriş deniyor olabilir.
- VPN istemcisi veya uygulama tekrar tekrar kimlik doğrulama denemesi yapıyor olabilir.
- Bir servis hesabı yanlış parola ile çalışıyor olabilir.
- Geçici authentication veya SSO problemi oluşmuş olabilir.

## 8. Eksik Bilgiler

- Başarılı giriş sonrası kullanıcı hangi işlemleri yaptı?
- Source IP daha önce görülmüş mü?
- Aynı source IP başka hesapları da denemiş mi?
- Kullanıcı normalde VPN kullanıyor mu?
- Kullanıcı normalde bu lokasyon veya cihazdan giriş yapıyor mu?
- MFA aktif mi?
- MFA denemeleri başarılı mı başarısız mı?
- Account lockout politikası çalışmış mı?
- Aynı zaman aralığında başka güvenlik alertleri var mı?
- Kullanıcı bu girişleri kendisinin yaptığını doğruluyor mu?

## 9. SOC Analyst İçin Adım Adım Kontrol Planı

1. `admin` hesabının kritik/yetkili hesap olup olmadığını doğrula.
2. Başarılı girişin zamanını belirle.
3. Başarılı giriş sonrası aktiviteleri incele.
4. Source IP adresinin geçmişini kontrol et.
5. Aynı IP başka kullanıcı hesaplarını da denemiş mi bak.
6. Kullanıcı normalde VPN üzerinden giriş yapıyor mu kontrol et.
7. Kullanıcının normal lokasyon ve cihaz bilgisini karşılaştır.
8. MFA durumunu kontrol et.
9. Account lockout veya benzer koruma mekanizmalarının çalışıp çalışmadığını incele.
10. Aynı zaman aralığında başka alert olup olmadığını araştır.
11. Kullanıcıyla iletişime geçip bu giriş denemelerini kendisinin yapıp yapmadığını doğrula.
12. Başarılı giriş sonrası şüpheli aktivite varsa olayı incident olarak yükseltmeyi değerlendir.

## 10. Ne Zaman Incident'a Yükseltilir?

- Kullanıcı bu girişleri kendisinin yapmadığını söylerse.
- Başarılı giriş sonrası olağan dışı işlem yapılmışsa.
- Source IP başka kullanıcı hesaplarını da denemişse.
- MFA başarısızlıkları veya MFA bypass şüphesi varsa.
- Admin hesabıyla yetki değişikliği, veri erişimi veya sistem ayarı değişikliği görülürse.
- Aynı zaman aralığında başka güvenlik alertleri oluşmuşsa.

## 11. Önerilen İlk Müdahale

Bu olay orta-yüksek öncelikle incelenmelidir. İlk müdahale olarak başarılı giriş sonrası aktiviteler, source IP geçmişi, kullanıcı doğrulaması, MFA durumu ve account lockout durumu kontrol edilmelidir.

Otomatik IP engelleme, hesap kapatma veya sistem üzerinde yıkıcı aksiyon önerilmemelidir. İnsan analistin kanıtları doğrulaması gerekir.

## 12. Kullanılan Kaynaklar

- knowledge_base/investigation_notes/login_log_fields.md
- knowledge_base/mitre/T1110_brute_force.md
- knowledge_base/playbooks/brute_force_playbook.md
- knowledge_base/nist/nist_incident_response_summary.md

## 13. Güven Düzeyi

**Orta-yüksek.**

Çünkü alertte brute force davranışını destekleyen güçlü kanıtlar var: kısa sürede çok sayıda başarısız giriş denemesi, admin hesabının hedeflenmesi, VPN gateway üzerinde gerçekleşmesi ve başarısız denemelerden sonra başarılı giriş görülmesi.

Ancak kesin saldırı demek için başarılı giriş sonrası aktiviteler, source IP geçmişi, MFA durumu ve kullanıcı doğrulaması gibi ek kanıtlar gerekir.
