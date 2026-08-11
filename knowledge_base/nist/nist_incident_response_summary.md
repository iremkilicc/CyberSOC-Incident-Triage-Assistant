# NIST Incident Response Summary

## Amaç

Bu dosya, siber güvenlik olaylarında savunmacı bakış açısıyla nasıl düşünülmesi gerektiğini özetler.

MITRE ATT&CK dosyaları saldırgan davranışını anlamaya yardım eder. Playbook dosyaları belirli alert türlerinde hangi kontrollerin yapılacağını anlatır. NIST incident response özeti ise olay müdahalesinin genel mantığını verir.

Bu dosya eğitim amaçlı sadeleştirilmiş bir özettir.

## Incident Response Nedir?

Incident response, bir güvenlik olayı fark edildiğinde olayın anlaşılması, kontrol altına alınması, temizlenmesi ve sonrasında ders çıkarılması sürecidir.

Bir alert tek başına kesin incident anlamına gelmeyebilir. Önce olayın ne olduğu, hangi sistemleri etkilediği ve risk seviyesinin ne olduğu analiz edilmelidir.

## Genel Olay Müdahale Mantığı

Bir SOC analyst güvenlik alerti gördüğünde aşağıdaki sorularla düşünmelidir:

1. Bu olay ne anlatıyor?
2. Hangi kullanıcı, cihaz veya sistem etkilenmiş?
3. Olayın kanıtları neler?
4. Bu olay hangi saldırı davranışına benzeyebilir?
5. Eksik bilgiler neler?
6. Olayın riski düşük mü, orta mı, yüksek mi?
7. İlk kontrol adımları neler olmalı?
8. Kontrol altına alma veya müdahale gerekli mi?
9. Olay sonrasında hangi dersler çıkarılabilir?

## 1. Olayı Tanımla

İlk adım, alertin ne anlattığını sade şekilde anlamaktır.

Örnekler:

- Çok sayıda başarısız login denemesi görüldü.
- Kullanıcı şüpheli bir e-posta bildirdi.
- Endpoint üzerinde encoded PowerShell komutu çalıştı.

Bu aşamada amaç hemen karar vermek değildir. Amaç olayın neye benzediğini anlamaktır.

## 2. Etkilenen Kullanıcı ve Sistemleri Belirle

Olay hangi kullanıcıyı, cihazı veya sistemi etkiliyor?

Bakılabilecek alanlar:

- user
- source_ip
- endpoint_name
- target_system
- recipient
- sender
- timestamp
- affected_host

Örnek:

Brute force olayında hedef kullanıcı `admin` ise risk artabilir.

Phishing olayında kullanıcı linke tıkladıysa risk artabilir.

PowerShell olayında endpoint kritik bir sunucuysa risk artabilir.

## 3. Kanıtları Topla ve Koru

Karar vermeden önce kanıtlar toplanmalıdır.

Kanıt örnekleri:

- login logs
- email headers
- command_line bilgisi
- parent_process bilgisi
- network connection bilgisi
- related_alerts
- kullanıcı beyanı
- güvenlik aracı uyarıları

Kanıtlar eksikse asistan kesin konuşmamalıdır.

Doğru ifade:

"Kaynaklarda bu olayı kesin saldırı olarak değerlendirmek için yeterli bilgi yok."

Yanlış ifade:

"Bu kesin saldırıdır."

## 4. Olayın Ciddiyetini Değerlendir

Olayın risk seviyesi kanıtlara göre değerlendirilmelidir.

Risk artıran örnekler:

- Admin veya privileged account etkilenmişse
- Başarısız girişlerden sonra başarılı login varsa
- Kullanıcı phishing linkine tıklayıp parola girdiyse
- Encoded PowerShell komutu çalışmışsa
- PowerShell sonrası dış bağlantı oluşmuşsa
- Aynı cihazda birden fazla alert varsa
- MFA devre dışıysa
- Olay kritik sistemde gerçekleşmişse

Risk azaltan örnekler:

- Kullanıcı olayın kendisinden kaynaklandığını doğruladıysa
- Bilinen IT bakım işlemi ise
- Link güvenli ve kurum tarafından doğrulanmışsa
- PowerShell kurumsal yönetim aracı tarafından çalıştırılmışsa
- Başarılı giriş yoksa
- Başka ilişkili alert yoksa

## 5. Kontrol Altına Alma Adımlarını Düşün

Kontrol altına alma, olayın yayılmasını veya daha fazla zarar vermesini engellemeye yönelik adımdır.

Bu proje otomatik müdahale yapmaz. Yani asistan:

- otomatik IP engellemez
- otomatik hesap kapatmaz
- otomatik cihaz izole etmez
- otomatik dosya silmez

Asistan sadece analiste öneri sunar.

Örnek öneriler:

- Kullanıcının aktif oturumlarını kontrol et.
- Kullanıcının parolasını sıfırlamayı değerlendir.
- Şüpheli mailin başka kullanıcılara gidip gitmediğini araştır.
- Endpoint üzerinde process tree bilgisini incele.
- Kaynak IP ve related alerts bilgilerini kontrol et.
- Olayı incident olarak yükseltmeyi değerlendir.

## 6. Temizleme ve Toparlanma Adımlarını Planla

Eğer olay gerçek incident olarak değerlendirilirse temizleme ve toparlanma adımları düşünülür.

Örnekler:

- Şüpheli oturumların sonlandırılması
- Parola sıfırlama
- MFA kontrolü
- Zararlı mailin karantinaya alınması
- Etkilenen cihazın detaylı incelenmesi
- Kullanıcı farkındalık bilgilendirmesi
- Güvenlik kuralı veya izleme iyileştirmesi

Bu adımlar kurum politikasına göre uygulanmalıdır. Asistan tek başına karar vermez.

## 7. Olay Sonrası Ders Çıkar

Olay kapandıktan sonra şu sorular sorulmalıdır:

- Alert doğru çalıştı mı?
- Daha erken tespit edilebilir miydi?
- Kullanıcı eğitimi gerekli mi?
- Yeni bir detection rule gerekir mi?
- Playbook güncellenmeli mi?
- Eksik log kaynağı var mı?
- Benzer olaylar tekrar ediyor mu?

Bu bölüm projenin gelişimi için de önemlidir. Çünkü RAG bilgi tabanı zamanla daha iyi hale getirilebilir.

## Asistanın Kullanacağı Genel Cevap Mantığı

Asistan bir alert, log parçası veya olay açıklaması aldığında şu sırayla cevap üretmelidir:

1. Olay Özeti
2. Olası Yorum / Hipotez
3. MITRE ATT&CK Eşleşmesi
4. Bu Yorumu Destekleyen Kanıtlar
5. Eksik Bilgiler
6. İlk Kontrol Adımları
7. Önerilen İlk Müdahale
8. False Positive İhtimali
9. Kullanılan Kaynaklar
10. Güven Düzeyi

## Önemli İlke

Asistan kesin hüküm vermemelidir.

Doğru ifade örnekleri:

- "Bu olay brute force davranışına benzeyebilir."
- "Bu e-posta phishing şüphesi oluşturabilir."
- "Bu PowerShell çalışması incelenmelidir."
- "Kesin karar için ek log bilgileri gereklidir."
- "Kaynaklarda yeterli bilgi yoksa kesin saldırı denmemelidir."

Yanlış ifade örnekleri:

- "Bu kesin saldırıdır."
- "Hesabı hemen kapat."
- "IP hemen engellenmeli."
- "Cihazı hemen sil."
- "Bu kesin malware davranışıdır."

## Senaryolara Uygulama

### Brute Force

Önce başarısız giriş sayısı, zaman aralığı, kaynak IP, hedef kullanıcı, başarılı giriş olup olmadığı ve MFA durumu kontrol edilir.

### Phishing

Önce sender, link, domain, attachment, email header, user_clicked ve credentials_entered bilgileri kontrol edilir.

### Suspicious PowerShell

Önce command_line, encoded_command, parent_process, user, endpoint_name, network_connection ve related_alerts bilgileri kontrol edilir.

## Kaynak Notu

Bu dosya NIST incident response yaklaşımının eğitim amaçlı sadeleştirilmiş bir özetidir. Gerçek kurum ortamlarında resmi politika, yasal gereklilikler ve kurumun incident response prosedürleri dikkate alınmalıdır.