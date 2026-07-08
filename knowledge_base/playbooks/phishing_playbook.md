# Phishing SOC Playbook

## Amaç

Bu playbook, kullanıcı tarafından bildirilen veya güvenlik sistemi tarafından işaretlenen şüpheli e-posta olaylarında SOC analyst’in hangi kontrolleri yapması gerektiğini açıklar.

Phishing alerti tek başına kesin saldırı anlamına gelmez. Bir e-posta gerçekten kötü niyetli olabilir, reklam/spam olabilir veya kullanıcı tarafından yanlış anlaşılmış olabilir. Bu yüzden e-posta içeriği, gönderen adresi, linkler, ek dosyalar ve kullanıcı aksiyonları kontrol edilmelidir.

## Bu Olay Ne Zaman Düşünülür?

Aşağıdaki durumlar phishing şüphesi oluşturabilir:

- E-postada acil işlem yaptırmaya çalışan bir mesaj varsa
- Kullanıcıdan parola, doğrulama kodu veya kişisel bilgi isteniyorsa
- E-postada bilinmeyen veya şüpheli bir link varsa
- Gönderen adresi gerçek kurumu taklit ediyorsa
- Ekte beklenmeyen bir dosya varsa
- Mesajda yazım hataları, garip dil veya baskı kuran ifadeler varsa
- Aynı e-posta birden fazla kullanıcıya gönderilmişse
- Kullanıcı linke tıkladığını veya bilgi girdiğini söylüyorsa

## Tipik Kanıtlar

Phishing şüphesinde aşağıdaki kanıtlar aranır:

- sender adresi
- reply-to adresi
- e-posta subject bilgisi
- link/domain bilgisi
- attachment varlığı
- email header bilgileri
- kullanıcının linke tıklayıp tıklamadığı
- kullanıcının kimlik bilgisi girip girmediği
- aynı mailin başka kullanıcılara gidip gitmediği
- güvenlik ürünlerinin mail veya link hakkında uyarı üretip üretmediği

## İlk Kontrol Adımları

SOC analyst aşağıdaki kontrolleri yapmalıdır:

1. Kullanıcı linke tıklamış mı kontrol et.
2. Kullanıcı parola, doğrulama kodu veya başka hassas bilgi girmiş mi öğren.
3. Gönderen e-posta adresini kontrol et.
4. Reply-to adresi ile gönderen adresi uyumlu mu bak.
5. E-postadaki linkin hangi domaine gittiğini kontrol et.
6. Ekte dosya var mı kontrol et.
7. Aynı e-posta başka kullanıcılara gönderilmiş mi araştır.
8. Kullanıcının hesabında şüpheli giriş veya aktivite var mı kontrol et.
9. Mail gateway, EDR veya security tool uyarısı var mı bak.
10. Gerekirse maili karantinaya alma veya kullanıcıya parola sıfırlatma önerisini değerlendir.

## Risk Artıran Durumlar

Aşağıdaki durumlar olayın riskini artırır:

- Kullanıcı linke tıkladıysa
- Kullanıcı parola veya MFA kodu girdiyse
- Mail çok sayıda kullanıcıya gönderildiyse
- Link bilinmeyen veya yeni oluşturulmuş bir domaine gidiyorsa
- Ekte çalıştırılabilir veya makro içeren dosya varsa
- Kullanıcı hesabında sonrasında şüpheli login aktivitesi görülüyorsa
- Mail, şirket içi güvenilir bir kurum gibi görünmeye çalışıyorsa
- Kullanıcı hesabı kritik yetkilere sahipse

## False Positive İhtimali

Phishing alerti her zaman gerçek saldırı değildir. Aşağıdaki durumlar false positive olabilir:

- E-posta gerçek bir kurumdan gelen yasal bildirim olabilir.
- Kullanıcı reklam veya spam maili phishing sanmış olabilir.
- Link güvenli ama kullanıcı tarafından bilinmeyen bir servis olabilir.
- Kurum içi otomatik bildirimler dışarıdan geliyormuş gibi görünebilir.
- Güvenlik aracı linki yanlış sınıflandırmış olabilir.

## Önerilen İlk Müdahale

Kesin karar vermeden önce kanıtlar kontrol edilmelidir.

Şüphe düşükse:

- Kullanıcıya maili açmaması ve linklere tıklamaması söylenir.
- E-posta ve link bilgisi kaydedilir.
- Benzer e-postalar izlenir.

Şüphe orta veya yüksekse:

- Kullanıcının linke tıklayıp tıklamadığı doğrulanır.
- Kullanıcı kimlik bilgisi girdiyse parola sıfırlama ve MFA kontrolü önerilir.
- Aynı mailin başka kullanıcılara gidip gitmediği araştırılır.
- Mail karantinaya alınabilir.
- Şüpheli domain veya URL güvenlik ekipleri tarafından incelenebilir.
- Kullanıcı hesabında olağan dışı login aktivitesi kontrol edilir.
- Olay incident olarak yükseltilebilir.

Otomatik hesap kapatma, mail silme veya domain engelleme bu projenin kapsamında değildir. Asistan sadece analiste öneri sunar.

## Asistanın Kullanacağı Cevap İpuçları

Asistan phishing şüphesi gördüğünde kesin konuşmamalıdır.

Doğru ifade örneği:

"Bu olay phishing şüphesine benzeyebilir. Çünkü e-postada acil parola sıfırlama mesajı ve bilinmeyen bir link bulunuyor. Kesin karar için gönderen adresi, link domaini, kullanıcının linke tıklayıp tıklamadığı ve kimlik bilgisi girip girmediği kontrol edilmelidir."

Yanlış ifade örneği:

"Bu kesin phishing saldırısıdır, kullanıcı hesabı hemen kapatılmalıdır."

## Kullanılabilecek MITRE Eşleşmeleri

- T1566 - Phishing

## Kaynak Notu

Bu playbook eğitim amaçlı hazırlanmıştır. Gerçek bir SOC ortamında kurumun kendi e-posta güvenlik politikaları, mail gateway kayıtları ve incident response prosedürleri dikkate alınmalıdır.