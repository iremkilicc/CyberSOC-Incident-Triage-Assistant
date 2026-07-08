# Email Investigation Fields

## Amaç

Bu dosya, phishing veya suspicious email olaylarını incelerken hangi e-posta alanlarına bakılması gerektiğini açıklar.

Phishing olaylarında sadece mailin içeriğine bakmak yeterli değildir. Gönderen bilgisi, link, ek dosya, mail başlıkları ve kullanıcının ne yaptığı birlikte değerlendirilmelidir.

## Önemli Alanlar

### sender

E-postayı gönderen adresidir.

Kontrol soruları:
- Gönderen adresi gerçek kuruma ait mi?
- Domain adı taklit edilmiş mi?
- Adres kullanıcıyı kandıracak şekilde benzetilmiş mi?

### recipient

E-postayı alan kullanıcıdır.

Kontrol soruları:
- Mail sadece bir kullanıcıya mı gönderilmiş?
- Birden fazla kullanıcı hedeflenmiş mi?
- Hedef kullanıcı kritik yetkilere sahip mi?

### subject

E-postanın konu başlığıdır.

Kontrol soruları:
- Acil işlem yaptırmaya çalışıyor mu?
- Parola sıfırlama, hesap kapatma veya ödeme gibi baskı kuran ifade var mı?
- Kullanıcıyı korkutmaya veya acele ettirmeye çalışıyor mu?

### link

E-postadaki URL veya link bilgisidir.

Kontrol soruları:
- Link bilinen bir domaine mi gidiyor?
- Domain gerçek kurumla uyumlu mu?
- Link kısaltılmış mı?
- Link kullanıcıyı login sayfasına yönlendiriyor mu?

### attachment

E-postada ek dosya olup olmadığını gösterir.

Kontrol soruları:
- Beklenmeyen dosya eki var mı?
- Dosya uzantısı şüpheli mi?
- Dosya çalıştırılabilir veya makro içerebilir mi?
- Kullanıcı eki açmış mı?

### email_header

E-postanın teknik başlık bilgileridir.

Kontrol soruları:
- Gönderen sunucu beklenen sunucu mu?
- Reply-to adresi farklı mı?
- SPF, DKIM veya DMARC sonuçları başarısız mı?
- Mail yönlendirme zinciri şüpheli mi?

### domain

Linkin veya gönderen adresinin alan adıdır.

Kontrol soruları:
- Domain yeni veya bilinmeyen mi?
- Gerçek kurum domainine benzetilmiş mi?
- Yazım hatası veya karakter değişikliği var mı?

### user_clicked

Kullanıcının linke tıklayıp tıklamadığını gösterir.

Bu alan önemlidir çünkü kullanıcı linke tıkladıysa risk artar.

### credentials_entered

Kullanıcının parola, MFA kodu veya hassas bilgi girip girmediğini gösterir.

Bu alan çok kritiktir. Eğer kullanıcı kimlik bilgisi girdiyse hesap güvenliği için ek kontroller gerekir.

## Asistanın Kullanacağı Not

Phishing olaylarında tek bir belirtiyle kesin karar verilmemelidir. Gönderen adresi, link/domain, ek dosya, header bilgileri ve kullanıcı aksiyonu birlikte değerlendirilmelidir.