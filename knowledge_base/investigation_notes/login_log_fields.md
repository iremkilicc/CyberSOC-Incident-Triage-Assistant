# Login Log Fields

## Amaç

Bu dosya, login ve authentication olaylarını incelerken hangi log alanlarına bakılması gerektiğini açıklar.

Brute force, valid accounts veya suspicious login gibi olaylarda bu alanlar SOC analyst için önemlidir.

## Önemli Alanlar

### user

Giriş denemesi yapılan kullanıcı hesabıdır.

Kontrol soruları:
- Kullanıcı kritik veya yetkili bir hesap mı?
- Kullanıcı normalde bu sisteme giriş yapar mı?
- Kullanıcı bu saatlerde aktif olur mu?

### source_ip

Giriş denemesinin geldiği IP adresidir.

Kontrol soruları:
- IP daha önce görülmüş mü?
- Aynı IP başka hesapları da denemiş mi?
- IP beklenen lokasyondan mı geliyor?
- IP dış kaynak mı, iç ağ mı?

### timestamp

Olayın gerçekleştiği zamandır.

Kontrol soruları:
- Giriş denemeleri kısa zaman aralığında mı olmuş?
- Olay mesai dışında mı gerçekleşmiş?
- Başarısız denemeden sonra başarılı giriş ne zaman olmuş?

### login_status

Girişin başarılı mı başarısız mı olduğunu gösterir.

Örnek değerler:
- failed
- success
- denied
- locked

### failed_attempt_count

Belirli zaman aralığındaki başarısız giriş denemesi sayısıdır.

Kontrol soruları:
- Sayı normal kullanıcı hatasını aşacak kadar yüksek mi?
- Denemeler tek kullanıcıya mı, çok kullanıcıya mı yapılmış?

### successful_login_after_failure

Başarısız denemelerden sonra başarılı giriş olup olmadığını gösterir.

Bu alan önemlidir çünkü başarılı giriş varsa hesabın ele geçirilmiş olma ihtimali artabilir.

### target_system

Giriş denemesinin yapıldığı sistemdir.

Örnek:
- vpn-gateway
- web-portal
- ssh-server
- rdp-host
- email-system

### location

Giriş denemesinin geldiği coğrafi konum veya ağ bölgesidir.

Kontrol soruları:
- Kullanıcı normalde bu lokasyondan giriş yapar mı?
- Impossible travel şüphesi var mı?

### device

Giriş yapan veya giriş denenmiş cihaz bilgisidir.

Kontrol soruları:
- Cihaz kullanıcıya ait mi?
- Daha önce görülmüş bir cihaz mı?
- Yeni veya bilinmeyen cihaz mı?

## Asistanın Kullanacağı Not

Login logları incelenirken tek bir alanla karar verilmemelidir. Kullanıcı, kaynak IP, zaman aralığı, başarılı giriş durumu, hedef sistem ve kullanıcı davranışı birlikte değerlendirilmelidir.