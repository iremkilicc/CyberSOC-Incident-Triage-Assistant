# T1110 - Brute Force

## Kısa Açıklama

Brute force, saldırganın bir parola, kullanıcı adı veya kimlik doğrulama bilgisini tekrar tekrar deneyerek doğru değeri bulmaya çalışmasıdır.

Bu teknik özellikle login sistemleri, VPN, SSH, RDP, web uygulamaları ve diğer kimlik doğrulama noktalarında görülebilir.

## Bu Teknik Ne Zaman Düşünülür?

Aşağıdaki durumlarda T1110 Brute Force düşünülebilir:

- Kısa sürede çok sayıda başarısız giriş denemesi varsa
- Aynı kullanıcıya tekrar tekrar parola deneniyorsa
- Aynı IP adresi birden fazla kullanıcı hesabını deniyorsa
- Başarısız giriş denemelerinden sonra başarılı giriş oluşuyorsa
- Kritik kullanıcı hesapları hedefleniyorsa
- Farklı lokasyonlardan olağan dışı giriş denemeleri görülüyorsa

## Tipik Kanıtlar

- failed_login kayıtları
- repeated authentication failure
- aynı source_ip bilgisinin tekrar etmesi
- aynı user alanının tekrar etmesi
- kısa time_window içinde çok sayıda deneme
- successful_login_after_failures bilgisi
- VPN, RDP, SSH veya web login üzerinde tekrar eden başarısız denemeler

## SOC Analyst İlk Neye Bakar?

- Başarılı giriş var mı?
- Başarılı giriş olduysa sonrasında ne yapılmış?
- Kaynak IP başka hesapları da denemiş mi?
- Hedef hesap kritik mi?
- Kullanıcı normalde bu lokasyondan giriş yapar mı?
- MFA aktif mi?
- Account lockout çalışmış mı?
- Aynı zaman aralığında başka alert var mı?

## False Positive İhtimali

Brute force benzeri alertler bazen saldırı dışı nedenlerle de oluşabilir:

- Kullanıcı şifresini unutmuş olabilir.
- Bir cihaz eski şifreyle otomatik giriş deniyor olabilir.
- Servis hesabı yanlış parola ile çalışıyor olabilir.
- Uygulama yapılandırması hatalı olabilir.
- Kimlik doğrulama sisteminde geçici problem olabilir.

## İlişkili Teknikler

- T1078 - Valid Accounts
- T1566 - Phishing
- T1003 - Credential Dumping

## Kaynak Notu

Bu dosya MITRE ATT&CK T1110 Brute Force tekniğinin eğitim amaçlı sadeleştirilmiş özetidir. Projede kaynaklı cevap üretimi için kullanılacaktır.