# MITRE ATT&CK T1003.001 — LSASS Memory

## Teknik Özet

Windows Local Security Authority Subsystem Service, kullanıcı oturumlarıyla ilişkili çeşitli kimlik doğrulama materyallerini süreç belleğinde tutabilir. Bir saldırgan yeterli ayrıcalık elde ettiğinde LSASS belleğine erişerek parola, hash veya oturum materyali toplamaya çalışabilir. Bu materyal daha sonra ayrıcalık artışı, alternatif kimlik doğrulama materyali kullanımı veya yatay hareket için kötüye kullanılabilir.

## SOC İçin Ana Bulgular

- LSASS sürecini hedefleyen olağandışı ProcessAccess olayı
- Beklenmeyen SourceImage, dosya yolu, parent process veya dijital imza
- Yüksek erişim hakları ve LSASS belleği okuma göstergeleri
- Kısa süre sonra oluşturulan .dmp dosyası
- Yerleşik sistem bileşeninin beklenmeyen dump davranışı
- Dump sonrasında ayrıcalıklı hesaplarla olağandışı başarılı oturumlar
- Aynı süreç ve dump göstergelerinin birden fazla endpointte görülmesi

## Yanlış Pozitif Ayrımı

Güvenlik ürünleri, hata ayıklama ve tanılama araçları LSASS erişimi üretebilir. Kaynak sürecin signer bilgisi, hash'i, kurulma yolu, allowlist durumu, değişiklik kaydı ve geçmiş davranışı doğrulanmalıdır. Tek bir erişim olayı bellek dökümü veya kimlik bilgisi kaybının kesin kanıtı olarak yazılmamalıdır.

## Müdahale İlkesi

Dump veya kimlik kötüye kullanımı doğrulanırsa süreç, dosya ve kimlik kanıtlarını koruyun. Etkilenen endpoint ve hesap müdahalesini kurum prosedürüyle ve yetkili onay altında uygulayın. Dump sırasında bellekte bulunabilecek kullanıcı, servis ve ayrıcalıklı hesapları kapsamlandırın; aynı göstergeleri kurum genelinde araştırın.

## Kaynak

- MITRE ATT&CK T1003.001: https://attack.mitre.org/techniques/T1003/001/
- MITRE ATT&CK T1003: https://attack.mitre.org/techniques/T1003/
