# Cloud Identity ve OAuth Consent Abuse Playbook

## Amaç

Bu playbook; Entra ID impossible travel veya atypical travel alarmını, beklenmeyen OAuth consent grant'i ve token tabanlı posta/dosya erişimini aynı olay zaman çizelgesinde değerlendirmek için kullanılır.

## Aşama 1 — Konum Anomalisi

İki oturum coğrafi olarak uzak konumlardan, gerçek seyahat süresinden daha kısa bir aralıkta görülmüşse kimlik kötüye kullanımı hipotezi değerlendirilir. Ancak kurumsal VPN, güvenli web gateway, mobil operatör çıkışı ve kullanıcının gerçek seyahati yanlış pozitif üretebilir.

Toplanacak temel alanlar:

- Sign-in zamanı, source IP, ülke/şehir ve ASN
- Cihaz ID, uyumluluk durumu ve işletim sistemi
- User-agent, istemci uygulama ve authentication protocol
- MFA sonucu, Conditional Access kararı ve risk seviyesi
- Kullanıcının seyahat, VPN ve cihaz doğrulaması

Yalnızca impossible travel bulgusu varsa ve hesap etkisi yoksa risk genellikle Orta seviyede tutulur.

## Aşama 2 — OAuth Consent Grant

Konum anomalisi çevresinde yeni bir OAuth uygulamasına izin verildiyse Entra audit logları incelenmelidir. App ID, service principal, publisher tenant, uygulama sahipleri, consent aktörü ve izin kapsamları doğrulanmalıdır.

Şu birleşimler riski Yüksek seviyeye çıkarır:

- Kullanıcının uygulamayı veya işlemi tanımaması
- Doğrulanmamış yayıncı
- Hassas posta, dosya veya dizin izinleri
- `offline_access` izni
- Uygulamanın yeni oluşturulmuş ya da kurumda daha önce görülmemiş olması

## Aşama 3 — Token ve Kaynak Erişimi

Consent sonrasında refresh token ya da access token kullanımı görülürse token olayları kaynak erişimleriyle korele edilmelidir. Microsoft Graph, Exchange Online, OneDrive ve SharePoint aktiviteleri incelenmelidir.

Yabancı IP'den token kullanımıyla e-posta okunması, dosya indirilmesi veya değiştirilmesi hesap etkisini doğrular. Bu durumda olay Kritik seviyede ele alınır ve veri erişimi kapsamı belirlenir.

## Öncelikli SOC Aksiyonları

1. Sign-in, risk detection, audit, consent, token ve kaynak erişim loglarını koruyun.
2. Kullanıcı, app ID, service principal, IP, cihaz ve correlation ID üzerinden zaman çizelgesi oluşturun.
3. Aynı uygulamaya izin veren diğer kullanıcıları ve aynı IP'den gelen token etkinliklerini araştırın.
4. Yetkisiz grant doğrulanırsa consent iptali, service principal kısıtlaması ve token/oturum müdahalesini kurum prosedürüyle yetkili onay altında uygulayın.
5. Erişilen posta ve dosyaların hassasiyetini, işlem türünü ve olası veri ifşasını kapsamlandırın.

## Yanlış Pozitif Kontrolleri

- Kullanıcının doğruladığı seyahat veya kurumsal VPN
- Kurum tarafından onaylanmış ve sahipliği doğrulanmış uygulama
- İş ihtiyacıyla uyumlu en az ayrıcalıklı izinler
- Bilinen cihaz, IP ve normal çalışma saatleri
- Kaynak erişiminin kullanıcının beklenen faaliyetiyle uyumlu olması

## Kaynaklar

- Microsoft Entra risk detections: https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks
- Microsoft, View activity logs of application permissions: https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/app-perms-audit-logs
- Microsoft, Protect against consent phishing: https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/protect-against-consent-phishing
- MITRE ATT&CK T1528: https://attack.mitre.org/techniques/T1528/

