# MITRE ATT&CK T1528 — Steal Application Access Token

## Teknik Özet

Uygulama access token'ları, bir kullanıcı veya servis adına SaaS ve bulut API'lerine erişmek için kullanılır. Bir saldırgan access token ya da refresh token elde ettiğinde parolayı tekrar kullanmadan, token'ın izin verdiği kaynaklara erişebilir. Refresh token yeni access token üretmeye devam edebildiği için olayın süresi tek bir kısa ömürlü access token'dan daha uzun olabilir.

OAuth consent phishing senaryosunda saldırgan kontrollü bir uygulama oluşturur ve kullanıcıyı uygulamaya yetki vermeye ikna eder. Verilen izinler posta, dosya, rehber veya başka kurumsal kaynaklara erişim sağlayabilir. Bu davranış MITRE ATT&CK T1528 ile ilişkilidir.

## SOC İçin Ana Bulgular

- Yeni veya beklenmeyen OAuth consent grant kaydı
- Doğrulanmamış yayıncıya ya da tanınmayan tenant'a ait uygulama
- Mail.Read, Mail.ReadWrite, Mail.Send, Files.Read.All, Files.ReadWrite.All veya Directory.ReadWrite.All gibi hassas izinler
- `offline_access` ile refresh token elde etme olasılığı
- Uygulama ya da token tarafından yabancı IP, yeni cihaz veya olağandışı user-agent üzerinden kaynak erişimi
- Consent sonrasında Microsoft Graph, Exchange Online, OneDrive veya SharePoint etkinliği

## Risk Yükseltme Mantığı

Yalnızca yeni bir uygulama kaydı tek başına saldırı kanıtı değildir. Uygulamanın yayıncısı, sahipleri, tenant'ı, iş amacı ve izin kapsamı doğrulanmalıdır.

Doğrulanmamış uygulamaya hassas delegated izinler verilmesi Yüksek riskli kabul edilmelidir. Consent sonrasında token kullanımı ve posta ya da dosya erişimi doğrulanırsa hesap ve veri etkisi oluştuğundan olay Kritik seviyeye yükseltilmelidir.

## Toplanacak Kanıtlar

- Consent grant zamanı, aktörü, app ID, object ID ve service principal ID
- İzin türü, kapsamı ve delegated/application ayrımı
- Uygulama publisher doğrulaması, publisher tenant ve uygulama sahipleri
- Access token ve refresh token etkinliğine ait sign-in, correlation ID, kaynak IP ve user-agent
- Microsoft Graph, Exchange, OneDrive ve SharePoint audit kayıtları
- Aynı uygulamaya consent veren diğer kullanıcılar

## Güvenli Müdahale İlkesi

Consent, token ve kaynak erişim kanıtları korunmadan uygulama kaydı değiştirilmemelidir. Yetkisiz erişim doğrulanırsa consent iptali, service principal kısıtlaması, oturum/token iptali ve hesap güvenliği adımları kurum prosedürü ve yetkili onayı altında uygulanmalıdır.

## Kaynaklar

- MITRE ATT&CK T1528: https://attack.mitre.org/techniques/T1528/
- Microsoft, Protect against consent phishing: https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/protect-against-consent-phishing
- Microsoft, Review permissions granted to enterprise applications: https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-application-permissions

