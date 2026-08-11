# Cloud Identity ve OAuth İnceleme Alanları

## Kimlik Doğrulama Alanları

- `user_principal_name`: Etkilenen kullanıcı
- `sign_in_time`: Oturum zamanı
- `source_ip`: Kaynak IP
- `location`: Ülke, bölge ve şehir
- `autonomous_system_number`: IP'nin ASN bilgisi
- `device_id`: Cihaz kimliği
- `device_compliance`: Uyumlu veya yönetilen cihaz durumu
- `user_agent`: İstemci user-agent bilgisi
- `client_app`: Tarayıcı, mobil uygulama veya başka istemci
- `authentication_requirement`: MFA gereksinimi
- `mfa_result`: MFA sonucu
- `conditional_access_status`: Conditional Access sonucu
- `risk_level`: Entra risk seviyesi
- `risk_event_type`: Impossible travel, atypical travel, anonymous IP veya anomalous token gibi risk türü
- `correlation_id`: İlişkili olayları birleştirmek için correlation ID

## OAuth Consent ve Uygulama Alanları

- `app_id`: Uygulama kimliği
- `app_display_name`: Görünen uygulama adı
- `service_principal_id`: Enterprise application/service principal kimliği
- `publisher_name`: Yayıncı adı
- `publisher_verified`: Yayıncı doğrulama durumu
- `publisher_tenant_id`: Yayıncı tenant kimliği
- `consent_actor`: İzni veren kullanıcı veya yönetici
- `consent_time`: Consent grant zamanı
- `permission_type`: Delegated veya application permission
- `permission_scopes`: Verilen izinler
- `offline_access`: Refresh token olasılığı sağlayan scope
- `application_owners`: Uygulama sahipleri

## Token Alanları

- `token_type`: Access token veya refresh token
- `resource`: Token'ın hedeflediği API veya servis
- `token_issued_at`: Token üretim zamanı
- `token_activity_time`: Token kullanım zamanı
- `source_ip`: Token kullanım kaynağı
- `user_agent`: Token istemcisi
- `session_id`: İlişkili oturum
- `correlation_id`: Consent, token ve kaynak erişimini bağlayan kimlik

## Kaynak Erişimi Alanları

- Exchange: mailbox, message ID, operation, result ve zaman
- OneDrive/SharePoint: site, dosya yolu, object ID, operation ve veri hacmi
- Microsoft Graph: resource, method, result ve uygulama kimliği
- Erişilen nesnenin hassasiyet etiketi ve paylaşım durumu
- Aynı app ID'nin eriştiği diğer kullanıcı ve kaynaklar

## Incident'a Yükseltme Göstergeleri

- Kullanıcının seyahati, VPN'i, oturumu veya uygulamayı doğrulamaması
- Doğrulanmamış yayıncı ve hassas izinlerin birlikte görülmesi
- `offline_access` ile beklenmeyen refresh token kullanımı
- Yabancı IP veya yeni cihazdan Microsoft Graph etkinliği
- Consent sonrasında posta ya da dosya erişimi
- Aynı app ID'nin birden fazla kullanıcıyı etkilemesi

## Kaynaklar

- Microsoft Entra risk detections: https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks
- Microsoft, Application permission activity logs: https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/app-perms-audit-logs
- Microsoft Graph permissions reference: https://learn.microsoft.com/en-us/graph/permissions-reference

