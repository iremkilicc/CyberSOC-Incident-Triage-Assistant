# T1566 - Phishing

## Kısa Açıklama

Phishing, saldırganın kullanıcıyı sahte e-posta, link, ek dosya veya mesaj yoluyla kandırmaya çalışmasıdır. Amaç genellikle kullanıcının kimlik bilgilerini ele geçirmek, zararlı bir dosya çalıştırmasını sağlamak veya kullanıcıyı sahte bir sayfaya yönlendirmektir.

Phishing olayları genellikle e-posta üzerinden görülür, ancak farklı iletişim kanalları üzerinden de gerçekleşebilir.

## Bu Teknik Ne Zaman Düşünülür?

Aşağıdaki durumlarda T1566 Phishing düşünülebilir:

- Kullanıcı şüpheli bir e-posta bildirdiyse
- E-postada acil parola sıfırlama veya hesap doğrulama mesajı varsa
- Bilinmeyen veya garip görünen bir link varsa
- Ekte beklenmeyen bir dosya varsa
- Gönderen adresi gerçek bir kurumu taklit ediyorsa
- Kullanıcı linke tıkladıysa veya kimlik bilgisi girdiyse
- Aynı e-posta birden fazla kullanıcıya gönderildiyse

## Tipik Kanıtlar

- suspicious email report
- sender adresi
- reply-to adresi
- subject bilgisi
- bilinmeyen URL veya domain
- attachment bilgisi
- user_clicked bilgisi
- credentials_entered bilgisi
- email header bilgileri
- aynı kampanyanın başka kullanıcılara ulaşıp ulaşmadığı

## SOC Analyst İlk Neye Bakar?

- Kullanıcı linke tıklamış mı?
- Kullanıcı parola veya MFA kodu girmiş mi?
- Gönderen adresi gerçek mi?
- Link hangi domaine gidiyor?
- Ekte dosya var mı?
- Mail başlıkları tutarlı mı?
- Aynı mail başka kullanıcılara da gitmiş mi?
- Kullanıcının hesabında sonrasında şüpheli login var mı?
- Mail gateway veya EDR uyarı üretmiş mi?

## False Positive İhtimali

Phishing şüphesi bazen gerçek saldırı olmayabilir:

- Yasal bir kurumdan gelen bildirim kullanıcıya şüpheli görünebilir.
- Reklam veya spam mail phishing sanılabilir.
- Kurum içi otomatik bildirimler dışarıdan gelmiş gibi algılanabilir.
- Link güvenli ama kullanıcı tarafından bilinmeyen bir servis olabilir.
- Güvenlik aracı yanlış pozitif üretmiş olabilir.

## İlişkili Teknikler

- T1078 - Valid Accounts
- T1003 - Credential Dumping
- T1059 - Command and Scripting Interpreter

## Kaynak Notu

Bu dosya MITRE ATT&CK T1566 Phishing tekniğinin eğitim amaçlı sadeleştirilmiş özetidir. Projede kaynaklı cevap üretimi için kullanılacaktır.