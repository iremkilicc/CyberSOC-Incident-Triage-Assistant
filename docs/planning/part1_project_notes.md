CyberSOC Incident Triage Assistant, kullanıcıdan gelen SOC alert, log parçası veya olay açıklamasını yorumlayan; MITRE ATT&CK, NIST Incident Response ve özel SOC playbook notlarından bilgi çekerek olayın neye benzeyebileceğini, ilk hangi kontrollerin yapılması gerektiğini ve olası müdahale adımlarını öneren offline RAG tabanlı bir analist destek asistanıdır.

Kendi cümlem:
Bu proje, bir alert geldiğinde bana “bu ne olabilir, neye bakmalıyım, ilk ne yapmalıyım?” diye yol gösteren yerel bir siber güvenlik asistanıdır.

Bu proje bir saldırı tespit sistemi değildir.

Sistem büyük ağ trafiğini veya milyonlarca logu otomatik analiz edip “saldırı var/yok” kararı vermez.

Sistem gerçek SIEM’e bağlanmaz, otomatik IP engellemez, kullanıcı hesabı kapatmaz ve sisteme doğrudan müdahale etmez.

Bu proje, kullanıcının verdiği alert/log/olay açıklamasını yorumlayan ve SOC analyst’e ilk triyaj sürecinde yardımcı olan bir karar destek asistanıdır.


## SOC nedir?
SOC, Security Operations Center demektir. Bir kurumun güvenlik olaylarını izleyen, alertleri takip eden ve şüpheli durumları inceleyen merkezidir. SOC ekibi sistemlerden gelen log ve alertleri değerlendirerek gerçek bir güvenlik olayı olup olmadığını anlamaya çalışır.

## SOC Analyst ne yapar?
SOC Analyst, gelen güvenlik uyarılarını inceleyen kişidir. Bir alert geldiğinde bunun gerçekten tehlikeli olup olmadığını, hangi kullanıcı veya sistemin etkilendiğini ve ilk hangi kontrollerin yapılması gerektiğini araştırır.

## Log nedir?
Log, sistemlerin tuttuğu olay kaydıdır. Örneğin bir kullanıcının giriş yapması, başarısız şifre denemesi, bir komut çalıştırılması veya bir bağlantı isteği log olarak kaydedilebilir.
2026-07-05 21:10 user=admin status=failed_login source_ip=192.168.1.25


## Alert nedir?
Alert, sistemin şüpheli gördüğü olay için ürettiği uyarıdır. Her alert gerçek saldırı değildir. SOC Analyst önce alertin false positive olup olmadığını ve gerçekten incident’e dönüşüp dönüşmediğini kontrol eder.


## Incident nedir?
Incident, güvenlik olayıdır. Bir alert incelendikten sonra gerçekten riskli, şüpheli veya kuruma zarar verebilecek bir durum olduğu düşünülürse incident olarak ele alınabilir. Her alert incident değildir; SOC analyst önce kanıtları kontrol eder.


## Triage / Triyaj nedir?
Triyaj, gelen alertin önceliğini ve önemini anlamaya çalışma sürecidir. SOC Analyst bu aşamada olayın neye benzediğini, ne kadar ciddi olduğunu ve ilk hangi adımları izlemesi gerektiğini belirler.

## MITRE ATT&CK nedir?
MITRE ATT&CK, saldırganların gerçek dünyada kullandığı taktik ve teknikleri anlatan bir bilgi tabanıdır. Siber güvenlikte bir olayın hangi saldırı davranışına benzediğini anlamak için kullanılır.
T1110 - Brute Force
T1566 - Phishing
T1059 - Command and Scripting Interpreter


## Tactic nedir?
Tactic, saldırganın amacıdır. Örneğin sisteme ilk giriş yapmak, yetki yükseltmek, kimlik bilgisi çalmak veya sistem içinde ilerlemek birer saldırgan amacı olabilir.


## Technique nedir?
bu amaç için kullanıdğı yöntemdir 


## NIST Incident Response nedir?
NIST Incident Response, güvenlik olaylarına nasıl hazırlanılacağı, olayların nasıl analiz edileceği ve nasıl müdahale edileceği konusunda rehberlik sağlar. MITRE daha çok saldırgan davranışını anlatırken, NIST savunmacının nasıl hareket etmesi gerektiğine yardım eder.


## Playbook / SOP nedir?
Playbook veya SOP, belirli bir olay türü geldiğinde izlenecek adımların yazılı olduğu rehberdir. Örneğin brute force alerti geldiğinde hangi loglara bakılacak, kullanıcı kontrolü nasıl yapılacak, başarılı giriş var mı diye nasıl kontrol edilecek gibi adımları içerir.


## RAG bu projede ne işe yarar?
RAG, yapay zekânın kendi kafasından cevap vermesi yerine önce verilen dokümanlarda arama yapmasını sağlar. Bu projede RAG, MITRE, NIST ve SOC playbook notlarından ilgili bilgileri bulacak ve model cevabını bu kaynaklara göre oluşturacaktır.



## Bu projede yapılacaklar

- Kullanıcıdan SOC alert, log parçası veya olay açıklaması almak
- Bu girdinin neye benzeyebileceğini yorumlamak
- MITRE ATT&CK tekniği önermek
- Olayı destekleyen kanıtları açıklamak
- Eksik bilgileri belirtmek
- İlk kontrol adımlarını listelemek
- Basit müdahale önerisi sunmak
- Kullanılan kaynakları göstermek
- Bilgi yoksa “kaynaklarda yeterli bilgi yok” demek

## Bu projede yapılmayacaklar

- Gerçek SIEM entegrasyonu
- Wazuh kurulumu
- Canlı şirket loglarıyla çalışma
- Otomatik IP engelleme
- Kullanıcı hesabı kapatma
- Sisteme otomatik müdahale
- Exploit veya saldırı kodu üretme
- Production seviyesinde SOC sistemi iddiası


## Asistan Cevap Formatı

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


Olay Özeti:
Admin kullanıcısına kısa sürede çok sayıda başarısız giriş denemesi yapılmış.

Olası Yorum:
Bu olay brute force davranışına benzeyebilir.

MITRE ATT&CK Eşleşmesi:
T1110 - Brute Force

Kanıtlar:
- Aynı kullanıcıya çok sayıda başarısız giriş var.
- Kısa zaman aralığında tekrar eden denemeler görülüyor.
- Admin hesabı hedeflenmiş.

İlk Kontrol Adımları:
1. Başarılı giriş olmuş mu kontrol et.
2. Kaynak IP başka hesapları da denemiş mi bak.
3. Kullanıcı normalde bu lokasyondan giriş yapıyor mu incele.
4. MFA ve account lockout politikalarını kontrol et.

Güven Düzeyi:
Orta. Daha net karar için başarılı giriş sonrası aktiviteler ve IP geçmişi incelenmeli.






## Demo Senaryosu 1: Brute Force Alert
bir hesaba kısa sürede çok fazla şifre dneemsi yapılması

Kullanıcı input:
Multiple failed login attempts for user admin from the same IP within 5 minutes. After several failed attempts, one successful login was observed.

Asistan ne cevaplamalı?
Bu olay brute force veya password guessing davranışına benzeyebilir. Başarılı giriş olduğu için risk artar. İlk olarak başarılı giriş sonrası aktiviteler, kaynak IP geçmişi, hedef kullanıcının kritikliği, aynı IP’nin başka hesaplara deneme yapıp yapmadığı ve MFA durumu kontrol edilmelidir.

Beklenen MITRE:
T1110 - Brute Force
T1078 - Valid Accounts ihtimali de kontrol edilebilir.

Kullanılacak kaynaklar:
MITRE T1110 özeti, MITRE T1078 özeti, Brute Force SOC Playbook, NIST incident response notu.




## Demo Senaryosu 2: Phishing Alert
kullanıcıya sahte mail gelmesi 

Kullanıcı input:
A user reported a suspicious email containing an urgent password reset message and an unknown link.

Asistan ne cevaplamalı?
Bu olay phishing şüphesi olabilir. Kullanıcının linke tıklayıp tıklamadığı, mail gönderen adresi, link domaini, mail başlıkları, ek dosya olup olmadığı ve aynı mailin başka kullanıcılara gidip gitmediği kontrol edilmelidir.

Beklenen MITRE:
T1566 - Phishing

Kullanılacak kaynaklar:
MITRE T1566 özeti, Phishing SOC Playbook, NIST incident response notu.






## Demo Senaryosu 3: Suspicious PowerShell Command
Windows bilgisayarda şüpheli PowerShell komutu çalışması.(terminal)

Parent process: PowerShell’i hangi programın başlattığını gösterir. Örneğin PowerShell normal bir admin terminalinden mi açıldı, yoksa Word, tarayıcı veya bilinmeyen bir dosya tarafından mı başlatıldı? Eğer Word veya tarayıcı gibi beklenmeyen bir program PowerShell başlattıysa bu daha şüpheli olabilir.

Kullanıcı input:
PowerShell executed an encoded command on a Windows endpoint. The command was started by a normal user account.

Asistan ne cevaplamalı?
Bu olay şüpheli komut çalıştırma davranışına benzeyebilir. Encoded PowerShell komutları zararlı aktivitelerde kullanılabilir, ancak kesin saldırı demek değildir. Komutun içeriği, çalıştıran kullanıcı, endpoint geçmişi, parent process, ağ bağlantıları ve aynı cihazdaki diğer uyarılar kontrol edilmelidir.

Beklenen MITRE:
T1059 - Command and Scripting Interpreter
Alt bağlam olarak PowerShell kullanımı değerlendirilebilir.

Kullanılacak kaynaklar:
MITRE T1059 özeti, Suspicious PowerShell Playbook, Endpoint Investigation Notes.




