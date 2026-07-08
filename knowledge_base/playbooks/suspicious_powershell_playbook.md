# Suspicious PowerShell SOC Playbook

## Amaç

Bu playbook, Windows cihazlarda şüpheli PowerShell komutu çalıştığında SOC analyst’in hangi kontrolleri yapması gerektiğini açıklar.

PowerShell tek başına zararlı değildir. Sistem yöneticileri ve teknik kullanıcılar PowerShell’i normal yönetim işleri için kullanabilir. Ancak saldırganlar da PowerShell’i komut çalıştırmak, bilgi toplamak, zararlı işlem başlatmak veya aktivitelerini gizlemek için kötüye kullanabilir.

Bu yüzden PowerShell alerti görüldüğünde hemen kesin saldırı denmemeli; komutun içeriği, kullanıcı, parent process, cihaz geçmişi ve ağ bağlantıları birlikte incelenmelidir.

## Bu Olay Ne Zaman Düşünülür?

Aşağıdaki durumlar şüpheli PowerShell kullanımı oluşturabilir:

- PowerShell normal kullanıcı hesabı tarafından çalıştırılmışsa
- Encoded veya gizlenmiş komut kullanılmışsa
- PowerShell beklenmeyen bir uygulama tarafından başlatılmışsa
- Komut satırı çok uzun, karmaşık veya okunması zor görünüyorsa
- PowerShell sonrasında dış ağ bağlantısı oluşmuşsa
- Aynı cihazda başka güvenlik alertleri varsa
- Kullanıcı normalde PowerShell kullanmıyorsa
- PowerShell bir phishing maili veya şüpheli dosya açıldıktan sonra çalışmışsa

## Tipik Kanıtlar

Şüpheli PowerShell olaylarında aşağıdaki kanıtlar aranır:

- command_line bilgisi
- encoded_command kullanımı
- parent_process bilgisi
- process_name
- kullanıcı hesabı
- endpoint adı
- PowerShell’in hangi zamanda çalıştığı
- PowerShell sonrası network connection oluşup oluşmadığı
- aynı cihazdaki diğer alertler
- PowerShell’i başlatan dosya veya uygulama
- kullanıcının normal davranışına uyup uymadığı

## İlk Kontrol Adımları

SOC analyst aşağıdaki kontrolleri yapmalıdır:

1. Komutu hangi kullanıcı çalıştırdı kontrol et.
2. Kullanıcı normalde PowerShell kullanır mı incele.
3. Komut satırı içeriğini kontrol et.
4. Encoded command varsa decode edilmiş gerçek içeriğin güvenli ortamda incelenmesi gerekir.
5. PowerShell’i hangi parent process başlatmış bak.
6. Parent process beklenen bir terminal mi, yoksa Word, tarayıcı veya şüpheli dosya mı kontrol et.
7. Komut çalıştıktan sonra dış ağ bağlantısı oluşmuş mu kontrol et.
8. Aynı endpoint üzerinde başka alert var mı bak.
9. Kullanıcı yakın zamanda phishing maili açmış mı veya şüpheli linke tıklamış mı kontrol et.
10. PowerShell çalışmasından sonra dosya indirme, yeni process başlatma veya yetki değişikliği olmuş mu incele.

## Risk Artıran Durumlar

Aşağıdaki durumlar olayın riskini artırır:

- Encoded command kullanılması
- Normal kullanıcı hesabının PowerShell çalıştırması
- Parent process olarak Word, Excel, browser veya bilinmeyen bir process görülmesi
- PowerShell sonrası dış IP veya bilinmeyen domaine bağlantı oluşması
- Aynı cihazda malware, phishing veya credential alertleri olması
- Komutun dosya indirme veya başka process başlatma davranışı göstermesi
- Kullanıcının bu işlemi kendisinin yapmadığını söylemesi
- Cihazda aynı zaman aralığında başka şüpheli aktiviteler görülmesi

## False Positive İhtimali

PowerShell alerti her zaman saldırı değildir. Aşağıdaki durumlar false positive olabilir:

- Sistem yöneticisi bakım veya kontrol işlemi yapıyor olabilir.
- Kurumsal script veya yazılım dağıtım aracı PowerShell kullanıyor olabilir.
- Güvenlik aracı veya IT aracı otomatik komut çalıştırmış olabilir.
- Kullanıcı teknik bir işlem için PowerShell açmış olabilir.
- Bazı yasal yazılımlar kurulum veya güncelleme sırasında PowerShell kullanabilir.

## Önerilen İlk Müdahale

Kesin karar vermeden önce kanıtlar kontrol edilmelidir.

Şüphe düşükse:

- Komutun bilinen bir IT işlemi olup olmadığını doğrula.
- Kullanıcı veya IT ekibiyle iletişime geç.
- Cihazdaki diğer uyarıları kontrol et.
- Olayı izlemeye devam et.

Şüphe orta veya yüksekse:

- Komutun ne yaptığını güvenli şekilde incele.
- Parent process ve process tree bilgisini kontrol et.
- Cihazdan dış bağlantı olup olmadığını araştır.
- Kullanıcının son aktivitelerini incele.
- Aynı cihazda başka alert olup olmadığını kontrol et.
- Gerekirse endpoint daha detaylı inceleme için işaretlenebilir.
- Olay incident olarak yükseltilebilir.

Otomatik izolasyon, dosya silme veya process sonlandırma bu projenin kapsamında değildir. Asistan sadece analiste öneri sunar.

## Asistanın Kullanacağı Cevap İpuçları

Asistan PowerShell alerti gördüğünde kesin konuşmamalıdır.

Doğru ifade örneği:

"Bu olay şüpheli PowerShell kullanımı olabilir. Encoded command kullanılması ve normal kullanıcı hesabı tarafından çalıştırılması nedeniyle incelenmelidir. Kesin karar için command_line, parent_process, kullanıcı davranışı, endpoint geçmişi ve network bağlantıları kontrol edilmelidir."

Yanlış ifade örneği:

"Bu kesin zararlı PowerShell saldırısıdır, cihaz hemen kapatılmalıdır."

## Kullanılabilecek MITRE Eşleşmeleri

- T1059 - Command and Scripting Interpreter
- Alt bağlam olarak PowerShell kullanımı değerlendirilebilir.

## Kaynak Notu

Bu playbook eğitim amaçlı hazırlanmıştır. Gerçek bir SOC ortamında kurumun kendi endpoint güvenlik araçları, log kaynakları ve incident response prosedürleri dikkate alınmalıdır.