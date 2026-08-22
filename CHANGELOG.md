# Changelog

MUVON sürüm değişikliklerinin kaydı. Bu dosya repo kökünde tutulur; her
GitHub Release notu (`gh release view vX.Y.Z`) buradaki bölümün bir
kopyasıdır.

Versiyonlama: [Semantic Versioning](https://semver.org/lang/tr/). `0.x`
sürümleri sırasında breaking değişiklikler minor (`0.1` → `0.2`)
seviyesinde gelebilir. `1.0.0` ticari yayın hazırlığı sinyali olacak.

Başlıklar (Gitea taksonomisi):

- `BREAKING` — geriye dönük uyumsuz değişiklikler (önce oku)
- `SECURITY` — güvenlik düzeltmeleri
- `FEATURES` — yeni özellikler
- `ENHANCEMENTS` — mevcut davranış iyileştirmeleri
- `BUGFIXES` — kusur düzeltmeleri

Upgrade'den önce: PostgreSQL ve volume'larınızı yedekleyin. Migration'lar
**forward-only**'dir; downgrade desteklenmez.

---

## [Unreleased]

Henüz birikme yok.

---

## [0.2.3] - 2026-08-23

Yedek almayı bağımsız bir yetenek haline getiren sürüm. Şema değişikliği yok;
yalnızca merkezi güncellemek yeterli, agent'ları güncellemeye gerek yok.

### FEATURES

- **Panelden yedek alınabiliyor.** Ayarlar → Sistem altına "Yedek al" düğmesi
  ve yedek listesi eklendi. Önceden yedek almanın tek yolu bir sistem
  yükseltmesi başlatmaktı; yükseltilecek bir şey yoksa yedek de alınamıyordu,
  yani riskli bir işten önce yedek almanın yolu yoktu.

  Yedek, yükseltmenin kullandığı akışın aynısından geçer: dosya `.part` adıyla
  yazılır, başlık kontrolünden ve veritabanının kendi imajıyla çalıştırılan
  `pg_restore -l` doğrulamasından geçerse yayınlanır, geçemezse `.rejected`
  uzantısıyla saklanır ve yedek sayılmaz. Panel doğrulanmış ile doğrulanamamış
  yedeği ayırt eder.

  Son 5 yedek tutulur, eskiler yeni bir yedek alındığında silinir. Bu sınır
  daha önce yoktu ve bir kurulumda 5,5 GB'lık ölü dosya birikmişti. Yükseltme
  ve yedek aynı kilidi paylaşır, çünkü ikisi de aynı veritabanını aynı dizine
  döker.

### Upgrade notları

Düğme merkezde çalışır: `muvon` ve `muvon-deployer` güncellendiğinde Ayarlar →
Sistem altında görünür. Edge agent'larını güncellemenize gerek yok.

Yedekler deployer container'ındaki `/var/lib/muvon/backups` dizinine, yani
compose'daki `backups` volume'üne yazılır. Kurulum script'inin aldığı yedekler
host üzerinde `/opt/muvon/backups` altında durmaya devam eder; ikisi ayrı
yerlerdir ve saklama sınırı yalnızca ilkine uygulanır.

Doğrulamayı geçemeyen bir yedek `.rejected` uzantısıyla saklanır ve listede
görünmez. Bu dosyalar budanmaz; ne üretildiğini inceleyip elle silmeniz
beklenir.

```bash
# Central:
bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install.sh) --version 0.2.3
```

---

## [0.2.2] - 2026-08-22

TLS sertifikalarının otomatik yenilenmesini onaran sürüm. Şema değişikliği yok.
Yenileme düzeltmesi agent tarafında, DNS ve uyarı düzeltmeleri merkezde çalışır.

### BUGFIXES

- **Sertifikalar süresi dolana kadar hiç yenilenmiyordu.** Agent, kendi
  ürettiği sertifikayı merkeze yedek olarak gönderiyor, sonra her TLS el
  sıkışmasında o yedeği merkezden geri okuyordu. autocert hiç çağrılmadığı için
  30 günlük yenileme zamanlayıcısı hiç kurulmuyordu; sertifika dolana kadar
  bekleniyor, dolduğu anda devreye giren kurtarma yolu yenisini alıyordu. Sonuç
  her domain için bitiş anında kısa bir TLS kesintisiydi. Bir üretim filosunda
  36 domain'in tamamı ilk üretimden beri bu durumdaydı; agent'ın yerel ACME
  önbelleğindeki dosyalara üç aydır dokunulmamıştı.

  Artık sıra şöyle: operatörün elle yüklediği sertifika her zaman kazanır,
  onun dışında sertifikayı üreten autocert yönetir, merkezdeki kopya ise asıl
  amacına döner ve yalnızca agent'ta yerel kopya yokken (soğuk başlangıç)
  kullanılır. O durumda yerel önbelleğe de yazılır, böylece sahiplik autocert'e
  geçer. Yenileme artık bitişten 30 gün önce, eski sertifika hâlâ geçerliyken
  arka planda yapılıyor, yani kesinti ortadan kalkıyor. ACME cevap veremezse
  merkezdeki geçerli yedek sunulmaya devam ediyor.

- **Cloudflare arkasındaki domain'ler panelde "Yanlış IP'ye yönlendiriyor"
  diye işaretleniyordu.** Kontrol, çözülen adresi origin IP'siyle karşılaştırıp
  eşleşmeyince hata veriyordu; önde bir CDN olma ihtimali hesaba katılmamıştı.
  Turuncu bulut açık her domain kalıcı olarak uyarı gösteriyordu, bu da gerçek
  uyarıları görünmez kılıyordu. Artık tüm cevaplar Cloudflare aralığındaysa
  durum `proxied` olarak raporlanıyor.

### ENHANCEMENTS

- **Sertifika bitişi artık uyarı üretiyor.** Kalan gün sayısı panelde zaten
  görünüyordu ama filo çapında bir yenileme arızası üç ay boyunca fark
  edilmedi, çünkü görmek için birinin bakması gerekiyordu. diaLOG artık altı
  saatte bir kontrol edip 14 günün altına düşen sertifikalar için normal
  alerting yolundan (Slack, e-posta) uyarı çıkarıyor. Eşik bilerek 30 değil 14:
  yenileme 30 gün kala çalıştığı için 14 güne inmiş bir sertifika "zamanı
  geldi" değil, "yenileme yapılmıyor" demektir.

### Upgrade notları

Yenileme düzeltmesi **agent tarafında** çalışır, yani edge host'ları
güncellemeden sertifikalar yenilenmeye başlamaz. Merkezi güncellemek DNS
durumunu ve bitiş uyarısını devreye sokar.

Agent güncellendikten sonraki ilk TLS el sıkışmasında autocert mevcut
sertifikayı sahiplenir. Bitişine 30 günden az kalmışsa yenileme zamanlayıcısı
geçmiş bir tarihle kurulur ve yenileme hemen arka planda yapılır; eski
sertifika hâlâ geçerli olduğu için kesinti olmaz. Yani süresi yaklaşmış
sertifikalar için ayrıca bir şey yapmanız gerekmez.

Bu sürümden sonra sertifikaların sahibi autocert'tir. Bir domain için elle
sertifika kullanmak isterseniz panelden yükleyin: operatörün yüklediği
sertifika her zaman öncelikli kalır. Merkezde saklanan ACME kopyaları artık
yalnızca agent'ın yerel önbelleği boşsa (soğuk başlangıç) devreye girer.

```bash
# Central:
bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install.sh) --version 0.2.2

# Agent (her edge sunucusunda):
bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install-agent.sh) --version 0.2.2
```

---

## [0.2.1] - 2026-08-22

v0.1.52'de eklenen yedek doğrulaması sağlam yedekleri reddedip yükseltmeyi
durduruyordu. Bu sürüm o hatayı ve onu teşhis etmeyi imkânsız kılan sessizliği
düzeltir. Şema değişikliği yok.

### BUGFIXES

- **Yedek doğrulaması sağlam yedeği bozuk sanıyor, yükseltmeyi iptal
  ediyordu.** Doğrulama, `pg_restore -l` komutunu veritabanının kendi imajından
  türetilen kısa ömürlü bir container'da çalıştırıyor. O imaj `postgres`
  kullanıcısına düşüyor, dump dosyası ise `0600 root` yazılıyor; sonuç izin
  hatası ve exit 1. Kod bunu "dump doğrulamayı geçemedi" diye okuyup yükseltmeyi
  durduruyordu. Aynı dosya root ile açıldığında sorunsuz okunuyor, yani yedekler
  baştan beri sağlamdı. Doğrulama container'ı artık root çalışıyor ve depolamayı
  salt okunur bağlıyor.

- **Başarısız yükseltme sunucuda hiçbir iz bırakmıyordu.** Yükseltme adımları
  yalnızca gRPC akışıyla tarayıcıya gidiyordu; operatör sekmeyi kapattığında ya
  da bağlantı koptuğunda hatanın nedeni hiçbir yerde kalmıyordu. "Sunucu log'una
  bak" demek anlamsızdı, çünkü log boştu. Her adım artık deployer'ın container
  log'una da yazılıyor, hatalar error seviyesinde.

- **Reddedilen yedek siliniyordu.** Doğrulamayı geçemeyen dosya artık
  `.rejected` uzantısıyla saklanıyor ve yolu hem hata mesajında hem log'da
  belirtiliyor, böylece ne üretildiği sonradan incelenebilir. Sağlam sanılıp
  kullanılma riski yok, çünkü adı `pgdata-*.dump` kalıbına uymuyor.

### Upgrade notları

v0.1.52 veya v0.2.0'da panelden yükseltme denediyseniz ve "backup failed,
upgrade aborted" hatası aldıysanız, yedeğiniz büyük olasılıkla sağlamdı; bu
sürümden sonra aynı yükseltme sorunsuz tamamlanır.

Bu sürüme geçerken yedek doğrulaması hâlâ eski (hatalı) kodla çalışacağı için
yükseltmeyi **yedek kutusunu işaretlemeden** başlatın, ya da önce elle bir yedek
alıp doğrulayın:

```bash
docker exec muvon-postgres pg_dump -Fc -U muvon -d muvon > muvon-$(date +%Y%m%d).dump
pg_restore -l muvon-$(date +%Y%m%d).dump | head
```

---

## [0.2.0] - 2026-08-22

Ziyaretçi konumunun kaynağı değişti: yerel MaxMind veritabanı kaldırıldı,
yerini Cloudflare'in ziyaretçi başlıkları aldı. Minor sürüm, çünkü bir özellik
kaldırılıyor ve Cloudflare arkasında olmayan kurulumlar konum bilgisini
tamamen kaybediyor. Bir şema migration'ı var, eklemeli.

### BREAKING

- **Yerel GeoIP veritabanı kaldırıldı; konum artık Cloudflare'den geliyor.**
  MUVON, ülke ve şehir bilgisini MaxMind GeoLite2 dosyasından okumayı bıraktı.
  Bunun yerine Cloudflare'in ziyaretçi konum başlıklarını (`CF-IPCountry`,
  `CF-IPCity`) kenarda damgalıyor; güven modeli istemci IP'siyle aynı, yani
  istek hem bir Cloudflare edge'inden gelmeli hem de operatörün paylaşılan
  sırrını taşımalı. Aksi halde herkes kendi ülkesini seçebilirdi.

  **Etkisi:** `geoip_enabled` ve `geoip_db_path` ayarları, Ayarlar sayfasındaki
  GeoIP bölümü, panodaki "GeoIP çalışmıyor" uyarı bandı, `geoip` volume'ü ve
  kurulum script'indeki MaxMind lisans adımı kaldırıldı. `country` ve `city`
  kolonları duruyor: eski satırlar olduğu gibi kalır, yeni satırları artık
  Cloudflare doldurur. Cloudflare arkasında olmayan host'larda konum boş kalır,
  çünkü isteği başka hiçbir şey bilmiyor.

### Upgrade notları

Konumun dolması için proxy'lediğiniz her Cloudflare zone'unda iki şey gerekir:

1. **Managed Transforms → Add visitor location headers** açık olmalı.
   `CF-IPCountry` ve `CF-IPCity` bunu gerektirir.
2. **Transform Rules → Modify Request Header → Set static** ile paylaşılan sır
   başlığı eklenmeli: ad `X-Muvon-CF-Key` (veya `AGENT_CLOUDFLARE_IP_HEADER` /
   `MUVON_CLOUDFLARE_IP_HEADER` ile değiştirdiğiniz ad), değer o host'u
   sonlandıran binary'nin sırrı: edge host'lar için ilgili agent'ın
   `AGENT_CLOUDFLARE_IP_SECRET` değeri, central host'lar için
   `MUVON_CLOUDFLARE_IP_SECRET`.

İkinci madde zaten gerçek istemci IP'si için de gerekliydi; eksikse MUVON
isteği güvenilmez sayar, log'lara Cloudflare edge IP'si düşer ve konum boş
kalır. **Sır her agent'ta ayrıdır**, bir zone'daki kuralı başka bir agent'ın
domain'ine kopyalamak sessizce çalışmaz.

Cloudflare kullanmıyorsanız bu sürümden sonra ülke ve şehir alanları boş
kalır. GeoLite dosyanız artık okunmuyor; `muvon_geoip` volume'ü elle
silinebilir.

Migration eklemeli çalışır: `geoip_enabled` ve `geoip_db_path` satırları
`settings` tablosundan silinir. Şema değişikliği yoktur.

```bash
# Central:
bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install.sh) --version 0.2.0

# Agent:
bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install-agent.sh) --version 0.2.0
```

---

## [0.1.52] - 2026-08-22

Panelde görünen bir değerin gerçekte uygulanmadığı bir dizi hatanın
düzeltmesi. Yedekleme kusuru veri kaybı riski taşıdığı için önce onu okuyun.
İki şema migration'ı var, ikisi de eklemeli.

### BUGFIXES

- **Panelden alınan her PostgreSQL yedeği bozuktu.** Sistem yükseltmesi
  sırasında çalışan `pg_dump -Fc`, çıktısını container log'ları için yazılmış
  satır ayrıştırıcısından geçiriyordu. O ayrıştırıcı satır sonlarına göre
  bölüp sondaki CR ve LF baytlarını kırpıyor, yani sıkıştırılmış ikili
  arşivden **her `0x0A` baytını siliyordu**. Akış "yedek alındı" diyordu ama
  ortaya çıkan dosyada `pg_restore` çöküyordu. Bir üretim sunucusunda bu
  şekilde yazılmış 34 arşivin (4,1 GB) tamamı açılamaz durumdaydı ve
  hiçbirinde tek bir satır sonu baytı kalmamıştı. Kurulum script'inin aldığı
  yedekler bu koddan geçmediği için sağlamdır. Yedek artık ikili akış olarak
  doğrudan diske yazılıyor, çerçeve ortasında kopan bir bağlantı hata
  sayılıyor, dosya `.part` adıyla yazılıp yalnızca başlık kontrolünden ve
  veritabanının kendi imajıyla çalıştırılan `pg_restore -l` doğrulamasından
  geçerse yayınlanıyor. Yedek isteyip alamayan bir yükseltme artık sessizce
  devam etmek yerine duruyor. **Elinizdeki eski `pgdata-*.dump` dosyalarına
  güvenmeyin; `pg_restore -l` ile teker teker doğrulayın.**

- **"Sertifikayı yenile" komutu sertifika yenilemiyordu.** Komut yalnızca
  bellek içi önbelleği temizleyip "bir sonraki handshake'te yenilenecek"
  diyerek başarı bildiriyordu. Sertifika hâlâ geçerliyken autocert yeniden
  sertifika almaz, yani hiçbir şey olmuyordu. Bir üretim sunucusunda dokuz
  komut da başarılı döndü ve tek bir sertifika yenilenmedi; gerçek yenileme
  ancak merkezdeki kayıt elle silinince gerçekleşti. Artık komut bitişe 30
  günden az kaldıysa sertifikayı hemen alıyor, kalmadıysa hiçbir şey yapmadan
  bulduğu bitiş tarihini bildiriyor. Erken yenileme istenirse "zorla" seçeneği
  var: bu durumda merkezdeki kayıt da bırakılıyor, çünkü servis yolunda o kopya
  öncelikli ve silinmeden yeni sertifika kullanılmıyor. Zorlamanın Let's
  Encrypt kotasından düştüğü ve kısa bir kesinti yarattığı panelde yazıyor.

- **Servis ayarlarını düzenlemek çalışan container'ı değiştirmiyordu, panel de
  bunu söylemiyordu.** env değişkenleri, ağlar, mount'lar ve komut container
  yaratılırken uygulanır. Kaydedince form yeni değeri gösteriyor, container ise
  eskisiyle çalışmaya devam ediyordu; aradaki farkı görmenin hiçbir yolu yoktu.
  Aynı desen daha önce ağ adı düzeltmesinde de yaşandı, servisler tek tek
  yeniden deploy edilene kadar düzelme gelmemişti. Artık her container hangi
  ayarlarla yaratıldığını taşıyor ve kayıtlı ayarlar farklıysa serviste
  "deploy bekliyor" rozeti çıkıyor. Düzenleme formu da kaydetmenin çalışan
  container'ı değiştirmediğini açıkça söylüyor. Yalnızca yeniden yaratmayı
  gerektiren alanlar sayılıyor; sağlık kontrolü, drain süresi gibi bir sonraki
  deploy'da zaten geçerli olan alanlar boşuna uyarı üretmiyor.

- **Ayarlardaki log saklama süresi hiçbir şeyi yönetmiyordu.** Panel
  `log_retention_days` anahtarına yazıyordu, hiçbir kod o anahtarı okumuyordu
  ve verinin ne kadar saklanacağını migration'a sabit yazılmış 30 günlük
  TimescaleDB politikaları belirliyordu. Alan boşken bile dolu görünüyordu,
  çünkü kaydedilmemiş her ayar için önerilen varsayılan gerçek değermiş gibi
  gösteriliyordu. Artık `retention_days` ayarı beş hypertable'ın tamamında
  gerçekten uygulanıyor (diaLOG değişiklikte ve beş dakikada bir uzlaştırıyor),
  `0` "hiç silme" anlamına geliyor ve panel Timescale'in o an uyguladığı
  değeri rozetlerle gösteriyor.

- **Ayarlar sayfasındaki dört kontrol hiçbir yere bağlı değildi.** ACME
  e-postası ve staging bayrağı okunmayan anahtarlara yazılıyordu, yani
  Let's Encrypt hesabında iletişim adresi hiç oluşmuyordu; genel istek limiti
  ve backend zaman aşımı alanları route bazlı ayarların kopyasıydı; partition
  ön-oluşturma alanının karşılığı ise üründe hiç yoktu. Yanlış anahtara
  yazılmış değerler migration ile doğru anahtara taşınıyor (silmeden önce
  kopyalanıyor), karşılığı olmayan kontroller kaldırıldı. Saklama süresi
  taşınırken pencere yalnızca büyütülüyor, asla küçültülmüyor: bir yükseltme
  log silmeye karar vermemeli.

- **Log işleme hattının dört ayarı hiçbir şeyi değiştirmiyordu.**
  `log_pipeline_buffer`, `log_worker_count`, `log_batch_size` ve
  `log_flush_interval_ms` veritabanına yazılıyor ve okunuyordu, ama hattı
  kuran kod yalnızca ortam değişkenlerine bakıyordu. Artık bu ayarlar
  gerçekten uygulanıyor. Yalnızca servis başlarken devreye girerler, çünkü
  çalışan bir hattı yeniden boyutlandırmak elindeki kayıtları düşürmek
  demektir; sunucuda açıkça `DIALOG_*` değişkeni verilmişse o kazanır.
  Geçerli değerler açılışta log'a yazılıyor.

- **Ayarların elle yeniden yüklenmesi gerektiği yazıyordu.** MUVON ve diaLOG
  zaten birkaç saniyede bir config'i tazeliyor; Dashboard'daki düğme sadece
  bunu hemen tetikliyor ve agent'lara gönderiyor.

### ENHANCEMENTS

- **Tarayıcı telemetrisinin örnekleme ayarları panele eklendi.**
  `rum_sample_rate` ve `rum_max_batch_bytes` kod tarafından okunuyor,
  tarayıcılara sunuluyor ve agent'lara gönderiliyordu, ama panelde kontrolleri
  yoktu; değiştirmenin tek yolu doğrudan API çağrısıydı.

### Upgrade notları

**Mevcut yedeklerinizi doğrulayın.** Panelin sistem yükseltmesiyle alınmış her
`pgdata-*.dump` dosyası bozuk; bu sürümden önce yazılmış olanlar kurtarılamaz.
Elinizde başka yedek yoksa yükseltmeden önce bir tane alın:

```bash
docker exec muvon-postgres pg_dump -Fc -U muvon -d muvon > muvon-$(date +%Y%m%d).dump
pg_restore -l muvon-$(date +%Y%m%d).dump | head   # doğrulayın, boş çıkmamalı
```

Bu sürümden sonra panelden alınan yedekler `pg_restore -l` ile otomatik
doğrulanır ve doğrulama başarısızsa yükseltme durur. Yedek isteyip
alamayacağınız bir durumda yükseltmeye devam etmek isterseniz yedek kutusunu
işaretlemeden çalıştırın.

İki migration eklemeli çalışır: `deploy_instances`'a `spec_hash` kolonu eklenir
(mevcut satırlar boş kalır, "bilinmiyor" sayılır) ve okunmayan anahtarlara
yazılmış ayarlar doğru anahtarlara taşınıp artık kayıtlar silinir. ACME e-postanızı
panelden girdiyseniz bu migration onu `letsencrypt_email` alanına taşır, yani
Let's Encrypt hesabınızda ilk kez gerçek bir iletişim adresi oluşur.

Log saklama süresi artık `retention_days` ayarından yönetiliyor ve varsayılan
30 gün olarak uygulanmaya devam eder. Daha uzun saklamak istiyorsanız
yükseltmeden sonra Ayarlar → Log Retention'dan değiştirin; küçültmek
kapsam dışındaki chunk'ları bir gün içinde kalıcı olarak siler.

```bash
# Central:
bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install.sh) --version 0.1.52

# Agent:
bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install-agent.sh) --version 0.1.52
```

---

## [0.1.51] - 2026-07-29

Çok projeli sunucularda ortaya çıkan iki sessiz hatanın düzeltmesi. Şema
migration'ı yok; sadece image güncellemesi gerekir.

### BUGFIXES

- **Aynı sunucuda birden çok proje barındırıldığında servisler birbirinin ağ
  adını kapıyordu.** Bir servis, ağlara yalnızca kendi slug'ıyla bağlanıyordu.
  Tek projeli bir sunucuda bu sorun değil, ama aynı sunucuda iki projenin de
  `api` adlı bir servisi olduğunda iki container aynı adı paylaşımlı proxy
  ağında birden talep ediyor. Docker bu durumda adı sırayla dağıtıyor, yani
  `http://api:8000` adresine giden bir kardeş servis rastgele bir projenin
  API'sine düşüyor. Canlı bir sunucuda dört container'ın `api`, dördünün
  `landing`, ikisinin `admin` adını paylaştığı görüldü. Hiçbir şey hata
  vermediği için sessizce yanlış veri servis edilebiliyordu.

  Container'lar artık ek olarak `<proje>-<servis>` adını da taşıyor. Kısa ad
  korundu, dolayısıyla mevcut env değerleri çalışmaya devam ediyor; operatör
  hazır olduğunda belirsizliği olmayan uzun ada geçebilir. İki projenin aynı
  sunucuda çalıştığı her kurulumda `SERVER_API_URL` benzeri değerlerin uzun ada
  çevrilmesi önerilir.

- **`GET /api/alerts/stats` her çağrıda 500 dönüyordu.** Toplamları hesaplayan
  sorgu `alerts` tablosunu şema niteleyicisi olmadan yazıyordu; aynı fonksiyondaki
  diğer iki sorgu zaten `dialog.alerts` kullanıyordu. `muvon` binary'si
  `search_path=public,paradedb` ile çalıştığı için tablo hiçbir zaman görünmüyor,
  handler da hatayı 500'e çeviriyordu. Sonuç: admin panelindeki Alerts sayfasının
  istatistik bloğu kalıcı olarak boştu. v0.1.1'de düzeltilen aynı sınıf hatanın
  gözden kaçmış son örneğiydi; admin'den çağrılan 65 sorgu tarandı, başka vaka yok.

### ENHANCEMENTS

- **Aralıklı başarısız olan bir test kararlı hale getirildi.** Kurcalanmış imza
  testi, base64url imzasının son karakterini değiştiriyordu. 32 baytlık bir HMAC
  43 karaktere kodlanıyor ve son karakterin yalnızca 4 biti anlamlı, kalan 2 bit
  dolgu. Değişiklik bu yüzden sık sık aynı imza baytlarına çözülüyor ve token
  geçerli kalıyordu. Artık tam 6 bit taşıyan ilk karakter değiştiriliyor.

### Upgrade notları

Alias düzeltmesi container'ı yaratan deployer'da çalışır: central servisler için
`muvon-deployer`, edge servisleri için ilgili agent bu sürüme yükseldikten sonra
etkin olur. Yeni ad bir sonraki deploy'da geçerli olur.

Aynı sunucuda birden fazla proje çalıştırıyorsanız, yükseltmeden sonra
servisler arası env değerlerini uzun ada çevirin, örneğin
`SERVER_API_URL=http://<proje>-api:8000`. Kısa ad çalışmaya devam eder ama çok
projeli bir sunucuda hangi projeye gideceği garanti değildir.

```bash
# Central:
bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install.sh) --version 0.1.51

# Agent:
bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install-agent.sh) --version 0.1.51
```

---

## [0.1.50] - 2026-07-26

Component pause'un düzeltilmesi ve gerçek istemci IP entegrasyon dokümanı. Şema
migration'ı yok.

### BUGFIXES

- **Component `paused` alanı API'den set edilemiyordu; artık çalışıyor ve
  gerçekten durduruyor.** `componentRequest` struct'ında `paused` alanı yoktu,
  bu yüzden PUT/POST update handler'ı değeri body'den hiç okumuyor, DB'deki
  değer create anındaki default'ta (`false`) sabit kalıyordu. DB ve query
  katmanı `paused`'u destekliyor olmasına ve dokümanların pause'u bir "durdurma"
  primitive'i olarak tarif etmesine rağmen, operatörün bir component'i
  duraklatmasının hiçbir yolu yoktu.

  Ayrıca pause fiilen yalnız yeni deploy'u reddediyordu; çalışan instance'a
  dokunmuyor, proxy ona trafik göndermeye devam ediyordu. Artık `paused: true`
  yapıldığında component'in active instance'ları draining'e alınıyor (sahibi
  deployer central ya da edge olsun bir sonraki tick'te container'ları durdurup
  kaldırıyor, reload sonrası proxy hemen trafiği kesiyor). `paused: false` yeni
  deploy'lara izin verir; instance'ı geri getirmek için bir deploy (veya
  rollback) gerekir. Bu, bir component'i config'ini kaybetmeden durdurmak için
  DELETE + yeniden yaratma zorunluluğunu ortadan kaldırır.

### ENHANCEMENTS

- **Gerçek istemci IP'si için entegrasyon dokümanı**: `docs/client-ip.md`. MUVON'un
  gönderdiği iki başlığın (`X-Real-IP` otoriter tek değer, `X-Forwarded-For` hop
  zinciri) anlamını, uygulamaların `MUVON_EDGE_IP` ile nasıl kapı kurması
  gerektiğini, FastAPI/ASGI ile Django için hazır middleware örneklerini, sık
  yapılan hataları (sunucunun kendi proxy-header katmanını açık bırakmak,
  `--forwarded-allow-ips=*`, container adresini sabit yazmak) ve doğrulama
  adımlarını içeriyor. Dokümandaki iki kod örneği de davranış testinden geçirildi.

---

## [0.1.49] - 2026-07-20

Forwarding başlıklarının sektörel standarda oturtulması. Şema migration'ı yok.

### SECURITY

- **Cloudflare paylaşılan secret'ı artık log'lara yazılmıyor.** İstek başlıkları
  SIEM'e kaydedilirken, CDN güvenini kanıtlayan secret başlık da (varsayılan
  `X-Muvon-CF-Key`, operatör adlandırdıysa o ad) diğerleriyle birlikte düz metin
  saklanıyordu. Log okuma yetkisi olan biri bu değeri alıp `CF-Connecting-IP`
  uydurarak bir isteğin hangi IP'ye atfedileceğini belirleyebilirdi. Başlık artık
  yakalama anında düşürülüyor.
- **Güvenilmeyen bir peer'in şema iddiası artık dikkate alınmıyor.** Düz HTTP ile
  bağlanan bir istemci `X-Forwarded-Proto: https` göndererek arkadaki uygulamaya
  isteğin güvenli olduğunu söyletebiliyordu. Bu iddia yalnız güvenilir bir
  upstream'den kabul ediliyor; TLS burada sonlandıysa o zaten otoriter.

### BUGFIXES

- **`X-Forwarded-For` zinciri doğru üretiliyor.** Proxy `Director` yerine
  `Rewrite` hook'una geçti. `Director` kullanılırken net/http/httputil, hook
  döndükten *sonra* TCP peer'ini zincire kendisi ekliyordu; hook bunu ne
  görebiliyor ne engelleyebiliyordu. Sonuçları: doğrudan bağlanan istemcilerde
  aynı adres iki kez yazılıyordu (`"1.2.3.4, 1.2.3.4"`), CDN arkasında ise
  zincirin son hop'u CDN edge'i olarak kalıyordu. Zinciri sağdan sola okuyan
  backend'ler (uvicorn, Rails, ASP.NET bu şekilde çalışır) bu yüzden CDN'i
  istemci sanabiliyordu.

  Yeni davranış, büyük proxy'lerin tamamının uyguladığı append semantiğidir:
  güvenilir bir upstream'in bildirdiği zincir korunur, isteğin geldiği hop bir
  kez eklenir, güvenilmeyen bir peer'in sunduğu zincir düşürülür.

- **Cloudflare artık güvenilir upstream sayılıyor.** Zincir ve şema kararları
  yalnız `trusted_proxies` listesine bakıyordu; paylaşılan secret'ı doğrulanmış
  bir CDN edge'i bu listede olmadığı için güvenilmez sayılıyor ve raporladığı
  zincir düşürülüyordu. Artık istemci IP'sini çözen mantıkla aynı kapı
  kullanılıyor, dolayısıyla ikisi kimin güvenilir olduğu konusunda ayrışamaz.

### Sözleşme

Arkadaki uygulamalar için: `X-Forwarded-For` **zinciri** taşır (denetim ve hop
sayan backend'ler için), `X-Real-IP` ise MUVON'un otoriter olarak çözdüğü **tek
istemci adresidir**. Zincirin hangi ucunun istemci olduğu araya CDN girip
girmediğine göre değişir; uygulamaların bunu bilmesi gerekmez, `X-Real-IP`
okumaları yeterlidir. Güven kapısı olarak `${MUVON_EDGE_IP}` kullanılmalıdır.

---

## [0.1.48] - 2026-07-20

v0.1.47'de gelen `${MUVON_EDGE_IP}` özelliğinin kusurlarının düzeltmesi. Şema
migration'ı yok; sadece image güncellemesi gerekir.

### BUGFIXES

- **`${MUVON_EDGE_IP}` component'in yalnız ilk ağına bakıyordu, bu yüzden çözülemiyordu.**
  (v0.1.47'de gelen özelliğin kusuru.) Bir component tipik olarak iki ağda bulunur: izole DB ağı
  ve paylaşımlı yönlendirme ağı. Edge proxy yalnız ikincisine bağlıdır ve bu ağ listede ilk sırada
  olmak zorunda değildir; pratikte DB ağı ilk sırada oluyor. Arama artık component'in **tüm**
  ağlarını deniyor ve proxy'nin gerçekten bağlı olduğu ilk ağdaki adresi kullanıyor.

- **Çözülemeyen token artık container'a literal olarak geçmiyor, deployment hata veriyor.**
  Önceki davranış token'ı olduğu gibi bırakmaktı ("hata görünür kalsın" gerekçesiyle). Pratikte bu,
  uygulamaya geçersiz bir adres veriyor ve açılışta crash loop üretiyor, yani hatayı görünür değil
  daha kötü hale getiriyordu. Artık deployment container yaratılmadan **önce**, üstelik migration
  çalışmadan ve `recreate` stratejisi eski container'ı durdurmadan önce, net bir mesajla durduruluyor.
  Blue-green sayesinde önceki instance hizmet vermeye devam ediyor.

### Upgrade

- v0.1.47'yi kurup `${MUVON_EDGE_IP}` kullanmayı denediyseniz, o deploy'lar başarısız olmuş
  olabilir. Bu sürüme geçtikten sonra component'i yeniden deploy etmek yeterli.
- Token'ı ilk kez kullanacaksanız, önce bu sürüme yükseltin. Yükseltme yapılmadan token
  çözülemez ve deployment (artık net bir hatayla) durur.

---

## [0.1.47] - 2026-07-20

### FEATURES

- **`${MUVON_EDGE_IP}`: edge proxy adresi artık component env'ine otomatik enjekte ediliyor.**
  Bir uygulamanın gerçek istemci IP'sini görebilmesi için proxy'ye güvenmesi gerekir
  (gunicorn `FORWARDED_ALLOW_IPS`, uvicorn `--forwarded-allow-ips`, nginx `set_real_ip_from`).
  O ayara şimdiye kadar container IP'si elle yazılıyordu; Docker adresleri yeniden dağıttığında
  ayar sessizce yanlış oluyor ve uygulama edge'in IP'sini son kullanıcı IP'si sanmaya başlıyordu.
  Hiçbir şey patlamadığı için de aylarca fark edilmeyebiliyordu.

  Deployer artık container'ı yaratırken edge proxy'nin o component'in ağındaki güncel adresini
  çözüyor, `MUVON_EDGE_IP` olarak env'e ekliyor ve component env değerlerindeki `${MUVON_EDGE_IP}`
  token'ını onunla değiştiriyor. Operatör `FORWARDED_ALLOW_IPS=${MUVON_EDGE_IP}` yazıp bırakıyor.

  Ayrıntılar:
  - Token hem component env değerlerinde hem **component command'ında** çözülür. gunicorn gibi
    sunucularda `--forwarded-allow-ips` komut satırı argümanı env değişkenini ezdiği için, yalnız
    env'i desteklemek düzeltmeyi eksik bırakırdı.
  - Değişim birebir token değişimi, kabuk genişletmesi değil; içinde `$` geçen secret'lar bozulmaz.
  - Adres çözülemezse token olduğu gibi bırakılır. Boş allow-list yazıp güveni sessizce kapatmak
    yerine görünür bir hata bırakmak tercih edildi.
  - Agent host'unda deployer zaten proxy'nin içinde çalışır, kendi container'ına bakar. Central'da
    proxy ayrı bir container olduğundan `muvon.role=edge` etiketiyle bulunur; etiket iki compose
    şablonuna da eklendi.
  - Değer her deploy'da yeniden çözülür, önbelleğe alınmaz.

### ENHANCEMENTS

- Operatör skill referansları (`.claude/skills/muvon/`) canlı kurulum incelemesiyle güncellendi:
  agent'ın systemd değil docker compose ile çalıştığı, agent auth başlığının `X-Api-Key` olduğu,
  `hosts.target_kind`/`target_agent_id` ile domain'lerin de bir agent'a bağlandığı düzeltildi;
  Docker subnet'inin kurulumdan kuruluma değişmesi, host firewall'unun gerçek maruziyeti
  göstermemesi, `:latest` yüzünden filo sürüm sürüklenmesi ve gerçek istemci IP zinciri yeni
  tuzak maddeleri olarak eklendi.

### Upgrade

- Enjeksiyon, container'ı yaratan deployer'da çalışır: central component'leri için `muvon-deployer`,
  edge component'leri için ilgili agent bu sürüme yükseldikten sonra etkin olur.
- Yükseltme sonrası uygulamanın trust ayarını token'a çevirin, örneğin
  `FORWARDED_ALLOW_IPS=${MUVON_EDGE_IP}`. Aynı token component command'ında da çalışır; sunucu
  bayrağını komut satırında geçiyorsanız orayı da güncelleyin, çünkü CLI env'i ezer.
- Değişiklik component yeniden yaratılınca (bir sonraki deploy) geçerli olur.

---

## [0.1.46] - 2026-07-13

Kod-inceleme turunda bulunan doğruluk ve güvenlik kusurlarının toplu
düzeltmesi. Şema migration'ı yok; sadece image güncellemesi gerekir.

### SECURITY

- **Admin login rate-limit'i artık istemci `X-Forwarded-For` / `X-Real-IP`
  başlığıyla atlatılamıyor.** Admin `extractClientIP` bu başlıkları güven
  kontrolü olmadan kabul ediyordu; saldırgan her denemede başlığı değiştirerek
  `/api/auth/login` limitini (100/dk) tamamen bypass edip sınırsız brute-force
  yapabiliyor, audit ve refresh-token kayıtlarındaki kaynak IP'sini de
  sahteleyebiliyordu. Admin artık proxy'nin trusted-proxy-aware IP çözümünü
  (`proxy.ClientIP`) kullanıyor: XFF/X-Real-IP yalnız doğrudan peer güvenilir
  bir proxy'yken (CF secret'lı Cloudflare edge veya yapılandırılmış trusted
  proxy) onurlanıyor, aksi halde gerçek peer adresi esas alınıyor.
- **X-Accel-Redirect korumalı dosya serve'i istemci başlığıyla devre dışı
  bırakılamıyor.** İstemci `Accept: text/event-stream` (veya `Upgrade`)
  göndererek accel intercept writer'ının kurulmasını engelleyip backend'in
  internal dosya yolunu (`X-Accel-Redirect` değeri) sızdırabiliyor, indirmeyi
  de boş döndürüyordu. Writer artık accel route'larda SIEM/SSE/upgrade
  gate'inden bağımsız, koşulsuz kuruluyor (hijack-safe): başlık her zaman
  strip ediliyor ve dosya doğru serve ediliyor.

### BUGFIXES

- **64 KiB (65536 bayt) üstü istek gövdelerinden tam 1 bayt kaybı.**
  `CaptureRequestBody`, truncation'ı tespit için `maxSize+1` bayt okuyup
  fazladan baytı `captured[:maxSize]` ile atıyor ama bu bayt `remaining`'de
  olmadığından forward edilen gövde offset 65536'da 1 bayt eksiliyordu (POST/
  PUT/PATCH, skip listesinde olmayan Content-Type). Base64/JSON gövdelerinde
  bozuk payload veya "geçersiz base64" 400'lerine yol açıyordu. Gövde artık
  tümüyle okunuyor, yalnız SIEM kopyası kırpılıyor; forward edilen gövde hiçbir
  boyutta değişmiyor. Okuma hatasında (client disconnect / boyut limiti) kısmi
  gövde backend'e iletilmiyor, istek 400/413 ile reddediliyor.
- **diaLOG http_logs worker'ı graceful shutdown'da kilitlenmiyor.** Drain
  döngüsündeki `break`, iç `select`'ten çıkıp `for {}`'da kalıyor; kanal
  kapandığında sonsuz spin ile shutdown'ı kilitliyor, son batch'i ve diğer
  pipeline'ların Stop'unu bloke edip SIGKILL'e kadar CPU yakıyordu.
- **Deploy crash + hızlı restart artık deployment/scheduled-job'u kalıcı
  kilitlemiyor.** Stale-reset yalnız açılışta çalıştığından, hızlı restart'ta
  taze `updated_at` eşiği geçemiyor ve satır süresiz `running` kalıyordu. Reset
  artık tick döngüsünde periyodik (throttled) çalışıp recovery'yi eşik
  penceresiyle sınırlıyor.
- **`recreate` stratejisi başarısız candidate'ta ölü container'a işaret eden
  `active` instance bırakmıyor.** Eski container candidate sağlıklı olmadan
  durduruluyordu ama DB satırı `active` kalıyordu (proxy 502'ye route eder).
  Eski instance'lar artık candidate başlamadan `draining`'e geçiriliyor;
  cleanupDraining hem başarı hem başarısızlık yolunda temizliyor.
- **Correlation engine SMTP/Slack gönderiminde bloke olmuyor (fail-open).**
  `smtp.SendMail`/`tls.Dial` timeout'suzdu; erişilemez SMTP host'u tek
  correlation goroutine'ini dakikalarca bloke edip sonraki logları
  korelasyondan düşürüyordu. SMTP artık timeout'lu, ctx-aware; alert dispatch
  ise ayrı goroutine'de (bağımsız 30s bütçe) çalışıyor.
- **Tek bozuk satır artık tüm COPY FROM batch'ini düşürmüyor.** URL path'indeki
  `%00` (NUL) veya geçersiz UTF-8 gibi PostgreSQL'in reddettiği baytlar tüm
  batch'i (ilgisiz geçerli kayıtlar dahil) düşürüyordu. http_logs, container ve
  client-event pipeline'ları artık text/jsonb/body alanlarını persistence
  sınırında temizliyor (NUL strip + geçerli UTF-8).
- **Response body capture, buffer tam dolunca `truncated` bayrağını doğru
  set ediyor.** Buffer `maxSize`'a tam dolduğunda sonraki write'lar sessizce
  düşüyor ama `IsResponseTruncated` `false` kalıyordu (SIEM'e yanlış "tam
  kayıt" metadata'sı). İstemciye giden gövde etkilenmiyordu.
- **Agent komut kanalı: imzasız komut artık dispatch edilmiyor.** Komut önce
  boş imzayla insert edilip imza ayrı UPDATE'te yazıldığından, araya giren bir
  claim boş-imzalı komutu alıp kalıcı "signature verification failed" ile
  başarısız kılabiliyordu. Claim sorgusu artık imza dolu olmayan satırı
  atlıyor.

### Upgrade

- Yeni image'ları çekip servisleri yeniden başlatın; edge agent'lar
  `agent.self_upgrade` ile güncellenir. 64 KiB üstü gövde düzeltmesi hem
  central proxy'de hem edge agent'ların proxy'sinde bu sürümle etkinleşir.

---

## [0.1.45] - 2026-06-08

### BUGFIXES

- **Scheduled job `run` modu container'ları artık çalışırken öldürülmüyor
  (exit 137).** Orphan reconciler (`reconcileOrphanContainers`) her tick'te
  `muvon.managed=true` taşıyan ama deploy-instance olmayan container'ları
  öksüz sayıp `ContainerRemove(force=true)` ile siliyordu. Scheduled job'lar
  deploy/drain döngüsünü bloklamamak için arka plan goroutine'inde koştuğundan,
  bir sonraki tick'in reconciler'ı henüz **çalışan** job container'ını ~15-18
  saniye içinde SIGKILL ediyordu — migration'lar tick içinde senkron koşup
  hemen silindiği için etkilenmiyordu. Deployer artık in-flight one-off
  container'ları (migration + scheduled job) bir sette takip edip reconciler'da
  atlıyor; crash sonrası set boş başladığı için gerçek öksüz carcass'lar yine
  temizlenir (regresyon yok).

### Upgrade notları

Deployer tarafı düzeltme — yeni migration yok. Scheduled job'ları `run` modunda
çalıştıran host'taki deployer'ı yükseltin: central component'ler için
`muvon-deployer`, edge component'ler için `agent`. (`exec` modu bu bug'tan
etkilenmiyordu.)

# Central:
bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install.sh) --version 0.1.45

# Agent:
bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install-agent.sh) --version 0.1.45

---

## [0.1.44] - 2026-06-08

### FEATURES

- **Zamanlanmış işler (cron).** MUVON artık managed-deploy platformlarının
  standart özelliği olan periyodik iş çalıştırmayı sunuyor (scrape / cleanup /
  rapor / sync) — daha önce her uygulamanın kendi worker container'ıyla yamadığı
  bir boşluk. Bir iş bir component'e bağlanır ve onun image / env / secret /
  network / mount'larını miras alır; `command` image CMD'ini override eder.
  - **Scheduler** (yalnız central `muvon`): cron ifadesine göre
    `scheduled_job_runs` kuyruğuna `pending` iş bırakır ve `next_run_at`'i bir
    sonraki cron sınırına ilerletir. Timezone destekli (statik binary'ye
    `time/tzdata` gömülü). Crash sonrası tek "catch-up" çalıştırma — kaçan
    tick'ler tek tek backfill edilmez.
  - **Executor** (deployer): mevcut deploy döngüsünün yanında, sınırlı sayıda
    (4) arka plan worker'ında çalıştırır — bir saate kadar sürebilen bir iş
    deploy/drain döngüsünü bloklamaz. `run` modu yeni one-off container açar;
    `exec` modu komutu component'in aktif container'ında çalıştırır. Exit code
    + log kuyruğu (~16 KB) çalışma kaydına işlenir.
  - **Hibrit topoloji**: hem central hem edge-agent component'leri için aynı
    `State` arayüzü üzerinden çalışır (`/api/v1/agent/deployer/job/*`,
    agent-sahiplik kontrollü). Operatör komut kanalına (`agent_commands`)
    dokunulmaz — ayrı tablolar, ayrı concern.
  - Admin UI'da **"Zamanlanmış İşler"** sayfası: iş tanımı, enable/disable,
    manuel "şimdi çalıştır" ve çalışma geçmişi (durum + exit code + çıktı).
  - `concurrency_policy=forbid` (varsayılan): önceki çalışma sürerken yeni tick
    atlanır ve görünür bir `skipped` kaydı bırakılır.

### Upgrade notları

İki yeni migration (`scheduled_jobs`, `scheduled_job_runs`) ilk açılışta
otomatik uygulanır — forward-only, manuel adım yok.

# Central:
bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install.sh) --version 0.1.44

# Agent:
bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install-agent.sh) --version 0.1.44

---

## [0.1.43] - 2026-06-01

### ENHANCEMENTS

- **Static route'lar artık per-route response header'larını uyguluyor.** Şimdiye
  kadar `resp_headers_add` / `resp_headers_del` yalnız proxy route'larında
  (ModifyResponse) çalışıyordu; static serve bunları yok sayıyordu. Artık static
  serve de uyguluyor — ör. private medya tutan bir static root'a
  `Cache-Control: private, no-store` eklenip paylaşımlı CDN'de cache'lenmesi
  önlenebiliyor.

---

## [0.1.42] - 2026-06-01

### BUGFIXES

- **X-Accel-Redirect: edge artık backend'in "hayalet gövdesi" yüzünden askıya
  alınmıyor.** Bir backend X-Accel yanıtına `Content-Length` yazıp gövdeyi boş
  gönderirse, ReverseProxy var olmayan byte'ları beklerken her indirme
  **~6 saniye** bloke olabiliyordu — dosya boyutundan bağımsız, sabit gecikme.
  MUVON artık X-Accel-Redirect gördüğünde (nginx gibi)
  upstream gövdesini **beklemeden atıyor**: dosyayı kendisi serve ediyor, sahte
  `Content-Length`'i kaldırıyor, gövdeyi boşaltıyor. Kötü davranan bir backend
  edge'i asla askıya alamaz. (Birim test: `accel_modifyresponse_test.go`.)

### SECURITY

- **Accel ile sunulan korumalı medya artık `Cache-Control: private, no-store`
  taşıyor.** Auth-gated belgeler paylaşımlı bir CDN (Cloudflare) veya tarayıcıda
  cache'lenip başka kullanıcıya servis edilemez. Backend kendi Cache-Control'ünü
  set ederse o korunur.

---

## [0.1.41] - 2026-06-01

### SECURITY

- **Cloudflare `CF-Connecting-IP` güveni artık paylaşımlı secret gerektiriyor
  (v0.1.40 regresyon düzeltmesi).** v0.1.40, peer bir Cloudflare aralığındaysa
  `CF-Connecting-IP`'ye güveniyordu; ancak Cloudflare egress IP'leri **tüm CF
  hesapları arasında paylaşımlı** olduğundan, bir saldırgan kendi CF zone'unu
  origin IP'sine yöneltip sahte `CF-Connecting-IP` enjekte ederek client IP'sini
  spoof edebilirdi (rate-limit / django-axes / audit baypas) — grey modda bile,
  origin IP'si public olduğu için. Artık `CF-Connecting-IP` yalnız **operatörün
  kendi zone'unda bir Transform Rule ile enjekte ettiği gizli header**
  (`MUVON_CLOUDFLARE_IP_SECRET` / `AGENT_CLOUDFLARE_IP_SECRET`, varsayılan header
  `X-Muvon-CF-Key`) eşleştiğinde + peer ∈ CF-aralığı iken kabul edilir
  (sabit-zamanlı karşılaştırma). Secret set değilse Cloudflare client-IP güveni
  **kapalıdır** (güvenli varsayılan = v0.1.40 öncesi davranış). Auto-synced CF
  aralıkları ve grey/orange toggle davranışı korunur. Davranış güvenlik
  testleriyle sabit (`cloudflare_test.go`: default-kapalı + yanlış-secret).

---

## [0.1.40] - 2026-06-01

### FEATURES

- **Native Cloudflare farkındalığı — gerçek client IP, sıfır config.** MUVON artık
  bir zone'un proxy'si (turuncu bulut) açıkken `CF-Connecting-IP` header'ından
  gerçek client'ı çözer; kapalıyken (gri / direkt) hiçbir şey değişmez. Operatör
  hiçbir liste tutmaz, `TrustedProxies`'e Cloudflare aralığı eklemez: MUVON,
  Cloudflare'in resmi IP aralıklarını (`cloudflare.com/ips-{v4,v6}`) açılışta ve
  12 saatte bir **otomatik çeker** (fetch başarısızsa bundled seed korunur).
  Grey↔orange istediğin an serbestçe çevrilir, config değişmeden doğru çalışır.

### SECURITY

- **`CF-Connecting-IP` yalnız peer gerçekten Cloudflare edge'iyse kabul edilir.**
  `peer ∈ CF-aralığı` kapısı, origin IP'sini bilen birinin sahte
  `CF-Connecting-IP` yollayıp client IP'sini spoof etmesini engeller (doğrudan
  origin'e vuran saldırganın peer'ı CF aralığında olmadığı için header yok
  sayılır, gerçek peer IP'si kullanılır). `CF-Connecting-IP` ayrıca XFF leftmost
  gibi client-spoof'lanamaz. Cloudflare arkasında giden `X-Forwarded-For` da
  yalnız çözülen gerçek client ile yazılır (CF'in spoof'lanabilir zinciri
  taşınmaz). Davranış birim testlerle sabit (`cloudflare_test.go`).

---

## [0.1.39] - 2026-06-01

### SECURITY

- **Untrusted client'tan gelen `X-Forwarded-For` artık backend'e taşınmıyor.**
  Edge, doğrudan peer trusted bir proxy DEĞİLSE (yani normal dış client) inbound
  `X-Forwarded-For` zincirini append ediyordu; bu, leftmost girdinin
  client-spoof'lu olmasına ve `XFF[0]` okuyan downstream servislerin (ör.
  django-axes gibi IP-bazlı kontroller) kandırılmasına izin veriyordu. Artık
  untrusted peer'da inbound XFF düşürülüp yalnız çözülen client IP ile yazılıyor;
  inbound zincir yalnız peer gerçek bir trusted upstream proxy ise (ör. önde CDN,
  `Host.TrustedProxies`'te tanımlı) korunuyor. `X-Real-IP` zaten koşulsuz
  overwrite ediliyordu (değişmedi) — bu yama `XFF[0]` okuyan servisleri de
  airtight yapar. Davranış birim testlerle sabitlendi (`director_xff_test.go`).

---

## [0.1.38] - 2026-06-01

### BUGFIXES

- **Health probe artık geçerli `Host` header gönderiyor.** Managed backend'ler
  container'ın dinamik iç adıyla (`muvon-<proje>-<sha>-<ts>`) dial ediliyor; bu
  ad hiçbir zaman uygulamanın `ALLOWED_HOSTS`'unda olmadığı için Django gibi katı
  framework'ler liveness probe'unu routing'den önce reddedip ~10 saniyede bir
  `DisallowedHost` ERROR basıyordu (gerçek kullanıcı trafiği etkilenmiyordu —
  sadece log/SIEM kirliliği). Hem runtime circuit-breaker probe'u
  (`internal/health`) hem deploy-anı health check'i (`internal/deployer`) artık
  `Host: localhost` gönderiyor; bağlantı yine container'a gidiyor, yalnız Host
  header'ı `ALLOWED_HOSTS`'ta kabul gören bir değer oluyor.

---

## [0.1.37] - 2026-05-27

### FEATURES

- **RUM imperatif event API** — `window.muvon.track(name, attrs)` ve
  `window.muvon.identify(id, traits)`. Uygulama kodu mantıksal bir anda
  yapılandırılmış custom event basabiliyor; önceden yalnız otomatik sinyaller +
  `data-mv-error`/`data-mv-track` deklaratif hook'ları vardı (tüketiciler bir JS
  callback'inden olay basmak için gizli-DOM hack'ine zorlanıyordu). GA-stili
  async-safe queue stub (`!function(w){...}(window)`) ile rum.js yüklenmeden
  önceki `muvon('track', …)` çağrıları tamponlanıp init'te boşaltılır; sonrası
  hem `muvon('track', …)` hem `muvon.track(…)` çalışır. `track` mevcut `custom`
  şemasına, `identify` `identify` event'i + envelope `user` bloğuna maplenir —
  **server tarafı değişmeden** generic event olarak saklanır (per-event user_id
  kolonu ileride eklenebilir). Otomatik instrumentation + `data-mv-*` aynen.

---

## [0.1.36] - 2026-05-27

### SECURITY

- **Edge `X-Frame-Options`: `DENY` → `SAMEORIGIN`**: edge'in sunduğu
  uygulamalar kendi aynı-origin içeriklerini gömebiliyor (ör. served `/media`
  dosyalarının `<object>`/`<iframe>` ile PDF/resim önizlemesi). `DENY`
  aynı-origin framing'i bile engelliyordu ve route bazında override
  edilemiyordu; `SAMEORIGIN` cross-site clickjacking'i yine bloklar. Daha katı
  framing gereken backend kendi header'ını set eder.

---

## [0.1.35] - 2026-05-27

### BUGFIXES

- **Managed deploy `recreate` + routable component reddediliyor**: recreate
  stratejisi candidate'tan önce eski instance'ı durdurur; routable bir serviste
  candidate health fail ederse sert kesinti olurdu. recreate yalnız
  non-routable singleton'lar (celery-beat gibi) için — routable servisler
  `blue_green` kullanmalı. Component create/update **merged input** üzerinde
  doğrulanıyor (partial update'i bozmaz).

### ENHANCEMENTS

- **`health_mode=running` crash-loop tespiti sertleştirildi**: RestartCount
  baseline'ı ilk inspect'te (state'ten bağımsız) alınıp herhangi bir artış
  anında unhealthy sayılıyor — `unless-stopped` ile hızlı crash-restart eden
  container artık grace penceresinden "healthy" sızamaz.
- **`health_mode=exec` güncelleme doğrulaması**: `health_command` merged
  input'tan kontrol ediliyor; yalnız mode'u `exec`'e çeviren (komutu yeniden
  göndermeyen) update artık yanlışlıkla reddedilmiyor.

---

## [0.1.34] - 2026-05-27

### FEATURES

- **Managed deploy'da worker-process desteği**: Bir component artık image'ın
  default CMD'sini ezen `command` ve HTTP dışı sağlık modları alıyor — böylece
  tek backend image'ı `web` / `celery worker` / `celery-beat` olarak ayrı
  component'ler halinde deploy edilebilir (CI/CD webhook → muvon-managed):

  - `command TEXT[]` — long-running container'ın CMD'sini ezer (mevcut
    `migration_command` desenini aynalar). Boş = image default.
  - `health_mode` — `http` (varsayılan; GET `health_path`) | `exec`
    (container içinde `health_command` çalışır, exit 0 = healthy — örn
    `celery -A config inspect ping`, worker'ın gerçekten fonksiyonel olduğunu
    doğrular) | `running` (container ayakta + crash-loop yok; `RestartCount`
    izlenir — beat gibi probe'suz süreçler için).
  - `health_command TEXT[]` — `exec` modunun probe'u.
  - `deploy_strategy` — `blue_green` (varsayılan, sıfır kesinti) | `recreate`
    (candidate başlamadan eski instance durdurulur — celery-beat gibi
    singleton'lar deploy penceresinde asla iki kez koşmaz; karşılığında kısa
    kesinti + rollback yok, k8s Recreate semantiği).
  - `deploy_order INT` — rollout sırası (artan); migration taşıyan component
    (örn web) worker'lardan önce gelsin diye, worker'lar göçmemiş şemaya
    çarpmaz.

  Tüm default'lar (`{}`, `http`, `blue_green`, `0`) mevcut deploy davranışını
  **birebir** korur — tatilji/karacil gibi mevcut servisler etkilenmez. UI:
  servis düzenleyici Advanced sekmesinde command + sağlık modu + strateji +
  sıra alanları. Central ve edge agent deployer'ı aynı kodu paylaştığından her
  iki host türünde de çalışır.

  Migration `add_deploy_components_worker_fields`: beş kolon, hepsi
  `NOT NULL DEFAULT`, forward-only.

---

## [0.1.33] - 2026-05-26

### FEATURES

- **W3C Trace Context ile cross-tier correlation**: Proxy artık her istek
  için ürettiği UUIDv7'nin 128 bitini lowercase hex `trace-id` olarak da
  kullanıyor — `X-Request-ID` aynı id'nin insan-okur tireli alias'ı (iki
  rakip id yok). Geçerli inbound `traceparent` **yalnız `TrustedProxies`'ten
  gelince** sürdürülür (public edge'de istemci kendi trace-id'sini dayatamaz),
  aksi halde taze üretilir; her hop için yeni `span-id`. Upstream'e
  `traceparent` enjekte edilir; tarayıcıya `Server-Timing: traceparent;desc=
  "00-<trace>-<span>-01"` yansıtılır (CORS'lu route'larda
  `Access-Control-Expose-Headers: Server-Timing` + `Timing-Allow-Origin`).
  `http_logs`'a `trace_id`/`span_id` kolonları eklendi — üç kanalın (http /
  container / client) ortak join anahtarı.

  Migration `add_http_logs_trace_id`: nullable iki kolon + partial index,
  forward-only.

- **Channel 3 — client-side telemetry (RUM) ingest**: Per-host opt-in
  (`hosts.rum_enabled`) reserved `POST /__muvon/rum` endpoint'i tarayıcı
  event'lerini (page_view, js_error, unhandled_rejection, resource_error,
  fetch, web_vital, route_change, visibility, pagehide, dom_error) toplar.
  Edge enrich: server-receive zamanı + trusted-proxy-aware client IP + host;
  GeoIP merkezi (SIEM) tarafında (agent'lar GeoLite taşımaz). Fail-open: pipe
  doluysa/yoksa **her zaman 204 + drop**, trafik etkilenmez. Yeni
  `client_events` TimescaleDB hypertable (`trace_id` + `session_id` join
  anahtarları), container_logs desenini aynalayan ayrı ince pipeline
  (`SendClientEventBatch` gRPC, drop-on-overflow). Admin panelde **Client
  Events** sayfası + `trace_id` ile http_logs'a join; Hosts düzenlemede RUM
  toggle. Sampling oranı + batch boyutu admin-tunable (`rum_sample_rate`,
  `rum_max_batch_bytes`), `GET /__muvon/rum/config`'ten servis edilir ve
  agent'lara push'lanır.

  Migration'lar `create_client_events_hypertable`,
  `add_client_events_compression_retention` (dialog), `add_hosts_rum_enabled`,
  `seed_rum_settings` (muvon) — hepsi forward-only.

- **Tarayıcı telemetri client lib (`clientlib`)**: ~6 KB zero-dependency
  native TS, edge `GET /__muvon/rum.js`'te servis eder (per-host opt-in,
  ETag-cache, binary'ye `go:embed`). Müşteri tek satır ekler:
  `<script src="/__muvon/rum.js" async></script>`. Otomatik enstrümantasyon:
  fetch/XHR patch (+ Server-Timing'den `trace_id` okuma), `window.onerror` /
  `unhandledrejection`, web-vitals (LCP/CLS/INP/FCP/TTFB), History API route
  değişimi, `sendBeacon` ile pagehide/visibilitychange flush, `[data-mv-error]`
  / `[data-mv-track]` DOM kancaları. Tüm enstrümantasyon hata-yutar — telemetri
  host sayfayı asla kıramaz. `make clientlib` bundle'ı yeniden üretir; çıktı
  (`.pb.go` gibi) repoda commit'li, böylece Node'suz `go build` çalışır.

### ENHANCEMENTS

- **Tekrarlanabilir protobuf codegen**: `make proto` hedefi pinlenmiş plugin
  sürümleriyle (`protoc-gen-go v1.36.11`, `protoc-gen-go-grpc v1.6.1`)
  `proto/`'yu yeniden üretir; sessiz versiyon drift'ini önler.

---

## [0.1.32] - 2026-05-21

### FEATURES

- **Redirect route'larında opt-in path/query preservation**: `route_type='redirect'`
  satırlarına yeni boolean alan `redirect_preserve_path` (default `false`).
  Açıkken proxy, gelen request'in `r.URL.Path` ve raw query string'ini
  `redirect_url`'in sonuna ekleyip 301 atar; `redirect_url`'in trailing
  slash'ı trim'lenir ki `//foo` üretilmesin. Klasik www → apex use case
  artık `www.x.com/foo?q=1` → `https://x.com/foo?q=1` şeklinde path/query'i
  koruyor. Default `false` mevcut literal-redirect davranışını bozmadan
  bırakır.

  Migration `add_routes_redirect_preserve_path`: tek `BOOLEAN NOT NULL
  DEFAULT false` kolonu, forward-only.

---

## [0.1.31] - 2026-05-16

### BUGFIXES

- **Rerun aynı release için zaman zaman 'no candidate instances'
  hatasıyla anında düşüyordu**: Daha önce başarıyla promote olmuş bir
  deployment'ı UI'dan Rerun ile yeniden tetikleyince (örn .env değişti,
  container'ı yeni env ile recreate et) deployment ~5 ms içinde
  'failed' düşüyordu. `PromoteDeployInstances` ilk promote'ta
  `deploy_release_components.status`'u 'succeeded'a alıyor; enqueue
  yolundaki ON CONFLICT branch'i rerun'da `image_ref`/`image_digest`
  güncelliyor ama `status`'u 'pending'e geri çekmiyordu.
  `LoadDeploymentPlan` ise `WHERE rc.status='pending'` filtresiyle
  bileşenleri seçtiğinden, rerun'da plan zero-component yüklüyordu,
  `processDeployment` for döngüsüne hiç girmeyip doğrudan
  Promote'u boş candidate listesiyle çağırıyordu → 500.

  Düzeltme: ON CONFLICT branch'i artık `status = 'pending'` da yazıyor.
  Fresh deploy ve rerun ikisinde de aynı pre-condition (rc.status =
  pending) garanti.

- **Container Logs listesinde agent host container'ları "unknown"
  badge'i ile görünüyordu**: v0.1.28'deki state filtresi düzeltmesi
  ile birlikte agent container'ları artık listede çıkıyordu, ama
  state inference branch'inde `m.Live=false` & `FinishedAt=""` durumu
  "unknown" olarak etiketleniyordu — filter mantığı bu durumu zaten
  "running" sayıyor, badge tutarsızdı. Backend artık `state='running'`
  döndürüyor; UI Live badge'ini state==='running' kapsayacak şekilde
  genişletti, central + agent container'ların badge'i aynı yeşil
  "live" çipi.

### ENHANCEMENTS

- **install-agent.sh + docker-compose.agent.yml + CHANGELOG v0.1.30
  provider-agnostik dile çekildi**: v0.1.30 yayınında live container
  tail dokümantasyonu Hetzner Cloud private network örnekleriyle
  (`10.0.0.3:9100`, "Hetzner Cloud Firewall private bypass") gömülü
  gitmişti. Özelliğin kendisi her zaman provider-agnostikti; sadece
  operatöre verilen örnekler/yorumlar belirli bir sağlayıcıya angaje
  görünüyordu. Şimdi:

  - `install-agent.sh` prompt'u üç senaryoyu listeliyor: iç ağ
    (private network / VPC / mesh), public IP + firewall, ve "kapalı
    tut" (live tail bu agent için devre dışı).
  - `docker-compose.agent.yml` yorumu "iç ağ adresi (provider private
    network, VPC subnet, VPN mesh)" diyor.
  - CHANGELOG v0.1.30 girişi `<private-ip>:9100` placeholder'ı
    kullanıyor; firewall mantığı provider-agnostik (Hetzner Cloud FW
    / AWS Security Group / iptables / nftables eşit listede).

  Davranışsal değişiklik yok; sadece dokümantasyon ve operatör UX.

---

## [0.1.30] - 2026-05-16

### FEATURES

- **Canlı container log tail artık agent host'lardaki container'lar için
  de çalışıyor**: Central admin UI'da Container Logs → Live tab'ında
  agent makinesindeki bir container'a tıklandığında akış kopmadan
  başlıyor. Önceki davranışta sadece central host'taki container'lar
  canlı görülebiliyordu — agent'takiler için "Live tail bağlantısı
  koptu" düşüyordu çünkü merkezi muvon-deployer agent host'taki
  Docker socket'ini göremiyor.

  Yeni mimari: agent binary kendi deployer gRPC server'ını TCP portunda
  yayınlıyor (default `9100`; `AGENT_DEPLOYER_TCP_BIND` ile bind
  edilecek interface seçilir). Central admin container'ın `host_id`'sine
  bakıp ya local Unix socket deployer'a ya da agent'ın TCP adresine
  dial ediyor.

  Güvenlik: bearer token HKDF ile `MUVON_ENCRYPTION_KEY`'den türetilir
  (label `muvon-deployer-rpc-v1`). Token wire'a düz yazılmaz — central
  ve agent aynı anahtardan aynı token'ı hesaplar. Anahtar yoksa
  endpoint 503 döner ve listener kalkmaz.

  Network topolojisi **provider-agnostik**: central ↔ agent arası
  herhangi bir iç ağ üzerinden çalışır — provider private network
  (Hetzner Cloud, AWS VPC, GCP VPC, vs), VPN mesh (Tailscale,
  Wireguard), bare-metal LAN. Public IP'den dial edilecekse
  provider firewall'unda yalnız merkez IP'sine 9100/tcp izni gerekir
  (token doğrulama zaten devrede, firewall defansif derinlik).

  Operatör adımları:
  - **Agent**: `install-agent.sh ... --deployer-tcp-bind <bind>`
    (kurulum veya update). `<bind>` örnekleri: `<private-ip>:9100`
    (iç ağ önerilen), `0.0.0.0:9100` (tüm interface, firewall'la
    sıkıştırılmış olmak şartıyla), boş (live tail kapalı).
  - **Central**: UI → Agents → ilgili agent → "Deployer addr (canlı
    container log için)" alanına `<host>:<port>` yaz, Kaydet.
  - **Mapping otomatik**: agent her config pull'da `X-Muvon-Host-Id`
    header'ı ile self-reports; central `agents.host_id` kolonuna
    persist eder. Operatör host_id elle eşleme yapmaz.

  Migration `add_agents_host_id_deployer_addr`:
  iki text kolon (host_id, deployer_addr) + host_id üzerinde partial
  index. Forward-only; central upgrade edilince otomatik koşar.

### ENHANCEMENTS

- **Container Logs listesi artık çalışan'lar üstte sıralanıyor**: live
  (FinishedAt boş) container'lar üstte, exited olanlar altta. Aynı
  durum içinde deployer-confirmed (`live=true`) historical-only'nin
  üstüne çıkıyor; eşitlik halinde en son aktiviteye göre (LastLogAt →
  StartedAt) azalan, son kırılım container adına göre artan. Eski
  upgrader/exited container'lar listenin altına iniyor.

### BUGFIXES

- **Agent SSE config_watch ~60s'de bir kopuyordu**: Merkezi MUVON'un
  HTTP server'larında global `WriteTimeout: 60s` ayarı, açık tutulan
  SSE stream'lerinin yazma tarafını tam 60. saniyede zorla kapatıyordu.
  Agent log'unda görünen `stream error: stream ID …; INTERNAL_ERROR;
  received from peer` mesajının kaynağı buydu. Bağlantı her dakika
  düşüp yeniden kuruluyor, bu süre içinde push edilen `config_updated`
  event'leri agent'a ulaşmıyordu (sonraki pull cycle'a kadar gecikme).

  Düzeltme: tüm uzun-ömürlü endpoint'lerde
  `http.NewResponseController(w).SetWriteDeadline(time.Time{})` ile
  sunucu-tarafı yazma deadline'ı bu bağlantı için sıfırlanıyor.
  Kapsam: `/api/v1/agent/watch` (SSE), `/api/v1/agent/commands`
  long-poll (max 50s wait — 60s'lik tampona fazla yakındı),
  `/api/system/upgrade/stream`, `/api/container-logs/.../stream`,
  `/api/logs/stream`.

---

## [0.1.28] - 2026-05-15

### BUGFIXES

- **Container Logs sayfası agent container'larını göstermiyordu**:
  `handleListContainers`'ın final state filtresi `state=running`
  durumunda `m.Live` (yalnız central deployer'dan gelen) container'ları
  geçiriyor, dialog'un historical dimension'undan gelen agent
  container'larını eliyordu. dialog'a log shipping çalışsa bile
  (auth fix v0.1.27), Live tab boş kalıyordu. Operatör m1'deki tatilji
  servislerinin loguna erişemiyordu.

  Düzeltme: state filtresi artık `FinishedAt` üzerinden çalışıyor —
  Live olsun olmasın, `FinishedAt` boşsa "running". Live badge bilgisi
  korunuyor (deployer-confirmed visibility hâlâ ayırt edilebilir) ama
  filtreleme kararı doğru sinyale göre veriliyor.

---

## [0.1.27] - 2026-05-15

### BUGFIXES

- **Agent log shipping `Unauthenticated` ile sessizce reddediliyor­du**:
  Aynı PostgreSQL instance'ı içinde iki ayrı `agents` tablosu var
  (legacy mimari). `muvon.agents` — operatörün admin panelinden
  yönettiği canlı tablo, `dialog.agents` — eski dönemden kalma
  schema-isolated kopya (boş). `queries_agents.go`'daki tüm SQL'ler
  `FROM agents` ile yazılmıştı, schema search_path'e bağlıydı.
  Dialog-siem `dialog` schema'sıyla çalıştığı için `dialog.agents`'a
  bakıyordu — orası boş — her api key invalid.

  Düzeltme: agents tablosunun **schema'sı muvon**'a aittir, dialog-siem
  yalnız okuma için cross-schema query yapar. Tüm SQL'ler artık
  `muvon.agents` ile explicit schema-qualified. Dialog-siem auth
  intercept'u doğru tabloya bakar, agent log batch'leri kabul edilir,
  `dialog.container_logs` dolar.

  Bu bug, agent tarafında `slog.Warn` ile görünür hale gelen
  `rpc error: code = Unauthenticated desc = invalid api key` ile
  tespit edildi (v0.1.26 fix'i sayesinde).

### Schema notu

- `dialog.agents` tablosu artık kullanılmıyor (drop edilmedi —
  forward-only migration garantisini bozmamak için boş bırakıldı).
  İleride bir cleanup migration ile temizlenebilir.

---

## [0.1.26] - 2026-05-15

### BUGFIXES

- **logship sessizce başarısız oluyordu**: agent dockerwatch line'ları
  lokal spool dosyasına yazıyordu (~MB'larca birikim), `shipOrSpool`
  ise gRPC send fail'ını `slog.Debug` ile loguyordu — agent INFO
  seviyesinde çalıştığı için hiç görünmüyordu. Replay loop'unda da
  Drain hatası tamamen sessizdi. Operator dialog UI'da
  `container_logs` boş görüyor, neden olduğunu bilemiyordu.

  Düzeltme: send fail + replay fail artık `slog.Warn` seviyesinde
  emit ediliyor. Hata mesajı, container short id, batch line sayısı
  loga düşüyor — gerçek sebep (auth reject, transport error, TLS
  mismatch, vs.) artık görünür.

---

## [0.1.25] - 2026-05-15

### BUGFIXES

- **`agent.self_upgrade` race condition**: Operatör Agents UI'da
  "Ek host mount yolları"nı değiştirip "Kaydet ve uygula" tıkladığında
  iki istek peş peşe gidiyordu: önce `PATCH /api/agents/{id}/mounts`
  (DB güncelleme + config reload), sonra `POST /api/agents/{id}/commands`
  (self_upgrade enqueue). Agent config pull'un SSE üzerinden tetiklenip
  yeni mount listesini state'ine alması ile command'ın long-poll'ünden
  düşmesi arasında yarış vardı; çoğu zaman command **eski state**'le
  çalışıyor, helper container önceki mount listesiyle yeniden
  başlatılıyordu.

  Düzeltme: admin enqueue handler artık `self_upgrade` komutu için
  payload'a `agents.extra_mounts`'u (dispatch zamanındaki canlı DB
  değeri) otomatik gömüyor. Agent handler payload'da `extra_mounts`
  varsa state'i atlayıp doğrudan onu kullanıyor. Operator-supplied
  payload override'lar korunuyor (UI veya CLI manuel mount listesi
  geçirebilir).

---

## [0.1.24] - 2026-05-15

### BUGFIXES

- **`agent.self_upgrade` helper'ı convention default mount'larını yok
  ediyordu**: v0.1.23'ün mount sync script'i compose'daki **tüm**
  `:ro` mount satırlarını sed `:d` ile silip sonra `EXTRA_MOUNTS`
  listesinden re-insert ediyordu. `EXTRA_MOUNTS` boş olduğunda
  `/root/.docker/config.json` ve `/opt/envfiles` defaults'ı da
  uçtu → GHCR pull 401, env_file_path erişimi yok.

  Düzeltme: helper artık compose'u **GitHub raw'dan taze indiriyor**
  (`wget -q -O`), convention default mount satırlarını üç targeted
  `sed s|...|...|` ile uncomment ediyor, sonra `EXTRA_MOUNTS`'taki
  her path'i duplicate-guard ile docker.sock anchor'ı altına insert
  ediyor. Tamamen idempotent — peş peşe iki self_upgrade aynı compose
  dosyasıyla biter, EXTRA_MOUNTS state'i ne olursa olsun default
  mount'lar her zaman aktif.

### Upgrade notları

- Agent v0.1.23'te kalan kurulumlar bir kez install-agent.sh ile
  düzeltilmeli (manuel kurtarma) çünkü mevcut bozuk helper kendi
  kendini yenileyemiyor. v0.1.24'e çıktıktan sonra UI'dan
  `agent.self_upgrade` güvenle tetiklenebilir.

---

## [0.1.23] - 2026-05-15

### FEATURES

- **Agent extra bind mounts UI-managed**: Operator artık edge agent'a
  expose edilecek ek host bind-mount yollarını central admin panelinden
  yönetir. Agents → bir agent satırı genişlet → "Ek host mount yolları"
  textarea'ya satır başına bir path. **Kaydet** sadece DB'ye yazar,
  **Kaydet ve uygula (recreate)** ek olarak `agent.self_upgrade` komutu
  tetikleyerek agent'ın helper container'ı üzerinden compose'unu
  yeniden yazıp container'ı recreate etmesini sağlar — operator SSH'a
  girmek zorunda kalmaz.

  Akış:
  ```
  UI edit → PATCH /api/agents/{id}/mounts → agents.extra_mounts DB
                                                  ↓
  Agent config pull → AgentPayload.ExtraMounts (memory'de)
                                                  ↓
  agent.self_upgrade → helper container EXTRA_MOUNTS env'i ile çalışır
                       → compose dosyasına ro mount satırlarını idempotent
                         olarak ekler (eski operatör mount'ları temizler,
                         yeni listeyi insert eder)
                       → docker compose up -d --no-deps --wait agent
                                                  ↓
  Yeni agent container'da extra mount'lar aktif → embedded deployer
  o yollardaki env file'lar / managed component mount source'larını
  açabilir
  ```

  v0.1.22'nin `install-agent.sh --mount` flag'i initial bootstrap için
  hâlâ destekleniyor; sonraki yönetim UI'dan. `.env`'deki
  `AGENT_EXTRA_MOUNTS` artık merkezi otorite değil — central DB
  state'i source of truth.

- **Yeni admin endpoint**: `PATCH /api/agents/{id}/mounts` — request
  body `{"extra_mounts": ["/opt/tatilji", ...]}`. Boş/whitespace
  girdiler düşürülür, audit log entry yazılır, config reload
  tetiklenir.

### Schema (forward-only)

- `agents` tablosuna `extra_mounts TEXT[] NOT NULL DEFAULT '{}'`
  eklendi.

### Upgrade notları

- Central + agent ikisini de v0.1.23'e alın (payload yeni field
  taşıyor). Eski agent yeni field'ı yoksayar, problem değil; eski
  central yeni agent'a göndermeyi bilmediği için extra mount'lar
  uygulanmaz, semantik bozulmaz.
- Mevcut `--mount` CLI flag ile kurulmuş agent'lar: install zamanı
  set edilen `AGENT_EXTRA_MOUNTS` `.env` değeri **silinmiyor**,
  ama agent self_upgrade sonrası compose'a artık DB'deki liste
  uygulanır. Geçiş sırasında çakışma riski yok çünkü her iki kaynak
  da aynı path'leri içerebilir.

---

## [0.1.22] - 2026-05-15

### BUGFIXES

- **`agent.self_upgrade` paralel container yaratıyordu, gerçek agent'ı
  recreate etmiyordu**: v0.1.20'de helper container yaklaşımına
  geçilmişti ama helper script `cd /host/agent` yapıyordu — `/host/`
  altındaki klasör adı `agent`, compose project name'i de o adı alıyor
  (`agent_default`). Operatör install-agent.sh ile gerçek agent'ı
  `/opt/muvon-agent` altına kurmuş, gerçek compose project name
  `muvon-agent`. İki ayrı project: helper `agent-agent-1` yeni bir
  container yaratıyor, gerçek `muvon-agent-agent-1` dokunulmadan
  çalışmaya devam ediyordu. Pull başarılı + helper exit 0 → command
  "succeeded" → ama agent eski binary'de kalıyordu.

  Düzeltme: helper mount target'ı `MUVON_HOST_AGENT_DIR`'in basename'ini
  alır (`/host/muvon-agent`), `docker compose` çağrısı `-p muvon-agent`
  flag'iyle gerçek project'i hedefler. Helper artık doğru container'ı
  recreate ediyor.

### FEATURES

- **`install-agent.sh --mount` flag + interactive prompt**: Operator
  istediği host yollarını agent container'a ro mount edebilir
  (`AGENT_EXTRA_MOUNTS` env state'i `.env`'de tutulur). v0.1.21'in
  `/opt/envfiles` convention'ı default mount olarak kalır; ek yollar
  bunun **üstüne** eklenir. Operatör mevcut yapısını taşımak zorunda
  değil — örneğin `/opt/tatilji/secrets/api.env` yerinde durur,
  `--mount /opt/tatilji` ile agent'a tanıtılır.

  Kullanım:
  ```
  # Yeni install (interaktif soracak):
  bash <(curl -fsSL .../install-agent.sh)
  # CLI flag (tekrarlanabilir):
  bash <(curl -fsSL .../install-agent.sh) --mount /opt/tatilji --mount /opt/another
  ```
  Update mode'da `--mount` verilirse mevcut `AGENT_EXTRA_MOUNTS` değeri
  override edilir; verilmezse state korunur. Her install çağrısı
  compose dosyasına mount satırlarını yeniden uygular.

---

## [0.1.21] - 2026-05-15

### BUGFIXES

- **Edge agent `env_file_path` host yolunu okuyamıyordu**:
  Komponent `env_file_path` set ettiğinde central muvon-deployer
  dosyayı host'taki `/opt/envfiles/`'tan kendi process'inde okuyor
  (`docker-compose.yml`'da `/opt/envfiles:/opt/envfiles:ro` mount var).
  Agent compose'da bu mount **yoktu**; embedded deployer host yolunu
  bulamayınca migration container env vars'sız başlatılıyor, alembic
  DB'ye bağlanamadan exit 1 ile düşüyordu.

  Düzeltme: agent compose'a aynı `/opt/envfiles:/opt/envfiles:ro`
  mount'u eklendi (central ile simetrik convention). `install-agent.sh`
  edge deployer enabled olan kurulumlarda dizini otomatik oluşturur
  (`mkdir -p /opt/envfiles`) ve mount satırını compose'da açar.

### Upgrade notları

- **Mevcut env file'larınız standart konuma taşınmalı**: `/opt/envfiles/`
  altına koyun (örnek isim: `tatilji-api.env`). MUVON UI'da o
  komponentin `env_file_path` alanını yeni yola güncelleyin.
- install-agent.sh'i bir kez daha çalıştırın — yeni compose dosyası
  indirilir, `/opt/envfiles` mount'u açılır, agent restart eder.
- Bind mount (`mounts: [...]`) ile env dosyası geçirenler için bu fix
  alternatif yol — mount'u tamamen kaldırıp `env_file_path` kullanmak
  artık doğru pattern. Mount, container'daki non-root user'ın host
  dosyasını okuyamadığı durumlarda permission denied verir.

---

## [0.1.20] - 2026-05-15

### BUGFIXES

- **`agent.self_upgrade` yeni image'a geçemiyordu**: handler sadece
  `docker pull` çağırıp `os.Exit(0)` yapıyordu. Docker'ın restart
  policy'si (`unless-stopped`) container'ı **mevcut image ID'siyle**
  yeniden başlatır, registry cache'ine yeni inen tag'i kullanmaz.
  Sonuç: pull başarılı, command "succeeded" döner, ama eski binary
  çalışmaya devam eder. v0.1.18'den v0.1.19'a geçmek isteyen kullanıcı
  managed_backends fix'ini alamadığı için "no backend configured" 502
  hatasıyla kalakaldı.

  Düzeltme: `handleSelfUpgrade` artık sistem-upgrade flow'undaki gibi
  bir `docker:27-cli` helper container fırlatır. Helper, host'taki
  `docker-compose.agent.yml`'i bind-mount eder ve `compose pull && up
  -d --no-deps --wait agent` çalıştırır — daemon container'ı yeni
  image'la **gerçekten recreate eder**. Helper kendi context'inde
  (Background) çalıştığı için agent process'i compose tarafından
  kill edilirken yarıda bırakılmaz. Pinned tag desteği: payload'da
  `image: ".../agent:0.1.20"` gibi bir override gelirse compose
  dosyasındaki `:latest` referansı önce sed ile pinned tag'e çevrilir.

### Schema (forward-only)

- `docker-compose.agent.yml`'a `MUVON_HOST_AGENT_DIR` env var eklendi
  (helper container'ın bind-mount path'ini bilmesi için). install-agent.sh
  `.env`'e `MUVON_AGENT_DIR=$INSTALL_DIR` yazıyor (default `/opt/muvon-agent`).

### Upgrade notları

- **Tek seferlik manuel adım**: v0.1.19 veya öncesindeki agent'ı yeni
  self_upgrade handler'a kavuşturmak için install-agent.sh'i bir kez
  daha çalıştır:
  ```
  ssh m1 'curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install-agent.sh | bash'
  ```
  Bu compose pull + up yapar (eski self_upgrade'in beceremediği şey),
  yeni `MUVON_HOST_AGENT_DIR` env var'ı kurar. Sonraki sürümlerde
  `agent.self_upgrade` UI butonu kendi başına çalışacak.

---

## [0.1.19] - 2026-05-15

### BUGFIXES

- **Agent proxy "no backend configured" 502 dönüyordu**:
  `AgentPayload` `Hosts` + `Routes` taşıyordu ama `RouteRule.ManagedBackends`
  alanını (yani managed component'a bağlı active container endpoint'leri)
  taşımıyordu. Agent payload'ı parse edip kendi config'ini kurarken
  `pickBackend` her zaman boş array görüyor, `ServeHTTP` 502 ile geri
  dönüyordu. Central'da aynı kod yolu `LoadFromDB` içinde
  `ListActiveManagedBackends`'i route'a aktardığı için sorun çıkmıyordu.

  Düzeltme: `AgentPayload`'a `managed_backends` field eklendi. Agent'a
  ait hostların route'larına bağlı tüm active backend'ler bu listede
  dedupe edilerek gönderiliyor. Agent tarafı `ToConfig` çıkışında
  component_id'ye göre group'layıp `RouteRule.ManagedBackends`'i
  dolduruyor. Proxy artık doğru container URL'sini round-robin'le seçer.

### Upgrade notları

- Central + agent **ikisini birlikte** v0.1.19'a alın. Eski agent yeni
  payload'ı parse eder (geriye dönük uyumlu, field optional) ama
  `managed_backends` boş kalır, problem devam eder. Eski central yeni
  agent'a göndermeyi de bilmediği için aynı durum. Symmetric upgrade.

---

## [0.1.18] - 2026-05-15

### BUGFIXES

- **Edge agent embedded-deployer modunda private GHCR pull 401 alıyordu**:
  `docker-compose.agent.yml` host'un `~/.docker/config.json` dosyasını
  agent container'a mount etmiyordu. Agent ImagePull (HTTP
  `/images/create`) yaptığında `loadDockerConfigAuths` boş dönüyor,
  X-Registry-Auth header'ı set edilmiyor, registry anonymous istek olarak
  görüp 401 dönüyordu.

  Central tarafında (`docker-compose.yml`) muvon-deployer için aynı
  mount zaten vardı; agent compose'da eksikti.

  Düzeltme: `docker-compose.agent.yml`'a yorumlu satır eklendi.
  `install-agent.sh` `AGENT_DEPLOYER_ENABLED=true` durumunda satırı
  açıyor (socket mount mantığıyla aynı). Host'ta `/root/.docker/config.json`
  yoksa kullanıcıya `docker login ghcr.io` direktifi gösteriliyor.

### Upgrade notları

- Edge agent v0.1.17 veya öncesinde kurulan ve embedded deployer aktif
  olan kurulumlar bu fix'i almak için **install-agent.sh'i yeniden
  çalıştırmalı** — yeni compose dosyası indirilir, mount satırı açılır,
  agent restart olur. `docker login ghcr.io` zaten yapılmışsa hiçbir
  ek adım gerekmez.

---

## [0.1.17] - 2026-05-15

### FEATURES

- **Host terminator ownership**: her host artık DB'de hangi MUVON
  instance'ının onu terminate ettiğini explicit taşıyor
  (`target_kind='central'` veya `target_kind='agent'`+`target_agent_id`).
  Bu tek değişiklik dört iyileştirme açıyor:

  1. **Add/Edit Host dialog'unda DNS hint**: operatör terminator'ü
     seçer seçmez "DNS A kaydını şu IP'ye yönlendir" mesajı anlık
     görünür. Cloudflare'a doğru IP yazmak için Hosts listesini
     beklemeye gerek yok.
  2. **Hosts listesinde terminator badge**: `central` veya
     `edge: tatilji (65.108.157.107)` etiketi her satırda.
  3. **DNS verification host-bazlı**: artık global IP listesi değil,
     **bu host'un kendi hedef IP'si**. Yanlış IP = "stale", doğrudur.
  4. **421 Misdirected Request enforcement**: yanlış makineye gelen
     trafik proxy katmanında 421 ile reddedilir + audit log. ACME
     HostPolicy de bu kuralı uygular — yanlış makine Let's Encrypt'i
     gereksiz yere zorlamaz. Ayrıca agent payload artık sadece
     **kendisine bind hostları** alır (central başka bir agent'a ait
     host'u görmez, agent kendine ait olmayanları görmez).

### Schema değişiklikleri (forward-only)

- `hosts` tablosuna iki kolon: `target_kind TEXT NOT NULL DEFAULT 'central'`
  (CHECK: `central|agent`) ve `target_agent_id TEXT REFERENCES agents(id)
  ON DELETE SET NULL`. Mevcut tüm host'lar default'ta `central` olarak başlar.

### Upgrade notları

- **Önemli**: v0.1.16'dan önce edge agent'a yönlendirilmiş hostlarınız
  varsa (DNS A record edge IP'sine bakıyorsa), bu sürüme geçtikten sonra
  **central proxy o trafiği 421 ile reddedecek** (default kayıt `central`
  olduğu için). Çözüm tek tıklama: Hosts → her satırı Edit → terminator
  radio'sundan **Edge agent: <ismi>** seç → Save. Sonra agent bir sonraki
  config pull'unda host'u alır, trafik düzgün akar.
- Agent'lar v0.1.13+ olmalı (public_ip self-report için). Daha eski
  agentlar için `last_remote_addr` fallback'i devrede ama Hetzner-style
  private network'ler için yanlış IP verir.

### Diğer

- `AgentPayloadFromConfig` imzası değişti (agentID parametresi eklendi).
  Embed yapan harici tüketici yok; iç değişiklik.

---

## [0.1.16] - 2026-05-15

### BUGFIXES

- **Migration komutu UI'ı bash sözdizimini bozuyordu**:
  ComponentEditorDialog'daki "Migration komutu" alanı tek satır Input'tu
  ve değeri `split(/\s+/)` ile whitespace üzerinden parçalıyordu. Operatör
  `bash -c "alembic upgrade head && ..."` yazdığında tırnaklar argümanın
  parçası olarak kalıyor, `&&` ayrı argüman oluyordu — sonuç: 9 saçma
  parça, migration container `exec: "bash,": not found` ile fail.

  Düzeltme: alan artık Textarea, **her satır bir argüman**. 3 satır
  girilirse 3 elemanlık array kaydedilir, bash quoting derdi yok.
  Mevcut komponentlerin yanlış parse edilmiş migration_command'larını
  operatör Düzenle ile yeniden kaydetmeli.

---

## [0.1.15] - 2026-05-15

### BUGFIXES

- **Agent TLS cache volume yanlış path'e mount edilmişti**:
  `docker-compose.agent.yml` `tls_cache` volume'unu `/var/lib/app/tls`'e
  bağlıyordu ama agent binary'sinin `AGENT_TLS_CACHE` default'u
  `/var/lib/agent/tls`. İki ayrı path → agent ACME ile cert alıyor,
  ephemeral container dizinine yazıyordu, container her recreate'te
  cache kayboluyordu. Sonuç: her restart Let's Encrypt'ten yeni issue
  → rate limit (haftada 5/domain) çok hızlı doluyor; TLS Certs ekranı
  agent-issued cert'leri hiç göstermiyor.

  Düzeltme: compose'taki mount artık `/var/lib/agent/tls` — agent'ın
  yazdığı path'le aynı. Operatör `bash <(curl -fsSL .../install-agent.sh)`
  ile yeniden çalıştırınca compose otomatik güncellenir.

---

## [0.1.14] - 2026-05-15

### BUGFIXES

- **`install-agent.sh` SSH pipe altında CHANGELOG prompt'unda crash**:
  `curl | bash` veya `ssh host 'curl | bash'` ile çalıştırıldığında
  stdin pipe oluyor ve `/dev/tty` da yok. `_read` fonksiyonu `read
  </dev/tty` ile fail ediyor, `set -e` ile script exit ediyordu.
  Aynı yolda `${!varname}` indirect expansion `set -u` altında
  unbound olarak ikinci kez patlıyordu. Sonuç: update mode'da
  CHANGELOG'u gösterdikten sonra `docker compose pull && up`
  adımına asla gelinmiyordu, operatör manuel olarak çalıştırmak
  zorunda kalıyordu.

  Düzeltme: `_read` ve `_read_secret` artık `read` fail'larını
  tolere ediyor (`|| true`), `${!varname-}` ile unbound-safe ve
  TTY yokluğunda default'a düşüyor. CHANGELOG sonrası "Devam
  edeyim mi?" prompt'u sadece TTY varken sorulur; SSH pipe altında
  otomatik geçiş — script'i bu şekilde çalıştıran operatör zaten
  upgrade'i onaylamış demektir.

---

## [0.1.13] - 2026-05-15

### FEATURES

- **DNS verification artık private-network topolojilerde çalışıyor.**
  Hetzner gibi sağlayıcılarda agent merkezi sunucuya private interface
  (örn. `10.0.0.3`) üzerinden bağlanıyordu; central bu IP'yi
  `last_remote_addr` olarak görüyor ve Hosts ekranında DNS verification
  için "beklenen IP" diye operatöre dönüyordu — anlamsız bir cevap,
  çünkü internet DNS bu private IP'ye ulaşamaz.

  Düzeltme: agent kendi externally-reachable public IP'sini self-report
  ediyor (`AGENT_PUBLIC_IP` env veya `--public-ip` flag, install
  script'i `ifconfig.me` ile otomatik tespit edip soruyor). Central
  startup'ta kendi public IP'sini benzer şekilde tespit ediyor
  (`MUVON_PUBLIC_IP` ile override). Hosts ekranı artık doğru IP'leri
  gösteriyor.

### Schema değişiklikleri (forward-only)

- `agents` tablosuna `public_ip TEXT NOT NULL DEFAULT ''` eklendi.
  Mevcut agent satırları boş başlar; bir sonraki config pull'da agent
  kendi public IP'sini bildirir.

### Upgrade notları

- **Edge agent'lar v0.1.13'e yükseltildiğinde**: install-agent.sh'i
  yeniden çalıştırın (`bash <(curl -fsSL .../install-agent.sh)`); script
  `.env` dosyasına `AGENT_PUBLIC_IP=<auto-detected>` satırını ekler.
  Manuel pin için `--public-ip <ip>` flag'i.
- **Central tarafı**: muvon binary startup'ta kendi public IP'sini
  tespit eder; air-gapped kurulumlarda `MUVON_PUBLIC_IP` env var
  ile manuel set edin.
- `settings.public_ip` (tekil) key'i bu sürümde okunmuyor; eski
  manual-set değerler etkisiz. (Pratikte UI'da hiç düzenlenmemişti,
  geçiş şeffaf.)

---

## [0.1.12] - 2026-05-15

### BUGFIXES

- **Component create endpoint `agent_id`'yi sessizce yutuyordu**:
  `componentRequest` struct'ında `AgentID` field'ı tanımlı değildi.
  Frontend doğru payload gönderiyordu ama JSON unmarshal `agent_id`'yi
  düşürüyor, sonra `buildComponentInput` `base.AgentID = ""` (defaults)
  ile dolduruyordu. Sonuç: wizard'da edge agent seçilse bile komponent
  her zaman central'a düşüyordu. v0.1.11 wizard fix'i de tek başına işe
  yaramıyordu; gerçek bug backend tarafındaydı.

  Düzeltme: `componentRequest`'e `AgentID *string \`json:"agent_id"\``
  eklendi. Create handler'da request varsa uygulanıyor (update handler'lar
  CLAUDE.md kuralı gereği by-design ignore — orphan container önleme).
  Bonus: agent_id boş değilse `agents` tablosunda var olup `is_active`
  olduğu doğrulanıyor; tanınmayan UUID veya inactive agent için 400 BadRequest.

---

## [0.1.11] - 2026-05-15

### BUGFIXES

- **Wizard sessizce yanlış host seçiyordu**: "Yeni Uygulama" wizard'ı,
  hangi sayfadan (Uygulamalar / Uzak Uygulamalar) açıldığına göre host
  seçicisini disable ediyordu (`lockedHost` prop). Memory prensibi
  "oluşturma akışı birleşik (tek wizard)" diyor — bu prop o prensibi
  kırıyordu. Daha kötüsü: default `agentID = ''` (central) → "Bu MUVON
  sunucusu" görsel olarak seçili gibi görünüyordu ama kullanıcı bir
  seçim yapmamıştı; submit'te sessizce central'a düştü.

  Düzeltme: `lockedHost` prop'u kaldırıldı (her iki seçenek her zaman
  açık), `agentID` tri-state oldu (`null` → seçim yok, `''` → central,
  `uuid` → edge). Validation `agentID === null` durumunda submit'i
  engelliyor: "Konum seçilmedi: ya bu MUVON sunucusunu ya da bir agent
  seç".

---

## [0.1.10] - 2026-05-15

### BUGFIXES

- **Sistem güncellemesi: helper container reconciler tarafından SIGTERM
  ile öldürülüyordu** (exit code 143). `RunHelperContainer` üretilen
  short-lived container'lara `muvon.managed=true` etiketi koyuyordu;
  `reconcileOrphanContainers` her tick'te `muvon.managed=true` etiketli
  ama DB'de live instance kaydı olmayan container'ları "orphan" sayıp
  `ContainerStop`'luyordu. Helper container DB'de hiçbir zaman olmaz —
  yarış kazanılırsa upgrader script bitmeden kill ediliyor ve upgrade
  "container exited 143" ile başarısız oluyordu.

  Düzeltme: helper container'lar artık `muvon.helper=true` etiketleniyor,
  `muvon.managed=true` koyulmuyor. Reconciler ayrıca belt-and-suspenders
  olarak `muvon.helper=true` etiketli olanları açıkça atlıyor. Helper'lar
  kendi yaşam döngülerini yönetir (başarı: explicit remove; başarısızlık:
  inceleme için karkas korunur).

### Upgrade Notları

- **v0.1.7–v0.1.9'dan UI üzerinden upgrade artık güvenilir değil**: aynı
  bug bu sürümlerde mevcut. Bu sürüme geçmek için SSH ile central host'a
  bağlanıp manuel olarak:

  ```bash
  cd /opt/muvon
  wget -O docker-compose.yml https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/docker-compose.yml
  sed -i -E "s|(ghcr\\.io/[^:]+):latest|\\1:0.1.10|g" docker-compose.yml
  docker compose pull
  docker compose up -d --no-deps --wait muvon dialog-siem muvon-deployer
  ```

  v0.1.10 yüklendikten sonra ilerideki upgrade'ler UI'dan güvenli.

---

## [0.1.9] - 2026-05-15

### BUGFIXES

- **UI: Apps sayfası null instances'ta crash**: Yeni proje oluşturulduktan
  sonra `instances` boş array yerine `null` dönüyordu (Go nil slice → JSON
  `null`); `Apps.tsx` iki ayrı yerde `proj.instances.find(...)` çağırdığı
  için `TypeError: Cannot read properties of null (reading 'find')` ile
  patlıyordu. Backend `ListDeployProjects` artık nil slice'ları boş array
  olarak normalize ediyor, frontend de defansif `?? []` ile koruyor.

---

## [0.1.8] - 2026-05-15

### FEATURES

- **UI: ComponentEditorDialog → Mounts editor**: "Gelişmiş" sekmesinde
  bind/volume/tmpfs satırları. Backend (`deploy_components.mounts`
  JSONB + deployer `HostConfig.Mounts`) zaten vardı, sadece UI eksikti.
  Host-secret-file pattern'i için kritik: operatör DB credentials'ını
  `/opt/<app>/api.env` gibi bir host dosyasına yazar, MUVON'un
  env_secret_keys'ine koymadan container'a bind eder. MUVON sadece
  mount path'ini bilir, içeriği değil.

### Upgrade notları

```bash
ssh <central> 'cd /opt/muvon && bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install.sh) --version 0.1.8 --yes'
```

Veya admin panel: Settings → Sistem → **"v0.1.8'e güncelle"** butonu.

---

## [0.1.7] - 2026-05-15

### BUGFIXES

- **Helper container artık `AutoRemove: false`**: Sistem upgrade flow
  helper container'ı (`docker:27-cli`) eskiden exit eder etmez Docker
  tarafından siliniyordu. Exit 137 gibi durumlarda `docker logs` ile
  son satır görünemez, root cause analizi imkansızdı. Şimdi carcass
  kalır; success path'inde kod explicit `ContainerRemove(force=true)`
  çağırır. Failed event admin UI'ya container adını sızdırır.
- **Helper container'a `Init: true`**: Docker tini'yi PID 1 olarak
  inject eder. `sh -c script` PID 1 sinyal/zombie problemleri ortadan
  kalkar. Yeni `HelperContainerOpts.Init` field'ı + `hostConfig.Init`
  pointer'ı (`docker.go`).
- **Helper context gRPC stream'inden ayrıştırıldı**: Eskiden helper'ın
  Docker API call'ları stream ctx'iyle bağlıydı. Stream koparsa
  (deployer recreate'i sırasında olur) in-flight Docker call'lar
  iptal oluyordu. Artık helper kendi 12 dakikalık `context.Background`
  türevi ctx kullanır.

### ENHANCEMENTS

- Helper script artık `set -ex` ile çalışır; her satır stdout'a echo
  edilir. Önce `set -e` ile ilk echo akmadan exit olduğunda hangi
  satırda öldüğü anlaşılamıyordu.
- Helper compose `up -d --wait` timeout'u 90 → 180 saniye. Slow disk
  veya çok katmanlı image'larda 90s'lik budget'ı aşma riskini azaltır.

### Upgrade notları

```bash
ssh <central> 'cd /opt/muvon && bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install.sh) --version 0.1.7 --yes'
```

Plus admin panel: Settings → Sistem → **"vX.Y.Z'a güncelle"** butonu
(downgrade için manuel onay sorulur).

---

## [0.1.6] - 2026-05-15

### BUGFIXES

- **System upgrade post-check `/health` endpoint**: `waitLocalHealthy`
  artık auth-free `/health` endpoint'ini poll'lar. Eskiden `/api/health`
  (JWT korumalı) çağırılıyordu, self-call 401 alıp 60s timeout'a
  düşüyordu; muvon zaten Healthy olsa bile UI "failed" gösteriyordu.
- **install.sh non-interactive TTY fallback**: SSH non-interactive
  shell'inde `/dev/tty` yok hatasıyla patlıyordu. `_ask` fonksiyonu
  artık `[ -r /dev/tty ]` kontrolüyle default'a düşer. `set -u` uyumlu
  `${!varname:-}` ifadesi de eklendi.
- **install.sh `--yes` / `MUVON_YES=1`**: CI/script invocation'larında
  CHANGELOG onay sorusunu atlamak için. SSH üzerinden non-interactive
  güncellemeyi mümkün kılar.

### ENHANCEMENTS

- **UI: UpgradeModal yeniden tasarımı**: "vX.Y.Z'a güncelle" primary
  action; pin tier matrix (`latest`/`v0`/`v0.1`) kaldırıldı (çoğu
  kullanıcı sadece en yeni semver istiyor); "Belirli bir sürüm"
  collapsible details içinde manuel input; "Güncel" badge mevcut
  sürüm == latest durumunda.
- **UI: em-dash temizliği**: Cümle-içi `—` 11 dosyada normal noktalama
  ile değiştirildi. Boş değer placeholder'ları (`'—'`) korundu.

### Upgrade notları

```bash
ssh ana 'cd /opt/muvon && bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install.sh) --version 0.1.6 --yes'
```

Veya admin panel: Settings → Sistem → **vX.Y.Z'a güncelle** butonu.

---

## [0.1.5] - 2026-05-15

### BUGFIXES

- **System upgrade false-positive "yeni sürüm var"**: `/api/system/
  version/latest` artık GHCR `:latest` digest'i yerine GitHub Tags
  API'sini sorgulayıp en yüksek semver release tag'ini döndürür;
  `update_available` semver karşılaştırmasından hesaplanır. Eskiden aynı
  commit'in main + tag push'larının farklı image digest üretmesi yüzünden
  UI sürekli "Yeni sürüm mevcut" diyordu.
- **CI `:latest` semantiği**: `:latest` artık yalnız v tag push'unda
  atılır (main push'lar sadece `:sha-XXX`, `:main` üretir). GHCR'daki
  `:latest` her zaman en güncel resmi release'e işaret eder, dev
  iterasyonlarına değil.
- **UI: SystemUpgradePanel display**: "GHCR :latest" digest sütunu
  yerine "Son release" semver tag'i gösterir.

### Upgrade notları

```bash
# Tercih edilen: admin panel → Settings → Sistem → Imajı güncelle →
# "v0.1" veya custom input "0.1.5" → Başlat. v0.1.4'teki kademeli
# recreate + post-stream healthcheck sayesinde UI üzerinden upgrade
# artık güvenilir.

# Fallback (CLI):
bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install.sh) --version 0.1.5
```

---

## [0.1.4] - 2026-05-15

### BUGFIXES

- **UI: Host dialog overflow**: `JWT Identity override` toggle açıldığında
  form ekran dışına taşıyordu. `DialogContent`'e `max-h-[90vh]
  overflow-y-auto` eklendi.
- **UI: UpgradeModal downgrade warning**: Hedef tag çalışan sürümden
  düşükse (semver karşılaştırması) `window.confirm` ile uyarı + onay
  iste. Forward-only migration kuralına aykırı dowgrade'leri kazara
  tetiklemeyi engeller.
- **System upgrade kademeli recreate**: Helper container artık `up -d
  --wait` çağrısını **iki fazda** yapar — önce muvon + dialog-siem
  recreate edilir + Healthy beklenir, sonra **muvon-deployer en son**
  recreate edilir. Eskiden tek `up -d --wait` çağrısında deployer kendi
  recreate'i sırasında helper'ın gRPC stream'i koparken muvon yarı
  start'ta kalıyordu.
- **System upgrade post-stream healthcheck**: Admin handler artık
  deployer gRPC stream EOF'unu "başarı" diye yorumlamıyor; bunun yerine
  lokal `:9443/api/health`'i 60 sn boyunca polluyor, 200 dönerse `done`,
  dönmezse `failed` event'i yayar. Stream koptu ama upgrade fail ettiğinde
  UI'da yanlış yeşil tik çıkmasını engeller.

### Upgrade notları

```bash
# Central:
bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install.sh) --version 0.1.4

# Agent:
bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install-agent.sh) --version 0.1.4
```

Bu sürümden itibaren **Settings → Sistem → Imajı güncelle** gerçek
production-grade üzere çalışır — gelecekteki update'leri admin UI'dan
tek tıkla yapabilirsin.

---

## [0.1.3] - 2026-05-15

### BUGFIXES

- **CI VERSION ldflags artık git tag'inden okuyor**: Eskiden repo
  kökündeki stale `VERSION` dosyası kullanılıyordu; image `:0.1.3` tag'i
  içinde `--version` "v0.1.0" yazıyordu (kafa karıştırıcı). Şimdi
  `refs/tags/vX.Y.Z` push'unda tag adı, main push'unda `VERSION` dosyası
  fallback olarak kullanılır.

---

## [0.1.2] - 2026-05-15

### BUGFIXES

- **System upgrade helper container compose'u tazeliyor**: Eskiden
  helper sadece `docker compose pull && up -d` çağırıyordu; compose
  dosyasındaki image tag'leri eski sürümde kalıyordu (env placeholder'ı
  yok). Helper artık `wget` ile compose'u GitHub'tan tazeler, target
  tag ile `sed`-replace eder, sonra pull + up çalıştırır.
- `writeEnvVersion` kaldırıldı (compose `VERSION` env'i kullanmıyor,
  `.env`'e yazmak no-op + kafa karıştırıcı).

---

## [0.1.1] - 2026-05-15

### BUGFIXES

- **Agent command claim CTE → subquery**: `ClaimNextAgentCommand`'da
  CTE + `UPDATE...FROM next` + `RETURNING` kombinasyonu kolon
  ambiguity'sine yol açıyordu (`id` hem `ac` hem `next` tablosunda).
  Subquery pattern ile değiştirildi; postgres log'larında 30 sn'de bir
  spam'leyen `column reference "id" is ambiguous` hatası susuyor.
- **`alerts` → `dialog.alerts` schema qualification**: `alerts` tablosu
  `dialog` schema'sında; muvon binary'sinin search_path'i
  (`muvon,public`) kapsamıyor. Tüm SQL referansları `dialog.alerts`
  ile qualify edildi; admin paneli `Alerts` sayfası artık çalışıyor.

---

## [0.1.0] - 2026-05-14

İlk public release. MUVON + diaLOG + agent + muvon-deployer hibrit
topoloji ile birlikte.

### SECURITY

- Agent API anahtarları artık `agents.api_key_hash` (SHA-256) olarak
  saklanır. Plaintext anahtar yalnızca `POST /api/agents` yanıtında bir
  kez döner; `GET /api/agents` artık `api_key` alanını dışarı vermez.
  Pre-migration satırlar ilk başarılı auth'ta otomatik olarak
  hash'lenir; admin müdahalesi gerekmez.
- **Central → agent komut imzalama**: Komut kanalı her komut için
  HMAC-SHA256 imzası taşır. İmzalama anahtarı `MUVON_ENCRYPTION_KEY`'den
  HKDF (`"muvon-agent-command-v1"` label) ile türetilir. Her komutun
  ayrıca rasgele `nonce`'ı ve `expires_at` TTL'i vardır; agent tarafında
  son 1000 komut ID'si LRU dedup, expired/replay reddedilir. Key boşsa
  command channel **sessizce devre dışı** (admin endpoint 503 döner) —
  yani komut yanlış imza ile asla dağıtılmaz.

### FEATURES

- **Hibrit topoloji**: Servisler `agent_id` ile etiketlenir. `NULL` =
  central `muvon-deployer` container'ları yönetir, set = o agent'ın
  embedded deployer'ı yönetir. Agent `AGENT_DEPLOYER_ENABLED=true` ile
  edge'de aynı lifecycle'ı koşturur.
- **Uygulama / Servis lifecycle yönetimi**: yeni REST CRUD
  endpoint'leri (`POST/PUT/DELETE /api/deploy/projects`,
  `POST/GET/PUT/DELETE /api/deploy/projects/{slug}/components/{component}`),
  Admin paneli "Yeni Uygulama" wizard'ı, env editör (`.env` yapıştırma,
  key bazında secret işaretleme), rollback (`POST
  /api/deploy/projects/{slug}/rollback`), pause/resume toggle'ı.
- **Env vars secret encryption**: `env_secret_keys` listesinde belirtilen
  key'ler AES-256-GCM ile şifreli saklanır, GET'te maskeli döner,
  deployer container start'ta decrypt eder. `MUVON_ENCRYPTION_KEY`
  central + deployer + her agent (`AGENT_ENCRYPTION_KEY`) için aynı
  olmalı.
- **DNS doğrulama**: `GET /api/hosts/{id}/dns-status` domain'i resolve
  edip beklenen IP'lerle (settings `public_ip` + agent'ların son
  IP'leri) karşılaştırır. Host kartında inline badge.
- **TLS durumu badge**: `GET /api/hosts/{id}/tls-status` sertifikanın
  geçerlilik durumunu, kalan günü, issuer'ı raporlar. Host kartında
  görünür.
- **Per-host `tls_mode`**: `off` / `redirect` / `auto` / `manual`
  seçenekleri. `manual` ve `off` ACME challenge'ı atlar.
- **CI/CD UI**: Apps proje dialog'unda "CI/CD" sekmesi — webhook URL,
  secret reveal/regenerate, GitHub Actions / GitLab CI / curl
  snippet'leri.
- **Sol menü ayrımı**: "Uygulamalar" (central) + "Uzak Uygulamalar"
  (edge). Aynı UI, host filtresi ile.
- Agent embedded deployer'ı için yeni endpoint'ler:
  `/api/v1/agent/deployer/{claim,plan,event,fail,instance,promote,…}`.
- **Tek tıkla sistem upgrade** (Settings → Sistem): `GET
  /api/system/version` çalışan binary'nin sürümünü + image digest'ini,
  `GET /api/system/version/latest` GHCR'ı anonim manifest HEAD ile
  yoklayıp `:latest` digest'ini döner (5 dk cache). `POST
  /api/system/upgrade {target_tag, take_backup}` deployer üzerinde bir
  helper container (`docker:27-cli`) çalıştırır — otomatik `pg_dump
  -Fc` alır, `docker compose pull && up -d --wait` ile tüm stack'i
  recreate eder. `GET /api/system/upgrade/stream` SSE ile
  pull/restart/post_check fazlarını canlı yayınlar; eşzamanlı bir
  upgrade isteği 409 alır. UI tarafında `SystemUpgradePanel` (çalışan vs
  GHCR karşılaştırma badge'i) + `UpgradeModal` (tag seçici, DB backup
  toggle, inline CHANGELOG preview, canlı progress). _Not: v0.1.0–v0.1.3
  arası bu akışta race var; production'da v0.1.4'e geç._
- **Central → agent komut kanalı** (`/agents` sayfasından her satırda
  aksiyon menüsü): `agent.cache_flush`, `agent.set_log_level` (TTL ile
  auto-revert), `cert.renew`, `agent.drain`, `agent.restart`,
  `agent.self_upgrade`, `agent.revoke`, ayrıca Apps sayfasında edge
  component instance kartında `container.restart` butonu. Komutlar
  `muvon.agent_commands` tablosunda durur (UUIDv7 PK, FOR UPDATE SKIP
  LOCKED claim, sweeper goroutine 30 sn'de bir stale satırları expired
  yapar). Agent uzun-pollar (`GET /api/v1/agent/commands?wait=25s`);
  central INSERT ettiğinde in-memory bus agent'ı uyandırır, fast-path
  ~50 ms. State makinesi: `pending → dispatched →
  succeeded|failed|expired`. UI: `AgentActionMenu` (dropdown + onay
  dialog + cert.renew için domain prompt), `AgentCommandHistory` (son
  10 komut + state badge'leri).
- **Versiyon altyapısı**: Repo kökünde `VERSION` (tek source of truth).
  Tüm Go binary'leri build sırasında `-X muvon/internal/version.{Version,
  Commit}` ldflags ile inject edilir; `--version` flag'i çıktıyı verir,
  startup log'una da düşer. Dockerfile `VERSION`+`COMMIT` build-arg
  alır; CI release.yml Plausible-style üçlü-tier tag matrisi yayar
  (`vX.Y.Z`, `vX.Y`, `vX`, `latest`), operatör `bash <(curl …
  install.sh) --version 0.1` (minor pin) ya da `--version 0.1.0`
  (patch pin) ile konservatiflik seçer; install.sh `docker-compose.yml`'deki
  `:latest` referanslarını seçilen tag ile değiştirir.
- **Idempotent install/update flow**: `install.sh` ve
  `install-agent.sh` aynı komutla hem ilk kurulum hem update — `.env`
  varsa update modu, yoksa fresh install. `MUVON_ENCRYPTION_KEY` ASLA
  overwrite edilmez; eksik env satırları sona eklenir, mevcut secret'lar
  korunur. Update modunda `/opt/muvon/backups/` altına otomatik
  `pg_dump -Fc` (son 5 yedek rotation). Status file
  (`/opt/muvon/.install-status`) SSH disconnect'e karşı süreç ilerleyişi
  saklar. CHANGELOG son sürüm bölümü onay öncesi gösterilir.
- **Per-component image retention (`keep_releases`)**: Yeni
  `deploy_components.keep_releases` kolonu (default 3, SQL CHECK ≥ 1).
  Başarılı promote sonrası `pruneImagesAfterPromote` her component için
  son N başarılı release dışındaki ve canlı bir instance'a bağlı
  olmayan image_ref'leri yerel Docker daemon'undan siler. SQL `in_use`
  filtresi + Docker'ın kendi refcount'u (409 sessizce yutulur) çift
  güvence. UI: `ComponentEditorDialog` → "Gelişmiş" sekmesinde sayısal
  input (1-50). Edge agent için `POST
  /api/v1/agent/deployer/prunable-images` endpoint'i.

### ENHANCEMENTS

- HTTP access log shipper artık bounded retry queue ile çalışır —
  geçici central kesintilerinde log düşmesi azalır.
- Agent fail-soft startup: `AGENT_CONFIG_CACHE` ile son başarılı config
  diske yazılır; central down'sa stale config ile başlar, arka planda
  yeniden bağlanır.
- Agent → central cert push exponential backoff ile yeniden dener
  (~30 dk'ya kadar).
- Tüm Go binary'leri `--version` flag'ini destekler.

### BUGFIXES

- `internal/deployer/service.go` artık `State` interface arkasında
  çalışıyor — central (`DBState`) ve agent (`APIState`) aynı lifecycle
  kodunu paylaşır.
- **Drain + orphan cleanup sertleştirmesi**: `cleanupDraining` artık
  `ContainerRemove(force=true)` çağırıyor; remove fail ederse instance
  `draining` state'inde kalır (önceden iyimser şekilde `stopped`
  işaretlenip tekrar denenmiyordu, container kalıcı orphan oluyordu).
  Stop ve remove hataları artık `slog.Warn` ile loglanır.
- **Orphan reconcile exited container'ları artık görüyor**: eskiden
  `ContainerList` (running-only) çağrılıyordu; `ContainerListAll(all=1)`
  ile değiştirildi.

---

## Şablon — yeni sürümler için

Yeni bir sürüm hazırlanırken `[Unreleased]` bölümünün başlığı
`## [X.Y.Z] - YYYY-MM-DD` olarak yenilenir, üstüne yeni bir
`[Unreleased]` bloğu eklenir. Sürüm yayınlandığında karşılığı
`git tag vX.Y.Z` atılır ve GitHub Release body'sine bu CHANGELOG
satırı kopyalanır.

```markdown
## [X.Y.Z] - YYYY-MM-DD

### BREAKING
### SECURITY
### FEATURES
### ENHANCEMENTS
### BUGFIXES

### Upgrade notları

# Central:
bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install.sh) --version X.Y.Z

# Agent:
bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install-agent.sh) --version X.Y.Z
```
