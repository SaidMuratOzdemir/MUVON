# Sürprizler, dikkat noktaları — agent burada takılır

Bu liste **gerçek probe sonucu** elde edildi. Skill burada her bir tuzağı bilirse, agent ilk denemede gereksiz cycle harcamaz.

## 1) Bearer header desteği **YOK**

`internal/admin/middleware.go:16-19` yorumu net: *"Cookie-only: the old Authorization: Bearer header path is gone."*

Yanlış: `curl -H "Authorization: Bearer <token>" ...` → her zaman **401**.
Doğru: cookie jar tabanlı flow (`references/auth.md`).

## 2) Refresh token **tek kullanımlık** (rotation)

`POST /api/auth/refresh` her çağrıda yeni cookie set eder. Cookie jar'ı **mutlaka** `-c` ile güncelle. Aynı refresh token'ı ikinci kez kullanırsan → 401 + tüm cookie'ler `Max-Age=0` ile silinir → tekrar login lazım.

Pratikte gözlemlenen:
```
POST /api/auth/refresh   (1. çağrı)  → 200, yeni cookies
POST /api/auth/refresh   (2. çağrı, aynı refresh)  → 401 + silinmiş cookies
```

## 3) 404 **plain text** döner, JSON değil

`curl ... /api/this-does-not-exist` → response body: `404 page not found`. Diğer hatalar (`401`, `403`, `500`) JSON döner. Agent response'u parse ederken `Content-Type: text/plain` veya HTTP code'a göre dallanma yapmalı.

## 4) Response zarfı **tutarsız**

```
/api/hosts           → [...]              # doğrudan array
/api/logs            → {"data": [...]}    # zarflı
/api/system/stats    → {...}              # object
```

Agent `response.data` varsayarsa hosts'da boşa çıkar; `response[0]` varsayarsa logs'da boşa çıkar. Her endpoint için biçimi `references/endpoints.md`'den teyit et.

## 5) Secret masking = **boş string**, `***` değil

```bash
$ curl ... /api/settings
{
  "alerting_smtp_password": "",
  "alerting_smtp_host": "",
  ...
}
```

Boş string **iki anlam** taşır: (a) hiç set edilmemiş, (b) set edilmiş ama maskeli. Agent ayırt edemez. Disiplin: settings yazma işlemini "set-and-forget" yap; "secret hala set mi?" diye verify etme.

CLAUDE.md notu: *"Secret settings are write-only in the API — GET /api/settings returns masked placeholders."*

## 6) Audit log **agent ↔ insan ayrımı yapmıyor**

`/api/audit` çıktısında `admin_user: admin` her iki tür için aynı. Yani audit'te "agent bu deploy'u tetikledi" yazmaz.

Disiplin: her yıkıcı çağrı öncesi stdout'a **AGENT_ACTION** damgası bas (bkz. SKILL.md). Kullanıcı transcript okurken audit'in eksik tarafını oradan tamamlar.

## 7) Access cookie sadece **15 dakika**

`__Host-muvon_access` Max-Age=899s. Uzun script'lerde access expire olur. `references/auth.md`'deki `muvon_api()` wrapper'ı 401 görünce auto-refresh yapıyor — bu pattern'i kullan.

## 8) `__Host-` prefix cookie

Cookie ismi `__Host-muvon_access` — başında underscore + tire. Bash'te tırnaklara dikkat:
```bash
# OK
awk '$6 == "__Host-muvon_access" {print $7}' cookies.txt
# Curl otomatik halleder — manuel header yazmaya gerek yok
```

## 9) macOS'ta `timeout` komutu **yok**

`timeout 5 curl ...` macOS'ta `command not found`. SSE testlerinde dikkat. Alternatifler:
```bash
( curl & sleep 5; kill $! ) 2>/dev/null    # POSIX, her yerde çalışır
gtimeout 5 curl ...                          # coreutils kuruluysa
```

## 10) `POST /api/deploy/webhook` JWT bypass

Bu endpoint admin auth'unu **bypass eder**, HMAC-SHA256 ile imzalı. Header: `X-Muvon-Signature-256`. Agent normalde bu endpoint'e dokunmaz — webhook çağırmak deploy tetikler. `POST /api/deploy/projects/{slug}/deploy` daha doğru API.

## 11) `POST /api/system/reload` zararsız ama yan etkili

Proxy traffic'i etkilemez ama:
- Connected edge agent'lara SSE push gönderir.
- Her config değişikliği sonrası **gerekli** — yoksa atomic.Value snapshot eski kalır.

Agent **API yazımı yaptıktan sonra** çağırmaz (handler'lar zaten kendi sonunda holder.Reload() çağırıyor); ama **manuel SQL yazıldıysa** (yasak — bkz. SKILL.md) reload çağırmak şart. Yasaklı senaryoyu hiç deneme.

## 12) Login rate-limit

`POST /api/auth/login` rate-limited (`internal/admin/server.go:95`). 429 alırsan birkaç saniye bekle, tekrar dene.

## 13) `POST /api/alerting/test/*` **gerçek mesaj gönderir**

Test bile dış dünyaya gider — Slack channel'a, email kutusuna. Kullanıcıdan açık onay alınmadan çağrılmamalı.

## 14) Logout **CSRF gerektirir**

Login bypass listesinde, logout değil. CSRF dance gerekli yoksa 403 alırsın.

## 15) SSE endpoint'lerinde Content-Type **`text/event-stream`**

`curl -sS` JSON beklerse `jq` patlar. `curl -N` ile streaming oku, manuel parse.

## 16) `Set-Cookie` `__Host-` ile başlayan attribute'lar

Cookie attribute parse'ında bazı tool'lar (eski Python `http.cookiejar`) `__Host-` prefix'i ile karışıyor. Bash + curl sorunsuz; başka dil/tool kullanıyorsan unutma.

## 17) Settings tablosu — boolean string olarak gelir

```json
"alerting_enabled": false,
"correlation_anomaly_enabled": true,
```
Bunlar gerçek boolean. Ama bazı settings (`alerting_smtp_port: 587`) sayı, bazıları string. `PUT /api/settings/{key}` body'sinde her zaman `{"value": ...}` formatı kullanılır — değer tipini koru.

## 18) `force_https` host alanı

`/api/hosts` çıktısında `force_https: true` görürsen, o host HTTP isteklerini 301'le HTTPS'e yönlendiriyor. Test ederken `https://` ile çağır yoksa redirect zinciri.

## 19) `trusted_proxies` boş array `[]`

Default. Eğer MUVON CDN/load balancer arkasındaysa, gerçek client IP bu listeye eklenmiş proxy'lerden alınır. Boş list = `X-Forwarded-For` güvenilmez sayılır, RemoteAddr kullanılır.

## 20) `jwt_identity_enabled` host bazlı

Her host JWT identity extraction'ı bağımsız aç/kapa. `jwt_identity_mode`: `verify` (signature doğrula, public_key gerek) veya `extract` (sadece decode et). Log'da `identity` alanı bunun sonucunda dolar.

## 21) Agent API key list yanıtında **artık YOK**

`GET /api/agents` artık `api_key` alanı döndürmez (SHA-256 hash'lendiği için). Plaintext key sadece **create yanıtında bir kez** döner: `POST /api/agents` → `{"agent": {...}, "api_key": "abc123..."}`. Bu key kullanıcıya gösterilmeli, sonra kaybolmuş kabul edilmeli. Operatör kaybederse yeni agent enroll etmek gerek.

Eski (Mart 2026 öncesi) `api_key` plaintext kolonu hâlâ DB'de, geçiş için. Auth middleware ilk başarılı login'de hash'i doldurur — kullanıcı için tamamen transparan.

## 22) `tls_mode=off` host **:443 dinlemez**

`hosts.tls_mode='off'` set ettiğinde MUVON o host için HTTPS terminate etmez, ACME challenge denemez. Browser HTTPS ile erişmeye çalışırsa cert hatası alır. Test ederken `http://`'la dene veya `tls_mode='auto'` çevir.

## 23) Component `agent_id` **sabit**

Servis create'te `agent_id` belirlenir (NULL = central, value = o agent edge). Sonradan değiştirilemez — `PUT /api/deploy/projects/{slug}/components/{component}` `agent_id`'yi yok sayar. Sebep: değiştirmek eski host'ta orphan container bırakır. Taşımak istiyorsan: servisi sil, yeniden yarat (env, mounts dahil her şey yeniden girilir).

## 24) Cross-host deploy straddle **reddedilir**

Bir uygulamanın iki servisi farklı `agent_id`'lerdeyse, deploy enqueue zamanı `enqueue deployment: components straddle hosts` ile reddedilir. Tüm servisleri aynı host'ta tut (hepsi central, ya da hepsi aynı agent).

## 25) `paused` = durdur (deploy engelle + çalışan instance'ları drain et)

`PUT .../components/<x>` body'sinde `{"paused": true}`:
- Yeni deploy denemeleri (webhook / manual / rollback) `component X is paused; resume it before deploying` ile **reddedilir**.
- Component'in **çalışan active instance'ları draining'e alınır**; sahibi deployer (central veya edge agent) bir sonraki tick'te container'ları durdurup kaldırır, proxy de trafiği hemen keser (yalnız `active` instance'lar route edilir). Yani pause gerçek bir "durdur"dur, sadece deploy kilidi değil.

`paused` API alanı **PUT ve POST body'sinden okunur** (pointer alan: göndermezsen mevcut değer korunur). Uyarı: yeterince eski bir MUVON sürümünde `componentRequest` struct'ında bu alan hiç yoktu, dolayısıyla `paused` API'den set edilemiyor, DB'de default `false` kalıyordu. Beklediğin gibi durmuyorsa çalışan sürümde alanın işlendiğini doğrula (`grep -n '"'"'json:"paused"'"'"' internal/admin/handlers_deploy_components.go`).

**Devam ettirme (resume):** `{"paused": false}` yeni deploy'lara izin verir ama çalışan instance'ı geri getirmez (pause onları drain etmişti). Ayağa kaldırmak için bir deploy gerekir: son başarılı release için `POST .../rollback`, ya da CI webhook / manual deploy.

Durdurmak için artık DELETE gerekmez; DELETE component'i kalıcı siler (spec kaybolur), pause ise config'i koruyup yalnız çalışmayı durdurur.

## 26) `MUVON_ENCRYPTION_KEY` ↔ `AGENT_ENCRYPTION_KEY` **eşleşmek zorunda**

Component secret env vars central'da AES-256-GCM şifreli saklanır. Container başlatırken deployer (central veya agent) decrypt eder. Üç noktada aynı key olmalı:

| Binary | Env var |
|---|---|
| `muvon` (central admin) | `MUVON_ENCRYPTION_KEY` |
| `muvon-deployer` | `MUVON_ENCRYPTION_KEY` |
| `agent` (edge, deployer aktifse) | `AGENT_ENCRYPTION_KEY` |

Birinde değişip ötekiler unutulursa: encrypt edilmiş env decrypt edilemez, container başlamaz. Symptom: deploy "running" sonra "failed", event'te `decrypt env <KEY> for component <slug>: ...`.

## 27) Embedded edge deployer Docker socket gerektirir

Agent'ta `AGENT_DEPLOYER_ENABLED=true` set edersen ama `AGENT_DOCKER_SOCKET` ulaşılamazsa deployer **sessizce devre dışı kalır**, log'da `deployer: enabled but docker socket unreachable; staying disabled`. Agent diğer işlevlerine devam eder ama o agent'a atanmış component'ler hiç deploy olmaz. Operatör symptom: deployment "pending" durumunda asılı kalır.

## 28) DNS status `no_target` cevabı

`GET /api/hosts/{id}/dns-status` `status: "no_target"` dönüyorsa: ne central `public_ip` setting'i var, ne de hiç agent kayıtlı. Settings'ten `public_ip`'i set et ya da bir agent enroll et — yoksa badge faydasız.

## 29) `MUVON_ENCRYPTION_KEY` artık agent command HMAC için de kullanılıyor

Key boşsa **iki şey sessizce kapanır**:
- Secret env vars + secret settings decrypt edilemez (zaten önceden böyleydi).
- **Agent command channel devre dışı** — `POST /api/agents/{id}/commands` 503 döner, hiçbir komut dağıtılmaz. UI'da AgentActionMenu çalışmaz, system upgrade tetiklenemez.

İmzalama anahtarı HKDF (`label="muvon-agent-command-v1"`) ile türetilir; key rotate edersen tüm `pending`/`dispatched` komutlar bir sonraki agent doğrulamasında reddedilir (imza mismatch). Bu yüzden key **gerçekten stabil** olmalı.

## 30) Agent command teslim **at-least-once**

Komut handler'ları `cmd/agent/commands.go`'da idempotent yazılır. Aynı komut ID'si iki kez gelirse `Registry.markSeen` (LRU 1000 entry) dedup yapar. Yine de **operatör side dikkat**:
- Aynı komutu UI'dan iki kez göndermek = `agent_commands` tablosunda iki ayrı row (farklı UUIDv7'lar). Dedup sadece **aynı ID**'nin tekrar teslim edilmesine karşı.
- `agent.restart` veya `agent.revoke` gibi yıkıcı komutları **birden fazla kez göndermeyin** — history kirlenir, supervisor restart loop'a girer gibi yanıltıcı görünüm.

## 31) System upgrade eşzamanlılığı 409 ile bloke

Process-wide `upgradeBroker` aktif tek upgrade'e izin verir. İkinci `POST /api/system/upgrade` çağrısı 409 alır. SSE stream (`GET /api/system/upgrade/stream`) late-joining listener'lar için event history replay'i yapar — yani upgrade başladıktan sonra bağlanan UI ilk event'leri kaçırmaz.

**v0.1.4'ten itibaren** helper container kademeli recreate yapar (muvon + dialog-siem önce, muvon-deployer en son) — deployer'ın spawn'ı yaptığı helper, kendi recreate sırasında muvon zaten Healthy olduğu için. Plus admin handler stream EOF'unu körü körüne "done" sayma yerine `:9443/api/health`'i 60 sn poll eder; başarısızsa `failed` event'i yayar. v0.1.0–v0.1.3 arası bu davranış yoktu, yarım kalan upgrade'ler UI'da yeşil tik gösteriyordu.

## 32) `keep_releases` çok düşük = rollback yolu kapanır

`deploy_components.keep_releases` (default 3) son N başarılı release'in image'ını host'ta tutar. **1'e düşürürsen rollback `POST /api/deploy/projects/{slug}/rollback` çağrısı image_pull başarısız olabilir** — eski tag GHCR'da varsa pull yeniden yapar, ama public olmayan registry'de auth sorunu çıkabilir. 50 üst sınır; 10+ büyük image'la (1 GB+) disk hızlı dolar.

Pratik öneriler:
- Üretim: 3 (current + 2 rollback hedefi).
- Büyük image (>1 GB) ve sık deploy: 2 (sadece bir önceki tutulur — disk öncelikli).
- Geliştirme: 1 (her promote eskisini siler — minimum disk).

UI: `ComponentEditorDialog` "Gelişmiş" sekmesi → "Tutulan release sayısı". DB CHECK ≥ 1, yani 0 set edilemez.

## 33) Image prune sırasında 409 = sessiz pas

`pruneImagesAfterPromote` her image_ref için `docker rmi` çağırır. Docker hâlâ kullanan bir container varsa 409 döner; kod 409'u **success** olarak yutar (loglanmaz). Bu doğru davranış — SQL `in_use` filter tutamadığı bir use-case'i (ör. başka bir component aynı image'ı paylaşıyor) Docker refcount yakalar. Symptom: image silinmesini bekledin, hâlâ var → muhtemelen başka bir container kullanıyor (`docker ps -a --filter ancestor=<ref>`).

## 34) Reconcile orphan'ları `ContainerListAll(all=1)` ile bulur

Eskiden `ContainerList` (running-only) kullanılıyordu, bu yüzden exited orphan'lar (failed migration, crashed candidate) görünmüyordu. v0.1.0 itibarıyla `ContainerListAll` ile tüm state'ler taranır. Bu da demektir ki: `muvon.managed=true` label'lı **DB'de olmayan** her container'a (state ne olursa olsun) `ContainerStop` + `ContainerRemove(force=true)` uygulanır. Manuel `docker run` ile `muvon.managed=true` label vermek = bir sonraki tick'te silinir.

## 35) `agent.revoke` clean shutdown, crashloop değil

`POST /api/agents/{id}/commands` body `{"kind":"agent.revoke"}` agent'ı **kalıcı durdurur**:
1. Central tarafında `agents.is_active=false` set edilir.
2. Komut agent'a teslim edilir; handler `os.Exit(1)` yapar.
3. Supervisor agent'ı yeniden başlatmaya çalışırsa central auth'u reddeder (`is_active=false`), agent immediately çıkar — crashloop'a girer gibi görünür, ama bu beklenen davranış.

Geri alma: yeni agent enroll (`POST /api/agents`); eski kayıt sırasıyla silinir (`DELETE /api/agents/{id}`). Plaintext API key bir kez döner — kaybedersen tekrar enroll.

## 36) Docker subnet'i ve agent container IP'si kurulumdan kuruluma DEĞİŞİR

Agent host'unda tipik olarak iki ağ olur: agent'ın paylaşımlı proxy ağı (`muvon-agent_default`) ve
uygulamanın DB ağı. Docker bunlara subnet'i **yaratılma sırasına** göre dağıtır. Uygulamanın DB
compose'u önce ayağa kalktıysa `172.18.0.0/16`'yı o kapar ve agent ağı `172.19.0.0/16` olur; sıra
tersse tam tersi. Aynı ürünün iki kurulumunda bu iki farklı çıkabilir.

Sonuçları:
- Bir install şablonuna, doküman örneğine veya uygulama env'ine **sabit subnet ya da sabit agent IP
  yazma**. Bir host'ta doğru olan diğerinde sessizce yanlış olur.
- `ipv4_address` ile pin atmak istiyorsan compose'da ağı açık `ipam.config.subnet` ile de tanımlaman
  gerekir; bu da o subnet'in her host'ta boş olduğu varsayımını yapar (başka bir ağ kapmışsa ağ
  oluşturma çakışır).
- Agent'ın son okteti pratikte `.2` çıkma eğiliminde (compose'da ilk yaratılan container), ama bu bir
  garanti değil: agent silinip yeniden yaratılırken araya bir deploy girerse yeni uygulama
  container'ı boşalan adresi kapar.

Doğru yaklaşım: adresi **çalışma anında** öğren (`docker network inspect <ağ>`), konfigürasyona gömme.

## 37) Gerçek istemci IP'si: uygulama tarafı ayarlanmazsa SESSİZCE yanlış olur

MUVON edge'i `X-Forwarded-For` gönderir, ama arkadaki uygulama sunucusu bu header'a **varsayılan
olarak güvenmez**. Güvenmediğinde istemci IP'si diye kaydettiği şey **edge container'ının IP'si**
olur. Hiçbir şey patlamaz: site açılır, istekler çalışır, sadece log/audit/rate-limit kayıtlarındaki
IP yanlıştır. Bu yüzden aylarca fark edilmeden kalabilir.

Sunucuya göre ayar:

| Sunucu | Ayar | Varsayılan |
|---|---|---|
| gunicorn | `FORWARDED_ALLOW_IPS` env veya `--forwarded-allow-ips` | `127.0.0.1` (edge'e güvenmez) |
| uvicorn | `--proxy-headers --forwarded-allow-ips` | proxy header'ları kapalı |
| Django | `SECURE_PROXY_SSL_HEADER` (yalnız şema için), IP'yi WSGI sunucusu belirler | yok |
| nginx (SPA/statik) | `set_real_ip_from` + `real_ip_header` | yok |

İki tuzak:
- **gunicorn'da CLI argümanı env'i ezer.** `FORWARDED_ALLOW_IPS` env'ini düzeltip komut satırında
  eski değer kalırsa hiçbir şey değişmez. Her ikisini de kontrol et:
  `docker inspect <container> --format '{{json .Config.Cmd}}'` ve `docker exec <container> env | grep -i forwarded`.
- **gunicorn CIDR desteklemez.** `gunicorn/http/message.py` içinde eşleştirme
  `peer_addr[0] in cfg.forwarded_allow_ips`, yani düz liste üyeliği. `172.18.0.0/16` yazarsan hiçbir
  adrese uymaz ve sessizce "güvenme" moduna düşer. Seçenekler: tam IP ya da `*`.

**Doğru ayar: adresi elle yazma, `${MUVON_EDGE_IP}` kullan.** Deployer container'ı yaratırken
edge proxy'nin o component'in ağındaki güncel adresini bulur, `MUVON_EDGE_IP` olarak env'e koyar ve
component env değerlerindeki `${MUVON_EDGE_IP}` token'ını onunla değiştirir. Yani:

```
FORWARDED_ALLOW_IPS=${MUVON_EDGE_IP}
```

Bu değer her deploy'da yeniden çözülür, dolayısıyla Docker adresi değiştirdiğinde (bkz. #36) ayar
kendiliğinden doğru kalır. Değişim **birebir token değişimidir**, kabuk tarzı genişletme değil, o
yüzden içinde `$` geçen secret değerler bozulmaz.

Edge adresi çözülemezse token **olduğu gibi bırakılır**: boş bir allow-list yazıp güveni sessizce
kapatmaktansa görünür bir hata bırakmak tercih edilir. Central'da proxy ile deployer ayrı
container'lar olduğu için proxy `muvon.role=edge` etiketinden bulunur; agent host'unda deployer zaten
proxy'nin içinde çalıştığı için kendi container'ına bakar.

Teşhis: `dialog.http_logs`'ta `client_ip` dağılımına bak. Tek bir private adres baskınsa
(özellikle edge'in container IP'si) trust ayarı yok demektir:
```sql
SELECT client_ip, count(*) FROM dialog.http_logs
WHERE timestamp > now() - interval '1 hour'
GROUP BY 1 ORDER BY 2 DESC LIMIT 10;
```

## 38) Host firewall'ı gerçek maruziyeti göstermez

`ufw inactive` ve `iptables INPUT ACCEPT` görmek "bu port dünyaya açık" demek DEĞİLDİR. Sağlayıcı
seviyesinde (cloud firewall, security group, VPC ACL) bir katman olabilir ve host'un içinden
görünmez. Tersi de doğru: ufw açık olsa bile provider katmanı beklenmedik bir portu açabilir.

`ss -tlnp`'nin `0.0.0.0` göstermesi yalnız **process'in** tüm arayüzleri dinlediğini söyler, o
paketin dışarıdan gelebildiğini değil.

Hüküm vermeden önce **dışarıdan ölç**:
```bash
nc -z -G 4 -w 4 <public-ip> <port> && echo acik || echo kapali/filtreli
```
Kontrol için bilinen açık bir portu (443) da test et; ikisi de kapalı çıkıyorsa ölçüm yolun bozuktur.

## 39) Self-upgrade helper container'ları ve eski image'lar birikir

`agent.self_upgrade` ve sistem upgrade akışı kısa ömürlü bir `docker:*-cli` helper container'ı
başlatır. Bu container `--rm` ile silinmez, `Exited(0)` olarak kalır. Uzun süredir ayakta olan
kurulumlarda onlarca birikir. Aynı şekilde eski sürüm image'ları da temizlenmez;
`pruneImagesAfterPromote` yalnız **managed component** image'larını kapsar, MUVON'un kendi
image'larını değil.

İşlevsel zarar yok ama `docker ps -a` okunmaz hale gelir ve disk şişer. Kontrol:
```bash
docker ps -a --filter "status=exited" --filter "ancestor=docker:27-cli"
docker system df
```
Temizlik yıkıcı bir işlemdir, operatör onayıyla yapılır (bkz. `destructive-ops.md`).

## 40) Agent'lar `:latest` kullanır, filo tek tip DEĞİLDİR

Agent compose'u genelde `VERSION=latest` ile gelir ve her host kendi upgrade'ini kendi zamanında
alır. Bir host'ta düzeltilmiş bir bug diğerinde hâlâ canlı olabilir. "Sürümü yükselttik" demek
**tüm** agent'ların yükseldiği anlamına gelmez.

Filo genelinde sürümü doğrula:
```bash
# her agent host'unda
docker inspect <agent-container> --format '{{index .Config.Labels "org.opencontainers.image.version"}}'
```
`:latest` tag'i yalnız yeni bir sürüm tag'i yayınlandığında hareket eder; agent'ın onu alması için
ayrıca `agent.self_upgrade` komutu (veya compose pull) gerekir.

## 41) Component silinince route'un bağı kopar (taşımalarda ana tuzak)

`agent_id` değiştirilemediği için bir component'i başka host'a taşımanın tek yolu silip yeniden
yaratmaktır (bkz. #23). Yeni component **yeni bir id alır**, oysa `routes.managed_component_id`
eskisini işaret ediyordu. DELETE sırasında bu alan `NULL`'a düşer ve route hiçbir backend'e
bağlı kalmaz.

Belirti son derece yanıltıcı: container'lar `healthy`, `/api/deploy/projects` çıktısında
instance'lar `active`, `GET /api/system/health/backends` hepsini `open` gösterir, ama **tüm
domainler 502 döner**. Backend sağlıklı olduğu için hata deployer'da veya uygulamada aranır;
oysa sorun route katmanındadır.

Taşıma sonrası mutlaka kontrol et:
```sql
SELECT h.domain, r.path_prefix, COALESCE(r.managed_component_id::text,'NULL') AS comp
FROM muvon.routes r JOIN muvon.hosts h ON h.id = r.host_id
WHERE h.domain LIKE '%<proje>%' ORDER BY 1;
```
`NULL` görünen her proxy route'u yeni component id'sine bağla. `PUT /api/routes/{id}`
gövdesi **tam route objesi** ister (pointer alan yok), bu yüzden önce `GET /api/routes/{id}`
ile oku, yalnız `managed_component_id`'yi değiştir, geri yaz.

Ayrıca **bir route tamamen kaybolabilir**: gerçek bir taşımada `form.tatilji.online`'ın tek
route'u silindi ve o domain 404 vermeye başladı. Taşıma öncesi ve sonrası route sayısını
karşılaştır, eksik olanı `POST /api/hosts/{id}/routes` ile geri ekle.

## 42) Aynı host'ta iki proje aynı slug'ı kullanırsa Docker ağ adı çakışır

Deployer container'ı ağa component slug'ıyla bağlar. Tek projeli host'ta sorun yok, ama çok
projeli bir host'ta iki projenin de `api` adlı component'i varsa **iki container aynı adı
paylaşımlı proxy ağında talep eder**. Docker DNS bu durumda round-robin yapar:
`http://api:8000` isteği rastgele bir projenin servisine düşer.

Gerçek bir kurulumda dört container `api`, dört container `landing`, iki container `admin`
adını paylaşıyordu. Hiçbir şey hata vermez, sadece yanlış projenin verisi servis edilir.
Özellikle SSR yapan landing'lerin `SERVER_API_URL=http://api:8000` ayarı bundan etkilenir.

Kontrol:
```bash
for c in $(docker network inspect muvon-agent_default --format '{{range .Containers}}{{.Name}}{{println}}{{end}}'); do
  docker inspect "$c" --format '{{.Name}} {{range $k,$v := .NetworkSettings.Networks}}{{if eq $k "muvon-agent_default"}}{{$v.Aliases}}{{end}}{{end}}'
done | sort -k2
```
Aynı ad birden fazla satırda görünüyorsa çakışma var.

Çözüm: bu sürümden itibaren container'lar ek olarak `<proje>-<component>` adını da taşır.
Çok projeli host'larda component'ler arası çağrıları bu uzun ada çevir
(`SERVER_API_URL=http://tatilji-api:8000`). Kısa ad geriye uyumluluk için duruyor, ama çok
projeli bir host'ta ona güvenme.
