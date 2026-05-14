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

## 25) `paused` servisler enqueue reddeder

`deploy_components.paused=true` ise yeni deploy denemesi (webhook / manual / rollback) `component X is paused; resume it before deploying` ile reddedilir. Önce `PUT .../components/<x>` ile `paused: false` yap.

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

Helper container deployer'ı **kendisi de** recreate eder; gRPC stream EOF görünür. Admin handler bu EOF'u `done` event'i olarak yorumlar — bunu hata zannetme. Browser tarafında SSE bağlantısı düşer, UI "Sayfayı yenile" butonu gösterir.

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
