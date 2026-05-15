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
