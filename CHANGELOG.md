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

— henüz birikme yok.

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
