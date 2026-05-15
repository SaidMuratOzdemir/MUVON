# MUVON mimarisi — operatör için 5 dakikalık özet

## Servisler

Tek Go modülü (`muvon`), dört bağımsız binary:

| Binary | Rolü | DB şeması |
|---|---|---|
| **muvon** | Edge gateway + admin API + admin SPA. TLS terminator. Host/route/cert/agent yönetimi. | `muvon` |
| **dialog-siem** | HTTP/container log pipeline. BM25 (pg_search) arama, TimescaleDB hypertable, korelasyon, alert üretimi. | `dialog` |
| **muvon-deployer** | Docker socket sahibi. DB'yi poll eder, yeni deploy job'larını çalıştırır. Container log shipping (logship). | yok |
| **agent** | Edge VPS'lere kurulan ince istemci. Central MUVON'dan config çeker (SSE), diaLOG'a log gönderir (TCP gRPC). `AGENT_DEPLOYER_ENABLED=true` ise lokal Docker socket'iyle aynı managed-deploy lifecycle'ını koşturur (kendi `agent_id`'sine atanmış component'ler için). | yok (config çeker) |

## Servisler arası iletişim

- **Unix socket** (`/run/muvon/{dialog,deployer}.sock`) — central VPS içi.
- **TCP gRPC :9001** — uzak agent → central diaLOG (firewall sınırlı).
- **HTTP + SSE** — uzak agent ↔ central muvon (config sync, watch).
- **Fail-open**: diaLOG çökerse traffic akmaya devam eder, log düşer.

## Veritabanı

Tek PostgreSQL 18 instance, **şema izolasyonlu**. Aktif eklentiler:
- **TimescaleDB** — `http_logs`, `http_bodies`, `alerts` hypertable. 7g compression, 30g retention.
- **pg_search** (ParadeDB/Tantivy) — `http_logs` üzerine BM25 indexes. Elasticsearch dependency yok.
- **pg_uuidv7** — primary key'ler zaman-sıralı; `ORDER BY id` chronological.

`schema_migrations` tablosu, `internal/db/migrations.go` slice'ı. Her migration `product` ile etiketli (`muvon`, `dialog`, ``=shared).

## Önemli mantık parçaları (operatör için)

### Config holder + hot reload
`internal/config/Holder` atomic.Value snapshot. Her DB değişikliğinden sonra `POST /api/system/reload` çağrılırsa:
1. Holder DB'den yeniden hidrasyon yapar.
2. Connected agent'lara SSE üzerinden push edilir.

DB'ye **direkt INSERT/UPDATE** çekersen reload tetiklemezsen yeni değer **load olmaz**. Bu yüzden yazma her zaman API üzerinden.

### Secret box (`internal/secret`)
AES-256-GCM. Settings'teki secret alanları (`muvon_jwt_secret`, SMTP password vs) şifreli saklar. `MUVON_ENCRYPTION_KEY` env stabil olmalı; yoksa eski secret'lar okunamaz olur.

API'de secret değerler **write-only**: `GET /api/settings` boş string döner (mask).

### Proxy pipeline (özet)
Her request için: host eşleştir → en uzun path prefix → proxy/static/redirect/accel → log_enabled ise diaLOG'a async log gönder.

### Managed deploy (hibrit topoloji)
Lifecycle aynı, host iki yerden biri:
1. Image pull
2. Migration container
3. Candidate start
4. Health check
5. **Atomic promote**: eski active → draining, candidate → active
6. Graceful drain (eski instances)

Proxy **sadece** `active` instance'lara yönlendirir. Drain sırasında eski instance hala in-flight request'lere cevap verir.

**Topoloji ayrımı `agent_id` ile:**
- `deploy_components.agent_id IS NULL` → central `muvon-deployer` (DB'ye direkt erişim) işler.
- `deploy_components.agent_id = '<id>'` → o agent'ın embedded deployer'ı (`AGENT_DEPLOYER_ENABLED=true`) işler. Aynı lifecycle kodu, ama state'i HTTP üzerinden central'a yazar (`/api/v1/agent/deployer/*`).

Kod paylaşımı `internal/deployer/State` interface'i ile:
- `NewDBState(*db.DB, agentID)` — central + edge (DB-direkt). Central `agentID=""` ile filterler.
- `NewAPIState(centralURL, apiKey)` — edge'in HTTP adapter'ı. State değişiklikleri central admin sunucusunun X-Api-Key endpoint'lerine düşer.

**Enqueue kuralı:** Bir deploy'da kullanılan tüm component'ler aynı `agent_id`'ye sahip olmalı. Aksi halde `enqueue deployment: components straddle hosts` ile reddedilir. `agent_id` create'te seçilir, update'le değiştirilemez — yoksa eski host'ta orphan container kalır.

**Secret env vars:** `deploy_components.env_secret_keys` listesindeki key'lerin value'ları `enc:` prefix'li ciphertext (AES-256-GCM). Deployer container başlatırken decrypt eder. `MUVON_ENCRYPTION_KEY` central ↔ deployer ↔ `AGENT_ENCRYPTION_KEY` edge'de **aynı olmak zorunda**, yoksa container başlatılamaz.

**Cleanup + image prune.** Her tick'in başında üç bakım adımı: (1) `cleanupDraining` — draining instance'ları `ContainerStop` + `ContainerRemove(force=true)`, başarısız remove tekrar denenir (DB state `draining` kalır); (2) `reconcileOrphanContainers` — `muvon.managed=true` label'lı container'ları `ContainerListAll(all=1)` ile listele, DB'de live olmayanları sil (exited carcass'lar dahil); (3) `CleanupStaleWarming` — deployment terminated ama warming'de kalmış instance'ları `unhealthy` işaretle. Başarılı promote sonrası `pruneImagesAfterPromote` çalışır: her component için `keep_releases` (default 3, SQL CHECK ≥ 1) dışındaki ve canlı bir instance'a bağlı olmayan image_ref'ler `docker rmi` ile yerelden silinir. Docker'ın kendi refcount'u + SQL-side `in_use` filter çift güvence; 409 (in-use) ve 404 (already gone) sessizce yutulur.

### Central → agent komut kanalı

Operatör `/agents` sayfasından her agent'a anlık komut yollar (`agent.cache_flush`, `agent.set_log_level`, `cert.renew`, `agent.drain`, `agent.restart`, `agent.self_upgrade`, `agent.revoke`, `container.restart`). Pattern:

1. Komut `muvon.agent_commands` tablosuna yazılır (UUIDv7 PK, HMAC-SHA256 imza, `nonce`, `expires_at`).
2. İmzalama anahtarı: HKDF(`MUVON_ENCRYPTION_KEY`, label=`"muvon-agent-command-v1"`). Key boşsa channel sessizce devre dışı, admin endpoint 503.
3. Agent uzun-pollar (`GET /api/v1/agent/commands?wait=25s`). Central INSERT edince `CommandBus.Wake(agentID)` agent'ı uyandırır — fast-path ~50 ms.
4. Agent imza + nonce + expires_at doğrular; son 1000 ID için LRU dedup (at-least-once delivery).
5. Sonucu `POST /api/v1/agent/commands/:id/result` ile döner. State: `pending → dispatched → succeeded|failed|expired`.
6. Sweeper goroutine 30 sn'de bir stale (`>5 dk`) satırları `expired` yapar.

Yıkıcı komutlar (`agent.revoke`, `agent.restart`, `agent.self_upgrade`, `agent.drain`): bkz. `destructive-ops.md`.

### Sistem self-upgrade (helper-container)

Settings → Sistem'den tek tıkla upgrade. Akış:

1. `GET /api/system/version` çalışan binary'nin sürümünü; `GET /api/system/version/latest` GHCR manifest HEAD (anonim, 5 dk cache) `:latest` digest'ini verir. UI karşılaştırır.
2. `POST /api/system/upgrade {target_tag, take_backup}` → admin → deployer gRPC `SystemUpgrade` (server-streaming).
3. Deployer: in-process mutex (409 on concurrent) → target tag normalize (v strip) → `pg_dump -Fc` (postgres container'da `docker exec`) → `docker:27-cli` helper container spawn et (mount: docker socket + `/opt/muvon:/host/muvon:rw`).
4. Helper script: `wget` compose'u GitHub raw'dan tazele → `sed` ile `:latest` → `:<target>` → `compose pull` → `compose up -d --no-deps --wait muvon dialog-siem` (önce) → `compose up -d --no-deps --wait muvon-deployer` (SON — helper'ın spawn'ı bu, recreate'i son'a iter).
5. Deployer recreate'i sırasında gRPC stream EOF olur. Admin handler bunu **başarı saymaz**: `:9443/api/health`'i 60 sn boyunca polluyor; 200 dönerse `done`, dönmezse `failed` event'i yayar.
6. UI canlı progress: `GET /api/system/upgrade/stream` SSE (`pull` / `restart` / `post_check` event'leri).

`docker-compose.yml` mount gerekleri: `/var/run/docker.sock`, `/opt/muvon:/host/muvon:rw`, `backups` volume.

## Repo haritası

```
cmd/
  muvon/           — edge gateway + admin server
  dialog-siem/     — SIEM
  muvon-deployer/  — deploy worker
  agent/           — edge agent
internal/
  admin/           — admin HTTP API (handlers_*, server.go, auth, csrf, cookies, middleware)
  agentsvc/        — agent config/watch/cert endpoints
  alerting/        — Slack/SMTP alert dispatchers
  config/          — Holder + Source (DBSource / AgentSource)
  correlation/     — anomaly/error-spike/auth-brute/export-burst
  db/              — pgx pool, migrations
  deployer/        — managed deploy worker, logship, gRPC
  geoip/           — MaxMind reader
  health/          — health/stats handlers
  identity/        — JWT identity extraction (kuryeden JWT user_id çıkar)
  logger/          — log enqueue → diaLOG
  middleware/      — proxy middlewares (rate limit, cors, security)
  proxy/           — proxy pipeline + accel + redirect
  router/          — host+path matcher
  secret/          — AES-GCM box
  tls/             — Let's Encrypt + cert cache
proto/             — protobuf (logpb, deployerpb)
frontend/dist/     — embedded SPA (go:embed)
ui/                — React SPA kaynağı
```

## Önemli notlar

- **Go modül adı `muvon`** — import path `muvon/internal/...`. Asla relative yapma.
- **CGO_ENABLED=0** — saf Go, hızlı build, küçük binary.
- **`embed.go` paketi `dialog`** (tarihsel). Yapı `//go:embed frontend/dist`.
- Repo kökündeki `muvon`, `dialog-siem` checked-in binary'ler **build input değil**, ignore et.

## CLAUDE.md

`/CLAUDE.md` projeyle ilgili tüm yapısal kuralları içerir. İlk şüphede oraya bak.
