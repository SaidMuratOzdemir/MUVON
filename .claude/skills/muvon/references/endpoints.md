# Endpoint envanteri ve response biçimleri

Kaynak: `internal/admin/server.go` (route tablosu). Buradan bir şey eksik veya yanlış geliyorsa **kaynağa bak** — `grep -n "HandleFunc" internal/admin/server.go`.

## Auth

| Method | Path | Auth | CSRF | Not |
|---|---|---|---|---|
| POST | `/api/auth/setup` | yok | bypass | İlk kurulum, 409 sonra |
| POST | `/api/auth/login` | yok | bypass | Rate limited |
| POST | `/api/auth/refresh` | refresh cookie | bypass | Tek kullanımlık rotation |
| POST | `/api/auth/logout` | access | **gerekli** | 3 cookie'yi siler |

## Hosts

| Method | Path | Yıkıcı? |
|---|---|---|
| GET | `/api/hosts` | ✗ |
| POST | `/api/hosts` | mutating |
| GET | `/api/hosts/{id}` | ✗ |
| PUT | `/api/hosts/{id}` | mutating (özellikle `tls_mode` değişiklikleri ACME davranışını anında değiştirir) |
| **DELETE** | **`/api/hosts/{id}`** | **YIKICI** — bağlı route'lar yetim kalır |
| GET | `/api/hosts/{id}/dns-status` | ✗ — domain'i resolve eder, beklenen IP'lerle (central `public_ip` + agent'ların last-seen IP'leri) kıyaslar |
| GET | `/api/hosts/{id}/tls-status` | ✗ — sertifika geçerli mi, kaç gün kaldı, issuer ne |

`tls_mode` değerleri: `off` (HTTP-only), `redirect` (HTTP→HTTPS 301), `auto` (Let's Encrypt), `manual` (sadece yüklenmiş cert). `off` veya `manual` host'lar için ACME challenge **denenmez**.

## Routes

| Method | Path | Yıkıcı? |
|---|---|---|
| GET | `/api/hosts/{id}/routes` | ✗ |
| POST | `/api/hosts/{id}/routes` | mutating |
| GET | `/api/routes/{id}` | ✗ |
| PUT | `/api/routes/{id}` | mutating |
| **DELETE** | **`/api/routes/{id}`** | **YIKICI** |

## Logs (HTTP)

| Method | Path | Not |
|---|---|---|
| GET | `/api/logs` | Filtre query params: `host`, `status`, `method`, `path`, `q` (BM25), `since`, `until`, `limit`, `cursor` |
| GET | `/api/logs/stats` | Aggregations |
| GET | `/api/logs/stream` | **SSE** — `text/event-stream`. EventSource veya `curl -N` ile |
| GET | `/api/logs/{id}` | Tek log detayı (body dahil) |
| PUT | `/api/logs/{id}/note` | Operatör notu |
| POST | `/api/logs/{id}/star` | Star toggle |
| GET | `/api/logs/{id}/jwt` | JWT identity claim'leri |

**Tip**: `/api/logs?limit=10&status=500&since=1h` gibi pratik query'ler.

## Container logs

| Method | Path | Not |
|---|---|---|
| GET | `/api/containers` | Yönetilen container listesi |
| GET | `/api/containers/{id}` | Detay + status |
| GET | `/api/containers/{id}/logs/stream` | SSE live tail |
| GET | `/api/container-logs` | Geçmiş arama (post-deploy crash analizi) |
| GET | `/api/container-logs/{id}/context` | Bir log etrafında ±N satır |

## Alerts

| Method | Path |
|---|---|
| GET | `/api/alerts` |
| GET | `/api/alerts/stats` |
| GET | `/api/alerts/{id}` |
| POST | `/api/alerts/{id}/acknowledge` (yan etki: alert "ack'lı" işaretlenir, geri alınmaz) |

## Settings

| Method | Path | Not |
|---|---|---|
| GET | `/api/settings` | Secret alanlar maskelenir (boş string olarak döner!) |
| PUT | `/api/settings/{key}` | **YIKICI**: özellikle `muvon_jwt_secret`, `muvon_encryption_key` |

## TLS

| Method | Path |
|---|---|
| GET | `/api/tls/certificates` |
| POST | `/api/tls/certificates` (cert override) |
| **DELETE** | **`/api/tls/certificates/{id}`** |

## Agents

| Method | Path |
|---|---|
| GET | `/api/agents` |
| POST | `/api/agents` (yeni agent enroll) |
| **DELETE** | **`/api/agents/{id}`** |

## System

| Method | Path | Not |
|---|---|---|
| GET | `/api/system/health` | Servis sağlık özeti |
| GET | `/api/system/stats` | Go runtime + uptime + counters |
| GET | `/api/system/health/backends` | Backend health (managed components) |
| GET | `/api/system/health/ingest` | Log ingest pipeline durumu |
| POST | `/api/system/reload` | **Yan etki**: config holder yenile + SSE push agent'lara |
| GET | `/api/system/version` | Çalışan binary'nin sürümü + image digest (Settings → Sistem paneli buradan okur) |
| GET | `/api/system/version/latest` | GHCR `:latest` manifest digest (5 dk cache); anonim manifest HEAD |
| **POST** | **`/api/system/upgrade`** | **YIKICI** — body `{target_tag, take_backup}`. Deployer helper container'ı `docker compose pull && up -d --wait` çalıştırır. Eşzamanlı isteğe 409. Encryption key boşsa 503 |
| GET | `/api/system/upgrade/stream` | **SSE** — `pull` / `restart` / `post_check` event'leri canlı yayılır. Helper kendisini de recreate ettiği için stream EOF olunca "done" yorumlanır |

## Agents (admin) + komut kanalı

| Method | Path | Not |
|---|---|---|
| GET | `/api/agents` | List (plaintext `api_key` artık YOK; bkz. pitfalls #21) |
| POST | `/api/agents` | Create — yanıt `{agent, api_key}`, plaintext key sadece burada bir kez döner |
| **DELETE** | **`/api/agents/{id}`** | **YIKICI** — agent disconnect |
| **POST** | **`/api/agents/{id}/commands`** | Body `{kind, payload}`. `kind` ∈ `agent.cache_flush` / `agent.set_log_level` / `cert.renew` / `agent.drain` / `agent.restart` / `agent.self_upgrade` / `agent.revoke` / `container.restart`. HMAC imzası central tarafında otomatik takılır. **`agent.revoke` ve `agent.restart` ve `agent.self_upgrade` YIKICI** (bkz. destructive-ops.md) |
| GET | `/api/agents/{id}/commands` | Son N komut + state (`pending`/`dispatched`/`succeeded`/`failed`/`expired`). UI'daki `AgentCommandHistory` bunu çeker |

Komut state makinesi: `pending → dispatched → succeeded|failed|expired`. Sweeper goroutine 30 sn'de bir stale satırları expired'a çevirir (default TTL = 5 dk). Encryption key boşsa endpoint sessizce 503 — komutlar **asla yanlış imza ile** dağıtılmaz.

## Audit

| Method | Path | Not |
|---|---|---|
| GET | `/api/audit` | `?limit=N&cursor=...` |

**UYARI**: Audit log şu anda agent ve human admin arasında ayrım yapmıyor (`admin_user: admin` her ikisi için). Bkz. SKILL.md "Her yıkıcı çağrı öncesi disiplin".

## Deploy

| Method | Path | Not |
|---|---|---|
| GET | `/api/deploy/projects` | Project + components + instances ağacı |
| POST | `/api/deploy/projects` | Yeni app yarat (slug, name, source_repo, webhook_secret) |
| PUT | `/api/deploy/projects/{slug}` | App ayarları (name, source_repo, webhook_secret rotate) |
| **DELETE** | **`/api/deploy/projects/{slug}`** | **YIKICI** — tüm servisler, release'ler, instance'lar cascade siler |
| GET | `/api/deploy/projects/{slug}/secret` | HMAC secret (webhook için) |
| POST | `/api/deploy/projects/{slug}/components` | Servis yarat (`slug`, `name`, `image_repo`, `internal_port`, `agent_id`, `env`, `env_secret_keys`, vb.) |
| GET | `/api/deploy/projects/{slug}/components/{component}` | Servis detay (secret env'ler `********` ile maskeli) |
| PUT | `/api/deploy/projects/{slug}/components/{component}` | Servisi güncelle; **`agent_id` güncellenemez** (yok sayılır), `paused` güncellenebilir |
| **DELETE** | **`/api/deploy/projects/{slug}/components/{component}`** | **YIKICI** — instance'lar drain edilir |
| GET | `/api/deploy/deployments` | Geçmiş deploy'lar |
| GET | `/api/deploy/deployments/{id}/events` | Deploy lifecycle event'leri |
| POST | `/api/deploy/deployments/{id}/rerun` | Bir deploy'u yeniden çalıştır |
| **POST** | **`/api/deploy/projects/{slug}/deploy`** | **YIKICI** — production'a yeni image |
| **POST** | **`/api/deploy/projects/{slug}/rollback`** | **YIKICI** — önceki succeeded release'in image_ref'leri ile yeni deployment kuyruğa eklenir |
| POST | `/api/deploy/webhook` | HMAC ile imzalı, JWT bypass — auth yok |

**Env vars + secrets.** Servis create/update payload'ında `env: {KEY: value}` map + `env_secret_keys: [KEY1, KEY2]` listesi. Listedekilerin value'ları AES-256-GCM ile şifreli saklanır. GET yanıtında `********` döner. Update sırasında `********` geri gönderilirse mevcut ciphertext korunur — secret'ı rotate etmek için yeni plaintext gönder.

**Cross-host straddle yasak.** Bir deploy'un tüm component'leri aynı `agent_id`'de olmalı. Aksi halde enqueue `components straddle hosts` ile reddedilir.

## Alerting test

| Method | Path | Not |
|---|---|---|
| POST | `/api/alerting/test/slack` | **Gerçek Slack mesajı gider** |
| POST | `/api/alerting/test/smtp` | **Gerçek email gider** |

## Agent API (edge agent için, admin değil)

`/api/v1/agent/...` — JWT yerine `X-Api-Key: <agent-key>` header. Sadece edge VPS'lerdeki `agent` binary'sini ilgilendirir. Skill'in operatör akışında **kullanılmaz**, sadece teşhis için bilgi:

| Method | Path | Not |
|---|---|---|
| GET | `/api/v1/agent/config` | Agent kendi config snapshot'ını çeker |
| GET | `/api/v1/agent/watch` | SSE — central config değiştiğinde push alır |
| GET / POST | `/api/v1/agent/cert/{domain}` | Cert pull (admin upload) / push (agent'ın ACME'sinin backup'ı) |
| POST | `/api/v1/agent/deployer/claim` | Embedded edge deployer kendi `agent_id`'sine ait pending deploy'u çeker |
| GET | `/api/v1/agent/deployer/plan/{id}` | Deploy planı (proje, release, component'ler) |
| POST | `/api/v1/agent/deployer/event` | Lifecycle event ekle |
| POST | `/api/v1/agent/deployer/fail` | Deployment'ı `failed` işaretle |
| POST | `/api/v1/agent/deployer/instance` | Yeni candidate container instance kaydı |
| POST | `/api/v1/agent/deployer/instance/unhealthy` | Instance'ı `unhealthy` işaretle |
| POST | `/api/v1/agent/deployer/instance/stopped` | Instance'ı `stopped` işaretle |
| POST | `/api/v1/agent/deployer/promote` | Atomic promote (eski active drain, candidate active) |
| POST | `/api/v1/agent/deployer/reset-stale` | Crash sonrası `running` stuck deployment'ları `pending`'e geri al |
| POST | `/api/v1/agent/deployer/cleanup-warming` | Biten deployment'a ait kalmış warming instance'ları temizle |
| GET | `/api/v1/agent/deployer/drainable` | Drain'i tamamlanan instance'ları listele |
| GET | `/api/v1/agent/deployer/live-containers` | Central'ın hâlâ canlı saydığı container ID'leri (orphan reconcile için) |
| GET | `/api/v1/agent/commands?wait=25s` | **Long-poll** — sıradaki imzalı komutu çek. Agent uyandığında veya wait dolduğunda 200 + komut payload'u; boşsa 204 |
| POST | `/api/v1/agent/commands/{id}/result` | Terminal report: `{state: succeeded|failed, output?, error?}`. At-least-once teslim, handler idempotent olmalı |

Hepsi `X-Api-Key`-auth + ownership filter — agent yalnız kendi `agent_id`'sine ait kayıtları görür/değiştirir.

## Response biçimleri — TUTARSIZ, dikkat

| Endpoint örnekleri | Biçim |
|---|---|
| `/api/hosts`, `/api/hosts/{id}/routes`, `/api/agents`, `/api/deploy/projects` | **Doğrudan array** `[ {...}, {...} ]` |
| `/api/logs`, `/api/audit`, `/api/alerts`, `/api/container-logs`, `/api/containers` | **Zarflı** `{"data":[ ... ], ...}` |
| `/api/system/stats`, `/api/system/health`, `/api/settings` | Object |
| 401/403/500 | `{"error":"..."}` |
| **404** | **`404 page not found`** (plain text — JSON DEĞİL!) |
| Yeni kaynak yaratma (POST 201) | Yaratılan kaynak objesi (zarfsız) |

Agent: response'tan veri çıkarmadan önce `jq -e` veya benzeri ile yapıyı doğrula.

## SSE örneği (`/api/logs/stream`)

macOS'ta `timeout` yok; alternatifler:

```bash
# Linux:
timeout 5 curl -sS -N -b "$CJ" "$BASE/api/logs/stream?host=foo.com"

# macOS:
( curl -sS -N -b "$CJ" "$BASE/api/logs/stream?host=foo.com" & PID=$!; sleep 5; kill $PID ) 2>/dev/null

# Veya:
gtimeout 5 curl ...  # coreutils kuruluysa
```

SSE event biçimi: `data: {...}\n\n`. Stream uzun süreli; bağlantı kopması normaldir (idle 60s sonra), reconnect gerekirse `Last-Event-ID` header.

## Path param kullanımı

Sayısal ID (`{id}`) veya slug (`{slug}`):
```bash
muvon_api GET "/api/hosts/2/routes"
muvon_api GET "/api/deploy/projects/<slug>"
muvon_api GET "/api/deploy/projects/<slug>/secret"
```

URL-encode etmek gerek değil (slug'lar zaten safe). Domain isimleri ID değil — host endpoint'leri ID-based.
