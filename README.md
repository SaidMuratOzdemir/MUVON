# MUVON

An edge gateway, security observability, and deploy platform composed of four independent Go services: a central reverse proxy with identity and geolocation enrichment, a SIEM engine with real-time correlation and alerting, a Docker-based managed deploy worker, and a lightweight edge agent that deploys on client servers.

### Standalone Mode (single server)

```
                          Internet (HTTPS)
                                |
                                v
                    +-----------+-----------+
                    |        MUVON          |
                    |   Edge Gateway :443   |
                    |   Admin: domain:443   |  ← MUVON_ADMIN_DOMAIN
                    +-----------+-----------+
                                |
                   Unix Socket  |
                   /run/muvon/  |
                    dialog.sock |
                                v
                         +------+------+
                         |   diaLOG    |
                         |  SIEM Engine|
                         +------+------+
                                |
                                v
                    +-----------+------------+
                    |    PostgreSQL 18       |
                    |   (Docker, internal)   |
                    +------------------------+
                                |
                    +-----------+-----------+
                    |    muvon-deployer     |
                    | /var/run/docker.sock  |
                    +-----------------------+
```

### Hub-and-Spoke Mode (distributed)

```
  Client Servers (agents)          Central Server
  ┌─────────────────────┐        ┌──────────────────────────────┐
  │  agent              │        │  MUVON  :443                 │
  │  :80/:443 (proxy)   │──SSE──▶│  (config push / hot reload)  │
  │  + edge deployer    │  HTTP  │                              │
  │  (optional)         │ ◀────▶│  (deployment lifecycle API)  │
  └─────────────────────┘        │                              │
  ┌─────────────────────┐        │  diaLOG  :9001 (TCP gRPC)    │
  │  agent              │──logs─▶│  (log ingestion from agents) │
  │  :80/:443 (proxy)   │        │                              │
  └─────────────────────┘        │  PostgreSQL 18  (internal)   │
                                 └──────────────────────────────┘
```

Agents are stateless: no database, no admin panel, no heavy processing. They pull configuration from central on startup, receive live config updates via SSE, and forward logs to diaLOG over TCP gRPC. TLS certificates are stored locally via ACME DirCache.

**Hybrid deploy.** Each app's services carry an `agent_id`: `NULL` = the central host runs the containers (via `muvon-deployer`); a specific agent ID = that edge agent runs the containers. The same lifecycle code drives both — agents enable it with `AGENT_DEPLOYER_ENABLED=true` and a reachable Docker socket. State (deployments, instances, releases) stays in the central DB; edge agents talk to it over `/api/v1/agent/deployer/*` (X-Api-Key auth).

---

## How It Works

MUVON sits at the edge and accepts all inbound HTTP/HTTPS traffic. For each request, it sends the full request/response pair to **diaLOG** for logging over a local Unix socket, so inter-service latency is measured in microseconds.

Each service is a standalone binary with its own database schema. They share a single PostgreSQL instance but never read each other's tables. If diaLOG goes down, MUVON continues routing traffic — logs are dropped, but the proxy never blocks.

| Service | What it does |
|---------|-------------|
| **MUVON** | Central server. Terminates TLS (auto Let's Encrypt or manual PEM), resolves virtual hosts, matches routes by path prefix, and proxies to upstreams. Serves the admin panel on `:443` for the configured `MUVON_ADMIN_DOMAIN` (falls back to `:9443` when no domain is set, for local dev). Enriches every log entry with **JWT identity** (verify + decode fallback) and **GeoIP** (country/city from local MaxMind DB). Provides config API and SSE watch endpoint for agents. |
| **agent** | Lightweight edge binary deployed on client servers. Pulls config from central MUVON on startup, watches for changes via SSE (hot reload). Proxies traffic using the central-managed host/route config. Sends logs to central diaLOG over TCP gRPC. No database, no admin panel — zero local state except ACME cert cache + an optional config snapshot for fail-soft cold-start (`AGENT_CONFIG_CACHE`). When `AGENT_DEPLOYER_ENABLED=true` it also runs the same managed-deploy lifecycle as `muvon-deployer` against its local Docker socket, with central reached via `/api/v1/agent/deployer/*` instead of a direct DB connection. |
| **diaLOG** | Receives structured log entries from MUVON or remote agents via gRPC (Unix socket for local, TCP for agents), buffers them in a Go channel, and flushes in batches using PostgreSQL `COPY FROM` for throughput. Stores logs in TimescaleDB Hypertables with UUIDv7 primary keys. Provides BM25 full-text search (via pg_search/Tantivy) across path, host, user-agent, and IP fields. Exposes SSE live tail for real-time monitoring. Runs a **correlation engine** that detects attack patterns (brute force, scanning, error spikes) in real time and triggers **alerts** via Slack and email. |
| **muvon-deployer** | A separate worker process that owns the Docker socket. Polls the database for pending deployment jobs and executes the full deploy lifecycle: image pull → one-off migration container → candidate container start → health check with restart retries → atomic promote (old active → draining, candidate → active) → graceful drain. Isolates host-level Docker access from the proxy and admin processes. |

---

## Quick Start

### Prerequisites

- **Go 1.24+**
- **Node.js 22+** (admin panel build için)
- **Docker** (postgres container için) veya harici PostgreSQL 18+
- PostgreSQL extensions:
  - [TimescaleDB](https://www.timescale.com/) — hypertables, compression, retention
  - [pg_search](https://github.com/paradedb/paradedb) (ParadeDB) — BM25 full-text search
  - [pg_uuidv7](https://github.com/fboulnois/pg_uuidv7) — UUIDv7 generation

### 1. Database Setup

```sql
CREATE DATABASE muvon;
\c muvon

CREATE EXTENSION IF NOT EXISTS pg_uuidv7;
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
CREATE EXTENSION IF NOT EXISTS pg_search;
```

### 2. Build

```bash
make deps
make build
# build/muvon, build/dialog-siem, build/agent, build/muvon-deployer

# Sadece muvon + agent (SIEM olmadan)
make build-minimal
```

### 3. Run

```bash
# 1. diaLOG (SIEM)
./build/dialog-siem \
  -dsn "postgres://muvon:muvon@localhost:5432/muvon?sslmode=disable" \
  -socket /tmp/dialog.sock

# 2. MUVON (edge gateway)
./build/muvon \
  -dsn "postgres://muvon:muvon@localhost:5432/muvon?sslmode=disable" \
  -log-socket /tmp/dialog.sock \
  -admin-domain panel.example.com
```

Open the admin panel on `https://panel.example.com` (or `http://127.0.0.1:9443` when `MUVON_ADMIN_DOMAIN` is unset) to:
1. Create the initial admin user (`POST /api/auth/setup`)
2. Add hosts (domains) you want to proxy
3. Add routes per host (proxy/static/redirect)
4. Configure TLS (auto Let's Encrypt by default)

---

## Güncelleme

`install.sh` ve `install-agent.sh` idempotent — aynı komut hem ilk
kurulum hem güncelleme için çalışır:

```bash
# Central host (merkezi MUVON sunucusu):
bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install.sh)

# Edge agent host (her birinde):
bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install-agent.sh)
```

Script ne yapar:

1. Compose ve postgres yardımcı dosyalarını yeniden indirir.
2. Mevcut `.env` korunur; yalnız yeni env satırları sona eklenir.
   `MUVON_ENCRYPTION_KEY` gibi secret'lar **kesinlikle overwrite edilmez**.
3. Update modunda PostgreSQL için `pg_dump -Fc` yedeği alınır
   (`/opt/muvon/backups/`). Son 5 yedek tutulur.
4. CHANGELOG'un son sürüm bölümü gösterilir, kullanıcı onayı istenir.
5. Image'lar pull edilir, servisler `up -d --wait` ile başlatılır.
6. Health check + sürüm raporu.

### Sürüm pin'leme

```bash
bash <(curl -fsSL .../install.sh) --version 0.1.0
```

`--version` verilmezse `:latest`. CI üç tier üretir: `0.1.0` (patch),
`0.1` (minor), `0` (major). Mevcut pin update'te korunur.

### Hibrit topoloji upgrade sırası

**Önce central, sonra her agent.** Yeni agent eski central'a istek atınca
`/api/v1/agent/deployer/*` endpoint'lerinde 404 alır; deploy loop'u durur
ama proxy/log işlevi çalışır.

```bash
# 1. Central
ssh central "bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install.sh)"

# 2. Health check (manuel)
curl -fsSL https://muvon.example.com/health

# 3. Her agent
for host in agent1 agent2; do
  ssh "$host" "bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install-agent.sh)"
done
```

### Migration disiplini

Migration'lar **forward-only**. `internal/db/migrations.go`'a yeni
migration **append edilir, asla edit ya da reorder edilmez**. Binary
startup'ta `RunMigrations` koşar — yeni image deploy edilince schema
otomatik yükselir.

**Downgrade desteklenmez.** Eski binary yeni schema ile uyumsuz olabilir;
PG snapshot'tan restore tek geri dönüş yolu.

### Backup / restore

Update öncesi otomatik `pg_dump -Fc` install.sh tarafından alınır.
Manuel:

```bash
docker compose exec -T postgres pg_dump -Fc -U muvon -d muvon \
  > /opt/muvon/backups/manual-$(date +%F).dump
```

Restore (felaket senaryosu):

```bash
docker compose stop muvon dialog-siem muvon-deployer
docker compose exec -T postgres pg_restore --clean -U muvon -d muvon \
  < /opt/muvon/backups/pgdata-YYYYMMDD-HHMMSS.dump
docker compose up -d
```

### CHANGELOG

[`CHANGELOG.md`](./CHANGELOG.md) sürüm değişikliklerinin kaynağıdır.
GitHub Release notları aynı içeriği taşır. Başlık taksonomisi: `BREAKING
/ SECURITY / FEATURES / ENHANCEMENTS / BUGFIXES`. Update öncesi her
zaman okumanız önerilir — script de zaten yapıyor.

---

## Architecture

```
                  Internet
                     |
                     v
          +----------+----------+
          |       MUVON         |   :443 (TLS termination)
          |   Edge Gateway      |   :80  (HTTP → HTTPS redirect)
          +-+-------------------+
            |
            +-----[gRPC]-----> /tmp/dialog.sock --> diaLOG (SIEM)
            |
            v
       Backend service
```

**Failure isolation.** If diaLOG goes down, MUVON keeps routing. Logs are dropped, admin Log pages show a 503 banner — everything else keeps working.

**Body capture.** Bodies are captured for `POST`/`PUT`/`PATCH`. `GET`/`DELETE`/`HEAD` are logged by headers, path, and query string only.

---

## Database Layout

Each service owns its own schema in a single PostgreSQL instance. No cross-schema reads.

| Schema | Service | Tables |
|--------|---------|--------|
| `muvon` | MUVON | hosts (`tls_mode`), routes, settings, tls_certificates, admin_users, admin_refresh_tokens, admin_audit_log, agents (`api_key_hash`), deploy_projects, deploy_components (`agent_id`, `paused`, `env`, `env_secret_keys`), deploy_releases, deploy_release_components, deploy_instances, deployments (`agent_id`), deployment_events |
| `dialog` | diaLOG | http_logs (Hypertable), http_log_bodies (Hypertable), log_notes, alerts, container_logs (Hypertable), containers |

---

## Features

### MUVON Edge Gateway

| Feature | Notes |
|---------|-------|
| TLS Termination | Per-host `tls_mode`: `off` / `redirect` / `auto` (Let's Encrypt) / `manual` (admin-uploaded PEM) |
| DNS verification | `GET /api/hosts/{id}/dns-status` resolves the domain and compares against central public IP + every agent's last-seen IP |
| TLS status | `GET /api/hosts/{id}/tls-status` reports cert validity, days remaining, issuer |
| Multi-Host Routing | Virtual host resolution by domain |
| Path-Prefix Matching | Longest-match wins, priority overrides |
| Per-Route Rate Limiting | Sliding window per IP, configurable RPS+burst |
| Per-Route Body Limit | `max_body_bytes`, returns 413 on exceed |
| Per-Route Timeout | `timeout_seconds`, propagates to upstream |
| CORS | Per-route origins, methods, headers, credentials |
| X-Accel-Redirect | Backend-controlled file serve, `accel_root` |
| Pre-Signed URLs | HMAC-SHA256 token + expires param |
| Static File Serving | `static_root` with optional SPA fallback |
| Redirect Routes | 301 redirects with optional target rewrite |
| Header Manipulation | Per-route add/del on request and response |
| Health-Aware Backends | Circuit breaker on consecutive failures |
| Multi-Backend Load Balance | Round-robin across `backend_urls[]` |
| Custom Error Pages | Per-route HTML for 4xx/5xx |
| One-Click Self-Update | Settings → Sistem: compare running binary vs latest GHCR digest, helper container runs `docker compose pull && up -d --wait`, automatic `pg_dump -Fc` backup, live SSE progress |
| Central → Agent Command Channel | Operator sends `cache_flush` / `set_log_level` / `cert.renew` / `drain` / `restart` / `self_upgrade` / `revoke` / `container.restart` from `/agents`; commands queued in DB with HMAC-SHA256 signature, long-poll delivery to agents, at-least-once + LRU dedup |

### Managed Deploy

| Feature | Notes |
|---------|-------|
| Hybrid topology | Components carry `agent_id`: NULL = central deployer runs the containers, set = the named agent's embedded deployer does |
| Project + service CRUD | `POST/PUT/DELETE /api/deploy/projects[/{slug}]`, `POST/GET/PUT/DELETE /api/deploy/projects/{slug}/components[/{component}]` |
| Env vars + secrets | Per-service env map; values for keys listed in `env_secret_keys` are AES-256-GCM encrypted at rest, masked on read, decrypted by the deployer at container start |
| CI/CD webhook | HMAC-SHA256 signed; admin panel reveals webhook URL + ready-to-paste GitHub Actions / GitLab CI / curl snippets |
| Manual deploy | Operator-triggered, same payload shape as the webhook |
| Rollback | `POST /api/deploy/projects/{slug}/rollback` redeploys the previous succeeded release verbatim |
| Pause / resume | `paused` flag drains a service and blocks new enqueues until cleared |
| Atomic promote | Old `active` → `draining`, candidate → `active` in one transaction; drain timeout configurable |

### diaLOG SIEM

| Feature | Notes |
|---------|-------|
| HTTP Logs | Full request/response capture: headers, bodies, timing, user identity, geolocation |
| TimescaleDB Hypertables | Daily chunks, 30-day retention, 7-day compression |
| BM25 Full-Text Search | pg_search index across path/host/UA/IP fields |
| UUIDv7 IDs | Time-ordered, K-sortable, no separate timestamp index |
| SSE Live Tail | Real-time log stream over Server-Sent Events |
| Body Capture | Configurable max size (default 64KB), truncation flag |
| JWT Identity Enrichment | Per-host verify/decode, claim extraction |
| GeoIP Enrichment | MaxMind GeoLite2 country/city lookup |
| Correlation Engine | path_scan, auth_brute, error_spike, traffic_anomaly, sensitive_access, data_export_burst |
| Alerting | Slack webhook + SMTP, per-fingerprint cooldown |
| Container Logs | stdout/stderr capture from managed containers, dimension table for picker |

### Admin Panel

React 19 + Vite 8 + shadcn/ui. Bundled into the `muvon` binary via `//go:embed`.

| Page | Route | Notes |
|------|-------|-------|
| Hosts | `/hosts` | CRUD virtual hosts + per-host JWT settings; expanding a row shows live DNS + TLS verification |
| Routes | `/routes` | Per-host routes (proxy/static/redirect) |
| Logs | `/logs` | Search, filter, view, star, note, live-tail |
| Alerts | `/alerts` | Correlation engine output, ack/dismiss |
| Containers | `/containers` | Live tail + history (managed and agent containers) |
| Uygulamalar | `/apps` | Central-hosted apps (services on the MUVON server); wizard, env editor, CI/CD snippets, rollback, pause |
| Uzak Uygulamalar | `/apps/edge` | Same UI filtered to apps whose services run on an agent host |
| Agents | `/agents` | API key management for hub-and-spoke setups (plaintext key revealed once on create) |
| Settings | `/settings` | Global settings (alerting, JWT, GeoIP, retention, central public_ip) |
| TLS | `/tls` | Manual PEM upload, ACME cert listing |
| Audit | `/audit` | Admin audit log |
| Settings → Sistem | `/settings` (üst panel) | One-click upgrade panel: running vs GHCR digest comparison, tag picker (`latest`/`v0`/`v0.1`/custom), DB backup toggle, inline CHANGELOG preview, live SSE progress |

If diaLOG is down, log pages show a service-offline banner. Everything else keeps working.

---

## Configuration

### MUVON

| Flag | Env var | Default | Notes |
|------|---------|---------|-------|
| `-dsn` | `MUVON_DSN` | `postgres://...` | PostgreSQL connection string |
| `-http` | `MUVON_HTTP_ADDR` | `:80` | HTTP listen address |
| `-https` | `MUVON_HTTPS_ADDR` | `:443` | HTTPS listen address |
| `-admin` | `MUVON_ADMIN_ADDR` | `:9443` | Admin API listen address (when admin-domain is unset) |
| `-admin-domain` | `MUVON_ADMIN_DOMAIN` | `""` | Serve admin panel on this domain via :443 |
| `-jwt-secret` | `MUVON_JWT_SECRET` | `change-me-in-production` | JWT signing secret for admin auth |
| `-log-socket` | `MUVON_LOG_SOCKET` | `/tmp/dialog.sock` | diaLOG Unix socket path |
| `-log-level` | `MUVON_LOG_LEVEL` | `info` | Log level (debug/info/warn/error) |
| `-encryption-key` | `MUVON_ENCRYPTION_KEY` | `""` | AES-256-GCM key for encrypted settings **and component env secrets**. Also seeds the HKDF derivation that signs central → agent commands (label `muvon-agent-command-v1`); if empty, the agent command channel is silently disabled and `POST /api/agents/:id/commands` returns 503. Must match `muvon-deployer`'s `MUVON_ENCRYPTION_KEY` and any agent's `AGENT_ENCRYPTION_KEY` — otherwise secret env vars cannot be decrypted at container start |
| `-config-reload-interval` | `MUVON_CONFIG_RELOAD_INTERVAL` | `5s` | Background config reload cadence |

### muvon-deployer

| Flag | Env var | Default | Notes |
|------|---------|---------|-------|
| `-dsn` | `MUVON_DSN` | `postgres://...` | PostgreSQL connection string |
| `-docker-host` | `MUVON_DOCKER_HOST` | `unix:///var/run/docker.sock` | Docker API host |
| `-poll` | `MUVON_DEPLOYER_POLL_INTERVAL` | `5s` | Deployment poll interval |
| `-grpc-socket` | `MUVON_DEPLOYER_SOCKET` | `/run/muvon/deployer.sock` | Unix socket for the deployer gRPC service (live container tail) |
| | `MUVON_ENCRYPTION_KEY` | `""` | Must match central MUVON's key to decrypt secret env vars |
| `-logship` | `MUVON_DEPLOYER_LOGSHIP_ENABLED` | `true` | Ship managed-container stdout/stderr to diaLOG |
| `-logship-dialog-socket` | `MUVON_DEPLOYER_LOGSHIP_DIALOG_SOCKET` | `/run/muvon/dialog.sock` | diaLOG socket for log shipping |
| `-logship-spool-dir` | `MUVON_DEPLOYER_LOGSHIP_SPOOL_DIR` | `/var/lib/muvon/logship` | Disk spool when diaLOG is unreachable |
| `-logship-spool-max-bytes` | `MUVON_DEPLOYER_LOGSHIP_SPOOL_MAX_BYTES` | `256 MiB` | Total spool disk budget |

### Agent

| Flag | Env var | Default | Notes |
|------|---------|---------|-------|
| `-central` | `AGENT_CENTRAL_URL` | (required) | Central server URL |
| `-api-key` | `AGENT_API_KEY` | (required) | Agent API key (plaintext is only revealed once on create) |
| `-http` | `AGENT_HTTP_ADDR` | `:80` | HTTP listen address |
| `-https` | `AGENT_HTTPS_ADDR` | `:443` | HTTPS listen address |
| `-log-addr` | `AGENT_LOG_ADDR` | `""` | Central diaLOG TCP address (host:port) |
| `-tls-cache` | `AGENT_TLS_CACHE` | `/var/lib/agent/tls` | Local ACME cert cache directory |
| `-config-cache` | `AGENT_CONFIG_CACHE` | `/var/lib/agent/config.json` | Disk cache of the last successful config payload; on cold start during a central outage the agent serves stale-but-working config and retries in the background |
| `-log-level` | `AGENT_LOG_LEVEL` | `info` | Log level |
| `-docker-socket` | `AGENT_DOCKER_SOCKET` | `unix:///var/run/docker.sock` | Local Docker daemon (shared by dockerwatch and the edge deployer; empty/unreadable = both features disabled) |
| `-dockerwatch` | `AGENT_DOCKERWATCH_ENABLED` | `true` | Ship local containers' stdout/stderr to central diaLOG |
| `-deployer` | `AGENT_DEPLOYER_ENABLED` | `false` | Run the embedded edge deployer so components with this agent's `agent_id` are spawned locally |
| `-deployer-poll-ms` | `AGENT_DEPLOYER_POLL_MS` | `5000` | Poll cadence for the edge deployer loop |
| `-deployer-encryption-key` | `AGENT_ENCRYPTION_KEY` | `""` | AES-256-GCM key — must match central's `MUVON_ENCRYPTION_KEY` to decrypt secret env vars |

### diaLOG

| Flag | Env var | Default | Notes |
|------|---------|---------|-------|
| `-dsn` | `DIALOG_DSN` | `postgres://...` | PostgreSQL connection string |
| `-socket` | `DIALOG_SOCKET` | `/tmp/dialog.sock` | gRPC Unix socket path |
| `-tcp` | `DIALOG_TCP_ADDR` | `""` | gRPC TCP listen address (for remote agents) |
| `-log-level` | `DIALOG_LOG_LEVEL` | `info` | Log level |

---

## Build & Release

`.github/workflows/release.yml` her `main` push'unda dört imajı (`muvon`, `dialog-siem`, `agent`, `muvon-deployer`) paralel olarak build edip `ghcr.io/SaidMuratOzdemir/MUVON/<service>:latest` adresine push eder. Tag push'larında (`v*`) otomatik GitHub Release oluşturulur.

---

## Repository Layout

```
cmd/
  muvon/              MUVON entry point (edge gateway, admin panel)
  dialog-siem/        diaLOG entry point (SIEM)
  muvon-deployer/     muvon-deployer entry point (managed Docker deploys)
  agent/              agent entry point (edge binary)

internal/
  admin/              HTTP handlers for admin API (auth, hosts, routes, settings, logs, alerts, agents, deploys, container logs)
  agentsvc/           Central-side agent config service (SSE watch + cert sync)
  alerting/           Slack + SMTP notifiers, fingerprint dedup
  config/             Config Source interface, DBSource (central) and AgentSource, hot reload Holder
  correlation/        Real-time correlation engine (sliding window rules, alerts)
  db/                 PostgreSQL pool, migrations, query helpers
  deployer/           Docker client, deploy lifecycle, gRPC server/client
  geoip/              MaxMind GeoLite2 reader
  health/             Backend health manager + circuit breaker
  identity/           JWT verify/decode + per-host claim extraction
  logger/             Pipeline + worker (COPY FROM batches), gRPC server/client, log entries
  middleware/         Recovery, rate limiter, security headers, gzip
  proxy/              Reverse proxy, body capture, X-Accel-Redirect, signed file serve
  router/             Host/path matching, admin-domain routing
  secret/             AES-256-GCM Box for encrypted settings
  tls/                ACME (autocert), DBCache, manager, manual cert upload

proto/
  logpb/              diaLOG service protobuf definitions
  deployerpb/         muvon-deployer service protobuf definitions

ui/
  src/                React SPA (admin panel)
```

---

## API Reference (selected)

### System

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/api/health` | Aggregated health (DB + Log) |
| `GET` | `/api/system/health` | Same as `/api/health`, JWT required |
| `POST` | `/api/system/reload` | Reload config from DB |
| `GET` | `/api/system/version` | Running binary's version + image digest |
| `GET` | `/api/system/version/latest` | GHCR `:latest` manifest digest (5 min cache) |
| `POST` | `/api/system/upgrade` | Trigger helper-container upgrade: `{target_tag, take_backup}`; 409 on concurrent run |
| `GET` | `/api/system/upgrade/stream` | SSE — live `pull` / `restart` / `post_check` progress |

### Agents (admin) / Commands

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/api/agents` | List agents (plaintext key not returned) |
| `POST` | `/api/agents` | Create agent; returns `{agent, api_key}` with plaintext key (only chance to read it) |
| `DELETE` | `/api/agents/:id` | Remove agent |
| `POST` | `/api/agents/:id/commands` | Enqueue a signed command for an agent (`cache_flush` / `set_log_level` / `cert.renew` / `agent.drain` / `agent.restart` / `agent.self_upgrade` / `agent.revoke` / `container.restart`) |
| `GET` | `/api/agents/:id/commands` | Recent commands + state (`pending` / `dispatched` / `succeeded` / `failed` / `expired`) |

### Agent API (edge → central, `X-Api-Key`)

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/api/v1/agent/config` | Pull config snapshot |
| `GET` | `/api/v1/agent/watch` | SSE — `config_updated` events on reload |
| `GET` | `/api/v1/agent/commands?wait=25s` | Long-poll for the next pending command (signed) |
| `POST` | `/api/v1/agent/commands/:id/result` | Terminal report (`succeeded` / `failed` + output/error) |
| `*` | `/api/v1/agent/deployer/*` | Embedded edge deployer (`claim` / `plan` / `event` / `instance` / `promote` / …) |

### Hosts / Routes

| Method | Path | Notes |
|--------|------|-------|
| `GET/POST` | `/api/hosts` | List / create hosts (per-host `tls_mode`) |
| `PUT/DELETE` | `/api/hosts/:id` | Update / delete host |
| `GET` | `/api/hosts/:id/dns-status` | Resolve domain, compare against expected IPs |
| `GET` | `/api/hosts/:id/tls-status` | Cert validity + days remaining + issuer |
| `GET/POST` | `/api/hosts/:id/routes` | List / create routes for host |
| `PUT/DELETE` | `/api/routes/:id` | Update / delete route |

### Apps / Deploy

| Method | Path | Notes |
|--------|------|-------|
| `GET/POST` | `/api/deploy/projects` | List apps / create app |
| `PUT/DELETE` | `/api/deploy/projects/:slug` | Update / delete app |
| `GET` | `/api/deploy/projects/:slug/secret` | Reveal webhook secret |
| `POST/GET/PUT/DELETE` | `/api/deploy/projects/:slug/components[/:component]` | Service CRUD; supports `env`, `env_secret_keys`, `agent_id`, `paused` |
| `POST` | `/api/deploy/projects/:slug/deploy` | Manual deploy (same payload as webhook) |
| `POST` | `/api/deploy/projects/:slug/rollback` | Redeploy the previous succeeded release |
| `POST` | `/api/deploy/webhook` | HMAC-SHA256 signed; bypasses JWT |
| `GET` | `/api/deploy/deployments` | Deployment history |
| `GET` | `/api/deploy/deployments/:id/events` | Lifecycle events |
| `POST` | `/api/deploy/deployments/:id/rerun` | Re-queue the same payload |

### Logs (proxied to diaLOG)

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/api/logs` | Search logs (filter by host/path/method/status/IP/text/user/time) |
| `GET` | `/api/logs/:id` | Log detail incl. headers + bodies |
| `GET` | `/api/logs/stats` | Aggregated metrics (status counts, top hosts, response times) |
| `GET` | `/api/logs/stream` | SSE live tail |
| `PUT` | `/api/logs/:id/note` | Add/update note |
| `POST` | `/api/logs/:id/star` | Toggle star |
| `GET` | `/api/logs/:id/jwt` | Reveal raw JWT (audit-logged) |

### Alerts

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/api/alerts` | List alerts (filter, paginate) |
| `GET` | `/api/alerts/stats` | Counts by rule/severity |
| `GET` | `/api/alerts/:id` | Alert detail |
| `POST` | `/api/alerts/:id/acknowledge` | Mark acknowledged |

### Settings

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/api/settings` | Read all (secrets masked) |
| `PUT` | `/api/settings/:key` | Update single setting (encrypted at rest if marked secret) |

---

## Logging Schema

```sql
CREATE TABLE http_logs (
  id                UUID DEFAULT gen_uuidv7() NOT NULL,
  timestamp         TIMESTAMPTZ NOT NULL DEFAULT now(),
  host              TEXT NOT NULL,
  client_ip         TEXT NOT NULL,
  method            TEXT NOT NULL,
  path              TEXT NOT NULL,
  query_string      TEXT,
  request_headers   JSONB,
  response_status   INTEGER NOT NULL,
  response_headers  JSONB,
  response_time_ms  INTEGER,
  request_size      INTEGER,
  response_size     INTEGER,
  user_agent        TEXT,
  error             TEXT,
  is_starred        BOOLEAN NOT NULL DEFAULT false,
  user_identity     JSONB,
  country           TEXT,
  city              TEXT,
  raw_jwt           TEXT,
  PRIMARY KEY (id, timestamp)
);
SELECT create_hypertable('http_logs', by_range('timestamp', INTERVAL '1 day'));
```

---

## Correlation Rules

The diaLOG correlation engine subscribes to the live log pipeline and evaluates sliding-window rules in real time. Each rule emits an `Alert` with a stable fingerprint; the alert manager applies per-fingerprint cooldown across all nodes.

| Rule | Trigger | Window | Severity |
|------|---------|--------|----------|
| `path_scan` | Same IP, 10+ distinct 404 paths | 2 min | warning |
| `auth_brute_force` | Same IP, 5+ failed logins (401/403, or 400 on auth path) | 2 min | critical |
| `error_spike` | Same host, 10+ 5xx responses | 1 min | critical |
| `traffic_anomaly` | Host RPS exceeds baseline by configured ratio | 10 min baseline / 1 min current | warning |
| `sensitive_access` | Configured glob path hit threshold from same IP | 5 min | warning |
| `data_export_burst` | Per-actor (JWT user or IP) export pattern threshold | 5 min | warning |

All thresholds and windows are admin-tunable via `/api/settings`.

---

## Language note

The README mixes English and Turkish (Turkish for ops sections). User-facing error strings and admin UI strings may be in either language — check neighbors before adding new text.
