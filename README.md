# MUVON

An edge gateway and security platform composed of four independent Go services: a central reverse proxy with identity and geolocation enrichment, a web application firewall, a SIEM engine with real-time correlation and alerting, and a lightweight edge agent that deploys on client servers.

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
                       |                |
          Unix Socket  |                |  Unix Socket
       /run/muvon/     |                |  /run/muvon/
        muwaf.sock     |                |  dialog.sock
                       v                v
               +-------+----+   +------+------+
               |   muWAF    |   |   diaLOG    |
               |  WAF Engine|   |  SIEM Engine|
               +-------+----+   +------+------+
                       |                |
                       v                v
                   +---+----------------+---+
                   |       PostgreSQL 16     |
                   |    (Docker, internal)   |
                   +------------------------+
```

### Hub-and-Spoke Mode (distributed)

```
  Client Servers (agents)          Central Server
  ┌─────────────────────┐        ┌──────────────────────────────┐
  │  agent              │        │  MUVON  :443                 │
  │  :80/:443 (proxy)   │──SSE──▶│  (config push / hot reload)  │
  │  optional muWAF     │        │                              │
  └─────────────────────┘        │  diaLOG  :9001 (TCP gRPC)   │
  ┌─────────────────────┐        │  (log ingestion from agents) │
  │  agent              │──logs─▶│                              │
  │  :80/:443 (proxy)   │        │  muWAF  /run/muvon/muwaf.sock│
  │  optional muWAF     │        │                              │
  └─────────────────────┘        │  PostgreSQL 16  (internal)   │
                                 └──────────────────────────────┘
```

Agents are stateless: no database, no admin panel, no heavy processing. They pull configuration from central on startup, receive live config updates via SSE, forward logs to diaLOG over TCP gRPC, and optionally talk to a co-located muWAF over a Unix socket. TLS certificates are stored locally via ACME DirCache.

---

## How It Works

MUVON sits at the edge and accepts all inbound HTTP/HTTPS traffic. For each request, it does two things before proxying to the upstream: it sends request metadata to **muWAF** for threat inspection, and it sends the full request/response pair to **diaLOG** for logging. Both calls happen over local Unix sockets, so inter-service latency is measured in microseconds.

Each service is a standalone binary with its own database schema. They share a single PostgreSQL instance but never read each other's tables. If muWAF or diaLOG goes down, MUVON continues routing traffic --- WAF checks are skipped and logs are dropped, but the proxy never blocks.

| Service | What it does |
|---------|-------------|
| **MUVON** | Central server. Terminates TLS (auto Let's Encrypt or manual PEM), resolves virtual hosts, matches routes by path prefix, and proxies to upstreams. Serves the admin panel on `:443` for the configured `MUVON_ADMIN_DOMAIN` (falls back to `:9443` when no domain is set, for local dev). For `POST`/`PUT`/`PATCH` requests, captures the request body and forwards it to muWAF; for `GET`/`HEAD`/`DELETE`, only headers and path are inspected. Enriches every log entry with **JWT identity** (verify + decode fallback) and **GeoIP** (country/city from local MaxMind DB). Provides config API and SSE watch endpoint for agents. |
| **agent** | Lightweight edge binary deployed on client servers. Pulls config from central MUVON on startup, watches for changes via SSE (hot reload). Proxies traffic using the central-managed host/route config. Sends logs to central diaLOG over TCP gRPC. Optionally connects to a co-located muWAF. No database, no admin panel — zero local state except ACME cert cache. |
| **muWAF** | Receives request metadata from MUVON (or agent) via gRPC, runs it through a regex/string-match rule engine covering 14 attack categories (SQLi, XSS, RCE, SSRF, etc.), maintains a cumulative IP threat score with decay, and returns an allow/block decision. Graduated response: `log` -> `rate_limit` -> `block` -> `temp_ban` -> `ban`. |
| **diaLOG** | Receives structured log entries from MUVON or remote agents via gRPC (Unix socket for local, TCP for agents), buffers them in a Go channel, and flushes in batches using PostgreSQL `COPY FROM` for throughput. Stores logs in TimescaleDB Hypertables with UUIDv7 primary keys. Provides BM25 full-text search (via pg_search/Tantivy) across path, host, user-agent, and IP fields. Exposes SSE live tail for real-time monitoring. Runs a **correlation engine** that detects attack patterns (brute force, scanning, error spikes) in real time and triggers **alerts** via Slack and email. |

---

## Quick Start

### Prerequisites

- **Go 1.24+**
- **Node.js 22+** (admin panel build için)
- **Docker** (postgres container için) veya harici PostgreSQL 16+
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
# Bağımlılıklar
make deps && make ui-install

# Tüm servisler (admin UI dahil)
make build
# build/muvon, build/muwaf, build/dialog-siem, build/agent

# Sadece muvon + agent (WAF/SIEM olmadan)
make build-minimal

# Linux cross-compile
make build-linux
# build/*-linux-amd64
```

### 3. Run (local dev)

```bash
# 1. muWAF (WAF engine) — opsiyonel
./build/muwaf \
  -dsn "postgres://user:pass@localhost/muvon?sslmode=disable" \
  -socket /tmp/muwaf.sock

# 2. diaLOG (SIEM engine) — opsiyonel
./build/dialog-siem \
  -dsn "postgres://user:pass@localhost/muvon?sslmode=disable" \
  -socket /tmp/dialog.sock \
  -tcp-addr :9001

# 3. MUVON (edge gateway + admin panel)
./build/muvon \
  -dsn "postgres://user:pass@localhost/muvon?sslmode=disable" \
  -jwt-secret "$(openssl rand -hex 32)" \
  -waf-socket /tmp/muwaf.sock \
  -log-socket /tmp/dialog.sock
# Admin panel: https://localhost:9443 (local dev — no MUVON_ADMIN_DOMAIN set)
```

**Agent mode** (client server — no database required):

```bash
./build/agent \
  -central "https://central.example.com" \
  -api-key  "<key from admin panel>" \
  -log-addr "central.example.com:9001" \
  -tls-cache /var/lib/agent/tls
```

### 4. First Run

1. Navigate to `https://localhost:9443` (local) or `https://<MUVON_ADMIN_DOMAIN>` (production)
2. Create the first admin user (setup wizard appears when no users exist)
3. Add hosts and configure routes via **Hosts** and **Routes**
4. Enable WAF inspection per route as needed
5. TLS certificates are issued automatically via Let's Encrypt

---

## Architecture Principles

### 1. gRPC over Unix Sockets

All inter-service communication uses gRPC on local Unix sockets — no TCP, no network exposure.

```
MUVON ---[gRPC]--> /tmp/waf.sock --> muWAF
MUVON ---[gRPC]--> /tmp/log.sock --> diaLOG SIEM
```

### 2. Fail-Open

If muWAF or diaLOG goes down, MUVON keeps routing. WAF checks are skipped, logs are dropped, admin WAF/Log pages show a 503 banner — everything else keeps working.

### 3. Selective Payload Transfer

Body is only forwarded to muWAF for `POST`/`PUT`/`PATCH`. `GET`/`DELETE`/`HEAD` are inspected by headers, path, and query string only.

### 4. Database Schema Isolation

Three isolated schemas on a single PostgreSQL 18 instance. Each service touches only its own schema:

| Schema | Owner | Contains |
|--------|-------|----------|
| `muvon` | MUVON | Hosts, routes, TLS certificates, ACME cache, settings, admin users, audit log |
| `muwaf` | muWAF | WAF rules, IP score tracking, detection events (Hypertable), exclusions, VT cache |
| `dialog` | diaLOG | HTTP access logs (Hypertable, UUIDv7 PK) with identity/geo enrichment, request/response bodies (Hypertable), BM25 search index, log notes/stars, correlation alerts (Hypertable) |

TimescaleDB handles chunking, compression (7-day policy), and retention (30-day policy) for all time-series tables.

---

## Features

### MUVON (Edge Gateway)

| Feature | Details |
|---------|---------|
| Virtual Hosting | Multi-domain, path-prefix routing with priority ordering |
| Route Types | `proxy` (reverse proxy), `static` (file server), `redirect` |
| X-Accel-Redirect | Per-route `accel_root` — backend handles auth, sets `X-Accel-Redirect` header, muvon serves the local file directly. Backend never reads file bytes. |
| Signed File Serve | Per-route `accel_signed_secret` — backend issues a pre-signed URL (`?token=<hmac>&expires=<unix>`), muvon validates HMAC-SHA256 and serves the file without calling the backend at all. Token format: `HMAC-SHA256(secret, path+":"+expires)`. |
| TLS | Let's Encrypt autocert (HTTP-01), manual PEM upload, PostgreSQL-backed cert store. Agents use local DirCache. |
| WebSocket & SSE | Full support --- response capture disabled for streaming connections |
| Per-route WAF | `waf_enabled` toggle --- per route WAF inspection control |
| Per-route Logging | `log_enabled` toggle --- disable SIEM for noisy routes (health checks, static assets) |
| JWT Identity | Extracts user identity from `Authorization: Bearer` tokens. HS256 verify with decode fallback --- configurable claim extraction (`sub`, `email`, `role`, etc.) |
| GeoIP Enrichment | Resolves client IPs to country/city using a local MaxMind GeoLite2-City mmdb file. Fully offline --- no external API calls at runtime |
| Hot Reload | Configuration changes apply atomically, zero-downtime. JWT secret, GeoIP DB, and alerting config all hot-reloadable. Agents receive config updates via SSE push. |
| Agent Management | Admin panel manages per-agent API keys. Agents authenticate to diaLOG TCP and the config/watch endpoints using these keys. |
| Admin Panel | React + shadcn/ui SPA, JWT auth, first-run setup wizard. Served on `:443` via `MUVON_ADMIN_DOMAIN`; falls back to `:9443` for local dev. |

### muWAF (Web Application Firewall)

| Feature | Details |
|---------|---------|
| Pattern Engine | Regex and string-match rules across 14 attack categories |
| Attack Categories | XSS, SQLi, RCE, LFI, RFI, SSRF, NoSQLi, SSTI, Log4Shell, Prototype Pollution, Session Fixation, Path Traversal, Command Injection, Custom |
| IP Scoring | Cumulative threat score per IP with configurable decay |
| Graduated Response | `log` -> `rate_limit` -> `block` -> `temp_ban` -> `ban` |
| IP Management | Manual ban/unban/whitelist via admin API |
| Rule Import | Bulk JSON import for rule sets |
| Exclusions | Per-route, per-parameter rule exclusions |

### diaLOG (SIEM Engine)

| Feature | Details |
|---------|---------|
| Structured Logging | Full request/response capture: headers, bodies, timing, WAF decisions, user identity, geolocation |
| Async Pipeline | Buffered channel -> worker pool -> batched PostgreSQL `COPY` |
| UUIDv7 Primary Keys | Time-ordered, globally unique IDs --- `ORDER BY id` = chronological order |
| BM25 Full-text Search | pg_search (Tantivy) powered search across path, host, user-agent, IP |
| TimescaleDB Hypertables | Auto-partitioned by time, columnar compression (7d), retention policy (30d) |
| Correlation Engine | Real-time pattern detection via in-memory sliding window counters. Subscribes to the log pipeline for zero-copy event analysis |
| Alerting System | Slack webhook and SMTP email notifications with fingerprint-based cooldown. Async dispatch --- never blocks the log pipeline |
| Live Tail | SSE streaming via gRPC-to-SSE bridge |
| Notes & Stars | Annotate and bookmark individual log entries |

---

## Central Admin Panel

The admin panel runs on MUVON `:443` (via `MUVON_ADMIN_DOMAIN`) and acts as the **single management interface** for all three services.

```
Browser https://<MUVON_ADMIN_DOMAIN>
    |
    +-- /api/hosts/*         --> MUVON (local)
    +-- /api/routes/*        --> MUVON (local)
    +-- /api/settings/*      --> MUVON (local)
    +-- /api/tls/*           --> MUVON (local)
    +-- /api/auth/*          --> MUVON (local)
    +-- /api/waf/*           --> muWAF (gRPC proxy)
    +-- /api/logs/*          --> diaLOG (gRPC proxy)
    +-- /api/health          --> Aggregated health (DB + WAF + Log)
```

If muWAF is down, WAF management pages show a service-offline banner. If diaLOG is down, log pages show a service-offline banner. Everything else keeps working.

---

## Configuration

### MUVON

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `-dsn` | `MUVON_DSN` | `postgres://...` | PostgreSQL connection string |
| `-http` | `MUVON_HTTP_ADDR` | `:80` | HTTP listener |
| `-https` | `MUVON_HTTPS_ADDR` | `:443` | HTTPS listener |
| `-admin-domain` | `MUVON_ADMIN_DOMAIN` | `""` | Serve admin panel on this domain via `:443` (e.g. `muvon.example.com`). When set, `:9443` is not started. |
| `-admin` | `MUVON_ADMIN_ADDR` | `:9443` | Admin panel listener — used only when `MUVON_ADMIN_DOMAIN` is not set |
| `-jwt-secret` | `MUVON_JWT_SECRET` | `change-me` | JWT signing key |
| `-waf-socket` | `MUVON_WAF_SOCKET` | `/tmp/muwaf.sock` | muWAF Unix socket path |
| `-log-socket` | `MUVON_LOG_SOCKET` | `/tmp/dialog.sock` | diaLOG Unix socket path |
| `-encryption-key` | `MUVON_ENCRYPTION_KEY` | `""` | AES-256-GCM key for encrypting secrets in DB |
| `-log-level` | `MUVON_LOG_LEVEL` | `info` | Log level |

### agent

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `-central` | `AGENT_CENTRAL_URL` | `""` | Central MUVON URL (required) |
| `-api-key` | `AGENT_API_KEY` | `""` | Agent API key from admin panel (required) |
| `-http` | `AGENT_HTTP_ADDR` | `:80` | HTTP listener |
| `-https` | `AGENT_HTTPS_ADDR` | `:443` | HTTPS listener |
| `-log-addr` | `AGENT_LOG_ADDR` | `""` | Central diaLOG TCP address (`host:port`) |
| `-waf-socket` | `AGENT_WAF_SOCKET` | `/tmp/muwaf.sock` | Local muWAF Unix socket (optional) |
| `-tls-cache` | `AGENT_TLS_CACHE` | `/var/lib/agent/tls` | Directory for ACME cert cache |
| `-log-level` | `AGENT_LOG_LEVEL` | `info` | Log level |

### muWAF

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `-dsn` | `MUWAF_DSN` | `postgres://...` | PostgreSQL connection string |
| `-socket` | `MUWAF_SOCKET` | `/tmp/muwaf.sock` | gRPC Unix socket path |
| `-log-level` | `MUWAF_LOG_LEVEL` | `info` | Log level |

### diaLOG

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `-dsn` | `DIALOG_DSN` | `postgres://...` | PostgreSQL connection string |
| `-socket` | `DIALOG_SOCKET` | `/tmp/dialog.sock` | gRPC Unix socket path |
| `-tcp-addr` | `DIALOG_TCP_ADDR` | `""` | TCP listener for agent log ingestion (e.g. `:9001`) |
| `-buffer` | `DIALOG_BUFFER` | `10000` | Log pipeline buffer size |
| `-workers` | `DIALOG_WORKERS` | `4` | Log pipeline worker count |
| `-batch` | `DIALOG_BATCH` | `1000` | Batch flush size |
| `-flush-ms` | `DIALOG_FLUSH_MS` | `2000` | Flush interval (ms) |
| `-log-level` | `DIALOG_LOG_LEVEL` | `info` | Log level |

### Runtime Settings (Admin Panel)

All runtime settings are stored in the `settings` table and managed via the admin panel (`GET/PUT /api/settings`). Changes take effect after the next config reload (triggered automatically on save).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `jwt_identity_enabled` | bool | `false` | Enable JWT identity extraction from Authorization header |
| `jwt_identity_mode` | string | `verify` | `verify` = HS256 verify first, `decode` = extract without verification |
| `jwt_claims` | string | `sub,email,name,role` | Comma-separated claim keys to extract |
| `jwt_secret` | string | `""` | HS256 HMAC secret (write-only in UI) |
| `geoip_enabled` | bool | `false` | Enable GeoIP enrichment |
| `geoip_db_path` | string | `""` | Absolute path to GeoLite2-City.mmdb file |
| `alerting_enabled` | bool | `false` | Enable alert notifications |
| `alerting_slack_webhook` | string | `""` | Slack incoming webhook URL |
| `alerting_smtp_host` | string | `""` | SMTP server hostname |
| `alerting_smtp_port` | int | `587` | SMTP port (587 = STARTTLS, 465 = implicit TLS) |
| `alerting_smtp_username` | string | `""` | SMTP authentication username |
| `alerting_smtp_password` | string | `""` | SMTP password (write-only in UI) |
| `alerting_smtp_from` | string | `""` | Sender email address |
| `alerting_smtp_to` | string | `""` | Comma-separated recipient addresses |
| `alerting_cooldown_seconds` | int | `300` | Minimum seconds between notifications for the same fingerprint |

---

## Production Deployment

### Docker Compose (recommended)

CI/CD (GitHub Actions) builds Docker images on every push to `main` and publishes them to `ghcr.io`.

### Ana Makine Kurulumu

**Ön koşullar:**
- Ubuntu 22.04+ veya Debian 12+ VPS
- 80 ve 443 portları boş (nginx, apache vb. çalışmıyor olmalı)
- Admin domain için DNS A kaydı sunucu IP'sine yönlendirilmiş olmalı

```bash
curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install.sh | bash
```

Script tek çalıştırmada şunları sorar ve tamamlar:

```
  Admin domain: muvon.example.com
  Admin kullanıcı adı [admin]:
  Admin şifresi (min 8 karakter):
  MaxMind Lisans Anahtarı:          ← GeoIP için, boş bırakılabilir
```

Ardından: Docker kurulumu (yoksa) → dosya indirme → secrets üretme → PostgreSQL build → servis başlatma → admin hesabı oluşturma.

**Firewall (ufw kullanıyorsanız):**

```bash
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow from <agent-ip> to any port 9001  # agent log ingestion — herkese açmayın
```

### Agent Makine Kurulumu

Ana makinenin admin panelinden API key oluşturun (Agents → New Key), ardından agent makinesinde:

```bash
curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install-agent.sh | bash
```

```
  Merkezi MUVON URL'si: https://muvon.example.com:9443
  Agent API Key:
  diaLOG log adresi [muvon.example.com:9001]:
```

Script bağlantı testi yapar, docker-compose.agent.yml'yi indirir ve agent'ı başlatır.

**Güncelleme:**

```bash
# Ana makine
cd /opt/muvon && docker compose pull && docker compose up -d

# Agent
cd /opt/muvon-agent && docker compose -f docker-compose.agent.yml pull && \
  docker compose -f docker-compose.agent.yml up -d
```

**Host'taki (dockerize edilmemiş) uygulamalar için backend URL:**

```
http://host.docker.internal:<port>
```

**Exposed ports:**

| Port | Servis | Kime açık |
|------|--------|-----------|
| `80` | muvon | Herkes (ACME + redirect) |
| `443` | muvon | Herkes (proxy + admin domain) |
| `9001` | dialog-siem | Sadece agent makineleri — firewall ile kısıtla |

PostgreSQL Docker iç ağında, dışarıya kapalı.

### CI/CD (GitHub Actions)

`.github/workflows/release.yml` her `main` push'unda dört imajı (`muvon`, `dialog-siem`, `muwaf`, `agent`) paralel olarak build edip `ghcr.io/SaidMuratOzdemir/MUVON/<service>:latest` adresine push eder. Tag push'larında (`v*`) otomatik GitHub Release oluşturulur.

```bash
# İlk kez image'ları çekmek için GitHub Container Registry'ye giriş:
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin
```

### GeoIP Database Setup

GeoIP enrichment requires a local MaxMind GeoLite2-City database. MUVON never contacts MaxMind at runtime.

`install.sh` kurulum sırasında MaxMind lisans anahtarını interaktif olarak sorar ve veritabanını otomatik olarak indirir. Lisans anahtarı [MaxMind ücretsiz kayıt](https://www.maxmind.com/en/geolite2/signup) ile edinilir.

Kurulum sonrası admin panelinden etkinleştirin:

```
Ayarlar → geoip_enabled = true
Ayarlar → geoip_db_path = /var/lib/geoip/GeoLite2-City.mmdb
```

**Veritabanını sıfır downtime ile güncellemek için:**

```bash
# Yeni mmdb'yi docker volume'a kopyala
docker run --rm \
  -v muvon_geoip:/data \
  -v /tmp/GeoLite2-City.mmdb:/src:ro \
  alpine sh -c "cp /src /data/GeoLite2-City.mmdb"

# Config reload tetikle (tüm bağlı agent'lara da gönderilir)
curl -X POST http://127.0.0.1:9443/api/system/reload \
  -H "Authorization: Bearer <admin-jwt>"
```

---

## Project Structure

```
cmd/
  muvon/              MUVON entry point (central gateway + admin)
  agent/              Lightweight edge agent (no DB, pulls config from central)
  muwaf/              muWAF entry point (WAF engine)
  dialog-siem/        diaLOG entry point (SIEM engine, Unix + TCP gRPC)
internal/
  admin/              Admin REST API handlers + gRPC proxy
  agentsvc/           Agent config API: SSE broadcaster, HTTP handlers for /api/v1/agent/*
  alerting/           Alert dispatch: Slack webhook, SMTP email, fingerprint cooldown
  config/             Atomic config holder; Source interface (DBSource / AgentSource), hot-reload
  correlation/        Real-time correlation engine: sliding window rules, alert generation
  db/                 PostgreSQL queries, migrations, agents table
  geoip/              MaxMind mmdb reader for IP-to-country/city resolution
  health/             Backend health manager (circuit breaker)
  identity/           JWT identity extraction (HS256 verify + decode fallback)
  logger/             Async log pipeline + gRPC server/client (Unix + TCP)
  middleware/         GZip, security headers, rate limiting, panic recovery
  proxy/              Reverse proxy, body capture, WAF pre-check, X-Accel-Redirect, signed file serve
  router/             Host/path matching, route resolution
  secret/             AES-256-GCM box for encrypting settings secrets in DB
  tls/                TLS manager, autocert, ACME cache (DB-backed + DirCache for agents)
  waf/                WAF engine, pattern matching, IP scoring, gRPC server/client
proto/
  wafpb/              WAF service protobuf definitions
  logpb/              Log service protobuf definitions
ui/                   React admin panel (Vite + TypeScript + shadcn/ui)
frontend/dist/        Embedded SPA (go:embed)
```

---

## Admin API Reference

All endpoints require `Authorization: Bearer <jwt>` except `/api/auth/login`, `/api/auth/setup`, and `/api/health`.

### Core (MUVON)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth/login` | Authenticate, receive JWT |
| `POST` | `/api/auth/setup` | Create first admin (setup mode) |
| `GET` | `/api/auth/me` | Current user info |
| `GET/POST/PUT/DELETE` | `/api/hosts/*` | Host CRUD |
| `GET/POST/PUT/DELETE` | `/api/hosts/:id/routes/*` | Route CRUD (includes `accel_root`, `accel_signed_secret` fields) |
| `GET/PUT` | `/api/settings/*` | Settings management (secret fields are write-only --- masked in GET responses) |
| `GET/POST/DELETE` | `/api/tls/certificates/*` | TLS certificate management |
| `GET` | `/api/agents` | List registered agents |
| `POST` | `/api/agents` | Create agent (generates API key) |
| `DELETE` | `/api/agents/:id` | Delete agent |
| `GET` | `/api/audit` | Audit log |
| `GET` | `/api/health` | Aggregated health (DB + WAF + Log) |
| `GET` | `/api/system/stats` | Runtime metrics |
| `POST` | `/api/system/reload` | Trigger config reload (also pushes update to all connected agents) |

### Agent API (authenticated with agent API key, not admin JWT)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/agent/config` | Fetch full config payload (hosts + routes + settings) |
| `GET` | `/api/v1/agent/watch` | SSE stream — sends `event: config_updated` on config change, keep-alive ping every 30s |

### WAF (proxied to muWAF)

| Method | Path | Description |
|--------|------|-------------|
| `GET/POST` | `/api/waf/rules` | List / create WAF rules |
| `PUT/DELETE` | `/api/waf/rules/:id` | Update / delete rule |
| `POST` | `/api/waf/rules/import` | Bulk import rules (JSON) |
| `GET` | `/api/waf/ips` | List tracked IPs |
| `POST` | `/api/waf/ips/ban` | Ban IP |
| `POST` | `/api/waf/ips/unban` | Unban IP |
| `POST` | `/api/waf/ips/whitelist` | Whitelist IP |
| `DELETE` | `/api/waf/ips/whitelist/:ip` | Remove from whitelist |
| `GET/POST/DELETE` | `/api/waf/exclusions/*` | Rule exclusion management |
| `GET` | `/api/waf/events` | Search WAF detection events |
| `GET` | `/api/waf/stats` | WAF statistics |

### Logs (proxied to diaLOG)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/logs` | Search logs (paginated, filterable) |
| `GET` | `/api/logs/:id` | Log detail with bodies |
| `GET` | `/api/logs/stats` | Aggregated metrics |
| `GET` | `/api/logs/stream` | SSE live tail |
| `POST` | `/api/logs/:id/star` | Toggle star |
| `PUT` | `/api/logs/:id/note` | Upsert note |

---

## Data Engine: PostgreSQL 18 + TimescaleDB + pg_search

diaLOG stores and searches logs entirely within PostgreSQL, using three extensions:

```
                     diaLOG Data Engine
  +-----------------------------------------------------+
  |  PostgreSQL 18                                       |
  |  +-- TimescaleDB Extension                           |
  |  |   +-- Hypertables (auto-partitioned by time)      |
  |  |   +-- Continuous Aggregates (materialized)        |
  |  |   +-- Compression (columnar, 10-20x ratio)        |
  |  +-- pg_search Extension (Tantivy-based FTS)         |
  |  |   +-- BM25 ranking                                |
  |  |   +-- Real-time index refresh                     |
  |  +-- UUIDv7 Primary Keys                             |
  |      +-- Time-ordered (K-Sortable)                   |
  |      +-- B-tree friendly (sequential inserts)        |
  |      +-- Globally unique (cross-service join)        |
  +-----------------------------------------------------+
```

**TimescaleDB Hypertables**

| Capability | Native PG Partitions | TimescaleDB Hypertable |
|-----------|---------------------|----------------------|
| Partition creation | Manual / cron | Automatic |
| Time-range queries | Full scan across partitions | Chunk exclusion (orders of magnitude faster) |
| Compression | None (pg_compress external) | Native columnar, 10-20x ratio |
| Continuous Aggregates | Materialized views (manual refresh) | Incremental, real-time, auto-refresh |
| Retention | Manual `DROP PARTITION` | `drop_chunks()` policy |
| Downsampling | Custom ETL | Built-in with `time_bucket()` |

**pg_search ([ParadeDB](https://github.com/paradedb/paradedb/tree/dev/pg_search)) — Tantivy-based BM25 full-text search as a PostgreSQL extension**

| Concern | Elasticsearch | pg_search |
|---------|--------------|-----------|
| Deployment | Separate JVM cluster (3+ nodes for HA) | PostgreSQL extension (zero extra infra) |
| Memory | 32GB+ JVM heap recommended | Shared with PostgreSQL buffer pool |
| Consistency | Eventually consistent (refresh interval) | Transactionally consistent |
| Joins | Impossible (denormalize everything) | Standard SQL JOINs with WAF events, IP scores |
| Operational cost | Dedicated team for index management, shard rebalancing, version upgrades | `CREATE EXTENSION pg_search` |

**UUIDv7 Primary Keys**

Log entries and WAF events use UUIDv7 PKs. The millisecond timestamp in the high bits makes them K-sortable (`ORDER BY id` = chronological order, no separate timestamp index), B-tree friendly (sequential inserts, no page splits), and usable as cross-service correlation IDs.

```sql
-- Example: diaLOG Hypertable with UUIDv7 PK and enrichment columns
CREATE TABLE dialog.http_logs (
    id              UUID        DEFAULT gen_uuidv7() NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT now(),
    host            TEXT        NOT NULL,
    client_ip       TEXT        NOT NULL,
    method          TEXT        NOT NULL,
    path            TEXT        NOT NULL,
    response_status INTEGER     NOT NULL,
    -- ... WAF, header, body fields ...
    user_identity   JSONB,          -- JWT claims + verified flag
    country         TEXT,           -- ISO country code (GeoIP)
    city            TEXT,           -- City name (GeoIP)
    PRIMARY KEY (id, timestamp)
);

SELECT create_hypertable('http_logs', by_range('timestamp', INTERVAL '1 day'));

-- Correlation alerts
CREATE TABLE dialog.alerts (
    id          UUID        DEFAULT gen_uuidv7() NOT NULL,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT now(),
    rule        TEXT        NOT NULL,
    severity    TEXT        NOT NULL,
    title       TEXT        NOT NULL,
    detail      JSONB,
    source_ip   TEXT,
    host        TEXT,
    fingerprint TEXT        NOT NULL,
    notified    BOOLEAN     NOT NULL DEFAULT false,
    PRIMARY KEY (id, timestamp)
);

SELECT create_hypertable('alerts', by_range('timestamp', INTERVAL '1 day'));
```

---

## SIEM Capabilities

### Log Enrichment Pipeline

Every HTTP request proxied by MUVON is enriched with contextual metadata before being sent to diaLOG:

```
  Incoming Request
        |
        v
  +-- Extract JWT Identity ----+
  |   Authorization: Bearer <> |
  |   1. HS256 verify          |
  |   2. Decode fallback       |
  |   -> claims, verified flag |
  +----------------------------+
        |
        v
  +-- GeoIP Lookup ------------+
  |   Client IP -> mmdb        |
  |   -> country (ISO code)    |
  |   -> city (English name)   |
  |   Skip: private/loopback   |
  +----------------------------+
        |
        v
  Log Entry (gRPC) --> diaLOG
```

**JWT Identity Extraction** operates in verify-first mode: it attempts HS256 signature validation using the configured secret, and falls back to unverified decode if verification fails. Both outcomes are recorded in the log:

| Field | Verify Success | Verify Failure |
|-------|---------------|----------------|
| `verified` | `true` | `false` |
| `source` | `jwt_verify` | `jwt_decode` |
| `claims` | Extracted claim values | Extracted claim values |

> Unverified identity (`verified: false`) is for observability only --- it must never be used for authorization decisions. The claims may be forged.

The JWT secret and claim list are managed via the admin panel and take effect on the next config reload. The secret field is **write-only** --- the admin API never returns the actual value, only a masked placeholder.

**GeoIP Enrichment** uses a local MaxMind GeoLite2-City mmdb file. The database is loaded via memory-mapped I/O (mmap), so the OS manages page caching --- no additional application-level cache is needed. Private and loopback IPs are detected and skipped without hitting the database. The mmdb file supports atomic reload for zero-downtime updates.

### Correlation Engine

diaLOG's correlation engine subscribes to the log pipeline and evaluates every entry against a set of in-memory sliding window rules. When a threshold is exceeded, an alert is produced and dispatched to the alerting system.

```
  Log Pipeline
       |
       +-- [Subscribe] --> Correlation Engine
                              |
                              +-- Rule: path_scan
                              +-- Rule: auth_brute_force
                              +-- Rule: error_spike
                              +-- Rule: waf_repeat_offender
                              |
                              v
                          Alert Sink
                              |
                              +-- Persist to alerts table
                              +-- Dispatch notifications
```

**Built-in Correlation Rules:**

| Rule | Condition | Window | Severity |
|------|-----------|--------|----------|
| `path_scan` | Same IP, 10+ distinct 404 paths | 2 min | warning |
| `auth_brute_force` | Same IP, 5+ responses with 401/403 | 2 min | critical |
| `error_spike` | Same host, 10+ responses with 5xx | 1 min | critical |
| `waf_repeat_offender` | Same IP, 3+ WAF blocks | 5 min | warning |

**Memory footprint:** Each active IP/host window consumes ~100 bytes. 10,000 concurrent IPs = ~1 MB. Stale windows are garbage-collected every 60 seconds.

### Alerting & Notifications

Alerts are persisted to a TimescaleDB hypertable (`alerts`) and optionally dispatched to external channels:

| Channel | Implementation | Dependency |
|---------|---------------|------------|
| **Slack** | HTTP POST to incoming webhook URL | stdlib `net/http` |
| **Email** | SMTP with STARTTLS (port 587) or implicit TLS (port 465) | stdlib `net/smtp` |

**Fingerprint-based cooldown** prevents alert spam. Each alert carries a fingerprint (e.g., `auth_brute_force:192.168.1.100`). If the same fingerprint was notified within the cooldown window (default: 5 minutes), the alert is still persisted to the database but notifications are suppressed. Independent problems (different fingerprints) are never affected by each other's cooldown.

All alerting configuration (enable/disable, Slack webhook, SMTP credentials, cooldown duration) is managed via the admin panel and hot-reloadable.

> **Multi-node note:** The current cooldown is in-memory (single process). For future multi-node deployments, cooldown deduplication can be coordinated via the `alerts` table using `INSERT ... ON CONFLICT` on the fingerprint column with a time window check.

---

## Roadmap

### muWAF AI Engine --- Real-Time Anomaly Detection

The current muWAF engine relies on deterministic pattern matching: regex rules, string signatures, and cumulative IP scoring. This catches known attack patterns effectively but is fundamentally blind to **zero-day exploits, novel evasion techniques, and polymorphic payloads** that don't match any existing signature.

The next evolution of muWAF will introduce a **hybrid detection pipeline** that combines rule-based analysis with machine learning inference:

```
  Incoming Request
        |
        v
  +---------------------------------------------+
  |          muWAF Hybrid Pipeline               |
  |                                              |
  |  Stage 1: Rule Engine (current)              |
  |  +-- Regex pattern matching                  |
  |  +-- String signature detection              |
  |  +-- Output: rule_score (0-100)              |
  |                                              |
  |  Stage 2: AI Anomaly Engine (roadmap)        |
  |  +-- Feature extraction (Go)                 |
  |  |   +-- Request entropy                     |
  |  |   +-- Token frequency analysis            |
  |  |   +-- Structural anomaly signals          |
  |  |   +-- Behavioral deviation metrics        |
  |  |   +-- Temporal pattern features           |
  |  +-- ONNX Runtime inference (<1ms)           |
  |  |   +-- Pre-trained anomaly model           |
  |  +-- Output: anomaly_score (0.0-1.0)         |
  |                                              |
  |  Stage 3: Decision Fusion                    |
  |  +-- combined = w1*rule + w2*anomaly         |
  |  +-- Threshold check                         |
  |  +-- Action: allow / log / block / ban       |
  +---------------------------------------------+
        |
        v
  Decision: ALLOW / AI_BLOCK / RULE_BLOCK
```

**Why ONNX Runtime in Go?**

| Alternative | Latency | Deployment | Go Integration |
|------------|---------|------------|---------------|
| External Python microservice (Flask/FastAPI) | 5-50ms (network + GIL) | Separate container, versioning headache | gRPC call overhead |
| TensorFlow Serving | 2-10ms (gRPC) | Heavy Docker image, GPU assumed | External dependency |
| **ONNX Runtime (C API via CGo)** | **<1ms (in-process)** | **Single binary, CPU-optimized** | **Native, zero network hop** |

ONNX Runtime runs the model **in the same process** as the WAF engine. No network serialization, no container orchestration, no Python GIL. A pre-trained anomaly detection model (trained offline on labeled attack datasets) is loaded at startup and executes inference on a feature vector extracted from each request.

**Key Design Decisions:**

- **Hybrid, not replacement** --- ML augments rules, it does not replace them. A request blocked by a regex rule is blocked regardless of anomaly score. ML catches what rules miss.
- **Offline training, online inference** --- Models are trained on curated datasets (CICIDS, HTTP CSIC, proprietary labeled data) and shipped as `.onnx` files. No online learning in production --- this avoids model poisoning attacks.
- **Explainability** --- Every AI block decision includes the top contributing features in the event log, so analysts can understand *why* the model flagged a request, not just that it did.
- **Graceful fallback** --- If ONNX Runtime fails to load or crashes, muWAF falls back to rule-only mode. The AI engine is an enhancement, never a single point of failure.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Go 1.24, Node.js 22 (UI) |
| IPC | gRPC + Protocol Buffers over Unix Domain Sockets |
| Database | PostgreSQL 18 + TimescaleDB + pg_search + UUIDv7 |
| GeoIP | MaxMind GeoLite2-City via `maxminddb-golang` (mmap, offline-only) |
| AI Inference (roadmap) | ONNX Runtime (C API via CGo, CPU-optimized) |
| Frontend | React 19, TypeScript, Vite 8, Tailwind CSS 4, shadcn/ui |
| Auth | JWT (HS256, 24h expiration) |
| Charts | Recharts |
| Fonts | Inter (UI) + Fira Code (monospace/data) |

---

## License

Proprietary. All rights reserved.
