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
| **MUVON** | Central server. Terminates TLS (auto Let's Encrypt or manual PEM), resolves virtual hosts, matches routes by path prefix, and proxies to upstreams. Serves the admin panel on `:443` for the configured `MUVON_ADMIN_DOMAIN` (falls back to `:9443` when no domain is set, for local dev). Enriches every log entry with **JWT identity** (verify + decode fallback); visitor country and city are stamped at the edge from Cloudflare's headers. Provides config API and SSE watch endpoint for agents. Also runs the **cron scheduler** that enqueues due scheduled-job runs for the deployer to execute. |
| **agent** | Lightweight edge binary deployed on client servers. Pulls config from central MUVON on startup, watches for changes via SSE (hot reload). Proxies traffic using the central-managed host/route config. Sends logs to central diaLOG over TCP gRPC. No database, no admin panel — zero local state except ACME cert cache + an optional config snapshot for fail-soft cold-start (`AGENT_CONFIG_CACHE`). When `AGENT_DEPLOYER_ENABLED=true` it also runs the same managed-deploy lifecycle as `muvon-deployer` against its local Docker socket, with central reached via `/api/v1/agent/deployer/*` instead of a direct DB connection. |
| **diaLOG** | Receives structured log entries from MUVON or remote agents via gRPC (Unix socket for local, TCP for agents), buffers them in a Go channel, and flushes in batches using PostgreSQL `COPY FROM` for throughput. Stores logs in TimescaleDB Hypertables with UUIDv7 primary keys. Search is trigram-indexed `ILIKE` (pg_trgm GIN) across path, host, user-agent, client IP, the enriched JWT identity and the captured bodies. Exposes SSE live tail for real-time monitoring. Runs a **correlation engine** that detects attack patterns (brute force, scanning, error spikes) in real time and triggers **alerts** via Slack and email. |
| **muvon-deployer** | A separate worker process that owns the Docker socket. Polls the database for pending deployment jobs and executes the full deploy lifecycle: image pull → one-off migration container → candidate container start → health check with restart retries → atomic promote (old active → draining, candidate → active) → graceful drain. The same loop also executes pending **scheduled job runs** (cron) in bounded background workers. Isolates host-level Docker access from the proxy and admin processes. |

---

## Quick Start

### Prerequisites

- **Go 1.25+**
- **Node.js 22+** (to build the admin panel)
- **Docker** (for the postgres container) or an external PostgreSQL 18+
- PostgreSQL extensions, all expected in `public`:
  - [TimescaleDB](https://www.timescale.com/) — hypertables, compression, retention
  - [pg_uuidv7](https://github.com/fboulnois/pg_uuidv7): UUIDv7 generation
  - `pg_trgm`: trigram GIN indexes behind log search. Ships with PostgreSQL

  The bundled image builds on ParadeDB, which is where `pg_search` came from. That extension backed an earlier BM25 search and is now dropped by a migration (see Full-Text Search below); the base image is kept only because it is what the current `pgdata` volume was initialised with.

### 1. Database Setup

```sql
CREATE DATABASE muvon;
\c muvon

CREATE EXTENSION IF NOT EXISTS pg_uuidv7;
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
```

Create them in `public`. A migration also creates `pg_trgm` if it is missing, but that migration runs with the service's own schema first in `search_path`, so the extension lands there instead and only the service that put it there can see its operator classes.

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
  -admin-domain panel.example.com \
  -jwt-secret "$(openssl rand -hex 32)" \
  -encryption-key "$MUVON_ENCRYPTION_KEY"
```

`-jwt-secret` and `-encryption-key` are required and have no defaults; the
binary exits if either is missing. Generate the encryption key **once** and
keep it: it is the only thing that can read the secrets it wrote.

```bash
export MUVON_ENCRYPTION_KEY=$(openssl rand -hex 32)
```

`dialog-siem` and `muvon-deployer` need the same `MUVON_ENCRYPTION_KEY` and
refuse to start without it.

Open the admin panel on `https://panel.example.com`. The plain-HTTP admin
listener on `127.0.0.1:9443` is started as well, in every configuration, and is
how the first admin user is created before any certificate exists. Keep it on
loopback or behind a firewall. Then:
1. Create the initial admin user (`POST /api/auth/setup`)
2. Add hosts (domains) you want to proxy
3. Add routes per host (proxy/static/redirect)
4. Configure TLS (auto Let's Encrypt by default)

---

## Updating

`install.sh` and `install-agent.sh` are idempotent: the same command performs
both the first install and every update afterwards.

```bash
# Central host:
bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install.sh)

# Every edge agent host:
bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install-agent.sh)
```

What the script does:

1. Re-downloads the compose file and the postgres helper files.
2. Keeps the existing `.env`, appending only newly introduced variables.
   Secrets such as `MUVON_ENCRYPTION_KEY` are **never overwritten**.
3. On an update, takes a `pg_dump -Fc` backup into `/opt/muvon/backups/`.
   The last 5 are kept.
4. Prints the newest CHANGELOG section and asks for confirmation.
5. Pulls the images and starts the services with `up -d --wait`.
6. Polls `127.0.0.1:9443/health` for up to 60 seconds.
7. Creates the admin account on a first install (skipped if one exists).
8. Reports the running version.

### Pinning a version

```bash
bash <(curl -fsSL .../install.sh) --version 0.1.0
```

Without `--version` the images track `:latest`. CI publishes three tiers per
release: `0.1.0` (patch), `0.1` (minor) and `0` (major). An existing pin is
preserved across updates.

### Upgrade order in a hybrid topology

**Central first, then each agent.** A new agent talking to an old central gets
404 on the `/api/v1/agent/deployer/*` endpoints: its deploy loop stops while
proxying and log shipping keep working.

```bash
# 1. Central
ssh central "bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install.sh)"

# 2. Health check
curl -fsSL https://muvon.example.com/health

# 3. Each agent
for host in agent1 agent2; do
  ssh "$host" "bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install-agent.sh)"
done
```

### Migration discipline

Migrations are **forward-only**. A new migration is **appended** to
`internal/db/migrations.go` and never edited or reordered. Each binary runs
`RunMigrations` at startup, so deploying a new image upgrades the schema.

**Downgrades are not supported.** An older binary may not understand the newer
schema, and restoring a PostgreSQL snapshot is the only way back.

### Backup and restore

`install.sh` takes a `pg_dump -Fc` backup before every update, and the panel can
take one on demand (Settings, System). Manually:

```bash
docker compose exec -T postgres pg_dump -Fc -U muvon -d muvon \
  > /opt/muvon/backups/manual-$(date +%F).dump
```

Restore:

```bash
docker compose stop muvon dialog-siem muvon-deployer
docker compose exec -T postgres pg_restore --clean -U muvon -d muvon \
  < /opt/muvon/backups/pgdata-YYYYMMDD-HHMMSS.dump
docker compose up -d
```

### CHANGELOG

[`CHANGELOG.md`](./CHANGELOG.md) is the source of truth for what changed in a
release, and the GitHub Release notes carry the same content. Section
taxonomy: `BREAKING / SECURITY / FEATURES / ENHANCEMENTS / BUGFIXES`. Read it
before updating; the installer prints it for you anyway.

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

**Body capture.** A body is captured when the request actually carries one
(`Content-Length` is not zero) and its content type is text-like. Binary and
bulk types are skipped by type, not by method: `multipart/form-data`,
`application/octet-stream`, `image/*`, `video/*`, `audio/*`, zip, gzip and PDF.
In practice that means `POST`/`PUT`/`PATCH` are captured and `GET`/`HEAD` are
logged by headers, path and query string alone, because they arrive without a
body. There is no method allow-list in the code, so a `DELETE` or `GET` that
does carry a body is captured like any other. The copy forwarded to the backend
is never truncated; only the SIEM copy is cut at `max_body_capture_size`
(default 64 KiB) and flagged as truncated.

---

## Database Layout

Each service owns its own schema in a single PostgreSQL instance. No cross-schema reads.

| Schema | Service | Tables |
|--------|---------|--------|
| `muvon` | MUVON | hosts (`tls_mode`, `rum_enabled`), routes, settings, tls_certificates, acme_cache, admin_users, admin_refresh_tokens, admin_audit_log, agents (`api_key_hash`), agent_commands, deploy_projects, deploy_components (`agent_id`, `paused`, `env`, `env_secret_keys`, `spec_hash` counterpart, `keep_releases`), deploy_releases, deploy_release_components, deploy_instances (`spec_hash`), deployments (`agent_id`), deployment_events, scheduled_jobs (`component_id`, `agent_id`, `schedule`, `exec_mode`), scheduled_job_runs |
| `dialog` | diaLOG | http_logs (Hypertable, `trace_id`, `span_id`), http_log_bodies (Hypertable), log_notes, alerts (Hypertable), container_logs (Hypertable), containers, client_events (Hypertable) |

`schema_migrations` is shared: each service applies only the migrations whose
`product` matches its own schema, plus the ones marked shared.

---

## Features

### MUVON Edge Gateway

| Feature | Notes |
|---------|-------|
| TLS Termination | Per-host `tls_mode`: `off` / `redirect` / `auto` (Let's Encrypt) / `manual` (admin-uploaded PEM) |
| DNS verification | `GET /api/hosts/{id}/dns-status` resolves the domain and compares against central public IP + every agent's last-seen IP |
| TLS status | `GET /api/hosts/{id}/tls-status` reports cert validity, days remaining, issuer |
| Multi-Host Routing | Virtual host resolution by domain |
| Path-Prefix Matching | The longest matching prefix always wins. `priority` only breaks ties between prefixes of equal length (routes are loaded `ORDER BY priority DESC`); it cannot promote a shorter prefix over a longer one |
| Per-Route Rate Limiting | Fixed one-second window keyed by client IP. Capacity is `rate_limit_burst`, falling back to `rate_limit_rps` when burst is zero. The counter resets when the window elapses rather than sliding, so a burst straddling two windows can pass |
| Per-Route Body Limit | `max_body_bytes`, returns 413 on exceed |
| Per-Route Timeout | `timeout_seconds`, propagates to upstream |
| CORS | Per-route origins, methods, headers, credentials |
| X-Accel-Redirect | Backend-controlled file serve, `accel_root` |
| Pre-Signed URLs | HMAC-SHA256 token + expires param |
| Static File Serving | `static_root` with optional SPA fallback |
| Redirect Routes | 301 redirects with optional target rewrite |
| Header Manipulation | Per-route add/del on request and response |
| Client IP Forwarding | `X-Real-IP` carries the resolved client address, `X-Forwarded-For` the hop chain; apps gate on the injected `MUVON_EDGE_IP`. See [docs/client-ip.md](docs/client-ip.md) |
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
| Worker processes | Per-component `command` (CMD override), `health_mode` (`http`/`exec`/`running`), `health_command`, `deploy_strategy` (`blue_green`/`recreate`), `deploy_order` — run web/celery/beat from one image, gate migration before workers, keep singletons from overlapping |
| Scheduled jobs (cron) | Component-bound periodic runs (scrape/cleanup/report/sync). Central scheduler enqueues on a cron expression (timezone-aware); the deployer executes in `run` (fresh one-off container) or `exec` (inside the active container) mode, bounded concurrency so a long job never blocks deploys. `concurrency_policy`, `timeout_seconds`, manual "run now", run history with exit code + output. `GET/POST/PUT/DELETE /api/deploy/projects/{slug}/jobs[/{job}]` + `/run`, `/runs`. Works on central and edge components |

### diaLOG SIEM

| Feature | Notes |
|---------|-------|
| HTTP Logs | Full request/response capture: headers, bodies, timing, user identity, geolocation |
| TimescaleDB Hypertables | Daily chunks. Compression from the `compression_days` and `compression_bodies_days` settings (default 7 days each, `0` = never compress), retention from `retention_days` (default 30 days, `0` = keep forever) |
| Full-Text Search | pg_trgm trigram GIN indexes, queried with `ILIKE`, across path, host, user-agent, client IP and `user_identity`; the captured bodies are searched only when the caller opts in, since that is the expensive shape. BM25 was dropped in an early migration because pg_search's operator did not propagate from a TimescaleDB hypertable to its chunks, so root-level queries returned nothing, and the extension itself is now dropped too |
| UUIDv7 IDs | Time-ordered, K-sortable, no separate timestamp index |
| SSE Live Tail | Real-time log stream over Server-Sent Events |
| Body Capture | Configurable max size (default 64KB), truncation flag |
| JWT Identity Enrichment | Per-host verify/decode, claim extraction |
| Visitor Location | Country and city from Cloudflare's visitor headers, trusted only through the operator's own zone |
| Correlation Engine | path_scan, auth_brute, error_spike, traffic_anomaly, sensitive_access, data_export_burst |
| Alerting | Slack webhook + SMTP, per-fingerprint cooldown |
| Container Logs | stdout/stderr capture from managed containers, dimension table for picker |
| Client Events (RUM) | Browser telemetry ingested at `/__muvon/rum`: page views, JS errors, web vitals, fetch failures, form/DOM signals — joined to http_logs by `trace_id` |
| Trace Context | W3C `traceparent` honoured/generated per request; reflected to the browser via `Server-Timing` so client events correlate with proxy + container logs on one id |

### Admin Panel

React 19 + Vite 8 + shadcn/ui. Bundled into the `muvon` binary via `//go:embed`.

| Page | Route | Notes |
|------|-------|-------|
| Dashboard | `/` | Landing view: traffic and ingest health at a glance |
| Hosts | `/hosts` | CRUD virtual hosts + per-host JWT settings; expanding a row shows live DNS + TLS verification |
| Routes | `/routes` | Per-host routes (proxy/static/redirect) |
| Logs | `/logs` | Search, filter, view, star, note, live-tail |
| Alerts | `/alerts` | Correlation engine output, ack/dismiss |
| Container Logs | `/container-logs` | Live tail + history (managed and agent containers) |
| Zamanlanmış İşler | `/jobs` | Cron-driven, component-bound job runs: schedule, enable/disable, run now, run history with exit code and output tail |
| Client Events | `/client-events` | Browser RUM telemetry; filter by trace/session/app/event, click `trace_id` to pivot to the matching http_logs |
| Uygulamalar | `/apps` | Central-hosted apps (services on the MUVON server); wizard, env editor, CI/CD snippets, rollback, pause |
| Uzak Uygulamalar | `/apps/edge` | Same UI filtered to apps whose services run on an agent host |
| Agents | `/agents` | API key management for hub-and-spoke setups (plaintext key revealed once on create) |
| Settings | `/settings` | Global settings (retention, telemetry sampling, TLS/ACME, JWT, alerting, correlation) |
| TLS | `/tls` | Manual PEM upload, ACME cert listing |
| Audit | `/audit` | Admin audit log |
| Settings, "Sistem" panel | `/settings` (top of the page) | One-click upgrade panel: running vs GHCR digest comparison, tag picker (`latest`/`v0`/`v0.1`/custom), DB backup toggle, inline CHANGELOG preview, live SSE progress |

Sidebar labels are shown above exactly as the panel renders them; the panel's
interface language is Turkish.

The sidebar footer carries the account controls: a key icon opens password
change (which also ends every other session) and the arrow signs out.

If diaLOG is down, log pages show a service-offline banner. Everything else keeps working.

---

## Configuration

### MUVON

| Flag | Env var | Default | Notes |
|------|---------|---------|-------|
| `-dsn` | `MUVON_DSN` | `postgres://dialog:dialog@localhost:5432/dialog?sslmode=disable` | PostgreSQL connection string |
| `-http` | `MUVON_HTTP_ADDR` | `:80` | HTTP listen address |
| `-https` | `MUVON_HTTPS_ADDR` | `:443` | HTTPS listen address |
| `-admin` | `MUVON_ADMIN_ADDR` | `:9443` | Admin API listen address. This listener is started in **every** configuration, including when `-admin-domain` is set, because the upgrade flow's local health check and `install.sh` both poll it. It speaks plain HTTP and the process applies no network restriction of its own: docker-compose publishes it as `127.0.0.1:9443:9443` (host loopback only), and a bare-metal install must firewall it |
| `-admin-domain` | `MUVON_ADMIN_DOMAIN` | `""` | Additionally serve the admin panel on this domain over :443 |
| `-jwt-secret` | `MUVON_JWT_SECRET` | (required) | Signing secret for admin session cookies. At least 32 characters; the binary exits if it is shorter. There is deliberately no default: an admin session is a signed cookie, so a guessable secret is a login bypass |
| `-log-socket` | `MUVON_LOG_SOCKET` | `/tmp/dialog.sock` | diaLOG Unix socket path |
| `-deployer-socket` | `MUVON_DEPLOYER_SOCKET` | `/run/muvon/deployer.sock` | muvon-deployer Unix socket (live container introspection + log tail) |
| `-log-level` | `MUVON_LOG_LEVEL` | `info` | Log level (debug/info/warn/error) |
| `-encryption-key` | `MUVON_ENCRYPTION_KEY` | (required) | AES-256-GCM key for encrypted settings **and component env secrets**, and the seed of the HKDF derivation that signs central to agent commands (label `muvon-agent-command-v1`). The binary exits without it. Must match `muvon-deployer`'s `MUVON_ENCRYPTION_KEY` and any agent's `AGENT_ENCRYPTION_KEY`, otherwise secret env vars cannot be decrypted at container start. Generate once and keep it: rotating it makes everything it encrypted unreadable |
| `-public-ip` | `MUVON_PUBLIC_IP` | `""` | Central's externally reachable IP, used by DNS verification. Auto-detected via ifconfig.me when empty; pin it on an air-gapped install |
| `-config-reload-interval` | `MUVON_CONFIG_RELOAD_INTERVAL` | `5s` | Background config reload cadence. A reload whose snapshot is byte-identical to the last one skips both the swap and the reload callbacks |
| `-version` | | | Print version and exit |
| | `MUVON_CLOUDFLARE_IP_SECRET` | `""` | Shared secret the operator injects with a Transform Rule on their own Cloudflare zone. Empty disables Cloudflare client-IP and visitor-location trust, which is the safe default |
| | `MUVON_CLOUDFLARE_IP_HEADER` | `X-Muvon-CF-Key` | Header that carries the secret above. Stripped before request headers reach the log pipeline |

### muvon-deployer

| Flag | Env var | Default | Notes |
|------|---------|---------|-------|
| `-dsn` | `MUVON_DSN` | `postgres://muvon:muvon@localhost:5432/muvon?sslmode=disable` | PostgreSQL connection string |
| `-docker-host` | `MUVON_DOCKER_HOST` | `unix:///var/run/docker.sock` | Docker API host |
| `-poll` | `MUVON_DEPLOYER_POLL_INTERVAL` | `5s` | Deployment poll interval |
| `-grpc-socket` | `MUVON_DEPLOYER_SOCKET` | `/run/muvon/deployer.sock` | Unix socket for the deployer gRPC service (live container tail, upgrade, backup) |
| `-log-level` | `MUVON_LOG_LEVEL` | `info` | Log level |
| | `MUVON_ENCRYPTION_KEY` | (required) | Must match central MUVON's key to decrypt secret env vars; the binary exits without it |
| `-max-viewers-per-container` | `MUVON_CONTAINER_LOG_MAX_VIEWERS_PER_CONTAINER` | `4` | Concurrent live-tail viewers per container |
| `-max-viewers-global` | `MUVON_CONTAINER_LOG_MAX_VIEWERS_GLOBAL` | `64` | Concurrent live-tail viewers overall |
| `-max-line` | `MUVON_CONTAINER_LOG_MAX_LINE` | `16384` | Max bytes per emitted log line; longer lines split with `truncated=true` |
| `-logship` | `MUVON_DEPLOYER_LOGSHIP_ENABLED` | `true` | Ship managed-container stdout/stderr to diaLOG |
| `-logship-dialog-socket` | `MUVON_DEPLOYER_LOGSHIP_DIALOG_SOCKET` | `/run/muvon/dialog.sock` | diaLOG socket for log shipping |
| `-logship-spool-dir` | `MUVON_DEPLOYER_LOGSHIP_SPOOL_DIR` | `/var/lib/muvon/logship` | Disk spool when diaLOG is unreachable |
| `-logship-spool-max-bytes` | `MUVON_DEPLOYER_LOGSHIP_SPOOL_MAX_BYTES` | `268435456` (256 MiB) | Total spool disk budget |
| `-logship-batch` | `MUVON_DEPLOYER_LOGSHIP_BATCH` | `500` | Lines per shipping batch |
| `-logship-flush-ms` | `MUVON_DEPLOYER_LOGSHIP_FLUSH_MS` | `1000` | Time between forced flushes |
| `-version` | | | Print version and exit |

### Agent

| Flag | Env var | Default | Notes |
|------|---------|---------|-------|
| `-central` | `AGENT_CENTRAL_URL` | (required) | Central server URL. Use the admin domain over HTTPS (`https://muvon.example.com`), not `:9443`: that port is plain HTTP and docker-compose binds it to host loopback |
| `-api-key` | `AGENT_API_KEY` | (required) | Agent API key (plaintext is only revealed once on create) |
| `-http` | `AGENT_HTTP_ADDR` | `:80` | HTTP listen address |
| `-https` | `AGENT_HTTPS_ADDR` | `:443` | HTTPS listen address |
| `-log-addr` | `AGENT_LOG_ADDR` | `""` | Central diaLOG TCP address (host:port) |
| `-tls-cache` | `AGENT_TLS_CACHE` | `/var/lib/agent/tls` | Local ACME cert cache directory |
| `-config-cache` | `AGENT_CONFIG_CACHE` | `/var/lib/agent/config.json` | Disk cache of the last successful config payload; on cold start during a central outage the agent serves stale-but-working config and retries in the background |
| `-log-level` | `AGENT_LOG_LEVEL` | `info` | Log level |
| `-public-ip` | `AGENT_PUBLIC_IP` | `""` | Externally reachable IP this agent self-reports for DNS verification; empty disables the self-report |
| `-docker-socket` | `AGENT_DOCKER_SOCKET` | `unix:///var/run/docker.sock` | Local Docker daemon (shared by dockerwatch and the edge deployer; empty or unreadable disables both) |
| `-dockerwatch` | `AGENT_DOCKERWATCH_ENABLED` | `true` | Ship local containers' stdout/stderr to central diaLOG |
| `-dockerwatch-host-id` | `AGENT_HOST_ID` | `""` | Identifier for this host in shipped logs (default: hostname) |
| `-dockerwatch-managed-only` | `AGENT_DOCKERWATCH_MANAGED_ONLY` | `false` | Tail only containers labelled `muvon.managed=true` |
| `-dockerwatch-spool-dir` | `AGENT_DOCKERWATCH_SPOOL_DIR` | `/var/lib/agent/logship` | Disk spool when central is unreachable |
| `-dockerwatch-spool-max-bytes` | `AGENT_DOCKERWATCH_SPOOL_MAX_BYTES` | `268435456` (256 MiB) | Total spool disk budget |
| `-dockerwatch-batch` | `AGENT_DOCKERWATCH_BATCH` | `500` | Lines per shipping batch |
| `-dockerwatch-flush-ms` | `AGENT_DOCKERWATCH_FLUSH_MS` | `1000` | Time between forced flushes |
| `-dockerwatch-max-line` | `AGENT_DOCKERWATCH_MAX_LINE` | `16384` | Per-line truncation threshold |
| `-deployer` | `AGENT_DEPLOYER_ENABLED` | `false` | Run the embedded edge deployer so components with this agent's `agent_id` are spawned locally |
| `-deployer-poll-ms` | `AGENT_DEPLOYER_POLL_MS` | `5000` | Poll cadence for the edge deployer loop |
| `-deployer-encryption-key` | `AGENT_ENCRYPTION_KEY` | `""` | AES-256-GCM key, must match central's `MUVON_ENCRYPTION_KEY`. Required only when `-deployer` is on, and then the agent exits without it: a deployer that cannot read secret env values would fail a deployment months later instead of at startup |
| `-deployer-tcp-listen` | `AGENT_DEPLOYER_TCP_LISTEN` | `""` | host:port for the deployer gRPC TCP listener that central dials for live container tail; empty disables it |
| `-version` | | | Print version and exit |
| | `AGENT_CLOUDFLARE_IP_SECRET` | `""` | Same contract as the central variable; empty disables Cloudflare client-IP trust |
| | `AGENT_CLOUDFLARE_IP_HEADER` | `X-Muvon-CF-Key` | Header carrying that secret |

### diaLOG

Every pipeline setting below also exists as a row in the `settings` table, which
is what the admin panel edits. A flag or env var passed at the host wins over the
stored setting, because that is the choice made closest to the machine. The
effective values are logged at boot, and a live pipeline is never resized: the
values are read once at startup.

| Flag | Env var | Default | Notes |
|------|---------|---------|-------|
| `-dsn` | `DIALOG_DSN` | `postgres://dialog:dialog@localhost:5432/dialog?sslmode=disable` | PostgreSQL connection string |
| `-socket` | `DIALOG_SOCKET` | `/tmp/dialog.sock` | gRPC Unix socket path |
| `-tcp-addr` | `DIALOG_TCP_ADDR` | `""` | gRPC TCP listen address for agent log ingestion (e.g. `:9001`) |
| `-log-level` | `DIALOG_LOG_LEVEL` | `info` | Log level |
| `-encryption-key` | `MUVON_ENCRYPTION_KEY` | (required) | AES-256-GCM key for encrypted settings (SMTP password and friends); the binary exits without it |
| `-buffer` | `DIALOG_BUFFER` | `10000` | HTTP log pipeline buffer size |
| `-workers` | `DIALOG_WORKERS` | `4` | HTTP log pipeline worker count |
| `-batch` | `DIALOG_BATCH` | `1000` | HTTP log pipeline batch size |
| `-flush-ms` | `DIALOG_FLUSH_MS` | `2000` | HTTP log pipeline flush interval (ms) |
| `-container-ingest` | `DIALOG_CONTAINER_INGEST` | `true` | Enable the container log ingest pipeline |
| `-container-buffer` / `-container-workers` / `-container-batch` / `-container-flush-ms` | `DIALOG_CONTAINER_BUFFER` / `DIALOG_CONTAINER_WORKERS` / `DIALOG_CONTAINER_BATCH` / `DIALOG_CONTAINER_FLUSH_MS` | `10000` / `2` / `1000` / `2000` | Container log pipeline sizing |
| `-client-event-ingest` | `DIALOG_CLIENT_EVENT_INGEST` | `true` | Enable the client event (RUM) ingest pipeline |
| `-client-event-buffer` / `-client-event-workers` / `-client-event-batch` / `-client-event-flush-ms` | `DIALOG_CLIENT_EVENT_BUFFER` / `DIALOG_CLIENT_EVENT_WORKERS` / `DIALOG_CLIENT_EVENT_BATCH` / `DIALOG_CLIENT_EVENT_FLUSH_MS` | `10000` / `2` / `1000` / `2000` | Client event pipeline sizing |
| `-version` | | | Print version and exit |

---

## Build & Release

`.github/workflows/release.yml` runs two jobs before anything is published.
`verify` builds the UI (the binary embeds it), then runs `go vet`,
`go test -race -count=1 ./...`, `staticcheck` and `govulncheck`. `integration`
starts a postgres and a timescale container and runs the two tests that need
real infrastructure: a `pg_dump` taken through the exec stream that
`pg_restore` accepts, and the retention and image prune rules against a real
planner. The build job depends on both, and each image is scanned by trivy for
fixable high and critical advisories before it is pushed, not after. Operators upgrade to these
images with one click, and a broken test noticed afterwards is noticed too
late.

Once the gate passes, the four images (`muvon`, `dialog-siem`, `agent`,
`muvon-deployer`) are built in parallel and pushed under
`ghcr.io/saidmuratozdemir/muvon/<service>`. The tags depend on what was pushed:

| Push | Tags produced |
|------|---------------|
| `main` | `:sha-<short-commit>` and `:main`, which are dev artifacts |
| `v1.2.3` | `:1.2.3`, `:1.2`, `:1` and `:latest`, plus a GitHub Release |

**`:latest` moves only on a `v*` tag push.** A commit to main never touches it,
which keeps `:latest` pointing at the newest official release and keeps the
panel's running-versus-latest digest comparison meaningful. To try a main
commit, pin `:sha-<commit>`.

All three segments of the image path are lowercase
(`ghcr.io/saidmuratozdemir/muvon/muvon`). Docker rejects uppercase repository
names, so copy the path as written.

---

## Repository Layout

```
cmd/
  muvon/              MUVON entry point (edge gateway, admin panel)
  dialog-siem/        diaLOG entry point (SIEM)
  muvon-deployer/     muvon-deployer entry point (managed Docker deploys)
  agent/              agent entry point (edge binary)

internal/
  admin/              HTTP handlers for admin API (auth, hosts, routes, settings, logs, alerts, agents, deploys, container logs, system version/upgrade/backup)
  agentctrl/          Command channel types, HMAC signing, agent-side registry and long-poll client
  agentsvc/           Central-side agent config service (SSE watch + cert sync + command bus)
  alerting/           Slack + SMTP notifiers, fingerprint dedup
  config/             Config Source interface, DBSource (central) and AgentSource, hot reload Holder
  correlation/        Real-time correlation engine (sliding window rules, alerts)
  db/                 PostgreSQL pool, migrations, query helpers, retention reconciler
  deployer/           Docker client, deploy lifecycle, scheduled-job executor, gRPC server/client
  health/             Backend health manager + circuit breaker
  identity/           JWT verify/decode + per-host claim extraction
  logger/             Pipeline + worker (COPY FROM batches), gRPC server/client, log entries
  middleware/         Recovery, rate limiter, security headers, gzip
  proxy/              Reverse proxy, body capture, X-Accel-Redirect, signed file serve, RUM ingest, Cloudflare trust
  router/             Host/path matching, admin-domain routing
  scheduler/          Central-only cron ticker that turns due scheduled_jobs into pending runs
  secret/             AES-256-GCM Box for encrypted settings
  tls/                ACME (autocert), DBCache, manager, manual cert upload
  version/            Build-stamped version and commit

proto/
  logpb/              diaLOG service protobuf definitions
  deployerpb/         muvon-deployer service protobuf definitions

clientlib/            Browser RUM client (TypeScript + esbuild). dist/rum.js is committed
                      and embedded; regenerate with `make clientlib`

docs/
  client-ip.md        How applications behind MUVON read the real visitor address

ui/
  src/                React SPA (admin panel)
```

---

## API Reference (selected)

### Auth

Sessions are cookie-based: a 15 minute access JWT, a 30 day rotating refresh
token, and a CSRF token the SPA echoes back. Every authenticated request
re-reads the user row and compares the token's `token_version` against it, so a
revoked session stops working on its next request rather than at the end of the
access token's lifetime.

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/api/auth/setup` | Create the first admin. Returns 409 once one exists |
| `POST` | `/api/auth/login` | Sign in |
| `POST` | `/api/auth/refresh` | Rotate the refresh token. Reuse of a rotated token revokes the whole family |
| `POST` | `/api/auth/logout` | Revoke this refresh token only; other devices stay signed in |
| `GET` | `/api/auth/me` | Current user |
| `POST` | `/api/auth/password` | Change your own password. Requires the current one, bumps `token_version` and revokes every refresh token, so all other sessions end. The caller is issued fresh cookies |

### System

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/health` | Aggregated health (DB + Log). **No JWT**, and the only unauthenticated one. This is what `install.sh` and the upgrade flow's local check poll |
| `GET` | `/api/system/health` | Same payload, JWT required |
| `GET` | `/api/system/health/backends` | Circuit-breaker state per backend |
| `GET` | `/api/system/health/ingest` | Log ingest pipeline health |
| `GET` | `/api/system/stats` | Dashboard counters |
| `POST` | `/api/system/reload` | Reload config from DB and push the change to connected agents over SSE. A snapshot identical to the current one is a no-op |
| `GET` | `/api/system/retention` | Live retention policies read from the Timescale job catalog, not from the migration |
| `GET` | `/api/system/version` | Running binary's version + image digest |
| `GET` | `/api/system/compression` | Enforced compression window per hypertable |
| `GET` | `/api/system/version/latest` | GHCR `:latest` manifest digest (5 min cache) |
| `POST` | `/api/system/backup` | Take a `pg_dump -Fc` backup now, verified with `pg_restore -l`; 409 while an upgrade or another backup holds the lock |
| `GET` | `/api/system/backups` | List the dumps on disk (last 5 are kept) |
| `POST` | `/api/system/upgrade` | Trigger helper-container upgrade: `{target_tag, take_backup}`; 409 on concurrent run |
| `GET` | `/api/system/upgrade/stream` | SSE with live `pull` / `restart` / `post_check` progress |

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

### Client Events / RUM

Edge endpoints under the reserved `/__muvon/` namespace, served on each
proxied host when `hosts.rum_enabled` is on (no JWT — public, fail-open).

| Method | Path | Notes |
|--------|------|-------|
| `POST` | `/__muvon/rum` | Ingest a browser event batch; always `204` (drops on parse error / full pipeline) |
| `GET` | `/__muvon/rum/config` | Sampling config served to clients (`sample_rates`, `max_batch_bytes`) |
| `GET` | `/__muvon/rum.js` | The embedded browser client lib (ETag-cached) |
| `GET` | `/api/client-events` | Admin search (filter by `trace_id`/`session_id`/`app`/`event_name`, cursor) — proxied to diaLOG |

Sampling is set in Settings → Client Telemetry: `rum_sample_rate` (0 to 1) and
`rum_max_batch_bytes`. Both are served to browsers and pushed to agents.

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

### Scheduled jobs

| Method | Path | Notes |
|--------|------|-------|
| `GET/POST` | `/api/deploy/projects/:slug/jobs` | List / create component-bound cron jobs |
| `GET/PUT/DELETE` | `/api/deploy/projects/:slug/jobs/:job` | Read / update / remove one job |
| `POST` | `/api/deploy/projects/:slug/jobs/:job/enable` | Enable or disable without deleting |
| `POST` | `/api/deploy/projects/:slug/jobs/:job/run` | Trigger a run now |
| `GET` | `/api/deploy/projects/:slug/jobs/:job/runs` | Run history with exit code and output tail |

### TLS / Audit / Containers / Alert tests

| Method | Path | Notes |
|--------|------|-------|
| `GET/POST` | `/api/tls/certificates` | List ACME + operator certs, upload a manual PEM |
| `DELETE` | `/api/tls/certificates/:id` | Remove a stored certificate |
| `GET` | `/api/audit` | Admin audit log |
| `GET` | `/api/containers` | Managed and agent containers (picker dimension) |
| `GET` | `/api/containers/:id` | Container detail |
| `GET` | `/api/containers/:id/logs/stream` | SSE live tail, proxied to the owning deployer |
| `GET` | `/api/container-logs` | Search stored container output |
| `GET` | `/api/container-logs/:id/context` | Surrounding lines for one entry |
| `PATCH` | `/api/agents/:id/mounts` | Update an agent's extra mounts |
| `PATCH` | `/api/agents/:id/deployer-addr` | Set the address central dials for live container tail |
| `POST` | `/api/alerting/test/slack` | Send a test Slack notification |
| `POST` | `/api/alerting/test/smtp` | Send a test email |

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
  trace_id          TEXT,
  span_id           TEXT,
  PRIMARY KEY (id, timestamp)
);
SELECT create_hypertable('http_logs', by_range('timestamp', INTERVAL '1 day'));
```

This is the cumulative shape, not one migration. `user_identity`, `country`,
`city`, `raw_jwt`, `trace_id` and `span_id` were added by later `ALTER TABLE`
migrations; `trace_id` carries a partial index and is the join key to
`container_logs` and `client_events`.

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

## Language

Repository documentation is English: this README, `CLAUDE.md`, `docs/` and the
agent skill files. Operator-facing surfaces are Turkish: the admin panel, the
installer output and the commented sample env files. Each file stays in one
language; do not mix them within a file. When adding a user-visible string,
follow the surface it belongs to rather than the language of the code around
it.
