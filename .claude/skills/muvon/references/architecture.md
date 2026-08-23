# MUVON architecture: a five minute briefing for an operator

## Services

One Go module (`muvon`), four independent binaries:

| Binary | Role | DB schema |
|---|---|---|
| **muvon** | Edge gateway, admin API and admin SPA. TLS terminator. Manages hosts, routes, certs and agents. | `muvon` |
| **dialog-siem** | HTTP and container log pipeline. Trigram (`pg_trgm`) search, TimescaleDB hypertables, correlation, alerting. | `dialog` |
| **muvon-deployer** | Owns the Docker socket. Polls the DB for deploy jobs and runs them. Ships container logs (logship). | none |
| **agent** | Thin client installed on edge VPSs. Pulls config from central MUVON (SSE), ships logs to diaLOG (TCP gRPC). With `AGENT_DEPLOYER_ENABLED=true` it also runs the same managed-deploy lifecycle against the local Docker socket, for components assigned to its own `agent_id`. | none (pulls config) |

## Inter-service communication

- **Unix sockets** (`/run/muvon/{dialog,deployer}.sock`) inside the central VPS.
- **TCP gRPC :9001** from remote agents to central diaLOG (firewalled).
- **HTTP + SSE** between remote agents and central muvon (config sync, watch).
- **Fail-open**: if diaLOG dies, traffic keeps flowing and logs are dropped.

## Database

One PostgreSQL 18 instance with **schema isolation**. Extensions in use:

- **TimescaleDB**: `http_logs`, `http_log_bodies`, `alerts`, `container_logs` and `client_events` hypertables, 7-day compression. Retention comes from the `retention_days` setting (default 30 days, `0` keeps forever); dialog-siem reconciles the Timescale job catalog against that setting. `GET /api/system/retention` returns what is actually applied.
- **pg_search** (ParadeDB/Tantivy): created by the first migration and required for startup, but **nothing queries it**. Its BM25 operator did not propagate from a hypertable to its chunks, so search moved to `pg_trgm` GIN indexes queried with `ILIKE` over path, host, user_agent, client_ip, `user_identity::text` and the body columns.
- **pg_uuidv7**: primary keys are time-ordered, so `ORDER BY id` is chronological.

The `schema_migrations` table tracks the ordered slice in `internal/db/migrations.go`. Every migration is tagged with a `product` (`muvon`, `dialog`, or empty for shared).

## Logic worth knowing as an operator

### Config holder and hot reload

`internal/config/Holder` keeps an atomic.Value snapshot. After a DB change, calling `POST /api/system/reload`:

1. Rehydrates the holder from the DB.
2. Pushes the change to connected agents over SSE.

A **direct INSERT or UPDATE** in the DB does not load until a reload happens, which is one reason writes always go through the API. Note that a reload whose snapshot is byte-identical to the current one is a no-op and fires no callbacks.

### Secret box (`internal/secret`)

AES-256-GCM. Secret settings (the SMTP password, per-host JWT secrets, and so on) are stored encrypted. `MUVON_ENCRYPTION_KEY` is **required**: `muvon`, `dialog-siem` and `muvon-deployer` refuse to start without it, and so does an agent with the deployer enabled. It must also stay stable, or previously encrypted values become unreadable.

Secret values are **write-only** in the API: `GET /api/settings` returns masked placeholders.

### Proxy pipeline (summary)

Per request: match the host, take the longest path prefix, then proxy, static, redirect or accel. If `log_enabled`, ship a log entry to diaLOG asynchronously.

### Managed deploy (hybrid topology)

The lifecycle is the same wherever it runs:

1. Image pull
2. Migration container
3. Candidate start
4. Health check
5. **Atomic promote**: old active becomes draining, candidate becomes active
6. Graceful drain of the old instances

The proxy routes to `active` instances **only**. During a drain the old instance still answers in-flight requests.

**Two separate topology questions, each with its own column:**

1. **Where does traffic terminate** → `hosts.target_kind` (`central` or `agent`) plus `hosts.target_agent_id`. The domain itself is bound to an agent, and that agent does its TLS and proxying.
2. **Who runs the container** → `deploy_components.agent_id`.
   - `NULL`: the central `muvon-deployer` handles it, with direct DB access.
   - `'<id>'`: that agent's embedded deployer handles it (`AGENT_DEPLOYER_ENABLED=true`). Same lifecycle code, but state is written to central over HTTP (`/api/v1/agent/deployer/*`).

In some installations **every** host and component lives on the edge, and central never sees customer traffic at all: it is a pure control plane plus SIEM. Never assume "everything is on central"; read those two columns first.

Code is shared through the `internal/deployer/State` interface:

- `NewDBState(*db.DB, agentID)` talks to PostgreSQL directly. Central passes `agentID=""` and therefore picks up only rows with a NULL `agent_id`.
- `NewAPIState(centralURL, apiKey)` is the edge's HTTP adapter, writing state through the central admin server's X-Api-Key endpoints.

**Enqueue rule:** every component in one deployment must share the same `agent_id`, otherwise it is rejected with `enqueue deployment: components straddle hosts`. `agent_id` is chosen at creation and cannot be changed by update, because changing it would orphan containers on the old host.

**Secret env vars:** values for keys listed in `deploy_components.env_secret_keys` are `enc:`-prefixed AES-256-GCM ciphertext. The deployer decrypts them when starting the container. Central's `MUVON_ENCRYPTION_KEY`, the deployer's copy and the edge's `AGENT_ENCRYPTION_KEY` must be **identical**, or the container cannot start.

**Cleanup and image prune.** Every tick starts with three maintenance steps: (1) `cleanupDraining` stops and force-removes draining containers, retrying on the next tick if removal fails (the row stays `draining` until Docker confirms); (2) `reconcileOrphanContainers` lists `muvon.managed=true` containers with `ContainerListAll(all=1)` and removes those the DB does not consider live, exited carcasses included; (3) `CleanupStaleWarming` marks instances left warming after their deployment ended as unhealthy. After a successful promote, `pruneImagesAfterPromote` runs: per component, image refs outside `keep_releases` (default 3, SQL CHECK >= 1) and not bound to a live instance are removed locally. Docker's own refcount plus the SQL-side `in_use` filter are the two safety nets; 409 (in use) and 404 (already gone) are swallowed.

### Anatomy of an edge agent host

A typical agent host looks like this (names vary per installation):

```
/opt/muvon-agent/          docker-compose.agent.yml + .env  → container: muvon-agent-agent-1
/opt/envfiles/             component env files, mounted read-only into the agent (env_file_path points here)
/opt/<project>/            optional: the app's DB compose, upload and media bind mounts
```

The network layout has two layers:

- **A shared proxy network** (`muvon-agent_default`): the agent plus every application container on that host. The agent reaches backends by container name, which is why route backend URLs look like `http://<component-slug>:<port>`.
- **A per-project isolated DB network**: each project's Postgres sits on its own network with only its own API. Two customer projects on the same host therefore cannot reach each other's database at the network level. This is the preferred pattern on multi-project hosts.

Application **source code is not on the host**: managed deploy pulls an image from a registry. The host holds only env files, the DB compose and persistent bind mounts (uploads, media).

The agent publishes 80 and 443. With the embedded deployer on, it listens on one more TCP port for live container log tail. That port is protected by an HKDF-derived bearer token, but should still be bound to an internal interface where possible (listening on all interfaces is the default).

**The real client IP chain matters here**: the edge resolves the correct address and passes it on, but if the application behind it is not configured to trust that, it records the edge's container IP instead and the mistake is silent. See `pitfalls.md` and `docs/client-ip.md` for the contract and per-server settings.

### The central to agent command channel

From the `/agents` page the operator sends a command to any agent (`agent.cache_flush`, `agent.set_log_level`, `cert.renew`, `agent.drain`, `agent.restart`, `agent.self_upgrade`, `agent.revoke`, `container.restart`). The pattern:

1. The command is written to `muvon.agent_commands` (UUIDv7 PK, HMAC-SHA256 signature, `nonce`, `expires_at`).
2. Signing key: HKDF(`MUVON_ENCRYPTION_KEY`, label `"muvon-agent-command-v1"`). The key is required for the binary to start, so the channel is always armed.
3. The agent long-polls (`GET /api/v1/agent/commands?wait=25s`). When central inserts a row, `CommandBus.Wake(agentID)` wakes the agent, a fast path of roughly 50 ms.
4. The agent verifies signature, nonce and `expires_at`, and keeps an LRU of the last 1000 IDs, since delivery is at-least-once.
5. The result comes back via `POST /api/v1/agent/commands/:id/result`. States: `pending → dispatched → succeeded|failed|expired`.
6. A sweeper goroutine marks stale rows (older than 5 minutes) `expired` every 30 seconds.

Destructive commands (`agent.revoke`, `agent.restart`, `agent.self_upgrade`, `agent.drain`) are covered in `destructive-ops.md`.

### System self-upgrade (helper container)

One-click upgrade from Settings, "Sistem" panel. The flow:

1. `GET /api/system/version` returns the running binary's version; `GET /api/system/version/latest` returns the GHCR `:latest` digest via an anonymous manifest HEAD (5 minute cache). The UI compares them.
2. `POST /api/system/upgrade {target_tag, take_backup}` goes from admin to the deployer over the gRPC `SystemUpgrade` server-streaming RPC.
3. The deployer takes an in-process mutex (409 on concurrent), normalises the target tag (strips a leading `v`), streams `pg_dump -Fc` out of the postgres container, and spawns a `docker:27-cli` helper container mounting the Docker socket plus `/opt/muvon:/host/muvon:rw`.
4. The helper script refreshes the compose file from GitHub raw with `wget`, rewrites `:latest` to `:<target>` with `sed`, runs `compose pull`, then `compose up -d --no-deps --wait muvon dialog-siem`, and finally `compose up -d --no-deps --wait muvon-deployer` (last, because the deployer is the helper's own spawner).
5. Recreating the deployer EOFs the gRPC stream. The admin handler does **not** treat that as success: it polls `127.0.0.1:9443/health` for up to 60 seconds and emits `done` only on a 200, otherwise `failed`. That path is the auth-free one; `/api/system/health` is the JWT-gated twin.
6. Live progress reaches the UI over `GET /api/system/upgrade/stream` (SSE events `pull`, `restart`, `post_check`).

Required mounts in `docker-compose.yml`: `/var/run/docker.sock`, `/opt/muvon:/host/muvon:rw`, and the `backups` volume.

## Repo map

```
cmd/
  muvon/           edge gateway + admin server
  dialog-siem/     SIEM
  muvon-deployer/  deploy worker
  agent/           edge agent
internal/
  admin/           admin HTTP API (handlers_*, server.go, auth, csrf, cookies, middleware)
  agentctrl/       command types, HMAC, agent-side registry and poll client
  agentsvc/        agent config/watch/cert endpoints, command bus
  alerting/        Slack and SMTP dispatchers
  config/          Holder + Source (DBSource / AgentSource)
  correlation/     anomaly, error spike, auth brute force, export burst
  db/              pgx pool, migrations, retention
  deployer/        managed deploy worker, scheduled jobs, logship, gRPC
  health/          backend health manager and circuit breaker
  identity/        JWT identity extraction
  logger/          log enqueue to diaLOG
  middleware/      proxy middlewares (rate limit, cors, security headers)
  proxy/           proxy pipeline, accel, redirect, RUM ingest, Cloudflare trust
  router/          host and path matcher
  scheduler/       central-only cron ticker for scheduled jobs
  secret/          AES-GCM box
  tls/             Let's Encrypt and cert cache
  version/         build-stamped version
proto/             protobuf (logpb, deployerpb)
clientlib/         browser RUM client, dist/rum.js is committed and embedded
frontend/dist/     embedded SPA (go:embed)
ui/                React SPA source
```

## Notes

- **The Go module is named `muvon`**, so imports are `muvon/internal/...`. Never relative.
- **CGO_ENABLED=0**: pure Go, fast builds, small binaries.
- **`embed.go` declares package `dialog`** for historical reasons. It embeds `frontend/dist`.
- The `muvon` and `dialog-siem` binaries sitting in the repo root are leftovers, not build inputs. Ignore them.

## CLAUDE.md

`/CLAUDE.md` holds the structural rules for the project. When in doubt, read it first.
