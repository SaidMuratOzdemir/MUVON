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

- **TimescaleDB**: `http_logs`, `http_log_bodies`, `container_logs` and `client_events` hypertables. `alerts` is a plain table on purpose: an open alert must outlive compression and retention. Compression and retention both come from settings that dialog-siem reconciles into the Timescale job catalog: `compression_days` and `compression_bodies_days` (default 7 days each, `0` never compresses) and `retention_days` (default 30 days, `0` keeps forever). `GET /api/system/compression` and `GET /api/system/retention` return what is actually applied. A compressed chunk cannot use a GIN index, so the uncompressed window is also the window where trigram search stays indexed.
- **pg_trgm**: GIN trigram indexes queried with `ILIKE` over path, host, user_agent, client_ip and `user_identity::text`. This is all of log search; there is no BM25. Body columns are indexed the same way but only searched when the caller passes `search_bodies`.
- **UUIDv7 keys** come from PostgreSQL 18's built-in `uuidv7()` through each schema's `gen_uuidv7()` wrapper, not from an extension: primary keys are time-ordered, so `ORDER BY id` is chronological.

Extensions belong in `public`. `postgres/init.sql` creates them at database init so they land there; a bare `CREATE EXTENSION` from a migration instead lands in the running service's own schema, which is how `pg_trgm` was owned by `dialog` until `move_pg_trgm_to_public`. Neither **pg_search** (BM25) nor **pg_cron** is part of the stack: `drop_pg_search` removed BM25, which lost to trigram indexes because its operator did not reach hypertable chunks, and scheduling is Go code in `internal/scheduler`.

The image (`postgres/Dockerfile`) is official PostgreSQL 18 with TimescaleDB at a pinned version, so nothing outside the product decides what a fresh volume gets. `drop_unused_extensions` clears what an earlier vendor base left in existing databases (postgis, vector, pg_ivm, fuzzystrmatch and the unused pg_uuidv7) and resets a `search_path` that named `paradedb`, dropping nothing with CASCADE. Switching an existing volume to the new image needs a clean shutdown first, because crash recovery cannot replay pg_search WAL records without the library.

The `schema_migrations` table tracks the ordered slice in `internal/db/migrations.go`. Every migration is tagged with a `product` (`muvon`, `dialog`, or empty for shared).

## Logic worth knowing as an operator

### Config holder and hot reload

`config.Holder` (`internal/config/hot_reload.go`) keeps an atomic.Value snapshot. After a DB change, calling `POST /api/system/reload`:

1. Rehydrates the holder from the DB.
2. Pushes the change to connected agents over SSE.

API handlers that change configuration (settings, agents, components, edge blocking) trigger this reload themselves.

A **direct INSERT or UPDATE** in the DB does not load until a reload happens, which is one reason writes always go through the API. Note that a reload whose snapshot is byte-identical to the current one is a no-op and fires no callbacks.

### Secret box (`internal/secret`)

AES-256-GCM. Secret settings (the SMTP password, per-host JWT secrets, and so on) are stored encrypted. `MUVON_ENCRYPTION_KEY` is **required**: `muvon`, `dialog-siem` and `muvon-deployer` refuse to start without it, and so does an agent with the deployer enabled. It must also stay stable, or previously encrypted values become unreadable.

Secret values are **write-only** in the API: `GET /api/settings` returns masked placeholders.

### Proxy pipeline (summary)

Per request: match the host, take the longest path prefix, then proxy, static, redirect or accel. If `log_enabled`, ship a log entry to diaLOG asynchronously.

### Alerts

- **Incidents.** One open alert per fingerprint (rule plus group value). Repeats raise `occurrences`; severity only rises; acknowledging closes it and the next firing opens a new one.
- **Rules are data.** Builtin rules (the HTTP correlation rules and the certificate watch) record without notifying until routed. Event rules belong to a project and match container log lines that are JSON with `event.name`.
- **Matching runs in the log transaction.** Container log batches are acknowledged only after commit; matches are written in the same transaction, and a resent batch is not counted twice. A project claim is kept only when the component runs on the sending host.
- **Notifications are an outbox.** A dispatcher in dialog-siem sends queued deliveries with retries and records each channel's outcome, visible in `GET /api/alerts/{id}`. Channels are named Slack or email destinations; email uses the SMTP account in settings.

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

**Cleanup and image prune.** Every tick starts with three maintenance steps: (1) `cleanupDraining` stops and force-removes draining containers, retrying on the next tick if removal fails (the row stays `draining` until Docker confirms); (2) `reconcileOrphanContainers` lists `muvon.managed=true` containers with `ContainerListAll(ctx, true)` and removes those the DB does not consider live, exited carcasses included; (3) `CleanupStaleWarming` marks instances left warming after their deployment ended as unhealthy. After a successful promote, `pruneImagesAfterPromote` runs: per component, images outside `keep_releases` (default 3, SQL CHECK >= 1) and not bound to a live instance are removed locally. Removal works from the image ID recorded at pull time, because a reference stops reaching the image once a tag moves off it. Docker reports removed, absent or in use, and only the first counts as a deletion; in use is left alone, since it is usually the draining instance from that same promote.

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

The agent publishes 80 and 443. With the embedded deployer on, it listens on one more TCP port for live container log tail (`9100` in `docker-compose.agent.yml`, set by `AGENT_DEPLOYER_TCP_LISTEN`; the host side is `AGENT_DEPLOYER_TCP_BIND`). That port is protected by a bearer token HKDF-derived from `AGENT_ENCRYPTION_KEY`, but should still be bound to an internal interface where possible (the compose default binds every interface). Central dials it at the agent's `deployer_addr`.

**The real client IP chain matters here**: the edge resolves the correct address and passes it on, but if the application behind it is not configured to trust that, it records the edge's container IP instead and the mistake is silent. See `pitfalls.md` and `docs/client-ip.md` for the contract and per-server settings.

### The central to agent command channel

From the `/agents` page the operator sends a command to any agent (`agent.cache_flush`, `agent.set_log_level`, `cert.renew`, `agent.drain`, `agent.restart`, `agent.self_upgrade`, `container.restart`). Revocation is not a command, because a command needs the agent to receive it: `POST /api/agents/{id}/revoke` is a central state change (see "Agent revocation" below). The pattern:

1. The command is written to `muvon.agent_commands` (UUIDv7 PK, HMAC-SHA256 signature, `nonce`, `expires_at`).
2. Signing key: HKDF(`MUVON_ENCRYPTION_KEY`, label `"muvon-agent-command-v1"`). The key is required for the binary to start, so the channel is always armed.
3. The agent long-polls (`GET /api/v1/agent/commands?wait=25`, whole seconds, capped at 50). When central inserts a row, `CommandBus.Wake(agentID)` wakes the waiting poll so it returns the command immediately instead of at the end of the wait.
4. The agent verifies signature, nonce and `expires_at`, and keeps an LRU of the last 1000 IDs, since delivery is at-least-once.
5. The result comes back via `POST /api/v1/agent/commands/:id/result`. States: `pending → dispatched → succeeded|failed|expired`.
6. A sweeper goroutine marks `pending` or `dispatched` rows past their `expires_at` (TTL 5 minutes by default, at most 1 hour) as `expired` every 30 seconds.

Destructive commands (`agent.restart`, `agent.self_upgrade`, `agent.drain`) are covered in `destructive-ops.md`.

### Agent revocation

Revocation lives on central and works whether or not the agent is reachable. `POST /api/agents/{id}/revoke` sets `is_active=false` with `revoked_at` and `revoked_by`, expires the agent's pending and dispatched commands, and calls `agentsvc` `Service.Disconnect`, which ends the open config watch stream and command long poll and refuses requests whose key lookup happened before the revocation. Both agent auth paths check `is_active`: `AuthMiddleware` answers 401 `agent revoked` (401 `invalid api key` for an unknown key), and dialog-siem's TCP gRPC refuses inactive agents on every unary call, so log ingestion stops at the next batch.

The agent keeps serving traffic with its last config (its local cache after a restart), logs the revocation once and retries every 10 minutes (`agentctrl.RevokedRetry`). A revoked key is never re-enabled: `POST /api/agents/{id}/rotate-key` issues a new key on the same row, reactivates it and keeps its host, component and scheduled job bindings. `DELETE /api/agents/{id}` also disconnects open sessions, and sets `agent_id` on components, deployments and scheduled jobs and `target_agent_id` on hosts to NULL.

### System self-upgrade (helper container)

One-click upgrade from the "Sistem güncellemesi" card at the top of the Settings page. The flow:

1. `GET /api/system/version` returns the running binary's version; `GET /api/system/version/latest` returns the newest published tag and reports `update_available` from a semver comparison. The digest travels along for display only: two CI runs on one commit produce different digests, so digest equality is not a usable signal.
2. `POST /api/system/upgrade {target_tag, take_backup}` goes from admin to the deployer over the gRPC `SystemUpgrade` server-streaming RPC.
3. The deployer takes an in-process mutex shared with on-demand backups (the admin side separately answers 409 to a concurrent upgrade), normalises the target tag (strips a leading `v`), streams `pg_dump -Fc` out of the postgres container when `take_backup` is set (a backup that cannot be produced aborts the upgrade), and spawns a `docker:27-cli` helper container mounting the Docker socket plus `/opt/muvon:/host/muvon:rw`.
4. The helper script refreshes the compose file from GitHub raw with `wget`, rewrites `:latest` to `:<target>` with `sed`, runs `compose pull muvon dialog-siem muvon-deployer`, then `compose up -d --no-deps --wait --wait-timeout 180 muvon dialog-siem`, and finally the same for `muvon-deployer` (last, because the deployer is the helper's own spawner).
5. Recreating the deployer EOFs the gRPC stream. The admin handler does **not** treat that as success: it polls `127.0.0.1:9443/health` for up to 60 seconds and emits `done` only on a 200, otherwise `failed`. That path is the auth-free one; `/api/system/health` is the JWT-gated twin.
6. Live progress reaches the UI over `GET /api/system/upgrade/stream`: SSE `upgrade` events whose `step` is `pre_check`, `backup`, `pull`, `restart`, `post_check`, `done` or `failed`.

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
  agentsvc/        agent config/watch/cert/deployer/blocklist endpoints, command bus
  alerting/        delivery outbox dispatcher, digests, Slack and SMTP senders
  alertrules/      alert rule and channel model plus validation, shared by the API and diaLOG
  blocklist/       edge blocking scorer and default patterns
  blocklistsvc/    wires the blocker into central and agents, persists blocks
  config/          Holder + Source (DBSource / AgentSource)
  correlation/     HTTP rules: path scan, auth brute force, error spike, traffic anomaly, sensitive access, data export burst
  db/              pgx pool, migrations, retention, compression
  deployer/        managed deploy worker, scheduled jobs, logship, gRPC
  eventrules/      event rule matching in the container log transaction, evaluator
  health/          backend health manager and circuit breaker
  identity/        JWT identity extraction
  logger/          diaLOG ingest pipelines (HTTP, container, client events) and their gRPC client/server
  middleware/      shared HTTP middlewares (gzip, rate limit, recovery, security headers)
  proxy/           proxy pipeline, accel, redirect, CORS, RUM ingest, Cloudflare trust
  router/          host and path matcher
  scheduler/       central-only cron ticker for scheduled jobs
  secret/          AES-GCM box
  testpg/          migrated PostgreSQL for integration tests
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
