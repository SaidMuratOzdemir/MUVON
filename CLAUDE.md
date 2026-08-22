# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

MUVON is an edge gateway, security observability, and deploy platform composed of four independent Go services that share a single PostgreSQL 18 instance. The Go module is `muvon`, Go 1.24, Node.js 22 for the UI.

| Binary (`cmd/`) | Role |
|---|---|
| `muvon` | Central edge gateway — terminates TLS, routes by host+path prefix, runs admin panel, owns the `muvon` DB schema. |
| `dialog-siem` | SIEM engine — gRPC (Unix + TCP), async log pipeline with PostgreSQL `COPY FROM`, correlation engine, alerting. Owns the `dialog` schema. |
| `muvon-deployer` | Separate worker that owns the central Docker socket. Polls DB for pending deploy jobs where `agent_id IS NULL`. Isolates Docker access from the proxy. |
| `agent` | Lightweight edge binary for client servers — no DB, pulls config from central MUVON via HTTP + SSE, ships logs to central diaLOG over TCP gRPC. With `AGENT_DEPLOYER_ENABLED=true` it also runs the same managed-deploy lifecycle locally against its Docker socket, claiming deployments where `agent_id` matches its own ID via `/api/v1/agent/deployer/*`. |

The four services talk via gRPC over Unix domain sockets (or TCP for agent → central diaLOG). MUVON is **fail-open**: if diaLOG is down, traffic still flows — logs are dropped.

## Common commands

```bash
# Dependencies
make deps          # go mod tidy + download
make ui-install    # cd ui && npm install

# Build — all four services (builds UI first, copies to frontend/dist for go:embed)
make build                  # native
make build-linux            # linux/amd64 cross-compile → build/*-linux-amd64
make build-minimal          # only muvon + agent (no SIEM/deployer)
make build-minimal-linux

# Run tests
make test                   # go test ./... -v -count=1
make test-race              # with -race
go test ./internal/db -run TestMigrations -v   # single package/test

# UI dev
make ui-dev                 # cd ui && npm run dev (Vite)
cd ui && npm run lint       # ESLint over the SPA

# Deploy (developer-only shortcuts — scp+docker cp restart)
make deploy                 # muvon only
make deploy-all             # muvon (alias for muvon-only deploy)
```

The Makefile `deploy` targets `scp` to an SSH host alias `vps` and `docker cp` into running containers — do not assume they work in arbitrary environments.

## Architecture essentials

### Single module, schema-isolated database
All services import from the same `muvon` Go module but each one only touches its own PostgreSQL schema (`muvon`, `dialog`). Migrations live in `internal/db/migrations.go` as a single ordered slice; each migration has a `product` field (`"muvon"`, `"dialog"`, or `""` for shared). `DB.RunMigrations` filters by the schema passed to `db.New(ctx, dsn, schema)` so a given service only applies its own (plus shared) migrations. `schema_migrations` table tracks applied names. **When adding a migration, always append to the slice — never reorder, never edit applied migrations.**

### Config holder and hot reload
`internal/config` defines a `Source` interface with two implementations:
- `DBSource` — used by central MUVON (reads `hosts`, `routes`, `settings`, managed backends from PostgreSQL).
- `AgentSource` — used by the `agent` binary (fetches from central via `/api/v1/agent/config` and subscribes to `/api/v1/agent/watch` SSE).

`config.Holder` wraps atomic.Value snapshots. Everything read-hot (proxy, router, logger) reads through the holder. `POST /api/system/reload` triggers reload and also pushes SSE updates to all connected agents. When touching config shape, update both `config.go` (struct) and the corresponding source loader.

### Proxy pipeline (`internal/proxy`)
Per request: resolve host → match route by longest path prefix → proxy/static/redirect/accel → if `log_enabled`, async-ship log entry to diaLOG via `logclient`. `accel.go` handles both `X-Accel-Redirect` (backend sets header) and pre-signed serve (`?token=<hmac>&expires=<unix>` where token is `HMAC-SHA256(secret, path+":"+expires)`).

### Managed deploy (hybrid topology)
Routes can bind to a managed component. The proxy selects only `active` instances (never warming/draining). The deploy lifecycle — image pull → migration container → candidate start → health check → atomic promote (old `active` → `draining`, candidate → `active`) → graceful drain — is shared code in `internal/deployer/service.go`, sitting behind a `State` interface:

- `NewDBState(db, agentID)` — direct PostgreSQL access. Central `muvon-deployer` constructs this with `agentID=""` so it only picks up rows with NULL `agent_id`.
- `NewAPIState(centralURL, apiKey)` — HTTP-backed adapter that talks to `/api/v1/agent/deployer/*` (claim, plan, event, instance, promote, fail, drainable, live-containers, …). The agent binary in `cmd/agent` constructs this when `AGENT_DEPLOYER_ENABLED=true` so the same lifecycle runs on the edge against the local Docker daemon.

`deploy_components` and `deployments` carry an `agent_id` column (nullable). Components for one deployment must all share the same `agent_id`; the enqueue path rejects cross-host straddles. Switching a component's `agent_id` after creation is intentionally not exposed in the API — the operator deletes + recreates instead, to avoid orphaning containers on the original host.

**Network aliases.** A container joins its networks under two names: the bare component slug and `<project>-<component>` (`qualifiedAlias` in `service.go`). The bare slug is kept for backwards compatibility but **collides on a host running two projects that both name a component `api`**: Docker round-robins the name, so a sibling reaching `http://api:8000` lands on an arbitrary project's service. On multi-project hosts, point cross-component env values (`SERVER_API_URL` and friends) at the qualified name.

**Config drift.** `env`, `networks`, `mounts` and `command` are applied when Docker creates the container, so editing them changes nothing about a running instance. `deploy_instances.spec_hash` records the `DeployComponent.SpecHash()` the container was created from (`internal/db/deploy_spec.go`), the component's current hash rides along on every API response, and the panel shows a "deploy bekliyor" badge when they differ. Fields the deployer re-reads per deployment (health mode/path/command, restart retries, drain timeouts, keep_releases) are deliberately outside the hash — they already apply without recreating anything. Rows written before the column exists carry `''` and read as unknown, not as drift.

**Moving a component between hosts.** `agent_id` is create-only, so the move is delete + recreate. The new row gets a new id and `routes.managed_component_id` is set to NULL on delete, which leaves every bound route without a backend: containers stay healthy, instances stay `active`, and the domain returns 502. Rebind the routes after recreating, and diff the route count before and after, because a route can be dropped entirely.

**Drain + prune hygiene.** Each tick of `Service.tick` runs `cleanupDraining` → `reconcileOrphanContainers` → `CleanupStaleWarming` before claiming new work. `cleanupDraining` issues `ContainerStop` then `ContainerRemove(force=true)`; if removal fails the instance stays in `draining` state and the next tick retries (no row is flipped to `stopped` until Docker confirms the container is gone). `reconcileOrphanContainers` calls `ContainerListAll(ctx, true)` so exited carcasses from failed migrations or crashed candidates are visible. After every successful Promote the loop calls `pruneImagesAfterPromote`: for each component it asks state for `ListPrunableImageRefs(componentID, keep_releases)` and `ImageRemove`s the results best-effort. `deploy_components.keep_releases` (default 3) is the per-component retention budget; the SQL excludes image refs still bound to a warming/active/draining instance, so an active container's image is never targeted even if it's older than the keep window.

Deploy webhook (`POST /api/deploy/webhook`) uses HMAC-SHA256 and bypasses JWT. Rollback (`POST /api/deploy/projects/{slug}/rollback`) enqueues a fresh deployment with the previous succeeded release's image refs.

**Env vars + secrets.** Each component has an `env` JSONB map and an `env_secret_keys` text array. Values for keys listed in `env_secret_keys` are stored as `enc:`-prefixed AES-256-GCM ciphertext, returned masked from `GET` endpoints, and decrypted by the deployer at container start. The same `MUVON_ENCRYPTION_KEY` must be set on the central `muvon` binary, `muvon-deployer`, and every edge agent (`AGENT_ENCRYPTION_KEY`) — mismatch = container fails to start because the deployer can't decrypt.

### Scheduled jobs (cron) — `scheduled_jobs` + `scheduled_job_runs`
A scheduled job is a periodic, **component-bound** one-off run (scrape / cleanup / report / sync). It borrows the bound component's image, env, secrets, networks and mounts; `command` overrides the image CMD. Three layers, deliberately separate from the operator command channel (`agent_commands`):
- **Scheduler** (`internal/scheduler`, central `muvon` only): a 30s ticker goroutine in `cmd/muvon/main.go` finds due jobs (`next_run_at <= now`), enqueues a `pending` `scheduled_job_runs` row (idempotent on `(job_id, scheduled_for)` for `trigger='schedule'`), and advances `next_run_at` to the next cron boundary. Cron parsing uses `robfig/cron/v3` (`ParseStandard` + `Next` only, not its runner); `cmd/muvon` imports `_ "time/tzdata"` so `LoadLocation` works in the static binary. Crash recovery: a stale `next_run_at` fires exactly **one** catch-up run, then realigns — no per-missed-tick backfill.
- **Executor** (`internal/deployer/service.go`): the same `Service.tick` that claims deployments also `dispatchJobRun`s — claims one pending run per tick (`FOR UPDATE SKIP LOCKED`, agent_id-scoped) into a bounded pool (`maxConcurrentJobs=4`) of **background goroutines** so a long job never blocks the deploy/drain loop. `run` mode spawns a fresh one-off container via the shared `runOneOff` helper (refactored out of `runMigration`); `exec` mode runs the command inside the component's active instance container via `ContainerExecCaptureCode`. Output tail (~16 KiB) + exit code land on the run row; containers carry `muvon.job=scheduled`.
- **Hybrid topology**: works for both central (`NewDBState`) and edge-agent (`NewAPIState`) components via the same `State` interface — `ClaimJobRun`/`LoadJob`/`FinishJobRun`/`ResetStaleJobRuns`, mirrored over `/api/v1/agent/deployer/job/*` with agent ownership checks.

Admin API: `/api/deploy/projects/{slug}/jobs[...]` (CRUD + `/enable`, `/run` manual trigger, `/runs` history). `concurrency_policy='forbid'` (default) skips a tick (recording a `skipped` run) when a prior run is still active. UI: `ui/src/pages/ScheduledJobs.tsx`.

### Admin panel + API
React 19 + Vite 8 + shadcn/ui in `ui/`. Built SPA is copied to `frontend/dist/` and embedded into the `muvon` binary via `//go:embed frontend/dist` in `embed.go` (package name is `dialog` for historical reasons). The admin HTTP server serves both `/api/*` and the SPA. Log endpoints are transparent gRPC proxies to diaLOG — if the socket is unavailable, handlers return a structured 503 and the UI shows a service-offline banner.

Admin panel binds:
- to `:443` on `MUVON_ADMIN_DOMAIN` when set (production).
- to `:9443` (local-only in docker-compose) when not set — used for initial setup before a TLS cert exists.

### Secrets box
`internal/secret.Box` is AES-256-GCM wrapping for settings values (JWT secret, SMTP password, etc.). Secret settings are **write-only in the API** — `GET /api/settings` returns masked placeholders. `MUVON_ENCRYPTION_KEY` must be stable across restarts or encrypted settings become unreadable (`decryptSetting` logs a warning and disables the feature rather than crashing). The same key also seeds the HKDF derivation used to sign agent commands (label `"muvon-agent-command-v1"`), so rotating it invalidates both encrypted settings and the agent command channel.

### Central → agent command channel
`internal/agentctrl` (types + HMAC + Registry + PollClient) and `internal/agentsvc/{cmdbus,commands}.go` implement a DB-backed, long-poll command queue. Operator-issued commands (`agent.cache_flush`, `agent.set_log_level`, `cert.renew`, `agent.drain`, `agent.restart`, `agent.self_upgrade`, `agent.revoke`, `container.restart`) are inserted into `muvon.agent_commands` with HMAC-SHA256 signature + nonce + `expires_at`. The signing key is derived once at startup via HKDF over `MUVON_ENCRYPTION_KEY` — if the key is empty, the admin endpoint returns 503 and the channel stays disabled. Agents long-poll `GET /api/v1/agent/commands?wait=25s`; `CommandBus.Wake(agentID)` short-circuits the wait when a new row lands. A sweeper goroutine in `cmd/muvon/main.go` expires stale rows every 30 s. Delivery is **at-least-once**: handlers must be idempotent, and the agent-side `Registry.markSeen` keeps a 1000-entry LRU of recent command IDs to drop duplicates. Terminal state (`succeeded`/`failed`) is reported back via `POST /api/v1/agent/commands/:id/result`. When adding a new command kind: append to `CommandKind` in `internal/agentctrl/types.go`, register a handler in `cmd/agent/commands.go`, and surface it in `ui/src/components/AgentActionMenu.tsx`. **A handler must report what it did, not what it hopes will happen** — `cert.renew` used to invalidate a cache and return "next handshake will renew", which for a still-valid certificate renewed nothing while reporting success. It now renews only when due (or when nothing is cached), reports the expiry it found otherwise, and takes `force` for a deliberate early renewal. Because an agent consults the central store before its own ACME cache, a forced renewal also deletes the stored row on the central side (`DeleteCertByDomain`, audited) — without that the old certificate keeps being served no matter what the agent issues.

### System self-upgrade (helper-container pattern)
`internal/admin/handlers_system_{version,upgrade}.go` + `internal/deployer/grpcserver/upgrade.go` implement a Coolify-style one-click upgrade. `GET /api/system/version/latest` hits GHCR with an anonymous manifest HEAD (5 min cache) to surface the `:latest` digest. `POST /api/system/upgrade` calls into the deployer over gRPC (`SystemUpgrade` server-streaming RPC), which: takes the in-process mutex (409 on concurrent), normalises the target tag (strips `v` prefix), streams `pg_dump -Fc` from the postgres container straight to a file via `ContainerExecStream`, and spawns a short-lived `docker:27-cli` helper container (`RunHelperContainer` in `internal/deployer/helpers.go`) that bind-mounts the Docker socket plus `/opt/muvon` and runs: (1) `wget` the latest compose from GitHub raw, (2) `sed` `ghcr.io/.../*:latest` → `:<target_tag>`, (3) `docker compose pull muvon dialog-siem muvon-deployer`, (4) `compose up -d --no-deps --wait muvon dialog-siem`, (5) `compose up -d --no-deps --wait muvon-deployer` (LAST — the deployer is the helper's spawner; recreating it tears the gRPC stream, so we promote it after muvon is already healthy). Helper stdout/stderr is demuxed and routed via `upgradeBroker` → SSE to `GET /api/system/upgrade/stream`. When the gRPC stream EOFs (deployer was just recreated), the admin handler does NOT auto-declare success — it polls `http://127.0.0.1:9443/api/health` for up to 60 s and emits `done` only when 200 is returned. Required mounts in `docker-compose.yml`: `/var/run/docker.sock`, `/opt/muvon:/host/muvon:rw`, and the `backups` volume.

**Binary output never goes through the log demuxer.** `execAttached` (used by `ContainerExecCaptureCode` for scheduled-job logs) splits Docker's frames on newlines and trims trailing CR/LF, which is right for logs and destroys anything binary. The backup path used it until v0.1.52 and deleted every `0x0A` byte from `pg_dump -Fc`, so all 34 archives written on the central host were unrestorable while the UI reported "backup written". Use `ContainerExecStream` (`copyDockerFrames`) for any non-text payload. A requested backup that cannot be produced, header-checked and verified with `pg_restore -l` now aborts the upgrade instead of warning.

### Data engine
diaLOG relies on three PostgreSQL extensions — miss any and startup fails:
- **TimescaleDB** — hypertables for `http_logs`, `http_bodies`, `alerts`; 7-day compression. Retention starts at 30 days from the migration but is owned by the `retention_days` setting: `runRetentionReconciler` in `cmd/dialog-siem` reconciles it into the Timescale job catalog (`internal/db/retention.go`) on change and every 5 minutes, so the panel value is the truth. `0` removes the policies entirely (keep forever). Migrations only ever install the initial policy with `if_not_exists`, so never treat the interval written there as the live value; read `timescaledb_information.jobs` or `GET /api/system/retention`.
Pipeline sizing (`log_pipeline_buffer`, `log_worker_count`, `log_batch_size`, `log_flush_interval_ms`) comes from the settings table, but only at startup: resizing a live pipeline would drop what it holds. An explicitly passed flag or `DIALOG_*` env var wins over the setting, since that is the choice made at the host. The effective values are logged at boot. These four were seeded and parsed but read by nothing until v0.1.52.

- **pg_search** (ParadeDB/Tantivy) — BM25 full-text search; no Elasticsearch dependency.
- **pg_uuidv7** — UUIDv7 PKs are time-ordered, so `ORDER BY id` is chronological and no separate timestamp index is needed.

## Conventions & gotchas

- **Go module name is `muvon`** — all internal imports are `muvon/internal/...`, never rewrite as relative.
- **`CGO_ENABLED=0`** for all builds (see Makefile + Dockerfile). Do not introduce CGo dependencies without discussion — the roadmap's ONNX integration is the one planned exception.
- **Unix sockets over TCP** for inter-service IPC. Adding a new inter-service call: prefer a gRPC service in `proto/` + a `grpcclient`/`grpcserver` pair under `internal/<service>/` mirroring `logger`.
- **Fail-open behavior is load-bearing.** When adding a new dependency on diaLOG in the MUVON proxy path, the call must not block traffic on socket failure — log and continue.
- **Selective body forwarding**: bodies are only captured for POST/PUT/PATCH. Don't add body inspection to GET/HEAD/DELETE paths.
- **`frontend/dist/` is generated** by `make ui-build`; the Makefile wipes and repopulates it. Do not edit files inside it.
- The repo root has a few hefty artifacts checked in (`muvon`, `dialog-siem` binaries; `GeoLite2-City.mmdb`, `geo.tar.gz`). These are not build inputs — don't modify, and don't commit new binaries.
- CI (`.github/workflows/release.yml`) builds all four images in parallel on every push to `main` and publishes to `ghcr.io/SaidMuratOzdemir/MUVON/<service>:latest`. Tag pushes (`v*`) create GitHub Releases.

## Language note

The primary README is English + Turkish mixed (Turkish for ops sections). User-facing error strings and admin UI strings may be in either language — check neighbors before adding new text.
