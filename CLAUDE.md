# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

MUVON is an edge gateway, security observability, and deploy platform composed of four independent Go services that share a single PostgreSQL 18 instance. The Go module is `muvon`, Go 1.25, Node.js 22 for the UI.

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

**Visitor location.** `country` and `city` on `http_logs` and `client_events` are stamped at the edge from Cloudflare's `CF-IPCountry` / `CF-IPCity` headers (`CloudflareLocation` in `internal/proxy/cloudflare.go`), behind the same gate as `CF-Connecting-IP`: the peer must be a Cloudflare edge and the request must carry the operator's shared secret. Any client can send those headers, so without that check a visitor could choose the country attributed to them. Hosts not behind Cloudflare carry no location, and the values require Cloudflare's "Add visitor location headers" managed transform. The local MaxMind reader (`internal/geoip`, the `geoip_*` settings, the `geoip` volume, the installer's MaxMind step) was removed in v0.2.0 in favour of this path, which needs no database to ship or refresh. There is no v0.1.53; the last v0.1 release was v0.1.52.

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
- to `:9443` **always**, plain HTTP, on every interface the process can reach. docker-compose publishes it as `127.0.0.1:9443:9443`, which is the only thing keeping it off the network; a bare-metal install has to firewall it. The listener cannot be gated on `MUVON_ADMIN_DOMAIN` because the upgrade flow polls `127.0.0.1:9443/health` to decide whether the new binary came up, and `install.sh` polls the same path.

**Sessions and revocation.** `authMiddleware` does not stop at a valid signature: it loads the user row and calls `sessionAccepted`, which requires `is_active` and an exact `token_version` match against the token's `tv` claim. That read is per request by design: a signature proves who issued the token, not that the session is still meant to work, and without the comparison a revoked session would stay valid for the remaining life of its access token. `POST /api/auth/password` is what bumps the column (and revokes the user's refresh rows), so it doubles as "sign out everywhere". If you add another way to revoke access, bump `token_version` rather than inventing a second mechanism.

### TLS certificate ownership
Renewal only works if autocert is the one asked for its own certificates: it arms a renewal timer when it serves a cert, so any source answering ahead of it takes renewal with it. A cached copy that is served on every handshake is enough to do that, which is why the resolution order below is load-bearing rather than cosmetic.

`Manager.GetCertificate` therefore resolves in this order: an operator-uploaded certificate (issuer is anything other than `letsencrypt*`) always wins; otherwise autocert answers for its own; central's copy is a backup used only when the agent has none locally, and it is seeded into the local ACME cache so autocert takes ownership from then on. `CertStore.GetOperatorCertificate` applies the same rule on central, where `PGCache.Put` mirrors ACME certs into `tls_certificates` for panel visibility. When adding a cert source, ask what arms its renewal before putting it ahead of autocert.

`runCertExpiryWatch` in `cmd/dialog-siem` alerts through the normal alerting path when a certificate is inside 14 days, which with renewal at 30 days means renewal is broken rather than merely due.

### Secrets box
`internal/secret.Box` is AES-256-GCM wrapping for settings values (SMTP password, per-host JWT secrets, etc.). Secret settings are **write-only in the API**: `GET /api/settings` returns masked placeholders. **`MUVON_ENCRYPTION_KEY` is required.** `muvon`, `dialog-siem` and `muvon-deployer` exit at startup without it, and the agent does too when `AGENT_DEPLOYER_ENABLED=true`. There is no passthrough mode: `NewBox("")` returns an error rather than a Box that stores plaintext. Keep it that way. `GET` masks secret keys unconditionally, so a Box that quietly stored plaintext would show `********` over a readable row, and a "warn and continue" branch here is invisible by construction. The key must also be stable across restarts, or values it already encrypted become unreadable (`decryptSetting` logs a warning and disables that feature rather than crashing). The same key also seeds the HKDF derivation used to sign agent commands (label `"muvon-agent-command-v1"`), so rotating it invalidates both encrypted settings and the agent command channel.

### Central → agent command channel
`internal/agentctrl` (types + HMAC + Registry + PollClient) and `internal/agentsvc/{cmdbus,commands}.go` implement a DB-backed, long-poll command queue. Operator-issued commands (`agent.cache_flush`, `agent.set_log_level`, `cert.renew`, `agent.drain`, `agent.restart`, `agent.self_upgrade`, `agent.revoke`, `container.restart`) are inserted into `muvon.agent_commands` with HMAC-SHA256 signature + nonce + `expires_at`. The signing key is derived once at startup via HKDF over `MUVON_ENCRYPTION_KEY`, which the binary requires, so the channel is always armed and a derivation failure is fatal rather than a silently disabled feature. Agents long-poll `GET /api/v1/agent/commands?wait=25s`; `CommandBus.Wake(agentID)` short-circuits the wait when a new row lands. A sweeper goroutine in `cmd/muvon/main.go` expires stale rows every 30 s. Delivery is **at-least-once**: handlers must be idempotent, and the agent-side `Registry.markSeen` keeps a 1000-entry LRU of recent command IDs to drop duplicates. Terminal state (`succeeded`/`failed`) is reported back via `POST /api/v1/agent/commands/:id/result`. When adding a new command kind: append to `CommandKind` in `internal/agentctrl/types.go`, register a handler in `cmd/agent/commands.go`, and surface it in `ui/src/components/AgentActionMenu.tsx`. **A handler must report what it did, not what it hopes will happen.** Invalidating a cache and returning "the next handshake will renew" is not a renewal report: for a still-valid certificate nothing happens. `cert.renew` renews when due (or when nothing is cached), otherwise reports the expiry it found, and takes `force` for a deliberate early renewal. Because an agent consults the central store before its own ACME cache, a forced renewal also deletes the stored row on the central side (`DeleteCertByDomain`, audited) — without that the old certificate keeps being served no matter what the agent issues.

### System self-upgrade (helper-container pattern)
`internal/admin/handlers_system_{version,upgrade}.go` + `internal/deployer/grpcserver/upgrade.go` implement a Coolify-style one-click upgrade. `GET /api/system/version/latest` hits GHCR with an anonymous manifest HEAD (5 min cache) to surface the `:latest` digest. `POST /api/system/upgrade` calls into the deployer over gRPC (`SystemUpgrade` server-streaming RPC), which: takes the in-process mutex (409 on concurrent), normalises the target tag (strips `v` prefix), streams `pg_dump -Fc` from the postgres container straight to a file via `ContainerExecStream`, and spawns a short-lived `docker:27-cli` helper container (`RunHelperContainer` in `internal/deployer/helpers.go`) that bind-mounts the Docker socket plus `/opt/muvon` and runs: (1) `wget` the latest compose from GitHub raw, (2) `sed` `ghcr.io/.../*:latest` → `:<target_tag>`, (3) `docker compose pull muvon dialog-siem muvon-deployer`, (4) `compose up -d --no-deps --wait muvon dialog-siem`, (5) `compose up -d --no-deps --wait muvon-deployer` (LAST, because the deployer is the helper's spawner: recreating it tears the gRPC stream, so we promote it after muvon is already healthy). Helper stdout/stderr is demuxed and routed via `upgradeBroker` → SSE to `GET /api/system/upgrade/stream`. When the gRPC stream EOFs (deployer was just recreated), the admin handler does NOT auto-declare success: it polls `http://127.0.0.1:9443/health` for up to 60 s and emits `done` only when 200 is returned. That path, not `/api/health`, is the auth-free one; `/api/system/health` is the JWT-gated twin. The `:9443` listener is started in every configuration, including when `MUVON_ADMIN_DOMAIN` is set, which is what makes this local poll possible; it is plain HTTP, so its containment is the compose mapping `127.0.0.1:9443:9443`. Required mounts in `docker-compose.yml`: `/var/run/docker.sock`, `/opt/muvon:/host/muvon:rw`, and the `backups` volume.

**Backups are their own capability.** `CreateBackup` / `ListBackups` on the deployer (`internal/deployer/grpcserver/backup.go`) expose the same dump path the upgrade uses, behind `POST /api/system/backup` and `GET /api/system/backups`. Until v0.2.3 the only way to get a backup was to start an upgrade, so there was no way to take one before other risky work. Both paths share `upgradeMu` because they dump the same database into the same directory, and `backupKeep` (5, matching the installer) bounds the directory so dumps cannot accumulate unnoticed. Pruning only ever touches `pgdata-*.dump`: a `.part` is an attempt in flight and a `.rejected` is the evidence of a failed verification.

**Binary output never goes through the log demuxer.** `execAttached` (used by `ContainerExecCaptureCode` for scheduled-job logs) splits Docker's frames on newlines and trims trailing CR/LF, which is right for logs and destroys anything binary: a `pg_dump -Fc` loses every `0x0A` byte and stops being restorable, while the write itself still looks successful. Use `ContainerExecStream` (`copyDockerFrames`) for any non-text payload. A requested backup that cannot be produced, header-checked and verified with `pg_restore -l` now aborts the upgrade instead of warning.

### Data engine
diaLOG relies on three PostgreSQL extensions, and startup fails if any is missing. All three belong in `public`: a bare `CREATE EXTENSION` lands in whatever schema the running service put first in its `search_path`, which is how `pg_trgm` ended up owned by `dialog` and visible to nothing else. `postgres/init.sql` creates them at database init, before any service connects, so they land in `public`; the migration that also creates `pg_trgm` finds it already there.
- **TimescaleDB** — hypertables for `http_logs`, `http_bodies`, `alerts`; 7-day compression. Retention starts at 30 days from the migration but is owned by the `retention_days` setting: `runRetentionReconciler` in `cmd/dialog-siem` reconciles it into the Timescale job catalog (`internal/db/retention.go`) on change and every 5 minutes, so the panel value is the truth. `0` removes the policies entirely (keep forever). Migrations only ever install the initial policy with `if_not_exists`, so never treat the interval written there as the live value; read `timescaledb_information.jobs` or `GET /api/system/retention`.
Pipeline sizing (`log_pipeline_buffer`, `log_worker_count`, `log_batch_size`, `log_flush_interval_ms`) comes from the settings table, but only at startup: resizing a live pipeline would drop what it holds. An explicitly passed flag or `DIALOG_*` env var wins over the setting, since that is the choice made at the host. The effective values are logged at boot, so a setting that is not reaching the pipeline is visible there.

- **pg_trgm**: trigram GIN indexes on path, host, user_agent, client_ip and `user_identity::text`, queried with `ILIKE '%term%'`. This is the whole of log search: the product does not have BM25. The body columns carry the same indexes but are searched only when the caller passes `search_bodies`, because that branch dominates the query cost.
- **pg_uuidv7** — UUIDv7 PKs are time-ordered, so `ORDER BY id` is chronological and no separate timestamp index is needed.

**pg_search and pg_cron are not part of the stack.** pg_search backed the original BM25 index, and that operator does not propagate from a TimescaleDB hypertable to its chunks, so `drop_dialog_bm25_index` moved search to pg_trgm and `drop_pg_search` removes the extension. Scheduling is Go code in `internal/scheduler`, so pg_cron has no role either. Neither is in `shared_preload_libraries`, so a `CREATE EXTENSION pg_search` added back without restoring the preload fails at startup.

## Conventions & gotchas

- **Go module name is `muvon`** — all internal imports are `muvon/internal/...`, never rewrite as relative.
- **`CGO_ENABLED=0`** for all builds (see Makefile + Dockerfile). Do not introduce CGo dependencies without discussion — the roadmap's ONNX integration is the one planned exception.
- **Services run as root, and dropping it is a release, not an edit.** The `sockets` volume is tmpfs and comes up `1777`, so a non-root uid can create `dialog.sock` there: the permission argument for root does not hold. The transition does. `cmd/dialog-siem` calls `os.Remove` on the socket path before listening, and a sticky directory only lets the owner unlink, so a non-root container meeting a root-owned socket left in a live tmpfs fails with "address already in use" and exits. `muvon` additionally binds `:80`/`:443` (needs `CAP_NET_BIND_SERVICE`) and writes ACME material to `tls_cache`, a root-owned volume; `muvon-deployer` needs the Docker socket and `/root/.docker/config.json`. Anyone changing this owns the upgrade path for existing installs, not just the compose line.
- **`go.mod` pins a `toolchain`, and the pin is a security floor.** The CI gate runs `govulncheck`, which reports against the standard library of whichever toolchain built the code, so a `go` directive alone would leave the version CI installs open to interpretation and a patched stdlib to chance. Raise the pin when a standard-library advisory lands; do not remove it. `Dockerfile` and the `Go 1.25+` line in `README.md` track the same floor.
- **Unix sockets over TCP** for inter-service IPC. Adding a new inter-service call: prefer a gRPC service in `proto/` + a `grpcclient`/`grpcserver` pair under `internal/<service>/` mirroring `logger`.
- **Fail-open behavior is load-bearing.** When adding a new dependency on diaLOG in the MUVON proxy path, the call must not block traffic on socket failure — log and continue.
- **Selective body capture**: the gate in `CaptureRequestBody` is the body itself, not the method. A request is captured when `Content-Length` is non-zero and the content type is not in the skip list (`multipart/form-data`, `application/octet-stream`, `image/`, `video/`, `audio/`, zip, gzip, pdf). GET and HEAD fall out of this naturally because they arrive without a body, but a GET or DELETE that does carry one is captured. Keep it that way: don't add a method allow-list, and don't add body inspection to paths that have no body to read.
- **`frontend/dist/` is generated** by `make ui-build`; the Makefile wipes and repopulates it. Do not edit files inside it.
- The repo root may hold leftover local artifacts (`muvon`, `dialog-siem` binaries; `GeoLite2-City.mmdb`, `geo.tar.gz`). They are gitignored, not repo content, and nothing builds from them — don't commit binaries.
- CI (`.github/workflows/release.yml`) builds all four images in parallel on every push to `main` and on every `v*` tag, publishing to `ghcr.io/saidmuratozdemir/muvon/<service>` (all three path segments lowercase; Docker rejects uppercase repository names). **A `main` push produces only `:sha-<short>` and `:main`.** `:latest`, along with `:X.Y.Z`, `:X.Y` and `:X`, is published only on a `v*` tag push, which also creates the GitHub Release. That is deliberate: `:latest` must point at the newest official release so the panel's running-vs-latest digest comparison stays meaningful.

## Language

**One language per file, no mixing.** Repository documentation is English: `README.md`, this file, `docs/` and `.claude/skills/`. Operator-facing surfaces are Turkish: the admin panel UI, installer output, and the commented sample env files (`.env.example`, `.env.agent.example`).

Code comments are English. A user-visible string follows the surface it appears on, not the language of the code around it: a panel toast is Turkish, a `slog` line or an API `error` field is English. When a doc has to quote a Turkish UI label (a sidebar entry, a button), quote it as the panel renders it and keep the surrounding prose in the file's language.
