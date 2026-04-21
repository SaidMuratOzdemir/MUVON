# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

MUVON is an edge gateway, security, and deploy platform composed of five independent Go services that share a single PostgreSQL 18 instance. The Go module is `muvon`, Go 1.24, Node.js 22 for the UI.

| Binary (`cmd/`) | Role |
|---|---|
| `muvon` | Central edge gateway — terminates TLS, routes by host+path prefix, runs admin panel, owns the `muvon` DB schema. |
| `muwaf` | WAF engine — gRPC Unix socket, pattern matching across 14 attack categories, owns the `muwaf` schema. |
| `dialog-siem` | SIEM engine — gRPC (Unix + TCP), async log pipeline with PostgreSQL `COPY FROM`, correlation engine, alerting. Owns the `dialog` schema. |
| `muvon-deployer` | Separate worker that owns the Docker socket. Polls DB for pending deploy jobs. Isolates Docker access from the proxy. |
| `agent` | Lightweight edge binary for client servers — no DB, pulls config from central MUVON via HTTP + SSE, ships logs to central diaLOG over TCP gRPC. |

The five services talk via gRPC over Unix domain sockets (or TCP for agent → central diaLOG). MUVON is **fail-open**: if muWAF or diaLOG is down, traffic still flows — WAF checks are skipped and logs are dropped.

## Common commands

```bash
# Dependencies
make deps          # go mod tidy + download
make ui-install    # cd ui && npm install

# Build — all five services (builds UI first, copies to frontend/dist for go:embed)
make build                  # native
make build-linux            # linux/amd64 cross-compile → build/*-linux-amd64
make build-minimal          # only muvon + agent (no WAF/SIEM/deployer)
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
make deploy-all             # muvon + muwaf
```

The Makefile `deploy` targets `scp` to an SSH host alias `vps` and `docker cp` into running containers — do not assume they work in arbitrary environments.

## Architecture essentials

### Single module, schema-isolated database
All services import from the same `muvon` Go module but each one only touches its own PostgreSQL schema (`muvon`, `muwaf`, `dialog`). Migrations live in `internal/db/migrations.go` as a single ordered slice; each migration has a `product` field (`"muvon"`, `"muwaf"`, `"dialog"`, or `""` for shared). `DB.RunMigrations` filters by the schema passed to `db.New(ctx, dsn, schema)` so a given service only applies its own (plus shared) migrations. `schema_migrations` table tracks applied names. **When adding a migration, always append to the slice — never reorder, never edit applied migrations.**

### Config holder and hot reload
`internal/config` defines a `Source` interface with two implementations:
- `DBSource` — used by central MUVON (reads `hosts`, `routes`, `settings`, managed backends from PostgreSQL).
- `AgentSource` — used by the `agent` binary (fetches from central via `/api/v1/agent/config` and subscribes to `/api/v1/agent/watch` SSE).

`config.Holder` wraps atomic.Value snapshots. Everything read-hot (proxy, router, WAF, logger) reads through the holder. `POST /api/system/reload` triggers reload and also pushes SSE updates to all connected agents. When touching config shape, update both `config.go` (struct) and the corresponding source loader.

### Proxy pipeline (`internal/proxy`)
Per request: resolve host → match route by longest path prefix → if `waf_enabled`, pre-check via `wafclient` (body forwarded only for POST/PUT/PATCH) → proxy/static/redirect/accel → if `log_enabled`, async-ship log entry to diaLOG via `logclient`. `accel.go` handles both `X-Accel-Redirect` (backend sets header) and pre-signed serve (`?token=<hmac>&expires=<unix>` where token is `HMAC-SHA256(secret, path+":"+expires)`).

### Managed deploy
Routes can bind to a managed component. The proxy selects only `active` instances (never warming/draining). The deploy lifecycle — image pull → migration container → candidate start → health check → atomic promote (old `active` → `draining`, candidate → `active`) → graceful drain — runs in `muvon-deployer`, which polls the DB and is the only service with Docker socket access. Deploy webhook (`POST /api/deploy/webhook`) uses HMAC-SHA256 and bypasses JWT.

### Admin panel + API
React 19 + Vite 8 + shadcn/ui in `ui/`. Built SPA is copied to `frontend/dist/` and embedded into the `muvon` binary via `//go:embed frontend/dist` in `embed.go` (package name is `dialog` for historical reasons). The admin HTTP server serves both `/api/*` and the SPA. WAF/Log endpoints are transparent gRPC proxies to muWAF/diaLOG — if the socket is unavailable, handlers return a structured 503 and the UI shows a service-offline banner.

Admin panel binds:
- to `:443` on `MUVON_ADMIN_DOMAIN` when set (production).
- to `:9443` (local-only in docker-compose) when not set — used for initial setup before a TLS cert exists.

### Secrets box
`internal/secret.Box` is AES-256-GCM wrapping for settings values (JWT secret, SMTP password, etc.). Secret settings are **write-only in the API** — `GET /api/settings` returns masked placeholders. `MUVON_ENCRYPTION_KEY` must be stable across restarts or encrypted settings become unreadable (`decryptSetting` logs a warning and disables the feature rather than crashing).

### Data engine
diaLOG relies on three PostgreSQL extensions — miss any and startup fails:
- **TimescaleDB** — hypertables for `http_logs`, `http_bodies`, `alerts`, WAF events; 7-day compression + 30-day retention.
- **pg_search** (ParadeDB/Tantivy) — BM25 full-text search; no Elasticsearch dependency.
- **pg_uuidv7** — UUIDv7 PKs are time-ordered, so `ORDER BY id` is chronological and no separate timestamp index is needed.

## Conventions & gotchas

- **Go module name is `muvon`** — all internal imports are `muvon/internal/...`, never rewrite as relative.
- **`CGO_ENABLED=0`** for all builds (see Makefile + Dockerfile). Do not introduce CGo dependencies without discussion — the roadmap's ONNX integration is the one planned exception.
- **Unix sockets over TCP** for inter-service IPC. Adding a new inter-service call: prefer a gRPC service in `proto/` + a `grpcclient`/`grpcserver` pair under `internal/<service>/` mirroring `waf` and `logger`.
- **Fail-open behavior is load-bearing.** When adding a new dependency on muWAF or diaLOG in the MUVON proxy path, the call must not block traffic on socket failure — log and continue.
- **Selective body forwarding**: bodies are only captured/forwarded for POST/PUT/PATCH. Don't add body inspection to GET/HEAD/DELETE paths.
- **`frontend/dist/` is generated** by `make ui-build`; the Makefile wipes and repopulates it. Do not edit files inside it.
- The repo root has a few hefty artifacts checked in (`muvon`, `muwaf`, `dialog-siem` binaries; `GeoLite2-City.mmdb`, `geo.tar.gz`). These are not build inputs — don't modify, and don't commit new binaries.
- CI (`.github/workflows/release.yml`) builds all four images in parallel on every push to `main` and publishes to `ghcr.io/SaidMuratOzdemir/MUVON/<service>:latest`. Tag pushes (`v*`) create GitHub Releases.

## Language note

The primary README is English + Turkish mixed (Turkish for ops sections). User-facing error strings and admin UI strings may be in either language — check neighbors before adding new text.
