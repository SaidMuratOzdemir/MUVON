# Access paths outside the API

When an API error is vague, an endpoint does not exist, or a **deep diagnosis** is needed: read the database directly, read the source. These are **optional**. Without SSH access, the API is enough.

## 1) Reaching the remote machine over SSH

This skill does not manage SSH. It assumes the user's `~/.ssh/config` already works. Check:

```bash
ssh -o BatchMode=yes -o ConnectTimeout=3 <alias> "true" 2>&1
```

Exit 0 means the alias is ready. On error, ask: "How do you ssh to the MUVON server? Which alias?"

## 2) Reading the database directly, READ ONLY

On the production VPS:

```bash
ssh <alias> "docker exec muvon-postgres psql -U muvon -d muvon -tAc \"<SELECT>\""
```

`-tA` gives tuples-only, unaligned output, which is easy to parse.

### Schemas

- **`muvon.*`**, admin and edge state:
  - `hosts` (`tls_mode`: off/redirect/auto/manual, `force_https`, `trusted_proxies`, per-host JWT identity settings). **`target_kind`** (`central` or `agent`) plus **`target_agent_id`** answer "which domain is served where": the domain itself binds to an agent, not just its components. In some installations every host is on the edge and central carries no traffic at all.
  - `routes` (can bind to a component through `managed_component_id`)
  - `agents` (`api_key_hash`)
  - `tls_certificates` (issuer: `manual`, `letsencrypt`, `letsencrypt:agent:<id>`)
  - `settings`, `acme_cache`, `admin_users`, `admin_refresh_tokens`, `admin_audit_log`
  - `deploy_projects`, `deploy_components` (`agent_id` nullable, `paused`, `env` JSONB, `env_secret_keys` text[], `keep_releases`)
  - `deploy_releases`, `deploy_release_components`, `deploy_instances` (`spec_hash`)
  - `deployments` (`agent_id` nullable: null means central, set means an edge agent)
  - `deployment_events`
  - `agent_commands` (UUIDv7 PK, `agent_id`, `kind`, `payload` JSONB, `signature`, `nonce`, `state`, `result` JSONB, `expires_at`, `dispatched_at`, `finished_at`)
  - `scheduled_jobs`, `scheduled_job_runs` (component-bound periodic work: cron `next_run_at`, `concurrency_policy`, run history with exit code and output tail)
- **`dialog.*`**, the SIEM: `http_logs`, `http_log_bodies`, `alerts`, `container_logs`, `containers`, `client_events` (browser RUM, joined to `http_logs` by `trace_id` and `session_id`).

### Useful queries

```sql
-- Which service runs where (central vs edge agent)?
SELECT p.slug AS project, c.slug AS component,
       COALESCE(a.name, 'central') AS host,
       c.paused, array_length(c.env_secret_keys, 1) AS secret_count
FROM muvon.deploy_components c
JOIN muvon.deploy_projects p ON p.id = c.project_id
LEFT JOIN muvon.agents a ON a.id = c.agent_id;

-- Which domain is served where (hosts bind to agents too)?
SELECT COALESCE(a.name, '(central)') AS location, h.target_kind, count(*) AS host_count
FROM muvon.hosts h
LEFT JOIN muvon.agents a ON a.id = h.target_agent_id
GROUP BY 1, 2 ORDER BY 3 DESC;

-- Fleet inventory: agents, when last seen, where they connected from
SELECT name, is_active, last_seen_at, last_remote_addr, config_version
FROM muvon.agents ORDER BY name;

-- Client IP health: a dominant private or single address means the trust
-- configuration is missing somewhere
SELECT client_ip, count(*) FROM dialog.http_logs
WHERE timestamp > now() - interval '1 hour'
GROUP BY 1 ORDER BY 2 DESC LIMIT 10;

-- Top 5xx paths in the last hour
SELECT host, path, count(*)
FROM dialog.http_logs
WHERE response_status >= 500
  AND timestamp > now() - interval '1 hour'
GROUP BY host, path ORDER BY 3 DESC LIMIT 10;

-- Most rate-limited IPs
SELECT client_ip, count(*)
FROM dialog.http_logs
WHERE response_status = 429
  AND timestamp > now() - interval '24 hours'
GROUP BY client_ip ORDER BY 2 DESC LIMIT 10;

-- Recent deployments, including which host ran them
SELECT d.id, p.slug AS project, d.release_id, d.trigger,
       COALESCE(a.name, 'central') AS host,
       d.status, d.started_at, d.finished_at
FROM muvon.deployments d
JOIN muvon.deploy_projects p ON p.id = d.project_id
LEFT JOIN muvon.agents a ON a.id = d.agent_id
ORDER BY d.created_at DESC LIMIT 5;

-- Hot endpoints over the last N minutes
SELECT host, path, count(*), percentile_cont(0.95) WITHIN GROUP (ORDER BY response_time_ms)
FROM dialog.http_logs
WHERE timestamp > now() - interval '15 minutes'
GROUP BY host, path ORDER BY 3 DESC LIMIT 20;

-- Where commands are stuck in the queue
SELECT c.id, a.name AS agent, c.kind, c.state,
       c.created_at, c.dispatched_at, c.finished_at,
       c.expires_at,
       (c.result->>'error') AS err
FROM muvon.agent_commands c
JOIN muvon.agents a ON a.id = c.agent_id
WHERE c.created_at > now() - interval '1 hour'
ORDER BY c.created_at DESC LIMIT 50;

-- Recent command history for one agent
SELECT kind, state, created_at, finished_at,
       coalesce(result->>'output', result->>'error', '') AS detail
FROM muvon.agent_commands
WHERE agent_id = '<agent-uuid>'
ORDER BY created_at DESC LIMIT 20;

-- Commands left pending (not yet expired by the sweeper, not yet claimed)
SELECT a.name, count(*)
FROM muvon.agent_commands c
JOIN muvon.agents a ON a.id = c.agent_id
WHERE c.state = 'pending' AND c.created_at < now() - interval '1 minute'
GROUP BY a.name ORDER BY 2 DESC;
```

### Never write to the database

A direct write bypasses the API layer:

- It does not reach the audit log.
- It skips the secret box, so secrets stay plaintext.
- The config holder does not rehydrate, so the new value never takes effect.

Database writes always go **through the API**.

## 3) Reading files: config and compose

```bash
ssh <alias> "cat /opt/muvon/.env"
ssh <alias> "cat /opt/muvon/docker-compose.yml"
ssh <alias> "docker compose -f /opt/muvon/docker-compose.yml ps"
ssh <alias> "docker compose -f /opt/muvon/docker-compose.yml logs --tail=200 muvon"
```

Inside `/opt/muvon/.env`:

- `POSTGRES_PASSWORD`: secret
- `MUVON_JWT_SECRET`: secret, required, at least 32 characters, no default. muvon refuses to start without it
- `MUVON_ENCRYPTION_KEY`: secret, required. muvon, dialog-siem and muvon-deployer all refuse to start without it, and it must match the edge agents' `AGENT_ENCRYPTION_KEY`. Losing it means encrypted settings and component secret env values become unreadable
- `MUVON_ADMIN_DOMAIN`, `LOG_LEVEL`: not secret

On an edge agent host the install directory is usually **`/opt/muvon-agent/`**, holding `docker-compose.agent.yml` and `.env`. The agent is not a systemd service; it runs under compose (container name `muvon-agent-agent-1`):

```bash
ssh <agent-host> "docker compose -f /opt/muvon-agent/docker-compose.agent.yml ps"
ssh <agent-host> "docker logs muvon-agent-agent-1 --tail 200"
```

Typical keys in that `.env`:

- `AGENT_API_KEY`: secret
- `AGENT_ENCRYPTION_KEY`: secret, must equal central's `MUVON_ENCRYPTION_KEY`. Required when `AGENT_DEPLOYER_ENABLED=true`, and the agent exits at startup without it
- `AGENT_CLOUDFLARE_IP_SECRET` and `AGENT_CLOUDFLARE_IP_HEADER`: one secret, one not. They enable trust in a CDN's client-IP header; empty means CDN headers are not believed
- `AGENT_CENTRAL_URL`, `AGENT_LOG_ADDR`: not secret. Where central and diaLOG are reached. The central URL is the admin domain over HTTPS, without a port: `:9443` is plain HTTP and compose binds it to loopback
- `AGENT_DEPLOYER_ENABLED`, `AGENT_DEPLOYER_POLL_MS`, `AGENT_DEPLOYER_TCP_LISTEN`: not secret. `AGENT_DEPLOYER_TCP_BIND` is a compose-level variable for the host-side port mapping, while `AGENT_DEPLOYER_TCP_LISTEN` is what the binary reads. Binding to an internal address is preferred over listening on all interfaces
- `AGENT_DOCKERWATCH_ENABLED`, `AGENT_DOCKERWATCH_MANAGED_ONLY`: not secret
- `AGENT_PUBLIC_IP`, `AGENT_HOST_ID`, `AGENT_EXTRA_MOUNTS`, `MUVON_AGENT_DIR`: not secret

The agent container's bind mounts: the Docker socket (rw, for the embedded deployer), the registry auth file (ro), the operator's env file directory (ro, usually `/opt/envfiles`), plus the `tls_cache`, `logship` and `config_cache` named volumes.

A component's env comes from two places, and **the component env map wins over the env file**: the file named by `env_file_path` (in the directory mounted read-only into the agent) and `deploy_components.env` JSONB. When tracing where a value came from, check both.

**Never echo a secret.** Check only whether it is set:

```bash
ssh <alias> "test -n \"\$(grep ^MUVON_JWT_SECRET /opt/muvon/.env | cut -d= -f2-)\" && echo 'set' || echo 'empty'"
```

## 4) Container logs through Docker

If container log shipping (`muvon-deployer logship`) is down, or you need to go further back:

```bash
ssh <alias> "docker logs <container-name> --tail 200 --timestamps"
ssh <alias> "docker logs <container-name> --since 1h"
```

Normally container logs live in `dialog.container_logs` and are reachable from the API (`/api/container-logs`).

## 5) Reading MUVON source

The production binary carries no source. Find it here:

### (a) The user's local repo

Ask the user where the repo is checked out rather than guessing a path. If the session is already running inside it:

```bash
git rev-parse --show-toplevel 2>/dev/null
```

With a path in hand, use `Read` and `Grep` directly.

### (b) GitHub raw (assuming the repo is public)

```bash
# One file:
curl -s https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/internal/admin/server.go | less

# Directory listing:
gh api repos/SaidMuratOzdemir/MUVON/contents/internal/admin?ref=main | jq -r '.[].name'

# File content, base64 decoded:
gh api repos/SaidMuratOzdemir/MUVON/contents/internal/admin/server.go?ref=main | jq -r '.content' | base64 -d
```

A private repo needs `gh auth login`.

### (c) Which version is running?

```bash
ssh <alias> "docker compose -f /opt/muvon/docker-compose.yml ps --format json" | jq -r '.[] | "\(.Service): \(.Image)"'
```

If the image carries a tag (`:v1.2.3` or a commit hash), fetch raw files at that ref. With `:latest`, check main's HEAD, remembering that `:latest` moves only on a `v*` tag push.

## 6) Fast paths into endpoint source

```bash
# Every route:
grep -nE 'HandleFunc\("(GET|POST|PUT|DELETE)' internal/admin/server.go

# A specific handler:
grep -rn 'handleSearchLogs' internal/admin/

# Migrations:
less internal/db/migrations.go
```

## 7) Data that exists in the DB but not in the API

Some tables have no admin API surface. Query the DB directly, and read the schema before interpreting it:

```bash
ssh <alias> "docker exec muvon-postgres psql -U muvon -d muvon -c '\d+ muvon.deployment_events'"
```

## 8) Running MUVON locally to try something

```bash
cd <path-to-clone>
cp .env.example .env
# Fill in .env (POSTGRES_PASSWORD, MUVON_JWT_SECRET, MUVON_ENCRYPTION_KEY and
# MUVON_ADMIN_DOMAIN are all required; compose refuses to start otherwise), then:
docker compose up -d
# Admin panel: http://127.0.0.1:9443 (compose publishes it on loopback only)
```

First admin: `POST http://127.0.0.1:9443/api/auth/setup`. After that, the skill's normal flow applies.

## Choosing a path

```
Need                              → First choice      → Fallback
──────────────────────────────────────────────────────────────────────
read state / list / detail        → API GET           → DB SELECT (if SSH)
log search                        → API /api/logs     → DB dialog.http_logs
audit log                         → API /api/audit    → DB muvon.admin_audit_log
is a secret set?                  → /opt/muvon/.env (set/empty)  → -
live container log                → API SSE stream    → ssh + docker logs -f
managed component image           → API /api/containers → docker compose ps
endpoint not found                → read the source   → -
auth/CSRF/middleware internals    → internal/admin/*.go  → -
deploy lifecycle internals        → internal/deployer/*.go → -
```

Note that `GET /api/settings` cannot answer "is this secret set": it returns `********` for every secret key regardless. Check the `.env` file instead.
