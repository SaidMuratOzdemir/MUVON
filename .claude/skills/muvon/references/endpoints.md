# Endpoint inventory and response shapes

Source of truth: `internal/admin/server.go`, which registers every route. If something here is missing or looks wrong, **read the source**: `grep -n "HandleFunc" internal/admin/server.go`.

## Auth

| Method | Path | Auth | CSRF | Note |
|---|---|---|---|---|
| POST | `/api/auth/setup` | none | exempt | First install only, 409 afterwards |
| POST | `/api/auth/login` | none | exempt | Rate limited |
| POST | `/api/auth/refresh` | refresh cookie | exempt | Single-use rotation |
| POST | `/api/auth/logout` | none needed | **required** | Revokes the current refresh token, clears all three cookies, 204 |
| GET | `/api/auth/me` | access | not applicable | Current user |
| POST | `/api/auth/password` | access | **required** | Body `{current_password, new_password}`. Bumps `token_version` and revokes every refresh row, so **all other sessions end**. The caller gets fresh cookies |

Every authenticated request re-reads the user row and compares `token_version`, so a revoked session fails on its next call with 401 `session revoked`. Refreshing does not help; log in again.

## Hosts

| Method | Path | Destructive? |
|---|---|---|
| GET | `/api/hosts` | no |
| POST | `/api/hosts` | mutating |
| GET | `/api/hosts/{id}` | no |
| PUT | `/api/hosts/{id}` | mutating (a `tls_mode` change alters ACME behaviour immediately) |
| **DELETE** | **`/api/hosts/{id}`** | **destructive**, its routes are deleted with it (`ON DELETE CASCADE`) |
| GET | `/api/hosts/{id}/dns-status` | no; resolves the domain and compares it against one expected IP: central's public IP for a central host, the target agent's self-reported `public_ip` for an agent host. Statuses: `ok`, `proxied` (every answer is a Cloudflare edge), `stale`, `unresolved`, `no_target`, `error` |
| GET | `/api/hosts/{id}/tls-status` | no; certificate validity, days remaining, issuer |

`tls_mode` values: `off` (HTTP only), `redirect` (301 to HTTPS), `auto` (Let's Encrypt), `manual` (uploaded cert only). ACME challenges are **not attempted** for `off` or `manual` hosts.

## Routes

| Method | Path | Destructive? |
|---|---|---|
| GET | `/api/hosts/{id}/routes` | no |
| POST | `/api/hosts/{id}/routes` | mutating |
| GET | `/api/routes/{id}` | no |
| PUT | `/api/routes/{id}` | mutating |
| **DELETE** | **`/api/routes/{id}`** | **destructive** |

## Logs (HTTP)

| Method | Path | Note |
|---|---|---|
| GET | `/api/logs` | Filters: `host`, `path`, `method`, `client_ip`, `user`, `q` (or `search`; free text, trigram `ILIKE`), `search_bodies` (opt in to searching captured bodies), `status_min`, `status_max`, `from`, `to`, `starred`, `response_time_min`, `response_time_max`, `limit`, `offset`. **There is no `since`, `until` or `status` parameter**: times are absolute RFC3339 in `from`/`to`, and a status range needs `status_min` plus `status_max`. A `from`/`to` that is not RFC3339, and a numeric filter that is not a whole number of zero or more, are refused with 400 naming the parameter. Unknown parameters are still ignored silently, so a typo returns unfiltered results rather than an error |
| GET | `/api/logs/stats` | Aggregations. Takes `host`, `from`, `to`; the bounds follow the same RFC3339 rule and default to the last 24 hours |
| GET | `/api/logs/stream` | **SSE**, `text/event-stream`. Use EventSource or `curl -N` |
| GET | `/api/logs/{id}` | One log with bodies |
| PUT | `/api/logs/{id}/note` | Operator note |
| POST | `/api/logs/{id}/star` | Toggle star |
| GET | `/api/logs/{id}/jwt` | Raw JWT (audit-logged) |

A handy query looks like
`/api/logs?limit=20&status_min=500&from=2026-08-23T09:00:00Z`.

**Free text narrows itself when no range is given.** With `q` set and `from`
empty the server applies a default window: thirty days, or seven when
`search_bodies` is on, because a compressed chunk cannot use a trigram index
and the body branch costs far more per row. An empty result therefore does not
mean "not found"; pass an explicit `from` before concluding anything. The panel
shows which window is in force, the API does not.

**`total` is a lower bound when bodies are searched.** The response carries
`total_exact`; when it is false the body branch could not be counted to the cap
in usable time and `total` is only what the pages walked so far prove. Search
does not paginate past 10000 either way.

## Container logs

| Method | Path | Note |
|---|---|---|
| GET | `/api/containers` | Managed container list |
| GET | `/api/containers/{id}` | Detail and status |
| GET | `/api/containers/{id}/logs/stream` | SSE live tail |
| GET | `/api/container-logs` | History search (post-deploy crash analysis) |
| GET | `/api/container-logs/{id}/context` | Surrounding lines around one entry |

## Client events (RUM)

| Method | Path | Note |
|---|---|---|
| GET | `/api/client-events` | Browser telemetry search, filter by `trace_id`, `session_id`, `app`, `event_name`, cursor. Proxied to diaLOG |

The ingest side lives on the proxied host, not on the admin API: `POST /__muvon/rum`, `GET /__muvon/rum/config`, `GET /__muvon/rum.js`, all gated on the host's `rum_enabled`.

## Alerts

| Method | Path |
|---|---|
| GET | `/api/alerts` |
| GET | `/api/alerts/stats` |
| GET | `/api/alerts/{id}` |
| POST | `/api/alerts/{id}/acknowledge` (side effect: the alert is marked acknowledged, not reversible) |

## Settings

| Method | Path | Note |
|---|---|---|
| GET | `/api/settings` | A secret key (`jwt_secret`, `alerting_smtp_password`) comes back as the literal `********` when it holds a value and as `""` when it is empty, never the value itself |
| PUT | `/api/settings/{key}` | Body `{"value": ...}` with the setting's own type. **Destructive** for the secret keys in particular |

Sending `********` back for a secret key is rejected, so a masked read cannot be written over the real value by accident.

## TLS

| Method | Path |
|---|---|
| GET | `/api/tls/certificates` |
| POST | `/api/tls/certificates` (certificate override) |
| **DELETE** | **`/api/tls/certificates/{id}`** |

## System

| Method | Path | Note |
|---|---|---|
| GET | `/health` | Unauthenticated, like login, setup, refresh, logout and the deploy webhook. DB and log health. This is what `install.sh` and the upgrade flow poll on `127.0.0.1:9443` |
| GET | `/api/system/health` | Same payload, JWT required |
| GET | `/api/system/stats` | Go runtime, uptime, counters |
| GET | `/api/system/health/backends` | Backend health (managed components) |
| GET | `/api/system/health/ingest` | Log ingest pipeline state |
| GET | `/api/system/retention` | Live retention policies read from the Timescale job catalog, not from the migration |
| POST | `/api/system/reload` | **Side effect**: rehydrates the config holder and pushes over SSE to agents. A snapshot identical to the current one is a no-op |
| GET | `/api/system/version` | Running binary version: `{running, tag}` |
| GET | `/api/system/compression` | Compression window per hypertable as Timescale enforces it, plus how many chunks are already columnar |
| GET | `/api/system/version/latest` | Highest `vX.Y.Z` tag from GitHub's anonymous tags API and `update_available` from a semver comparison with the running version, 5 minute cache. The GHCR `:latest` digest is included for display only |
| POST | `/api/system/backup` | Takes a verified `pg_dump -Fc` now. While an upgrade or another backup holds the lock the call fails with 500, because the handler maps every error from the deployer to 500 |
| GET | `/api/system/backups` | Lists the dumps on disk (the last 5 are kept) |
| **POST** | **`/api/system/upgrade`** | **Destructive**, body `{target_tag, take_backup}`. A helper container runs `docker compose pull && up -d --wait`. 409 on a concurrent request |
| GET | `/api/system/upgrade/stream` | **SSE**. Each event is `event: upgrade` with a `step` of `pre_check`, `locked`, `backup`, `pull`, `post_check`, `done` or `failed`; `idle` arrives when no upgrade is running and `end` closes the stream. The deployer's stream EOFs because the helper recreates the deployer; the handler then polls `127.0.0.1:9443/health` before reporting success |

## Agents and the command channel

| Method | Path | Note |
|---|---|---|
| GET | `/api/agents` | List. The plaintext `api_key` is **not** returned, not even masked |
| POST | `/api/agents` | Create. The response `{agent, api_key}` carries the plaintext key **once** |
| **DELETE** | **`/api/agents/{id}`** | **Destructive**, the agent disconnects |
| PATCH | `/api/agents/{id}/mounts` | Update the agent's extra mounts |
| PATCH | `/api/agents/{id}/deployer-addr` | Set the address central dials for live container tail |
| **POST** | **`/api/agents/{id}/commands`** | 202 with the command row; 404 for an unknown agent, 409 `agent is disabled` for an inactive one. Body `{kind, payload, ttl_seconds}` (TTL default 300, capped at 3600) with `kind` in `agent.cache_flush` / `agent.set_log_level` / `cert.renew` / `agent.drain` / `agent.restart` / `agent.self_upgrade` / `agent.revoke` / `container.restart`. Central attaches the HMAC signature. **`agent.revoke`, `agent.restart` and `agent.self_upgrade` are destructive** (see `destructive-ops.md`) |
| GET | `/api/agents/{id}/commands` | Recent commands and state (`pending` / `dispatched` / `succeeded` / `failed` / `expired`). The UI's `AgentCommandHistory` reads this |

Command state machine: `pending → dispatched → succeeded|failed|expired`. A sweeper goroutine marks rows past their `expires_at` as `expired` every 30 seconds (default TTL 5 minutes). The signing key is derived from `MUVON_ENCRYPTION_KEY`, which the binary requires, so the channel is always armed.

## Audit

| Method | Path | Note |
|---|---|---|
| GET | `/api/audit` | `?limit=N&offset=N&action=X&from=RFC3339&to=RFC3339`. A bound that is not RFC3339 is refused with 400 rather than dropped |

**Warning**: the audit log does not currently distinguish an agent from a human admin (`admin_user: admin` for both). See the discipline section in SKILL.md.

## Deploy

| Method | Path | Note |
|---|---|---|
| GET | `/api/deploy/projects` | The project, component and instance tree |
| POST | `/api/deploy/projects` | Create an app (slug, name, source_repo, webhook_secret) |
| PUT | `/api/deploy/projects/{slug}` | App settings (name, source_repo, rotate webhook_secret) |
| **DELETE** | **`/api/deploy/projects/{slug}`** | **Destructive**, cascades to services, releases and instances |
| GET | `/api/deploy/projects/{slug}/secret` | The HMAC secret used by the webhook |
| POST | `/api/deploy/projects/{slug}/components` | Create a service (`slug`, `name`, `image_repo`, `internal_port`, `agent_id`, `env`, `env_secret_keys`, and so on) |
| GET | `/api/deploy/projects/{slug}/components/{component}` | Service detail, secret env values masked with `********` |
| PUT | `/api/deploy/projects/{slug}/components/{component}` | Update. **`agent_id` cannot be changed** (it is ignored); `paused` can |
| **DELETE** | **`/api/deploy/projects/{slug}/components/{component}`** | **Destructive**, instances drain |
| GET | `/api/deploy/deployments` | Deployment history |
| GET | `/api/deploy/deployments/{id}/events` | Lifecycle events |
| POST | `/api/deploy/deployments/{id}/rerun` | Re-run a deployment |
| **POST** | **`/api/deploy/projects/{slug}/deploy`** | **Destructive**, a new image goes to production |
| **POST** | **`/api/deploy/projects/{slug}/rollback`** | **Destructive**, queues a deployment with the previous succeeded release's image refs |
| POST | `/api/deploy/webhook` | HMAC-signed, bypasses JWT |

**Env vars and secrets.** Create and update payloads carry an `env: {KEY: value}` map plus `env_secret_keys: [KEY1, KEY2]`. Values for the listed keys are stored AES-256-GCM encrypted and come back as `********`. Sending `********` back on update keeps the stored ciphertext; to rotate a secret, send new plaintext.

**No cross-host straddle.** Every component in one deployment must share the same `agent_id`, or enqueue fails with `components straddle hosts`.

## Scheduled jobs

| Method | Path | Note |
|---|---|---|
| GET / POST | `/api/deploy/projects/{slug}/jobs` | List and create component-bound cron jobs |
| GET / PUT / DELETE | `/api/deploy/projects/{slug}/jobs/{job}` | Read, update, remove |
| POST | `/api/deploy/projects/{slug}/jobs/{job}/enable` | Enable or disable without deleting |
| POST | `/api/deploy/projects/{slug}/jobs/{job}/run` | Trigger a run now |
| GET | `/api/deploy/projects/{slug}/jobs/{job}/runs` | Run history with exit code and output tail |

A job borrows its component's image, env, secrets, networks and mounts. `exec_mode` is `run` (a fresh one-off container) or `exec` (inside the active instance). `concurrency_policy='forbid'` records a `skipped` run when a previous one is still going.

## Edge blocking

| Method | Path | Note |
|---|---|---|
| GET | `/api/security/patterns` | Path patterns with kind, score and enabled flag |
| POST | `/api/security/patterns` | Create or update a pattern |
| **DELETE** | **`/api/security/patterns`** | **Destructive**; a builtin pattern returns 409, because the next boot would restore it (disable it instead) |
| GET | `/api/security/blocks` | Currently blocked clients |
| **DELETE** | **`/api/security/blocks/{key}`** | Lifts one block |
| **POST** | **`/api/security/blocks/flush`** | Lifts every block |

## Alerting tests

| Method | Path | Note |
|---|---|---|
| POST | `/api/alerting/test/slack` | **Sends a real Slack message** |
| POST | `/api/alerting/test/smtp` | **Sends a real email** |

## Agent API (for the edge agent, not the admin)

`/api/v1/agent/...` uses `X-Api-Key: <agent-key>` instead of a JWT. It concerns the `agent` binary on edge VPSs only, and is **not part of the operator flow**. Listed here for diagnosis:

| Method | Path | Note |
|---|---|---|
| GET | `/api/v1/agent/config` | The agent pulls its config snapshot |
| GET | `/api/v1/agent/watch` | SSE, pushed when central config changes |
| GET / POST | `/api/v1/agent/cert/{domain}` | Pull a cert (operator upload) or push one (a backup of the agent's own ACME cert) |
| POST | `/api/v1/agent/blocklist` | Report a block decided on this edge; ownership comes from the authenticated agent, never the body |
| POST | `/api/v1/agent/deployer/claim` | The embedded edge deployer claims a pending deploy for its own `agent_id` |
| GET | `/api/v1/agent/deployer/plan/{id}` | The deploy plan (project, release, components) |
| POST | `/api/v1/agent/deployer/event` | Append a lifecycle event |
| POST | `/api/v1/agent/deployer/fail` | Mark the deployment failed |
| POST | `/api/v1/agent/deployer/instance` | Record a new candidate container instance |
| POST | `/api/v1/agent/deployer/instance/unhealthy` | Mark an instance unhealthy |
| POST | `/api/v1/agent/deployer/instance/stopped` | Mark an instance stopped |
| POST | `/api/v1/agent/deployer/component/drain-active` | Drain a component's active instances before a recreate |
| POST | `/api/v1/agent/deployer/promote` | Atomic promote (old active drains, candidate becomes active) |
| POST | `/api/v1/agent/deployer/reset-stale` | After a crash, return stuck `running` deployments to `pending` |
| POST | `/api/v1/agent/deployer/cleanup-warming` | Clean up warming instances left over from a finished deployment |
| GET | `/api/v1/agent/deployer/drainable` | Instances whose drain has completed |
| GET | `/api/v1/agent/deployer/live-containers` | Container IDs central still considers live (for orphan reconciliation) |
| POST | `/api/v1/agent/deployer/prunable-images` | Images the agent may remove after a promote |
| POST | `/api/v1/agent/deployer/image-id` | Record the image ID a reference resolved to at pull time |
| POST | `/api/v1/agent/deployer/job/claim` | Claim a pending scheduled job run for this agent |
| GET | `/api/v1/agent/deployer/job/{runID}` | Load a claimed run with its job and component |
| POST | `/api/v1/agent/deployer/job/finish` | Report a run's exit code and output |
| POST | `/api/v1/agent/deployer/job/reset-stale` | Return runs stuck in `running` after a crash |
| GET | `/api/v1/agent/commands?wait=25` | **Long poll** for the next signed command. `wait` is whole seconds, default 25, capped at 50. 200 with the command when one arrives, 204 when the wait ends empty |
| POST | `/api/v1/agent/commands/{id}/result` | Terminal report `{state: succeeded|failed, output?, error?, data?}`. 204 on success, 409 when the command is already finished. Delivery is at-least-once, so handlers must be idempotent |

All of these are `X-Api-Key` authenticated with an ownership filter: an agent only sees and changes rows belonging to its own `agent_id`.

## Response shapes are inconsistent, watch out

| Example endpoints | Shape |
|---|---|
| `/api/hosts`, `/api/hosts/{id}/routes`, `/api/agents`, `/api/deploy/projects` | **A bare array**: `[ {...}, {...} ]` |
| `/api/logs`, `/api/audit`, `/api/alerts`, `/api/container-logs`, `/api/containers` | **Enveloped**: `{"data":[ ... ], ...}` |
| `/api/system/stats`, `/api/system/health`, `/api/settings` | An object |
| 401/403/500 | `{"error":"..."}` |
| **404** | JSON `{"error":"..."}` for a missing resource on a registered route; **`404 page not found` as plain text** for a path no route matches |
| Resource creation (POST 201) | The created object, no envelope |

Validate the shape with `jq -e` or similar before extracting anything.

## SSE example (`/api/logs/stream`)

macOS has no `timeout`; alternatives:

```bash
# Linux:
timeout 5 curl -sS -N -b "$CJ" "$BASE/api/logs/stream?host=foo.com"

# macOS:
( curl -sS -N -b "$CJ" "$BASE/api/logs/stream?host=foo.com" & PID=$!; sleep 5; kill $PID ) 2>/dev/null

# Or, with coreutils installed:
gtimeout 5 curl ...
```

Event format is `data: {...}\n\n`. Streams are long-lived and the server clears its write timeout for them, but proxies in between may still drop an idle connection. The server sends no event IDs, so a `Last-Event-ID` header replays nothing: reconnect and accept the gap.

## Path parameters

Numeric ids (`{id}`) or slugs (`{slug}`):

```bash
muvon_api GET "/api/hosts/2/routes"
muvon_api GET "/api/deploy/projects/<slug>/components/<component>"
muvon_api GET "/api/deploy/projects/<slug>/secret"
```

No URL encoding needed, since slugs are already safe. Domain names are not ids: host endpoints are id-based.
