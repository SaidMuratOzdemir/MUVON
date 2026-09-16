# Endpoint inventory and response shapes

Source of truth: `internal/admin/server.go`, which registers every route. If something here is missing or looks wrong, **read the source**: `grep -n "HandleFunc" internal/admin/server.go`.

## Auth

| Method | Path | Auth | CSRF | Note |
|---|---|---|---|---|
| POST | `/api/auth/setup` | none | exempt | First install only, 409 afterwards. Password at least 8 characters; 201 with the user and a session |
| POST | `/api/auth/login` | none | exempt | Rate limited (100 requests a minute per client IP across `/api/auth/*`, 429 beyond) |
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
| GET | `/api/hosts/{id}/dns-status` | no; resolves the domain and compares against the one expected IP: central's detected public IP for a `central` host, or the target agent's reported `public_ip` (falling back to its last remote address) for an `agent` host |
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
| GET | `/api/containers` | Managed container list, `{data, count}`. Filters: `state` (`running`/`exited`), `project`, `component`, `host_id`, `limit` |
| GET | `/api/containers/{id}` | Detail and status |
| GET | `/api/containers/{id}/logs/stream` | SSE live tail. Takes `host_id`, `tail`, `follow` (default true), `since`, and the stream selectors |
| GET | `/api/container-logs` | History search (post-deploy crash analysis). Filters: `container_id`, `container_name`, `project`, `component`, `release_id`, `deployment_id`, `host_id`, `stream`, `from`, `to`, `q`, `regex`, `before`/`after` cursors, `limit`. Returns `{data, next_before_cursor, next_after_cursor}` |
| GET | `/api/container-logs/{id}/context` | Surrounding lines around one entry, `n` per side (default 50) |

## Client events (RUM)

| Method | Path | Note |
|---|---|---|
| GET | `/api/client-events` | Browser telemetry search, filter by `trace_id`, `session_id`, `app`, `host_id`, `event_name`, `from`, `to`, the `before` cursor and `limit`. Returns `{data, next_before_cursor}`. Proxied to diaLOG |

The ingest side lives on the proxied host, not on the admin API: `POST /__muvon/rum`, `GET /__muvon/rum/config`, `GET /__muvon/rum.js`, all gated on the host's `rum_enabled`.

## Alerts

| Method | Path | Note |
|---|---|---|
| GET | `/api/alerts` | Filters: `rule`, `rule_id`, `severity` (`info`/`warning`/`high`/`critical`), `project`, `host`, `source_ip`, `fingerprint`, `acknowledged`, `is_test`, `from`/`to` on `last_seen_at`, `limit`, `offset` |
| GET | `/api/alerts/stats` | Open counts by rule and severity, test alerts excluded |
| GET | `/api/alerts/{id}` | The alert plus `deliveries`: per channel `kind`, `status` (`pending`/`sent`/`failed`/`skipped`), `attempts`, `last_error` |
| POST | `/api/alerts/{id}/acknowledge` | Closes the incident, not reversible. The next firing opens a new alert |

An alert is an incident: one open row per fingerprint, `occurrences` counts repeats, `severity` only rises. `evidence` lists the log lines it came from (`log_id`, `log_timestamp`, `container_id`, `component`, `line`, the rule's `fields`).

## Alert rules and channels

| Method | Path | Note |
|---|---|---|
| GET | `/api/alert-rules` | Builtin and event rules together |
| POST | `/api/alert-rules` | Create an event rule. Unknown JSON fields are refused |
| GET / PUT / DELETE | `/api/alert-rules/{id}` | On a builtin rule only `enabled`, `delivery`, `remind_minutes` and `channel_ids` take effect, and `channel_ids` is replaced by what is sent; deleting one is 409 |
| POST | `/api/alert-rules/{id}/test` | **Opens a test alert and notifies the rule's channels.** 202 with `{alert_id, channels}`; 400 when the rule routes nowhere |
| GET / POST | `/api/alert-channels` | Named Slack or email channels. `slack_webhook` is write-only: responses carry `has_webhook` and `webhook_host` |
| PUT / DELETE | `/api/alert-channels/{id}` | An empty `slack_webhook` keeps the stored one; `kind` cannot change |
| POST | `/api/alert-channels/{id}/test` | **Sends a real message now** and returns the sender's error on failure (502) |
| GET | `/api/alert-projects` | Every project with its default `channel_ids` |
| PUT | `/api/alert-projects/{slug}` | Replace a project's default channels, body `{channel_ids}` |
| GET | `/api/alert-events?project=<slug>&component=` | Event names and fields the project logged in the last 7 days |

Validation errors are 400 with `{"error": "...", "field": "..."}`. The rule model and the log contract are in the repository's `docs/app-events.md`.

## Settings

| Method | Path | Note |
|---|---|---|
| GET | `/api/settings` | A key/value object. The secret keys `jwt_secret` and `alerting_smtp_password` come back as the literal `********` when set, never the value |
| PUT | `/api/settings/{key}` | Body `{"value": <json>}`. Triggers a config reload. **Destructive** for secret keys in particular |

Sending `********` back for a secret key is rejected with 400, so a masked read cannot be written over the real value by accident. `MUVON_JWT_SECRET` and `MUVON_ENCRYPTION_KEY` are environment variables, not settings.

## Edge blocking

| Method | Path | Note |
|---|---|---|
| GET | `/api/security/patterns` | Every pattern, disabled and builtin rows included |
| POST | `/api/security/patterns` | Create or edit, body `{kind, pattern, score, rule, enabled, note}`. `kind` is `filename`, `segment`, `regex` or `allow`; a regex that does not compile is 400 |
| **DELETE** | **`/api/security/patterns?kind=&pattern=`** | Removes an operator pattern. A builtin one is 409: disable it instead |
| GET | `/api/security/blocks` | Addresses currently refused |
| **DELETE** | **`/api/security/blocks/{key}`** | Lifts one block and clears its penalty ladder |
| **POST** | **`/api/security/blocks/flush`** | Releases every block, returns `{released: n}` |

## TLS

| Method | Path |
|---|---|
| GET | `/api/tls/certificates` |
| POST | `/api/tls/certificates` (certificate override, body `{domain, cert_pem, key_pem}`, stored with issuer `manual`) |
| **DELETE** | **`/api/tls/certificates/{id}`** (numeric id) |

## System

| Method | Path | Note |
|---|---|---|
| GET | `/health` | **The unauthenticated health check.** DB and log health. This is what `install.sh` and the upgrade flow poll on `127.0.0.1:9443` |
| GET | `/api/system/health` | Same payload, JWT required |
| GET | `/api/system/stats` | Go runtime, uptime, counters |
| GET | `/api/system/health/backends` | Backend health (managed components) |
| GET | `/api/system/health/ingest` | Log ingest pipeline state |
| GET | `/api/system/retention` | Live retention policies read from the Timescale job catalog, not from the migration |
| POST | `/api/system/reload` | **Side effect**: rehydrates the config holder and pushes over SSE to agents. A snapshot identical to the current one is a no-op |
| GET | `/api/system/version` | `{running, tag}`: the running binary's version string and its bare tag |
| GET | `/api/system/compression` | Compression window per hypertable as Timescale enforces it, plus how many chunks are already columnar |
| GET | `/api/system/version/latest` | Highest semver tag from the GitHub tags API, `update_available` from a semver comparison with the running tag, and the image digest for display only. 5 minute cache |
| POST | `/api/system/backup` | Takes a verified `pg_dump -Fc` now. While an upgrade or another backup holds the lock it fails with 500 and `another upgrade or backup is already running`; 503 when the deployer is unreachable |
| GET | `/api/system/backups` | `{backups, keep_limit}`: the dumps on disk (the last 5 are kept) |
| **POST** | **`/api/system/upgrade`** | **Destructive**, body `{target_tag, take_backup}`. 202 with `{stream_url, target_tag}`. A helper container runs `docker compose pull` then `up -d --no-deps --wait`. 409 on a concurrent request |
| GET | `/api/system/upgrade/stream` | **SSE**. Each `upgrade` event carries `{step, level, message, timestamp, done}` with `step` in `pre_check` / `backup` / `pull` / `restart` / `post_check` / `done` / `failed`; an `idle` event means no upgrade is running and `end` closes the stream. The deployer stream EOFs because the helper recreates the deployer; the handler then polls `127.0.0.1:9443/health` for up to 60 seconds before reporting `done` |

## Agents and the command channel

| Method | Path | Note |
|---|---|---|
| GET | `/api/agents` | List. The plaintext `api_key` is **not** returned, not even masked |
| POST | `/api/agents` | Create, body `{name}`. The 201 response `{agent, api_key}` carries the plaintext key **once** |
| **DELETE** | **`/api/agents/{id}`** | **Destructive**. The key stops working and open sessions are disconnected; `deploy_components.agent_id`, `deployments.agent_id`, `hosts.target_agent_id` and `scheduled_jobs.agent_id` become NULL. 204; 404 when missing |
| **POST** | **`/api/agents/{id}/revoke`** | **Destructive**. Sets `is_active=false`, `revoked_at` and `revoked_by` (the admin username), expires pending and dispatched commands, and ends the agent's config watch stream and command long poll. Works whether or not the agent is reachable. 200 with the agent row; 404 when missing. Idempotent: revoking again keeps the original time and author. Audit `revoke_agent` |
| **POST** | **`/api/agents/{id}/rotate-key`** | **Destructive**. New random key on the same row, `is_active=true`, `revoked_at` and `revoked_by` cleared, sessions on the old key disconnected. 200 `{agent, api_key}` with the plaintext key **once**; 404 when missing. The only way back from a revocation; host, component and scheduled job bindings are kept. Audit `rotate_agent_key` |
| PATCH | `/api/agents/{id}/mounts` | Body `{extra_mounts: [...]}`. Only stores the desired list; the running agent picks it up on `agent.self_upgrade` |
| PATCH | `/api/agents/{id}/deployer-addr` | Body `{deployer_addr}`, the `host:port` central dials for live container tail; empty disables it |
| **POST** | **`/api/agents/{id}/commands`** | 202 with the command row; 404 when the agent is missing; 409 `agent is revoked` when it is inactive. Body `{kind, payload, ttl_seconds}` (TTL default 300, capped at 3600) with `kind` in `agent.cache_flush` / `agent.set_log_level` / `cert.renew` / `agent.drain` / `agent.restart` / `agent.self_upgrade` / `container.restart`; any other kind (including the removed `agent.revoke`) is 400 `unknown command kind`. Central attaches the HMAC signature. **`agent.drain`, `agent.restart` and `agent.self_upgrade` are destructive** (see `destructive-ops.md`) |
| GET | `/api/agents/{id}/commands` | Recent commands (`limit`, default 50, max 200) and state (`pending` / `dispatched` / `succeeded` / `failed` / `expired`). The UI's `AgentCommandHistory` reads this |

Command state machine: `pending → dispatched → succeeded|failed|expired`. A sweeper goroutine marks `pending` or `dispatched` rows past their `expires_at` as `expired` every 30 seconds (default TTL 5 minutes). The signing key is derived from `MUVON_ENCRYPTION_KEY`, which the binary requires, so the channel is always armed.

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
| GET | `/api/deploy/deployments` | Deployment history (`limit`) |
| GET | `/api/deploy/deployments/{id}/events` | Lifecycle events |
| POST | `/api/deploy/deployments/{id}/rerun` | Re-enqueues the original deployment's payload |
| **POST** | **`/api/deploy/projects/{slug}/deploy`** | **Destructive**, a new image goes to production. Body `{release_id, repo, branch, commit_sha, components: {<component>: {image_ref, image_digest}}}`; `release_id` falls back to `commit_sha`, and every component needs an `image_ref`. 202 with `{deployment, idempotent}` |
| **POST** | **`/api/deploy/projects/{slug}/rollback`** | **Destructive**, queues a deployment with an earlier release's image refs. Body `{from_release_id}` or `{to_release_id}`, not both (400 `from_release_id and to_release_id are mutually exclusive`). Default target: the newest succeeded release created strictly before `from_release_id` (ordered by `created_at`, then id); an empty body starts from the project's newest release. `to_release_id` redeploys exactly that release: 404 `release not found` when it does not exist, 409 `release did not succeed` when it did not succeed. 404 `release not found` for an unknown `from_release_id`, 404 `no earlier succeeded release` when nothing qualifies. 202 `{deployment, idempotent, rolled_to, new_release}` |
| POST | `/api/deploy/webhook` | Same body as a manual deploy plus `project`. HMAC-SHA256 of the raw body in `X-Muvon-Signature-256` or `X-Hub-Signature-256` (`sha256=<hex>`), bypasses JWT. 202, or 200 when idempotent |

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

## Agent API (for the edge agent, not the admin)

`/api/v1/agent/...` uses `X-Api-Key: <agent-key>` instead of a JWT. It concerns the `agent` binary on edge VPSs only, and is **not part of the operator flow**. Listed here for diagnosis:

| Method | Path | Note |
|---|---|---|
| GET | `/api/v1/agent/config` | The agent pulls its config snapshot |
| GET | `/api/v1/agent/watch` | SSE, pushed when central config changes |
| GET / POST | `/api/v1/agent/cert/{domain}` | Pull a cert (operator upload) or push one (a backup of the agent's own ACME cert) |
| POST | `/api/v1/agent/deployer/claim` | The embedded edge deployer claims a pending deploy for its own `agent_id` |
| GET | `/api/v1/agent/deployer/plan/{id}` | The deploy plan (project, release, components) |
| POST | `/api/v1/agent/deployer/event` | Append a lifecycle event |
| POST | `/api/v1/agent/deployer/fail` | Mark the deployment failed |
| POST | `/api/v1/agent/deployer/instance` | Record a new candidate container instance |
| POST | `/api/v1/agent/deployer/instance/unhealthy` | Mark an instance unhealthy |
| POST | `/api/v1/agent/deployer/instance/stopped` | Mark an instance stopped |
| POST | `/api/v1/agent/deployer/component/drain-active` | Flip a component's active instances to draining so their containers can be recreated |
| POST | `/api/v1/agent/deployer/promote` | Atomic promote (old active drains, candidate becomes active) |
| POST | `/api/v1/agent/deployer/reset-stale` | After a crash, return stuck `running` deployments to `pending` |
| POST | `/api/v1/agent/deployer/cleanup-warming` | Clean up warming instances left over from a finished deployment |
| GET | `/api/v1/agent/deployer/drainable` | Instances whose drain has completed |
| GET | `/api/v1/agent/deployer/live-containers` | Container IDs central still considers live (for orphan reconciliation) |
| POST | `/api/v1/agent/deployer/prunable-images` | Body `{component_id, keep_n}`: images the edge may remove after a promote |
| POST | `/api/v1/agent/deployer/image-id` | Body `{release_uuid, component_id, image_id}`: record the image ID a reference resolved to at pull time |
| POST | `/api/v1/agent/deployer/job/claim` | Claim the next pending scheduled job run this agent owns |
| GET | `/api/v1/agent/deployer/job/{runID}` | The run's job, bound component and image ref |
| POST | `/api/v1/agent/deployer/job/finish` | Record a run's terminal state |
| POST | `/api/v1/agent/deployer/job/reset-stale` | Body `{older_than_seconds}`: recover this agent's crash-stuck runs |
| POST | `/api/v1/agent/blocklist` | Report a block the edge decided; ownership comes from the authenticated agent, never the body |
| GET | `/api/v1/agent/commands?wait=25` | **Long poll** for the next signed command. `wait` is whole seconds (default 25, max 50). 200 with the command when one is claimed, 204 when the wait ends empty |
| POST | `/api/v1/agent/commands/{id}/result` | Terminal report `{state: succeeded|failed, output?, error?, data?}`. 204 on success, 409 when the command is already terminal. Delivery is at-least-once, so handlers must be idempotent |

All of these are `X-Api-Key` authenticated with an ownership filter: an agent only sees and changes rows belonging to its own `agent_id`.

## Response shapes are inconsistent, watch out

| Example endpoints | Shape |
|---|---|
| `/api/hosts`, `/api/hosts/{id}/routes`, `/api/agents`, `/api/deploy/projects`, `/api/alert-rules`, `/api/alert-channels`, `/api/security/patterns` | **A bare array**: `[ {...}, {...} ]` |
| `/api/logs`, `/api/audit`, `/api/alerts`, `/api/container-logs`, `/api/containers`, `/api/client-events` | **Enveloped**: `{"data":[ ... ], ...}` |
| `/api/system/stats`, `/api/system/health`, `/api/settings` | An object |
| 400/401/403/500, and 404 for a missing resource on a registered route | `{"error":"..."}` |
| **404 for an unregistered path** | **`404 page not found`** as plain text, **not JSON** (a wrong method on a registered path is likewise a plain text 405) |
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

Event format is `data: {...}\n\n`. The server lifts its 60 second write timeout for streams, but a proxy or CDN in between can still cut an idle connection, so reconnect when that happens. No event IDs are sent, so a `Last-Event-ID` header replays nothing.

## Path parameters

Numeric ids (`{id}`) or slugs (`{slug}`):

```bash
muvon_api GET "/api/hosts/2/routes"
muvon_api GET "/api/deploy/projects/<slug>/components/<component>"
muvon_api GET "/api/deploy/projects/<slug>/secret"
```

No URL encoding needed, since slugs are already safe. Domain names are not ids: host endpoints are id-based.
