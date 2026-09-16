# Destructive endpoints and the confirmation protocol

The audit log cannot currently tell an agent apart from a human. While that is true, discipline around destructive operations is **the agent's responsibility**.

## Confirmation protocol, before every destructive call

1. **Gather context**: which resource (id, slug, domain), what changes, is there a way back?
2. **Print an AGENT_ACTION stamp** to stdout, where the user sees it in the transcript:
   ```
   AGENT_ACTION: DELETE /api/hosts/12
   AGENT_ACTION: domain=foo.com (3 active routes attached)
   AGENT_ACTION: rollback path: re-create host + routes by hand
   ```
3. **Ask for explicit approval**:
   > "Shall I perform this destructive operation? (yes/no)"
4. **Do not act** until the user says yes. Half-approvals like "I think so", "ok", "maybe" do not count.
5. Afterwards: make the call, summarise the result, and confirm it landed in the audit log (`GET /api/audit?limit=1`).

## High danger, never without approval

### Deletion

| Endpoint | Effect | Rollback |
|---|---|---|
| `DELETE /api/hosts/{id}` | Host goes, and its routes go with it (DB cascade) | Re-create host and routes by hand |
| `DELETE /api/routes/{id}` | One route; the host is untouched | Re-create by hand |
| `DELETE /api/tls/certificates/{id}` | Certificate goes, HTTPS for that host breaks | With `tls_mode=auto` ACME re-issues automatically; with `manual` you re-upload |
| `DELETE /api/agents/{id}` | The edge agent record goes, its key stops working and its open sessions are disconnected. `deploy_components.agent_id`, `deployments.agent_id`, `hosts.target_agent_id` and `scheduled_jobs.agent_id` become NULL, so those rows lose their host binding | Enroll again (the plaintext key is returned once) and rebind hosts, components and jobs by hand. To cut an agent off without losing bindings, revoke instead (below) |
| `DELETE /api/deploy/projects/{slug}` | App, every service, releases and instances cascade away | Re-create by hand, env vars included |
| `DELETE /api/deploy/projects/{slug}/components/{component}` | The service goes and its instances drain | Re-create by hand with the same `agent_id`, but it gets a **new id**, so rebind every route that pointed at it |

### Deploy

| Endpoint | Effect | Rollback |
|---|---|---|
| `POST /api/deploy/projects/{slug}/deploy` | A new image reaches production | Deploy the previous tag again, or roll back |
| `POST /api/deploy/projects/{slug}/rollback` | Queues a new deployment with the image refs of the **newest succeeded release created before `from_release_id`** (the project's newest release when the body is empty), or of exactly `to_release_id` when that is given | `POST .../deploy` with the newest tag, or roll back with `to_release_id` naming the release you left |
| `POST /api/deploy/deployments/{id}/rerun` | Re-runs a failed deploy | Same tag is redeployed, so the blast radius is small |

Before any deploy call, check:

- Is the image tag right? A typo breaks the deploy.
- Did the previous deploy succeed? (`GET /api/deploy/deployments?limit=20`, filtered by `project_slug`; the endpoint takes only `limit`)
- Is there a migration? (`GET /api/deploy/projects/<slug>`, look at each component's `migration_command`)
- Is the service `paused`? Paused services are rejected at enqueue time; clear it first with `PUT .../components/<x>`.
- Is the component's `agent_id` right, and if it is on the edge, is that agent running with `AGENT_DEPLOYER_ENABLED=true`? (check `last_seen_at` in `GET /api/agents`)

### Pause and resume (mutating, be careful)

| Endpoint | Effect |
|---|---|
| `PUT /api/deploy/projects/{slug}/components/{component}` with `{"paused":true}` | The service's instances start draining and **new deploys are rejected at enqueue** |
| `PUT /api/deploy/projects/{slug}/components/{component}` with `{"paused":false}` | The service can be deployed again, but existing instances do not come back on their own: a new deploy is required |

### Settings, especially the secret ones

| Key | Danger |
|---|---|
| `alerting_smtp_password` | A wrong value makes every email channel fail; each delivery then records the SMTP error |
| `jwt_secret` | The global secret for `verify`-mode JWT identity; a wrong value stops identity extraction on hosts that rely on it |
| `retention_days`, `compression_days`, `compression_bodies_days` | Lowering `retention_days` makes the Timescale job drop older chunks on its next run; that data is gone |
| `security_blocking_enabled`, `security_block_*` | Turning blocking on or lowering the threshold can refuse legitimate clients with 403 |

`PUT /api/settings/{key}` always needs approval.

`MUVON_JWT_SECRET`, `MUVON_ENCRYPTION_KEY` and `MUVON_PUBLIC_IP` are **not** settings: they live in `/opt/muvon/.env` and no API writes them. Changing `MUVON_JWT_SECRET` signs everyone out. Changing `MUVON_ENCRYPTION_KEY` makes encrypted settings, alert channel webhooks **and** component secret env values unreadable, invalidates the agent command channel, and must be matched by every edge's `AGENT_ENCRYPTION_KEY`, or containers stop starting. Both are host edits plus a restart and need the same approval.

### Certificate override

`POST /api/tls/certificates` stores the certificate with issuer `manual` and takes over serving from the automatic one. The ACME row for the same domain is not deleted; it stays in `tls_certificates` next to it. It is normally used when the operator holds a real certificate (corporate CA, wildcard).

Note the ownership order: an operator-uploaded certificate wins over autocert, autocert answers for its own, and central's copy is only a backup for an agent that has none locally. Putting anything ahead of autocert stops renewal, because autocert only arms its renewal timer for certificates it actually serves.

### System upgrade

| Endpoint | Effect | Rollback |
|---|---|---|
| `POST /api/system/upgrade` with `{target_tag, take_backup}` | `muvon`, `dialog-siem` and `muvon-deployer` are recreated with new images (Postgres is not touched); the admin panel and the proxy go down for seconds. The compose file is re-downloaded and pinned to the tag. A `pg_dump -Fc` lands in the `backups` volume (`GET /api/system/backups`) | Upgrade again with the previous `target_tag`, or restore the dump by hand |

Before calling:

- Read the running version with `GET /api/system/version`.
- Ask `GET /api/system/version/latest` what the newest published tag is.
- Trust `update_available` from that response, which is a semver comparison. Do not compare digests: two CI runs on one commit produce different ones, so equality proves nothing either way.
- Send `take_backup: true` explicitly. The panel's checkbox starts checked, but the API reads an omitted field as `false`. **Do not turn it off.** A backup that cannot be produced and verified aborts the upgrade.
- Is `target_tag` a published image tag? A leading `v` is stripped and empty means `latest`. Valid shapes: `latest`, `X`, `X.Y`, `X.Y.Z` (from `v*` tags), `main`, or `sha-<short>`. A bare commit SHA is not a tag, so the pull fails.
- Concurrent upgrades are refused with 409. A stream EOF is expected, because the helper container recreates the deployer itself; the handler then polls `127.0.0.1:9443/health` before declaring success.

A backup can also be taken on its own with `POST /api/system/backup`, which shares the same lock. Prefer that before any risky work rather than starting an upgrade just to get a dump. Each new dump prunes the directory to the newest 5, so older dumps are deleted.

Switching the Postgres image (see `pitfalls.md` #47) is a manual host operation outside this API. It needs approval, a fresh verified backup, and a clean `docker compose stop -t 120 postgres` before the rebuild.

### Agent commands (central to edge)

`POST /api/agents/{id}/commands` carries every `kind` through one API, but **the risk profile differs per kind**.

| `kind` | Risk | Effect | Rollback |
|---|---|---|---|
| `agent.cache_flush` | low | Clears the local cache | None needed; the next request refills it |
| `agent.set_log_level` | low | Changes the log level for `payload.ttl_seconds`, then reverts | Wait for the TTL or send a new level |
| `cert.renew` | medium | Renews when the certificate is actually due, or reports the expiry it found. Takes `force` for a deliberate early renewal, which also deletes central's stored copy | ACME retries; mind Let's Encrypt rate limits |
| `container.restart` | medium | Restarts the named agent-side container | It comes back |
| **`agent.drain`** with `{enabled:true}` | **destructive by intent** | The command reports `drain enabled` and stores a flag, but in this version nothing on the request path reads that flag, so traffic is **not** refused. Do not rely on it to take an edge out of rotation | Send `{enabled:false}` |
| **`agent.restart`** | **destructive** | The agent binary exits 0 and the supervisor (systemd or the Docker restart policy) brings it back | Automatic; no manual step |
| **`agent.self_upgrade`** | **destructive** | Image refresh and container recreate, seconds of downtime | If the new image is broken, deploy the previous tag manually |
There is no `agent.revoke` kind: sending it returns 400 `unknown command kind`. A command to a revoked agent returns 409 `agent is revoked`.

Before sending a command:

- `GET /api/agents`: is the target's `last_seen_at` fresh? Sending to an offline agent is pointless; the row expires after 5 minutes.
- `GET /api/agents/{id}/commands`: what was sent recently? Avoid duplicate drains or restart spam.
- Delivery is at-least-once and handlers are idempotent, but do not send `restart` or `self_upgrade` more than once: it confuses the user and pollutes the history.

### Agent key revocation and rotation

Both are central state changes and take effect whether or not the agent is reachable. See `pitfalls.md` #35.

| Endpoint | Risk | Effect | Rollback |
|---|---|---|---|
| **`POST /api/agents/{id}/revoke`** | **most destructive** | Sets `is_active=false` with `revoked_at` and `revoked_by`, expires the agent's pending and dispatched commands and disconnects its config stream and command poll. The agent API answers the key with 401 `agent revoked` and dialog-siem refuses it, so config updates, log shipping, deploys and commands stop. The edge keeps serving traffic from its last config. Idempotent; audited as `revoke_agent` | No way to re-enable the key. Rotate the key and restart the agent with it |
| **`POST /api/agents/{id}/rotate-key`** | **destructive** | Issues a new key on the same row, sets `is_active=true`, clears `revoked_at` and `revoked_by`, and disconnects sessions using the old key. The old key stops working at once, so a running agent loses central until it is restarted with the new key. Returns `{agent, api_key}` with the plaintext key once; bindings are kept. Audited as `rotate_agent_key` | None for the old key. Deliver the new key to the agent's `AGENT_API_KEY` and restart it |

Before either call, confirm the agent id and name with `GET /api/agents`, and make sure whoever will restart the agent is ready to receive the new key, which cannot be read again.

## Medium danger, inform the user and get a yes

| Endpoint | Effect |
|---|---|
| `POST /api/alerts/{id}/acknowledge` | Not reversible. Closes the incident and stops its reminders; the next firing opens a new alert and notifies again |
| `POST /api/system/reload` | Side effect: an SSE push to agents |
| `POST /api/alert-channels/{id}/test` | **Sends a real Slack message or email** to that channel |
| `POST /api/alert-rules/{id}/test` | **Opens a test alert and notifies every channel the rule routes to** |
| `PUT /api/alert-rules/{id}`, `PUT /api/alert-projects/{slug}` | Changes where, and whether, incidents are notified |
| `DELETE /api/alert-rules/{id}` | An event rule and its routing go; its application events stop raising alerts |
| `DELETE /api/alert-channels/{id}` | The channel and every route to it go. An event rule left without channels falls back to its project's defaults; a builtin rule records without notifying |
| `POST /api/security/blocks/flush`, `DELETE /api/security/blocks/{key}` | Lifts edge blocks; a scanner that was refused gets through again |
| `POST /api/security/patterns`, `DELETE /api/security/patterns` | Changes what edge blocking scores |
| `POST /api/deploy/projects/{slug}/jobs/{job}/run` | Runs the scheduled job now, against production data |
| `DELETE /api/deploy/projects/{slug}/jobs/{job}` | The job and its run history go |
| `POST /api/logs/{id}/star` | A UI marker only |
| `PUT /api/logs/{id}/note` | An operator note, for reading context |

## Low danger, informing is enough

| Endpoint | Effect |
|---|---|
| `POST /api/hosts` | Creates a host, purely additive |
| `POST /api/hosts/{id}/routes` | Adds a route |
| `PUT /api/hosts/{id}`, `PUT /api/routes/{id}` | Update (report the previous value) |

Even so, **read the current value before a PUT** and show the user what changes:
```
AGENT_ACTION: PUT /api/routes/3, log_enabled: true → false
```

## One more "never": writing to the DB directly

Even with SSH access, **do not** run `INSERT`, `UPDATE` or `DELETE` against the database:

- It does not reach the audit log.
- It skips the secret box, so encrypted fields land as plaintext and the API cannot read them back.
- It does not trigger a config holder reload, so the new value never takes effect.
- A foreign key violation can break the compose stack.

The database is **read-only** for this skill (`references/alternate-access.md`).

## No dry run, so pre-validate by hand

The MUVON API has no dry-run or preview mode. Before a destructive call:

- Read the target resource (a GET for detail).
- List the sub-resources it affects.
- Summarise for the user and get approval.

For example, before deleting a host:

```bash
muvon_api GET "/api/hosts/12"                # detail
muvon_api GET "/api/hosts/12/routes"         # attached routes
# stdout:
#   AGENT_ACTION: DELETE /api/hosts/12 (foo.com)
#   - its 3 routes go too (DB cascade, so nothing is orphaned)
#   - the TLS cert stays (delete it separately: DELETE /api/tls/certificates/<id>)
#   Shall I continue?
```

## Wrap-up checklist

After a destructive operation:

1. **Check the HTTP code** (200/201 means done; 400/500 gets reported as-is).
2. **Confirm the audit entry** (`GET /api/audit?limit=1`: does the last row match the AGENT_ACTION?).
3. **Service health**: is `GET /api/system/health` fine?
4. **The affected area**: after a deploy, watch `GET /api/deploy/deployments?limit=1`.
5. Keep the summary to about three lines; the user scans it.
