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
| `DELETE /api/hosts/{id}` | Host goes, and its routes are deleted with it (`ON DELETE CASCADE`) | Re-create host and routes by hand |
| `DELETE /api/routes/{id}` | One route; the host is untouched | Re-create by hand |
| `DELETE /api/tls/certificates/{id}` | Certificate goes, HTTPS for that host breaks | With `tls_mode=auto` ACME re-issues automatically; with `manual` you re-upload |
| `DELETE /api/agents/{id}` | The edge agent record goes and the agent disconnects | Enroll again (the plaintext key is returned once) |
| `DELETE /api/deploy/projects/{slug}` | App, every service, releases and instances cascade away | Re-create by hand, env vars included |
| `DELETE /api/deploy/projects/{slug}/components/{component}` | The service goes and its instances drain | Re-create by hand with the same `agent_id`, but it gets a **new id**, so rebind every route that pointed at it |

### Deploy

| Endpoint | Effect | Rollback |
|---|---|---|
| `POST /api/deploy/projects/{slug}/deploy` | A new image reaches production | Deploy the previous tag again, or roll back |
| `POST /api/deploy/projects/{slug}/rollback` | Queues a new deployment using the **previous succeeded release's image refs** | `POST .../deploy` with the newest tag |
| `POST /api/deploy/deployments/{id}/rerun` | Re-runs a failed deploy | Same tag is redeployed, so the blast radius is small |

Before any deploy call, check:

- Is the image tag right? A typo breaks the deploy.
- Did the previous deploy succeed? (`GET /api/deploy/deployments?limit=20` and filter the result by `project_slug`; the endpoint reads only `limit`)
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
| `jwt_secret` | The global secret used to verify JWT identity signatures on logged requests. A wrong value makes that verification fail |
| `alerting_smtp_password`, `alerting_slack_webhook` | A wrong value breaks alerting silently |

`PUT /api/settings/{key}` always needs approval.

`MUVON_JWT_SECRET` (admin sessions) and `MUVON_ENCRYPTION_KEY` are environment variables in `.env`, not settings, and no API call changes them. Changing `MUVON_JWT_SECRET` ends every admin session. Changing `MUVON_ENCRYPTION_KEY` makes existing encrypted settings **and** component secret env values unreadable, and it must match the deployer's `MUVON_ENCRYPTION_KEY` and every edge's `AGENT_ENCRYPTION_KEY`, or containers stop starting.

### Certificate override

`POST /api/tls/certificates` stores the uploaded certificate for its domain with issuer `manual`, replacing the stored row for that domain. It is normally used when the operator holds a real certificate (corporate CA, wildcard).

Note the ownership order: an operator-uploaded certificate wins over autocert, autocert answers for its own, and central's copy is only a backup for an agent that has none locally. Putting anything ahead of autocert stops renewal, because autocert only arms its renewal timer for certificates it actually serves.

### System upgrade

| Endpoint | Effect | Rollback |
|---|---|---|
| `POST /api/system/upgrade` with `{target_tag, take_backup}` | The helper re-downloads the compose file, pins the image tag with `sed`, pulls and recreates `muvon`, `dialog-siem` and `muvon-deployer`; the admin panel and the proxy go down for seconds. Postgres is not recreated. With `take_backup` a `pg_dump -Fc` lands in the `backups` volume (`/var/lib/muvon/backups` inside the deployer) | Upgrade again with the previous `target_tag`, or restore the dump by hand |

Before calling:

- Read the running version with `GET /api/system/version`.
- Ask `GET /api/system/version/latest` what the newest published tag is.
- Trust `update_available` from that response, which is a semver comparison. Do not compare digests: two CI runs on one commit produce different ones, so equality proves nothing either way.
- Is `take_backup=true`? The panel's checkbox starts checked, but the API reads an omitted field as false, so send it explicitly. **Do not turn it off.**
- Is `target_tag` a tag CI actually publishes? `latest`, a release version (`0.5.2`, `0.5` or `0`, a leading `v` is stripped), `main`, or `sha-<short-commit>`. A bare commit SHA is not an image tag.
- Concurrent upgrades are refused with 409. A stream EOF is expected, because the helper container recreates the deployer itself; the handler then polls `127.0.0.1:9443/health` before declaring success.

A backup can also be taken on its own with `POST /api/system/backup`, which shares the same lock. Prefer that before any risky work rather than starting an upgrade just to get a dump.

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
| **`agent.revoke`** | **most destructive** | The agent acknowledges and exits 1. Central does not change the agent row and the key stays valid, so under the agent compose's `restart: unless-stopped` the container comes back and reconnects. `DELETE /api/agents/{id}` is what makes central reject the key | Enroll again (`POST /api/agents`); the plaintext key is returned once |

Before sending a command:

- `GET /api/agents`: is the target's `last_seen_at` fresh? Sending to an offline agent is pointless; the row expires after 5 minutes.
- `GET /api/agents/{id}/commands`: what was sent recently? Avoid duplicate drains or restart spam.
- Delivery is at-least-once and handlers are idempotent, but do not send `restart` or `revoke` more than once: it confuses the user and pollutes the history.

## Medium danger, inform the user and get a yes

| Endpoint | Effect |
|---|---|
| `POST /api/alerts/{id}/acknowledge` | Not reversible, but only UI state |
| `POST /api/system/reload` | Side effect: an SSE push to agents |
| `POST /api/alerting/test/slack` | **Sends a real Slack message** into the channel |
| `POST /api/alerting/test/smtp` | **Sends a real email** into someone's inbox |
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
AGENT_ACTION: PUT /api/routes/3: log_enabled true → false
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
