# Diagnostic patterns for common scenarios

So that "we have a problem with X" has a starting point.

## 1) "A host is throwing 5xx, the error rate went up"

```
1. Ask for the time window (last N minutes or hours).
2. GET /api/logs?host=<x>&status=500&since=<N>&limit=20
   → collect the top error paths.
3. GET /api/logs/{id} → look at the response body (the backend's own message).
4. GET /api/deploy/deployments?slug=<component>&limit=5 → was there a deploy inside
   that window? If so, the deploy is the prime suspect; offer a rollback.
5. GET /api/system/health → is MUVON itself healthy?
6. With SSH: docker logs <container> --since=<N> → the backend stack trace.
7. Report the findings in about five lines.
```

**Typical findings**:

- 502 **while containers are healthy and instances are active**: the route binding may be gone. If a component was recently deleted and re-created (a host move), `routes.managed_component_id` fell to `NULL`. Check the route before hunting the backend; see `pitfalls.md`.
- 502: the backend is down (a managed component crashed). `GET /api/containers` shows `exited` or `restarting`.
- 503: the backend is healthy but overloaded. Check rate limit settings.
- 504: backend timeout. The route's `timeout_seconds` may be too small.
- Generic 500: internal to the backend. Read the app log.

## 2) "The deploy failed" or "the deploy is stuck pending"

```
1. GET /api/deploy/deployments?limit=3 → the latest id, status and agent_id.
2. GET /api/deploy/deployments/<id>/events → lifecycle events. Which step stopped:
   pull, migration, candidate start, health check or promote?
3. Still pending? Check agent_id.
   - agent_id == "" (central): is muvon-deployer running? docker compose ps.
   - agent_id == "<id>": is that agent alive (GET /api/agents → last_seen_at)?
     Is AGENT_DEPLOYER_ENABLED=true? Is AGENT_DOCKER_SOCKET reachable?
4. With SSH: docker logs <new-container> → did the app fail to start?
5. Stuck at migration: GET /api/container-logs?container=<migration-container>
6. Health check failing: does the backend's /health return 200 from inside?
   ssh <alias> "docker exec <container> wget -qO- localhost:<port>/health"
7. A "decrypt env ... for component ..." event means the encryption keys differ.
   Central muvon, muvon-deployer and the edge agent's AGENT_ENCRYPTION_KEY must match.
```

**Typical findings**:

- Image pull failed: registry auth. Check that `/root/.docker/config.json` is mounted.
- Migration container exited 1: the migration script is broken, or the DB connection is wrong.
- Health check timeout: slow app startup against a short health window.
- Promote succeeded but no traffic arrives: the route's `managed_component_id` points elsewhere.
- "Components straddle hosts": one app's services sit on different `agent_id`s. Move them together.
- "Component X is paused": clear it with `PUT /api/deploy/projects/<slug>/components/<x>` and `{"paused":false}`.
- Deployment does not leave pending and no container appears on the edge: that agent has `AGENT_DEPLOYER_ENABLED=false`, or the Docker socket is unreachable. The agent log says `deployer: enabled but docker socket unreachable; staying disabled`.

## 3) "An edge agent disconnected"

The agent is **not a systemd service**; it runs under docker compose. The install directory is usually `/opt/muvon-agent/` (`docker-compose.agent.yml` plus `.env`), and the container is `muvon-agent-agent-1`.

```
1. GET /api/agents → last_seen_at and last_remote_addr. Which are stale?
2. SSH to the agent host:
   ssh <agent-host> "docker compose -f /opt/muvon-agent/docker-compose.agent.yml ps"
3. Agent log:
   ssh <agent-host> "docker logs muvon-agent-agent-1 --tail 200"
4. Connection test (agent auth uses X-Api-Key, not Bearer):
   ssh <agent-host> "curl -sf -o /dev/null -w '%{http_code} %{remote_ip}\n' \
     https://<central-domain>/api/v1/agent/config -H 'X-Api-Key: <agent-api-key>'"
   → does remote_ip come out on the path you expect (private or public)?
5. Was the agent disabled? In muvon.agents:
   SELECT name, is_active, last_seen_at, last_remote_addr FROM muvon.agents;
```

**Typical findings**:

- The container crashed or never started: `docker ps -a` shows `Created` or `Exited`.
- `agents.is_active=false` (revoked): it must be enrolled again; the agent fails auth and exits.
- Network: firewall, DNS or TLS certificate trouble.
- The agent is an older build; the fleet is not necessarily uniform (see `pitfalls.md`).
- The agent exits at startup complaining about `AGENT_ENCRYPTION_KEY`: with the embedded deployer enabled, the key is required and missing it is fatal by design.

**If `last_remote_addr` is an address you did not expect**, look at which path the agent takes to central. A common setup resolves the central domain to an internal address through `/etc/hosts`; without that line, traffic leaves through the public interface and central sees the public address. That is a routing difference, not a fault, but it does make hosts inconsistent:

```bash
ssh <agent-host> "grep <central-domain> /etc/hosts || echo 'no private override'"
ssh <agent-host> "getent hosts <central-domain>"
```

## 4) "TLS certificate trouble"

Triage with the two status endpoints first:

- `GET /api/hosts/{id}/dns-status`: does the A record resolve to the expected IP?
  - `unresolved`: DNS has not propagated, or the user never added the record.
  - `stale`: DNS points at the wrong IP (often the old host).
  - `no_target`: central could not detect its own public IP and there is no agent either. There is no `public_ip` setting to edit; central detects it at startup, and `MUVON_PUBLIC_IP` pins it when detection is unwanted.
  - `wildcard`: a `*.example.com` host; verify per subdomain.
- `GET /api/hosts/{id}/tls-status`: valid, expiring, expired, missing or off.

Scenarios:

- "Certificate expiring": `tls-status` shows a small `days_left`. `GET /api/tls/certificates` for the full list. Note that renewal is due at 30 days, so anything still standing at 14 days means renewal is broken, not merely due.
- "No certificate on a new host": check DNS status first, then `tls_mode`. ACME is never attempted for `off` or `manual`. For `auto`:
  ```bash
  dig +short <host>
  curl -fsSL --max-time 5 ifconfig.me   # the MUVON server's IP
  ```
  If they differ, the user needs to fix DNS.
- ACME challenge failures: mind Let's Encrypt rate limits.
- "There is a certificate but the browser says invalid": check for a missing chain via `GET /api/tls/certificates`.
- Edge host TLS: on a host with `agent_id` set, the agent issues the certificate through ACME and pushes a backup to central. If the agent is down, no new certificate arrives.

Ownership order matters when diagnosing renewal: an operator-uploaded certificate wins, then autocert, and central's copy is only a backup for an agent with nothing local. Anything answering ahead of autocert silently disables renewal, because autocert arms its renewal timer only for certificates it actually serves.

## 5) "Container log shipping is not working"

```
1. GET /api/system/health/ingest → pipeline state.
2. GET /api/containers/<id>/logs/stream → does SSE work?
3. SSH: ls -la /var/lib/muvon/logship/ → is the spool filling up?
4. docker logs muvon-deployer --tail=200 | grep logship
5. Is the dialog-siem container healthy? docker compose ps
```

**Typical findings**:

- diaLOG is down, so the spool accumulates. Bring diaLOG back.
- The spool budget was exceeded and the oldest container's lines were dropped (`MUVON_DEPLOYER_LOGSHIP_SPOOL_MAX_BYTES`).
- Log shipping is disabled: `MUVON_DEPLOYER_LOGSHIP_ENABLED=false` in `.env`.

## 6) "No alerts, nothing in Slack"

```
1. GET /api/settings → is alerting_enabled true?
2. GET /api/alerts?limit=5 → are alerts being produced at all?
3. POST /api/alerting/test/slack → a manual test, after the user approves
4. dialog-siem log: docker logs dialog-siem | grep alert
5. Cooldown: the same fingerprint is skipped within alerting_cooldown_seconds (default 300).
```

## 7) "A setting changed but nothing happened"

Either `POST /api/system/reload` was never called, or the snapshot is unchanged. When in doubt:

```bash
curl -sS -b "$CJ" -H "X-CSRF-Token: $CSRF" -X POST "$BASE/api/system/reload"
```

Then confirm with `GET /api/system/stats` that uptime did not reset: a reload refreshes the snapshot, it does not restart the process. Note that a reload whose snapshot is byte-identical to the current one is a deliberate no-op and fires no callbacks, so "nothing happened" can also mean "nothing actually differs".

## 8) "Unusual traffic, possibly an attack"

```
1. GET /api/logs?status=403&since=15m → a 403 spike?
2. GET /api/alerts → any auth_brute_force or error_spike alerts?
3. /api/logs?q=.env or /api/logs?path=.env → bot scanning
4. Top talkers straight from the DB (with SSH):
   SELECT client_ip, count(*) FROM dialog.http_logs
   WHERE timestamp > now() - interval '15 minutes'
   GROUP BY client_ip ORDER BY 2 DESC LIMIT 20;
5. If an IP stands out, suggest a firewall rule or a route-level block to the user.
```

**Worth noticing**: bots scan for `/app/.env`, `/.git/config`, `/wp-admin`, `/phpmyadmin` and similar. If any of those return **200**, the backend is exposing them. MUVON does not block that, since it is a legitimate route; tell the user.

## 9) "Something is wrong with a customer application (a managed component)"

This skill knows MUVON, **not the customer's application internals**. The flow:

```
1. /api/containers → component status (running, restarting, exited)
2. /api/container-logs?component=<x>&limit=20 → application log
3. With SSH and the user's approval: docker exec <container> /bin/sh
4. The customer repo URL: /api/deploy/projects/<slug> → source_repo
   Read and grep it locally if it is cloned, otherwise gh repo clone.
```

## 10) "MUVON is down, the admin panel will not open"

```
1. SSH: docker compose -f /opt/muvon/docker-compose.yml ps
   → what is the muvon container's status?
2. docker compose logs muvon --tail=100
3. Can /api/system/health be reached from outside over HTTPS?
4. Is Postgres reachable? docker exec muvon-postgres pg_isready
5. Is the disk full? df -h
```

**Typical findings**:

- The DB volume filled up: retention never ran; clean up manually.
- Postgres was OOM-killed: watch memory with docker stats.
- Wrong TLS cache path: check the `tls_cache` volume mount.
- A config holder panic: `docker logs muvon | grep -i panic`.
- The container exits immediately after an update with a message about `MUVON_JWT_SECRET` or `MUVON_ENCRYPTION_KEY`: both are required and have no defaults. `install.sh` generates them; a hand-rolled `.env` may be missing one.

## 11) "I sent a command but the agent did not run it"

```
1. GET /api/agents/{id}/commands → what state is the last command in?
   - pending: the agent has not claimed it (is the long poll open? is last_seen_at fresh?)
   - dispatched: claimed but no result reported (the handler blocked, or the agent crashed)
   - failed: what does result.error say?
   - expired: the sweeper cleaned it up (default TTL 5 minutes) because the agent never claimed it.
2. GET /api/agents → is the target's last_seen_at fresh? Sending to an offline agent is pointless.
3. SSH to the agent: docker logs muvon-agent-agent-1 --tail=200 | grep -E 'command|poll'
   - "poll: no commands" is a normal idle long poll.
   - "poll: signature mismatch" means MUVON_ENCRYPTION_KEY and AGENT_ENCRYPTION_KEY differ.
   - "command expired" means the TTL ran out before the agent claimed it.
   - "command dedupe" means the same ID was delivered twice, which is expected under
     at-least-once delivery and harmless.
```

**Typical findings**:

- The agent was revoked and needs re-enrolling; it fails auth and exits.
- `AGENT_ENCRYPTION_KEY` does not match central, so every command fails with `signature mismatch`. Set both sides to the same value.
- The agent lost its Docker socket, so `agent.restart` and `container.restart` fail quietly (see `pitfalls.md`).
- `agent.set_log_level` was sent with a very short `payload.ttl_seconds`, so debug logging reverted before anything useful was captured. Send it again with a longer TTL.

## 12) "The system upgrade hung, or the SSE stream dropped"

```
1. A 409 from POST /api/system/upgrade means one is already running (the mutex).
   GET /api/system/upgrade/stream joins the existing stream and replays history.
2. After the stream EOFs, the admin handler polls /health for 60 seconds:
   - "post_check: deployer stream closed, waiting for muvon..." → normal, wait
   - "done: upgrade verified — muvon healthy on new image" → success
   - "failed: muvon did not become healthy within 60s" → the recreate failed, investigate
3. On a failed event, over SSH:
   ssh <central> "docker compose -f /opt/muvon/docker-compose.yml ps"
   → are the services "Up"? "Restarting" means the healthcheck is failing.
4. Find the helper container: ssh <central> "docker ps -a --filter ancestor=docker:27-cli"
   → take the most recent exited one and read its script output with docker logs <id>.
5. Migration failure (a new binary against an old schema): docker compose logs muvon | grep migration.
6. Backups: ssh <central> "ls -lt /opt/muvon/backups/ | head -5"
7. Worst case: edit the compose file by hand (pin the old tag) and docker compose up -d --wait,
   or restore from the pg_dump (see the README's backup and restore section).
```

**Typical findings**:

- `pg_dump` did not finish in time on a large database. A standalone `POST /api/system/backup` is the better path there, and it verifies the dump with `pg_restore -l` before accepting it.
- The helper container failed auth during `docker compose pull`: the `/root/.docker/config.json` mount is missing from the `muvon-deployer` service.
- The new image's migration failed, so the old binary stopped and the new one exits during migration. `/health` returns nothing; connect to postgres and inspect the last applied migration.
- The version endpoint returns 503: the deployer is down (`docker compose ps`).

## 13) "Client IPs in the logs are wrong, always the same private address"

Symptom: `dialog.http_logs.client_ip`, or the application's own audit record, shows one private address instead of the real visitor. That address is usually **the edge container's IP**. It is a silent failure: traffic flows, only the record is wrong, which is why it survives for months.

There are two separate layers. Do not conflate them:

```
1. The edge (MUVON) layer: what reaches the SIEM?
   SELECT client_ip, count(*) FROM dialog.http_logs
   WHERE timestamp > now() - interval '1 hour' GROUP BY 1 ORDER BY 2 DESC LIMIT 10;
   - One private address dominating means the edge's own trust configuration is off:
     the host's trusted_proxies list (GET /api/hosts) and Cloudflare trust
     (is MUVON_CLOUDFLARE_IP_SECRET / AGENT_CLOUDFLARE_IP_SECRET set?).
   - Behind a CDN with no secret set, the edge treats the CDN's address as the client.

2. The application layer: what does the backend see?
   Even when the edge passes the right address, an application that does not trust it
   records the edge's IP instead. docs/client-ip.md is the contract.
   ssh <agent-host> "docker exec <app-container> env | grep -iE 'forwarded|trusted|real_ip'"
   ssh <agent-host> "docker inspect <app-container> --format '{{json .Config.Cmd}}'"
   → a command-line flag overrides the environment, so check both.
```

**Typical findings**:

- The application has no client-IP handling at all, so every recorded address is the edge's.
- It has one, but pointing at a **stale address**: the edge container's IP changes when it is recreated. `MUVON_EDGE_IP` is injected per deployment for exactly this reason; a hardcoded address stops matching silently.
- The application enables its server's own forwarded-header handling. Behind a CDN this is worse than nothing: those implementations walk the `X-Forwarded-For` chain and pick the rightmost untrusted entry, which is the CDN edge, so the CDN gets recorded as the visitor. The contract is to read `X-Real-IP` gated on `MUVON_EDGE_IP` instead.
- An SSR or ISR frontend fetches its own public domain server-side. Those requests come back through the edge with no real user behind them and pollute the SIEM with NAT addresses. Fix: point server-side fetches at the internal container address (`SERVER_API_URL=http://<component-slug>:<port>`) and leave the client on the public URL.

## General tips

- **Start with a narrow window** (the last 15 minutes). Slow queries and huge responses waste everyone's time.
- **No more than five endpoint calls before stopping to think.** Collect, reason, then continue.
- Report every finding **with its source**: "GET /api/logs?status=500&since=1h → 47 rows, top path /api/auth".
- When you meet a field you do not recognise: `Read internal/db/migrations.go` and grep.
- Stay honest about uncertainty: report to the user, propose an action, and **let them approve it**.
