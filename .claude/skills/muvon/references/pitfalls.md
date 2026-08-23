# Surprises and traps: where an agent gets stuck

This list came out of **real probing**. Knowing each trap up front saves wasted cycles on the first attempt.

## 1) There is **no** Bearer header support

The comment in `internal/admin/middleware.go` is explicit: cookie-only, the old `Authorization: Bearer` path is gone.

Wrong: `curl -H "Authorization: Bearer <token>" ...` always returns **401**.
Right: the cookie jar flow in `references/auth.md`.

## 2) Refresh tokens are **single use** (rotation)

Every `POST /api/auth/refresh` sets new cookies. Always update the jar with `-c`. Using the same refresh token twice returns 401 and clears every cookie with `Max-Age=0`, so you must log in again.

Observed in practice:

```
POST /api/auth/refresh   (first call)                 → 200, new cookies
POST /api/auth/refresh   (second call, same token)    → 401 + cleared cookies
```

## 3) 404 is **plain text**, not JSON

`curl ... /api/this-does-not-exist` returns the body `404 page not found`. Other errors (401, 403, 500) are JSON. Branch on the status code or `Content-Type` before parsing.

## 4) The response envelope is **inconsistent**

```
/api/hosts           → [...]              # bare array
/api/logs            → {"data": [...]}    # enveloped
/api/system/stats    → {...}              # object
```

Assuming `response.data` breaks on hosts; assuming `response[0]` breaks on logs. Confirm the shape per endpoint in `references/endpoints.md`.

## 5) Secret masking is the literal `********`

`GET /api/settings` returns `"********"` for every secret key, whether or not a value is set. It is **not** an empty string, and it does not tell you whether the secret exists.

Consequences:

- You cannot verify "is this secret still set?" through the API. To answer that, read `/opt/muvon/.env` over SSH and report only set or empty.
- Writing `********` back is rejected, so a masked read cannot overwrite the real value by accident.

Treat settings writes as set-and-forget.

## 6) The audit log **does not distinguish agent from human**

`/api/audit` shows `admin_user: admin` for both. Nothing in the audit says "an agent triggered this deploy".

Discipline: print an **AGENT_ACTION** line to stdout before every destructive call (see SKILL.md). The user reading the transcript fills in what the audit log cannot.

## 7) The access cookie lasts only **15 minutes**

`__Host-muvon_access` has `Max-Age=899`. Long scripts outlive it. Use the `muvon_api()` wrapper in `references/auth.md`, which refreshes on a 401.

## 8) The `__Host-` cookie prefix

The cookie is named `__Host-muvon_access`, with a leading double underscore and a hyphen. Mind the quoting in bash:

```bash
# fine
awk '$6 == "__Host-muvon_access" {print $7}' cookies.txt
# curl handles it automatically; no manual header needed
```

## 9) macOS has no `timeout`

`timeout 5 curl ...` is `command not found` on macOS, which matters for SSE tests:

```bash
( curl & sleep 5; kill $! ) 2>/dev/null    # POSIX, works everywhere
gtimeout 5 curl ...                        # if coreutils is installed
```

## 10) `POST /api/deploy/webhook` bypasses JWT

It skips admin auth and is authenticated by an HMAC-SHA256 signature in `X-Muvon-Signature-256`. An agent normally does not touch it: calling it triggers a deploy. `POST /api/deploy/projects/{slug}/deploy` is the right API.

## 11) `POST /api/system/reload` is harmless but not side-effect free

It does not disturb proxy traffic, but it does push over SSE to connected edge agents, and it is required after any change made outside the API. Handlers already call the holder's reload themselves, so an agent does not need to call it after an API write. A reload whose snapshot matches the current one is a deliberate no-op.

## 12) Login is rate limited

`POST /api/auth/login` sits behind a rate limiter. On a 429, wait a few seconds and retry.

## 13) `POST /api/alerting/test/*` **sends a real message**

Even the test path reaches the outside world: a Slack channel, someone's inbox. Never call it without explicit approval.

## 14) Logout **requires CSRF**

Login is exempt; logout is not. Without the header you get 403. Neither is `POST /api/auth/password` exempt.

## 15) SSE endpoints return `text/event-stream`

`curl -sS` piped into `jq` will fail. Read with `curl -N` and parse manually.

## 16) `__Host-` prefixed cookies confuse some tooling

Bash and curl are fine. Some older libraries (Python's `http.cookiejar`, for instance) mishandle the prefix during attribute parsing. Worth remembering in another language.

## 17) Settings values are typed

```json
"alerting_enabled": false,
"correlation_anomaly_enabled": true,
```

Those are real booleans, while `alerting_smtp_port: 587` is a number and others are strings. `PUT /api/settings/{key}` always takes `{"value": ...}`; preserve the type.

## 18) The `force_https` host field

`force_https: true` in `/api/hosts` means that host 301-redirects HTTP to HTTPS. Test with `https://` or you will chase redirects.

## 19) `trusted_proxies` defaults to an empty array

An empty list means `X-Forwarded-For` is not believed and `RemoteAddr` is used. Behind a CDN or load balancer, the real client IP comes only from peers listed here (or through the separate Cloudflare secret gate).

## 20) `jwt_identity_enabled` is per host

Each host toggles JWT identity extraction independently. `jwt_identity_mode` is `verify` (check the signature, which needs the secret) or decode-only enrichment. The log's `identity` field is populated from that. Decode-only claims are observational and must not be used for authorisation.

## 21) The agent API key is **no longer in the list response**

`GET /api/agents` does not return `api_key`, because it is stored SHA-256 hashed. The plaintext key comes back **once**, in the create response: `POST /api/agents` → `{"agent": {...}, "api_key": "abc123..."}`. Show it to the user and then treat it as gone. If the operator loses it, enroll a new agent.

The legacy plaintext `api_key` column still exists in the table for migration purposes. The auth middleware fills in the hash on the first successful call, which is transparent to the user.

## 22) A host with `tls_mode=off` does **not** serve :443

With `hosts.tls_mode='off'`, MUVON neither terminates HTTPS for that host nor attempts an ACME challenge. A browser using HTTPS gets a certificate error. Test with `http://`, or switch the mode to `auto`.

## 23) A component's `agent_id` is **fixed**

It is chosen at creation (NULL means central, a value means that edge agent) and cannot be changed afterwards: `PUT /api/deploy/projects/{slug}/components/{component}` ignores the field. Changing it would leave an orphan container on the old host. To move a component: delete it and re-create it, re-entering everything including env and mounts.

## 24) Cross-host straddle is **rejected**

If two services of one app sit on different `agent_id`s, enqueue fails with `enqueue deployment: components straddle hosts`. Keep all of an app's services on one host: all central, or all on the same agent.

## 25) `paused` really stops the service

`PUT .../components/<x>` with `{"paused": true}`:

- New deploy attempts (webhook, manual, rollback) are **rejected** with `component X is paused; resume it before deploying`.
- The component's **active instances are moved to draining**. The owning deployer stops and removes the containers on its next tick, and the proxy cuts traffic immediately, because only `active` instances are routed. Pause is a real stop, not just a deploy lock.

The field is read from both PUT and POST bodies as a pointer, so omitting it preserves the current value.

**Resume** with `{"paused": false}` allows deploys again but does **not** bring the instance back, since pausing drained it. Getting it running takes a deploy: `POST .../rollback` for the last succeeded release, or a CI webhook or manual deploy.

Stopping no longer requires DELETE. DELETE removes the component permanently, taking its spec with it, while pause keeps the configuration and only stops the running.

## 26) `MUVON_ENCRYPTION_KEY` and `AGENT_ENCRYPTION_KEY` **must match**

Component secret env values are stored AES-256-GCM encrypted and decrypted by the deployer at container start. Three places need the same key:

| Binary | Env var |
|---|---|
| `muvon` (central admin) | `MUVON_ENCRYPTION_KEY` |
| `muvon-deployer` | `MUVON_ENCRYPTION_KEY` |
| `agent` (edge, with the deployer enabled) | `AGENT_ENCRYPTION_KEY` |

Change one and forget the others and encrypted env cannot be decrypted, so the container never starts. Symptom: a deployment goes `running` then `failed`, with an event reading `decrypt env <KEY> for component <slug>: ...`.

## 27) The embedded edge deployer needs the Docker socket

With `AGENT_DEPLOYER_ENABLED=true` but an unreachable `AGENT_DOCKER_SOCKET`, the deployer **stays silently disabled** and logs `deployer: enabled but docker socket unreachable; staying disabled`. The agent keeps doing everything else, but components assigned to it never deploy. Operator symptom: the deployment hangs in `pending`.

Note the contrast with the encryption key, which is fatal rather than silent: with the deployer enabled and `AGENT_ENCRYPTION_KEY` empty, the agent exits at startup with a clear message.

## 28) A `no_target` DNS status

`GET /api/hosts/{id}/dns-status` returns `status: "no_target"` when central could not determine its own public address and no agent is registered either.

There is **no `public_ip` row in `settings`** to fix this with. Central detects its address at startup and `MUVON_PUBLIC_IP` (or `-public-ip`) pins it. The `public_ip` column that does exist belongs to `muvon.agents` and is what each agent self-reports about itself.

## 29) `MUVON_ENCRYPTION_KEY` also derives the agent command HMAC key

The signing key is `HKDF(MUVON_ENCRYPTION_KEY, label="muvon-agent-command-v1")`.

The key is **required for the binary to start at all**, so there is no "key missing, channel quietly disabled" state to diagnose any more. What remains true is that rotating it breaks things: every `pending` and `dispatched` command fails signature verification at the agent, and everything the old key encrypted becomes unreadable. The key must be genuinely stable.

## 30) Command delivery is **at-least-once**

Handlers in `cmd/agent/commands.go` are written to be idempotent, and `Registry.markSeen` (an LRU of 1000 entries) drops a repeated ID. Operator-side care is still needed:

- Sending the same command twice from the UI creates two rows with different UUIDv7s. The dedup only protects against the **same ID** being delivered twice.
- Do not send destructive commands such as `agent.restart` or `agent.revoke` more than once: the history gets noisy and the supervisor's behaviour starts to look like a restart loop.

## 31) Concurrent system upgrades are blocked with 409

A process-wide mutex allows one upgrade at a time, so a second `POST /api/system/upgrade` gets 409. The SSE stream replays event history for late joiners, so a UI that connects mid-upgrade does not miss the beginning.

The helper container recreates services in stages (muvon and dialog-siem first, muvon-deployer last), because the deployer is the helper's own spawner. The admin handler does not treat the resulting stream EOF as success: it polls `127.0.0.1:9443/health` for 60 seconds and emits `failed` if health never returns.

## 32) A very low `keep_releases` closes the rollback path

`deploy_components.keep_releases` (default 3) keeps the images of the last N succeeded releases on the host. **Drop it to 1 and a rollback may fail at image pull**: the old tag can be re-pulled from a public registry, but a private one can fail auth. The upper bound is 50, and 10 or more large images (over 1 GB) fills a disk quickly.

Practical guidance:

- Production: 3 (current plus two rollback targets).
- Large images and frequent deploys: 2 (only the previous one is kept; disk wins).
- Development: 1 (each promote deletes the last).

In the UI: `ComponentEditorDialog`, the "Gelişmiş" tab, "Tutulan release sayısı". A DB CHECK enforces at least 1.

## 33) A 409 during image prune is a deliberate no-op

`pruneImagesAfterPromote` calls `docker rmi` per image ref. If a container still uses it, Docker returns 409 and the code swallows it as success without logging. That is correct: Docker's refcount catches a case the SQL `in_use` filter cannot, such as another component sharing the same image. Symptom: you expected an image to disappear and it is still there. Check `docker ps -a --filter ancestor=<ref>`.

## 34) Orphan reconciliation uses `ContainerListAll(all=1)`

It used to list running containers only, so exited orphans (a failed migration, a crashed candidate) were invisible. Now every state is scanned, which means **any container labelled `muvon.managed=true` that the DB does not know about** is stopped and force-removed, whatever its state. Hand-running `docker run` with that label means it disappears on the next tick.

## 35) `agent.revoke` is a clean shutdown, not a crash loop

`POST /api/agents/{id}/commands` with `{"kind":"agent.revoke"}` stops the agent permanently:

1. Central sets `agents.is_active=false`.
2. The command reaches the agent and its handler exits 1.
3. If a supervisor restarts it, central rejects its auth and it exits immediately. It looks like a crash loop, and that is the expected shape.

To undo: enroll a new agent (`POST /api/agents`) and delete the old record (`DELETE /api/agents/{id}`). The plaintext key is returned once.

## 36) Docker subnets and the agent's container IP **differ per installation**

An agent host typically has two networks: the agent's shared proxy network (`muvon-agent_default`) and the application's DB network. Docker assigns subnets **in creation order**. If the application's DB compose came up first, it takes `172.18.0.0/16` and the agent network becomes `172.19.0.0/16`; the other way round if the order was reversed. Two installations of the same product can differ.

Consequences:

- **Never write a fixed subnet or a fixed agent IP** into an install template, a documentation example or an application's env. What is right on one host is silently wrong on another.
- Pinning with `ipv4_address` requires declaring the network with an explicit `ipam.config.subnet`, which assumes that subnet is free on every host; if another network took it, creation conflicts.
- The agent's last octet tends to be `.2` in practice, being the first container compose creates, but that is not a guarantee: if a deploy lands between the agent being removed and recreated, a new application container takes the freed address.

The right approach is to learn the address **at runtime** (`docker network inspect <network>`) rather than baking it into configuration.

## 37) The real client IP is **silently wrong** unless the application does its part

MUVON writes two headers on every proxied request: `X-Real-IP` carries the client address the edge resolved, and `X-Forwarded-For` carries the hop chain. The application behind it does not trust either by default, and when it does not, the address it records is **the edge container's IP**. Nothing breaks: the site loads, requests succeed, only the logged, audited and rate-limited address is wrong. That is why it survives for months.

**The contract is `X-Real-IP`, gated on `MUVON_EDGE_IP`.** The deployer resolves the edge proxy's current address on the component's network, injects it as `MUVON_EDGE_IP`, and substitutes the literal `${MUVON_EDGE_IP}` token in env values and command arguments. The application trusts `X-Real-IP` only when the peer is that address:

```
if peer == MUVON_EDGE_IP:   # did this really come from the edge
    client_ip = X-Real-IP   # then take the authoritative answer
else:
    client_ip = peer
```

`docs/client-ip.md` carries the full contract with ready middleware for ASGI, Django and nginx.

**Do not enable the application server's own forwarded-header handling** (`--proxy-headers`, `--forwarded-allow-ips`, `FORWARDED_ALLOW_IPS`). Those implementations walk the `X-Forwarded-For` chain and take the rightmost entry that is not in their trusted list. Behind a CDN, MUVON emits `client, cdn-edge`, so with only the edge trusted the rightmost untrusted entry is the CDN and the application records the CDN as the visitor. Making it correct would mean trusting the CDN's entire address ranges and keeping that list current forever. The server layer also runs before application middleware, so when it is active it wins and the middleware never gets a chance.

Two related traps:

- **A command-line flag overrides the environment.** Fixing an env var while a stale flag remains in the command changes nothing. Check both: `docker inspect <container> --format '{{json .Config.Cmd}}'` and `docker exec <container> env | grep -i forwarded`.
- **Hardcoded addresses go stale.** The edge container's IP changes when it is recreated (see #36), and a stale gate simply stops matching, silently. That is what `${MUVON_EDGE_IP}` exists to prevent; substitution is a literal token replace, not shell expansion, so secrets containing `$` are not mangled. If the edge address cannot be resolved, the token is deliberately left in place and the deployment fails with a clear reason, rather than collapsing into an empty allow-list that quietly trusts no one.

Diagnosis: look at the `client_ip` distribution in `dialog.http_logs`. One private address dominating, especially the edge's container IP, means the trust configuration is missing:

```sql
SELECT client_ip, count(*) FROM dialog.http_logs
WHERE timestamp > now() - interval '1 hour'
GROUP BY 1 ORDER BY 2 DESC LIMIT 10;
```

## 38) A host firewall does not show real exposure

Seeing `ufw inactive` and `iptables INPUT ACCEPT` does **not** mean a port is open to the world. There may be a provider-level layer (cloud firewall, security group, VPC ACL) that is invisible from inside the host. The reverse is also true: even with ufw enabled, a provider layer can open something unexpected.

`ss -tlnp` showing `0.0.0.0` only says the **process** listens on all interfaces, not that packets can reach it from outside.

Measure from outside before concluding:

```bash
nc -z -G 4 -w 4 <public-ip> <port> && echo open || echo closed/filtered
```

Test a known-open port (443) as a control. If both come back closed, your measurement path is broken.

## 39) Helper containers and old images accumulate

`agent.self_upgrade` and the system upgrade flow start a short-lived `docker:*-cli` helper container. It is not removed with `--rm`, so it stays as `Exited(0)`. On a long-lived installation dozens pile up. Old version images are not cleaned either: `pruneImagesAfterPromote` covers **managed component** images, not MUVON's own.

Nothing breaks, but `docker ps -a` becomes unreadable and the disk grows:

```bash
docker ps -a --filter "status=exited" --filter "ancestor=docker:27-cli"
docker system df
```

Cleaning up is a destructive operation and needs operator approval (see `destructive-ops.md`).

## 40) Agents track `:latest`, so the fleet is **not uniform**

Agent compose usually ships with `VERSION=latest`, and each host upgrades on its own schedule. A bug fixed on one host can still be live on another. "We upgraded" does not mean **every** agent upgraded.

Verify per host:

```bash
docker inspect <agent-container> --format '{{index .Config.Labels "org.opencontainers.image.version"}}'
```

Also note that `:latest` moves only when a new `v*` tag is published, and an agent still needs `agent.self_upgrade` (or a compose pull) to actually take it.

## 41) Deleting a component breaks its route binding (the main trap in a move)

Because `agent_id` cannot be changed, moving a component to another host means delete and re-create (see #23). The new component gets a **new id**, while `routes.managed_component_id` pointed at the old one. The DELETE sets that field to `NULL` and the route ends up bound to no backend.

The symptom is thoroughly misleading: containers are `healthy`, instances show `active` in `/api/deploy/projects`, `GET /api/system/health/backends` reports everything `open`, and yet **every domain returns 502**. Since the backend looks healthy, people hunt in the deployer or the application, while the problem is at the route layer.

Always check after a move:

```sql
SELECT h.domain, r.path_prefix, COALESCE(r.managed_component_id::text,'NULL') AS comp
FROM muvon.routes r JOIN muvon.hosts h ON h.id = r.host_id
WHERE h.domain LIKE '%<project>%' ORDER BY 1;
```

Rebind every proxy route showing `NULL` to the new component id. `PUT /api/routes/{id}` wants the **complete route object** (no pointer fields), so `GET /api/routes/{id}` first, change only `managed_component_id`, and write it back.

A route can also **disappear entirely**: in one real move a domain's only route was deleted and it started returning 404. Compare the route count before and after, and restore anything missing with `POST /api/hosts/{id}/routes`.

## 42) Two projects on one host sharing a component slug collide in Docker DNS

The deployer attaches a container to the network under its component slug. On a single-project host that is fine, but on a multi-project host where two projects each have a component named `api`, **both containers claim the same name on the shared proxy network**. Docker DNS round-robins, so a request to `http://api:8000` lands on an arbitrary project's service.

In one real installation four containers shared the name `api`, four shared `landing` and two shared `admin`. Nothing errors; the wrong project's data is simply served. Server-side rendering that points at `SERVER_API_URL=http://api:8000` is especially exposed.

Check:

```bash
for c in $(docker network inspect muvon-agent_default --format '{{range .Containers}}{{.Name}}{{println}}{{end}}'); do
  docker inspect "$c" --format '{{.Name}} {{range $k,$v := .NetworkSettings.Networks}}{{if eq $k "muvon-agent_default"}}{{$v.Aliases}}{{end}}{{end}}'
done | sort -k2
```

A name appearing on more than one line is a collision.

Fix: containers now also carry a `<project>-<component>` alias. On multi-project hosts, point cross-component calls at the long name (`SERVER_API_URL=http://<project>-api:8000`). The short alias remains for backwards compatibility, but do not rely on it where projects share a host. Aliases are assigned at container creation, so upgrading the version is not enough: each component has to be redeployed.

## 43) Secrets are fail-closed now, and a startup exit is the symptom

`MUVON_ENCRYPTION_KEY` and `MUVON_JWT_SECRET` are both required and have no defaults. A container that exits immediately after an update, complaining about one of them, is configured rather than broken: `install.sh` generates both, but a hand-written `.env` may be missing one.

The strictness is deliberate: `GET` masks secret keys unconditionally, so a build that accepted a missing key could store a value unencrypted and still show `********` for it. On an installation that predates the requirement, treat secrets written without a key as unencrypted and rewrite them through the API once one is configured.
