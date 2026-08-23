---
name: muvon
description: Operate the MUVON edge gateway and diaLOG SIEM remotely via the admin API. Read hosts, routes, HTTP/container logs, alerts, deployments, managed components, agents, audit, settings and system health. Debug production issues, investigate 5xx spikes, check deploy status, inspect configuration. Use this skill whenever the user mentions MUVON, diaLOG, an edge gateway, a host/route/deploy/agent/alert/container, asks to investigate logs, troubleshoot a 5xx, examine a configuration, or take an action against a MUVON deployment.
---

# MUVON operator skill

MUVON is an edge gateway, SIEM and managed-deploy platform built from four Go services (see `references/architecture.md`). This skill is for connecting to a live MUVON installation to **read state, investigate incidents, and take carefully gated mutating actions**.

## First moves, every session

1. **Establish which installation.** Which MUVON is the user talking about? What is the URL, the admin username, and where is the password kept? **Ask the user.** This skill stores no credentials.
2. **Log in** and create a cookie jar. `references/auth.md` walks through it.
3. Decide which reference file covers the task before starting it.

## Reference files

| Topic | File |
|---|---|
| Architecture, services, schemas | `references/architecture.md` |
| Login, cookies, the CSRF dance, refresh rotation | `references/auth.md` |
| Endpoint inventory, response shapes, SSE | `references/endpoints.md` |
| **Surprises and traps** | `references/pitfalls.md` |
| Destructive endpoints and the confirmation protocol | `references/destructive-ops.md` |
| Reading the DB directly over SSH + psql, reading source | `references/alternate-access.md` |
| Diagnostic patterns (5xx, deploy, agent, TLS) | `references/troubleshooting.md` |

Open these with `Read` **when they are needed**. Do not load them all up front; that is wasted context.

## Never without explicit user approval

- Any endpoint with DELETE (`/api/hosts/{id}`, `/api/routes/{id}`, `/api/tls/certificates/{id}`, `/api/agents/{id}`, `/api/deploy/projects/{slug}`, `/api/deploy/projects/{slug}/components/{component}`).
- `POST /api/deploy/projects/{slug}/deploy`, which ships a new image to production.
- `POST /api/deploy/projects/{slug}/rollback`, which queues a fresh deployment of the previous succeeded release.
- `POST /api/tls/certificates`, a certificate override.
- `PUT /api/settings/{key}`, especially `muvon_jwt_secret`, `muvon_encryption_key` and SMTP credentials.
- `PUT /api/deploy/projects/{slug}/components/{component}` with `paused: true`: the service's running instances drain and new deploys are blocked.
- `POST /api/alerting/test/slack` and `POST /api/alerting/test/smtp`, which send a real Slack or email message.
- `POST /api/system/upgrade`, which recreates the whole stack with `docker compose pull && up -d`; the admin panel and the proxy go down briefly.
- `POST /api/agents/{id}/commands`, especially `kind` = `agent.restart` / `agent.revoke` / `agent.drain` / `agent.self_upgrade`, which stop, drain, permanently revoke or re-image a remote edge.
- Writing to the database directly (`INSERT`, `UPDATE`, `DELETE`). A direct write bypasses the audit log, secret encryption and the config holder's reload. Writes always go through the API.
- Echoing secret values (`.env`, `MUVON_JWT_SECRET`, `MUVON_ENCRYPTION_KEY`, `AGENT_ENCRYPTION_KEY`, the SMTP password, agent API keys, component env secrets) to stdout or to the user. Report only whether they are set or empty. An agent API key is returned once, in the create response; the list endpoint does not carry it at all, not even masked.

Full list and confirmation protocol: `references/destructive-ops.md`.

## Discipline before every mutating call

The MUVON audit log **cannot currently tell an agent apart from a human admin** (`admin_user: admin` looks identical for both). So:

1. Print a single AGENT_ACTION line to stdout before the call:
   ```
   AGENT_ACTION: POST /api/deploy/projects/<slug>/deploy {"image_tag":"<tag>"}
   ```
2. Get an explicit "yes" from the user.
3. Make the call.
4. Summarise the result: what was affected, what status code came back.

Apply this to **every** mutating call. Until the audit log is fixed in code, this line is the only traceability there is.

## Work it out yourself: read the source

When an API error is vague, an endpoint cannot be found, or a response shape is unexpected, **read the source**. The MUVON codebase is self-documenting:

- If a local clone is available, use `Read` and `Grep` directly. Ask the user where it is rather than guessing a path.
- Otherwise: `gh api repos/SaidMuratOzdemir/MUVON/contents/<path>?ref=main` or `curl https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/<path>`.
- Every endpoint is registered in one file: `internal/admin/server.go`. To find a handler: `grep -n "handle<Name>" internal/admin/*.go`.

Details: `references/alternate-access.md`.

## Output style

- **Short.** Organised, no repetition.
- Use tables, headings and `code` blocks; the user scans rather than reads.
- Cite the source of every finding: which endpoint, which query, which log timestamp.
- If there is a side effect or an error, end with a concrete "**Next step:**" suggestion.

## Limits

- This skill is for **reading and carefully gated writing**. It is not autonomous monitoring; it acts when the user asks.
- Do not assume SSH access. Ask whether `ssh <alias>` works before relying on it. The API is usually enough.
- Never write passwords, agent tokens or secret contents to a file. Credentials that arrive in the user's prompt belong in that session's cookie jar and nowhere else.
