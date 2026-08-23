# Auth: the cookie and CSRF dance against the MUVON admin API

The MUVON admin API uses browser-style auth. **There is no Bearer header path** (`internal/admin/middleware.go`). The only way in: log in with username and password, receive three cookies, then send the cookie jar plus a CSRF header on every request.

## The three cookies

| Cookie | Lifetime | Path | HttpOnly | Purpose |
|---|---|---|---|---|
| `__Host-muvon_access` | 15 min | `/` | yes | The JWT, sent automatically on later API calls |
| `muvon_refresh` | 30 days | `/api/auth` | yes | Renews the access token, **single use** |
| `muvon_csrf` | 30 days | `/` | no | Double-submit token. JS-readable. Copy it into a header on every POST/PUT/DELETE |

The `__Host-` prefix is a browser rule: Path=/, Secure, no Domain attribute. It causes no trouble in curl.

## 1) Log in

```bash
BASE="https://muvon.example.com"
CJ=$(mktemp)
curl -sS -c "$CJ" -X POST "$BASE/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"'"$MUVON_PASSWORD"'"}' \
  --max-time 10
```

**Success** (200):
```json
{"user":{"id":1,"username":"admin","is_active":true,"created_at":"..."}}
```

**Failures**:
- 401 `{"error":"invalid credentials"}`, wrong password or username
- 400 `{"error":"username and password required"}`, missing field
- 429, rate limited (the login endpoint is behind a rate limiter, `internal/admin/server.go`)

## 2) GET calls

GET, HEAD and OPTIONS need no CSRF token. Cookies alone:

```bash
curl -sS -b "$CJ" "$BASE/api/hosts" --max-time 10
```

## 3) POST, PUT and DELETE: the CSRF dance

Read the CSRF token from the cookie jar and put it in the `X-CSRF-Token` header:

```bash
CSRF=$(awk '$6 == "muvon_csrf" {print $7}' "$CJ")
curl -sS -b "$CJ" \
  -H "X-CSRF-Token: $CSRF" \
  -H "Content-Type: application/json" \
  -X POST "$BASE/api/hosts" \
  -d '{"domain":"example.com","is_active":true}' \
  --max-time 10
```

Token format: 32 random bytes, base64url. Missing or mismatched gives **403** with `csrf cookie missing`, `csrf header missing` or `csrf mismatch`.

Exempt from CSRF: `POST /api/auth/setup`, `POST /api/auth/login`, `POST /api/auth/refresh` and `POST /api/deploy/webhook` (HMAC-signed). **Logout is not exempt** and needs the header. Neither is `POST /api/auth/password`.

## 4) Refresh: single-use rotation

When the access cookie expires after 15 minutes you get a 401. Fix:

```bash
curl -sS -b "$CJ" -c "$CJ" -X POST "$BASE/api/auth/refresh" --max-time 10
```

**Critical**: refresh token rotation is on. **Every refresh invalidates the old refresh token and sets a new access, refresh and csrf cookie.** Always pass `-c "$CJ"` so the jar is updated; without it the next refresh returns 401 and every cookie is cleared (verified in practice).

Refresh success (200) returns the user object. Refresh failure (401) clears all three cookies with `Max-Age=0`, so you must log in again.

## 5) An auto-refresh wrapper

Access tokens are short-lived, which matters in long-running scripts. Suggested pattern:

```bash
muvon_api() {
  local method="$1" path="$2"; shift 2
  local csrf=$(awk '$6=="muvon_csrf"{print $7}' "$CJ")
  local code=$(curl -sS -o /tmp/muvon-body -w "%{http_code}" \
    -b "$CJ" -c "$CJ" \
    ${csrf:+-H "X-CSRF-Token: $csrf"} \
    -X "$method" "$BASE$path" "$@" --max-time 30)
  if [ "$code" = "401" ]; then
    # access expired — try refresh once
    curl -sS -b "$CJ" -c "$CJ" -X POST "$BASE/api/auth/refresh" --max-time 10 >/dev/null
    csrf=$(awk '$6=="muvon_csrf"{print $7}' "$CJ")
    code=$(curl -sS -o /tmp/muvon-body -w "%{http_code}" \
      -b "$CJ" -c "$CJ" \
      ${csrf:+-H "X-CSRF-Token: $csrf"} \
      -X "$method" "$BASE$path" "$@" --max-time 30)
  fi
  cat /tmp/muvon-body
  return $([ "$code" -lt 400 ] && echo 0 || echo 1)
}
```

Use: `muvon_api GET /api/hosts`, or `muvon_api POST /api/hosts -d '{"domain":"x.com"}' -H "Content-Type: application/json"`.

## 6) Log out

```bash
CSRF=$(awk '$6 == "muvon_csrf" {print $7}' "$CJ")
curl -sS -b "$CJ" -H "X-CSRF-Token: $CSRF" -X POST "$BASE/api/auth/logout" --max-time 10
rm -f "$CJ"
```

Logout requires the CSRF header. The server returns all three cookies with `Max-Age=0`; delete the local jar file as well.

## 7) Setup: the first admin only

```bash
curl -sS -X POST "$BASE/api/auth/setup" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"..."}'
```

Returns `409` once an admin exists. This endpoint is for the **initial install** and is never used again.

## 8) Changing a password ends other sessions

`POST /api/auth/password` takes `{"current_password": "...", "new_password": "..."}` and requires an active session plus the CSRF header. It bumps the user's `token_version` and revokes every refresh row, so **every other session dies at its next request**. The caller receives fresh cookies and keeps working, but any other jar you were holding for the same user is now dead: log in again.

This also matters when reading state: a 401 saying `session revoked` means the version moved, not that the token expired. Refreshing will not help; log in.

## 9) Error codes

| Code | Meaning | Next step |
|---|---|---|
| 401 `not authenticated` | No cookie, or expired | Log in or refresh |
| 401 `invalid or expired session` | JWT validation failed | Refresh, then log in if needed |
| 401 `session revoked` | Account disabled, or password changed since the token was issued | Log in again; refresh will not help |
| 403 `csrf cookie missing` | The csrf cookie was dropped (wrong jar?) | Check the cookie jar |
| 403 `csrf header missing` | No `X-CSRF-Token` header | Add the header |
| 403 `csrf mismatch` | Cookie and header disagree | Refresh the cookie jar |
| 400 `<field> is required` | Body validation | Complete the body |
| 429 | Rate limited | Wait and retry |

## 10) Security notes

- **Keep the password in an env var** (`export MUVON_PASSWORD=...`) so it stays out of shell history.
- **chmod 600 the cookie jar** (`umask 077; mktemp`, or `chmod 600`).
- `rm -f "$CJ"` when the session ends.
- This skill **never writes credentials to persistent memory**. Ask the user each session, or read from the environment.

## 11) Agent API keys: operator auth versus edge auth

This skill targets the operator admin panel. Agent (edge) auth is a separate mechanism:

- The edge agent binary sends `X-Api-Key: <agent-key>`, not a cookie.
- The key is stored **SHA-256 hashed** in `agents.api_key_hash`. The auth middleware compares hashes; a pre-migration plaintext row is hashed automatically on its first successful call.
- The plaintext key is returned **once, in the create response**:
  ```json
  POST /api/agents → {"agent": {...}, "api_key": "abc123..."}
  ```
  `GET /api/agents` does **not** return `api_key` at all. If the operator loses it, enroll a new agent (delete the old one, create a new one).
- Never echo a key. Report only "set" or "absent". If a rotation is needed, tell the user the enroll command rather than reading the key yourself.

## 12) Central to agent command signing, a layer above X-Api-Key

`X-Api-Key` authenticates the agent to central transport (HTTP and SSE). It does **not** authenticate the command payloads. Each command row additionally carries an HMAC-SHA256 signature:

- Signing key: `HKDF(MUVON_ENCRYPTION_KEY, label="muvon-agent-command-v1")`. Central's `MUVON_ENCRYPTION_KEY` and the edge's `AGENT_ENCRYPTION_KEY` **must be identical**, or verification fails.
- Canonical encoding that gets signed: `id || agent_id || kind || nonce || expires_at || payload_json`, deterministic.
- Replay protection: a random 16 byte `nonce`, an `expires_at` TTL (5 minutes by default), and an agent-side LRU of the last 1000 command IDs.
- `MUVON_ENCRYPTION_KEY` is required for the binary to start at all, so the channel is always armed. There is no "key missing, channel disabled" state to diagnose any more.

Practical consequence: if an agent shows as disconnected but its `X-Api-Key` is right, the command still queues, and the agent verifies and runs it when it comes back. A signature failure almost always means `MUVON_ENCRYPTION_KEY` and `AGENT_ENCRYPTION_KEY` differ (see `pitfalls.md`).
