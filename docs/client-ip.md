# Client IP behind MUVON

Your application does not see the visitor's address on the TCP connection. It sees
MUVON's address, because MUVON is what connects to it. This page defines how the
real address is passed along, what your application has to do to read it, and how
to prove it works.

Getting this wrong is quiet. Nothing crashes, pages load, requests succeed. Only
the recorded address is wrong, which is why it can go unnoticed for months. The
address usually feeds rate limiting, audit trails and abuse detection, so a wrong
value weakens exactly the things that are supposed to be trustworthy.

## What MUVON sends

Every proxied request carries two headers. They answer different questions and
must not be used interchangeably.

| Header | Meaning | Use it for |
|---|---|---|
| `X-Real-IP` | The client address MUVON resolved, as a single value | Deciding who the client is |
| `X-Forwarded-For` | The hop chain, oldest first | Auditing, debugging, hop counting |

`X-Real-IP` is authoritative. MUVON has already done the work behind it: if a CDN
sits in front, MUVON validated the CDN's shared secret before believing what the
CDN reported; if another reverse proxy sits in front, MUVON checked it against the
host's configured trusted proxies. Anything a client sends in these headers is
overwritten.

`X-Forwarded-For` follows the convention every major proxy uses (nginx, Envoy,
HAProxy, Cloudflare, AWS load balancers): the chain reported by a trusted upstream
is preserved and the hop the request arrived from is appended. A chain offered by
an untrusted peer is discarded, so a forged entry cannot reach your application.

Behind a CDN the two look like this:

```
X-Real-IP:       203.0.113.7
X-Forwarded-For: 203.0.113.7, 198.51.100.4
                 client        CDN edge
```

Without a CDN the client is the only hop:

```
X-Real-IP:       203.0.113.7
X-Forwarded-For: 203.0.113.7
```

### Why not just read an end of the chain

Because which end holds the client depends on the topology, and your application
should not have to know the topology.

Reading the **leftmost** entry is unsafe. A CDN appends the real client to
whatever `X-Forwarded-For` the client supplied, so the leftmost value can be
attacker controlled.

Reading the **rightmost** entry requires knowing which hops are proxies. Behind a
CDN the rightmost hop is the CDN itself, so an application that does not recognise
that CDN's address ranges will record the CDN as the visitor. Those ranges change,
and every application would have to track them.

`X-Real-IP` removes the question: the component that already knows which hops are
proxies is the one that writes the answer.

## What your application must do

Trust `X-Real-IP` only when the request actually came from MUVON. Otherwise any
container that can reach your app could send the header and choose its own
identity.

MUVON injects `MUVON_EDGE_IP` into every managed container at start, holding the
edge address on that container's network. Use it as the gate. Never hardcode a
container address: Docker reassigns those, and a stale value silently disables the
check.

The rule in two lines:

```
if peer == MUVON_EDGE_IP:   # did this really come from the edge
    client_ip = X-Real-IP   # then take the authoritative answer
else:
    client_ip = peer        # otherwise leave it alone
```

Apply it as early as possible, so everything downstream (rate limiting, audit
logging, request logs) sees the corrected value.

### FastAPI, Starlette, any ASGI app

Write it as pure ASGI middleware, not `BaseHTTPMiddleware`. The latter wraps the
response stream and has known interactions with streaming and SSE endpoints; this
only needs to touch `scope`, so it stays out of the response path entirely.

```python
import os
from ipaddress import ip_address, ip_network


class RealClientIPMiddleware:
    """Replace scope["client"] with X-Real-IP when the peer is the MUVON edge."""

    def __init__(self, app, trusted: str | None = None) -> None:
        self.app = app
        raw = os.getenv("MUVON_EDGE_IP", "") if trusted is None else trusted
        nets = []
        for item in raw.split(","):
            item = item.strip()
            if item:
                try:
                    nets.append(ip_network(item, strict=False))
                except ValueError:
                    continue
        self.trusted = tuple(nets)

    async def __call__(self, scope, receive, send):
        if not self.trusted or scope.get("type") not in ("http", "websocket"):
            return await self.app(scope, receive, send)

        client = scope.get("client")
        if not client or not self._trusted_peer(client[0]):
            return await self.app(scope, receive, send)

        real = ""
        for name, value in scope.get("headers", ()):
            if name == b"x-real-ip":
                real = value.decode("latin1").split(",")[0].strip()
                break

        if real:
            try:
                ip_address(real)
            except ValueError:
                return await self.app(scope, receive, send)
            scope["client"] = (real, client[1] if len(client) > 1 else 0)

        return await self.app(scope, receive, send)

    def _trusted_peer(self, host: str) -> bool:
        try:
            addr = ip_address(host)
        except ValueError:
            return False
        return any(addr in net for net in self.trusted)
```

Register it last, so it ends up outermost:

```python
app.add_middleware(RealClientIPMiddleware)
```

After this, `request.client.host` is the real visitor address everywhere.

### Django

Normalise `REMOTE_ADDR` in middleware, so every existing consumer keeps working
unchanged: `django-axes`, throttling, audit records and access logs all read the
same value.

```python
import os
from ipaddress import ip_address, ip_network


def _trusted():
    nets = []
    for item in os.getenv("MUVON_EDGE_IP", "").split(","):
        item = item.strip()
        if item:
            try:
                nets.append(ip_network(item, strict=False))
            except ValueError:
                continue
    return tuple(nets)


_TRUSTED = _trusted()


class RealClientIPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        meta = request.META
        remote = meta.get("REMOTE_ADDR") or ""
        if _TRUSTED and self._trusted_peer(remote):
            real = (meta.get("HTTP_X_REAL_IP") or "").split(",")[0].strip()
            if real and self._valid(real):
                meta["REMOTE_ADDR_EDGE"] = remote  # keep the edge hop for debugging
                meta["REMOTE_ADDR"] = real
        return self.get_response(request)

    @staticmethod
    def _valid(value):
        try:
            ip_address(value)
            return True
        except ValueError:
            return False

    def _trusted_peer(self, host):
        return self._valid(host) and any(ip_address(host) in net for net in _TRUSTED)
```

Put it near the top of `MIDDLEWARE`, before anything that reads the address.

`SECURE_PROXY_SSL_HEADER` is unrelated: it covers the scheme, not the address, and
MUVON sets `X-Forwarded-Proto` for it.

### Static sites served by nginx

If the container only serves static files, it has nothing to fix. If it logs and
you want real addresses in those logs:

```nginx
set_real_ip_from  <MUVON_EDGE_IP>;
real_ip_header    X-Real-IP;
```

The address has to be substituted at container start, since it is only known then.

## What not to do

**Do not enable your server's own proxy header handling.** For uvicorn and
gunicorn that means leaving `--proxy-headers`, `--forwarded-allow-ips` and the
`FORWARDED_ALLOW_IPS` environment variable unset. Those make the server rewrite
the client address from the chain by picking an end of it, which is the ambiguity
this contract exists to avoid. The server layer runs before your middleware, so if
it is active it wins, and your middleware never gets a chance.

This is concrete, not theoretical. Uvicorn's `ProxyHeadersMiddleware` first
requires the peer to be in its trusted list, then walks `X-Forwarded-For` from
the right and takes the first entry that is *not* trusted. Behind a CDN, MUVON
emits the chain `client, cdn-edge`. If the trusted list holds only MUVON's
address, the rightmost untrusted entry is the CDN edge, so the application
records the CDN as the visitor. Every request looks fine and every address is
wrong. Making it correct would mean trusting MUVON's address plus all of the
CDN's ranges, and keeping that list current forever, which is exactly the burden
`X-Real-IP` removes.

The same reasoning is why a CDN tells you to prefer its single-valued header
over the chain, and why nginx solves this with `real_ip_header` plus an explicit
`set_real_ip_from` rather than with hop counting. MUVON's `X-Real-IP` and the
`MUVON_EDGE_IP` gate are that pattern: one authoritative value, trusted from one
known peer.

Note that gunicorn reads `FORWARDED_ALLOW_IPS` from the environment even when no
command line flag is present, and passes it to uvicorn when running
`UvicornWorker`. Setting it in an env file is enough to re-enable the behaviour by
accident.

**Do not use `--forwarded-allow-ips=*`.** It tells the server to trust the
forwarded headers from any peer. On a host where several projects share one Docker
network, any neighbouring container can then present a header and be believed.

**Do not hardcode the edge address.** Docker reassigns container addresses. A
literal that is correct today becomes wrong after a redeploy, and the failure is
silent because the gate simply stops matching.

**Do not widen the gate to a whole private range.** `172.16.0.0/12` covers every
container on the host, not just the edge. Use the exact address MUVON injects.

## Verifying it works

Make a request from a known address and compare three places. They must agree.

```bash
curl -s https://api.ipify.org          # the address you are coming from
curl -sS -o /dev/null https://<your-domain>/
```

**1. What the edge resolved**, from the MUVON database:

```sql
SELECT timestamp, host, path, client_ip
FROM dialog.http_logs
WHERE host = '<your-domain>'
ORDER BY timestamp DESC LIMIT 5;
```

**2. What the application saw**, in its own access log:

```bash
docker logs <app-container> --tail 20
```

**3. What was persisted**, in whichever table records addresses:

```sql
SELECT created_at, ip_address FROM <audit-table>
ORDER BY created_at DESC LIMIT 5;
```

A mismatch between 1 and 2 means the application layer is misconfigured: either
the middleware is missing, the gate does not match, or the server's own proxy
handling is still enabled. Check what actually reached the container:

```bash
docker inspect <app-container> --format '{{json .Config.Cmd}}'
docker exec <app-container> env | grep -E 'MUVON_EDGE_IP|FORWARDED'
```

`MUVON_EDGE_IP` should be present, `FORWARDED_ALLOW_IPS` should not.

## Notes for CDN setups

MUVON believes a CDN's client address header only when the request also carries a
shared secret that the operator injects at the CDN, using a transform rule on
their own zone. This matters because CDN egress addresses are shared across all of
that CDN's customers: arriving from a CDN address proves nothing on its own, since
an attacker can route their own CDN zone at your origin and forge the header. The
secret is the part they cannot obtain.

Configure it with `MUVON_CLOUDFLARE_IP_SECRET` and, if you use a non default
header name, `MUVON_CLOUDFLARE_IP_HEADER` (agents use the `AGENT_` prefixed
equivalents). Leave the secret empty and CDN client-address trust stays off, which
is the safe default.

The secret header is stripped before request headers are stored in the log
pipeline, so it does not end up readable in the SIEM.
