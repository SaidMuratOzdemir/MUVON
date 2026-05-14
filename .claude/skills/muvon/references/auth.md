# Auth — cookie + CSRF dance ile MUVON admin API

MUVON admin API browser-tarzı auth kullanır. **Bearer header desteği yok** (`internal/admin/middleware.go:16-19`). Tek yol: kullanıcı adı + şifre ile login → 3 cookie → her istekte cookie jar + CSRF header.

## Üç cookie

| Cookie | Süre | Path | HttpOnly | Amaç |
|---|---|---|---|---|
| `__Host-muvon_access` | 15 dk | `/` | ✓ | JWT — sonraki API çağrılarında otomatik gönderilir |
| `muvon_refresh` | 30 gün | `/api/auth` | ✓ | Access'i yenilemek için, **tek kullanımlık** |
| `muvon_csrf` | 30 gün | `/` | ✗ | Double-submit token. JS-okur. Her POST/PUT/DELETE'te header'a kopyala |

`__Host-` prefix browser kuralı: Path=/ + Secure + Domain attribute yok. Curl'da sorun çıkarmaz.

## 1) Login

```bash
BASE="https://muvon.example.com"
CJ=$(mktemp)
curl -sS -c "$CJ" -X POST "$BASE/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"'"$MUVON_PASSWORD"'"}' \
  --max-time 10
```

**Başarılı yanıt** (200):
```json
{"user":{"id":1,"username":"admin","is_active":true,"created_at":"..."}}
```

**Hata yanıtları**:
- 401 `{"error":"invalid credentials"}` — yanlış şifre/kullanıcı
- 400 `{"error":"username and password required"}` — eksik alan
- 429 — rate limit (login endpoint'i rate-limit'li, `internal/admin/server.go`)

## 2) GET çağrıları

GET/HEAD/OPTIONS CSRF gerektirmez. Sadece cookie:

```bash
curl -sS -b "$CJ" "$BASE/api/hosts" --max-time 10
```

## 3) POST/PUT/DELETE çağrıları — CSRF dance

CSRF token'ı cookie jar'dan oku, `X-CSRF-Token` header'a koy:

```bash
CSRF=$(awk '$6 == "muvon_csrf" {print $7}' "$CJ")
curl -sS -b "$CJ" \
  -H "X-CSRF-Token: $CSRF" \
  -H "Content-Type: application/json" \
  -X POST "$BASE/api/hosts" \
  -d '{"domain":"example.com","is_active":true}' \
  --max-time 10
```

CSRF format: 32 byte rastgele, base64url. Mismatched veya missing → **403** `csrf cookie missing` / `csrf header missing` / `csrf mismatch`.

Bypass listesinde (CSRF gerektirmez): `POST /api/auth/setup`, `POST /api/auth/login`, `POST /api/deploy/webhook` (HMAC ile imzalı). **Logout dahil değil** — CSRF gerektirir.

## 4) Refresh — tek kullanımlık rotation

Access cookie 15 dk dolduğunda 401 alırsın. Çözüm:

```bash
curl -sS -b "$CJ" -c "$CJ" -X POST "$BASE/api/auth/refresh" --max-time 10
```

**KRİTİK**: refresh token rotation aktif. **Her refresh çağrısı eski refresh'i geçersiz kılar ve YENİ access + refresh + csrf cookie'lerini set eder.** `-c "$CJ"` ile cookie jar'ı **mutlaka güncelle**, yoksa bir sonraki refresh denemende 401 + tüm cookie'ler silinir (gerçekten test edildi).

Refresh başarılı yanıt (200): user objesi.
Refresh başarısız (401): tüm 3 cookie `Max-Age=0` ile silinir → yeniden login lazım.

## 5) Otomatik refresh wrapper'ı

Long-running script'lerde access süresi sınırlı. Önerilen pattern:

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

Kullanım: `muvon_api GET /api/hosts` veya `muvon_api POST /api/hosts -d '{"domain":"x.com"}' -H "Content-Type: application/json"`.

## 6) Logout

```bash
CSRF=$(awk '$6 == "muvon_csrf" {print $7}' "$CJ")
curl -sS -b "$CJ" -H "X-CSRF-Token: $CSRF" -X POST "$BASE/api/auth/logout" --max-time 10
rm -f "$CJ"
```

Logout CSRF gerektirir. Sunucu 3 cookie'yi de `Max-Age=0` ile döner; lokal cookie jar dosyasını da sil.

## 7) Setup — ilk admin (sadece kurulum)

```bash
curl -sS -X POST "$BASE/api/auth/setup" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"..."}'
```

`409` döner eğer admin user zaten varsa. Bu endpoint sadece **ilk kurulum** içindir; sonra kullanılmaz.

## 8) Hata kodları özet

| Code | Anlam | Sonraki adım |
|---|---|---|
| 401 `not authenticated` | Cookie yok/expire | Login veya refresh |
| 401 `invalid or expired session` | JWT validation fail | Refresh, sonra gerekirse login |
| 403 `csrf cookie missing` | csrf cookie atlanmış (jar yanlış?) | Cookie jar'ı doğrula |
| 403 `csrf header missing` | `X-CSRF-Token` header yok | Header'ı ekle |
| 403 `csrf mismatch` | Cookie ↔ header eşleşmiyor | Cookie jar'ı yenile |
| 400 `<alan> is required` | Body validation | Body'i tamamla |
| 429 | Rate limit | Bekle ve tekrar dene |

## 9) Güvenlik notları

- **Şifreyi env var'a koy** (`export MUVON_PASSWORD=...`), bash history'e yazma.
- **Cookie jar dosyasını chmod 600** yap (`umask 077; mktemp` veya `chmod 600`).
- Session bittiğinde `rm -f "$CJ"`.
- Bu skill credentials'ı **persistent memory'ye yazmaz**. Her oturumda kullanıcıdan iste veya env'den oku.

## 10) Agent API key — operatör ↔ edge auth

Bu skill operatör admin paneline yöneliktir; agent (edge) auth'u tamamen ayrı bir mekanizma:

- Edge agent binary'sinin gönderdiği header: `X-Api-Key: <agent-key>` (cookie değil).
- Anahtar **SHA-256 hash'lenmiş** olarak `agents.api_key_hash` kolonunda saklanır (Mart 2026'dan itibaren). Auth middleware hash karşılaştırması yapar; pre-migration plaintext satırlar varsa ilk başarılı login'de hash otomatik doldurulur.
- Plaintext anahtar **sadece create yanıtında bir kez** döner:
  ```json
  POST /api/agents → {"agent": {...}, "api_key": "abc123..."}
  ```
  `GET /api/agents` artık `api_key` alanını **döndürmez**. Operatör kaybederse yeni agent enroll etmek gerek (eskiyi sil + yeni yarat).
- Plaintext yansıtma yasağı: Bu skill, herhangi bir agent API key'ini stdout'a veya kullanıcıya açık yazmaz. Sadece "set" / "absent" durumunu raporla; rotate gerekiyorsa kullanıcıya enroll komutunu söyle, key'i kendin görme.

## 11) Central → agent komut imzalama (X-Api-Key'den ayrı katman)

`X-Api-Key` agent ↔ central HTTP/SSE transport'unu authentikatör eder; **komut payload'larının kendisini değil**. Komutlar ayrıca her satırda HMAC-SHA256 imzası taşır:

- İmzalama anahtarı: `HKDF(MUVON_ENCRYPTION_KEY, label="muvon-agent-command-v1")`. Yani central'daki `MUVON_ENCRYPTION_KEY` ile edge agent'taki `AGENT_ENCRYPTION_KEY` **aynı olmak zorunda**, yoksa imza doğrulaması başarısız.
- İmzalanan canonical encoding: `id || agent_id || kind || nonce || expires_at || payload_json` (deterministik).
- Replay koruması: `nonce` rasgele 16 byte, `expires_at` TTL (default 5 dk), agent-side LRU dedup son 1000 komut ID'si.
- Key boşsa: admin endpoint (`POST /api/agents/:id/commands`) 503 döner — komut **asla** yanlış imza ile dağıtılmaz.

Operatör için pratik sonuç: agent disconnected sembol gösteriyor ama X-Api-Key doğruysa komut sıraya girer, agent online olunca imza doğrular ve çalıştırır. İmza fail veriyorsa root cause genelde `MUVON_ENCRYPTION_KEY ≠ AGENT_ENCRYPTION_KEY` (bkz. `pitfalls.md` #29).
