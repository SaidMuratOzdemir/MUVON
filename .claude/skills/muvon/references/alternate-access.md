# API'nin dışındaki erişim yolları

API'den hata mesajı belirsiz, endpoint yoksa veya **derin teşhis** gerekiyorsa: DB'yi doğrudan oku, kaynak kodu oku. Bunlar **opsiyonel** — kullanıcının SSH erişimi yoksa, sadece API yeter.

## 1) SSH ile uzak makineye bağlanma

Skill `ssh` yapmaz. Kullanıcı bilgisayarındaki `~/.ssh/config` zaten varsayılır. Kontrol et:
```bash
ssh -o BatchMode=yes -o ConnectTimeout=3 <alias> "true" 2>&1
```

Çıkış 0 = alias hazır. Hata = kullanıcıdan alias sor: "MUVON sunucusuna nasıl ssh ediyorsun? alias?"

## 2) DB doğrudan okuma — SADECE READ

Production VPS'inde:
```bash
ssh <alias> "docker exec muvon-postgres psql -U muvon -d muvon -tAc \"<SELECT>\""
```

`-tA` flag'i: tuples-only + unaligned → CSV-vari çıktı, parse kolay.

### Şemalar

- **`muvon.*`** — admin/edge state:
  - `hosts` (`tls_mode`: off/redirect/auto/manual, `force_https`, `trusted_proxies`, JWT identity per-host).
    **`target_kind`** (`central` | `agent`) + **`target_agent_id`** → domain'in kendisi de bir agent'a
    bağlanır, sadece component'ler değil. Bir kurulumda tüm host'lar edge'de olabilir ve central'da
    hiç trafik olmayabilir; "hangi domain nerede" sorusunu bu iki kolon cevaplar.
  - `routes` (`managed_component_id` ile bir component'e bağlanabilir)
  - `agents` (`api_key_hash` BYTEA; eski `api_key` plaintext geçişte hâlâ var)
  - `tls_certificates` (issuer: `manual` / `letsencrypt` / `letsencrypt:agent:<id>`)
  - `settings`, `admin_users`, `admin_refresh_tokens`, `admin_audit_log`
  - `deploy_projects`, `deploy_components` (`agent_id` nullable, `paused`, `env` JSONB, `env_secret_keys` text[])
  - `deploy_releases`, `deploy_release_components`, `deploy_instances`
  - `deployments` (`agent_id` nullable — null = central, set = edge agent)
  - `deployment_events`
  - `agent_commands` (UUIDv7 PK, `agent_id`, `kind`, `payload` JSONB, `signature` BYTEA, `nonce` BYTEA, `state`, `result` JSONB, `expires_at`, `dispatched_at`, `finished_at`)
  - `scheduled_jobs`, `scheduled_job_runs` (component'e bağlı periyodik işler; cron `next_run_at`,
    `concurrency_policy`, run geçmişi + exit code + çıktı kuyruğu)
- **`dialog.*`** (SIEM): `http_logs`, `http_log_bodies`, `alerts`, `container_logs`, `containers`,
  `client_events` (RUM / tarayıcı telemetrisi; `trace_id` + `session_id` ile http_logs'a join edilir).

### Pratik sorgular

```sql
-- Hangi servis hangi host'ta (central vs edge agent)?
SELECT p.slug AS project, c.slug AS component,
       COALESCE(a.name, 'central') AS host,
       c.paused, array_length(c.env_secret_keys, 1) AS secret_count
FROM muvon.deploy_components c
JOIN muvon.deploy_projects p ON p.id = c.project_id
LEFT JOIN muvon.agents a ON a.id = c.agent_id;

-- Hangi domain nerede servis ediliyor (host'lar da agent'a bağlanır)?
SELECT COALESCE(a.name, '(central)') AS yer, h.target_kind, count(*) AS host_sayisi
FROM muvon.hosts h
LEFT JOIN muvon.agents a ON a.id = h.target_agent_id
GROUP BY 1, 2 ORDER BY 3 DESC;

-- Filo envanteri: agent'lar, en son ne zaman görüldü, central'a nereden bağlandı
SELECT name, is_active, last_seen_at, last_remote_addr, config_version
FROM muvon.agents ORDER BY name;

-- İstemci IP sağlığı: private/tek adres baskınlığı trust ayarının eksik olduğunu gösterir
SELECT client_ip, count(*) FROM dialog.http_logs
WHERE timestamp > now() - interval '1 hour'
GROUP BY 1 ORDER BY 2 DESC LIMIT 10;

-- Son 1 saat 5xx top path
SELECT host, path, count(*)
FROM dialog.http_logs
WHERE response_status >= 500
  AND timestamp > now() - interval '1 hour'
GROUP BY host, path ORDER BY 3 DESC LIMIT 10;

-- En çok rate-limited olan IP
SELECT client_ip, count(*)
FROM dialog.http_logs
WHERE response_status = 429
  AND timestamp > now() - interval '24 hours'
GROUP BY client_ip ORDER BY 2 DESC LIMIT 10;

-- En son deploy'lar (host kategorisi dahil)
SELECT d.id, p.slug AS project, d.release_id, d.trigger,
       COALESCE(a.name, 'central') AS host,
       d.status, d.started_at, d.finished_at
FROM muvon.deployments d
JOIN muvon.deploy_projects p ON p.id = d.project_id
LEFT JOIN muvon.agents a ON a.id = d.agent_id
ORDER BY d.created_at DESC LIMIT 5;

-- Hot endpoint son N dakika
SELECT host, path, count(*), percentile_cont(0.95) WITHIN GROUP (ORDER BY response_time_ms)
FROM dialog.http_logs
WHERE timestamp > now() - interval '15 minutes'
GROUP BY host, path ORDER BY 3 DESC LIMIT 20;

-- Agent command kuyruğunda neyin nerede durduğunu gör
SELECT c.id, a.name AS agent, c.kind, c.state,
       c.created_at, c.dispatched_at, c.finished_at,
       c.expires_at,
       (c.result->>'error') AS err
FROM muvon.agent_commands c
JOIN muvon.agents a ON a.id = c.agent_id
WHERE c.created_at > now() - interval '1 hour'
ORDER BY c.created_at DESC LIMIT 50;

-- Bir agent'a son N komut (history)
SELECT kind, state, created_at, finished_at,
       coalesce(result->>'output', result->>'error', '') AS detail
FROM muvon.agent_commands
WHERE agent_id = '<agent-uuid>'
ORDER BY created_at DESC LIMIT 20;

-- "Pending kalan" komutları say (sweeper henüz expire etmedi ama agent çekmedi)
SELECT a.name, count(*)
FROM muvon.agent_commands c
JOIN muvon.agents a ON a.id = c.agent_id
WHERE c.state = 'pending' AND c.created_at < now() - interval '1 minute'
GROUP BY a.name ORDER BY 2 DESC;
```

### Asla — DB'ye yazma

API katmanını atlatır:
- Audit log'a düşmez
- Secret box şifreleme atlanır (secrets plaintext kalır)
- Config holder yeniden hidrasyon yapmaz → yeni değer ayağa kalkmaz

DB write işleri **her zaman API** üzerinden.

## 3) Dosya okuma — config + compose

```bash
ssh <alias> "cat /opt/muvon/.env"
ssh <alias> "cat /opt/muvon/docker-compose.yml"
ssh <alias> "docker compose -f /opt/muvon/docker-compose.yml ps"
ssh <alias> "docker compose -f /opt/muvon/docker-compose.yml logs --tail=200 muvon"
```

`/opt/muvon/.env` içinde:
- `POSTGRES_PASSWORD` — secret
- `MUVON_JWT_SECRET` — secret
- `MUVON_ENCRYPTION_KEY` — secret (kayıp = encrypted settings VE component secret env'leri okunamaz; deployer ve edge agent ile aynı olmalı)
- `MUVON_ADMIN_DOMAIN`, `LOG_LEVEL` — public

Edge agent host'larında kurulum dizini genelde **`/opt/muvon-agent/`**: `docker-compose.agent.yml`
+ `.env`. Agent systemd servisi değildir, compose ile çalışır (container adı `muvon-agent-agent-1`):
```bash
ssh <agent-host> "docker compose -f /opt/muvon-agent/docker-compose.agent.yml ps"
ssh <agent-host> "docker logs muvon-agent-agent-1 --tail 200"
```

`.env` içinde tipik anahtarlar:
- `AGENT_API_KEY` — secret
- `AGENT_ENCRYPTION_KEY` — secret (central'ın `MUVON_ENCRYPTION_KEY`'i ile aynı olmak zorunda)
- `AGENT_CLOUDFLARE_IP_SECRET` / `AGENT_CLOUDFLARE_IP_HEADER`: secret + public. CDN arkasındaki
  gerçek istemci IP güveni bunlarla açılır, boşsa CDN başlıklarına güvenilmez
- `AGENT_CENTRAL_URL`, `AGENT_LOG_ADDR`: public. Central'a ve diaLOG'a nereden gidileceği
- `AGENT_DEPLOYER_ENABLED`, `AGENT_DEPLOYER_POLL_MS`, `AGENT_DEPLOYER_TCP_BIND`: public.
  `TCP_BIND` boşsa 9100 tüm arayüzlerde dinler, iç ağ adresine bind etmek tercih edilir
- `AGENT_DOCKERWATCH_ENABLED`, `AGENT_DOCKERWATCH_MANAGED_ONLY`: public
- `AGENT_PUBLIC_IP`, `AGENT_HOST_ID`, `AGENT_EXTRA_MOUNTS`, `MUVON_AGENT_DIR`: public

Agent container'ının bind mount'ları: docker socket (rw, embedded deployer için), registry auth
dosyası (ro), operatör env dosyaları dizini (ro, genelde `/opt/envfiles`), artı `tls_cache` /
`logship` / `config_cache` named volume'ları.

Component'lerin env'i iki kaynaktan gelir ve **component env map, env dosyasını ezer**:
`env_file_path` ile gösterilen dosya (agent'a ro mount edilmiş dizinde) + `deploy_components.env`
JSONB. Bir değerin nereden geldiğini ararken ikisine de bak.

**Stdout'a secret yansıtma** — sadece "set/empty" kontrol et:
```bash
ssh <alias> "test -n \"\$(grep ^MUVON_JWT_SECRET /opt/muvon/.env | cut -d= -f2-)\" && echo 'set' || echo 'empty'"
```

## 4) Container logs (Docker üzerinden)

Eğer container log shipping (`muvon-deployer logship`) düşmüşse veya geçmişe gitmek istiyorsan:
```bash
ssh <alias> "docker logs <container-name> --tail 200 --timestamps"
ssh <alias> "docker logs <container-name> --since 1h"
```

Normalde container log'lar `dialog.container_logs` tablosunda — API'den (`/api/container-logs`) erişilebilir.

## 5) MUVON kaynak kodu okuma

Production binary'de kaynak yok. Kaynak şuralarda:

### (a) Kullanıcının lokal repo'sunda

Kullanıcı `~/PycharmProjects/muvon`, `~/work/muvon` gibi bir yerde repo'yu clone'lamış olabilir. Önce sor:
```bash
ls -d ~/*/muvon ~/PycharmProjects/muvon ~/work/muvon 2>/dev/null
```

Bulduysan: `Read`, `Grep` doğrudan kullan.

### (b) GitHub raw (public repo varsayımı)

```bash
# Tek dosya:
curl -s https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/internal/admin/server.go | less

# Klasör listesi:
gh api repos/SaidMuratOzdemir/MUVON/contents/internal/admin?ref=main | jq -r '.[].name'

# Dosya içeriği base64-decode:
gh api repos/SaidMuratOzdemir/MUVON/contents/internal/admin/server.go?ref=main | jq -r '.content' | base64 -d
```

Repo private ise `gh auth login` gerek.

### (c) Hangi sürüm çalışıyor?

```bash
ssh <alias> "docker compose -f /opt/muvon/docker-compose.yml ps --format json" | jq -r '.[] | "\(.Service): \(.Image)"'
```

Image tag yazıyorsa (`:v1.2.3` veya commit hash) o ref ile raw fetch yap. `:latest` ise `git log` ile main'in HEAD'ine bak.

## 6) Endpoint kaynaklarına hızlı erişim

```bash
# Tüm route'ları listele:
grep -nE 'HandleFunc\("(GET|POST|PUT|DELETE)' internal/admin/server.go

# Belirli handler'ı bul:
grep -rn 'handleSearchLogs' internal/admin/

# DB migrations:
less internal/db/migrations.go
```

## 7) Mevcut olmayan veriyi sorgulama (DB'de var ama API'de yok)

Bazı tabloların admin API'sinde karşılığı olmayabilir (`muvon.managed_instances`, `muvon.deployments_events` vs.). DB doğrudan sorgu — okumadan ne olduğunu anlamak için kaynak şemasını oku:
```bash
ssh <alias> "docker exec muvon-postgres psql -U muvon -d muvon -c '\d+ muvon.deployments_events'"
```

## 8) Lokal MUVON çalıştırarak test etmek

Kullanıcı isterse skill'i lokalde dener. Kuruluş:
```bash
cd ~/PycharmProjects/muvon
cp .env.example .env
# .env'i doldur, sonra:
docker compose up -d
# Admin paneli: http://127.0.0.1:9443 (compose'da local-only)
```

İlk admin: `POST http://127.0.0.1:9443/api/auth/setup`. Sonrası skill'in normal akışı.

## Hangi yolu seç — karar şeması

```
İhtiyaç                          → Birinci yol     → İkinci yol
─────────────────────────────────────────────────────────────────
state/list/detail okuma          → API GET         → DB SELECT (SSH varsa)
log arama (BM25)                 → API /api/logs   → DB dialog.http_logs
audit log                        → API /api/audit  → DB muvon.audit_log
secret kontrol (set mi?)         → API /api/settings (boş = ?)  → /opt/muvon/.env (set/empty)
container live log               → API SSE stream  → ssh + docker logs -f
managed component image         → API /api/containers  → docker compose ps
endpoint bulamadın               → kaynağa bak                  → -
auth/CSRF/middleware iç işleyiş  → internal/admin/*.go         → -
deploy lifecycle iç işleyiş      → internal/deployer/*.go      → -
```
