# Teşhis pattern'leri — sık karşılaşılan senaryolar

Kullanıcı "şu sorun var" dediğinde nereden başlayacağını bilesin.

## 1) "Bir hostta 5xx yedik / hata oranı arttı"

```
1. Time window'u sor (son N dk/saat).
2. GET /api/logs?host=<x>&status=500&since=<N>&limit=20
   → Top error path'lerini topla.
3. GET /api/logs/{id} → response body'ye bak (backend hata mesajı).
4. /api/deploy/deployments?slug=<host-component>&limit=5 → son deploy <N içinde mi?
   Eğer evet → muhtemel sebep deploy. Rollback öner.
5. GET /api/system/health → MUVON kendisi sağlıklı mı?
6. SSH varsa: docker logs <container> --since=<N> → backend stack trace.
7. Bulgular özeti → kullanıcıya 5 satırla raporla.
```

**Tipik bulgular**:
- 502 → backend down (managed component crashed). `GET /api/containers` → status `exited`/`restarting`.
- 503 → backend healthy ama overload. Rate limit configleri kontrol.
- 504 → backend timeout. `timeout_seconds` route'ta küçük olabilir.
- 500 generic → backend internal. App log'una bak.

## 2) "Yeni deploy başarısız" / "Deploy 'pending' kaldı"

```
1. GET /api/deploy/deployments?limit=3 → son deploy id, status, agent_id.
2. GET /api/deploy/deployments/<id>/events → lifecycle event'leri.
   Hangi adımda durdu? (pull / migration / candidate-start / health-check / promote)
3. Deploy 'pending' kalmışsa: agent_id'yi kontrol et.
   - agent_id == "" (central) → muvon-deployer çalışıyor mu? docker compose ps.
   - agent_id == "<id>" → o agent çalışıyor mu (GET /api/agents → last_seen_at)?
     AGENT_DEPLOYER_ENABLED=true mu? AGENT_DOCKER_SOCKET ulaşılabilir mi?
4. SSH varsa: docker logs <new-container> → app start fail mı?
5. Migration adımındaysa: GET /api/container-logs?container=<migration-container>
6. Health-check fail: backend'in /health endpoint'i 200 mü? curl içeriden:
   ssh <alias> "docker exec <container> wget -qO- localhost:<port>/health"
7. "decrypt env ... for component ..." event'i → MUVON_ENCRYPTION_KEY mismatch.
   Central muvon, muvon-deployer, edge agent'ın AGENT_ENCRYPTION_KEY'i hepsi aynı olmalı.
```

**Tipik bulgular**:
- ImagePull başarısız → docker registry auth (`/root/.docker/config.json` mount'ı yok mu kontrol).
- Migration container exit 1 → migration script bozuk veya DB connection hatalı.
- Health check timeout → app slow startup. Health check window küçük.
- Promote başarılı ama traffic alıyor olması gerekirken almıyor → route `managed_component_id` yanlış.
- "Components straddle hosts" → bir app'in servisleri farklı agent_id'lerde. Hepsini aynı yere taşı.
- "Component X is paused" → `PUT /api/deploy/projects/<slug>/components/<x>` body `{"paused":false}`.
- Deploy "pending" durmuyor ama edge'de hiç container açılmıyor → o agent'ın `AGENT_DEPLOYER_ENABLED`'i false veya Docker socket ulaşılamaz. Agent log: `deployer: enabled but docker socket unreachable; staying disabled`.

## 3) "Edge agent disconnected / kayboldu"

```
1. GET /api/agents → last_seen kolonu. Hangileri stale?
2. SSH ile agent host'a bağlan: systemctl status muvon-agent
3. Agent log: journalctl -u muvon-agent -n 200 --no-pager
4. Connection test: agent → central muvon HTTPS reach edebiliyor mu?
   ssh <agent-host> "curl -sf https://<central>/api/v1/agent/config -H 'Authorization: Bearer <agent-token>'"
5. Agent token revoke edildi mi? muvon.agent_tokens tablosu DB'de.
```

**Tipik bulgular**:
- Agent binary çökmüş → restart.
- Agent token revoke → yeniden enroll.
- Network → firewall, DNS, TLS cert problemi.
- Agent eski sürüm → `agent --version` ile kontrol, manuel upgrade.

## 4) "TLS cert problemi"

Önce iki status endpoint'iyle hızlı triage:
- `GET /api/hosts/{id}/dns-status` → DNS A kaydı beklenen IP'ye dönüyor mu?
  - `unresolved` = DNS henüz yayılmamış, bekle veya kullanıcı DNS panel'inden A kaydı eklemedi.
  - `stale` = DNS yanlış IP'ye gidiyor (eski host'a).
  - `no_target` = settings.public_ip set edilmemiş ve agent da yok — operatör eylemi gerek.
  - `wildcard` = `*.example.com` host'u, alt-domain başına ayrı doğrula.
- `GET /api/hosts/{id}/tls-status` → cert durumu (valid / expiring / expired / missing / off).

Senaryolar:
- "Cert expiring": `tls-status` → `days_left` küçük. `GET /api/tls/certificates` → tam liste.
- "Cert almıyor (yeni host)": önce DNS status, sonra `tls_mode`. `off` veya `manual` ise ACME hiç denenmez. `auto` ise:
  ```bash
  dig +short <host>
  curl -fsSL --max-time 5 ifconfig.me   # MUVON sunucu IP'si
  ```
  Eşleşmiyorsa: kullanıcıya DNS düzelt diye söyle.
- ACME challenge fail: Let's Encrypt rate limit (haftalık 50 cert/domain).
- "Cert var ama tarayıcı invalid diyor": chain eksik mi? GET /api/tls/certificates/<id> → cert detayı.
- Edge host TLS: `agent_id` set olan host'ta cert agent'ın kendisi ACME ile alıp central'a backup pushlar. Agent down ise yeni cert gelmez.

## 5) "Container log shipping çalışmıyor"

```
1. GET /api/system/health/ingest → ingest pipeline durumu.
2. GET /api/containers/<id>/logs/stream → SSE çalışıyor mu?
3. SSH: ls -la /var/lib/muvon/logship/   → spool dizini doluyor mu?
4. docker logs muvon-deployer --tail=200 | grep logship
5. dialog-siem container'ı sağlıklı mı: docker compose ps
```

**Tipik bulgular**:
- diaLOG down → spool birikiyor. diaLOG'u kaldır.
- Spool max byte aşıldı → eski container'ların log'u atıldı (config: `MUVON_DEPLOYER_LOGSHIP_SPOOL_MAX_BYTES`).
- logship disabled → `.env`'de `MUVON_DEPLOYER_LOGSHIP_ENABLED=false`.

## 6) "Alert gelmiyor / Slack mesaj yok"

```
1. GET /api/settings → alerting_enabled = true mu?
2. GET /api/alerts?limit=5 → alert üretiliyor mu?
3. POST /api/alerting/test/slack → manuel test (kullanıcıdan onay sonra)
4. dialog-siem log: docker logs dialog-siem | grep alert
5. Cooldown: alerting_cooldown_seconds (default 300) içinde aynı alert atlanır.
```

## 7) "Settings değişti ama uygulanmadı"

`POST /api/system/reload` çağrılmadı mı? Veya holder snapshot eski mi? Şüphe yoksa:
```bash
curl -sS -b "$CJ" -H "X-CSRF-Token: $CSRF" -X POST "$BASE/api/system/reload"
```

Sonra `GET /api/system/stats` ile uptime değişmediğini teyit et (reload = restart değil, sadece snapshot yenileme).

## 8) "Anormal trafik / olası saldırı"

```
1. GET /api/logs?status=403&since=15m → 403 spike?
2. GET /api/alerts → auth_brute, error_spike alarmları var mı?
3. /api/logs?q=.env veya /api/logs?path=.env → bot taramaları
4. DB doğrudan top-IP query (ssh varsa):
   SELECT client_ip, count(*) FROM dialog.http_logs
   WHERE timestamp > now() - interval '15 minutes'
   GROUP BY client_ip ORDER BY 2 DESC LIMIT 20;
5. Şüpheli IP varsa: kullanıcıya öner — firewall veya MUVON route'ta block.
```

**Önemli gözlem**: Bot'lar genelde `/app/.env`, `/.git/config`, `/wp-admin`, `/phpmyadmin` gibi path'leri tarar. Eğer **200 dönüyorsa** o path'ler — backend açık. MUVON proxy bunu blokleemiyor (legit route). Kullanıcıya not.

## 9) "Müşteri uygulaması (managed component) sorunu"

Bu skill MUVON'u biliyor, **müşteri uygulaması iç işleyişini bilmiyor**. Akış:
```
1. /api/containers → component status (running/restarting/exited)
2. /api/container-logs?component=<x>&limit=20 → uygulama log
3. SSH varsa: docker exec <container> /bin/sh → uygulama içine bağlan (kullanıcı onayıyla)
4. Müşteri repo URL'si: /api/deploy/projects/<slug> → source_repo
   Repo lokalde varsa Read/Grep, yoksa gh repo clone.
```

## 10) "MUVON çöktü / admin paneli açılmıyor"

```
1. SSH: docker compose -f /opt/muvon/docker-compose.yml ps
   → muvon container status?
2. docker compose logs muvon --tail=100
3. /api/system/health çağırılabiliyor mu (HTTPS dış)?
4. Postgres reach edilebiliyor mu? docker exec muvon-postgres pg_isready
5. Volume disk dolu mu? df -h
```

**Tipik bulgular**:
- DB volume disk dolu → log retention çalışmamış, manuel cleanup.
- Postgres crashed (OOM) → docker stats ile bellek izle.
- TLS cert path yanlış → `tls_cache` volume mount.
- Config holder paniği → docker logs muvon | grep -i panic.

## 11) "Komut gönderildi ama agent çalıştırmadı"

```
1. GET /api/agents/{id}/commands → son komut state'i ne?
   - pending → agent henüz çekmedi (uzun-poll açık mı? last_seen_at taze mi?)
   - dispatched → agent çekti ama result raporlamadı (handler bloklandı veya agent crashed)
   - failed → result.error ne diyor?
   - expired → sweeper temizledi (default TTL 5 dk); agent o sürede çekmedi.
2. GET /api/agents → hedef agent last_seen_at taze mi? Çevrimdışıysa anlamsız.
3. POST /api/agents/{id}/commands 503 alıyorsan: MUVON_ENCRYPTION_KEY boş (komut kanalı kapalı).
   ssh <central> "grep -q ^MUVON_ENCRYPTION_KEY /opt/muvon/.env && echo set || echo empty"
4. SSH ile agent'a bağlan: docker logs muvon-agent --tail=200 | grep -E 'command|poll'
   - "poll: no commands" = normal idle long-poll.
   - "poll: signature mismatch" = MUVON_ENCRYPTION_KEY ↔ AGENT_ENCRYPTION_KEY uyumsuz.
   - "command expired" = TTL doldu (agent geç çekti).
   - "command dedupe" = aynı ID iki kez teslim edildi (at-least-once delivery, sorun yok).
5. Komut çok eski mi? Sweeper 30 sn'de bir > 5 dk expired yapar; bunlar history'de "expired" görünür.
```

**Tipik bulgular**:
- Agent revoke edilmişti, yeniden enroll lazım (auth fail edip çıkıyor).
- AGENT_ENCRYPTION_KEY central'dakiyle eşleşmiyor → tüm komutlar `signature mismatch`. Her iki tarafı eşit set et.
- Agent docker socket'i kaybetmiş (`agent.restart` veya `container.restart` komutları sessiz başarısız oluyor) — pitfalls #27.
- `agent.set_log_level` TTL'i (`payload.ttl_seconds`) çok kısa girilmiş → debug log toparlanmadan auto-revert oldu. Daha uzun TTL ile yeniden gönder.

## 12) "System upgrade takıldı / SSE stream koptu"

```
1. POST /api/system/upgrade 409 alıyorsan: zaten upgrade çalışıyor (broker mutex).
   GET /api/system/upgrade/stream → mevcut akışa katıl, history replay görürsün.
2. SSE stream EOF olunca panik yok — helper container deployer'ı da recreate ediyor,
   bu beklenen davranış. UI "Sayfayı yenile" butonu göstermeli.
3. Sayfayı yenile, GET /api/system/version → çalışan binary digest'i değişti mi?
   GET /api/system/version/latest ile karşılaştır.
4. Hâlâ takılıysa SSH ile:
   ssh <central> "docker compose -f /opt/muvon/docker-compose.yml ps"
   → servisler "Up" mı? "Restarting"se bir tanesi ayağa kalkmıyor.
5. Helper container log: ssh <central> "docker ps -a --filter ancestor=docker:27-cli"
   → exited helper'ı bul, logs incele.
6. pg_dump alındı mı: ssh <central> "ls -lt /opt/muvon/backups/ | head -5"
7. Felaket senaryosu: .env'de VERSION'ı eski tag'e çevir + tekrar upgrade tetikle;
   ya da pg_dump yedeğinden manuel restore (bkz. README "Backup / restore").
```

**Tipik bulgular**:
- `pg_dump` 30+ saniyede tamamlanamadı → büyük DB, `take_backup=false` ile dene; ama bu durumda **manuel snapshot** al önce.
- Helper container `docker compose pull` aşamasında auth fail → `/root/.docker/config.json` mount eksik (compose'da `muvon-deployer` servisine mount edilmiş olmalı).
- Yeni image migration'ı fail → eski binary durmuş, yeni binary migration'da çıkıyor. `/api/system/health` 503; SSH ile postgres'e bağlan, son migration'ı incele.
- 503 alıyorsan: encryption key boş → command channel yok ama system upgrade ayrı endpoint, normalde çalışmalı. Versiyon endpoint'i 503 dönüyorsa deployer down (`docker compose ps`).

## Genel ipuçları

- **Önce dar bir time-window** kullan (son 15 dk). Yavaş query ve büyük response yorucu olur.
- **Tek pencerede 5'ten fazla endpoint çağırma** — sonuçları topla, sonra düşün, sonra devam.
- Her bulguyu **kaynakla** raporla: "GET /api/logs?status=500&since=1h → 47 satır, top path /api/auth".
- Bilmediğin bir alan görürsen: `Read internal/db/migrations.go` ve `grep`.
- Şüphede kal: kullanıcıya rapor et, aksiyon önerin sun, **kullanıcı onaylasın**.
