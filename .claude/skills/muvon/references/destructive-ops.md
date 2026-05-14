# Yıkıcı endpoint'ler ve onay protokolü

Audit log şu an agent ↔ insan ayrımı yapmıyor. Yıkıcı operasyon yaparken **agent'ın sorumluluğu** disiplinli olmaktır.

## Onay protokolü — her yıkıcı çağrıdan önce

1. **Bağlam topla**: hangi kaynak (id/slug/domain), ne değişecek, geriye dönüş yolu var mı?
2. **AGENT_ACTION damgası bas** stdout'a — kullanıcı transcript'te görür:
   ```
   AGENT_ACTION: DELETE /api/hosts/12
   AGENT_ACTION: domain=foo.com (3 active route bağlı)
   AGENT_ACTION: rollback yolu: re-create host + routes manuel
   ```
3. **Açık onay iste**:
   > "Bu yıkıcı işlemi yapayım mı? (evet/hayır)"
4. Kullanıcı "evet" yazmadan **hareket etme**. "Sanırım", "tamam", "olabilir" gibi yarım onaylar yetmez.
5. Sonrası: çağrıyı yap, sonucu özetle, audit log'da göründüğünü teyit et (`GET /api/audit?limit=1`).

## Yüksek-tehlike endpoint'leri — ASLA onaysız

### Silme

| Endpoint | Etki | Rollback |
|---|---|---|
| `DELETE /api/hosts/{id}` | Host + bağlı route'lar yetim | Manuel re-create |
| `DELETE /api/routes/{id}` | Tek route, host etkilenmez | Manuel re-create |
| `DELETE /api/tls/certificates/{id}` | Cert silinir, host HTTPS düşer | `tls_mode=auto` ise yeniden ACME issue (otomatik); `manual` ise yeniden upload |
| `DELETE /api/agents/{id}` | Edge agent kaydı silinir, agent disconnect | Yeniden enroll (plaintext key bir kez döner) |
| `DELETE /api/deploy/projects/{slug}` | App + tüm servisler + release'ler + instance'lar cascade | Manuel re-create (env vars dahil hepsini yeniden gir) |
| `DELETE /api/deploy/projects/{slug}/components/{component}` | Servis silinir, instance'lar drain edilir | Manuel re-create (component aynı `agent_id` ile, ama yeni id alır) |

### Deploy

| Endpoint | Etki | Rollback |
|---|---|---|
| `POST /api/deploy/projects/{slug}/deploy` | Production'a yeni image (managed component) | Önceki tag ile yeniden deploy ya da rollback |
| `POST /api/deploy/projects/{slug}/rollback` | Yeni deployment kuyruğa eklenir; **önceki succeeded release'in image_ref'leri** kullanılır | `POST .../deploy` ile son tag'i tekrar yay |
| `POST /api/deploy/deployments/{id}/rerun` | Failed deploy'u yeniden çalıştır | Aynı tag dağıtılır, etki azalır |

Deploy çağrısı öncesi kontrol et:
- Image tag doğru mu? (typo deploy'u kıracak)
- Önceki deploy başarılı mıydı? (`GET /api/deploy/deployments?slug=<x>&limit=5`)
- Migration var mı? (`GET /api/deploy/projects/<slug>` → component'lerin `migration_command`'ı)
- Servis `paused` mi? Pause'lu servisler enqueue zamanı reddedilir — önce `PUT .../components/<x>` ile `paused: false` yap.
- Component `agent_id` doğru mu? Edge'deyse `AGENT_DEPLOYER_ENABLED=true` ile çalışan agent var mı? (`GET /api/agents`'in `last_seen_at` kolonu)

### Pause / resume (mutating, dikkat)

| Endpoint | Etki |
|---|---|
| `PUT /api/deploy/projects/{slug}/components/{component}` body `{"paused":true}` | Servisin instance'ları drain başlar, **yeni deploy enqueue reddedilir** |
| `PUT /api/deploy/projects/{slug}/components/{component}` body `{"paused":false}` | Servis tekrar deploy alabilir; ama mevcut instance'lar otomatik geri gelmez — yeni deploy şart |

### Settings (özellikle secret alanlar)

| Anahtar | Tehlike |
|---|---|
| `muvon_jwt_secret` | Değişirse tüm session'lar invalidate olur — herkes login ekranına |
| `muvon_encryption_key` | Değişirse mevcut şifreli settings **VE** component secret env'leri okunamaz hale gelir (kayıp). Üstelik central'ın `MUVON_ENCRYPTION_KEY`'i deployer ve edge agent'lardaki `AGENT_ENCRYPTION_KEY` ile eşleşmek zorunda; bir tarafı değişip diğerini unutursan container başlatılamaz |
| `alerting_smtp_password`, `alerting_slack_webhook` | Yanlış değer = alerting bozulur, sessiz başarısızlık |
| `public_ip` | DNS verification badge'i bu değere göre kıyas yapar; yanlış değer = "stale" yanılması |

`PUT /api/settings/{key}` her zaman onaylı.

### Cert override

`POST /api/tls/certificates` mevcut otomatik cert'i override eder. Önceki cert'i siler. Genelde kullanıcının elinde gerçek cert (corporate CA, wildcard cert) varsa yapılır.

### System upgrade

| Endpoint | Etki | Rollback |
|---|---|---|
| `POST /api/system/upgrade` body `{target_tag, take_backup}` | Tüm stack yeni image'larla recreate edilir; admin paneli ve proxy kısaca düşer (downtime ~saniyeler). `pg_dump -Fc` `/opt/muvon/backups/` altına alınır | `.env`'de `VERSION`'ı eskiye çevir + tekrar `/api/system/upgrade`; veya `pg_dump` yedeğinden manuel restore |

Çağrı öncesi:
- `GET /api/system/version` ile çalışan sürümü oku.
- `GET /api/system/version/latest` ile GHCR `:latest` digest'ini al.
- Aynı digest ise upgrade gereksiz — kullanıcıyı uyar.
- `take_backup=true` mı? **Default açık, kapatma.** (Coolify'ın "SKIP_BACKUP" zafiyetinden kaçınıyoruz.)
- `target_tag` doğru formatta mı? (`latest` / `v0` / `v0.1` / `v0.1.0` / commit SHA).
- Eşzamanlı upgrade engellenir (409). Stream EOF = "done" — helper container deployer'ı da recreate ettiği için bu beklenen davranış.

### Agent commands (central → edge)

`POST /api/agents/{id}/commands` her `kind` aynı API üzerinden gider; **kind'a göre risk profili farklı**.

| `kind` | Risk | Etki | Rollback |
|---|---|---|---|
| `agent.cache_flush` | düşük | Lokal cache temizler | Etkisiz — sonraki request cache'i yeniden doldurur |
| `agent.set_log_level` | düşük | `payload.ttl_seconds` süresince log seviyesini değiştirir, sonra auto-revert | TTL dolar veya yeni `set_log_level` |
| `cert.renew` | orta | `payload.domain` için cert cache'i invalidate eder; sonraki TLS handshake'te yeni cert alınır | ACME yeniden dener; rate limit (Let's Encrypt) dikkat |
| `container.restart` | orta | Belirtilen agent-side container'ı restart eder | Yeniden başlatır |
| **`agent.drain`** body `{enabled:true}` | **YIKICI** | Agent yeni request'leri 503 ile reddetmeye başlar | `{enabled:false}` ile aç |
| **`agent.restart`** | **YIKICI** | Agent binary `os.Exit(0)` yapar; supervisor (systemd / docker restart policy) yeniden başlatır | Supervisor yeniden başlatır (otomatik); manuel müdahale gerekmez |
| **`agent.self_upgrade`** | **YIKICI** | Image refresh + container recreate; downtime ~saniyeler | Yeni image bozuksa: önceki tag ile manuel deploy gerek |
| **`agent.revoke`** | **EN YIKICI** | Agent kalıcı durur (`os.Exit(1)`), central'da `is_active=false` set edilir. Crashloop yerine clean shutdown | Yeniden enroll (eski sil + yeni `POST /api/agents`); plaintext key sadece bir kez döner |

Komut çağrısı öncesi:
- `GET /api/agents` → hedef agent `last_seen_at` taze mi? Çevrimdışı agent'a komut göndermek anlamsız (5 dk sonra `expired` olur).
- `GET /api/agents/{id}/commands` → o agent'a son ne gönderildi? Mükerrer drain veya restart spam'i olmasın.
- `MUVON_ENCRYPTION_KEY` boşsa endpoint 503 döner — komut **dağıtılmaz**. Bu doğru davranış (yanlış imza ile asla teslim olmaz).
- At-least-once teslim: handler tarafında idempotent olduğu garanti. Yine de `restart`/`revoke`'u **birden fazla kez göndermeyin** — kullanıcı kafası karışır, history kirlenir.

## Orta tehlike — kullanıcıya bilgi ver, "evet" al

| Endpoint | Etki |
|---|---|
| `POST /api/alerts/{id}/acknowledge` | Geri alınmaz, ama sadece UI state |
| `POST /api/system/reload` | Yan etki: SSE push agent'lara |
| `POST /api/alerting/test/slack` | **Gerçek Slack mesajı gider** — channel'ı kirletir |
| `POST /api/alerting/test/smtp` | **Gerçek email gider** — inbox'ı kirletir |
| `POST /api/logs/{id}/star` | Sadece UI işareti |
| `PUT /api/logs/{id}/note` | Operatör notu — okuma bağlamı için |

## Düşük tehlike — bilgi yeterli

| Endpoint | Etki |
|---|---|
| `POST /api/hosts` | Yeni host oluşturur (yıkıcı değil, eklemekten ibaret) |
| `POST /api/hosts/{id}/routes` | Yeni route ekler |
| `PUT /api/hosts/{id}`, `PUT /api/routes/{id}` | Güncelleme (önceki değeri raporla) |

Yine de **PUT/UPDATE öncesi mevcut değeri oku**, gerekirse kullanıcıya "şunu şuna çeviriyorum" göster:
```
AGENT_ACTION: PUT /api/routes/3 — log_enabled: true → false
```

## Bir tek "asla" daha — DB'ye doğrudan yazma

SSH erişimi olsa bile DB'ye direkt `INSERT`/`UPDATE`/`DELETE` **YAPMA**:
- Audit log'a düşmez.
- Secret box'tan geçmez → encrypted alanlar plaintext gider, sonradan API'den okunamaz.
- Config holder reload tetiklenmez → yeni değer ayağa kalkmaz.
- FK constraint hatasında compose kırılır.

DB **sadece okuma** içindir (`references/alternate-access.md`).

## Dry-run yok — manuel ön-doğrulama yap

MUVON API'sinin dry-run/preview modu yok. Yıkıcı çağrı öncesi:
- Hedef kaynağı oku (GET ile detay)
- Etkilenen alt kaynakları listele
- Kullanıcıya özet sun, onay al

Misal — host silmeden önce:
```bash
muvon_api GET "/api/hosts/12"                # detay
muvon_api GET "/api/hosts/12/routes"         # bağlı route'lar
# stdout:
#   AGENT_ACTION: DELETE /api/hosts/12 (foo.com)
#   - 3 bağlı route da silinecek (yetim olmasın diye DB cascade)
#   - TLS cert silinmeyecek (manuel: DELETE /api/tls/certificates/<id>)
#   Devam edeyim mi?
```

## Toparlama checklist'i

Yıkıcı operasyon sonrası:
1. **HTTP code'u kontrol et** (200/201 = OK, 400/500 = düşünmeden raporla).
2. **Audit'i teyit et** (`GET /api/audit?limit=1` → son satır AGENT_ACTION'a uyuyor mu?).
3. **Servis sağlığı**: `GET /api/system/health` ok mu?
4. **Etkilenen alan**: deploy yaptıysan `GET /api/deploy/deployments?limit=1` ile durumu izle.
5. Özet 3 satırı geçmesin, kullanıcı tarayarak okusun.
