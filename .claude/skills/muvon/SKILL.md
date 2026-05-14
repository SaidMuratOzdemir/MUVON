---
name: muvon
description: Operate the MUVON edge gateway and diaLOG SIEM remotely via the admin API. Read hosts, routes, HTTP/container logs, alerts, deployments, managed components, agents, audit, settings and system health. Debug production issues, investigate 5xx spikes, check deploy status, inspect configuration. Use this skill whenever the user mentions MUVON, diaLOG, an edge gateway, a host/route/deploy/agent/alert/container, asks to investigate logs, troubleshoot a 5xx, examine a configuration, or take an action against a MUVON deployment.
---

# MUVON operatör skill'i

MUVON, dört Go servisinden oluşan bir edge gateway + SIEM + managed-deploy platformudur (bkz. `references/architecture.md`). Bu skill, Claude'un canlı bir MUVON kurulumuna uzaktan bağlanarak **durum okuması yapması, olay incelemesi yapması ve dikkatli mutasyon aksiyonları alması** için yazılmıştır.

## İlk hareket — her oturumda yapılacaklar

1. **Bağlam (context) doğrula**. Kullanıcı hangi MUVON kurulumundan bahsediyor? URL, admin kullanıcı adı, şifre nerede saklanıyor? Bunları **kullanıcıdan al** — bu skill credentials saklamaz.
2. **Login ol** ve cookie jar oluştur. `references/auth.md` adım adım anlatıyor.
3. Sorulan işi yapmadan önce hangi reference dosyasının ilgili olduğuna karar ver.

## Reference dosyaları

| Konu | Dosya |
|---|---|
| Mimari, servisler, şemalar | `references/architecture.md` |
| Login + cookie + CSRF dance + refresh rotation | `references/auth.md` |
| Endpoint envanteri, response formatları, SSE | `references/endpoints.md` |
| **Sürprizler ve dikkat noktaları** | `references/pitfalls.md` |
| Yıkıcı endpoint listesi + onay protokolü | `references/destructive-ops.md` |
| SSH + psql ile DB doğrudan oku, kaynak kod oku | `references/alternate-access.md` |
| Teşhis pattern'leri (5xx, deploy, agent, TLS) | `references/troubleshooting.md` |

Bu dosyaları **gerektiğinde** `Read` ile aç. Hepsini başta yükleme — token harcaması olur.

## Asla yapma listesi (kullanıcıdan açık onay almadıkça)

- DELETE içeren herhangi bir endpoint (`/api/hosts/{id}`, `/api/routes/{id}`, `/api/tls/certificates/{id}`, `/api/agents/{id}`, `/api/deploy/projects/{slug}`, `/api/deploy/projects/{slug}/components/{component}`).
- `POST /api/deploy/projects/{slug}/deploy` — production'a yeni image deploy eder.
- `POST /api/deploy/projects/{slug}/rollback` — yeni bir deployment kuyruğa eklenir, önceki başarılı release'i tekrar yayar.
- `POST /api/tls/certificates` — cert override.
- `PUT /api/settings/{key}` — özellikle `muvon_jwt_secret`, `muvon_encryption_key`, SMTP credentials.
- `PUT /api/deploy/projects/{slug}/components/{component}` ile `paused: true` — servis drain'e geçer, yeni deploy bloklanır.
- `POST /api/alerting/test/slack` / `POST /api/alerting/test/smtp` — gerçek Slack/email mesajı gider.
- `POST /api/system/upgrade` — tüm stack `docker compose pull && up -d` ile yeniden yaratılır; admin paneli ve proxy kısaca düşer.
- `POST /api/agents/{id}/commands` özellikle `kind` = `agent.restart` / `agent.revoke` / `agent.drain` / `agent.self_upgrade` — uzak edge'i durdurur, drain eder, kalıcı revoke eder veya image değiştirir.
- DB'ye doğrudan **yazma** (`INSERT`, `UPDATE`, `DELETE`). DB yazma audit'i, secret encryption'ı, config holder reload'unu atlar. Yazma her zaman API üzerinden.
- Secret değerleri (`.env`, `MUVON_JWT_SECRET`, `MUVON_ENCRYPTION_KEY`, `AGENT_ENCRYPTION_KEY`, SMTP password, agent API key'leri, component env secret'ları) **stdout veya kullanıcıya yansıtma**. Sadece "set/empty" durumunu söyle. Agent API anahtarı zaten sadece create response'unda bir kere döner — list'te artık masked bile değil, hiç yok.

Tam liste ve onay protokolü için → `references/destructive-ops.md`.

## Her yıkıcı çağrı öncesi disiplin

MUVON audit log'u **şu an** agent ve insan admin'i ayırt edemez (`admin_user: admin` her ikisi için aynı görünür). Bu nedenle:

1. Çağrı öncesi **stdout'a tek satır AGENT_ACTION damgası bas**:
   ```
   AGENT_ACTION: POST /api/deploy/projects/<slug>/deploy {"image_tag":"<tag>"}
   ```
2. Kullanıcıdan **açık "evet"** al.
3. Çağrıyı yap.
4. Sonucu özetle (kaç satır etkilendi, dönen status code).

Bu disiplini **her** mutasyon çağrısında uygula. Audit log koddan düzeltilene kadar tek izlenebilirlik bu.

## Kendi başına çözme — "kaynağa bak" prensibi

API'den hata mesajı belirsizse, endpoint bulamadıysan, response yapısı beklenmedikse → **kaynağa bak**. MUVON kod tabanı self-documenting:

- Lokalde repo varsa (`~/PycharmProjects/muvon` veya benzeri): `Read`/`Grep` doğrudan.
- Yoksa: `gh api repos/SaidMuratOzdemir/MUVON/contents/<path>?ref=main` veya `curl https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/<path>`.
- Endpoint listesi tek dosyada: `internal/admin/server.go`. Bir handler arıyorsan: `grep -n "handle<Name>" internal/admin/*.go`.

Detay → `references/alternate-access.md`.

## Çıktı tarzı

- **Kısa.** Çıktı oraganize, gereksiz tekrar yok.
- Tablolar, başlıklar ve `code` bloklarını kullan — kullanıcı tarayarak okur.
- Bulguları yansıtırken **kaynak göster**: hangi endpoint, hangi sorgu, hangi log timestamp.
- Yan etki/hata varsa son satıra "**Sonraki adım önerisi:**" diye somut bir hareket öner.

## Kısıtlamalar

- Bu skill **sadece okuma + dikkatli yazma** için. Otonom 24/7 izleme/aksiyon değil — kullanıcı çağırınca devreye gir.
- SSH erişimi varsayma. Kullanıcı `ssh <alias>` çalışıyor mu önce sor. Yoksa API yeter.
- Şifre, agent token, secret içerik dosyaya yazma. Kullanıcı promptunda gelen credentials sadece o oturumun cookie jar'ına işle.
