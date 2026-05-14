#!/usr/bin/env bash
# MUVON Kurulum + Güncelleme Scripti
#
# Tek script, iki rol:
#   • İlk kurulum  — .env yoksa interaktif olarak admin/şifre/MaxMind sorar
#   • Güncelleme   — .env varsa secret'ları korur, yalnız yeni satırları
#                    ekler, image pull + DB backup + compose up yapar
#
# Kullanım:
#   bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install.sh)
#   bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install.sh) --version v0.1.0
#
# Idempotent: tekrar çalıştırmak güvenli.
#
# Önerilen pattern: bash <(curl -fsSL .../install.sh) [--version vX.Y.Z]
# Process substitution stdin'i TTY'da bırakır; interactive read sorunsuz.

set -euo pipefail

INSTALL_DIR="${MUVON_DIR:-/opt/muvon}"
BRANCH="${MUVON_BRANCH:-main}"
RAW="https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/${BRANCH}"
STATUS_FILE="${INSTALL_DIR}/.install-status"
BACKUP_DIR="${INSTALL_DIR}/backups"

# --version X.Y.Z (veya vX.Y.Z) → compose dosyasındaki :latest'i bu tag ile değiştir.
TARGET_VERSION=""
while [ $# -gt 0 ]; do
  case "$1" in
    --version) TARGET_VERSION="${2:-}"; shift 2 ;;
    --version=*) TARGET_VERSION="${1#*=}"; shift ;;
    *) shift ;;
  esac
done
TARGET_VERSION="${TARGET_VERSION#v}"

# ── Status / log helpers ─────────────────────────────────────────────────
# SSH disconnect olsa bile süreç devam ederken durumu izlemek için
# /opt/muvon/.install-status dosyasına step|message|epoch yazarız.
# Tail edilebilir, parse edilebilir.
status() {
  local step="$1" msg="$2"
  mkdir -p "$INSTALL_DIR"
  printf '%s|%s|%s\n' "$step" "$msg" "$(date +%s)" >> "$STATUS_FILE"
  printf '  %s\n' "$msg"
}

fail() {
  status "FAIL" "$1"
  printf '\nHATA: %s\n' "$1" >&2
  exit 1
}

# curl | bash durumunda bile TTY'dan okuyabilmek için
_ask() {
  local prompt="$1" varname="$2" default="${3:-}"
  if [ -t 0 ]; then
    read -r -p "$prompt" "$varname"
  else
    read -r -p "$prompt" "$varname" </dev/tty
  fi
  if [ -z "${!varname}" ] && [ -n "$default" ]; then
    printf -v "$varname" '%s' "$default"
  fi
}

_ask_secret() {
  local prompt="$1" varname="$2"
  if [ -t 0 ]; then
    read -r -s -p "$prompt" "$varname"; echo
  else
    read -r -s -p "$prompt" "$varname" </dev/tty; echo
  fi
}

_ask_yes_no() {
  local prompt="$1" default="${2:-N}"
  local answer
  _ask "$prompt" answer "$default"
  case "$answer" in y|Y|yes|YES|Yes) return 0 ;; *) return 1 ;; esac
}

# .env satırını yazar/günceller. Üç-mod:
#   mode=set     : varsa overwrite, yoksa append (FORCE)
#   mode=upsert  : yalnız boşsa veya yoksa doldur (mevcut değeri KORUR)
#   mode=ensure  : yoksa append, varsa dokunma
_env_upsert() {
  local file="$1" key="$2" value="$3" mode="${4:-upsert}"
  if grep -qE "^${key}=" "$file"; then
    case "$mode" in
      set)
        # Overwrite — yalnız ihtiyaç olunca (örn. MUVON_ADMIN_DOMAIN değişti)
        sed -i.bak "s|^${key}=.*|${key}=${value}|" "$file" && rm -f "${file}.bak"
        ;;
      upsert)
        # Var ve boş değilse koru, boşsa doldur
        local current
        current=$(grep -E "^${key}=" "$file" | head -1 | cut -d= -f2-)
        if [ -z "$current" ]; then
          sed -i.bak "s|^${key}=.*|${key}=${value}|" "$file" && rm -f "${file}.bak"
        fi
        ;;
      ensure)
        : # already present, do nothing
        ;;
    esac
  else
    # Satır yok — sona ekle
    printf '%s=%s\n' "$key" "$value" >> "$file"
  fi
}

# ── Başlık ────────────────────────────────────────────────────────────────
echo ""
echo "  ███╗   ███╗██╗   ██╗██╗   ██╗ ██████╗ ███╗   ██╗"
echo "  ████╗ ████║██║   ██║██║   ██║██╔═══██╗████╗  ██║"
echo "  ██╔████╔██║██║   ██║██║   ██║██║   ██║██╔██╗ ██║"
echo "  ██║╚██╔╝██║██║   ██║╚██╗ ██╔╝██║   ██║██║╚██╗██║"
echo "  ██║ ╚═╝ ██║╚██████╔╝ ╚████╔╝ ╚██████╔╝██║ ╚████║"
echo "  ╚═╝     ╚═╝ ╚═════╝   ╚═══╝   ╚═════╝ ╚═╝  ╚═══╝"
echo ""

# ── Mod tespiti: ilk kurulum mu, update mı ───────────────────────────────
if [ -f "${INSTALL_DIR}/.env" ]; then
  MODE="update"
  echo "  Mod: Güncelleme (mevcut .env tespit edildi)"
  echo "  Kurulum dizini: $INSTALL_DIR"
else
  MODE="install"
  echo "  Mod: İlk kurulum"
  echo "  Kurulum dizini: $INSTALL_DIR"
fi
echo ""

# Status file'ı yeni run için ihtiyat olarak rotate et (eski log'u koru)
mkdir -p "$INSTALL_DIR"
if [ -f "$STATUS_FILE" ]; then
  mv "$STATUS_FILE" "${STATUS_FILE}.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
fi
status "START" "Mod: $MODE"

# ── Min requirements check (Sentry pattern) ──────────────────────────────
status "CHECK" "Sistem gereksinimleri kontrol ediliyor..."

# Bash sürümü
if [ "${BASH_VERSINFO:-0}" -lt 4 ]; then
  fail "Bash 4.0+ gerekli (bulunan: ${BASH_VERSION:-unknown})."
fi

# Port 80/443 sadece ilk kurulumda kontrol et (update'te zaten MUVON tutuyor)
if [ "$MODE" = "install" ]; then
  for PORT in 80 443; do
    if ss -tlnH "sport = :$PORT" 2>/dev/null | grep -q ":$PORT" || \
       lsof -i ":$PORT" -sTCP:LISTEN -t &>/dev/null 2>&1; then
      echo "HATA: Port $PORT meşgul. MUVON bu portu kullanıyor." >&2
      echo "      Çakışan servisi durdurun:"
      ss -tlnp "sport = :$PORT" 2>/dev/null || lsof -i ":$PORT" -sTCP:LISTEN 2>/dev/null || true
      fail "Port $PORT meşgul."
    fi
  done
fi

# Docker — yoksa kur
if ! command -v docker &>/dev/null; then
  status "DOCKER" "Docker bulunamadı, kuruluyor..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
fi
if ! docker compose version &>/dev/null 2>&1; then
  fail "'docker compose' v2 bulunamadı. Docker >= 24 gerekli."
fi

# Docker API version ≥ 1.43 (deployer image pull credentials için lazım)
DOCKER_API=$(docker version --format '{{.Server.APIVersion}}' 2>/dev/null || echo "0.0")
# Basit numeric compare — "1.43" >= "1.43"
if ! awk -v have="$DOCKER_API" -v need="1.43" 'BEGIN{ split(have,h,"."); split(need,n,"."); exit !(h[1]>n[1] || (h[1]==n[1] && h[2]>=n[2])) }'; then
  fail "Docker API $DOCKER_API çok eski; en az 1.43 gerekli (Docker ≥24)."
fi

# Disk alanı — en az 2 GiB
AVAIL_KB=$(df -k "$(dirname "$INSTALL_DIR")" | awk 'NR==2 {print $4}')
if [ "${AVAIL_KB:-0}" -lt 2000000 ]; then
  fail "$(dirname "$INSTALL_DIR") altında en az 2 GiB boş alan gerekli (mevcut: $((AVAIL_KB/1024)) MiB)."
fi

status "CHECK" "Tüm gereksinimler OK."

# ── Mod'a göre interaktif sorgu ──────────────────────────────────────────
SERVER_IP=$(curl -fsSL --max-time 5 -4 ifconfig.me 2>/dev/null \
  || curl -fsSL --max-time 5 ifconfig.me 2>/dev/null \
  || echo "<sunucu-ip>")

if [ "$MODE" = "install" ]; then
  echo ""
  echo "── Yapılandırma ──────────────────────────────────────────────────────"
  echo ""
  echo "  Bu sunucunun IP'si: $SERVER_IP"
  echo "  Admin domain için DNS A kaydı bu IP'ye yönlendirilmiş olmalı."
  echo "  Örn: muvon.example.com → $SERVER_IP"
  echo ""
  _ask "  Admin domain: " ADMIN_DOMAIN
  [ -z "$ADMIN_DOMAIN" ] && fail "Admin domain boş bırakılamaz."

  echo ""
  _ask "  Admin kullanıcı adı [admin]: " ADMIN_USER "admin"

  echo ""
  while true; do
    _ask_secret "  Admin şifresi (min 8 karakter): " ADMIN_PASS
    if [ ${#ADMIN_PASS} -lt 8 ]; then
      echo "  Şifre çok kısa, tekrar girin."
    else
      _ask_secret "  Admin şifresi (tekrar): " ADMIN_PASS2
      if [ "$ADMIN_PASS" != "$ADMIN_PASS2" ]; then
        echo "  Şifreler eşleşmiyor, tekrar girin."
      else
        break
      fi
    fi
  done

  echo ""
  echo "── GeoIP (isteğe bağlı) ──────────────────────────────────────────────"
  echo ""
  echo "  MaxMind GeoLite2-City — IP bazlı ülke/şehir bilgisi."
  echo "  Ücretsiz lisans: https://www.maxmind.com/en/geolite2/signup"
  echo "  Atlamak için Enter'a basın."
  echo ""
  _ask "  MaxMind Lisans Anahtarı: " MAXMIND_KEY
else
  # Update modu — kullanıcıdan en az şey iste
  echo ""
  echo "── Güncelleme planı ──────────────────────────────────────────────────"
  echo ""
  echo "  • Compose ve postgres yardımcı dosyaları yeniden indirilecek."
  echo "  • .env korunacak; yalnız yeni env satırları sona eklenecek."
  echo "  • PostgreSQL için pg_dump (-Fc) yedeği alınacak: $BACKUP_DIR/"
  echo "  • Image'lar pull edilip servisler restart edilecek."
  echo ""
  if [ -n "$TARGET_VERSION" ]; then
    echo "  Hedef versiyon: $TARGET_VERSION"
    echo ""
  fi
fi

echo ""
echo "── İşlem başlıyor ────────────────────────────────────────────────────"
echo ""

# ── Dosyalar — her seferinde taze indir ──────────────────────────────────
status "FILES" "Compose ve yardımcı dosyalar indiriliyor..."
mkdir -p "$INSTALL_DIR" "$BACKUP_DIR"
cd "$INSTALL_DIR"

EXISTING_PIN=""
if [ -f docker-compose.yml ]; then
  EXISTING_PIN=$(grep -oE 'ghcr\.io/[^:[:space:]]+:[^[:space:]"]+' docker-compose.yml | head -1 | awk -F: '{print $NF}')
fi
curl -fsSL "$RAW/docker-compose.yml"   -o docker-compose.yml
curl -fsSL "$RAW/.env.example"         -o .env.example

EFFECTIVE_PIN="${TARGET_VERSION:-$EXISTING_PIN}"
if [ -n "$EFFECTIVE_PIN" ] && [ "$EFFECTIVE_PIN" != "latest" ]; then
  sed -i -E "s|(ghcr\.io/[^:]+):latest|\1:$EFFECTIVE_PIN|g" docker-compose.yml
  status "PIN" "Image tag → :$EFFECTIVE_PIN"
fi
mkdir -p postgres
curl -fsSL "$RAW/postgres/Dockerfile"  -o postgres/Dockerfile
curl -fsSL "$RAW/postgres/init.sql"    -o postgres/init.sql

# CHANGELOG göster (varsa) — update modunda
if [ "$MODE" = "update" ]; then
  if curl -fsSL "$RAW/CHANGELOG.md" -o /tmp/muvon-changelog.md 2>/dev/null; then
    echo ""
    echo "── CHANGELOG son sürüm bölümü ────────────────────────────────────────"
    # İlk iki ## başlığı arasını (en yeni release) yazdır
    awk '/^## /{c++} c==1{print} c==2{exit}' /tmp/muvon-changelog.md | head -80
    echo "─────────────────────────────────────────────────────────────────────"
    rm -f /tmp/muvon-changelog.md
    echo ""
    if ! _ask_yes_no "  Devam edeyim mi? [y/N]: "; then
      status "ABORT" "Kullanıcı iptal etti."
      exit 0
    fi
  fi
fi

# ── .env oluştur veya merge et ───────────────────────────────────────────
status "ENV" ".env hazırlanıyor..."

if [ "$MODE" = "install" ]; then
  # İlk kurulum — example'dan başla, secret'ları üret
  cp .env.example .env
  PG_PASS=$(openssl rand -hex 32)
  JWT_SECRET=$(openssl rand -hex 32)
  ENC_KEY=$(openssl rand -hex 32)
  _env_upsert .env POSTGRES_PASSWORD     "$PG_PASS"      set
  _env_upsert .env MUVON_JWT_SECRET      "$JWT_SECRET"   set
  _env_upsert .env MUVON_ENCRYPTION_KEY  "$ENC_KEY"      set
  _env_upsert .env MUVON_ADMIN_DOMAIN    "$ADMIN_DOMAIN" set
else
  # Update — mevcut secret'lara DOKUNMA, eksik anahtarları ekle
  cp .env "${BACKUP_DIR}/.env.$(date +%Y%m%d-%H%M%S)"

  # Eksik secret'lar varsa üret (örn. ENCRYPTION_KEY ilk kurulumda
  # set edilmediyse — eski install.sh'ten kalmış olabilir).
  # MUVON_ENCRYPTION_KEY'i ASLA overwrite etme — encrypted veri var ise
  # kayıp olur.
  if ! grep -qE '^POSTGRES_PASSWORD=..' .env; then
    _env_upsert .env POSTGRES_PASSWORD "$(openssl rand -hex 32)" set
  fi
  if ! grep -qE '^MUVON_JWT_SECRET=..' .env; then
    _env_upsert .env MUVON_JWT_SECRET "$(openssl rand -hex 32)" set
  fi
  if ! grep -qE '^MUVON_ENCRYPTION_KEY=..' .env; then
    echo ""
    echo "  ⚠  Mevcut .env'de MUVON_ENCRYPTION_KEY boş veya yok."
    echo "     Yeni bir tane üretiliyor — eğer eski kurulumda secret"
    echo "     ayarlar veya component env secret'ları varsa OKUNAMAZ."
    echo ""
    _env_upsert .env MUVON_ENCRYPTION_KEY "$(openssl rand -hex 32)" set
  fi
fi

# .env.example'da olup .env'de olmayan satırları ekle (Coolify merge pattern'i)
# Yalnız "KEY=" formatındaki satırları (yorumları/boş satırları atla)
while IFS= read -r line; do
  case "$line" in
    \#*|"") continue ;;
  esac
  key="${line%%=*}"
  if [ -n "$key" ] && ! grep -qE "^${key}=" .env; then
    printf '%s\n' "$line" >> .env
    status "ENV" "Yeni env satırı eklendi: $key"
  fi
done < .env.example

# ── GeoIP (ilk kurulumda) ─────────────────────────────────────────────────
if [ "$MODE" = "install" ] && [ -n "$MAXMIND_KEY" ]; then
  status "GEOIP" "GeoLite2-City indiriliyor..."
  GEOIP_URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${MAXMIND_KEY}&suffix=tar.gz"
  if wget -q "$GEOIP_URL" -O geo.tar.gz 2>/dev/null; then
    tar -xzf geo.tar.gz --wildcards '*.mmdb' --strip-components=1
    if [ -f GeoLite2-City.mmdb ]; then
      docker volume create muvon_geoip 2>/dev/null || true
      docker run --rm \
        -v muvon_geoip:/data \
        -v "$INSTALL_DIR/GeoLite2-City.mmdb:/src/GeoLite2-City.mmdb:ro" \
        alpine sh -c "cp /src/GeoLite2-City.mmdb /data/GeoLite2-City.mmdb"
      rm -f geo.tar.gz GeoLite2-City.mmdb
      status "GEOIP" "Hazır. Admin panelinden etkinleştirin: geoip_enabled = true"
    else
      rm -f geo.tar.gz
      status "GEOIP" "mmdb dosyası bulunamadı, atlandı."
    fi
  else
    rm -f geo.tar.gz 2>/dev/null || true
    status "GEOIP" "İndirilemedi (lisans anahtarı hatalı?), atlandı."
  fi
fi

# ── Update modunda DB backup ─────────────────────────────────────────────
if [ "$MODE" = "update" ]; then
  if docker compose ps --status running --services 2>/dev/null | grep -q "^postgres$"; then
    status "BACKUP" "PostgreSQL yedeği alınıyor..."
    BACKUP_FILE="${BACKUP_DIR}/pgdata-$(date +%Y%m%d-%H%M%S).dump"
    if docker compose exec -T postgres pg_dump -Fc -U muvon -d muvon > "$BACKUP_FILE" 2>/dev/null; then
      status "BACKUP" "Yedek: $BACKUP_FILE ($(du -h "$BACKUP_FILE" | cut -f1))"
      # Son 5 yedeği tut, daha eskileri sil (rotation)
      ls -t "${BACKUP_DIR}"/pgdata-*.dump 2>/dev/null | tail -n +6 | xargs -r rm -f
    else
      rm -f "$BACKUP_FILE"
      status "BACKUP" "Yedek alınamadı (postgres ulaşılamaz olabilir) — devam ediliyor."
    fi
  fi
fi

# ── Image pull ───────────────────────────────────────────────────────────
status "PULL" "GHCR'dan image'lar çekiliyor..."
docker compose pull muvon dialog-siem muvon-deployer

if [ "$MODE" = "install" ]; then
  status "BUILD" "PostgreSQL image build ediliyor (ilk seferde ~2-3 dk)..."
  docker compose build postgres
fi

# ── Servisler ─────────────────────────────────────────────────────────────
status "UP" "Servisler başlatılıyor..."
docker compose up -d --wait --wait-timeout 120 || {
  # --wait timeout olduğunda compose hata verir ama servisler ayağa
  # kalkmış olabilir; logu sun ve devam et.
  status "UP" "Wait timeout — log'lara bakılıyor..."
  docker compose logs --tail=30
}

# ── Health check ─────────────────────────────────────────────────────────
status "HEALTH" "MUVON :9443/health bekleniyor..."
for i in $(seq 1 60); do
  HTTP_CODE=$(curl -fsSL -o /dev/null -w "%{http_code}" \
    --max-time 2 http://127.0.0.1:9443/health 2>/dev/null || echo "000")
  if [ "$HTTP_CODE" = "200" ]; then
    status "HEALTH" "Servis hazır (${i}s)."
    break
  fi
  if [ "$i" = "60" ]; then
    status "HEALTH" "Servis 60 saniyede hazır olmadı; log'a bakın:"
    docker compose logs --tail=20 muvon
  fi
  sleep 1
done

# ── İlk admin hesabı (yalnız ilk kurulumda) ──────────────────────────────
if [ "$MODE" = "install" ]; then
  status "ADMIN" "Admin hesabı oluşturuluyor..."

  JSON_BODY=$(printf '{"username":"%s","password":"%s"}' \
    "$(printf '%s' "$ADMIN_USER" | sed 's/["\\]/\\&/g')" \
    "$(printf '%s' "$ADMIN_PASS" | sed 's/["\\]/\\&/g')")

  SETUP=$(curl -fsSL -s -o /dev/null -w "%{http_code}" \
    -X POST http://127.0.0.1:9443/api/auth/setup \
    -H "Content-Type: application/json" \
    -d "$JSON_BODY" 2>/dev/null || echo "000")

  case "$SETUP" in
    200|201) status "ADMIN" "Admin hesabı oluşturuldu: $ADMIN_USER" ;;
    409)     status "ADMIN" "Admin hesabı zaten mevcut, atlandı." ;;
    *)
      echo ""
      echo "UYARI: Admin hesabı otomatik oluşturulamadı (HTTP $SETUP)."
      echo "       Aşağıdaki komutu manuel çalıştırın:"
      echo ""
      echo "  curl -X POST http://127.0.0.1:9443/api/auth/setup \\"
      echo "    -H 'Content-Type: application/json' \\"
      echo "    -d '{\"username\":\"${ADMIN_USER}\",\"password\":\"SifreniGir\"}'"
      echo ""
      ;;
  esac
fi

# Sürüm bilgisini status'a yaz
RUNNING_VERSION=$(docker compose exec -T muvon /usr/local/bin/app --version 2>/dev/null | head -1 || echo "unknown")
status "DONE" "Çalışan sürüm: $RUNNING_VERSION"

# ── Özet ──────────────────────────────────────────────────────────────────
ADMIN_DOMAIN_OUT=$(grep '^MUVON_ADMIN_DOMAIN=' .env | cut -d= -f2-)
VERSION_OUT=$(awk '/image:[[:space:]]*ghcr\.io\/.*\/muvon:/{n=split($NF,a,":"); print a[n]; exit}' docker-compose.yml)

echo ""
docker compose ps
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
if [ "$MODE" = "install" ]; then
echo "║  Kurulum tamamlandı!                                         ║"
else
echo "║  Güncelleme tamamlandı!                                      ║"
fi
echo "║                                                              ║"
printf "║  Admin paneli : https://%-37s║\n" "$ADMIN_DOMAIN_OUT"
printf "║  Image VERSION: %-45s║\n" "$VERSION_OUT"
printf "║  Çalışan sürüm: %-45s║\n" "$RUNNING_VERSION"
echo "║                                                              ║"
echo "║  Sonraki güncelleme: aynı komutu tekrar koştur               ║"
echo "║    bash <(curl -fsSL .../install.sh)                         ║"
echo "║                                                              ║"
echo "║  Üretim için sürümü pin'le:                                  ║"
echo "║    bash <(curl -fsSL .../install.sh) --version v0.1.0        ║"
echo "║                                                              ║"
echo "║  Hibrit topoloji: önce central, sonra her agent              ║"
echo "║  Forward-only migration — downgrade DESTEKLENMEZ             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
