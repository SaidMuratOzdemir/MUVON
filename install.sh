#!/usr/bin/env bash
# MUVON Kurulum Scripti
# Kullanım: curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install.sh | bash
set -euo pipefail

INSTALL_DIR="${MUVON_DIR:-/opt/muvon}"
BRANCH="${MUVON_BRANCH:-main}"
RAW="https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/${BRANCH}"

# curl | bash durumunda bile TTY'dan okuyabilmek için
_ask() {
  local prompt="$1" varname="$2" default="${3:-}"
  if [ -t 0 ]; then
    read -r -p "$prompt" "$varname"
  else
    read -r -p "$prompt" "$varname" </dev/tty
  fi
  [ -z "${!varname}" ] && [ -n "$default" ] && printf -v "$varname" '%s' "$default"
}

_ask_secret() {
  local prompt="$1" varname="$2"
  if [ -t 0 ]; then
    read -r -s -p "$prompt" "$varname"; echo
  else
    read -r -s -p "$prompt" "$varname" </dev/tty; echo
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
echo "  Edge Gateway + WAF + SIEM — Kurulum"
echo "  Kurulum dizini: $INSTALL_DIR"
echo ""

# ── Tüm girdileri başta topla ─────────────────────────────────────────────
SERVER_IP=$(curl -fsSL --max-time 5 ifconfig.me 2>/dev/null || echo "<sunucu-ip>")

echo "── Yapılandırma ──────────────────────────────────────────────────────"
echo ""
echo "  Bu sunucunun IP'si: $SERVER_IP"
echo "  Admin domain için DNS A kaydı bu IP'ye yönlendirilmiş olmalı."
echo "  Örn: muvon.example.com → $SERVER_IP"
echo ""
_ask "  Admin domain: " ADMIN_DOMAIN
if [ -z "$ADMIN_DOMAIN" ]; then
  echo "HATA: Admin domain boş bırakılamaz." >&2; exit 1
fi

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

echo ""
echo "── Kurulum başlıyor ──────────────────────────────────────────────────"
echo ""

# ── Port kontrolü ─────────────────────────────────────────────────────────
for PORT in 80 443; do
  if ss -tlnH "sport = :$PORT" 2>/dev/null | grep -q ":$PORT" || \
     lsof -i ":$PORT" -sTCP:LISTEN -t &>/dev/null 2>&1; then
    echo "HATA: Port $PORT meşgul. MUVON bu portu kullanıyor." >&2
    echo "      Çakışan servisi durdurun:"
    ss -tlnp "sport = :$PORT" 2>/dev/null || lsof -i ":$PORT" -sTCP:LISTEN 2>/dev/null || true
    exit 1
  fi
done

# ── Docker ────────────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  echo "==> Docker kuruluyor..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
fi

if ! docker compose version &>/dev/null 2>&1; then
  echo "HATA: 'docker compose' v2 bulunamadı. Docker >= 24 gerekli." >&2; exit 1
fi

# ── Dosyalar ──────────────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo "==> Dosyalar indiriliyor..."
curl -fsSL "$RAW/docker-compose.yml"   -o docker-compose.yml
curl -fsSL "$RAW/.env.example"         -o .env.example
mkdir -p postgres
curl -fsSL "$RAW/postgres/Dockerfile"  -o postgres/Dockerfile
curl -fsSL "$RAW/postgres/init.sql"    -o postgres/init.sql

# ── .env ──────────────────────────────────────────────────────────────────
echo "==> Yapılandırma dosyası oluşturuluyor..."
cp .env.example .env

PG_PASS=$(openssl rand -hex 32)
JWT_SECRET=$(openssl rand -hex 32)
ENC_KEY=$(openssl rand -hex 32)

sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${PG_PASS}|"        .env
sed -i "s|^MUVON_JWT_SECRET=.*|MUVON_JWT_SECRET=${JWT_SECRET}|"        .env
sed -i "s|^MUVON_ENCRYPTION_KEY=.*|MUVON_ENCRYPTION_KEY=${ENC_KEY}|"  .env
sed -i "s|^MUVON_ADMIN_DOMAIN=.*|MUVON_ADMIN_DOMAIN=${ADMIN_DOMAIN}|" .env

# ── GeoIP ─────────────────────────────────────────────────────────────────
if [ -n "$MAXMIND_KEY" ]; then
  echo "==> GeoLite2-City indiriliyor..."
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
      echo "    GeoIP hazır. Admin panelinden etkinleştirin: geoip_enabled = true"
    else
      echo "UYARI: mmdb dosyası bulunamadı, GeoIP atlandı." >&2
      rm -f geo.tar.gz
    fi
  else
    echo "UYARI: GeoIP indirilemedi (lisans anahtarı hatalı?), atlandı." >&2
    rm -f geo.tar.gz 2>/dev/null || true
  fi
fi

# ── Servisler ─────────────────────────────────────────────────────────────
echo "==> GHCR'dan image'lar çekiliyor..."
docker compose pull muvon dialog-siem muwaf

echo "==> PostgreSQL image build ediliyor (ilk seferde ~2-3 dk)..."
docker compose build postgres

echo "==> Servisler başlatılıyor..."
docker compose up -d

# ── Servis ayağa kalkmasını bekle ─────────────────────────────────────────
echo "==> MUVON hazır olana kadar bekleniyor..."
for i in $(seq 1 60); do
  HTTP_CODE=$(curl -fsSL -o /dev/null -w "%{http_code}" \
    --max-time 2 http://127.0.0.1:9443/health 2>/dev/null || echo "000")
  if [ "$HTTP_CODE" = "200" ]; then
    echo "    Servis hazır. (${i}s)"
    break
  fi
  if [ "$i" = "60" ]; then
    echo "UYARI: Servis 60 saniyede hazır olmadı." >&2
    docker compose logs --tail=20
  fi
  sleep 1
done

# ── İlk admin hesabı ──────────────────────────────────────────────────────
echo "==> Admin hesabı oluşturuluyor..."

# JSON gövdesini güvenli şekilde oluştur (özel karakter içeren şifre desteği)
JSON_BODY=$(printf '{"username":"%s","password":"%s"}' \
  "$(printf '%s' "$ADMIN_USER" | sed 's/["\\]/\\&/g')" \
  "$(printf '%s' "$ADMIN_PASS" | sed 's/["\\]/\\&/g')")

SETUP=$(curl -fsSL -s -o /dev/null -w "%{http_code}" \
  -X POST http://127.0.0.1:9443/api/auth/setup \
  -H "Content-Type: application/json" \
  -d "$JSON_BODY" 2>/dev/null || echo "000")

if [ "$SETUP" = "200" ] || [ "$SETUP" = "201" ]; then
  echo "    Admin hesabı oluşturuldu: $ADMIN_USER"
elif [ "$SETUP" = "409" ]; then
  echo "    Admin hesabı zaten mevcut."
else
  echo ""
  echo "UYARI: Admin hesabı otomatik oluşturulamadı (HTTP $SETUP)."
  echo "       Aşağıdaki komutu manuel çalıştırın:"
  echo ""
  echo "  curl -X POST http://127.0.0.1:9443/api/auth/setup \\"
  echo "    -H 'Content-Type: application/json' \\"
  echo "    -d '{\"username\":\"${ADMIN_USER}\",\"password\":\"SifreniGir\"}'"
  echo ""
fi

# ── Özet ──────────────────────────────────────────────────────────────────
echo ""
docker compose ps
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Kurulum tamamlandı!                                         ║"
echo "║                                                              ║"
printf "║  Admin paneli : https://%-37s║\n" "$ADMIN_DOMAIN"
printf "║  Kullanıcı    : %-45s║\n" "$ADMIN_USER"
echo "║                                                              ║"
echo "║  TLS sertifikası ilk istekte Let's Encrypt'ten alınır.      ║"
echo "║                                                              ║"
echo "║  Güncelleme:                                                 ║"
echo "║    cd /opt/muvon                                             ║"
echo "║    docker compose pull && docker compose up -d               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
