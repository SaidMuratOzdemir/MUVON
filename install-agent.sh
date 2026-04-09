#!/usr/bin/env bash
# MUVON Agent Kurulum Scripti
# Kullanım: curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install-agent.sh | bash
set -euo pipefail

INSTALL_DIR="${MUVON_AGENT_DIR:-/opt/muvon-agent}"
RAW="https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/${MUVON_BRANCH:-main}"

# pipe ile çalışırken /dev/tty üzerinden kullanıcı girişi al
_read() {
  local prompt="$1" varname="$2" default="${3:-}"
  if [ -t 0 ]; then
    read -r -p "$prompt" "$varname"
  else
    read -r -p "$prompt" "$varname" </dev/tty
  fi
  # boş girişte default uygula
  if [ -z "${!varname}" ] && [ -n "$default" ]; then
    printf -v "$varname" '%s' "$default"
  fi
}

echo "==> MUVON Agent Kurulumu"
echo "    Kurulum dizini: $INSTALL_DIR"
echo ""
echo "    Bu script agent makineyi merkezi MUVON sunucusuna bağlar."
echo "    Devam etmeden önce:"
echo "      1. Ana makinenin admin paneline giriş yapın"
echo "      2. Ayarlar → Agents → Yeni API Key oluşturun"
echo ""

# ── Docker kontrolü ──────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  echo "==> Docker bulunamadı, kuruluyor..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
fi

if ! docker compose version &>/dev/null 2>&1; then
  echo "HATA: 'docker compose' (v2) bulunamadı. Docker >= 24 gerekli." >&2
  exit 1
fi

# ── Gerekli bilgileri iste ────────────────────────────────────────────────
_read "    Merkezi MUVON URL'si (ör: https://muvon.example.com:9443): " CENTRAL_URL
if [ -z "$CENTRAL_URL" ]; then
  echo "HATA: AGENT_CENTRAL_URL boş bırakılamaz." >&2
  exit 1
fi

_read "    Agent API Key (admin panelinden): " API_KEY
if [ -z "$API_KEY" ]; then
  echo "HATA: AGENT_API_KEY boş bırakılamaz." >&2
  exit 1
fi

# LOG_ADDR için merkezi sunucunun host'unu varsayılan olarak öner
DEFAULT_HOST=$(echo "$CENTRAL_URL" | sed -E 's|https?://||' | cut -d: -f1)
_read "    diaLOG log adresi [${DEFAULT_HOST}:9001] (atlamak için Enter): " LOG_ADDR "${DEFAULT_HOST}:9001"

echo ""

# ── Bağlantı testi ────────────────────────────────────────────────────────
echo "==> Merkezi sunucu bağlantısı test ediliyor..."
if curl -fsSL --max-time 10 \
     -H "X-Api-Key: $API_KEY" \
     "$CENTRAL_URL/api/v1/agent/config" -o /dev/null 2>/dev/null; then
  echo "    Bağlantı başarılı."
else
  echo ""
  echo "UYARI: Merkezi sunucuya bağlanılamadı."
  echo "       URL ve API Key'i kontrol edin, veya sunucunun :9443 portunu açın."
  echo "       Devam etmek istiyor musunuz? (y/N)"
  _read "" CONFIRM
  if [[ ! "$CONFIRM" =~ ^[yY]$ ]]; then
    exit 1
  fi
fi

# ── Dizin ve dosyalar ────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo "==> Compose dosyaları indiriliyor..."
curl -fsSL "$RAW/docker-compose.agent.yml" -o docker-compose.agent.yml

# ── .env oluştur ──────────────────────────────────────────────────────────
cat > .env <<EOF
GITHUB_REPO=SaidMuratOzdemir/MUVON
VERSION=latest

AGENT_CENTRAL_URL=${CENTRAL_URL}
AGENT_API_KEY=${API_KEY}
AGENT_LOG_ADDR=${LOG_ADDR}

LOG_LEVEL=info
EOF

echo "==> .env oluşturuldu."

# ── Image çek ve başlat ───────────────────────────────────────────────────
echo "==> Agent image çekiliyor..."
docker compose -f docker-compose.agent.yml pull

echo "==> Agent başlatılıyor..."
docker compose -f docker-compose.agent.yml up -d

echo ""
echo "==> Durum:"
docker compose -f docker-compose.agent.yml ps

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  MUVON Agent çalışıyor!                                      ║"
echo "║                                                              ║"
echo "║  Merkezi sunucu: $CENTRAL_URL"
echo "║                                                              ║"
echo "║  Agent konfigürasyonu otomatik olarak merkezi sunucudan     ║"
echo "║  çekilir. Admin panelinde host/route değişikliği yapınca    ║"
echo "║  bu agent anında güncellenir (SSE, sıfır downtime).         ║"
echo "║                                                              ║"
echo "║  Güncelleme:                                                 ║"
echo "║    cd $INSTALL_DIR"
echo "║    docker compose -f docker-compose.agent.yml pull          ║"
echo "║    docker compose -f docker-compose.agent.yml up -d         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
