#!/usr/bin/env bash
# MUVON Agent Kurulum + Güncelleme Scripti
#
# Tek script, iki rol:
#   • İlk kurulum  — .env yoksa interaktif olarak central URL/API key sorar
#   • Güncelleme   — .env varsa değerleri korur, yalnız yeni env satırlarını
#                    ekler, image pull + restart yapar
#
# Kullanım:
#   bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install-agent.sh)
#   bash <(curl -fsSL https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/main/install-agent.sh) --version v0.1.0
#
# Idempotent: tekrar çalıştırmak güvenli.

set -euo pipefail

INSTALL_DIR="${MUVON_AGENT_DIR:-/opt/muvon-agent}"
BRANCH="${MUVON_BRANCH:-main}"
RAW="https://raw.githubusercontent.com/SaidMuratOzdemir/MUVON/${BRANCH}"
STATUS_FILE="${INSTALL_DIR}/.install-status"
COMPOSE_FILE="${INSTALL_DIR}/docker-compose.agent.yml"

TARGET_VERSION=""
while [ $# -gt 0 ]; do
  case "$1" in
    --version) TARGET_VERSION="${2:-}"; shift 2 ;;
    --version=*) TARGET_VERSION="${1#*=}"; shift ;;
    *) shift ;;
  esac
done
TARGET_VERSION="${TARGET_VERSION#v}"

# ── Helpers ──────────────────────────────────────────────────────────────
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

_read() {
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

_read_secret() {
  local prompt="$1" varname="$2"
  if [ -t 0 ]; then
    read -r -s -p "$prompt" "$varname"; echo
  else
    read -r -s -p "$prompt" "$varname" </dev/tty; echo
  fi
}

_yn() {
  local prompt="$1" default="${2:-N}" answer
  _read "$prompt" answer "$default"
  case "$answer" in y|Y|yes|YES|Yes) return 0 ;; *) return 1 ;; esac
}

_env_upsert() {
  local file="$1" key="$2" value="$3" mode="${4:-upsert}"
  if grep -qE "^${key}=" "$file"; then
    case "$mode" in
      set)
        sed -i.bak "s|^${key}=.*|${key}=${value}|" "$file" && rm -f "${file}.bak"
        ;;
      upsert)
        local current
        current=$(grep -E "^${key}=" "$file" | head -1 | cut -d= -f2-)
        [ -z "$current" ] && { sed -i.bak "s|^${key}=.*|${key}=${value}|" "$file" && rm -f "${file}.bak"; }
        ;;
      ensure) : ;;
    esac
  else
    printf '%s=%s\n' "$key" "$value" >> "$file"
  fi
}

# Compose dosyasında Docker socket mount satırını aç (RW veya RO).
# Yorumlu satırı bulup başındaki "# " işaretini kaldırır.
_enable_socket_mount() {
  local mode="$1"  # "rw" veya "ro"
  local suffix=""
  [ "$mode" = "ro" ] && suffix=":ro"
  # Yorumlu pattern: "      # - /var/run/docker.sock:/var/run/docker.sock:ro"
  # Eğer zaten aktif (yorum yok) satır varsa dokunma.
  if grep -qE '^[[:space:]]+- /var/run/docker\.sock:/var/run/docker\.sock' "$COMPOSE_FILE"; then
    return 0
  fi
  sed -i.bak -E \
    "s|^([[:space:]]+)# - /var/run/docker\\.sock:/var/run/docker\\.sock:ro|\\1- /var/run/docker.sock:/var/run/docker.sock${suffix}|" \
    "$COMPOSE_FILE" && rm -f "${COMPOSE_FILE}.bak"
}

# ── Başlık + mod tespiti ─────────────────────────────────────────────────
echo ""
echo "── MUVON Agent ──────────────────────────────────────────────────────"
echo ""

if [ -f "${INSTALL_DIR}/.env" ]; then
  MODE="update"
  echo "  Mod: Güncelleme (mevcut .env tespit edildi)"
else
  MODE="install"
  echo "  Mod: İlk kurulum"
  echo ""
  echo "  Bu script agent makineyi merkezi MUVON sunucusuna bağlar."
  echo "  Devam etmeden önce:"
  echo "    1. Merkezi sunucudaki admin paneline giriş yapın"
  echo "    2. Agents → Yeni Agent ekleyin, API anahtarını kopyalayın"
fi
echo "  Kurulum dizini: $INSTALL_DIR"
echo ""

mkdir -p "$INSTALL_DIR"
[ -f "$STATUS_FILE" ] && mv "$STATUS_FILE" "${STATUS_FILE}.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
status "START" "Mod: $MODE"

# ── Docker kontrolü ──────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  status "DOCKER" "Docker bulunamadı, kuruluyor..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
fi
if ! docker compose version &>/dev/null 2>&1; then
  fail "'docker compose' (v2) bulunamadı. Docker >= 24 gerekli."
fi

# ── Mod'a göre giriş ─────────────────────────────────────────────────────
DEPLOYER_ENABLED="false"
ENC_KEY=""

if [ "$MODE" = "install" ]; then
  _read "    Merkezi MUVON URL'si (ör: https://muvon.example.com:9443): " CENTRAL_URL
  [ -z "$CENTRAL_URL" ] && fail "AGENT_CENTRAL_URL boş bırakılamaz."

  _read "    Agent API Key (admin panelinden): " API_KEY
  [ -z "$API_KEY" ] && fail "AGENT_API_KEY boş bırakılamaz."

  DEFAULT_HOST=$(echo "$CENTRAL_URL" | sed -E 's|https?://||' | cut -d: -f1)
  _read "    diaLOG log adresi [${DEFAULT_HOST}:9001] (atlamak için Enter): " LOG_ADDR "${DEFAULT_HOST}:9001"

  echo ""
  echo "── Embedded edge deployer (opsiyonel) ───────────────────────────────"
  echo ""
  echo "  Bu makinede müşteri uygulamalarının container'larını çalıştırmak"
  echo "  istiyor musun? Açarsan:"
  echo "    • Agent Docker socket'ine RW erişebilecek"
  echo "    • Merkezi 'Uzak Uygulamalar' sayfasından bu agent'a atanan"
  echo "      servisler burada deploy edilecek (image pull → run → health)."
  echo "    • Encryption key merkezdekiyle AYNI olmalı (secret env'leri"
  echo "      decrypt etmek için)."
  echo ""
  if _yn "  Edge deployer'ı aktif et? [y/N]: "; then
    DEPLOYER_ENABLED="true"
    echo ""
    echo "  Merkezi sunucudaki .env'den MUVON_ENCRYPTION_KEY değerini al"
    echo "  ve buraya yapıştır. Bu değer agent'larla central arasında AYNI"
    echo "  olmalı."
    echo ""
    while true; do
      _read_secret "  Encryption key (hex, 64 karakter): " ENC_KEY
      if [ -z "$ENC_KEY" ]; then
        echo "  Boş bırakılamaz."
      elif [ ${#ENC_KEY} -lt 32 ]; then
        echo "  Çok kısa (en az 32 karakter). Tekrar dene."
      else
        break
      fi
    done
  fi
else
  echo ""
  echo "── Güncelleme planı ──────────────────────────────────────────────────"
  echo ""
  echo "  • Compose dosyası yeniden indirilecek."
  echo "  • .env korunacak; yalnız yeni env satırları sona eklenecek."
  echo "  • Image pull edilip agent restart edilecek."
  echo ""
  if [ -n "$TARGET_VERSION" ]; then
    echo "  Hedef versiyon: $TARGET_VERSION"
    echo ""
  fi
fi

# ── Bağlantı testi (ilk kurulumda) ───────────────────────────────────────
if [ "$MODE" = "install" ]; then
  status "PING" "Merkezi sunucu bağlantısı test ediliyor..."
  if curl -fsSL --max-time 10 \
       -H "X-Api-Key: $API_KEY" \
       "$CENTRAL_URL/api/v1/agent/config" -o /dev/null 2>/dev/null; then
    status "PING" "Bağlantı başarılı."
  else
    echo ""
    echo "UYARI: Merkezi sunucuya bağlanılamadı."
    echo "       URL ve API Key'i kontrol edin, veya sunucunun :9443 portunu açın."
    if ! _yn "       Yine de devam edeyim mi? [y/N]: "; then
      fail "Kurulum iptal edildi."
    fi
  fi
fi

# ── Compose dosyası — her seferinde taze indir ───────────────────────────
status "FILES" "Compose dosyası indiriliyor..."
cd "$INSTALL_DIR"
EXISTING_PIN=""
if [ -f docker-compose.agent.yml ]; then
  EXISTING_PIN=$(grep -oE 'ghcr\.io/[^:[:space:]]+:[^[:space:]"]+' docker-compose.agent.yml | head -1 | awk -F: '{print $NF}')
fi
curl -fsSL "$RAW/docker-compose.agent.yml" -o docker-compose.agent.yml

EFFECTIVE_PIN="${TARGET_VERSION:-$EXISTING_PIN}"
if [ -n "$EFFECTIVE_PIN" ] && [ "$EFFECTIVE_PIN" != "latest" ]; then
  sed -i -E "s|(ghcr\.io/[^:]+):latest|\1:$EFFECTIVE_PIN|g" docker-compose.agent.yml
  status "PIN" "Image tag → :$EFFECTIVE_PIN"
fi

# ── .env oluştur veya merge et ───────────────────────────────────────────
status "ENV" ".env hazırlanıyor..."

if [ "$MODE" = "install" ]; then
  cat > .env <<EOF
AGENT_CENTRAL_URL=${CENTRAL_URL}
AGENT_API_KEY=${API_KEY}
AGENT_LOG_ADDR=${LOG_ADDR}

LOG_LEVEL=info

# Embedded edge deployer
AGENT_DEPLOYER_ENABLED=${DEPLOYER_ENABLED}
AGENT_DEPLOYER_POLL_MS=5000
AGENT_ENCRYPTION_KEY=${ENC_KEY}

# Fail-soft startup config cache (volume içinde tutulur)
# AGENT_CONFIG_CACHE=/var/lib/agent/config.json

# Container log shipping
AGENT_DOCKERWATCH_ENABLED=true
AGENT_DOCKERWATCH_MANAGED_ONLY=false
EOF
  status "ENV" ".env oluşturuldu."

  # Docker socket mount'ı doğru moda aç
  if [ "$DEPLOYER_ENABLED" = "true" ]; then
    _enable_socket_mount rw
    status "ENV" "Docker socket: RW (edge deployer için)"
  else
    _enable_socket_mount ro
    status "ENV" "Docker socket: RO (yalnız dockerwatch için)"
  fi
else
  # Update — mevcut .env'i yedekle, eksik satırları ekle
  cp .env ".env.$(date +%Y%m%d-%H%M%S).bak"

  # docker-compose.agent.yml'den varsayılan değerleri çıkar ve eksikleri
  # .env'e ekle. Mevcut hiçbir satır overwrite edilmez.
  # Yeni v0.1.0 ile gelen alanlar (manuel kontrol):
  _env_upsert .env AGENT_DEPLOYER_ENABLED       "false"  ensure
  _env_upsert .env AGENT_DEPLOYER_POLL_MS       "5000"   ensure
  _env_upsert .env AGENT_ENCRYPTION_KEY         ""       ensure
  _env_upsert .env AGENT_DOCKERWATCH_ENABLED    "true"   ensure
  _env_upsert .env AGENT_DOCKERWATCH_MANAGED_ONLY "false" ensure

  # Eski .env'de deployer aktif mi öğren — socket mount'ı koru
  if grep -qE '^AGENT_DEPLOYER_ENABLED=true' .env; then
    if grep -qE '^AGENT_ENCRYPTION_KEY=$' .env; then
      echo ""
      echo "  ⚠  AGENT_DEPLOYER_ENABLED=true ama AGENT_ENCRYPTION_KEY boş."
      echo "     Edge deployer secret env'leri decrypt edemez —"
      echo "     central'ın MUVON_ENCRYPTION_KEY'i ile aynı değeri set et."
      echo ""
    fi
    _enable_socket_mount rw
  else
    _enable_socket_mount ro
  fi
fi

# CHANGELOG göster (update'te)
if [ "$MODE" = "update" ]; then
  if curl -fsSL "$RAW/CHANGELOG.md" -o /tmp/muvon-changelog.md 2>/dev/null; then
    echo ""
    echo "── CHANGELOG son sürüm bölümü ────────────────────────────────────────"
    awk '/^## /{c++} c==1{print} c==2{exit}' /tmp/muvon-changelog.md | head -80
    echo "─────────────────────────────────────────────────────────────────────"
    rm -f /tmp/muvon-changelog.md
    echo ""
    if ! _yn "  Devam edeyim mi? [y/N]: "; then
      status "ABORT" "Kullanıcı iptal etti."
      exit 0
    fi
  fi
fi

# ── Image pull + restart ─────────────────────────────────────────────────
status "PULL" "Agent image çekiliyor..."
docker compose -f docker-compose.agent.yml pull

status "UP" "Agent başlatılıyor..."
docker compose -f docker-compose.agent.yml up -d --wait --wait-timeout 60 || {
  status "UP" "Wait timeout — log'lar:"
  docker compose -f docker-compose.agent.yml logs --tail=20
}

# Sürüm bilgisi
RUNNING_VERSION=$(docker compose -f docker-compose.agent.yml exec -T agent /usr/local/bin/app --version 2>/dev/null | head -1 || echo "unknown")
status "DONE" "Çalışan sürüm: $RUNNING_VERSION"

CENTRAL_URL_OUT=$(grep '^AGENT_CENTRAL_URL=' .env | cut -d= -f2-)
VERSION_OUT=$(awk '/image:[[:space:]]*ghcr\.io\/.*\/agent:/{n=split($NF,a,":"); print a[n]; exit}' docker-compose.agent.yml)
DEPLOYER_OUT=$(grep '^AGENT_DEPLOYER_ENABLED=' .env | cut -d= -f2-)

echo ""
docker compose -f docker-compose.agent.yml ps
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
if [ "$MODE" = "install" ]; then
echo "║  Agent kuruldu ve çalışıyor.                                 ║"
else
echo "║  Agent güncellendi.                                          ║"
fi
echo "║                                                              ║"
printf "║  Merkez       : %-45s║\n" "$CENTRAL_URL_OUT"
printf "║  Image VERSION: %-45s║\n" "$VERSION_OUT"
printf "║  Çalışan sürüm: %-45s║\n" "$RUNNING_VERSION"
printf "║  Edge deployer: %-45s║\n" "$DEPLOYER_OUT"
echo "║                                                              ║"
echo "║  Config merkezden SSE ile çekilir (sıfır downtime).          ║"
echo "║                                                              ║"
echo "║  Sonraki güncelleme: aynı komutu tekrar koştur               ║"
echo "║    bash <(curl -fsSL .../install-agent.sh)                   ║"
echo "║                                                              ║"
echo "║  Hibrit topoloji upgrade sırası:                             ║"
echo "║    1. Önce merkezi MUVON                                     ║"
echo "║    2. Sonra her agent (bu makine)                            ║"
echo "║  Aksi halde yeni agent eski central'ın olmayan endpoint'lere ║"
echo "║  istek atar ve 404 alır.                                     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
