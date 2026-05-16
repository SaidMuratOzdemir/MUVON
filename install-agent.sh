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
PUBLIC_IP_ARG=""
EXTRA_MOUNTS_ARG=""
DEPLOYER_TCP_BIND_ARG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --version) TARGET_VERSION="${2:-}"; shift 2 ;;
    --version=*) TARGET_VERSION="${1#*=}"; shift ;;
    --public-ip) PUBLIC_IP_ARG="${2:-}"; shift 2 ;;
    --public-ip=*) PUBLIC_IP_ARG="${1#*=}"; shift ;;
    --mount) EXTRA_MOUNTS_ARG="${EXTRA_MOUNTS_ARG} ${2:-}"; shift 2 ;;
    --mount=*) EXTRA_MOUNTS_ARG="${EXTRA_MOUNTS_ARG} ${1#*=}"; shift ;;
    --deployer-tcp-bind) DEPLOYER_TCP_BIND_ARG="${2:-}"; shift 2 ;;
    --deployer-tcp-bind=*) DEPLOYER_TCP_BIND_ARG="${1#*=}"; shift ;;
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
    read -r -p "$prompt" "$varname" || true
  elif [ -r /dev/tty ]; then
    read -r -p "$prompt" "$varname" </dev/tty || true
  fi
  if [ -z "${!varname-}" ] && [ -n "$default" ]; then
    printf -v "$varname" '%s' "$default"
  fi
}

_read_secret() {
  local prompt="$1" varname="$2"
  if [ -t 0 ]; then
    read -r -s -p "$prompt" "$varname" || true
    echo
  elif [ -r /dev/tty ]; then
    read -r -s -p "$prompt" "$varname" </dev/tty || true
    echo
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

# Private GHCR / Docker Hub için host root config'ini agent container'a
# ro mount. Sadece edge deployer enabled olduğunda gerek (anonymous pull
# yetiyorsa skip). Host'ta /root/.docker/config.json yoksa uyar ama
# satırı yine de açar — sonradan docker login yapılırsa otomatik etki.
_enable_docker_config_mount() {
  if grep -qE '^[[:space:]]+- /root/\.docker/config\.json:/root/\.docker/config\.json' "$COMPOSE_FILE"; then
    return 0
  fi
  sed -i.bak -E \
    "s|^([[:space:]]+)# - /root/\\.docker/config\\.json:/root/\\.docker/config\\.json:ro|\\1- /root/.docker/config.json:/root/.docker/config.json:ro|" \
    "$COMPOSE_FILE" && rm -f "${COMPOSE_FILE}.bak"
  if [ ! -f /root/.docker/config.json ]; then
    echo ""
    echo "  ⚠  /root/.docker/config.json yok. Private image pull için login gerek:"
    echo "       docker login ghcr.io -u <github-user>"
    echo "     (PAT scope: read:packages)"
    echo ""
  fi
}

# Operator env files convention: /opt/envfiles altındaki tüm env file'lar
# agent'a ro mount edilir. Central muvon-deployer ile simetrik. install
# zamanı dizini oluşturur (yoksa) ve mount satırını açar.
_enable_envfiles_mount() {
  if grep -qE '^[[:space:]]+- /opt/envfiles:/opt/envfiles' "$COMPOSE_FILE"; then
    return 0
  fi
  mkdir -p /opt/envfiles
  chmod 755 /opt/envfiles
  sed -i.bak -E \
    "s|^([[:space:]]+)# - /opt/envfiles:/opt/envfiles:ro|\\1- /opt/envfiles:/opt/envfiles:ro|" \
    "$COMPOSE_FILE" && rm -f "${COMPOSE_FILE}.bak"
}

# Operator-defined extra mounts. Boşluklu liste, her elemanı agent
# container'a ro bind mount eder (host:container aynı path). Convention
# /opt/envfiles yetmediğinde — örn /opt/<app>/secrets gibi mevcut bir
# dizini agent'a tanıtmak için. State .env'de tutulur, her install-agent.sh
# çalıştığında compose'a yeniden uygulanır.
#
# $1: boşluklu host yolları listesi (örn "/opt/tatilji /opt/another")
_apply_extra_mounts() {
  local paths="$1"
  [ -z "$paths" ] && return 0
  for raw in $paths; do
    local p
    p="$(echo "$raw" | tr -d '[:space:]')"
    [ -z "$p" ] && continue
    [ ! -e "$p" ] && echo "  ⚠  Ek mount yolu yok (yine de eklendi): $p"
    if grep -qE "^[[:space:]]+- ${p}:${p}" "$COMPOSE_FILE"; then
      continue
    fi
    # docker.sock satırının altına insert. Anchor sabit, yine de "g" yok.
    sed -i.bak -E \
      "/^[[:space:]]+- \\/var\\/run\\/docker\\.sock:/a\\
      - ${p}:${p}:ro" \
      "$COMPOSE_FILE" && rm -f "${COMPOSE_FILE}.bak"
  done
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

  # Public IP — DNS verification için central'a bildirilir. Operatör --public-ip
  # ile override edebilir; yoksa ifconfig.me'den auto-detect, hata olursa boş.
  if [ -n "$PUBLIC_IP_ARG" ]; then
    PUBLIC_IP="$PUBLIC_IP_ARG"
  else
    PUBLIC_IP="$(curl -fsS --max-time 5 -4 https://ifconfig.me 2>/dev/null | tr -d '[:space:]' || true)"
  fi
  _read "    Bu agent'ın public IP'si [${PUBLIC_IP:-auto-detect başarısız}] (Enter ile onayla, değiştirmek için yaz): " PUBLIC_IP "$PUBLIC_IP"

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

    # Ek host mount yolları — operatörün kendi yapısı /opt/envfiles
    # convention'ı dışında bir yerdeyse (örn /opt/tatilji/secrets). agent
    # container bu yolları ro mount eder ki embedded deployer
    # env_file_path veya mounts referansı açabilsin.
    if [ -n "$EXTRA_MOUNTS_ARG" ]; then
      EXTRA_MOUNTS="$EXTRA_MOUNTS_ARG"
    else
      echo ""
      echo "  Ek host yollarını agent'a mount edebilirsin (env_file_path veya"
      echo "  managed component mounts için). Boşluklu liste, boş bırakırsan"
      echo "  yalnız /opt/envfiles convention mount'u açık olur."
      _read "  Ek mount yolları (örn '/opt/tatilji /opt/another'): " EXTRA_MOUNTS
    fi

    # Canlı container log tail — central bu portu (gRPC) çağırarak
    # docker logs --follow akışını UI'ya köprüler. Yetkilendirme
    # AGENT_ENCRYPTION_KEY'den HKDF ile türetilir; key olmadan
    # listener kalkmaz.
    if [ -n "$DEPLOYER_TCP_BIND_ARG" ]; then
      DEPLOYER_TCP_BIND="$DEPLOYER_TCP_BIND_ARG"
    else
      echo ""
      echo "  Canlı container log tail için merkez'in bu agent'a ulaşacağı"
      echo "  host:port. Üç tipik senaryo:"
      echo ""
      echo "    1) İç ağ (private network / VPC / mesh):"
      echo "       <private-ip>:9100  (örn provider-içi RFC1918 adresi,"
      echo "       Tailscale/Wireguard mesh IP'si, AWS/GCP VPC subnet IP'si)"
      echo "       → Önerilen. Public yüzey sıfır."
      echo ""
      echo "    2) Public IP + güvenlik duvarı:"
      echo "       0.0.0.0:9100  (veya çıplak 9100)"
      echo "       → Provider firewall'unda (Hetzner Cloud FW / AWS Security"
      echo "       Group / iptables / nftables / vs) yalnız merkez'in IP'sine"
      echo "       9100/tcp izin ver. Token zaten zorunlu; yine de defansif"
      echo "       derinlik için kapatılı tut."
      echo ""
      echo "    3) Erişimsiz:"
      echo "       Boş bırak → live tail bu agent için kapalı kalır;"
      echo "       History sekmesi (dialog üzerinden) yine çalışır."
      echo ""
      _read "  Deployer TCP bind [9100]: " DEPLOYER_TCP_BIND "9100"
    fi
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
AGENT_PUBLIC_IP=${PUBLIC_IP}
MUVON_AGENT_DIR=${INSTALL_DIR}
AGENT_EXTRA_MOUNTS=${EXTRA_MOUNTS:-}

LOG_LEVEL=info

# Embedded edge deployer
AGENT_DEPLOYER_ENABLED=${DEPLOYER_ENABLED}
AGENT_DEPLOYER_POLL_MS=5000
AGENT_ENCRYPTION_KEY=${ENC_KEY}
# Canlı container log tail için merkez'in dial edeceği port.
# AGENT_DEPLOYER_TCP_BIND iki şekil alabilir:
#   "<host>:9100" → host-side bind tek interface'e (örn private IP).
#   "9100"        → tüm interface'lere (0.0.0.0:9100). Public yüzeyi
#                    olan host'ta provider firewall'unda 9100/tcp'yi
#                    yalnız merkez'in IP'sine izin ver.
# Central UI → Agents → bu agent'ın "Deployer addr" alanı bu değeri
# (host:port halini) bilmeli — yoksa routing açılamaz.
AGENT_DEPLOYER_TCP_BIND=${DEPLOYER_TCP_BIND}

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
    _enable_docker_config_mount
    _enable_envfiles_mount
    _apply_extra_mounts "${EXTRA_MOUNTS:-}"
    status "ENV" "Docker socket: RW (edge deployer için) + registry creds + /opt/envfiles${EXTRA_MOUNTS:+ + ek mountlar:$EXTRA_MOUNTS}"
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
  # v0.1.20: self_upgrade helper container needs host path of compose dir
  _env_upsert .env MUVON_AGENT_DIR              "$INSTALL_DIR" ensure
  # v0.1.22: operator-defined extra host mounts
  _env_upsert .env AGENT_EXTRA_MOUNTS           ""             ensure
  # --mount flag verilmişse mevcut değeri override et (additive değil; flag
  # birden çok kez kullanılabilir, hepsi tek string'e toplandı).
  if [ -n "$EXTRA_MOUNTS_ARG" ]; then
    _env_upsert .env AGENT_EXTRA_MOUNTS         "$EXTRA_MOUNTS_ARG" set
  fi
  # v0.1.30: deployer TCP bind for live container-log tail. Empty
  # default means docker compose falls back to "9100" (= 0.0.0.0:9100).
  _env_upsert .env AGENT_DEPLOYER_TCP_BIND      ""             ensure
  if [ -n "$DEPLOYER_TCP_BIND_ARG" ]; then
    _env_upsert .env AGENT_DEPLOYER_TCP_BIND    "$DEPLOYER_TCP_BIND_ARG" set
  fi

  # v0.1.13: public IP self-report. Boşsa auto-detect dene; başarısızsa boş bırak.
  if ! grep -qE '^AGENT_PUBLIC_IP=' .env; then
    DETECTED_IP=""
    if [ -n "$PUBLIC_IP_ARG" ]; then
      DETECTED_IP="$PUBLIC_IP_ARG"
    else
      DETECTED_IP="$(curl -fsS --max-time 5 -4 https://ifconfig.me 2>/dev/null | tr -d '[:space:]' || true)"
    fi
    _env_upsert .env AGENT_PUBLIC_IP "$DETECTED_IP" ensure
    [ -n "$DETECTED_IP" ] && status "ENV" "AGENT_PUBLIC_IP otomatik tespit edildi: $DETECTED_IP"
  elif [ -n "$PUBLIC_IP_ARG" ]; then
    # Operatör --public-ip ile override istiyorsa mevcut değeri değiştir
    _env_upsert .env AGENT_PUBLIC_IP "$PUBLIC_IP_ARG" set
    status "ENV" "AGENT_PUBLIC_IP override: $PUBLIC_IP_ARG"
  fi

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
    _enable_docker_config_mount
    _enable_envfiles_mount
    # .env'deki AGENT_EXTRA_MOUNTS state'ini her güncellemede compose'a uygula —
    # compose dosyası yeniden indiriliyor, mount satırları her seferinde silinir.
    EXISTING_EXTRA=$(grep '^AGENT_EXTRA_MOUNTS=' .env | cut -d= -f2- || true)
    _apply_extra_mounts "$EXISTING_EXTRA"
  else
    _enable_socket_mount ro
  fi
fi

# CHANGELOG göster (update'te). Interaktif TTY varsa onay sor; SSH pipe
# (curl | bash) altında otomatik devam — operatör script'i çalıştırdıysa
# zaten kabul etmiş demektir.
if [ "$MODE" = "update" ]; then
  if curl -fsSL "$RAW/CHANGELOG.md" -o /tmp/muvon-changelog.md 2>/dev/null; then
    echo ""
    echo "── CHANGELOG son sürüm bölümü ────────────────────────────────────────"
    awk '/^## /{c++} c==1{print} c==2{exit}' /tmp/muvon-changelog.md | head -80
    echo "─────────────────────────────────────────────────────────────────────"
    rm -f /tmp/muvon-changelog.md
    echo ""
    if [ -t 0 ] || [ -r /dev/tty ]; then
      if ! _yn "  Devam edeyim mi? [y/N]: "; then
        status "ABORT" "Kullanıcı iptal etti."
        exit 0
      fi
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
