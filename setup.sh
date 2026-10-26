#!/usr/bin/env bash
# Chuan bi lab: tao .env (secret = openssl rand -hex), cert indexer, hash user indexer,
# render ossec.conf cua manager. Chay lai bao nhieu lan cung duoc, khong ghi de secret cu.
set -euo pipefail
cd "$(dirname "$0")"

hex() { openssl rand -hex "${1:-16}"; }

# 1. .env
if [ ! -f .env ]; then
  echo "[+] Tao .env voi secret random (openssl rand -hex)"
  cat > .env <<ENV
WAZUH_VERSION=4.14.9

# --- Secret (openssl rand -hex). Doi sau lan chay dau thi phai 'docker compose down -v' ---
INDEXER_PASSWORD=$(hex 16)
DASHBOARD_PASSWORD=$(hex 16)
# Wazuh API bat buoc co chu hoa + so + ky tu dac biet nen them tien to 'Wz1.' truoc chuoi hex
API_PASSWORD=Wz1.$(hex 16)
ENROLLMENT_PASSWORD=$(hex 16)
CLUSTER_KEY=$(hex 16)

# --- Zalo Bot (dien token roi chay lai ./setup.sh) ---
ZALO_BOT_TOKEN=
ZALO_CHAT_ID=zgr-8a45b1cc3fa3d6fd8fb2
ZALO_MIN_LEVEL=7

# --- WAF ---
WAF_MODE=DetectionOnly
WAF_HTTP_PORT=8080
WAF_UPSTREAM=http://backend:8080

# --- Dashboard (rootless khong mo duoc port < 1024) ---
DASHBOARD_PORT=8443

# --- Agent ---
# Thu muc chua auth.log. Rootless: /var/log/wazuh-lab (install-rootless.sh tao). Rootful: /var/log
AUTH_LOG_DIR=/var/log/wazuh-lab
AGENT_NAME=lab-host
ENV
  chmod 600 .env
fi

# .env tao tu ban cu (Telegram) thi bo sung bien Zalo
if ! grep -q '^ZALO_CHAT_ID=' .env; then
  echo "[+] Them bien Zalo vao .env"
  printf '\n# --- Zalo Bot (dien token roi chay lai ./setup.sh) ---\nZALO_BOT_TOKEN=\nZALO_CHAT_ID=zgr-8a45b1cc3fa3d6fd8fb2\nZALO_MIN_LEVEL=7\n' >> .env
fi

set -a; . ./.env; set +a

# 2. Cert TLS cho indexer/manager/dashboard (tu ky bang openssl, DN khop voi wazuh.indexer.yml)
CERT_DIR=config/wazuh_indexer_ssl_certs
if [ ! -f "$CERT_DIR/root-ca.pem" ]; then
  echo "[+] Sinh cert bang openssl"
  mkdir -p "$CERT_DIR"
  SUBJ_BASE="/C=US/L=California/O=Wazuh/OU=Wazuh"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$CERT_DIR/root-ca.key" 2>/dev/null
  openssl req -x509 -new -key "$CERT_DIR/root-ca.key" -sha256 -days 3650 \
    -subj "$SUBJ_BASE/CN=root-ca" -out "$CERT_DIR/root-ca.pem"
  for node in admin wazuh.indexer wazuh.manager wazuh.dashboard; do
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$CERT_DIR/$node-key.pem" 2>/dev/null
    openssl req -new -key "$CERT_DIR/$node-key.pem" -subj "$SUBJ_BASE/CN=$node" -out "$CERT_DIR/$node.csr"
    printf 'subjectAltName=DNS:%s\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\n' "$node" > "$CERT_DIR/$node.ext"
    openssl x509 -req -in "$CERT_DIR/$node.csr" -CA "$CERT_DIR/root-ca.pem" -CAkey "$CERT_DIR/root-ca.key" \
      -CAcreateserial -days 3650 -sha256 -extfile "$CERT_DIR/$node.ext" -out "$CERT_DIR/$node.pem" 2>/dev/null
    rm -f "$CERT_DIR/$node.csr" "$CERT_DIR/$node.ext"
  done
  cp "$CERT_DIR/root-ca.pem" "$CERT_DIR/root-ca-manager.pem"
  # indexer/dashboard chay bang uid 1000 nen phai doc duoc key; lab nen de 644
  chmod 644 "$CERT_DIR"/*.pem
  chmod 600 "$CERT_DIR/root-ca.key"
fi

# 3. internal_users.yml voi bcrypt hash cua password trong .env
if [ ! -f config/wazuh_indexer/internal_users.yml ]; then
  echo "[+] Hash password indexer"
  bcrypt_hash() {
    docker run --rm --entrypoint bash -e JAVA_HOME=/usr/share/wazuh-indexer/jdk "wazuh/wazuh-indexer:${WAZUH_VERSION}" \
      /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$1" 2>/dev/null | tail -n1
  }
  ADMIN_HASH=$(bcrypt_hash "$INDEXER_PASSWORD")
  KS_HASH=$(bcrypt_hash "$DASHBOARD_PASSWORD")
  cat > config/wazuh_indexer/internal_users.yml <<YML
---
_meta:
  type: "internalusers"
  config_version: 2

admin:
  hash: "${ADMIN_HASH}"
  reserved: true
  backend_roles:
  - "admin"
  description: "Admin user"

kibanaserver:
  hash: "${KS_HASH}"
  reserved: true
  description: "Dashboard server user"
YML
fi

# 4. ossec.conf manager + mat khau enrollment
if [ -z "${ZALO_BOT_TOKEN:-}" ] || [ -z "${ZALO_CHAT_ID:-}" ]; then
  echo "[!] Chua co ZALO_BOT_TOKEN / ZALO_CHAT_ID trong .env: alert se khong ve Zalo"
fi
# Chua co token thi bo han khoi <integration> de manager khong goi Zalo voi URL rong
STRIP_INT=()
[ -z "${ZALO_BOT_TOKEN:-}" ] || [ -z "${ZALO_CHAT_ID:-}" ] && STRIP_INT=(-e '/<integration>/,/<\/integration>/d')
sed "${STRIP_INT[@]}" \
    -e "s|__ZALO_BOT_TOKEN__|${ZALO_BOT_TOKEN:-}|" \
    -e "s|__ZALO_CHAT_ID__|${ZALO_CHAT_ID:-}|" \
    -e "s|__ZALO_MIN_LEVEL__|${ZALO_MIN_LEVEL:-7}|" \
    -e "s|__CLUSTER_KEY__|${CLUSTER_KEY}|" \
    config/wazuh_cluster/wazuh_manager.conf.tpl > config/wazuh_cluster/wazuh_manager.conf
printf '%s\n' "$ENROLLMENT_PASSWORD" > config/wazuh_cluster/authd.pass
chmod 600 config/wazuh_cluster/wazuh_manager.conf config/wazuh_cluster/authd.pass
# integratord chay bang user wazuh, file mount vao la root:root nen phai cho other doc+chay
chmod 755 config/wazuh_cluster/integrations/custom-zalo config/wazuh_cluster/integrations/custom-zalo.py

if [ ! -r "$AUTH_LOG_DIR/auth.log" ]; then
  echo "[!] Khong doc duoc $AUTH_LOG_DIR/auth.log. Rootless: chay ./install-rootless.sh. Rootful: dat AUTH_LOG_DIR=/var/log va cai rsyslog"
fi

echo "[+] Xong. Chay: docker compose up -d --build"
