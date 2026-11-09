#!/usr/bin/env bash
# Suricata (cai bang apt, chay bang root) -> Wazuh.
# eve.json mac dinh quyen 644 nen agent rootless doc truc tiep duoc, khong can rsyslog nhu Sysmon.
# Script nay: tai rule ET Open, kiem tra config, restart suricata, ban 1 alert test.
#   ./enable-suricata.sh          (chay bang user lab, co sudo; chay lai nhieu lan duoc)
set -euo pipefail
cd "$(dirname "$0")"
die() { echo "[x] $*" >&2; exit 1; }

LOG_DIR="${SURICATA_LOG_DIR:-/var/log/suricata}"
CONF=/etc/suricata/suricata.yaml

command -v suricata >/dev/null || die "Chua cai suricata (sudo apt install suricata)"
systemctl is-active --quiet suricata || die "Service suricata khong chay"
[ -r "$LOG_DIR/eve.json" ] || die "$(id -un) khong doc duoc $LOG_DIR/eve.json (can quyen 644 va thu muc 755)"

echo "[+] Tai rule ET Open (suricata-update)"
sudo suricata-update -q || die "suricata-update loi: server co ra duoc rules.emergingthreats.net khong?"
RULES=/var/lib/suricata/rules/suricata.rules
N=$(sudo grep -cE '^(alert|drop|reject|pass) ' "$RULES" || true)
echo "    $N rule dang bat trong $RULES"
[ "${N:-0}" -gt 0 ] || die "suricata.rules rong"

echo "[+] Kiem tra config"
if ! OUT=$(sudo suricata -T -c "$CONF" 2>&1); then
  echo "$OUT" | tail -5; die "suricata -T loi, chua restart"
fi

echo "[+] Restart suricata (ngung bat goi khoang 20-40s trong luc nap rule)"
sudo systemctl restart suricata
for _ in $(seq 1 90); do
  sudo grep -q 'Engine started' "$LOG_DIR/suricata.log" 2>/dev/null && break
  sleep 1
done
systemctl is-active --quiet suricata || die "Suricata khong len lai: sudo journalctl -u suricata -n 30"

echo "[+] Ban alert test (testmynids.org, rule 2100498)"
curl -s -o /dev/null --max-time 10 http://testmynids.org/uid/index.html || true
sleep 5
if grep -q '2100498' "$LOG_DIR/fast.log" 2>/dev/null; then
  echo "    OK: $(grep '2100498' "$LOG_DIR/fast.log" | tail -1 | cut -c1-160)"
else
  echo "[!] Chua thay alert test trong fast.log. Engine co the chua nap xong, doi 1 phut roi: tail $LOG_DIR/fast.log"
fi

echo "[+] Xong. Cho agent/manager nap config moi:"
echo "    docker compose up -d --force-recreate wazuh.manager wazuh.agent"
