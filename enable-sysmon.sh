#!/usr/bin/env bash
# Dua log Sysmon for Linux vao lab Wazuh (chay bang user lab, co sudo). Chay lai nhieu lan duoc.
# Sysmon ghi XML vao syslog voi program_name "sysmon". Container rootless khong doc duoc
# /var/log/syslog, nen rsyslog copy rieng event Sysmon sang /var/log/wazuh-lab/sysmon.log
# (thu muc da co ACL cho user lab, do install-rootless.sh tao).
set -euo pipefail

USER_NAME="$(id -un)"
die() { printf '[x] %s\n' "$*" >&2; exit 1; }

command -v sysmon >/dev/null || die "Chua cai Sysmon for Linux"
systemctl is-active --quiet sysmon || die "Service sysmon khong chay"
[ -d /var/log/wazuh-lab ] || die "Chua co /var/log/wazuh-lab, chay ./install-rootless.sh truoc"

RSYSLOG_USER="$(grep -hE '^\$PrivDropToUser' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | awk '{print $2}' | tail -1)"
RSYSLOG_USER="${RSYSLOG_USER:-root}"

echo "[+] rsyslog: copy event Sysmon sang /var/log/wazuh-lab/sysmon.log"
# Bo EventID 4 (state), 5 (ProcessTerminate), 16 (config change): nhieu ma khong co gia tri phat hien
sudo tee /etc/rsyslog.d/61-wazuh-lab-sysmon.conf >/dev/null <<'EOF'
# Lab Wazuh: event Sysmon for Linux cho agent rootless doc
if $programname == 'sysmon' and not re_match($msg, '<EventID>(4|5|16)</EventID>') then {
    action(type="omfile" file="/var/log/wazuh-lab/sysmon.log" fileCreateMode="0640")
}
EOF
sudo rsyslogd -N1 >/dev/null || die "Config rsyslog loi"

echo "[+] logrotate: xoay vong hang ngay, toi da 500MB, giu 2 ban"
sudo tee /etc/logrotate.d/wazuh-lab-sysmon >/dev/null <<EOF
/var/log/wazuh-lab/sysmon.log {
    su $RSYSLOG_USER adm
    daily
    maxsize 500M
    rotate 2
    compress
    delaycompress
    missingok
    notifempty
    create 0640 $RSYSLOG_USER adm
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
EOF
sudo systemctl restart rsyslog

for _ in $(seq 1 10); do [ -s /var/log/wazuh-lab/sysmon.log ] && break; sleep 1; done
if [ -r /var/log/wazuh-lab/sysmon.log ]; then
  echo "    /var/log/wazuh-lab/sysmon.log doc duoc ($(wc -l < /var/log/wazuh-lab/sysmon.log) dong)"
else
  die "$USER_NAME khong doc duoc /var/log/wazuh-lab/sysmon.log"
fi
echo "[+] Xong. Chay: docker compose up -d --force-recreate wazuh.manager wazuh.agent"
