#!/usr/bin/env bash
# Tao tai khoan dashboard cho nguoi khac: xem alert + them/sua rule, decoder, CDB list,
# restart manager de nap rule. Khong co quyen quan ly user, agent, ossec.conf.
#   ./add-rule-user.sh <ten>      (chay lai cung ten = dat lai password)
set -euo pipefail
cd "$(dirname "$0")"
[ $# -eq 1 ] || { echo "Dung: $0 <ten-user>"; exit 1; }
# Script Python chay trong container manager (co san INDEXER_PASSWORD, API_PASSWORD trong env)
docker compose exec -T -e NEW_USER="$1" wazuh.manager \
  /var/ossec/framework/python/bin/python3 - < scripts/add_rule_user.py
