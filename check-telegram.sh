#!/usr/bin/env bash
# Kiem tra nhanh Telegram: bot con trong group khong, group co bat Topics khong, va gui 1 tin test
# vao General + tung topic trong TELEGRAM_TOPICS. Doc token tu secrets/ (setup.sh tao), khong in token ra.
set -euo pipefail
cd "$(dirname "$0")"
exec python3 - <<'EOF'
import json, re, urllib.error, urllib.request
tok = open("secrets/telegram.token").read().strip()
env = dict(re.findall(r'^(\w+)=(.*)$', open(".env").read(), re.M))
chat = env["TELEGRAM_CHAT_ID"].strip('"')
topics_all = json.load(open("secrets/telegram_topics.json"))
def call(method, **p):
    req = urllib.request.Request(f"https://api.telegram.org/bot{tok}/{method}", data=json.dumps(p).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        return json.load(urllib.request.urlopen(req, timeout=10))
    except urllib.error.HTTPError as e:
        return json.load(e)
me = call("getMe")["result"]
print("bot:", "@" + me["username"])
def check(label, chat):
    g = call("getChat", chat_id=chat)
    print(f"[{label}] group:", g.get("result", {}).get("title"), "| topics:", g.get("result", {}).get("is_forum"), g.get("description", ""))
    m = call("getChatMember", chat_id=chat, user_id=me["id"])
    print(f"[{label}] bot trong group:", m.get("result", {}).get("status"), m.get("description", ""))
    for name, tid in [("General", None)] + list(topics_all.get(chat, {}).items()):
        p = {"chat_id": chat, "text": f"[test wazuh-lab] {label} topic {name}"}
        if tid:
            p["message_thread_id"] = tid
        r = call("sendMessage", **p)
        print(f"[{label}] {name:22} ->", "OK" if r.get("ok") else r.get("description"))
check("group 1", chat)
c2 = env.get("TELEGRAM2_CHAT_ID", "").strip('"')
if c2:
    check("group 2", c2)
EOF
