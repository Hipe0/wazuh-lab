#!/usr/bin/env python3
# Gui alert Wazuh vao chat/group Zalo qua Zalo Bot API (bot-api.zaloplatforms.com).
# integratord goi: custom-zalo <alert_file> <api_key=chat_id> <hook_url=https://bot-api.zaloplatforms.com>
# Token bot doc tu TOKEN_FILE, khong de trong ossec.conf: ai co quyen manager:read tren Wazuh API
# (ke ca role readonly) deu doc duoc ossec.conf qua dashboard.
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request

LOG_FILE = "/var/ossec/logs/integrations.log"
MAX_TEXT = 2000  # gioi han text cua sendMessage
MAX_LOG = 500
# CA bundle cua host (compose mount vao). Mang co SSL inspection thi CA cua proxy chi nam
# trong trust store cua host, Python cua Wazuh khong biet -> CERTIFICATE_VERIFY_FAILED.
HOST_CA = "/etc/ssl/host-ca-bundle.crt"
TOKEN_FILE = "/run/secrets/zalo_token"

CORAZA_RE = re.compile(r'\[id "(\d+)"\].*?\[msg "([^"]*)"\].*?\[data "([^"]*)"\]')
SKIP_RULES = {"949110", "980170", "980130"}  # rule tong hop anomaly score, khong co payload
SYSMON_FIELDS = [
    ("eventid", "EventID"), ("user", "User"), ("image", "Image"), ("commandline", "CommandLine"),
    ("parentimage", "Parent"), ("parentcommandline", "ParentCmd"),
    ("destinationip", "DstIP"), ("destinationport", "DstPort"), ("targetfilename", "File"),
]


def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"custom-zalo: {msg}\n")


def get(d, path, default=None):
    for k in path.split("."):
        if not isinstance(d, dict) or k not in d:
            return default
        d = d[k]
    return d


def coraza_matches(full_log, limit=4):
    """Lay (id, msg, data) cac rule CRS da match tu audit log Coraza."""
    try:
        messages = json.loads(full_log).get("messages") or []
    except (ValueError, AttributeError):
        return []
    out = []
    for m in messages:
        hit = CORAZA_RE.search(m.get("error_message", ""))
        if hit and hit.group(1) not in SKIP_RULES:
            out.append(hit.groups())
    return out[:limit]


def build_message(alert):
    # Gui text thuong (khong parse_mode) cho chac, khoi lo escape HTML/Markdown
    rule = alert.get("rule", {})
    level = rule.get("level", 0)
    icon = "🔴" if level >= 12 else "🟠" if level >= 10 else "🟡"
    lines = [
        f"{icon} WAZUH ALERT | level {level}",
        f"Rule: {rule.get('id', '?')} - {rule.get('description', '')}",
        f"Agent: {get(alert, 'agent.name', '?')} ({get(alert, 'agent.ip', '-')})",
        f"Time: {alert.get('timestamp', '')}",
    ]
    srcip = get(alert, "data.srcip") or get(alert, "data.transaction.client_ip")
    if srcip:
        lines.append(f"Src IP: {srcip}")
    user = get(alert, "data.dstuser") or get(alert, "data.srcuser")
    if user:
        lines.append(f"User: {user}")
    uri = get(alert, "data.transaction.request.uri")
    if uri:
        method = get(alert, "data.transaction.request.method", "")
        lines.append(f"Request: {method} {uri[:300]}")
    groups = rule.get("groups")
    if groups:
        lines.append(f"Groups: {', '.join(groups)}")
    full_log = alert.get("full_log")
    sysmon = get(alert, "data.sysmon")
    if isinstance(sysmon, dict):
        # Log Sysmon la XML dai, cat 500 ky tu chi con header <System>: in field da decode
        for key, label in SYSMON_FIELDS:
            if sysmon.get(key) not in (None, "", "-"):
                lines.append(f"{label}: {str(sysmon[key])[:300]}")
    elif full_log and get(alert, "data.transaction"):
        for rid, msg, data in coraza_matches(full_log):
            lines.append(f"- CRS {rid}: {msg}\n  {data[:200]}")
    elif full_log:
        lines.append(f"Log: {full_log[:MAX_LOG]}")
    text = "\n".join(lines)
    return text if len(text) <= MAX_TEXT else text[: MAX_TEXT - 3] + "..."


def main():
    if len(sys.argv) < 4:
        log(f"thieu tham so ({len(sys.argv) - 1})")
        sys.exit(1)
    alert_file, chat_id, hook_url = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(alert_file) as f:
        alert = json.load(f)

    body = json.dumps({"chat_id": chat_id, "text": build_message(alert)}).encode()
    url = hook_url
    # hook_url cu co san /bot<token>/sendMessage thi dung nguyen
    if "/sendMessage" not in hook_url and os.path.isfile(TOKEN_FILE):
        with open(TOKEN_FILE) as f:
            url = f"{hook_url.rstrip('/')}/bot{f.read().strip()}/sendMessage"
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        ctx = ssl.create_default_context(cafile=HOST_CA) if os.path.isfile(HOST_CA) else None
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as err:
        # Khong ghi url vao log vi chua bot token
        log(f"Zalo tra HTTP {err.code}: {err.read()[:300]!r}")
        sys.exit(1)
    except Exception as err:
        log(f"loi gui Zalo: {type(err).__name__}: {err}")
        sys.exit(1)
    # Zalo co the tra HTTP 200 nhung ok=false (sai chat_id, bot khong o trong group...)
    try:
        data = json.loads(raw)
    except ValueError:
        log(f"Zalo tra ve khong phai JSON: {raw[:300]!r}")
        sys.exit(1)
    if not data.get("ok"):
        log(f"Zalo tu choi: error_code={data.get('error_code')} description={data.get('description')!r}")
        sys.exit(1)


if __name__ == "__main__":
    main()
