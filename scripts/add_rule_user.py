"""Tao tai khoan dashboard chi duoc xem alert va them/sua rule, decoder, CDB list.

Chay ben trong container wazuh.manager (add-rule-user.sh goi). Dung luon INDEXER_PASSWORD va
API_PASSWORD co san trong env cua container, nen khong phai truyen secret qua dong lenh.

Hai lop quyen:
  - Indexer (OpenSearch security): user dang nhap dashboard, chi doc duoc index wazuh-*.
  - Wazuh API (RBAC): dashboard goi API bang run_as voi authinfo cua user. Rule RBAC khop
    backend role "wazuh_rule_editor" -> role readonly + role rule_editor (sua rule, restart manager).
Chay lai voi cung ten thi dat lai password moi.
"""
import base64
import json
import os
import re
import secrets
import ssl
import sys
import urllib.error
import urllib.request

USER = os.environ.get("NEW_USER", "")
ROLE = "wazuh_rule_editor"
IDX = "https://wazuh.indexer:9200/_plugins/_security/api"
API = "https://localhost:55000"
IDX_CTX = ssl.create_default_context(cafile="/etc/ssl/root-ca.pem")
# API dung cert tu sinh cua manager, chi goi localhost trong chinh container nay
API_CTX = ssl._create_unverified_context()

if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,31}", USER):
    sys.exit("[x] Ten user: 3-32 ky tu a-z 0-9 . _ -")
if USER in ("admin", "kibanaserver", "wazuh", "wazuh-wui"):
    sys.exit(f"[x] '{USER}' la user he thong, chon ten khac")


def call(method, url, ctx, auth, body=None):
    headers = {"Content-Type": "application/json", "Authorization": auth}
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        sys.exit(f"[x] {method} {url.split('?')[0]} -> {e.code}: {e.read().decode()[:300]}")


# --- 1. Indexer: role, role mapping, user -------------------------------------------------
basic = "Basic " + base64.b64encode(f"admin:{os.environ['INDEXER_PASSWORD']}".encode()).decode()


def idx(method, path, body=None):
    return call(method, f"{IDX}/{path}", IDX_CTX, basic, body)


idx("PUT", f"roles/{ROLE}", {
    "description": "Wazuh lab: doc alert (wazuh-*), quyen sua rule nam o Wazuh API RBAC",
    "cluster_permissions": ["cluster_composite_ops_ro"],
    "index_permissions": [{"index_patterns": ["wazuh-*"],
                           "allowed_actions": ["read", "indices:admin/mappings/get"]}],
})
idx("PUT", f"rolesmapping/{ROLE}", {"backend_roles": [ROLE]})
# Wazuh API bat password co chu hoa, so, ky tu dac biet; giu cung kieu voi API_PASSWORD
password = "Wz1." + secrets.token_hex(12)
idx("PUT", f"internalusers/{USER}", {
    "password": password,
    # kibanauser -> role kibana_user co san: quyen toi thieu de dung dashboard
    "backend_roles": [ROLE, "kibanauser"],
    "description": "Wazuh lab: xem alert, them/sua rule",
})
print(f"[+] Indexer: user {USER}, role {ROLE}")

# --- 2. Wazuh API RBAC ----------------------------------------------------------------------
basic_api = "Basic " + base64.b64encode(f"wazuh-wui:{os.environ['API_PASSWORD']}".encode()).decode()
token = call("POST", f"{API}/security/user/authenticate", API_CTX, basic_api)["data"]["token"]
bearer = "Bearer " + token


def api(method, path, body=None):
    return call(method, f"{API}{path}", API_CTX, bearer, body)


def ensure(kind, name, body):
    """Tim theo ten, chua co thi tao. Tra ve id."""
    for it in api("GET", f"/security/{kind}?limit=500")["data"]["affected_items"]:
        if it["name"] == name:
            return it["id"]
    return api("POST", f"/security/{kind}", body)["data"]["affected_items"][0]["id"]


# Moi action chi nhan dung loai resource cua no (GET /security/actions), nen tach policy
policies = {
    "rule_editor_files": (["rules:read", "decoders:read", "lists:read"],
                          ["rule:file:*", "decoder:file:*", "list:file:*"]),
    "rule_editor_write": (["rules:update", "decoders:update", "lists:update"], ["*:*:*"]),
    # Dashboard kiem tra config (manager:read) truoc khi restart de nap rule moi
    "rule_editor_restart": (["manager:read", "manager:restart", "cluster:status"], ["*:*:*"]),
}
pol_ids = [ensure("policies", n, {"name": n, "policy": {"actions": a, "resources": r, "effect": "allow"}})
           for n, (a, r) in policies.items()]
role_id = ensure("roles", "rule_editor", {"name": "rule_editor"})
api("POST", f"/security/roles/{role_id}/policies?policy_ids={','.join(map(str, pol_ids))}")

readonly_id = ensure("roles", "readonly", {"name": "readonly"})
rule_id = ensure("rules", "wui_rule_editor", {"name": "wui_rule_editor",
                                              "rule": {"MATCH": {"backend_roles": [ROLE]}}})
for rid in (role_id, readonly_id):
    api("POST", f"/security/roles/{rid}/rules?rule_ids={rule_id}")
print("[+] Wazuh API: backend role wazuh_rule_editor -> role readonly + rule_editor")

print(f"""
Tai khoan dashboard:
  user:     {USER}
  password: {password}
""")
