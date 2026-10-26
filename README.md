# Lab Wazuh + Coraza WAF + alert Zalo (docker compose)

Một VM chạy hết: Wazuh single-node (manager, indexer, dashboard), 1 Wazuh agent, Caddy + OWASP Coraza (CRS v4) làm WAF, app demo `go-httpbin` đứng sau WAF. Alert từ level 7 trở lên được bắn về Zalo qua Zalo Bot API.

```
attacker ──HTTP──> waf (Caddy+Coraza :8080) ──> backend (httpbin)
                     │ audit.log (JSON, volume coraza_logs)
host /var/log/auth.log ┐
                       ├─> wazuh.agent ──1514──> wazuh.manager ──> wazuh.indexer <── wazuh.dashboard (:443)
coraza_logs ───────────┘                          └─ integratord ──> Zalo Bot API ──> chat/group
```

Đã chạy thử toàn bộ stack trên cả Docker rootful lẫn rootless (Wazuh 4.14.9, Caddy 2.11.7, coraza-caddy v2.6.2, CRS 4.25.0): agent enroll được, sshd fail/brute force và SQLi/XSS/LFI qua WAF đều ra alert, tin nhắn Zalo gửi đúng format API (test bằng mock server, sandbox không gọi được bot-api.zaloplatforms.com).

## 0. Chuẩn bị server (Docker rootless)

Lab chạy bằng **Docker rootless**: dockerd chạy bằng user thường, root trong container chỉ là user đó trên host. Container bị chiếm thì kẻ tấn công cũng không có root trên server.

**Bước 1: kiểm tra server, không sửa gì.** SSH thẳng vào bằng user sẽ chạy lab (đừng `sudo su - user`, sẽ mất `XDG_RUNTIME_DIR` và systemd --user):
```bash
./preflight.sh        # in [OK]/[WARN]/[FAIL] + lệnh sửa, lưu log preflight-<host>-<time>.log
```
Nó kiểm tra: OS/kernel/RAM/disk, user có sudo, systemd --user, linger, subuid/subgid, user namespace, AppArmor (Ubuntu 23.10+ chặn userns), `/dev/net/tun`, cgroup, các tool (`uidmap`, `slirp4netns`, `acl`, `rsyslog`...), Docker rootful có đang chạy không, `vm.max_map_count`, port 1514/1515/8080/8443/9200/55000 có bị chiếm không, UFW, kết nối ra Docker Hub / proxy.golang.org / bot-api.zaloplatforms.com, NTP.

**Bước 2: cài.** Gửi log preflight cho tao xem trước nếu có FAIL lạ, rồi:
```bash
./install-rootless.sh                    # dừng lại nếu thấy Docker rootful đang chạy
./install-rootless.sh --disable-rootful  # server không dùng Docker rootful nữa: tắt docker.service
./install-rootless.sh --keep-rootful     # còn container rootful đang dùng: chạy song song
```
Script dùng sudo để: cài gói thiếu (`uidmap dbus-user-session slirp4netns fuse-overlayfs acl rsyslog`...), thêm repo Docker + `docker-ce-rootless-extras`, thêm subuid/subgid nếu thiếu, tạo AppArmor profile cho rootlesskit (Ubuntu 24.04), ghi `vm.max_map_count=262144` vào `/etc/sysctl.d/99-wazuh-lab.conf`, `loginctl enable-linger`. Phần chạy bằng user: `dockerd-rootless-setuptool.sh install`, override port driver `slirp4netns`, `docker context use rootless`. Chạy lại nhiều lần được.

Mấy chỗ khác rootful, script đã xử lý sẵn:
- **auth.log**: file là `root:adm 640`, container rootless không đọc được. Script cho rsyslog ghi thêm một bản vào `/var/log/wazuh-lab/auth.log`, thư mục có ACL đọc cho user lab (ACL mặc định nên file mới sau logrotate vẫn đọc được). Compose mount **cả thư mục** chứ không mount một file, vì logrotate tạo inode mới và mount một file sẽ kẹt ở file cũ (đã test: rotate xong agent vẫn đọc tiếp).
- **IP nguồn**: port driver mặc định `builtin` làm container chỉ thấy IP gateway. Script chuyển sang `slirp4netns` nên WAF/Wazuh thấy IP thật của client (đã test). Riêng request từ chính server vào `127.0.0.1` sẽ hiện `10.0.2.2`.
- **Port < 1024**: user thường không mở được, nên dashboard để `8443` (`DASHBOARD_PORT` trong `.env`). Compose cũng bỏ `ulimits` (rootless không nâng được memlock/nofile), container kế thừa `LimitNOFILE=infinity` của docker.service.
- **Firewall**: rootless không tự chọc lỗ iptables như rootful, UFW đang bật thì phải `sudo ufw allow 8080,8443,1514,1515/tcp`.

Chạy rootful vẫn được: đặt `AUTH_LOG_DIR=/var/log` trong `.env`.

## 1. Bot Zalo

Dùng [Zalo Bot Platform](https://bot.zaloplatforms.com): API kiểu Telegram, `POST https://bot-api.zaloplatforms.com/bot<TOKEN>/sendMessage` với JSON `{"chat_id", "text"}`, text tối đa 2000 ký tự.

1. Tạo bot trên Zalo Bot Platform, lấy **bot token** dạng `12345689:abc-xyz`. Token không hết hạn trừ khi mày reset.
2. Chat id đích: `zgr-8a45b1cc3fa3d6fd8fb2` (đã điền sẵn `ZALO_CHAT_ID` trong `.env`). Cần đổi chat khác thì nhắn bot một tin rồi lấy `result.message.chat.id` qua `getUpdates` (phải chưa set webhook):
   ```bash
   curl -s -X POST "https://bot-api.zaloplatforms.com/bot<TOKEN>/getUpdates" | python3 -m json.tool
   ```
3. **Test gửi tay trước khi dựng lab.** Tài liệu Zalo Bot chưa nói rõ bot có gửi được vào group không (id `zgr-` có vẻ là group), nên thử 1 lần cho chắc:
   ```bash
   curl -s -X POST -H 'Content-Type: application/json' \
        -d '{"chat_id":"zgr-8a45b1cc3fa3d6fd8fb2","text":"test wazuh-lab"}' \
        "https://bot-api.zaloplatforms.com/bot<TOKEN>/sendMessage"
   ```
   Trả `"ok":true` là được. `"ok":false` thì đọc `description` (thường là sai chat id hoặc bot chưa ở trong group).

Tin nhắn gửi dạng text thường (không dùng `parse_mode`) cho chắc. Lỗi gửi được ghi vào `/var/ossec/logs/integrations.log` trong manager, kể cả khi Zalo trả HTTP 200 nhưng `ok:false`.

## 2. Setup + chạy

```bash
cd wazuh-lab
./setup.sh                 # lần đầu: tạo .env với secret random (openssl rand -hex 16), cert, hash password
nano .env                  # điền ZALO_BOT_TOKEN (ZALO_CHAT_ID đã điền sẵn)
./setup.sh                 # chạy lại để render token vào ossec.conf của manager
docker compose up -d --build
docker compose ps          # đợi ~1-2 phút cho indexer + manager lên
```

`setup.sh` làm gì:
- `.env`: mọi secret (`INDEXER_PASSWORD`, `DASHBOARD_PASSWORD`, `API_PASSWORD`, `ENROLLMENT_PASSWORD`, `CLUSTER_KEY`) sinh bằng `openssl rand -hex 16`. Riêng `API_PASSWORD` có tiền tố `Wz1.` vì Wazuh API bắt buộc password có chữ hoa, số và ký tự đặc biệt, chuỗi hex thuần sẽ bị từ chối. Đã có `.env` thì không ghi đè.
- Cert TLS: tự ký bằng openssl (root CA + admin, indexer, manager, dashboard), DN khớp `config/wazuh_indexer/wazuh.indexer.yml`.
- `internal_users.yml`: bcrypt hash password `admin` và `kibanaserver` từ `.env` (dùng `hash.sh` trong image indexer). Đã bỏ các user demo của Wazuh.
- `wazuh_manager.conf`: render từ `.tpl`, thay token/chat id/cluster key. Không có token thì tự bỏ block `<integration>`.
- `authd.pass`: mật khẩu enrollment, agent phải có mới đăng ký được vào manager.

Truy cập:
- Dashboard: `https://<IP-VM>:8443` (cert tự ký), user `admin`, password = `INDEXER_PASSWORD` trong `.env`.
- WAF: `http://<IP-VM>:8080`.

## 3. Test

```bash
# auth.log: SSH sai password nhiều lần (8 lần trong 2 phút -> rule 5763 level 10 -> Zalo)
for i in $(seq 1 10); do sshpass -p wrong ssh -o StrictHostKeyChecking=no root@127.0.0.1 true; done

# WAF
curl "http://127.0.0.1:8080/get?q=<script>alert(1)</script>"                 # XSS   -> 100211
curl "http://127.0.0.1:8080/get?f=../../../../etc/passwd"                      # LFI   -> 100212
curl -X POST -H 'Content-Type: application/json' \
     -d '{"ho_ten":"a'"'"' UNION SELECT password FROM users--"}' http://127.0.0.1:8080/post   # SQLi -> 100210
```
SSH test cần sshd chạy trên host (`sudo systemctl start ssh`). Xem alert trên Dashboard → Threat Hunting, lọc `rule.groups: coraza` hoặc `rule.groups: sshd`.

Debug nhanh:
```bash
docker compose exec wazuh.manager /var/ossec/bin/agent_control -l          # agent có Active không
docker compose exec wazuh.manager tail -f /var/ossec/logs/alerts/alerts.log
docker compose exec wazuh.manager grep -i integrat /var/ossec/logs/ossec.log
docker compose exec wazuh.manager cat /var/ossec/logs/integrations.log     # lỗi Zalo trả về (ok=false, sai chat_id...)
docker compose exec waf tail -n1 /var/log/coraza/audit.log
```

## 4. Rule cho log Coraza (`config/wazuh_cluster/rules/local_rules.xml`)

| ID | Level | Khi nào |
|---|---|---|
| 100200 | 3 | Mọi transaction Coraza ghi audit log |
| 100201 | 10 | CRS 949110 bắn (vượt anomaly score) |
| 100210 | 10 | ...và có tag `attack-sqli` |
| 100211 | 10 | ...`attack-xss` |
| 100212 | 12 | ...`attack-lfi` |
| 100213 | 12 | ...`attack-rce` |
| 100220 | 12 | ≥ 8 alert tấn công từ cùng `client_ip` trong 60s (scanner) |

Log Coraza được đọc bằng `log_format json` nên Wazuh tự tách field (`transaction.client_ip`, `transaction.request.uri`...), không cần decoder riêng. Tin Zalo của alert WAF liệt kê các rule CRS đã match kèm `Matched Data`.

Ngưỡng gửi Zalo: `ZALO_MIN_LEVEL` trong `.env` (mặc định 7, tức bỏ qua sshd fail lẻ level 5).

## 5. Đổi cấu hình

| Sửa gì | Làm gì |
|---|---|
| `local_rules.xml`, `.tpl`, `.env` (Zalo) | `./setup.sh && docker compose up -d --force-recreate wazuh.manager` |
| `waf/Caddyfile` | `docker compose restart waf` (file được mount, không cần build lại) |
| `WAF_MODE=On` (chặn thật) / `WAF_UPSTREAM` | sửa `.env` rồi `docker compose up -d waf` |
| Password trong `.env` sau khi đã chạy | Phải `docker compose down -v`, xóa `config/wazuh_indexer/internal_users.yml`, chạy lại `./setup.sh`. Indexer chỉ đọc `internal_users.yml` lần khởi tạo đầu tiên. |

Lưu ý: dùng `--force-recreate` chứ đừng chỉ `restart` manager, lúc test `restart` không chắc copy lại file config.

## 6. Mấy điểm cần biết

- **SecAuditLogRelevantStatus** dùng regex Go (RE2), không có lookahead `(?!...)` như ModSecurity. Đã viết lại thành `^(?:5|40[0-35-9]|4[1-9])` (4xx trừ 404, và 5xx).
- **Token bot Zalo nằm trong `wazuh_manager.conf`** (file đã được `chmod 600`, có trong `.gitignore`), và Wazuh in nguyên URL có token vào `ossec.log` khi gọi integration lỗi. Đừng gửi log đó cho người khác mà chưa che token.
- **Audit log quá lớn**: Wazuh cắt event > 64KB, JSON bị cắt sẽ không decode được. Request body to (upload file) có thể rơi vào trường hợp này.
- **SCA đã tắt** trên cả manager lẫn agent: nó chấm CIS cho OS của container (Amazon Linux), không liên quan tới VM của mày, và lần đầu chạy bắn khoảng 180 alert level 7.
- Cert key để mode 644 vì indexer/dashboard chạy bằng uid 1000 trong container (rootless thì map sang subuid trên host, không phải owner của file). Lab thì được, đừng dùng y nguyên cho môi trường thật.
- Muốn bảo vệ app thật thay cho httpbin: đặt `WAF_UPSTREAM=https://...` và thêm `header_up Host` + `transport http { tls_server_name ... }` như Caddyfile của lab WAF cũ (`waf-lab/README.md` trong project).
- Sysmon: lab này chưa đọc log Sysmon. Sysmon cài trên Windows thì cần cài Wazuh agent cho Windows và thêm `<localfile><location>Microsoft-Windows-Sysmon/Operational</location><log_format>eventchannel</log_format></localfile>`. Sysmon for Linux thì đọc qua syslog.

## Cấu trúc

```
wazuh-lab/
├── preflight.sh           # kiểm tra server, chỉ đọc
├── install-rootless.sh    # cài Docker rootless + chuẩn bị host (sudo)
├── docker-compose.yml
├── setup.sh               # .env, cert, hash password, render config
├── waf/{Dockerfile,Caddyfile}
└── config/
    ├── wazuh_indexer/wazuh.indexer.yml        (internal_users.yml do setup.sh sinh)
    ├── wazuh_dashboard/opensearch_dashboards.yml
    ├── wazuh_agent/ossec.conf                 (localfile auth.log + coraza audit.log)
    └── wazuh_cluster/
        ├── wazuh_manager.conf.tpl             (auth dùng password, block integration Zalo)
        ├── rules/local_rules.xml
        └── integrations/custom-zalo{,.py}
```
