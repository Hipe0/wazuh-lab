#!/usr/bin/env bash
# Cai Docker rootless cho user hien tai + chuan bi host cho lab Wazuh.
# Chay bang user thuong co sudo (KHONG sudo ./install-rootless.sh). Chay lai nhieu lan duoc.
#
#   ./install-rootless.sh                  # dung lai neu thay Docker rootful dang chay
#   ./install-rootless.sh --disable-rootful  # tat Docker rootful (docker.service) roi cai rootless
#   ./install-rootless.sh --keep-rootful     # giu rootful, chay rootless song song
set -euo pipefail

MODE=""
for a in "$@"; do
  case "$a" in
    --disable-rootful) MODE=disable ;;
    --keep-rootful) MODE=keep ;;
    *) echo "Tham so khong hop le: $a"; exit 1 ;;
  esac
done

USER_NAME="$(id -un)"
step() { printf '\n[+] %s\n' "$*"; }
die()  { printf '[x] %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -ne 0 ] || die "Dung chay bang root. Chay bang user se dung Docker rootless."
[ -n "${XDG_RUNTIME_DIR:-}" ] && [ -d "$XDG_RUNTIME_DIR" ] || die "Khong co XDG_RUNTIME_DIR. SSH thang vao bang $USER_NAME (khong dung 'sudo su')."
. /etc/os-release
case "$ID" in ubuntu|debian|kali) ;; *) die "Script chi ho tro Ubuntu/Debian/Kali (dang la $ID)";; esac
sudo -v

# ---------------------------------------------------------------------------
# Kiem tra rootful TRUOC khi apt cai docker-ce (apt se tu bat docker.service)
ROOTFUL_WAS_ACTIVE=0
if systemctl is-active --quiet docker.service docker.socket 2>/dev/null; then
  ROOTFUL_WAS_ACTIVE=1
  RUNNING="$(sudo docker ps -q 2>/dev/null | wc -l)"
  [ -n "$MODE" ] || die "Docker rootful dang chay ($RUNNING container). Chay lai voi --disable-rootful hoac --keep-rootful."
fi

# ---------------------------------------------------------------------------
step "Cai goi phu thuoc"
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  ca-certificates curl gnupg openssl tar uidmap dbus-user-session slirp4netns \
  fuse-overlayfs iptables acl iproute2 rsyslog

# ---------------------------------------------------------------------------
step "Repo Docker + docker-ce-rootless-extras"
if ! apt-cache policy docker-ce-rootless-extras 2>/dev/null | grep -q 'Candidate: [0-9]'; then
  case "$ID" in
    ubuntu) REPO_OS=ubuntu; CODENAME="$VERSION_CODENAME" ;;
    debian) REPO_OS=debian; CODENAME="$VERSION_CODENAME" ;;
    kali)   REPO_OS=debian; CODENAME=bookworm ;;   # Docker khong co repo cho Kali, dung cua Debian
  esac
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/$REPO_OS/gpg" | sudo gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
  sudo chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$REPO_OS $CODENAME stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
  sudo apt-get update -qq
fi
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  docker-ce docker-ce-cli containerd.io docker-ce-rootless-extras docker-compose-plugin docker-buildx-plugin

# ---------------------------------------------------------------------------
step "Docker rootful"
# Tat rootful tru khi no da chay tu truoc va user chon --keep-rootful.
# (Neu truoc do khong chay thi chinh apt vua bat len, tat di cho sach.)
SETUP_FORCE=""
if [ "$ROOTFUL_WAS_ACTIVE" = 1 ] && [ "$MODE" = keep ]; then
  SETUP_FORCE="--force"
  echo "    Giu Docker rootful, rootless chay song song"
else
  [ "${RUNNING:-0}" -eq 0 ] || echo "    Canh bao: dung $RUNNING container rootful"
  sudo systemctl disable --now docker.service docker.socket 2>/dev/null || true
  sudo rm -f /var/run/docker.sock
fi

# ---------------------------------------------------------------------------
step "subuid/subgid cho $USER_NAME"
if ! grep -qE "^$USER_NAME:" /etc/subuid || ! grep -qE "^$USER_NAME:" /etc/subgid; then
  sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 "$USER_NAME"
fi
grep -E "^$USER_NAME:" /etc/subuid /etc/subgid

# ---------------------------------------------------------------------------
if [ -r /proc/sys/kernel/apparmor_restrict_unprivileged_userns ] && \
   [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns)" = 1 ]; then
  step "AppArmor profile cho rootlesskit (Ubuntu 23.10+ chan unprivileged userns)"
  sudo tee /etc/apparmor.d/usr.bin.rootlesskit >/dev/null <<'EOF'
abi <abi/4.0>,
include <tunables/global>

/usr/bin/rootlesskit flags=(unconfined) {
  userns,

  include if exists <local/usr.bin.rootlesskit>
}
EOF
  sudo systemctl restart apparmor.service
fi

# ---------------------------------------------------------------------------
step "sysctl: vm.max_map_count cho Wazuh indexer"
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-wazuh-lab.conf >/dev/null
sudo sysctl -q -p /etc/sysctl.d/99-wazuh-lab.conf

step "Bat linger: Docker rootless chay ca khi logout"
sudo loginctl enable-linger "$USER_NAME"

# ---------------------------------------------------------------------------
step "Cai Docker rootless"
dockerd-rootless-setuptool.sh install $SETUP_FORCE

# Port driver slirp4netns: container thay IP that cua client (builtin se thay IP gateway),
# can cho rule WAF/Wazuh theo IP. Doi lai throughput port cham hon, lab khong anh huong.
mkdir -p ~/.config/systemd/user/docker.service.d
cat > ~/.config/systemd/user/docker.service.d/override.conf <<'EOF'
[Service]
Environment="DOCKERD_ROOTLESS_ROOTLESSKIT_NET=slirp4netns"
Environment="DOCKERD_ROOTLESS_ROOTLESSKIT_PORT_DRIVER=slirp4netns"
EOF
systemctl --user daemon-reload
systemctl --user enable docker >/dev/null 2>&1
systemctl --user restart docker
docker context use rootless >/dev/null

# ---------------------------------------------------------------------------
step "Ban copy auth.log cho container rootless doc duoc"
# auth.log la root:adm 640. Container rootless chay bang uid cua $USER_NAME va khong mang theo
# nhom adm, nen rsyslog ghi them 1 ban vao /var/log/wazuh-lab, cap quyen doc qua ACL.
# Compose mount ca thu muc (khong mount 1 file): logrotate tao inode moi, mount 1 file se dinh inode cu.
RSYSLOG_USER="$(grep -hE '^\$PrivDropToUser' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | awk '{print $2}' | tail -1)"
RSYSLOG_USER="${RSYSLOG_USER:-root}"   # Ubuntu: syslog, Debian/Kali: root
sudo install -d -m 0750 -o "$RSYSLOG_USER" -g adm /var/log/wazuh-lab
sudo setfacl -m "u:$USER_NAME:rx" -m "d:u:$USER_NAME:r" /var/log/wazuh-lab
sudo tee /etc/rsyslog.d/60-wazuh-lab.conf >/dev/null <<'EOF'
# Lab Wazuh: copy auth/authpriv cho agent rootless doc (/var/log/wazuh-lab co ACL cho user lab)
auth,authpriv.* action(type="omfile" file="/var/log/wazuh-lab/auth.log" fileCreateMode="0640")
EOF
sudo tee /etc/logrotate.d/wazuh-lab >/dev/null <<EOF
/var/log/wazuh-lab/auth.log {
    su $RSYSLOG_USER adm
    weekly
    rotate 4
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
sudo systemctl enable --now rsyslog >/dev/null 2>&1 || true
sudo systemctl restart rsyslog
logger -p authpriv.info "wazuh-lab: test ghi auth log"
sleep 1
if [ -r /var/log/wazuh-lab/auth.log ]; then echo "    /var/log/wazuh-lab/auth.log doc duoc"
else die "$USER_NAME khong doc duoc /var/log/wazuh-lab/auth.log"; fi

# ---------------------------------------------------------------------------
step "Kiem tra"
docker info --format 'SecurityOptions: {{.SecurityOptions}}' | grep -q rootless && echo "    docker dang chay rootless" || die "docker info khong bao rootless"
docker run --rm hello-world >/dev/null && echo "    hello-world chay OK"
docker compose version
cat <<EOF

Xong. Buoc tiep:
  cd wazuh-lab && ./setup.sh && docker compose up -d --build
Neu mo shell moi ma 'docker' bao khong ket noi duoc daemon: docker context use rootless
EOF
