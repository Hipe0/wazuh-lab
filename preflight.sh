#!/usr/bin/env bash
# Kiem tra server truoc khi cai Docker rootless + lab Wazuh. CHI DOC, khong sua gi.
# Chay bang user thuong (user se chay Docker rootless), KHONG chay bang root/sudo.
# Ket qua duoc luu vao preflight-<hostname>.log de gui lai.
set -uo pipefail

LOG="preflight-$(hostname)-$(date +%Y%m%d-%H%M).log"
exec > >(tee "$LOG") 2>&1

PORTS=(1514 1515 8080 8443 9200 55000)
HOSTS=(download.docker.com registry-1.docker.io production.cloudflare.docker.com proxy.golang.org bot-api.zaloplatforms.com)
NEED_RAM_MB=6000
NEED_DISK_GB=20

ok=0; warn=0; fail=0
OK()   { printf '  [ OK ] %s\n' "$*"; ok=$((ok+1)); }
WARN() { printf '  [WARN] %s\n' "$*"; warn=$((warn+1)); }
FAIL() { printf '  [FAIL] %s\n' "$*"; fail=$((fail+1)); }
FIX()  { printf '         -> %s\n' "$*"; }
sec()  { printf '\n== %s\n' "$*"; }
has()  { command -v "$1" >/dev/null 2>&1; }
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

USER_NAME="$(id -un)"
echo "Preflight $(date -Is) | host=$(hostname) | user=$USER_NAME"

# ---------------------------------------------------------------------------
sec "He dieu hanh / phan cung"
if [ -r /etc/os-release ]; then . /etc/os-release; OK "OS: ${PRETTY_NAME:-$ID}"; else WARN "Khong doc duoc /etc/os-release"; fi
case "${ID:-}" in
  ubuntu|debian|kali) ;;
  *) WARN "install-rootless.sh chi ho tro Ubuntu/Debian/Kali; distro '${ID:-?}' phai cai tay" ;;
esac
KVER="$(uname -r | cut -d- -f1)"
if ver_ge "$KVER" 5.11; then OK "Kernel $(uname -r) (>= 5.11, overlay2 rootless duoc)"
elif ver_ge "$KVER" 4.18; then WARN "Kernel $(uname -r) < 5.11: rootless phai dung fuse-overlayfs (cham hon)"
else FAIL "Kernel $(uname -r) qua cu cho Docker rootless (can >= 4.18)"; fi
ARCH="$(uname -m)"; [ "$ARCH" = x86_64 ] || [ "$ARCH" = aarch64 ] && OK "Arch $ARCH" || FAIL "Arch $ARCH khong co image Wazuh"
CPUS="$(nproc)"; [ "$CPUS" -ge 4 ] && OK "CPU: $CPUS core" || WARN "CPU: $CPUS core (khuyen nghi >= 4)"
RAM_MB="$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)"
AVAIL_MB="$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo)"
if [ "$RAM_MB" -ge 8000 ]; then OK "RAM: ${RAM_MB}MB (trong ${AVAIL_MB}MB)"
elif [ "$RAM_MB" -ge "$NEED_RAM_MB" ]; then WARN "RAM: ${RAM_MB}MB, du chay nhung sat (khuyen nghi 8GB)"
else FAIL "RAM: ${RAM_MB}MB < ${NEED_RAM_MB}MB, indexer + manager + dashboard se thieu RAM"; fi
DISK_GB="$(df -BG --output=avail "$HOME" | tail -1 | tr -dc 0-9)"
[ "$DISK_GB" -ge "$NEED_DISK_GB" ] && OK "Disk trong o \$HOME: ${DISK_GB}GB" || FAIL "Disk trong o \$HOME: ${DISK_GB}GB < ${NEED_DISK_GB}GB (image Wazuh ~4GB + data)"

# ---------------------------------------------------------------------------
sec "User / sudo"
if [ "$(id -u)" -eq 0 ]; then FAIL "Dang chay bang root. Docker rootless phai cai cho user thuong"; FIX "dang nhap SSH thang bang user do roi chay lai"
else OK "User thuong: $USER_NAME (uid $(id -u))"; fi
if id -nG | tr ' ' '\n' | grep -qxE 'sudo|wheel'; then OK "$USER_NAME thuoc nhom sudo"; else WARN "$USER_NAME khong thuoc nhom sudo/wheel (install-rootless.sh can sudo)"; fi
if [ -n "${XDG_RUNTIME_DIR:-}" ] && [ -d "${XDG_RUNTIME_DIR}" ]; then OK "XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR"
else FAIL "Khong co XDG_RUNTIME_DIR (thuong do vao bang 'sudo su - user' hoac 'su')"; FIX "SSH thang vao bang $USER_NAME, hoac: sudo machinectl shell $USER_NAME@"; fi
if has systemctl && systemctl --user show-environment >/dev/null 2>&1; then OK "systemd --user hoat dong"
else FAIL "systemd --user khong chay"; FIX "sudo apt install -y dbus-user-session, roi logout/login lai"; fi
if has loginctl && loginctl show-user "$USER_NAME" -p Linger 2>/dev/null | grep -q 'Linger=yes'; then OK "Linger da bat (daemon chay ca khi logout)"
else WARN "Linger chua bat: logout SSH la Docker rootless tat theo"; FIX "sudo loginctl enable-linger $USER_NAME"; fi

# ---------------------------------------------------------------------------
sec "User namespace (dieu kien cua rootless)"
for f in /etc/subuid /etc/subgid; do
  line="$(grep -E "^($USER_NAME|$(id -u)):" "$f" 2>/dev/null | head -1)"
  cnt="$(echo "$line" | cut -d: -f3)"
  if [ -n "$line" ] && [ "${cnt:-0}" -ge 65536 ]; then OK "$f: $line"
  else FAIL "$f khong co dai >= 65536 cho $USER_NAME"; FIX "sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $USER_NAME"; fi
done
MAXNS="$(cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo 0)"
[ "$MAXNS" -gt 0 ] && OK "user.max_user_namespaces=$MAXNS" || FAIL "user.max_user_namespaces=0"
if [ -r /proc/sys/kernel/unprivileged_userns_clone ]; then
  [ "$(cat /proc/sys/kernel/unprivileged_userns_clone)" = 1 ] && OK "kernel.unprivileged_userns_clone=1" || FAIL "kernel.unprivileged_userns_clone=0"
fi
if [ -r /proc/sys/kernel/apparmor_restrict_unprivileged_userns ] && [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns)" = 1 ]; then
  if [ -n "$(ls /etc/apparmor.d/ 2>/dev/null | grep -i rootlesskit)" ]; then OK "AppArmor chan userns nhung da co profile rootlesskit"
  else WARN "AppArmor chan unprivileged userns (Ubuntu 23.10+): rootlesskit can profile rieng"; FIX "install-rootless.sh tu tao /etc/apparmor.d/usr.bin.rootlesskit"; fi
fi
if [ -c /dev/net/tun ] && [ -r /dev/net/tun ] && [ -w /dev/net/tun ]; then OK "/dev/net/tun doc/ghi duoc (slirp4netns can)"
else FAIL "/dev/net/tun khong ton tai hoac user khong doc/ghi duoc"; FIX "sudo modprobe tun; quyen chuan la crw-rw-rw- root root"; fi
if [ "$(stat -fc %T /sys/fs/cgroup)" = cgroup2fs ]; then OK "cgroup v2"
else WARN "cgroup v1: rootless chay duoc nhung khong gioi han CPU/RAM container duoc"; fi

# ---------------------------------------------------------------------------
sec "Cong cu"
check_tool() { # $1 lenh, $2 goi apt
  if has "$1"; then OK "$1 ($(command -v "$1"))"; else FAIL "Thieu $1"; FIX "sudo apt install -y $2"; MISSING_PKGS+=("$2"); fi
}
MISSING_PKGS=()
check_tool curl curl
check_tool openssl openssl
check_tool tar tar
check_tool newuidmap uidmap
check_tool newgidmap uidmap
check_tool slirp4netns slirp4netns
check_tool iptables iptables
check_tool setfacl acl
check_tool ss iproute2
ver_ge "$KVER" 5.11 || check_tool fuse-overlayfs fuse-overlayfs
if has rsyslogd; then OK "rsyslog"; else FAIL "Thieu rsyslog -> khong co /var/log/auth.log"; FIX "sudo apt install -y rsyslog"; MISSING_PKGS+=(rsyslog); fi

# ---------------------------------------------------------------------------
sec "Docker"
if has docker; then OK "docker CLI: $(docker --version 2>/dev/null)"; else WARN "Chua co docker CLI (install-rootless.sh se cai tu repo Docker)"; fi
if has docker && docker compose version >/dev/null 2>&1; then
  OK "docker compose: $(docker compose version --short 2>/dev/null)"
else WARN "Chua co docker compose plugin"; FIX "sudo apt install -y docker-compose-plugin"; fi
if has dockerd-rootless-setuptool.sh; then OK "docker-ce-rootless-extras da cai"; else WARN "Chua co docker-ce-rootless-extras"; FIX "sudo apt install -y docker-ce-rootless-extras"; fi
if { has systemctl && systemctl is-active --quiet docker.service 2>/dev/null; } || [ -S /var/run/docker.sock ]; then
  n="$(sudo -n docker ps -q 2>/dev/null | wc -l || true)"
  WARN "Docker rootful dang chay (docker.service). Container dang chay: ${n:-khong kiem tra duoc (can sudo)}"
  FIX "Neu server KHONG dung rootful: install-rootless.sh --disable-rootful. Neu con dung: --keep-rootful (chay song song)"
else OK "Khong co Docker rootful dang chay"; fi
if has systemctl && systemctl --user is-active --quiet docker 2>/dev/null; then
  OK "Docker rootless da chay (systemctl --user)"
  if docker info 2>/dev/null | grep -qi rootless; then OK "docker info xac nhan rootless"
  else WARN "docker CLI dang tro toi daemon khong phai rootless"; FIX "docker context use rootless"; fi
fi

# ---------------------------------------------------------------------------
sec "Sysctl / port"
MMC="$(cat /proc/sys/vm/max_map_count)"
[ "$MMC" -ge 262144 ] && OK "vm.max_map_count=$MMC" || { FAIL "vm.max_map_count=$MMC < 262144 (indexer khong khoi dong)"; FIX "install-rootless.sh ghi vao /etc/sysctl.d/99-wazuh-lab.conf"; }
UPS="$(cat /proc/sys/net/ipv4/ip_unprivileged_port_start 2>/dev/null || echo 1024)"
OK "ip_unprivileged_port_start=$UPS (rootless chi mo duoc port >= $UPS; dashboard mac dinh 8443)"
if has ss; then
  for p in "${PORTS[@]}"; do
    if ss -ltnH "sport = :$p" 2>/dev/null | grep -q .; then FAIL "Port $p dang bi chiem: $(ss -ltnpH "sport = :$p" 2>/dev/null | awk '{print $4, $6}' | head -1)"
    else OK "Port $p trong"; fi
  done
fi
if has ufw && sudo -n ufw status 2>/dev/null | grep -q 'Status: active'; then
  WARN "UFW dang bat: rootless KHONG tu mo firewall nhu rootful"; FIX "sudo ufw allow 8080,8443,1514,1515/tcp"
fi

# ---------------------------------------------------------------------------
sec "Log"
if [ -f /var/log/auth.log ]; then
  OK "/var/log/auth.log ton tai ($(stat -c '%U:%G %a' /var/log/auth.log))"
  if [ -r /var/log/wazuh-lab/auth.log ]; then OK "/var/log/wazuh-lab/auth.log doc duoc (ban copy cho container rootless)"
  else WARN "Container rootless khong doc duoc auth.log (root:adm 640) -> install-rootless.sh tao ban copy /var/log/wazuh-lab/auth.log cho $USER_NAME"; fi
else FAIL "Khong co /var/log/auth.log"; FIX "sudo apt install -y rsyslog"; fi

# ---------------------------------------------------------------------------
sec "Mang ra ngoai"
for h in "${HOSTS[@]}"; do
  code="$(curl -sS -o /dev/null -m 8 -w '%{http_code}' "https://$h/" 2>/dev/null)"
  if [ -n "$code" ] && [ "$code" != 000 ]; then OK "https://$h (HTTP $code)"; else FAIL "Khong ket noi duoc https://$h"; fi
done
[ -n "${HTTPS_PROXY:-${https_proxy:-}}" ] && WARN "Co bien HTTPS_PROXY: Docker rootless can them proxy trong ~/.config/systemd/user/docker.service.d/"
if has timedatectl; then timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -q yes && OK "Dong ho da sync NTP" || WARN "Dong ho chua sync NTP (lech gio lam alert sai timestamp)"; fi

# ---------------------------------------------------------------------------
printf '\n== Tong ket: %d OK, %d WARN, %d FAIL\n' "$ok" "$warn" "$fail"
if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
  printf 'Goi thieu: %s\n' "$(printf '%s\n' "${MISSING_PKGS[@]}" | sort -u | tr '\n' ' ')"
fi
echo "Log: $PWD/$LOG"
[ "$fail" -eq 0 ]
