set -euo pipefail

if [ "$(uname -m)" != x86_64 ]; then
  printf '%s\n' '仅支持原生 x86_64 运行器' >&2
  exit 1
fi
if ! sudo test -c /dev/kvm || ! sudo test -r /dev/kvm || ! sudo test -w /dev/kvm; then
  printf '%s\n' '运行器缺少可用的硬件虚拟化设备' >&2
  exit 1
fi
sudo python3 -I -c 'import fcntl, os; fd = os.open("/dev/kvm", os.O_RDWR); version = fcntl.ioctl(fd, 0xAE00, 0); assert version == 12, "虚拟化接口版本不支持"; vm = fcntl.ioctl(fd, 0xAE01, 0); os.close(vm); os.close(fd)'
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://pkgs.zabbly.com/key.asc | sudo tee /etc/apt/keyrings/zabbly.asc >/dev/null
sudo tee /etc/apt/sources.list.d/zabbly-incus.list >/dev/null <<'EOF'
deb [signed-by=/etc/apt/keyrings/zabbly.asc] https://pkgs.zabbly.com/incus/stable noble main
EOF
installed_version=$(dpkg-query -W -f='${Version}' incus 2>/dev/null || true)
if [ -n "$installed_version" ] && [ "${installed_version#*7.5}" = "$installed_version" ]; then
  sudo DEBIAN_FRONTEND=noninteractive apt-get remove -y incus
fi
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  incus qemu-system-x86 qemu-utils ovmf virtiofsd genisoimage \
  openssh-client sshpass ca-certificates \
  python3-guestfs python3-yaml libguestfs-tools
if ! sudo sh -c 'command -v mkisofs >/dev/null 2>&1 || command -v genisoimage >/dev/null 2>&1'; then
  printf '%s\n' '代理配置盘生成工具缺失，需要 mkisofs 或 genisoimage' >&2
  exit 1
fi
sudo systemctl start incus
sudo timeout 120 incus admin waitready
server_version=$(sudo incus query /1.0 | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["environment"]["server_version"])')
client_version=$(incus --version)
case "$server_version" in 7.5 | 7.5.*) : ;; *)
  printf '%s\n' "incus 服务端版本不符合要求：${server_version}，需要 7.5 系列" >&2
  exit 1;;
esac
case "$client_version" in 7.5 | 7.5.*) : ;; *)
  printf '%s\n' "incus 客户端版本不符合要求：${client_version}，需要 7.5 系列" >&2
  exit 1;;
esac
printf 'incus 版本已确认：客户端 %s，服务端 %s\n' "$client_version" "$server_version"
sudo incus admin init --preseed <<'YAML'
config:
  images.auto_update_interval: "0"
networks:
  - name: incusbr0
    type: bridge
    config:
      ipv4.address: auto
      ipv4.nat: "true"
      ipv6.address: none
storage_pools:
  - name: default
    driver: dir
profiles:
  - name: default
    devices:
      root:
        path: /
        pool: default
        type: disk
      eth0:
        network: incusbr0
        type: nic
YAML
sudo iptables -I FORWARD 1 -i incusbr0 -j ACCEPT
sudo iptables -I FORWARD 1 -o incusbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
remote_names=$(sudo incus remote list --format=json | python3 -I -c 'import json, sys; print("\n".join(json.load(sys.stdin)))')
if ! grep -Fxq images <<<"$remote_names"; then
  sudo incus remote add images https://images.linuxcontainers.org --protocol=simplestreams --public
fi
sudo incus version
sudo incus remote list --format=json
sudo incus storage list
sudo incus network list
qemu-img --version
sudo python3 -I -c 'import guestfs; print("离线磁盘模块已就绪")'
df -h
