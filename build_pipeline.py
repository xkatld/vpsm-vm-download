from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import math
import os
import platform
import re
import secrets
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

ARCHITECTURE = "amd64"
RUNNERS = {"amd64": "ubuntu-24.04"}
NATIVE_ARCHITECTURES = {"x86_64": "amd64", "amd64": "amd64"}
COMMON_PACKAGES = "bash git unzip screen wget curl sudo nano ca-certificates"
README_CONTENT = "本系统为vpsm91.com构建,本文件无实际作用可随意处理。"
RELEASE_DISPLAY = {
    "debian": {"bookworm": "12", "forky": "14", "trixie": "13"},
    "ubuntu": {"jammy": "2204", "noble": "2404", "resolute": "2604"},
    "centos": {"9-Stream": "9-stream", "10-Stream": "10-stream"},
}
VM_CPU = 2
VM_MEMORY = "2GiB"
VM_DISK = "12GiB"
MIN_HOST_MEMORY = 3 * 1024 ** 3
MIN_HOST_DISK = 24 * 1024 ** 3


@dataclass(frozen=True)
class ImageSpec:
    distro: str
    release: str
    architecture: str
    variant: str
    build_date: str

    @property
    def image_alias(self) -> str:
        return f"{self.distro}-{self.release}".lower()

    @property
    def display_release(self) -> str:
        return RELEASE_DISPLAY.get(self.distro, {}).get(self.release, self.release)

    def container_name(self) -> str:
        release = self.display_release.replace(".", "")
        return f"{self.distro}{release}-{self.architecture}-kvm".lower()

    def remote_path(self) -> str:
        return f"images:{self.distro}/{self.release}/{self.architecture}"


def load_manifest(path: Path, architecture: str = ARCHITECTURE) -> list[ImageSpec]:
    if architecture not in RUNNERS:
        raise ValueError("不支持的清单架构")
    with path.open("r", encoding="utf-8", newline="") as handle:
        rows = csv.reader(handle, delimiter="\t")
        try:
            fields = [column.split(":", 1)[0].strip() for column in next(rows)]
        except StopIteration:
            raise ValueError("镜像清单为空") from None
        required = {
            "Distribution", "Release", "Architecture", "Variant", "Build date",
            "LXC (privileged)", "LXC (unprivileged)", "Incus (container)", "Incus (VM)",
        }
        if len(fields) != 9 or set(fields) != required:
            raise ValueError("镜像清单必须包含规定的九列")
        specs = []
        seen = set()
        for number, row in enumerate(rows, 2):
            if not row:
                continue
            if len(row) != 9:
                raise ValueError(f"镜像清单第 {number} 行列数错误")
            values = dict(zip(fields, (value.strip() for value in row)))
            if values["Architecture"] != architecture or values["Variant"] != "default" or values["Incus (VM)"] != "YES":
                continue
            selected = [values[key] for key in ("Distribution", "Release", "Architecture", "Variant", "Build date")]
            if not all(selected) or any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", value) for value in selected[:4]):
                raise ValueError(f"镜像清单第 {number} 行内容错误")
            key = tuple(selected[:4])
            if key in seen:
                raise ValueError(f"镜像清单第 {number} 行重复")
            seen.add(key)
            specs.append(ImageSpec(*selected))
    if not specs:
        raise ValueError("清单中没有匹配的虚拟机镜像")
    return specs


def shell_quote(value: str) -> str:
    return shlex.quote(value)


def shell_lines(*lines: str) -> str:
    return "\n".join(lines) + "\n"


def normalize_export(export_dir: Path, prefix: str) -> tuple[Path, Path]:
    from scripts.vm_image import normalize_export as normalize
    return normalize(export_dir, prefix)


def sanitize_disk(disk_path: Path) -> None:
    from scripts.sanitize_vm import sanitize_disk as sanitize
    sanitize(disk_path)


class BuildTerminated(RuntimeError):
    pass


class IncusCommandError(RuntimeError):
    pass


class SetupStepError(RuntimeError):
    pass


class Pipeline:
    def __init__(self, specs: Sequence[ImageSpec], output_dir: Path,
                 root_password: str | None = None, ssh_timeout: float = 120,
                 agent_timeout: float = 300, package_index_timeout: float = 600) -> None:
        self.specs = list(specs)
        self.output_dir = Path(output_dir)
        self.root_password = root_password if root_password is not None else secrets.token_urlsafe(32)
        self.ssh_timeout = ssh_timeout
        self.agent_timeout = agent_timeout
        self.package_index_timeout = package_index_timeout
        self.inherited_secrets = tuple(os.environ.get(key, "") for key in ("SSHPASS", "IMAGE_ROOT_PASSWORD"))
        self.run_id = uuid.uuid4().hex
        self.resource_prefix = f"vpsm-{self.run_id}-"
        self.created_containers: list[str] = []
        self.created_base_aliases: list[str] = []
        self.created_published_aliases: list[str] = []
        self.sanitized_containers: set[str] = set()
        self.exported_files: list[str] = []
        self.output_ready = False
        self.started_at = datetime.now(timezone.utc)

    def resource_name(self, name: str) -> str:
        if len(self.resource_prefix + name) > 63:
            name = name[:16] + "-" + hashlib.sha256(name.encode()).hexdigest()[:8]
        return self.resource_prefix + name

    def container_name(self, spec: ImageSpec) -> str:
        return self.resource_name(spec.container_name())

    def base_alias(self, spec: ImageSpec) -> str:
        return self.resource_name(f"{spec.image_alias}-{spec.architecture}")

    @property
    def containers(self) -> list[str]:
        return [self.container_name(spec) for spec in self.specs]

    def safe_error(self, exc: BaseException) -> str:
        if isinstance(exc, subprocess.TimeoutExpired):
            return "外部命令执行超时"
        if isinstance(exc, subprocess.CalledProcessError):
            return f"外部命令失败，退出码 {exc.returncode}"
        if isinstance(exc, OSError):
            return "文件或系统操作失败"
        if isinstance(exc, (IncusCommandError, SetupStepError, BuildTerminated)):
            return str(exc).replace(self.root_password, "[临时凭据]")
        return f"构建失败，异常类型 {type(exc).__name__}"

    @staticmethod
    def command_environment() -> dict[str, str]:
        return {key: value for key, value in os.environ.items()
                if key not in {"IMAGE_ROOT_PASSWORD", "SSHPASS"}}

    def safe_stderr(self, value: str | bytes | None) -> str:
        if not value:
            return ""
        text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
        for secret in sorted(filter(None, (self.root_password, *self.inherited_secrets)), key=len, reverse=True):
            text = text.replace(secret, "[临时凭据]")
        text = "".join(character if character == "\n" or character.isprintable() else repr(character)[1:-1]
                       for character in text).replace("::", "：：")
        lines = text.splitlines()
        result = "\n".join("诊断：" + line for line in lines[:12])
        return result[:2048] + ("\n诊断：[已截断]" if len(result) > 2048 or len(lines) > 12 else "")

    def incus(self, args: Sequence[str], *, capture: bool = False,
              input: str | None = None, timeout: float = 1800,
              diagnostic_stderr: bool = False) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(["incus", *args], input=input, check=True, text=True,
                                  capture_output=True, env=self.command_environment(), timeout=timeout)
        except (OSError, subprocess.SubprocessError) as exc:
            error = self.safe_error(exc)
            if diagnostic_stderr and input is None:
                detail = self.safe_stderr(getattr(exc, "stderr", None))
                if detail:
                    error += "\n" + detail
            raise IncusCommandError(error) from None

    def exec_container(self, container: str, command: str) -> subprocess.CompletedProcess[str]:
        return self.incus(["exec", container, "--", "sh", "-c", command], diagnostic_stderr=True)

    def preflight(self) -> None:
        if len(self.specs) != 1:
            raise ValueError("每次构建必须选择一个版本")
        spec = self.specs[0]
        if spec.architecture not in RUNNERS or NATIVE_ARCHITECTURES.get(platform.machine().lower()) != spec.architecture:
            raise RuntimeError("需要原生 amd64 构建主机")
        if spec.distro not in {"almalinux", "alpine", "centos", "debian", "ubuntu"}:
            raise ValueError("不支持的发行版")
        if not self.root_password or any(value in self.root_password for value in "\n\r\x00"):
            raise ValueError("临时测试密码格式错误")
        if any(not math.isfinite(value) or value <= 0 for value in
               (self.ssh_timeout, self.agent_timeout, self.package_index_timeout)):
            raise ValueError("等待期限必须是有限正数")
        if self.output_dir.is_symlink() or (self.output_dir.exists() and
                (not self.output_dir.is_dir() or any(self.output_dir.iterdir()))):
            raise RuntimeError("输出目录必须不存在或为空目录")
        for executable in ("incus", "ssh", "sshpass", "qemu-img", "guestfish"):
            if shutil.which(executable) is None:
                raise RuntimeError(f"缺少构建工具：{executable}")
        device = Path("/dev/kvm")
        if not device.exists() or not stat.S_ISCHR(device.stat().st_mode) or not os.access(device, os.R_OK | os.W_OK):
            raise RuntimeError("需要可读写的 KVM 设备")
        if (os.cpu_count() or 0) < VM_CPU:
            raise RuntimeError("主机至少需要两个处理器")
        memory = re.search(r"^MemAvailable:\s+(\d+)\s+kB$", Path("/proc/meminfo").read_text(), re.MULTILINE)
        if memory is None or int(memory.group(1)) * 1024 < MIN_HOST_MEMORY:
            raise RuntimeError("主机可用内存必须至少为 3GiB")
        parent = self.output_dir.absolute()
        while not parent.exists():
            parent = parent.parent
        if shutil.disk_usage(parent).free < MIN_HOST_DISK:
            raise RuntimeError("输出文件系统可用空间必须至少为 24GiB")
        self.incus(["version"], timeout=30)

    def download_images(self) -> None:
        for spec in self.specs:
            alias = self.base_alias(spec)
            self.incus(["image", "copy", spec.remote_path(), "local:", "--alias", alias, "--vm", "--quiet"])
            self.created_base_aliases.append(alias)

    def launch_containers(self) -> None:
        for spec in self.specs:
            name = self.container_name(spec)
            self.incus(["init", self.base_alias(spec), name, "--vm",
                        "--config", "security.secureboot=false",
                        "--config", f"limits.cpu={VM_CPU}", "--config", f"limits.memory={VM_MEMORY}",
                        "--device", f"root,size={VM_DISK}"])
            self.created_containers.append(name)
            self.incus(["config", "device", "add", name, "agent", "disk", "source=agent:config"],
                       diagnostic_stderr=True)
            self.incus(["start", name], timeout=self.agent_timeout, diagnostic_stderr=True)
            self.wait_for_container(name)

    def wait_for_container(self, container: str) -> None:
        deadline = time.monotonic() + self.agent_timeout
        while (remaining := deadline - time.monotonic()) > 0:
            try:
                self.incus(["exec", container, "--", "true"], timeout=min(10, remaining))
            except IncusCommandError:
                pass
            else:
                if time.monotonic() <= deadline:
                    return
            time.sleep(min(2, max(0, deadline - time.monotonic())))
        raise RuntimeError("虚拟机代理就绪等待超时")

    @staticmethod
    def ssh_config_command() -> str:
        return shell_lines(
            "set -eu", "config=/etc/ssh/sshd_config",
            '{ printf \'PermitRootLogin yes\\nPasswordAuthentication yes\\n\'; cat "$config"; } > "$config.vpsm"',
            'chmod 600 "$config.vpsm"', 'mv "$config.vpsm" "$config"',
        )

    def setup_step(self, container: str, label: str, command: str | None = None,
                   *, timeout: float = 1800) -> None:
        try:
            if command is None:
                self.incus(["exec", container, "--", "chpasswd"], input=f"root:{self.root_password}\n", timeout=30)
            else:
                self.incus(["exec", container, "--", "sh", "-c", command], timeout=timeout, diagnostic_stderr=True)
        except IncusCommandError as exc:
            raise SetupStepError(f"配置步骤 {label} 失败：{exc}") from None

    def wait_for_package_index(self, container: str, command: str) -> None:
        deadline = time.monotonic() + self.package_index_timeout
        last_error = "尚未完成软件源索引更新"
        attempt = 0
        while (remaining := deadline - time.monotonic()) > 0:
            attempt += 1
            guest_timeout = max(1, math.ceil(remaining))
            marker = "VPSM_INDEX_EXIT_" + secrets.token_hex(16) + "="
            wrapped = shell_lines(
                f"timeout -k 5 {guest_timeout} sh -c {shell_quote(command)}",
                "index_status=$?", f'printf \'\\n{marker}%s\\n\' "$index_status"',
            )
            started = time.monotonic()
            try:
                result = self.incus(["exec", container, "--", "sh", "-c", wrapped],
                                    timeout=guest_timeout + 15, diagnostic_stderr=True)
            except IncusCommandError as exc:
                message = f"软件源索引第 {attempt} 轮，耗时 {time.monotonic() - started:.1f} 秒，退出码未知：{exc}"
                print(message, file=sys.stderr)
                raise SetupStepError(message + "；未确认客户机命令结束，停止重试") from None
            output, separator, status = result.stdout.rpartition("\n" + marker)
            returncode = int(status.strip()) if separator and re.fullmatch(r"\d{1,3}\n", status) else None
            detail = self.safe_stderr((output if separator else result.stdout) + "\n" + result.stderr)
            last_error = (f"软件源索引第 {attempt} 轮，耗时 {time.monotonic() - started:.1f} 秒，"
                          f"退出码 {returncode if returncode is not None else '未知'}")
            if detail:
                last_error += "\n" + detail
            print(last_error, file=sys.stderr)
            if returncode is None or returncode >= 124:
                raise SetupStepError(last_error + "\n客户机超时或结束状态异常，停止重试")
            if returncode == 0:
                if time.monotonic() <= deadline:
                    return
                break
            time.sleep(min(2, max(0, deadline - time.monotonic())))
        raise SetupStepError("软件源索引准备超时：" + last_error)

    def setup_one(self, spec: ImageSpec, container: str) -> None:
        prefix = "set -eu\n"
        if spec.distro == "alpine":
            index, install = "apk update", "apk add openssh"
            services = [("启用远程登录", "rc-update add sshd"), ("重启远程登录", "rc-service sshd restart")]
        elif spec.distro in {"debian", "ubuntu"}:
            prefix += "export DEBIAN_FRONTEND=noninteractive\n"
            index, install = "apt-get -o APT::Update::Error-Mode=any update", "apt-get install -y openssh-server"
            services = [("启用远程登录", "systemctl enable ssh"), ("重启远程登录", "systemctl restart ssh")]
        else:
            index, install = "dnf makecache", "dnf install -y openssh-server"
            services = [("启用远程登录", "systemctl enable sshd"), ("重启远程登录", "systemctl restart sshd")]
        self.wait_for_package_index(container, prefix + "exec " + index)
        for label, command in [
            ("安装远程登录", install), ("生成测试主机密钥", "ssh-keygen -A"),
            ("配置远程登录", self.ssh_config_command()), *services,
        ]:
            self.setup_step(container, label, prefix + command)
        self.setup_step(container, "设置临时密码")

    def setup_containers(self) -> None:
        for spec in self.specs:
            self.setup_one(spec, self.container_name(spec))

    @staticmethod
    def package_install_command(spec: ImageSpec) -> str:
        if spec.distro == "alpine":
            return shell_lines("set -eu", f"apk add {COMMON_PACKAGES}", "update-ca-certificates",
                               "test -s /etc/ssl/certs/ca-certificates.crt")
        if spec.distro in {"debian", "ubuntu"}:
            return shell_lines("set -eu", "export DEBIAN_FRONTEND=noninteractive",
                               f"apt-get install -y {COMMON_PACKAGES}", "update-ca-certificates",
                               "test -s /etc/ssl/certs/ca-certificates.crt")
        if spec.distro in {"almalinux", "centos"}:
            major = spec.release.split("-", 1)[0]
            if major not in {"8", "9", "10"}:
                raise ValueError("不支持的企业系统版本")
            repo = "powertools" if major == "8" else "crb"
            epel = (f"https://dl.fedoraproject.org/pub/epel/epel-release-latest-{major}.noarch.rpm"
                    if spec.distro == "centos" else "epel-release")
            retry = ('retry_install() { attempt=1; while ! dnf install -y "$@"; do'
                     ' attempt=$((attempt + 1)); if test "$attempt" -gt 3; then exit 1; fi;'
                     " dnf clean all; sleep 5; done; }")
            return shell_lines("set -eu", retry, "retry_install dnf-plugins-core",
                               f"dnf config-manager --set-enabled {repo}", f"retry_install {epel}",
                               f"retry_install {COMMON_PACKAGES}", "update-ca-trust extract",
                               "test -s /etc/pki/tls/certs/ca-bundle.crt")
        raise ValueError("不支持的发行版")

    def install_common_packages(self) -> None:
        for spec in self.specs:
            self.exec_container(self.container_name(spec), self.package_install_command(spec))

    def write_readmes(self) -> None:
        for container in self.containers:
            self.exec_container(container, f"printf '%s\\n' {shell_quote(README_CONTENT)} > /root/README.md")

    @staticmethod
    def extract_ip(value: str) -> str | None:
        for candidate in re.findall(r"[0-9a-fA-F:.]+", value):
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if address.version == 4 and not address.is_loopback and not address.is_unspecified and not address.is_link_local:
                return str(address)
        return None

    def container_ip(self, container: str, *, timeout: float = 10) -> str | None:
        result = self.incus(["list", container, "--format", "csv", "-c", "4"], timeout=timeout)
        return self.extract_ip(result.stdout)

    def test_ssh(self) -> None:
        for container in self.containers:
            deadline = time.monotonic() + self.ssh_timeout
            while (remaining := deadline - time.monotonic()) > 0:
                try:
                    address = self.container_ip(container, timeout=min(10, remaining))
                    remaining = deadline - time.monotonic()
                    if address and remaining > 0:
                        result = subprocess.run([
                            "sshpass", "-d", "0", "ssh", "-4", "-F", "/dev/null",
                            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                            "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1",
                            "-o", "NumberOfPasswordPrompts=1", "-o", "PreferredAuthentications=password",
                            "-o", "PubkeyAuthentication=no", f"root@{address}", "whoami",
                        ], input=self.root_password + "\n", text=True, capture_output=True,
                            env=self.command_environment(), timeout=min(10, remaining))
                        if result.returncode == 0 and result.stdout.strip() == "root" and time.monotonic() <= deadline:
                            break
                except (IncusCommandError, OSError, subprocess.SubprocessError):
                    pass
                time.sleep(min(2, max(0, deadline - time.monotonic())))
            else:
                raise RuntimeError("IPv4 远程登录认证超时")

    @staticmethod
    def first_boot_identity_command(spec: ImageSpec) -> str:
        helper = ["set -eu"]
        if spec.distro == "alpine":
            helper.extend([
                "if ! test -s /etc/machine-id; then", "    umask 022",
                "    tr -d '-' < /proc/sys/kernel/random/uuid > /etc/machine-id",
                "    test -s /etc/machine-id", "    chmod 0644 /etc/machine-id", "fi",
            ])
        helper.append("/usr/bin/ssh-keygen -A")
        command = shell_lines(
            "set -eu", "mkdir -p /usr/local/libexec",
            "cat > /usr/local/libexec/vpsm-firstboot <<'EOF'", *helper, "EOF",
            "chmod 0755 /usr/local/libexec/vpsm-firstboot",
        )
        if spec.distro == "alpine":
            return command + shell_lines(
                "cat > /etc/init.d/vpsm-firstboot <<'EOF'", "#!/sbin/openrc-run",
                'description="初始化缺失的虚拟机身份"', "depend() {", "    need localmount",
                "    before networking sshd dbus machine-id", "}", "start() {",
                "    /bin/sh /usr/local/libexec/vpsm-firstboot", "}", "EOF",
                "chmod 0755 /etc/init.d/vpsm-firstboot", "rc-update add vpsm-firstboot boot",
                "for service in networking sshd; do",
                '    printf \'\\nrc_need="${rc_need:-} vpsm-firstboot"\\n\' >> "/etc/conf.d/$service"', "done",
            )
        return command + shell_lines(
            "cat > /etc/systemd/system/vpsm-firstboot.service <<'EOF'", "[Unit]",
            "Description=初始化缺失的远程登录主机密钥", "DefaultDependencies=no", "After=local-fs.target",
            "Before=ssh.service sshd.service ssh.socket sshd.socket shutdown.target", "Conflicts=shutdown.target",
            "", "[Service]", "Type=oneshot", "ExecStart=/bin/sh /usr/local/libexec/vpsm-firstboot",
            "RemainAfterExit=yes", "", "[Install]", "WantedBy=multi-user.target", "EOF",
            "for unit in ssh.service sshd.service ssh.socket sshd.socket sshd-keygen@.service; do",
            '    mkdir -p "/etc/systemd/system/$unit.d"',
            '    cat > "/etc/systemd/system/$unit.d/10-vpsm-firstboot.conf" <<\'EOF\'',
            "[Unit]", "Requires=vpsm-firstboot.service", "After=vpsm-firstboot.service", "EOF", "done",
            "systemctl daemon-reload", "systemctl enable vpsm-firstboot.service",
        )

    def cleanup_containers(self) -> None:
        from scripts.image_cleanup import CREDENTIAL_PATHS, PROVISION_CONF, PROVISION_MASK

        common = shell_lines(
            "set -eu", "printf 'root:!\\n' | chpasswd -e",
            "provision=" + PROVISION_CONF, "mask=" + PROVISION_MASK, "confdir=${mask%/*}",
            'if test -e "$provision" || test -L "$provision"; then',
            '    test -f "$provision" && test ! -L "$provision"',
            '    grep -qF -- /root/.ssh "$provision"',
            '    if test -e "$confdir" || test -L "$confdir"; then',
            '        test -d "$confdir" && test "$(readlink -f -- "$confdir")" = "$confdir"',
            "    else", '        mkdir -p "$confdir"', "    fi",
            '    test ! -L "$mask"',
            '    if test -e "$mask"; then', '        test -f "$mask"', "    fi",
            '    : > "$mask"', '    test ! -s "$mask"', "fi",
            "for path in " + " ".join(CREDENTIAL_PATHS),
            "do", '    parent=${path%/*}',
            '    if test ! -e "$parent" && test ! -L "$parent"; then continue; fi',
            '    if ! test -d "$parent" || test "$(readlink -f -- "$parent")" != "$parent"; then exit 1; fi',
            '    if test "$path" = /root/.ssh; then', '        rm -rf -- "$path"',
            "    else", '        if test -e "$path" || test -L "$path"; then',
            '            test -L "$path" || test -f "$path"', "        fi", '        rm -f -- "$path"',
            "    fi", '    test ! -e "$path" && test ! -L "$path"', "done",
            "for directory in /tmp /var/tmp; do", '    test ! -L "$directory"',
            '    if test -d "$directory"; then',
            '        for path in "$directory"/* "$directory"/.[!.]* "$directory"/..?*; do',
            '            rm -rf -- "$path"', '            test ! -e "$path" && test ! -L "$path"',
            "        done", "    fi", "done",
            "awk -F: '$1 == \"root\" { found=1; if ($2 != \"!\") exit 1 } END { if (!found) exit 1 }' /etc/shadow",
        )
        for spec in self.specs:
            if spec.distro == "alpine":
                package_cleanup = "apk cache clean"
                stop_ssh = "rc-service sshd stop\n"
            else:
                package_cleanup = ("apt-get clean && rm -rf /var/lib/apt/lists/*"
                                   if spec.distro in {"debian", "ubuntu"} else "dnf clean all && rm -rf /var/cache/dnf")
                stop_ssh = shell_lines(
                    "for unit in ssh.socket sshd.socket ssh.service sshd.service; do",
                    '    if load_state=$(systemctl show "$unit" --property=LoadState --value); then',
                    '        test -n "$load_state"', "    else", '        test "$load_state" = not-found', "    fi",
                    '    if test "$load_state" != not-found; then', '        systemctl stop "$unit"', "    fi", "done",
                )
            container = self.container_name(spec)
            self.exec_container(container, self.first_boot_identity_command(spec) + stop_ssh + common + package_cleanup + "\n")
            self.sanitized_containers.add(container)

    def write_checksums(self) -> None:
        lines = []
        for name in self.exported_files:
            path = self.output_dir / name
            if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
                raise RuntimeError("交付镜像文件缺失或为空")
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            lines.append(f"{digest.hexdigest()}  {name}\n")
        with (self.output_dir / "SHA256SUMS").open("x", encoding="utf-8") as handle:
            handle.write("".join(lines))

    def publish_and_export(self) -> None:
        for spec in self.specs:
            container = self.container_name(spec)
            if container not in self.sanitized_containers:
                raise RuntimeError("禁止发布尚未清除测试凭据的虚拟机")
            self.incus(["stop", container, "--timeout", "120"], timeout=150, diagnostic_stderr=True)
            result = self.incus(["list", container, "--format", "json"], timeout=30)
            instances = json.loads(result.stdout)
            if (not isinstance(instances, list) or len(instances) != 1 or
                    instances[0].get("name") != container or instances[0].get("type") != "virtual-machine" or
                    instances[0].get("status_code") != 102):
                raise RuntimeError("发布前必须确认本次虚拟机已正常停止")
            self.incus(["publish", container, "--alias", container])
            self.created_published_aliases.append(container)
            prefix = spec.container_name()
            with tempfile.TemporaryDirectory(prefix=".export-", dir=self.output_dir) as directory:
                export_dir = Path(directory)
                self.incus(["image", "export", container, str(export_dir / prefix)])
                metadata_path, disk_path = (Path(path) for path in normalize_export(export_dir, prefix))
                files = ((metadata_path, prefix + ".tar.xz"), (disk_path, prefix + ".qcow2"))
                for path, expected in files:
                    if (not path.resolve().is_relative_to(export_dir.resolve()) or path.name != expected or path.is_symlink()
                            or not path.is_file() or path.stat().st_size == 0):
                        raise RuntimeError("导出模块返回了无效文件")
                    destination = self.output_dir / expected
                    if destination.exists() or destination.is_symlink():
                        raise RuntimeError("禁止覆盖已有交付文件")
                sanitize_disk(disk_path)
                for path, expected in files:
                    if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
                        raise RuntimeError("离线清理后镜像文件无效")
                    os.link(path, self.output_dir / expected, follow_symlinks=False)
                    self.exported_files.append(expected)
            self.exported_files.sort()
            self.write_checksums()

    def final_cleanup(self) -> None:
        for name in reversed(self.created_containers[:]):
            try:
                self.incus(["delete", name, "--force"], timeout=60)
                self.created_containers.remove(name)
            except Exception:
                print("[注意] 本次创建的临时虚拟机清理失败", file=sys.stderr)
        for aliases in (self.created_published_aliases, self.created_base_aliases):
            for alias in reversed(aliases[:]):
                try:
                    self.incus(["image", "alias", "delete", alias], timeout=60)
                    aliases.remove(alias)
                except Exception:
                    print("[注意] 本次创建的镜像别名清理失败", file=sys.stderr)

    def write_summary(self, status: str, error: str | None = None) -> None:
        payload = {
            "status": status,
            "image_type": "virtual-machine",
            "started_at": self.started_at.isoformat(),
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "architecture": self.specs[0].architecture,
            "images": [asdict(spec) | {"image_alias": self.base_alias(spec)} for spec in self.specs],
            "exported_files": list(self.exported_files),
        }
        if error:
            payload["error"] = error.replace(self.root_password, "[临时凭据]")
        with (self.output_dir / "build-summary.json").open("x", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
        summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_file:
            with open(summary_file, "a", encoding="utf-8") as handle:
                handle.write(f"虚拟机镜像构建\n\n- 状态：{'成功' if status == 'success' else '失败'}\n- 架构：amd64\n")
                for name in self.exported_files:
                    handle.write(f"- {name}\n")

    @staticmethod
    def handle_sigterm(signum: int, frame: object) -> None:
        raise BuildTerminated("构建被终止信号中断")

    def run(self) -> None:
        status = "failed"
        error = None
        ready = False
        stage = "主机预检"
        previous_handler = signal.signal(signal.SIGTERM, self.handle_sigterm)
        try:
            self.preflight()
            ready = True
            self.output_dir.mkdir(parents=True, exist_ok=True)
            if any(self.output_dir.iterdir()):
                raise RuntimeError("输出目录必须为空")
            self.output_ready = True
            stages = (
                ("获取基础镜像", self.download_images), ("创建并启动虚拟机", self.launch_containers),
                ("配置远程登录", self.setup_containers), ("安装通用软件包", self.install_common_packages),
                ("写入镜像标识", self.write_readmes), ("测试远程登录", self.test_ssh),
                ("清理在线状态", self.cleanup_containers), ("停止并导出清理镜像", self.publish_and_export),
            )
            for stage, action in stages:
                action()
            status = "success"
        except (Exception, KeyboardInterrupt) as exc:
            error = f"阶段 {stage} 失败：{self.safe_error(exc)}"
            print(error, file=sys.stderr)
            raise RuntimeError(error) from None
        finally:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            try:
                if ready:
                    self.final_cleanup()
                if self.output_ready:
                    try:
                        self.write_summary(status, error)
                    except Exception:
                        if error is None:
                            raise RuntimeError("无法写入构建摘要") from None
                        print("[注意] 无法写入失败摘要", file=sys.stderr)
            finally:
                signal.signal(signal.SIGTERM, previous_handler)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="构建单规格 amd64 虚拟机镜像")
    parser.add_argument("--manifest", type=Path, default=Path("镜像.md"))
    parser.add_argument("--output-dir", type=Path, default=Path("dist"))
    parser.add_argument("--matrix", action="store_true")
    parser.add_argument("--architecture", choices=tuple(RUNNERS))
    parser.add_argument("--distro")
    parser.add_argument("--release")
    parser.add_argument("--ssh-timeout", type=float, default=120)
    parser.add_argument("--agent-timeout", type=float, default=300)
    parser.add_argument("--package-index-timeout", type=float, default=600)
    args = parser.parse_args(argv)
    if not args.matrix and not all((args.architecture, args.distro, args.release)):
        parser.error("构建必须指定架构、发行版和版本")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.matrix:
            include = [{"distro": spec.distro, "release": spec.release, "architecture": architecture, "runner": runner}
                       for architecture, runner in RUNNERS.items() for spec in load_manifest(args.manifest, architecture)]
            print(json.dumps({"include": include}, separators=(",", ":")))
            return 0
        specs = [spec for spec in load_manifest(args.manifest, args.architecture)
                 if spec.distro == args.distro and spec.release == args.release]
        if len(specs) != 1:
            raise ValueError("必须恰好匹配一个清单版本")
        Pipeline(specs, args.output_dir, ssh_timeout=args.ssh_timeout, agent_timeout=args.agent_timeout,
                 package_index_timeout=args.package_index_timeout).run()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        print("[错误] 构建失败；如已生成构建摘要，请查看摘要", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
