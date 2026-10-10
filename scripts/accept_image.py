from __future__ import annotations

import argparse
import base64
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
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from build_pipeline import (
    COMMON_PACKAGES, NATIVE_ARCHITECTURES, README_CONTENT, RELEASE_DISPLAY,
    RUNNERS, ImageSpec,
)
from scripts.image_cleanup import CREDENTIAL_PATHS
from scripts.verify_artifacts import verify_artifact


class CheckError(RuntimeError):
    pass


class AcceptanceTerminated(RuntimeError):
    pass


def safe_error(exc: BaseException) -> str:
    if isinstance(exc, CheckError):
        return str(exc)
    if isinstance(exc, (AcceptanceTerminated, KeyboardInterrupt)):
        return "验收中断或超过整体时限"
    if isinstance(exc, subprocess.TimeoutExpired):
        return "命令执行超时"
    if isinstance(exc, subprocess.CalledProcessError):
        return "命令执行失败"
    if isinstance(exc, OSError):
        return "文件系统或程序操作失败"
    if isinstance(exc, (ValueError, TypeError, KeyError)):
        return "产物或运行时数据无效"
    return "运行时出现未预期错误"


def parse_os_release(text: str) -> dict[str, str]:
    result = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith(chr(35)):
            continue
        key, separator, raw = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or key in result:
            raise CheckError("系统发行信息格式错误")
        values = shlex.split(raw, comments=False, posix=True)
        if len(values) > 1:
            raise CheckError("系统发行信息字段错误")
        result[key] = values[0] if values else ""
    return result


def check_os_release(text: str, spec: ImageSpec) -> None:
    values = parse_os_release(text)
    if values.get("ID") != spec.distro:
        raise CheckError("系统发行版不匹配")
    version = values.get("VERSION_ID", "")
    codename = values.get("VERSION_CODENAME", "")
    if spec.distro == "debian":
        expected = RELEASE_DISPLAY["debian"][spec.release]
        valid = bool(version or codename) and (not version or version == expected) and (
            not codename or codename == spec.release)
    elif spec.distro == "ubuntu":
        number = RELEASE_DISPLAY["ubuntu"][spec.release]
        valid = version == number[:2] + "." + number[2:] and (
            not codename or codename == spec.release)
    else:
        expected = spec.release.split("-", 1)[0]
        valid = bool(re.fullmatch(re.escape(expected) + r"(?:\.[0-9]+)*", version))
        if spec.distro == "centos":
            valid = valid and "CentOS Stream" in values.get("NAME", "")
    if not valid:
        raise CheckError("系统发行版本不匹配")


def import_paths(root: Path, spec: ImageSpec) -> list[Path]:
    expected = {key: getattr(spec, key) for key in ("distro", "release", "architecture")}
    if verify_artifact(root, expected) != 2:
        raise CheckError("虚拟机产物必须包含元数据和磁盘两个文件")
    summary = json.loads((root / "build-summary.json").read_text(encoding="utf-8"))
    names = [spec.container_name() + suffix for suffix in (".tar.xz", ".qcow2")]
    if summary.get("image_type") != "virtual-machine" or sorted(summary["exported_files"]) != sorted(names):
        raise CheckError("虚拟机产物类型或文件名不匹配")
    return [root / name for name in names]


def instance_row(text: str, name: str) -> dict:
    rows = json.loads(text)
    if not isinstance(rows, list):
        raise CheckError("实例列表格式错误")
    matches = [row for row in rows if isinstance(row, dict) and row.get("name") == name]
    if len(matches) != 1:
        raise CheckError("无法唯一识别验收虚拟机")
    return matches[0]


def normalize_mac(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value):
        return ""
    return value.lower()


def instance_addresses(text: str, name: str, mac: str) -> dict[str, str]:
    row = instance_row(text, name)
    mac = normalize_mac(mac)
    if row.get("status") != "Running" or not mac:
        return {}
    networks = (row.get("state") or {}).get("network") or {}
    matches = [interface for name, interface in networks.items()
               if name != "lo" and interface.get("type") != "loopback"
               and normalize_mac(interface.get("hwaddr", "")) == mac]
    if len(matches) != 1:
        return {}
    addresses = {}
    for entry in matches[0].get("addresses", []):
        raw = entry.get("address", "")
        if not isinstance(raw, str) or "%" in raw:
            continue
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if (address.is_loopback or address.is_unspecified or address.is_link_local
                or address.is_multicast or getattr(address, "ipv4_mapped", None)):
            continue
        if entry.get("family") == ("inet" if address.version == 4 else "inet6"):
            addresses.setdefault("ipv4" if address.version == 4 else "ipv6", str(address))
    return addresses


def public_hostkey_fingerprints(text: str) -> dict[str, str]:
    fingerprints = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            raise CheckError("主机公钥格式错误")
        algorithm = parts[0]
        if algorithm not in {"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256",
                              "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"} or algorithm in fingerprints:
            raise CheckError("主机公钥类型不受支持或重复")
        try:
            blob = base64.b64decode(parts[1], validate=True)
        except ValueError:
            raise CheckError("主机公钥编码错误") from None
        fields = []
        rest = blob
        while rest:
            if len(rest) < 4:
                raise CheckError("主机公钥数据错误")
            size = int.from_bytes(rest[:4], "big")
            if size == 0 or size > len(rest) - 4:
                raise CheckError("主机公钥数据错误")
            fields.append(rest[4:4 + size])
            rest = rest[4 + size:]
        valid = bool(fields) and fields[0] == algorithm.encode("ascii")
        if algorithm == "ssh-ed25519":
            valid = valid and len(fields) == 2 and len(fields[1]) == 32
        elif algorithm == "ssh-rsa":
            valid = valid and len(fields) == 3
        else:
            curve = algorithm.removeprefix("ecdsa-sha2-")
            valid = valid and len(fields) == 3 and fields[1] == curve.encode("ascii")
            valid = valid and len(fields[2]) == {"nistp256": 65, "nistp384": 97, "nistp521": 133}[curve]
        if not valid:
            raise CheckError("主机公钥字段错误")
        fingerprints[algorithm] = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    if not fingerprints:
        raise CheckError("未发现主机公钥")
    return fingerprints


class Acceptance:
    READY_TIMEOUT = 120
    AGENT_TIMEOUT = 240
    OVERALL_TIMEOUT = 25 * 60
    CLEANUP_TIMEOUT = 90
    DIAGNOSTICS_TIMEOUT = 45
    DIAGNOSTIC_LIMIT = 12000
    STDERR_LIMIT = 2048
    STAGES = (
        "report-directory", "preflight", "verify-export", "create-project", "profile-root",
        "profile-network", "import-image", "create-instance", "cold-start", "cold-agent",
        "cold-vm-config", "cold-network", "os-release", "packages", "ca-bundle", "readme",
        "root-lock", "credential-backups", "test-password", "cold-ssh-ipv4", "cold-ssh-ipv6",
        "cold-sshd-config", "cold-identity", "restart-stop", "restart-start", "restart-agent",
        "restart-vm-config", "restart-network", "restart-ssh-ipv4", "restart-ssh-ipv6",
        "restart-sshd-config", "restart-identity", "identity-stability", "primary-stop",
        "create-clone", "clone-start", "clone-agent", "clone-vm-config", "clone-network",
        "clone-root-lock", "clone-credential-backups", "clone-test-password", "clone-ssh-ipv4",
        "clone-ssh-ipv6", "clone-sshd-config", "clone-identity", "identity-uniqueness",
    )

    def __init__(self, spec: ImageSpec, output_dir: Path, report_dir: Path) -> None:
        self.spec = spec
        self.output_dir = output_dir.resolve()
        self.report_dir = report_dir.resolve()
        suffix = uuid.uuid4().hex
        self.project = "vpsm-vm-accept-" + suffix
        self.instance = "accept"
        self.clone_instance = "clone"
        self.owned_instance_names = {self.instance, self.clone_instance}
        self.alias = "export-" + suffix
        self.project_created = False
        self.report_ready = False
        self.deadline: float | None = None
        self.password = secrets.token_urlsafe(32)
        self.diagnostic_secrets = {self.password}
        self.diagnostic_secrets.update(os.environ.get(key, "") for key in ("SSHPASS", "IMAGE_ROOT_PASSWORD"))
        self.report = {
            "status": "failed", "started_at": datetime.now(timezone.utc).isoformat(),
            "steps": [{"stage": stage, "status": "NOT_RUN"} for stage in self.STAGES],
            "addresses": {}, "identities": {},
            "limitations": [
                "仅验收受控网络内的双栈远程登录，不要求公网连接。",
                "原始产物只读导入，身份检查来自独立首次启动的虚拟机。",
                "账户备份和登录残留在首次启动设置临时口令之前检查。",
            ],
        }

    def step(self, label: str, action: Callable):
        record = next((item for item in self.report["steps"] if item["stage"] == label), None)
        if record is None:
            record = {"stage": label, "status": "NOT_RUN"}
            self.report["steps"].append(record)
        try:
            result = action()
        except (Exception, KeyboardInterrupt) as exc:
            record.update(status="FAIL", error=safe_error(exc))
            self.report.setdefault("error", {"stage": label, "message": record["error"]})
            print(f"[错误] 验收阶段 {label}：{record['error']}", flush=True)
            raise
        record["status"] = "PASS"
        return result

    def diagnostic_text(self, value: str | bytes | None, limit: int) -> str:
        text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value or ""
        secrets_to_hide = self.diagnostic_secrets | {self.password}
        secrets_to_hide.update(os.environ.get(key, "") for key in ("SSHPASS", "IMAGE_ROOT_PASSWORD"))
        for secret in sorted(filter(None, secrets_to_hide), key=len, reverse=True):
            text = text.replace(secret, "[已隐藏]")
            text = text.replace(json.dumps(secret, ensure_ascii=False)[1:-1], "[已隐藏]")
        text = re.sub(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\|$)", "", text)
        text = re.sub(r"(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]", "", text)
        for secret in sorted(filter(None, secrets_to_hide), key=len, reverse=True):
            text = text.replace(secret, "[已隐藏]")
        text = re.sub(r"-----BEGIN [^-]*?(?:PRIVATE KEY|CERTIFICATE)-----.*?(?:-----END [^-]+-----|$)",
                      "[已隐藏]", text, flags=re.DOTALL)
        text = re.sub(r"(?im)^.*(?:password|passwd|sshpass|token|credential|secret|authorization|user\.|volatile\.)[^\n]*$",
                      "[已隐藏敏感行]", text)
        text = text.replace("::", "：：").replace(chr(35) * 2 + "[", "[已移除标记]")
        text = "".join(character if character == "\n" or character.isprintable()
                       else f"\\u{ord(character):04x}" for character in text)
        return text[:limit] + ("\n[已截断]" if len(text) > limit else "")

    def command(self, args: Sequence[str], *, input: str | None = None,
                timeout: float = 60, password: bool = False,
                diagnostic: bool = False) -> subprocess.CompletedProcess:
        if self.deadline is not None:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise CheckError("超过整体验收时限")
            timeout = min(timeout, remaining)
        environment = {key: value for key, value in os.environ.items()
                       if key not in {"IMAGE_ROOT_PASSWORD", "SSHPASS"}}
        if password:
            environment["SSHPASS"] = self.password
        diagnostic = diagnostic and input is None and not password and list(args[:3]) == [
            "incus", "--project", self.project] and (
                list(args[3:4]) in (["init"], ["start"], ["stop"])
                or list(args[3:5]) == ["image", "import"]
                or list(args[3:6]) in (["config", "device", "add"], ["profile", "device", "add"]))
        try:
            return subprocess.run(list(args), input=input, text=True, capture_output=True,
                                  check=True, timeout=timeout, env=environment)
        except subprocess.CalledProcessError as exc:
            if diagnostic:
                stderr = self.diagnostic_text(exc.stderr, self.STDERR_LIMIT)
                raise CheckError(f"命令执行失败，退出码 {exc.returncode}：{stderr or '无标准错误输出'}") from None
            raise
        except subprocess.TimeoutExpired as exc:
            if diagnostic:
                stderr = self.diagnostic_text(exc.stderr, self.STDERR_LIMIT)
                raise CheckError(f"命令执行超时：{stderr or '无标准错误输出'}") from None
            raise

    def incus(self, args: Sequence[str], **kwargs) -> subprocess.CompletedProcess:
        return self.command(["incus", "--project", self.project, *args], **kwargs)

    def guest(self, args: Sequence[str], **kwargs) -> subprocess.CompletedProcess:
        return self.incus(["exec", self.instance, "--", *args], **kwargs)

    def prepare_report(self) -> None:
        if self.report_dir == self.output_dir or self.output_dir in self.report_dir.parents:
            raise CheckError("验收报告目录必须位于镜像产物目录之外")
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            path = Path(summary).resolve()
            if path == self.output_dir or self.output_dir in path.parents:
                raise CheckError("流水线摘要必须位于镜像产物目录之外")
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.report_ready = True

    def preflight(self) -> None:
        spec = self.spec
        if (spec.architecture != "amd64" or spec.architecture not in RUNNERS
                or NATIVE_ARCHITECTURES.get(platform.machine().lower()) != "amd64"):
            raise CheckError("仅支持原生运行器上的 amd64 虚拟机")
        valid_release = False
        if spec.distro in RELEASE_DISPLAY:
            valid_release = spec.release in RELEASE_DISPLAY[spec.distro]
        elif spec.distro == "alpine":
            valid_release = bool(re.fullmatch(r"3\.[0-9]+", spec.release))
        elif spec.distro == "almalinux":
            valid_release = spec.release in {"8", "9", "10"}
        if not valid_release:
            raise CheckError("不支持指定发行版或版本")
        for timeout in (self.READY_TIMEOUT, self.AGENT_TIMEOUT, self.OVERALL_TIMEOUT,
                        self.DIAGNOSTICS_TIMEOUT, self.CLEANUP_TIMEOUT):
            if not math.isfinite(timeout) or timeout <= 0:
                raise CheckError("验收时限必须为有限正数")
        packages = COMMON_PACKAGES.split()
        if len(packages) != 9 or len(set(packages)) != 9 or "ca-certificates" not in packages:
            raise CheckError("预装包清单必须包含九个不同软件包及证书包")
        for executable in ("incus", "sshpass", "ssh"):
            if shutil.which(executable) is None:
                raise CheckError("缺少虚拟机或远程登录命令")
        self.report["image"] = {key: getattr(spec, key) for key in ("distro", "release", "architecture")}
        self.report["image_type"] = "virtual-machine"

    def create_project(self) -> None:
        self.command(["incus", "--project", "default", "project", "create", self.project,
                      "-c", "features.images=true", "-c", "features.profiles=true",
                      "-c", "features.networks=false"])
        self.project_created = True

    def init_instance(self) -> None:
        self.incus([
            "init", self.alias, self.instance, "--vm", "--profile", "default",
            "-c", "security.secureboot=false", "-c", "limits.cpu=2",
            "-c", "limits.memory=2GiB", "-d", "root,size=12GiB",
        ], timeout=180, diagnostic=True)
        self.incus(["config", "device", "add", self.instance, "agent", "disk", "source=agent:config"],
                   diagnostic=True)

    def check_vm_config(self) -> None:
        row = instance_row(self.incus(["list", self.instance, "--format", "json"]).stdout, self.instance)
        config = row.get("expanded_config") or {}
        if row.get("type") != "virtual-machine" or config.get("security.secureboot") != "false":
            raise CheckError("实例必须为关闭安全启动的虚拟机")
        if config.get("limits.cpu") != "2" or config.get("limits.memory") != "2GiB":
            raise CheckError("虚拟机处理器或内存限制不匹配")
        devices = row.get("expanded_devices") or {}
        root = devices.get("root") or {}
        nic = devices.get("eth0") or {}
        if (root.get("type") != "disk" or root.get("pool") != "default" or root.get("path") != "/"
                or root.get("size") != "12GiB"):
            raise CheckError("虚拟机根磁盘配置不匹配")
        if nic.get("type") != "nic" or nic.get("network") != "incusbr0" or nic.get("name") != "eth0":
            raise CheckError("虚拟机网卡配置不匹配")

    def wait(self, probe: Callable[[float], object], error: str, *, timeout: float | None = None):
        deadline = time.monotonic() + (self.READY_TIMEOUT if timeout is None else timeout)
        if self.deadline is not None:
            deadline = min(deadline, self.deadline)
        while (remaining := deadline - time.monotonic()) > 0:
            try:
                result = probe(min(10, remaining))
                if result and time.monotonic() <= deadline:
                    return result
            except (subprocess.SubprocessError, OSError):
                pass
            time.sleep(min(2, max(0, deadline - time.monotonic())))
        raise CheckError(error)

    def agent_ready(self) -> None:
        self.wait(lambda timeout: self.guest(["true"], timeout=timeout).returncode == 0,
                  "虚拟机代理就绪超时", timeout=self.AGENT_TIMEOUT)

    def network_ready(self, phase: str) -> dict[str, str]:
        def probe(timeout: float):
            started = time.monotonic()
            text = self.incus(["list", self.instance, "--format", "json"], timeout=timeout).stdout
            row = instance_row(text, self.instance)
            device = (row.get("expanded_devices") or {}).get("eth0") or {}
            mac = normalize_mac(device.get("hwaddr", "")) or normalize_mac(
                (row.get("expanded_config") or {}).get("volatile.eth0.hwaddr", ""))
            if not mac:
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    return None
                mac = self.incus(["config", "get", self.instance, "volatile.eth0.hwaddr"],
                                 timeout=remaining).stdout.strip()
            addresses = instance_addresses(text, self.instance, mac)
            return addresses if set(addresses) == {"ipv4", "ipv6"} else None
        addresses = self.wait(probe, "按网卡硬件地址匹配的双栈网络就绪超时")
        self.report["addresses"][phase] = addresses
        return addresses

    def check_packages(self) -> None:
        for package in COMMON_PACKAGES.split():
            if self.spec.distro == "alpine":
                self.guest(["apk", "info", "-e", package])
            elif self.spec.distro in {"debian", "ubuntu"}:
                result = self.guest(["dpkg-query", "-W", "-f=${Status}", package])
                if result.stdout.strip() != "install ok installed":
                    raise CheckError("必需软件包未完整安装")
            else:
                self.guest(["rpm", "-q", package])

    def check_readme(self) -> None:
        if self.guest(["cat", "/root/README.md"]).stdout != README_CONTENT + "\n":
            raise CheckError("镜像说明文件与构建内容不一致")

    def check_root_lock(self) -> None:
        rows = [line.split(":") for line in self.guest(["cat", "/etc/shadow"]).stdout.splitlines()
                if line.split(":", 1)[0] == "root"]
        if len(rows) != 1 or len(rows[0]) != 9 or rows[0][1] != "!":
            raise CheckError("发布镜像的管理员口令字段必须严格为感叹号")

    def check_credential_backups(self) -> None:
        rules = {f"{index:03d}\n": path for index, path in enumerate(CREDENTIAL_PATHS, 1)}
        script = "set -eu; " + " ".join(
            f"for path in {path}; do "
            'if [ -e "$path" ] || [ -L "$path" ]; then '
            f"printf '%s\\n' '{index:03d}'; exit 1; fi; done;"
            for index, path in enumerate(CREDENTIAL_PATHS, 1)
        )
        try:
            result = self.guest(["sh", "-c", script])
        except subprocess.CalledProcessError as exc:
            if exc.returncode == 1 and exc.stdout in rules:
                raise CheckError(
                    f"凭据残留命中规则 {exc.stdout.strip()}：{rules[exc.stdout]}，退出码 {exc.returncode}"
                ) from None
            raise CheckError(f"凭据残留检查执行故障，退出码 {exc.returncode}") from None
        if result.stdout:
            raise CheckError(f"凭据残留检查返回无效结果，退出码 {result.returncode}")

    def ssh(self, family: int, address: str) -> None:
        parsed = ipaddress.ip_address(address)
        if family not in (4, 6) or parsed.version != family:
            raise CheckError("远程登录地址族不匹配")
        def probe(timeout: float):
            result = self.command([
                "sshpass", "-e", "ssh", f"-{family}", "-F", "/dev/null",
                "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                "-o", "GlobalKnownHostsFile=/dev/null", "-o", "ConnectTimeout=5",
                "-o", "ConnectionAttempts=1", "-o", "NumberOfPasswordPrompts=1",
                "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
                "-o", "LogLevel=ERROR", f"root@{address}", "whoami",
            ], timeout=timeout, password=True)
            return result.stdout.strip() == "root"
        self.wait(probe, "管理员口令远程登录验收超时")

    def check_boot(self, phase: str, addresses: dict[str, str]) -> None:
        self.step(phase + "-ssh-ipv4", lambda: self.ssh(4, addresses["ipv4"]))
        self.step(phase + "-ssh-ipv6", lambda: self.ssh(6, addresses["ipv6"]))
        self.step(phase + "-sshd-config", lambda: self.guest(["/usr/sbin/sshd", "-t"]))

    def sample_identity(self, phase: str) -> dict:
        machine_id = self.guest(["cat", "/etc/machine-id"]).stdout
        if not re.fullmatch(r"[0-9a-f]{32}\n?", machine_id) or machine_id.rstrip("\n") == "0" * 32:
            raise CheckError("机器标识必须为非零的三十二位小写十六进制值")
        public_keys = self.guest([
            "sh", "-c",
            "set -eu; for path in /etc/ssh/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_rsa_key.pub "
            '/etc/ssh/ssh_host_ecdsa_key.pub; do if [ -e "$path" ] || [ -L "$path" ]; '
            'then cat "$path"; printf "\\n"; fi; done',
        ]).stdout
        keys = public_hostkey_fingerprints("\n".join(line for line in public_keys.splitlines() if line.strip()))
        identity = {
            "machine_id_sha256": hashlib.sha256(machine_id.rstrip("\n").encode("ascii")).hexdigest(),
            "ssh_host_key_fingerprints": keys,
        }
        self.report["identities"][phase] = identity
        return identity

    @staticmethod
    def check_identity_stability(initial: dict, restarted: dict) -> None:
        if initial != restarted:
            raise CheckError("正常重启后机器标识或主机公钥发生变化")

    @staticmethod
    def check_identity_uniqueness(primary: dict, clone: dict) -> None:
        if primary["machine_id_sha256"] == clone["machine_id_sha256"]:
            raise CheckError("两个独立虚拟机的机器标识重复")
        first = primary["ssh_host_key_fingerprints"]
        second = clone["ssh_host_key_fingerprints"]
        if not first or first.keys() != second.keys():
            raise CheckError("独立虚拟机必须具有相同的非空主机公钥类型集")
        if set(first.values()) & set(second.values()):
            raise CheckError("两个独立虚拟机的主机公钥重复")

    def boot_ready(self, phase: str) -> dict[str, str]:
        self.step(phase + "-start", lambda: self.incus(["start", self.instance], timeout=120, diagnostic=True))
        self.step(phase + "-agent", self.agent_ready)
        self.step(phase + "-vm-config", self.check_vm_config)
        return self.step(phase + "-network", lambda: self.network_ready(phase))

    def check_clone(self, primary_identity: dict) -> None:
        self.step("primary-stop", lambda: self.incus(["stop", self.instance, "--timeout", "60"], timeout=90, diagnostic=True))
        primary_instance, primary_password = self.instance, self.password
        self.instance = self.clone_instance
        self.password = secrets.token_urlsafe(32)
        self.diagnostic_secrets.update((primary_password, self.password))
        try:
            self.step("create-clone", self.init_instance)
            addresses = self.boot_ready("clone")
            self.step("clone-root-lock", self.check_root_lock)
            self.step("clone-credential-backups", self.check_credential_backups)
            self.step("clone-test-password", lambda: self.guest(["chpasswd"], input=f"root:{self.password}\n"))
            self.check_boot("clone", addresses)
            identity = self.step("clone-identity", lambda: self.sample_identity("clone"))
            self.step("identity-uniqueness", lambda: self.check_identity_uniqueness(primary_identity, identity))
        finally:
            self.instance, self.password = primary_instance, primary_password

    def collect_diagnostics(self) -> None:
        if not self.project_created or not self.report_ready:
            return
        directory = self.report_dir / "diagnostics"
        directory.mkdir(parents=True, exist_ok=True)
        record = self.report.setdefault("diagnostics", {"files": [], "errors": []})
        rows = json.loads(self.incus(["list", "--format", "json"], timeout=10).stdout)
        if not isinstance(rows, list):
            raise CheckError("诊断实例列表格式错误")
        config_keys = {"security.secureboot", "limits.cpu", "limits.memory", "image.architecture",
                       "image.description", "image.os", "image.release", "image.serial", "image.type"}
        device_keys = {"type", "pool", "path", "size", "network", "name", "nictype"}
        owned_rows = {}
        for row in rows:
            if isinstance(row, dict) and isinstance(row.get("name"), str) and row["name"] in self.owned_instance_names:
                owned_rows[row["name"]] = row
        for row in owned_rows.values():
            for config_field in ("config", "expanded_config"):
                config = row.get(config_field) or {}
                if isinstance(config, dict):
                    self.diagnostic_secrets.update(value for key, value in config.items()
                                                   if key not in config_keys and isinstance(value, str) and value)
            for device_field in ("devices", "expanded_devices"):
                devices = row.get(device_field) or {}
                if isinstance(devices, dict):
                    for device in devices.values():
                        if isinstance(device, dict):
                            self.diagnostic_secrets.update(value for key, value in device.items()
                                                           if key not in device_keys and isinstance(value, str)
                                                           and value and value != "agent:config")
        for name, row in owned_rows.items():
            if self.deadline is not None and time.monotonic() >= self.deadline:
                record["errors"].append("诊断收集超过时限")
                return
            config = row.get("expanded_config") or row.get("config") or {}
            devices = row.get("expanded_devices") or row.get("devices") or {}
            if not isinstance(config, dict) or not isinstance(devices, dict):
                record["errors"].append("实例诊断配置格式错误")
                continue
            safe_config = {
                key: self.diagnostic_text(value, 256) for key, value in config.items()
                if key in config_keys and isinstance(value, str)
            }
            safe_devices = {}
            for device_name in ("root", "eth0", "agent"):
                device = devices.get(device_name)
                if not isinstance(device, dict):
                    continue
                safe_devices[device_name] = {
                    key: self.diagnostic_text(value, 256) for key, value in device.items()
                    if key in device_keys and isinstance(value, str)
                }
                if device_name == "agent" and device.get("source") == "agent:config":
                    safe_devices[device_name]["source"] = "agent:config"
            configuration = {
                key: self.diagnostic_text(row.get(key), 256)
                for key in ("name", "type", "status") if isinstance(row.get(key), str)
            }
            configuration.update(config=safe_config, devices=safe_devices)
            path = directory / (name + "-config.json")
            try:
                path.write_text(json.dumps(configuration, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                record["files"].append(str(path.relative_to(self.report_dir)))
            except (Exception, KeyboardInterrupt) as exc:
                record["errors"].append(safe_error(exc))
            for label, args in (
                ("logs", ["info", name, "--show-log"]),
                ("console", ["console", name, "--show-log"]),
            ):
                if self.deadline is not None and time.monotonic() >= self.deadline:
                    record["errors"].append("诊断收集超过时限")
                    return
                try:
                    result = self.incus(args, timeout=10)
                    path = directory / (name + "-" + label + ".txt")
                    path.write_text(self.diagnostic_text(result.stdout, self.DIAGNOSTIC_LIMIT), encoding="utf-8")
                    record["files"].append(str(path.relative_to(self.report_dir)))
                except (Exception, KeyboardInterrupt) as exc:
                    record["errors"].append(safe_error(exc))

    def cleanup(self) -> bool:
        if not self.project_created:
            return True
        ok = True
        for resource, listing, key, delete in (
            ("instances", ["list", "--format", "json"], "name", ["delete"]),
            ("images", ["image", "list", "--format", "json"], "fingerprint", ["image", "delete"]),
            ("profiles", ["profile", "list", "--format", "json"], "name", ["profile", "delete"]),
        ):
            try:
                rows = self.step("cleanup-list-" + resource, lambda: json.loads(self.incus(listing, timeout=15).stdout))
                for index, row in enumerate(rows):
                    if resource == "profiles" and row[key] == "default":
                        continue
                    force = self.report["status"] != "success"
                    if resource == "instances" and not force and row.get("status") != "Stopped":
                        try:
                            self.step(f"cleanup-stop-{index}", lambda: self.incus(
                                ["stop", row[key], "--timeout", "20"], timeout=25, diagnostic=True))
                        except Exception:
                            ok = False
                            force = True
                    args = [*delete, row[key]] + (["--force"] if resource == "instances" and force else [])
                    try:
                        self.step(f"cleanup-{resource}-{index}", lambda: self.incus(args, timeout=30))
                    except Exception:
                        ok = False
            except Exception:
                ok = False
        try:
            self.step("cleanup-project", lambda: self.incus(["project", "delete", self.project], timeout=30))
            self.project_created = False
        except Exception:
            ok = False
        return ok

    def write_report(self) -> None:
        self.report["finished_at"] = datetime.now(timezone.utc).isoformat()
        path = self.report_dir / "acceptance-report.json"
        path.write_text(json.dumps(self.report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            labels = {"success": "通过", "failed": "失败", "PASS": "通过", "FAIL": "失败", "NOT_RUN": "未执行"}
            rows = ["虚拟机镜像验收", "", "结果：" + labels[self.report["status"]], "",
                    "| 阶段 | 结果 |", "|---|---|"]
            rows += [f"| {item['stage']} | {labels[item['status']]} |" for item in self.report["steps"]]
            if "error" in self.report:
                error = self.report["error"]
                rows += ["", f"失败阶段：{error['stage']}，{error['message']}"]
            rows += ["", *self.report["limitations"], ""]
            with open(summary, "a", encoding="utf-8") as handle:
                handle.write("\n".join(rows) + "\n")

    @staticmethod
    def interrupted(signum: int, frame: object) -> None:
        raise AcceptanceTerminated()

    def run(self) -> int:
        previous_term = signal.signal(signal.SIGTERM, self.interrupted)
        previous_alarm = signal.signal(signal.SIGALRM, self.interrupted)
        self.deadline = time.monotonic() + self.OVERALL_TIMEOUT
        signal.setitimer(signal.ITIMER_REAL, self.OVERALL_TIMEOUT)
        try:
            self.step("report-directory", self.prepare_report)
            self.step("preflight", self.preflight)
            paths = self.step("verify-export", lambda: import_paths(self.output_dir, self.spec))
            self.step("create-project", self.create_project)
            self.step("profile-root", lambda: self.incus([
                "profile", "device", "add", "default", "root", "disk", "pool=default", "path=/"], diagnostic=True))
            self.step("profile-network", lambda: self.incus([
                "profile", "device", "add", "default", "eth0", "nic", "network=incusbr0", "name=eth0"], diagnostic=True))
            self.step("import-image", lambda: self.incus([
                "image", "import", *map(str, paths), "--alias", self.alias], timeout=300, diagnostic=True))
            self.step("create-instance", self.init_instance)
            addresses = self.boot_ready("cold")
            self.step("os-release", lambda: check_os_release(self.guest(["cat", "/etc/os-release"]).stdout, self.spec))
            self.step("packages", self.check_packages)
            ca_bundle = ("/etc/pki/tls/certs/ca-bundle.crt" if self.spec.distro in {"almalinux", "centos"}
                         else "/etc/ssl/certs/ca-certificates.crt")
            self.step("ca-bundle", lambda: self.guest(["test", "-s", ca_bundle]))
            self.step("readme", self.check_readme)
            self.step("root-lock", self.check_root_lock)
            self.step("credential-backups", self.check_credential_backups)
            self.step("test-password", lambda: self.guest(["chpasswd"], input=f"root:{self.password}\n"))
            self.check_boot("cold", addresses)
            initial = self.step("cold-identity", lambda: self.sample_identity("cold"))
            self.step("restart-stop", lambda: self.incus(["stop", self.instance, "--timeout", "60"], timeout=90, diagnostic=True))
            addresses = self.boot_ready("restart")
            self.check_boot("restart", addresses)
            restarted = self.step("restart-identity", lambda: self.sample_identity("restart"))
            self.step("identity-stability", lambda: self.check_identity_stability(initial, restarted))
            self.check_clone(initial)
            self.report["status"] = "success"
        except (Exception, KeyboardInterrupt) as exc:
            self.report.setdefault("error", {"stage": "acceptance", "message": safe_error(exc)})
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            previous_int = signal.signal(signal.SIGINT, signal.SIG_IGN)
            if self.report["status"] != "success" and self.project_created and self.report_ready:
                self.deadline = time.monotonic() + self.DIAGNOSTICS_TIMEOUT
                signal.setitimer(signal.ITIMER_REAL, self.DIAGNOSTICS_TIMEOUT)
                try:
                    self.collect_diagnostics()
                except (Exception, KeyboardInterrupt) as exc:
                    self.report.setdefault("diagnostics", {"files": [], "errors": []})["errors"].append(safe_error(exc))
                finally:
                    signal.setitimer(signal.ITIMER_REAL, 0)
            self.deadline = time.monotonic() + self.CLEANUP_TIMEOUT
            signal.setitimer(signal.ITIMER_REAL, self.CLEANUP_TIMEOUT)
            try:
                try:
                    if not self.cleanup():
                        self.report["status"] = "failed"
                except Exception as exc:
                    self.report["status"] = "failed"
                    self.report.setdefault("error", {"stage": "cleanup", "message": safe_error(exc)})
                if self.report_ready:
                    try:
                        self.write_report()
                    except Exception:
                        self.report["status"] = "failed"
                        print("[错误] 无法写入验收报告或流水线摘要", flush=True)
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, previous_alarm)
                signal.signal(signal.SIGTERM, previous_term)
                signal.signal(signal.SIGINT, previous_int)
        return 0 if self.report["status"] == "success" else 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="验收原生架构的虚拟机镜像产物")
    parser.add_argument("--output-dir", type=Path, default=Path("dist"), help="镜像产物目录")
    parser.add_argument("--report-dir", type=Path, default=Path("acceptance"), help="验收报告目录")
    parser.add_argument("--distro", required=True, help="发行版")
    parser.add_argument("--release", required=True, help="发行版本")
    parser.add_argument("--architecture", required=True, choices=("amd64",), help="原生处理器架构")
    args = parser.parse_args(argv)
    spec = ImageSpec(args.distro, args.release, args.architecture, "default", "acceptance")
    return Acceptance(spec, args.output_dir, args.report_dir).run()


if __name__ == "__main__":
    raise SystemExit(main())
