from __future__ import annotations

import fnmatch
import importlib
from pathlib import Path, PurePosixPath

from scripts.image_cleanup import CREDENTIAL_DIRECTORIES, CREDENTIAL_PATHS, PROVISION_CONF, PROVISION_MASK
from scripts.vm_image import validate_disk


REQUIRED_PATHS = ("/etc", "/etc/ssh", "/var/lib/dbus", "/var/backups", "/root", *CREDENTIAL_PATHS)


def safe_guest_path(path: str) -> str:
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
        raise ValueError("客户机路径不是安全绝对路径")
    if "\\" in path or any(ord(char) < 32 or ord(char) == 127 for char in path):
        raise ValueError("客户机路径包含非法字符")
    if ".." in path.split("/") or str(PurePosixPath(path)) != path:
        raise ValueError("客户机路径越界或未规范化")
    return path


def safe_parent(guest: object, path: str) -> bool:
    safe_guest_path(path)
    parent = str(PurePosixPath(path).parent)
    if not guest.is_dir(parent):
        if guest.exists(parent) or guest.is_symlink(parent):
            raise ValueError("清理目标父路径不是目录")
        return False
    if guest.realpath(parent) != parent:
        raise ValueError("清理目标父路径包含符号链接")
    return True


def cleanup_targets(guest: object) -> set[str]:
    paths = {path for path in CREDENTIAL_PATHS if "*" not in path}
    patterns = ("/etc/ssh/ssh_host_*", *(path for path in CREDENTIAL_PATHS if "*" in path))
    for pattern in patterns:
        if safe_parent(guest, pattern):
            parent = str(PurePosixPath(pattern).parent)
            for path in guest.glob_expand(pattern):
                safe_guest_path(path)
                if str(PurePosixPath(path).parent) != parent or not fnmatch.fnmatchcase(path, pattern):
                    raise ValueError("清理目标超出允许范围")
                paths.add(path)
    return paths


def sanitize_disk(path: Path) -> None:
    path = Path(path).absolute()
    validate_disk(path, check=True)
    guestfs = importlib.import_module("guestfs")
    guest = guestfs.GuestFS(python_return_dict=True)
    launched = False
    try:
        guest.set_backend("direct")
        guest.set_trace(False)
        guest.set_verbose(False)
        guest.add_drive_opts(str(path), format="qcow2", readonly=0)
        guest.launch()
        launched = True
        roots = guest.inspect_os()
        if len(roots) != 1:
            raise ValueError("虚拟机必须包含唯一可识别系统根")
        mountpoints = guest.inspect_get_mountpoints(roots[0])
        if not isinstance(mountpoints, dict) or "/" not in mountpoints:
            raise ValueError("虚拟机缺少有效挂载信息")
        for mountpoint, device in mountpoints.items():
            safe_guest_path(mountpoint)
            safe_guest_path(device)
            if not device.startswith("/dev/") or device == "/dev/":
                raise ValueError("挂载设备不合法")
        for mountpoint in sorted(mountpoints, key=lambda item: (item.count("/"), len(item), item)):
            if mountpoint == "/" or any(target == mountpoint or target.startswith(mountpoint + "/") for target in REQUIRED_PATHS):
                if mountpoint != "/" and (not guest.is_dir(mountpoint) or guest.realpath(mountpoint) != mountpoint):
                    raise ValueError("挂载路径不存在或包含符号链接")
                guest.mount(mountpoints[mountpoint], mountpoint)
        machine_id = "/etc/machine-id"
        if not safe_parent(guest, machine_id):
            raise ValueError("虚拟机缺少系统配置目录")
        if guest.is_symlink(machine_id) or guest.exists(machine_id) and not guest.is_file(machine_id):
            raise ValueError("系统身份文件不是普通文件")
        guest.write(machine_id, b"")
        dbus_id = "/var/lib/dbus/machine-id"
        if safe_parent(guest, dbus_id):
            if guest.exists(dbus_id) or guest.is_symlink(dbus_id):
                if not guest.is_symlink(dbus_id) and not guest.is_file(dbus_id):
                    raise ValueError("消息总线身份文件类型错误")
                guest.rm(dbus_id)
            guest.ln_sf("/etc/machine-id", dbus_id)
        if guest.exists(PROVISION_CONF) or guest.is_symlink(PROVISION_CONF):
            if guest.is_symlink(PROVISION_CONF) or not guest.is_file(PROVISION_CONF):
                raise ValueError("tmpfiles 配置不是普通文件")
            if b"/root/.ssh" in guest.read_file(PROVISION_CONF):
                mask_dir = str(PurePosixPath(PROVISION_MASK).parent)
                if guest.is_symlink(mask_dir):
                    raise ValueError("tmpfiles 掩蔽目录包含符号链接")
                if not guest.is_dir(mask_dir):
                    guest.mkdir_p(mask_dir)
                if guest.is_symlink(PROVISION_MASK) or guest.exists(PROVISION_MASK) and not guest.is_file(PROVISION_MASK):
                    raise ValueError("tmpfiles 掩蔽路径类型错误")
                guest.write(PROVISION_MASK, b"")
        targets = cleanup_targets(guest)
        for target in sorted(targets):
            if not safe_parent(guest, target):
                continue
            if guest.exists(target) or guest.is_symlink(target):
                if target in CREDENTIAL_DIRECTORIES and not guest.is_symlink(target) and guest.is_dir(target):
                    if guest.realpath(target) != target:
                        raise ValueError("清理目录包含符号链接")
                    guest.rm_rf(target)
                else:
                    if not guest.is_symlink(target) and not guest.is_file(target):
                        raise ValueError("清理目标不是普通文件或符号链接")
                    guest.rm(target)
        if guest.is_symlink(machine_id) or not guest.is_file(machine_id) or guest.filesize(machine_id) != 0:
            raise ValueError("系统身份未清空")
        if safe_parent(guest, dbus_id):
            if not guest.is_symlink(dbus_id) or guest.readlink(dbus_id) != "/etc/machine-id":
                raise ValueError("消息总线身份链接未正确重建")
            if guest.filesize(dbus_id) != 0:
                raise ValueError("消息总线身份未清空")
        for target in targets | cleanup_targets(guest):
            if safe_parent(guest, target) and (guest.exists(target) or guest.is_symlink(target)):
                raise ValueError("身份密钥、账号备份或历史记录仍存在")
        if guest.exists(PROVISION_MASK) or guest.is_symlink(PROVISION_MASK):
            if guest.is_symlink(PROVISION_MASK) or not guest.is_file(PROVISION_MASK) or guest.filesize(PROVISION_MASK) != 0:
                raise ValueError("tmpfiles 掩蔽文件无效")
        guest.sync()
        guest.shutdown()
        launched = False
    finally:
        try:
            if launched:
                guest.shutdown()
        finally:
            guest.close()
