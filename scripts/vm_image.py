from __future__ import annotations

import io
import json
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath


MAX_METADATA_SIZE = 1024 * 1024
MAX_TEMPLATE_SIZE = 16 * 1024 * 1024
MAX_METADATA_TOTAL = 64 * 1024 * 1024
MAX_MEMBERS = 4096
MAX_DISK_SIZE = 256 * 1024 * 1024 * 1024
ARCHIVE_SUFFIXES = (".tar.xz", ".tar.gz", ".tar.bz2", ".tar")
TRUSTED_DIRECTORY = Path(__file__).resolve().parent


def regular_file(path: Path) -> Path:
    path = Path(path).absolute()
    if path.is_symlink() or not path.is_file():
        raise ValueError("文件缺失或不是普通文件")
    if path.stat().st_size == 0:
        raise ValueError("文件为空")
    return path


def validate_disk(path: Path, check: bool = False) -> dict:
    path = regular_file(path)
    if path.stat().st_size > MAX_DISK_SIZE:
        raise ValueError("磁盘文件超出大小限制")
    with path.open("rb") as handle:
        header = handle.read(104)
    if len(header) < 72 or header[:4] != b"QFI\xfb":
        raise ValueError("磁盘不是有效的 qcow2 文件")
    version = struct.unpack_from(">I", header, 4)[0]
    backing_offset, backing_size = struct.unpack_from(">QI", header, 8)
    if version not in {2, 3} or backing_offset or backing_size:
        raise ValueError("磁盘版本不支持或依赖后端文件")
    if version == 3:
        if len(header) < 104 or struct.unpack_from(">Q", header, 72)[0] & 4:
            raise ValueError("磁盘依赖外部数据文件或头部不完整")
    result = subprocess.run(
        ["qemu-img", "info", "--output=json", "--", str(path)],
        check=True, capture_output=True, text=True, timeout=120,
        cwd=TRUSTED_DIRECTORY,
    )
    info = json.loads(result.stdout)
    if not isinstance(info, dict) or info.get("format") != "qcow2":
        raise ValueError("磁盘格式不是 qcow2")

    def reject_dependencies(value: object) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                normalized = key.lower().replace("_", "-")
                if ("backing" in normalized or normalized in {"data-file", "external-data-file"}) and item:
                    raise ValueError("磁盘存在外部依赖")
                reject_dependencies(item)
        elif isinstance(value, list):
            for item in value:
                reject_dependencies(item)

    reject_dependencies(info)
    if check:
        subprocess.run(
            ["qemu-img", "check", "-f", "qcow2", "--", str(path)],
            check=True, capture_output=True, text=True, timeout=3600,
            cwd=TRUSTED_DIRECTORY,
        )
    return info


class SafeTarInfo(tarfile.TarInfo):
    def _proc_member(self, archive: tarfile.TarFile) -> tarfile.TarInfo:
        archive.safe_header_count = getattr(archive, "safe_header_count", 0) + 1
        if archive.safe_header_count > MAX_MEMBERS * 2:
            raise ValueError("归档扩展头过多")
        if self.type in {tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK}:
            archive.safe_header_size = getattr(archive, "safe_header_size", 0) + self.size
            if self.size < 0 or archive.safe_header_size > MAX_METADATA_SIZE:
                raise ValueError("归档扩展头过大")
        elif not (self.isfile() or self.isdir()) or self.type == tarfile.GNUTYPE_SPARSE:
            raise ValueError("归档包含不支持的成员类型")
        return super()._proc_member(archive)

    def _proc_gnusparse_00(self, *args: object) -> None:
        raise ValueError("归档包含稀疏成员")

    _proc_gnusparse_01 = _proc_gnusparse_00
    _proc_gnusparse_10 = _proc_gnusparse_00


def member_name(member: tarfile.TarInfo) -> str:
    name = member.name
    if not name or "\\" in name or any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise ValueError("归档成员名称不安全")
    if name.startswith("/") or ".." in name.split("/"):
        raise ValueError("归档成员路径越界")
    parts = [part for part in name.split("/") if part not in {"", "."}]
    normalized = "/".join(parts)
    if not (member.isfile() or member.isdir()) or member.issparse():
        raise ValueError("归档包含链接、特殊文件或稀疏成员")
    if member.linkname or member.size < 0 or len(name) > 4096:
        raise ValueError("归档成员信息不安全")
    if member.isdir() and member.size:
        raise ValueError("归档目录携带数据")
    return normalized


def scan_archive(path: Path, disk_output: Path | None = None) -> tuple[list[tuple[str, bool, bytes]], bool]:
    path = regular_file(path)
    if disk_output is None and path.stat().st_size > MAX_METADATA_TOTAL:
        raise ValueError("元数据归档过大")
    entries = []
    seen = set()
    total = 0
    has_disk = False
    with tarfile.open(path, mode="r|*", tarinfo=SafeTarInfo) as archive:
        for index, member in enumerate(archive, 1):
            if index > MAX_MEMBERS:
                raise ValueError("归档成员过多")
            name = member_name(member)
            if name in seen:
                raise ValueError("归档成员重复")
            seen.add(name)
            if name == "" and member.isdir():
                continue
            if name == "rootfs.img" and member.isfile() and disk_output is not None:
                if not 0 < member.size <= MAX_DISK_SIZE:
                    raise ValueError("磁盘成员大小不合法")
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError("无法读取磁盘成员")
                with source, disk_output.open("xb") as target:
                    shutil.copyfileobj(source, target, 1024 * 1024)
                if disk_output.stat().st_size != member.size:
                    raise ValueError("磁盘成员数据不完整")
                has_disk = True
                continue
            is_metadata = name == "metadata.yaml" and member.isfile()
            is_template = name == "templates" and member.isdir() or name.startswith("templates/")
            if not is_metadata and not is_template:
                raise ValueError("归档包含非白名单成员或容器根目录")
            limit = MAX_METADATA_SIZE if is_metadata else MAX_TEMPLATE_SIZE
            total += member.size
            if member.size > limit or total > MAX_METADATA_TOTAL:
                raise ValueError("元数据成员超出大小限制")
            data = b""
            if member.isfile():
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError("无法读取元数据成员")
                with source:
                    data = source.read(member.size + 1)
                if len(data) != member.size or is_metadata and not data.strip():
                    raise ValueError("元数据成员为空或不完整")
            entries.append((name, member.isdir(), data))
        trailing = archive.fileobj.read(tarfile.RECORDSIZE * 2 + 1)
        if len(trailing) > tarfile.RECORDSIZE * 2 or trailing.strip(b"\x00"):
            raise ValueError("归档尾部包含额外内容")
    kinds = {name: is_dir for name, is_dir, data in entries}
    if "metadata.yaml" not in kinds:
        raise ValueError("归档缺少元数据文件")
    for name in kinds:
        for parent in PurePosixPath(name).parents:
            if str(parent) in kinds and not kinds[str(parent)]:
                raise ValueError("归档成员的父路径不是目录")
    return entries, has_disk


def validate_metadata(path: Path) -> None:
    if not Path(path).name.endswith(".tar.xz"):
        raise ValueError("元数据归档必须使用 tar.xz")
    path = regular_file(path)
    with path.open("rb") as handle:
        if handle.read(6) != b"\xfd7zXZ\x00":
            raise ValueError("元数据归档压缩格式错误")
    scan_archive(path)


def normalize_export(export_dir: Path, prefix: str) -> tuple[Path, Path]:
    export_dir = Path(export_dir).absolute()
    if export_dir.is_symlink() or not export_dir.is_dir():
        raise ValueError("导出目录无效")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", prefix):
        raise ValueError("导出前缀不安全")
    sources = list(export_dir.iterdir())
    if not 1 <= len(sources) <= 2:
        raise ValueError("必须提供单个完整虚拟机导出")
    archives = []
    disks = []
    for path in sources:
        regular_file(path)
        if any(path.name.endswith(suffix) for suffix in ARCHIVE_SUFFIXES):
            archives.append(path)
        elif path.suffix in {".root", ".qcow2"}:
            disks.append(path)
        else:
            raise ValueError("导出包含未知文件")
    if len(archives) != 1 or len(disks) > 1:
        raise ValueError("必须提供一份元数据和一个磁盘")
    archive = archives[0]
    suffix = next(suffix for suffix in ARCHIVE_SUFFIXES if archive.name.endswith(suffix))
    if disks and disks[0].stem != archive.name[:-len(suffix)]:
        raise ValueError("分离导出的文件前缀不匹配")
    output_dir = Path(tempfile.mkdtemp(prefix="normalized-", dir=export_dir))
    disk_path = output_dir / f"{prefix}.qcow2"
    metadata_path = output_dir / f"{prefix}.tar.xz"
    entries, has_disk = scan_archive(archive, disk_path)
    if has_disk == bool(disks):
        raise ValueError("虚拟机磁盘缺失或重复")
    if disks:
        if disks[0].stat().st_size > MAX_DISK_SIZE:
            raise ValueError("磁盘文件超出大小限制")
        with disks[0].open("rb") as source, disk_path.open("xb") as target:
            shutil.copyfileobj(source, target, 1024 * 1024)
    validate_disk(disk_path, check=True)
    with metadata_path.open("xb") as output:
        with tarfile.open(fileobj=output, mode="w:xz") as archive_output:
            for name, is_dir, data in entries:
                member = tarfile.TarInfo(name)
                member.type = tarfile.DIRTYPE if is_dir else tarfile.REGTYPE
                member.mode = 0o755 if is_dir else 0o644
                member.size = len(data)
                archive_output.addfile(member, io.BytesIO(data) if not is_dir else None)
    return metadata_path, disk_path
