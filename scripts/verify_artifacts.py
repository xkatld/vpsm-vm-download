from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


PROJECT_DIRECTORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIRECTORY))

from build_pipeline import ImageSpec
from scripts.vm_image import regular_file, validate_disk, validate_metadata


MAX_SUMMARY_SIZE = 1024 * 1024


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_control_file(path: Path) -> str:
    path = regular_file(path)
    if path.stat().st_size > MAX_SUMMARY_SIZE:
        raise ValueError("产物控制文件过大")
    return path.read_text(encoding="utf-8")


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("汇总包含重复字段")
        result[key] = value
    return result


def verify_artifact(root: Path, expected: dict) -> int:
    root = Path(root).absolute()
    if root.is_symlink() or not root.is_dir():
        raise ValueError("产物目录不合法")
    if expected.get("architecture") != "amd64":
        raise ValueError("仅支持 amd64 虚拟机产物")
    summary = json.loads(read_control_file(root / "build-summary.json"), object_pairs_hook=unique_object)
    if not isinstance(summary, dict):
        raise ValueError("构建汇总格式错误")
    if summary.get("status") != "success" or summary.get("architecture") != "amd64":
        raise ValueError("构建未成功或架构错误")
    if summary.get("image_type") != "virtual-machine":
        raise ValueError("构建汇总不是虚拟机类型")
    images = summary.get("images")
    if not isinstance(images, list) or len(images) != 1 or not isinstance(images[0], dict):
        raise ValueError("每份产物必须仅包含一台虚拟机")
    if any(images[0].get(key) != expected.get(key) for key in ("distro", "release", "architecture")):
        raise ValueError("虚拟机版本与预期不一致")
    if images[0].get("image_type", "virtual-machine") != "virtual-machine":
        raise ValueError("镜像条目不是虚拟机")
    spec = ImageSpec(expected["distro"], expected["release"], expected["architecture"], "default", "snapshot")
    prefix = spec.container_name()
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*-amd64-kvm", prefix):
        raise ValueError("虚拟机产物命名错误")
    names = {f"{prefix}.tar.xz", f"{prefix}.qcow2"}
    files = summary.get("exported_files")
    if not isinstance(files, list) or len(files) != 2 or any(not isinstance(name, str) for name in files):
        raise ValueError("导出文件列表不合法")
    if set(files) != names:
        raise ValueError("必须仅包含规范元数据与 qcow2 磁盘")
    if {path.name for path in root.iterdir()} != names | {"build-summary.json", "SHA256SUMS"}:
        raise ValueError("产物文件缺失或存在额外文件")
    for name in names:
        regular_file(root / name)
    checksums = {}
    for line in read_control_file(root / "SHA256SUMS").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *]([^\r\n]+)", line)
        if not match or match[2] in checksums:
            raise ValueError("校验和条目格式错误或重复")
        checksums[match[2]] = match[1]
    if set(checksums) != names:
        raise ValueError("校验和未精确覆盖最终产物")
    for name, digest in checksums.items():
        if sha256(root / name) != digest:
            raise ValueError("最终产物校验和不一致")
    validate_metadata(root / f"{prefix}.tar.xz")
    validate_disk(root / f"{prefix}.qcow2")
    return 2


def main() -> int:
    parser = argparse.ArgumentParser(description="逐份下载并验证虚拟机产物")
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9]+", args.run_id):
        raise ValueError("运行编号格式错误")
    matrix = json.loads(read_control_file(args.matrix), object_pairs_hook=unique_object)
    rows = matrix.get("include") if isinstance(matrix, dict) else None
    if not isinstance(rows, list) or len(rows) != 15:
        raise ValueError("预期构建矩阵必须包含十五个镜像")
    names = []
    for row in rows:
        if not isinstance(row, dict) or row.get("architecture") != "amd64":
            raise ValueError("构建矩阵包含不支持的架构")
        if any(not isinstance(row.get(key), str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", row[key]) for key in ("distro", "release")):
            raise ValueError("构建矩阵版本信息不合法")
        names.append(f"images-{row['distro']}-{row['release']}-{row['architecture']}")
    if len(names) != len(set(names)):
        raise ValueError("构建矩阵包含重复产物")
    total = 0
    for row, name in zip(rows, names):
        with tempfile.TemporaryDirectory(prefix="vpsm-vm-verify-") as directory:
            subprocess.run(
                ["gh", "run", "download", args.run_id, "--name", name, "--dir", directory],
                check=True, timeout=1200, cwd=PROJECT_DIRECTORY,
            )
            total += verify_artifact(Path(directory), row)
            print(f"[正确] 已验证虚拟机产物：{name}")
    report = f"已验证 {len(rows)} 个虚拟机镜像，共 {total} 个导出文件。"
    print(report)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
            handle.write(report + "\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print("[错误] 虚拟机产物验证失败。", file=sys.stderr)
        raise SystemExit(1)
