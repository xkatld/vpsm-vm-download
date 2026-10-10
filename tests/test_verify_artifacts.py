import io
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from build_pipeline import ImageSpec
from scripts import verify_artifacts, vm_image


class VerifyArtifactsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.expected = {"distro": "debian", "release": "13", "architecture": "amd64"}
        self.prefix = ImageSpec("debian", "13", "amd64", "default", "snapshot").container_name()
        self.metadata = self.root / f"{self.prefix}.tar.xz"
        with tarfile.open(self.metadata, "w:xz") as archive:
            data = b"architecture: x86_64\n"
            member = tarfile.TarInfo("metadata.yaml")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        self.disk = self.root / f"{self.prefix}.qcow2"
        self.disk.write_bytes(b"qcow2-test")
        self.summary = {
            "status": "success", "architecture": "amd64", "image_type": "virtual-machine",
            "images": [self.expected.copy()], "exported_files": [self.metadata.name, self.disk.name],
        }
        self.write_summary()
        self.write_checksums()
        self.disk_patch = patch.object(verify_artifacts, "validate_disk", return_value={"format": "qcow2"})
        self.validate_disk = self.disk_patch.start()
        self.addCleanup(self.disk_patch.stop)

    def write_summary(self):
        (self.root / "build-summary.json").write_text(json.dumps(self.summary), encoding="utf-8")

    def write_checksums(self):
        content = "".join(f"{verify_artifacts.sha256(path)}  {path.name}\n" for path in (self.metadata, self.disk))
        (self.root / "SHA256SUMS").write_text(content, encoding="utf-8")

    def test_single_vm_verified_readonly(self):
        self.assertEqual(verify_artifacts.verify_artifact(self.root, self.expected), 2)
        self.validate_disk.assert_called_once_with(self.disk)

    def write_metadata(self, data):
        with tarfile.open(self.metadata, "w:xz") as archive:
            member = tarfile.TarInfo("metadata.yaml")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))

    def test_metadata_architecture_checked_even_with_valid_summary_and_hashes(self):
        for data in (
            b"architecture: x86_64_v2\n",
            b"architecture: amd64\n",
            b"architecture: aarch64\n",
            b"architecture: x86_64\nproperties:\n  user.vpsm.source_architecture: x86_64_v2\n",
        ):
            with self.subTest(data=data):
                self.write_metadata(data)
                self.write_checksums()
                with self.assertRaises(ValueError):
                    verify_artifacts.verify_artifact(self.root, self.expected)
        self.validate_disk.assert_not_called()

    def test_normalized_metadata_requires_new_checksum(self):
        original = b"architecture: x86_64_v2\n"
        self.write_metadata(original)
        self.write_checksums()
        self.write_metadata(vm_image.normalize_metadata(original))
        with self.assertRaisesRegex(ValueError, "校验和不一致"):
            verify_artifacts.verify_artifact(self.root, self.expected)
        self.validate_disk.assert_not_called()
        self.write_checksums()
        before = self.metadata.read_bytes()
        self.assertEqual(verify_artifacts.verify_artifact(self.root, self.expected), 2)
        self.assertEqual(self.metadata.read_bytes(), before)

    def test_expected_architecture_passed_to_metadata_validator(self):
        with patch.object(verify_artifacts, "validate_metadata") as validate:
            verify_artifacts.verify_artifact(self.root, self.expected)
        validate.assert_called_once_with(self.metadata, expected_architecture="amd64")

    def test_summary_type_architecture_status_and_count_rejected(self):
        for key, value in (("image_type", "container"), ("architecture", "arm64"), ("status", "failed"), ("images", [])):
            with self.subTest(key=key):
                original = self.summary[key]
                self.summary[key] = value
                self.write_summary()
                with self.assertRaises(ValueError):
                    verify_artifacts.verify_artifact(self.root, self.expected)
                self.summary[key] = original

    def test_duplicate_summary_key_rejected(self):
        (self.root / "build-summary.json").write_text('{"status":"failed","status":"success"}', encoding="utf-8")
        with self.assertRaises(ValueError):
            verify_artifacts.verify_artifact(self.root, self.expected)

    def test_extra_file_and_unexpected_export_rejected(self):
        (self.root / "unexpected").write_bytes(b"extra")
        with self.assertRaises(ValueError):
            verify_artifacts.verify_artifact(self.root, self.expected)

    def test_missing_qcow2_rejected(self):
        self.summary["exported_files"] = [self.metadata.name]
        self.write_summary()
        with self.assertRaises(ValueError):
            verify_artifacts.verify_artifact(self.root, self.expected)

    def test_checksum_uses_final_disk_bytes(self):
        self.disk.write_bytes(b"modified-after-checksum")
        with self.assertRaises(ValueError):
            verify_artifacts.verify_artifact(self.root, self.expected)
        self.validate_disk.assert_not_called()

    def test_checksum_duplicate_missing_and_traversal_rejected(self):
        checksum_file = self.root / "SHA256SUMS"
        checksum = verify_artifacts.sha256(self.metadata)
        cases = (
            f"{checksum}  {self.metadata.name}\n" * 2,
            f"{checksum}  {self.metadata.name}\n",
            f"{checksum}  ../escape\n",
            f"{'0' * 64}  {self.disk.name}\n{checksum}  {self.metadata.name}\n",
        )
        for content in cases:
            with self.subTest(content=content):
                checksum_file.write_text(content, encoding="utf-8")
                with self.assertRaises(ValueError):
                    verify_artifacts.verify_artifact(self.root, self.expected)

    def test_control_file_symlink_rejected(self):
        other = self.root / "control"
        other.mkdir()
        (other / "SHA256SUMS").symlink_to(self.root / "SHA256SUMS")
        with self.assertRaises(ValueError):
            verify_artifacts.read_control_file(other / "SHA256SUMS")

    def test_metadata_contains_container_root_rejected(self):
        with tarfile.open(self.metadata, "w:xz") as archive:
            for name, kind, data in (("metadata.yaml", tarfile.REGTYPE, b"a: b"), ("rootfs", tarfile.DIRTYPE, b"")):
                member = tarfile.TarInfo(name)
                member.type = kind
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data) if data else None)
        self.write_checksums()
        with self.assertRaises(ValueError):
            verify_artifacts.verify_artifact(self.root, self.expected)

    def test_disk_validator_failure_propagates(self):
        self.validate_disk.side_effect = ValueError("磁盘存在外部依赖")
        with self.assertRaises(ValueError):
            verify_artifacts.verify_artifact(self.root, self.expected)

    def test_downloads_are_sequential_and_cleaned(self):
        rows = [{"distro": "debian", "release": str(index), "architecture": "amd64"} for index in range(1, 16)]
        matrix = self.root / "matrix.json"
        matrix.write_text(json.dumps({"include": rows}), encoding="utf-8")
        directories = []

        def download(command, **options):
            directory = Path(command[command.index("--dir") + 1])
            self.assertTrue(directory.is_dir())
            self.assertEqual(list(directory.iterdir()), [])
            self.assertTrue(all(not previous.exists() for previous in directories))
            self.assertEqual(options["cwd"], verify_artifacts.PROJECT_DIRECTORY)
            directories.append(directory)
            return subprocess.CompletedProcess(command, 0)

        with patch.object(verify_artifacts.sys, "argv", ["verify_artifacts", "--matrix", str(matrix), "--run-id", "123"]):
            with patch.object(verify_artifacts.subprocess, "run", side_effect=download):
                with patch.object(verify_artifacts, "verify_artifact", return_value=2) as verify:
                    with patch.dict(verify_artifacts.os.environ, {}, clear=True), patch("builtins.print") as output:
                        self.assertEqual(verify_artifacts.main(), 0)
        self.assertEqual(verify.call_count, 15)
        self.assertTrue(all(not directory.exists() for directory in directories))
        output.assert_any_call("已验证 15 个虚拟机镜像，共 30 个导出文件。")

    def test_incomplete_matrix_rejected_before_download(self):
        matrix = self.root / "matrix.json"
        matrix.write_text(json.dumps({"include": [self.expected]}), encoding="utf-8")
        with patch.object(verify_artifacts.sys, "argv", ["verify_artifacts", "--matrix", str(matrix), "--run-id", "123"]):
            with patch.object(verify_artifacts.subprocess, "run") as run, self.assertRaises(ValueError):
                verify_artifacts.main()
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
