import io
import json
import struct
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import vm_image


def disk_bytes(version=3, backing=0, external=False):
    header = bytearray(104)
    header[:4] = b"QFI\xfb"
    struct.pack_into(">I", header, 4, version)
    struct.pack_into(">Q", header, 8, backing)
    struct.pack_into(">Q", header, 72, 4 if external else 0)
    return bytes(header)


def make_archive(path, entries):
    with tarfile.open(path, "w:xz") as archive:
        for name, content, kind in entries:
            member = tarfile.TarInfo(name)
            member.type = kind
            if kind == tarfile.SYMTYPE or kind == tarfile.LNKTYPE:
                member.linkname = "/etc/passwd"
            member.size = len(content) if kind == tarfile.REGTYPE else 0
            archive.addfile(member, io.BytesIO(content) if member.isfile() else None)


class VmImageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.info = subprocess.CompletedProcess([], 0, json.dumps({"format": "qcow2"}), "")

    def export_archive(self, extra=()):
        path = self.root / "source.tar.xz"
        make_archive(path, [("metadata.yaml", b"architecture: x86_64\n", tarfile.REGTYPE), *extra])
        return path

    def test_unified_export_streams_disk_and_whitelist(self):
        source = self.export_archive([
            ("templates", b"", tarfile.DIRTYPE),
            ("templates/hostname.tpl", b"{{ instance.name }}", tarfile.REGTYPE),
            ("rootfs.img", disk_bytes(), tarfile.REGTYPE),
        ])
        with patch.object(vm_image.subprocess, "run", return_value=self.info) as run:
            metadata, disk = vm_image.normalize_export(self.root, "debian13-amd64-kvm")
        self.assertTrue(source.is_file())
        self.assertNotEqual(metadata.parent, self.root)
        self.assertEqual(disk.read_bytes(), disk_bytes())
        vm_image.validate_metadata(metadata)
        with tarfile.open(metadata) as archive:
            self.assertEqual(archive.getnames(), ["metadata.yaml", "templates", "templates/hostname.tpl"])
        self.assertEqual([call.args[0][1] for call in run.call_args_list], ["info", "check"])
        self.assertTrue(all(call.kwargs["cwd"] == vm_image.TRUSTED_DIRECTORY for call in run.call_args_list))

    def test_split_root_and_qcow2_exports(self):
        for suffix in (".root", ".qcow2"):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                make_archive(root / "source.tar.xz", [("metadata.yaml", b"architecture: x86_64", tarfile.REGTYPE)])
                source = root / f"source{suffix}"
                source.write_bytes(disk_bytes())
                with patch.object(vm_image.subprocess, "run", return_value=self.info):
                    metadata, disk = vm_image.normalize_export(root, "debian13-amd64-kvm")
                self.assertNotEqual(source.stat().st_ino, disk.stat().st_ino)
                self.assertEqual(disk.read_bytes(), source.read_bytes())
                self.assertEqual(metadata.name, "debian13-amd64-kvm.tar.xz")

    def test_missing_and_duplicate_disks_rejected(self):
        self.export_archive()
        with self.assertRaises(ValueError):
            vm_image.normalize_export(self.root, "test")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_archive(root / "source.tar.xz", [
                ("metadata.yaml", b"a: b", tarfile.REGTYPE),
                ("rootfs.img", disk_bytes(), tarfile.REGTYPE),
            ])
            (root / "source.qcow2").write_bytes(disk_bytes())
            with self.assertRaises(ValueError):
                vm_image.normalize_export(root, "test")

    def test_unsafe_archive_members_rejected(self):
        cases = [
            ("../escape", b"a", tarfile.REGTYPE),
            ("/absolute", b"a", tarfile.REGTYPE),
            ("templates/../../escape", b"a", tarfile.REGTYPE),
            ("rootfs", b"", tarfile.DIRTYPE),
            ("templates/link", b"", tarfile.SYMTYPE),
            ("templates/hard", b"", tarfile.LNKTYPE),
            ("templates/fifo", b"", tarfile.FIFOTYPE),
            ("templates/device", b"", tarfile.CHRTYPE),
            ("templates\\escape", b"a", tarfile.REGTYPE),
            ("metadata.yaml", b"duplicate", tarfile.REGTYPE),
        ]
        for entry in cases:
            with self.subTest(name=entry[0]), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "metadata.tar.xz"
                make_archive(path, [("metadata.yaml", b"a: b", tarfile.REGTYPE), entry])
                with self.assertRaises(ValueError):
                    vm_image.validate_metadata(path)

    def test_parent_file_conflict_rejected(self):
        path = self.export_archive([
            ("templates/a", b"a", tarfile.REGTYPE),
            ("templates/a/b", b"b", tarfile.REGTYPE),
        ])
        with self.assertRaises(ValueError):
            vm_image.validate_metadata(path)

    def test_oversized_metadata_rejected(self):
        path = self.export_archive()
        with patch.object(vm_image, "MAX_METADATA_SIZE", 2), self.assertRaises(ValueError):
            vm_image.validate_metadata(path)

    def test_oversized_pax_header_rejected(self):
        path = self.root / "metadata.tar.xz"
        with tarfile.open(path, "w:xz", format=tarfile.PAX_FORMAT) as archive:
            member = tarfile.TarInfo("metadata.yaml")
            member.pax_headers = {"comment": "a" * 4096}
            member.size = 4
            archive.addfile(member, io.BytesIO(b"a: b"))
        with patch.object(vm_image, "MAX_METADATA_SIZE", 1024), self.assertRaises(ValueError):
            vm_image.validate_metadata(path)

    def test_disk_format_and_dependencies_rejected(self):
        path = self.root / "disk.qcow2"
        for content in (b"raw image", disk_bytes(backing=104), disk_bytes(external=True), disk_bytes(version=4)):
            path.write_bytes(content)
            with patch.object(vm_image.subprocess, "run") as run, self.assertRaises(ValueError):
                vm_image.validate_disk(path)
            run.assert_not_called()
        path.write_bytes(disk_bytes())
        for info in (
            {"format": "raw"},
            {"format": "qcow2", "backing-filename": "base"},
            {"format": "qcow2", "format-specific": {"data": {"data-file": "external"}}},
        ):
            result = subprocess.CompletedProcess([], 0, json.dumps(info), "")
            with patch.object(vm_image.subprocess, "run", return_value=result), self.assertRaises(ValueError):
                vm_image.validate_disk(path)

    def test_qemu_failure_is_fatal(self):
        path = self.root / "disk.qcow2"
        path.write_bytes(disk_bytes())
        with patch.object(vm_image.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "qemu-img")):
            with self.assertRaises(subprocess.CalledProcessError):
                vm_image.validate_disk(path, check=True)

    def test_readonly_validation_does_not_run_check(self):
        path = self.root / "disk.qcow2"
        path.write_bytes(disk_bytes())
        with patch.object(vm_image.subprocess, "run", return_value=self.info) as run:
            vm_image.validate_disk(path)
        self.assertEqual(run.call_count, 1)
        self.assertNotIn("-r", run.call_args.args[0])

    def test_source_symlink_and_prefix_traversal_rejected(self):
        path = self.export_archive()
        (self.root / "source.root").symlink_to(path)
        with self.assertRaises(ValueError):
            vm_image.normalize_export(self.root, "test")
        with self.assertRaises(ValueError):
            vm_image.normalize_export(self.root, "../test")


if __name__ == "__main__":
    unittest.main()
