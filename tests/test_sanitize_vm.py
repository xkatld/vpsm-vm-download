import fnmatch
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts import sanitize_vm


class FakeGuest:
    def __init__(self):
        self.files = {
            "/etc/machine-id": b"old-id",
            "/var/lib/dbus/machine-id": b"old-id",
            "/etc/ssh/ssh_host_rsa_key": b"private",
            "/etc/ssh/ssh_host_rsa_key.pub": b"public",
            "/etc/shadow-": b"backup",
            "/var/backups/passwd.bak": b"backup",
            "/root/.bash_history": b"history",
            "/etc/shadow": b"preserved",
            "/boot/efi/keep": b"preserved",
            "/etc/ssh/sshd_config": b"preserved",
        }
        self.links = {}
        self.directories = {"/", "/etc", "/etc/ssh", "/var", "/var/lib", "/var/lib/dbus", "/var/backups", "/root", "/boot", "/boot/efi"}
        self.mountpoints = {"/boot/efi": "/dev/sda1", "/var/lib": "/dev/vg/lib", "/": "/dev/vg/root", "/var": "/dev/vg/var", "/boot": "/dev/sda2"}
        self.roots = ["/dev/vg/root"]
        self.calls = []
        self.fail_mount = False
        self.fail_shutdown = False
        self.skip_remove = False

    def set_backend(self, value):
        self.calls.append(("backend", value))

    def set_trace(self, value):
        self.calls.append(("trace", value))

    def set_verbose(self, value):
        self.calls.append(("verbose", value))

    def add_drive_opts(self, path, **options):
        self.calls.append(("drive", path, options))

    def launch(self):
        self.calls.append(("launch",))

    def inspect_os(self):
        return self.roots

    def inspect_get_mountpoints(self, root):
        return self.mountpoints

    def mount(self, device, mountpoint):
        if self.fail_mount:
            raise RuntimeError("挂载失败")
        self.calls.append(("mount", device, mountpoint))

    def is_dir(self, path):
        return path in self.directories

    def realpath(self, path):
        return self.links.get(path, path)

    def is_file(self, path):
        return path in self.files or self.links.get(path) in self.files

    def is_symlink(self, path):
        return path in self.links

    def exists(self, path):
        return path in self.files or path in self.directories or self.links.get(path) in self.files

    def write(self, path, data):
        self.files[path] = data

    def rm(self, path):
        self.calls.append(("rm", path))
        if not self.skip_remove:
            self.files.pop(path, None)
            self.links.pop(path, None)

    def ln_sf(self, target, path):
        self.links[path] = target

    def glob_expand(self, pattern):
        return [path for path in set(self.files) | set(self.links) if fnmatch.fnmatchcase(path, pattern)]

    def filesize(self, path):
        return len(self.files[self.links.get(path, path)])

    def readlink(self, path):
        return self.links[path]

    def sync(self):
        self.calls.append(("sync",))

    def shutdown(self):
        self.calls.append(("shutdown",))
        if self.fail_shutdown:
            raise RuntimeError("关闭失败")

    def close(self):
        self.calls.append(("close",))


class SanitizeVmTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.disk = Path(self.directory.name) / "image.qcow2"
        self.guest = FakeGuest()
        self.validation = patch.object(sanitize_vm, "validate_disk")
        self.validate = self.validation.start()
        self.addCleanup(self.validation.stop)
        self.importer = patch.object(sanitize_vm.importlib, "import_module", return_value=SimpleNamespace(GuestFS=lambda **options: self.guest))
        self.importer.start()
        self.addCleanup(self.importer.stop)

    def test_minimal_identity_cleanup_and_mount_order(self):
        sanitize_vm.sanitize_disk(self.disk)
        self.validate.assert_called_once_with(self.disk, check=True)
        self.assertEqual(self.guest.files["/etc/machine-id"], b"")
        self.assertEqual(self.guest.links["/var/lib/dbus/machine-id"], "/etc/machine-id")
        self.assertNotIn("/etc/ssh/ssh_host_rsa_key", self.guest.files)
        self.assertNotIn("/etc/shadow-", self.guest.files)
        self.assertNotIn("/var/backups/passwd.bak", self.guest.files)
        self.assertNotIn("/root/.bash_history", self.guest.files)
        self.assertEqual(self.guest.files["/etc/shadow"], b"preserved")
        self.assertEqual(self.guest.files["/boot/efi/keep"], b"preserved")
        self.assertEqual(self.guest.files["/etc/ssh/sshd_config"], b"preserved")
        mounts = [call[2] for call in self.guest.calls if call[0] == "mount"]
        self.assertEqual(mounts, ["/", "/var", "/var/lib"])
        self.assertEqual(self.guest.calls[-3:], [("sync",), ("shutdown",), ("close",)])
        self.assertIn(("backend", "direct"), self.guest.calls)

    def test_ambiguous_roots_rejected_and_closed(self):
        for roots in ([], ["/dev/a", "/dev/b"]):
            with self.subTest(roots=roots):
                self.guest.roots = roots
                with self.assertRaises(ValueError):
                    sanitize_vm.sanitize_disk(self.disk)
                self.assertEqual(self.guest.calls[-1], ("close",))

    def test_mount_traversal_rejected(self):
        self.guest.mountpoints["/var/../etc"] = "/dev/sda3"
        with self.assertRaises(ValueError):
            sanitize_vm.sanitize_disk(self.disk)
        self.assertEqual(self.guest.files["/etc/machine-id"], b"old-id")

    def test_mount_failure_propagates(self):
        self.guest.fail_mount = True
        with self.assertRaises(RuntimeError):
            sanitize_vm.sanitize_disk(self.disk)
        self.assertEqual(self.guest.calls[-1], ("close",))

    def test_symlink_machine_id_rejected(self):
        self.guest.links["/etc/machine-id"] = "/etc/shadow"
        with self.assertRaises(ValueError):
            sanitize_vm.sanitize_disk(self.disk)
        self.assertEqual(self.guest.files["/etc/shadow"], b"preserved")

    def test_symlink_parent_rejected(self):
        self.guest.links["/etc/ssh"] = "/etc"
        with self.assertRaises(ValueError):
            sanitize_vm.sanitize_disk(self.disk)

    def test_dangling_host_key_link_removed(self):
        self.guest.links["/etc/ssh/ssh_host_ecdsa_key"] = "/missing"
        sanitize_vm.sanitize_disk(self.disk)
        self.assertNotIn("/etc/ssh/ssh_host_ecdsa_key", self.guest.links)

    def test_failed_cleanup_detected(self):
        self.guest.skip_remove = True
        with self.assertRaises(ValueError):
            sanitize_vm.sanitize_disk(self.disk)

    def test_shutdown_failure_propagates(self):
        self.guest.fail_shutdown = True
        with self.assertRaises(RuntimeError):
            sanitize_vm.sanitize_disk(self.disk)
        self.assertEqual(self.guest.calls[-1], ("close",))

    def test_unexpected_glob_path_rejected(self):
        with patch.object(self.guest, "glob_expand", return_value=["/etc/shadow"]):
            with self.assertRaises(ValueError):
                sanitize_vm.sanitize_disk(self.disk)


if __name__ == "__main__":
    unittest.main()
