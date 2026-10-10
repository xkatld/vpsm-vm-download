import fnmatch
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts import sanitize_vm
from scripts.image_cleanup import (
    ACCOUNT_BACKUP_SUFFIXES, ACCOUNT_FILES, CREDENTIAL_DIRECTORIES, CREDENTIAL_PATHS, HISTORY_FILES,
    PROVISION_CONF, PROVISION_MASK,
)


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

    def rm_rf(self, path):
        self.calls.append(("rm_rf", path))
        if not self.skip_remove:
            self.files = {name: data for name, data in self.files.items() if name != path and not name.startswith(path + "/")}
            self.links = {name: target for name, target in self.links.items() if name != path and not name.startswith(path + "/")}
            self.directories = {name for name in self.directories if name != path and not name.startswith(path + "/")}

    def ln_sf(self, target, path):
        self.links[path] = target

    def read_file(self, path):
        return self.files[self.links.get(path, path)]

    def mkdir_p(self, path):
        current = ""
        for part in path.split("/"):
            if part:
                current += "/" + part
                self.directories.add(current)

    def glob_expand(self, pattern):
        return [path for path in set(self.files) | set(self.links) | self.directories if fnmatch.fnmatchcase(path, pattern)]

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

    def test_cleanup_covers_shared_account_and_history_rules(self):
        self.guest.directories.update({"/root/.local", "/root/.local/share", "/root/.local/share/fish"})
        targets = set(HISTORY_FILES)
        for account in ACCOUNT_FILES:
            targets.update(f"/etc/{account}{suffix}" for suffix in ACCOUNT_BACKUP_SUFFIXES)
            targets.update(f"/var/backups/{account}{suffix}" for suffix in ("", "-", "~", ".bak", "-old.gz"))
        self.guest.files.update({path: b"backup" for path in targets})
        preserved = {"/var/backups/unrelated": b"keep", "/root/.ssh_notes": b"keep", "/etc/passwd": b"keep"}
        self.guest.files.update(preserved)
        sanitize_vm.sanitize_disk(self.disk)
        self.assertFalse(targets & self.guest.files.keys())
        for path, value in preserved.items():
            self.assertEqual(self.guest.files[path], value)
        self.assertTrue(set(CREDENTIAL_DIRECTORIES) <= set(CREDENTIAL_PATHS))

    def test_root_ssh_directory_is_only_recursive_target(self):
        self.guest.directories.update({"/root/.ssh", "/root/.ssh/nested"})
        self.guest.files["/root/.ssh/nested/key"] = b"private"
        self.guest.links["/root/.ssh/linked"] = "/etc/shadow"
        sanitize_vm.sanitize_disk(self.disk)
        self.assertNotIn("/root/.ssh", self.guest.directories)
        self.assertNotIn("/root/.ssh/nested/key", self.guest.files)
        self.assertEqual(self.guest.files["/etc/shadow"], b"preserved")
        self.assertEqual([call for call in self.guest.calls if call[0] == "rm_rf"], [("rm_rf", "/root/.ssh")])

    def test_root_ssh_link_is_unlinked_without_following_target(self):
        self.guest.links["/root/.ssh"] = "/etc"
        sanitize_vm.sanitize_disk(self.disk)
        self.assertNotIn("/root/.ssh", self.guest.links)
        self.assertIn(("rm", "/root/.ssh"), self.guest.calls)
        self.assertFalse(any(call[0] == "rm_rf" for call in self.guest.calls))
        self.assertEqual(self.guest.files["/etc/shadow"], b"preserved")

    def test_backup_directory_is_not_recursively_removed(self):
        self.guest.directories.add("/var/backups/passwd.archive")
        self.guest.files["/var/backups/passwd.archive/keep"] = b"keep"
        with self.assertRaises(ValueError):
            sanitize_vm.sanitize_disk(self.disk)
        self.assertEqual(self.guest.files["/var/backups/passwd.archive/keep"], b"keep")
        self.assertNotIn(("rm_rf", "/var/backups/passwd.archive"), self.guest.calls)

    def test_provision_conf_with_ssh_rule_is_masked(self):
        content = b"d- /root :0700 root :root -\nd- /root/.ssh :0700 root :root -\n"
        self.guest.files[PROVISION_CONF] = content
        sanitize_vm.sanitize_disk(self.disk)
        self.assertEqual(self.guest.files[PROVISION_CONF], content)
        self.assertEqual(self.guest.files[PROVISION_MASK], b"")
        self.assertIn("/etc/tmpfiles.d", self.guest.directories)

    def test_provision_conf_without_ssh_rule_is_preserved(self):
        self.guest.files[PROVISION_CONF] = b"d /run/example 0755 root root -\n"
        sanitize_vm.sanitize_disk(self.disk)
        self.assertNotIn(PROVISION_MASK, self.guest.files)

    def test_provision_conf_link_is_rejected(self):
        self.guest.links[PROVISION_CONF] = "/etc/shadow"
        with self.assertRaises(ValueError):
            sanitize_vm.sanitize_disk(self.disk)
        self.assertNotIn(PROVISION_MASK, self.guest.files)

    def test_provision_mask_link_is_rejected(self):
        self.guest.directories.add("/etc/tmpfiles.d")
        self.guest.files[PROVISION_CONF] = b"d- /root/.ssh :0700 root :root -\n"
        self.guest.links[PROVISION_MASK] = "/etc/shadow"
        with self.assertRaises(ValueError):
            sanitize_vm.sanitize_disk(self.disk)
        self.assertEqual(self.guest.files["/etc/shadow"], b"preserved")

    def test_provision_mask_must_stay_empty(self):
        self.guest.directories.add("/etc/tmpfiles.d")
        self.guest.files[PROVISION_CONF] = b"d /run/example 0755 root root -\n"
        self.guest.files[PROVISION_MASK] = b"d- /root/.ssh :0700 root :root -\n"
        with self.assertRaises(ValueError):
            sanitize_vm.sanitize_disk(self.disk)

    def test_root_parent_link_rejected(self):
        self.guest.links["/root"] = "/etc"
        with self.assertRaises(ValueError):
            sanitize_vm.sanitize_disk(self.disk)
        self.assertFalse(any(call[0] == "rm_rf" for call in self.guest.calls))

    def test_history_submount_is_mounted_before_cleanup(self):
        self.guest.directories.update({"/root/.local", "/root/.local/share", "/root/.local/share/fish"})
        self.guest.mountpoints["/root/.local"] = "/dev/vg/history"
        self.guest.files["/root/.local/share/fish/fish_history"] = b"history"
        sanitize_vm.sanitize_disk(self.disk)
        self.assertIn(("mount", "/dev/vg/history", "/root/.local"), self.guest.calls)
        self.assertNotIn("/root/.local/share/fish/fish_history", self.guest.files)

    def test_same_parent_unmatched_glob_path_rejected(self):
        with patch.object(self.guest, "glob_expand", return_value=["/etc/ssh/sshd_config"]):
            with self.assertRaises(ValueError):
                sanitize_vm.sanitize_disk(self.disk)
        self.assertEqual(self.guest.files["/etc/ssh/sshd_config"], b"preserved")

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
