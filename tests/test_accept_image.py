import base64
import hashlib
import json
import subprocess
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import MagicMock, call, patch

from build_pipeline import COMMON_PACKAGES, ImageSpec, README_CONTENT
from scripts.accept_image import (
    Acceptance, AcceptanceTerminated, CheckError, check_os_release, import_paths,
    instance_addresses, main, public_hostkey_fingerprints, safe_error,
)


def completed(stdout=""):
    return subprocess.CompletedProcess([], 0, stdout, "")


def public_key(value=1):
    fields = [b"ssh-ed25519", bytes([value]) * 32]
    blob = b"".join(len(field).to_bytes(4, "big") + field for field in fields)
    return "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " 任意备注"


def identity(value=1):
    return {
        "machine_id_sha256": hashlib.sha256(bytes([value])).hexdigest(),
        "ssh_host_key_fingerprints": public_hostkey_fingerprints(public_key(value)),
    }


def vm_row(name="vm"):
    return {
        "name": name, "status": "Running", "type": "virtual-machine",
        "expanded_config": {"security.secureboot": "false", "limits.cpu": "2", "limits.memory": "2GiB"},
        "expanded_devices": {
            "root": {"type": "disk", "pool": "default", "path": "/", "size": "12GiB"},
            "eth0": {"type": "nic", "network": "incusbr0", "name": "eth0", "hwaddr": "00:16:3e:12:34:56"},
        },
        "state": {"network": {
            "enp5s0": {"type": "broadcast", "hwaddr": "00:16:3E:12:34:56", "addresses": [
                {"family": "inet", "address": "10.20.30.40"},
                {"family": "inet6", "address": "fd42:1234::2"},
            ]},
        }},
    }


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.spec = ImageSpec("debian", "bookworm", "amd64", "default", "acceptance")
        self.acceptance = Acceptance(self.spec, Path("dist"), Path("acceptance"))

    def test_import_verifies_and_orders_vm_artifacts(self):
        prefix = self.spec.container_name()
        summary = {"image_type": "virtual-machine", "exported_files": [prefix + ".qcow2", prefix + ".tar.xz"]}
        with patch("scripts.accept_image.verify_artifact", return_value=2) as verify:
            with patch.object(Path, "read_text", return_value=json.dumps(summary)):
                paths = import_paths(Path("dist"), self.spec)
        self.assertEqual(paths, [Path("dist") / (prefix + ".tar.xz"), Path("dist") / (prefix + ".qcow2")])
        verify.assert_called_once_with(Path("dist"), {"distro": "debian", "release": "bookworm", "architecture": "amd64"})

    def test_invalid_verifier_result_stops_import(self):
        with patch("scripts.accept_image.verify_artifact", return_value=0):
            with patch.object(Path, "read_text") as read:
                with self.assertRaises(CheckError):
                    import_paths(Path("dist"), self.spec)
        read.assert_not_called()

    def test_verifier_failure_stops_import(self):
        with patch("scripts.accept_image.verify_artifact", side_effect=ValueError("不可信诊断")):
            with patch.object(Path, "read_text") as read:
                with self.assertRaises(ValueError):
                    import_paths(Path("dist"), self.spec)
        read.assert_not_called()

    def test_import_rejects_container_and_unexpected_filenames(self):
        prefix = self.spec.container_name()
        for summary in (
            {"image_type": "container", "exported_files": [prefix + ".tar.xz", prefix + ".qcow2"]},
            {"image_type": "virtual-machine", "exported_files": ["../metadata.tar.xz", prefix + ".qcow2"]},
            {"image_type": "virtual-machine", "exported_files": [prefix + ".tar.xz", prefix + ".rootfs.tar.xz"]},
        ):
            with self.subTest(summary=summary):
                with patch("scripts.accept_image.verify_artifact", return_value=2):
                    with patch.object(Path, "read_text", return_value=json.dumps(summary)):
                        with self.assertRaises(CheckError):
                            import_paths(Path("dist"), self.spec)

    def test_network_matches_hardware_address_not_guest_name(self):
        row = vm_row()
        row["state"]["network"]["eth0"] = {
            "hwaddr": "00:16:3e:00:00:00", "addresses": [{"family": "inet", "address": "192.0.2.10"}],
        }
        result = instance_addresses(json.dumps([row]), "vm", "00:16:3e:12:34:56")
        self.assertEqual(result, {"ipv4": "10.20.30.40", "ipv6": "fd42:1234::2"})

    def test_network_excludes_loopback_and_nonusable_addresses(self):
        row = vm_row()
        row["state"]["network"]["enp5s0"]["addresses"] = [
            {"family": "inet", "address": "127.0.0.1"},
            {"family": "inet", "address": "0.0.0.0"},
            {"family": "inet", "address": "169.254.1.1"},
            {"family": "inet", "address": "224.0.0.1"},
            {"family": "inet6", "address": "::1"},
            {"family": "inet6", "address": "fe80::1"},
            {"family": "inet6", "address": "fd42::1%enp5s0"},
            {"family": "inet6", "address": "::ffff:10.20.30.40"},
            {"family": "inet6", "address": "非法地址"},
        ]
        self.assertEqual(instance_addresses(json.dumps([row]), "vm", "00:16:3e:12:34:56"), {})
        row["state"]["network"] = {"lo": vm_row()["state"]["network"]["enp5s0"]}
        self.assertEqual(instance_addresses(json.dumps([row]), "vm", "00:16:3e:12:34:56"), {})

    def test_network_rejects_ambiguous_mac_and_stopped_vm(self):
        row = vm_row()
        row["state"]["network"]["enp6s0"] = row["state"]["network"]["enp5s0"]
        self.assertEqual(instance_addresses(json.dumps([row]), "vm", "00:16:3e:12:34:56"), {})
        row = vm_row()
        row["status"] = "Stopped"
        self.assertEqual(instance_addresses(json.dumps([row]), "vm", "00:16:3e:12:34:56"), {})

    def test_network_falls_back_to_volatile_mac_without_yaml(self):
        acceptance = self.acceptance
        row = vm_row(acceptance.instance)
        row["expanded_devices"]["eth0"].pop("hwaddr")
        with patch.object(acceptance, "incus", side_effect=[completed(json.dumps([row])), completed("00:16:3e:12:34:56\n")]) as incus:
            addresses = acceptance.network_ready("cold")
        self.assertEqual(addresses["ipv6"], "fd42:1234::2")
        self.assertEqual(incus.call_args_list[1].args[0], ["config", "get", acceptance.instance, "volatile.eth0.hwaddr"])
        self.assertEqual(acceptance.report["addresses"]["cold"], addresses)

    def test_network_accepts_expanded_volatile_mac(self):
        acceptance = self.acceptance
        row = vm_row(acceptance.instance)
        row["expanded_devices"]["eth0"].pop("hwaddr")
        row["expanded_config"]["volatile.eth0.hwaddr"] = "00:16:3e:12:34:56"
        with patch.object(acceptance, "incus", return_value=completed(json.dumps([row]))) as incus:
            acceptance.network_ready("restart")
        incus.assert_called_once()

    def test_init_explicitly_sets_vm_limits(self):
        acceptance = self.acceptance
        with patch.object(acceptance, "incus", return_value=completed()) as incus:
            acceptance.init_instance()
        args = incus.call_args.args[0]
        self.assertEqual(args[:4], ["init", acceptance.alias, acceptance.instance, "--vm"])
        for setting in ("security.secureboot=false", "limits.cpu=2", "limits.memory=2GiB", "root,size=12GiB"):
            self.assertIn(setting, args)
        self.assertFalse(any("security.privileged" in arg for arg in args))

    def test_vm_configuration_requires_vm_and_secureboot_false(self):
        acceptance = self.acceptance
        row = vm_row(acceptance.instance)
        with patch.object(acceptance, "incus", return_value=completed(json.dumps([row]))):
            acceptance.check_vm_config()
        for invalid in ("container", "virtual-machine"):
            row["type"] = invalid
            row["expanded_config"]["security.secureboot"] = "true" if invalid == "virtual-machine" else "false"
            with patch.object(acceptance, "incus", return_value=completed(json.dumps([row]))):
                with self.assertRaises(CheckError):
                    acceptance.check_vm_config()

    def test_agent_wait_is_separate_and_bounded(self):
        acceptance = self.acceptance
        with patch.object(acceptance, "wait") as wait:
            acceptance.agent_ready()
        self.assertEqual(wait.call_args.kwargs["timeout"], 240)
        probe = wait.call_args.args[0]
        with patch.object(acceptance, "guest", return_value=completed()) as guest:
            self.assertTrue(probe(7))
        guest.assert_called_once_with(["true"], timeout=7)

    def test_boot_waits_for_agent_before_configuration_and_network(self):
        acceptance = self.acceptance
        order = []
        with ExitStack() as stack:
            stack.enter_context(patch.object(acceptance, "incus", side_effect=lambda *args, **kwargs: order.append("start")))
            stack.enter_context(patch.object(acceptance, "agent_ready", side_effect=lambda: order.append("agent")))
            stack.enter_context(patch.object(acceptance, "check_vm_config", side_effect=lambda: order.append("config")))
            stack.enter_context(patch.object(acceptance, "network_ready", side_effect=lambda phase: order.append("network")))
            for phase in ("cold", "restart", "clone"):
                acceptance.boot_ready(phase)
        self.assertEqual(order, ["start", "agent", "config", "network"] * 3)

    def test_wait_respects_overall_deadline(self):
        acceptance = self.acceptance
        acceptance.deadline = 100
        probe = MagicMock()
        with patch("scripts.accept_image.time.monotonic", return_value=101):
            with self.assertRaises(CheckError):
                acceptance.wait(probe, "已超时", timeout=240)
        probe.assert_not_called()

    def test_agent_timeout_does_not_modify_guest(self):
        acceptance = self.acceptance
        with patch.object(acceptance, "guest", side_effect=subprocess.CalledProcessError(1, ["命令"])) as guest:
            with patch("scripts.accept_image.time.monotonic", side_effect=[0, 0, 241, 241]):
                with patch("scripts.accept_image.time.sleep"):
                    with self.assertRaises(CheckError):
                        acceptance.agent_ready()
        guest.assert_called_once_with(["true"], timeout=10)

    def test_package_database_checks_nine_packages(self):
        with patch.object(self.acceptance, "guest", return_value=completed("install ok installed")) as guest:
            self.acceptance.check_packages()
        self.assertEqual(len(COMMON_PACKAGES.split()), 9)
        self.assertEqual(guest.call_count, 9)
        self.assertIn(call(["dpkg-query", "-W", "-f=${Status}", "ca-certificates"]), guest.call_args_list)

    def test_readme_is_exact(self):
        with patch.object(self.acceptance, "guest", return_value=completed(README_CONTENT + "\n")):
            self.acceptance.check_readme()
        with patch.object(self.acceptance, "guest", return_value=completed(README_CONTENT)):
            with self.assertRaises(CheckError):
                self.acceptance.check_readme()

    def test_root_lock_requires_exact_exclamation(self):
        for value in ("!", "!!", "*", "", "$6$不可输出"):
            with self.subTest(value=value):
                with patch.object(self.acceptance, "guest", return_value=completed(f"root:{value}:1:0:99999:7:::\n")):
                    if value == "!":
                        self.acceptance.check_root_lock()
                    else:
                        with self.assertRaises(CheckError):
                            self.acceptance.check_root_lock()

    def test_backup_checks_are_read_only_and_cover_accounts(self):
        with patch.object(self.acceptance, "guest", return_value=completed()) as guest:
            self.acceptance.check_credential_backups()
        script = guest.call_args.args[0][2]
        for account in ("shadow", "gshadow", "passwd", "group"):
            self.assertIn(f"/etc/{account}-", script)
            self.assertIn(f"/etc/{account}.bak", script)
            self.assertIn(f"/var/backups/{account}*", script)
        self.assertIn('[ -L "$path" ]', script)
        self.assertNotIn("rm ", script)

    def test_ssh_forces_each_address_family_and_uses_environment_password(self):
        acceptance = self.acceptance
        for family, address in ((4, "10.20.30.40"), (6, "fd42:1234::2")):
            with patch.object(acceptance, "command", return_value=completed("root\n")) as command:
                acceptance.ssh(family, address)
            args = command.call_args.args[0]
            self.assertIn(f"-{family}", args)
            self.assertIn(f"root@{address}", args)
            self.assertNotIn(acceptance.password, args)
            self.assertTrue(command.call_args.kwargs["password"])

    def test_ssh_rejects_family_mismatch(self):
        with self.assertRaises(CheckError):
            self.acceptance.ssh(4, "fd42::1")

    def test_identity_reports_only_hashes_and_public_fingerprints(self):
        machine_id = "1234567890abcdef" * 2
        with patch.object(self.acceptance, "guest", side_effect=[completed(machine_id + "\n"), completed(public_key())]) as guest:
            result = self.acceptance.sample_identity("cold")
        self.assertEqual(result["machine_id_sha256"], hashlib.sha256(machine_id.encode("ascii")).hexdigest())
        serialized = json.dumps(self.acceptance.report)
        self.assertNotIn(machine_id, serialized)
        self.assertNotIn("任意备注", serialized)
        self.assertNotIn(self.acceptance.password, serialized)
        self.assertIn("SHA256:", serialized)
        self.assertIn("ssh_host_ed25519_key.pub", guest.call_args_list[1].args[0][2])

    def test_identity_rejects_missing_zero_or_malformed_machine_id(self):
        for value in ("", "0" * 32, "A" * 32, "1" * 31, "1" * 32 + "\n\n"):
            with patch.object(self.acceptance, "guest", return_value=completed(value)):
                with self.assertRaises(CheckError):
                    self.acceptance.sample_identity("cold")

    def test_public_key_parser_rejects_bad_blob_or_duplicate_type(self):
        for text in ("", "ssh-ed25519 ###", "ssh-ed25519 YQ==", public_key() + "\n" + public_key(2)):
            with self.subTest(text=text):
                with self.assertRaises(CheckError):
                    public_hostkey_fingerprints(text)

    def test_identity_stability_and_uniqueness(self):
        first, second = identity(1), identity(2)
        Acceptance.check_identity_stability(first, first)
        Acceptance.check_identity_uniqueness(first, second)
        with self.assertRaises(CheckError):
            Acceptance.check_identity_stability(first, second)
        with self.assertRaises(CheckError):
            Acceptance.check_identity_uniqueness(first, first)
        shared_key = {**second, "ssh_host_key_fingerprints": first["ssh_host_key_fingerprints"]}
        with self.assertRaises(CheckError):
            Acceptance.check_identity_uniqueness(first, shared_key)

    def test_clone_uses_original_alias_and_stops_primary_first(self):
        acceptance = self.acceptance
        primary, password = acceptance.instance, acceptance.password
        addresses = {"ipv4": "10.20.30.40", "ipv6": "fd42::2"}
        with ExitStack() as stack:
            incus = stack.enter_context(patch.object(acceptance, "incus", return_value=completed()))
            stack.enter_context(patch.object(acceptance, "boot_ready", return_value=addresses))
            stack.enter_context(patch.object(acceptance, "check_root_lock"))
            stack.enter_context(patch.object(acceptance, "check_credential_backups"))
            stack.enter_context(patch.object(acceptance, "check_boot"))
            stack.enter_context(patch.object(acceptance, "sample_identity", return_value=identity(2)))
            acceptance.check_clone(identity(1))
        args = [item.args[0] for item in incus.call_args_list]
        self.assertEqual(args[0], ["stop", primary, "--timeout", "60"])
        self.assertEqual(args[1][:4], ["init", acceptance.alias, acceptance.clone_instance, "--vm"])
        self.assertFalse(any("copy" in entry or "publish" in entry or "--force" in entry for entry in args))
        self.assertEqual(acceptance.instance, primary)
        self.assertEqual(acceptance.password, password)

    def test_cleanup_never_touches_unowned_project(self):
        with patch.object(self.acceptance, "incus") as incus:
            self.assertTrue(self.acceptance.cleanup())
        incus.assert_not_called()

    def test_failed_project_creation_does_not_authorize_cleanup(self):
        with patch.object(self.acceptance, "command", side_effect=subprocess.CalledProcessError(1, ["incus"])):
            with self.assertRaises(subprocess.CalledProcessError):
                self.acceptance.create_project()
        self.assertFalse(self.acceptance.project_created)

    def test_cleanup_enumerates_owned_resources_and_skips_default_profile(self):
        acceptance = self.acceptance
        acceptance.project_created = True
        def respond(args, **kwargs):
            if args == ["list", "--format", "json"]:
                return completed(json.dumps([{"name": "partial-vm", "type": "virtual-machine", "status": "Running"}]))
            if args == ["image", "list", "--format", "json"]:
                return completed(json.dumps([{"fingerprint": "a" * 64}]))
            if args == ["profile", "list", "--format", "json"]:
                return completed(json.dumps([{"name": "default"}, {"name": "partial-profile"}]))
            return completed()
        with patch.object(acceptance, "incus", side_effect=respond) as incus:
            self.assertTrue(acceptance.cleanup())
        args = [item.args[0] for item in incus.call_args_list]
        self.assertIn(["delete", "partial-vm", "--force"], args)
        self.assertIn(["image", "delete", "a" * 64], args)
        self.assertIn(["profile", "delete", "partial-profile"], args)
        self.assertNotIn(["profile", "delete", "default"], args)
        self.assertEqual(args[-1], ["project", "delete", acceptance.project])

    def test_success_cleanup_uses_normal_shutdown_without_force(self):
        acceptance = self.acceptance
        acceptance.project_created = True
        acceptance.report["status"] = "success"
        responses = [completed(json.dumps([{"name": "vm", "status": "Running"}])), completed(), completed(),
                     completed("[]"), completed('[{"name":"default"}]'), completed()]
        with patch.object(acceptance, "incus", side_effect=responses) as incus:
            self.assertTrue(acceptance.cleanup())
        args = [item.args[0] for item in incus.call_args_list]
        self.assertIn(["stop", "vm", "--timeout", "20"], args)
        self.assertIn(["delete", "vm"], args)
        self.assertFalse(any("--force" in entry for entry in args))

    def test_commands_are_project_scoped_and_deadline_bounded(self):
        acceptance = self.acceptance
        acceptance.deadline = 105
        with patch("scripts.accept_image.time.monotonic", return_value=100):
            with patch("scripts.accept_image.subprocess.run", return_value=completed()) as run:
                acceptance.incus(["delete", "vm", "--force"], timeout=60)
        self.assertEqual(run.call_args.args[0][:3], ["incus", "--project", acceptance.project])
        self.assertEqual(run.call_args.kwargs["timeout"], 5)
        self.assertTrue(run.call_args.kwargs["capture_output"])

    def test_external_errors_never_include_raw_output(self):
        secret = "不可输出的口令与原始日志"
        errors = [ValueError(secret), OSError(secret), subprocess.CalledProcessError(1, [secret], output=secret),
                  subprocess.TimeoutExpired([secret], 10, output=secret)]
        for error in errors:
            self.assertNotIn(secret, safe_error(error))
        with patch("builtins.print"):
            with self.assertRaises(ValueError):
                self.acceptance.step("cold-agent", lambda: (_ for _ in ()).throw(ValueError(secret)))
        self.assertNotIn(secret, json.dumps(self.acceptance.report))

    def test_report_cannot_modify_artifacts(self):
        acceptance = Acceptance(self.spec, Path("dist"), Path("dist/acceptance"))
        with patch.object(Path, "mkdir") as mkdir:
            with self.assertRaises(CheckError):
                acceptance.prepare_report()
        mkdir.assert_not_called()

    def test_os_release_checks_distribution_and_release(self):
        check_os_release('ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n', self.spec)
        check_os_release('ID=debian\nVERSION_CODENAME=bookworm\n', self.spec)
        with self.assertRaises(CheckError):
            check_os_release('ID=debian\nVERSION_ID="13"\n', self.spec)
        with self.assertRaises(CheckError):
            check_os_release('ID=ubuntu\nVERSION_ID="12"\n', self.spec)

    def test_cli_only_accepts_amd64_and_expected_defaults(self):
        with patch("scripts.accept_image.Acceptance") as constructor:
            constructor.return_value.run.return_value = 0
            self.assertEqual(main(["--distro", "debian", "--release", "bookworm", "--architecture", "amd64"]), 0)
        self.assertEqual(constructor.call_args.args[1:], (Path("dist"), Path("acceptance")))
        with patch("sys.stderr"):
            with self.assertRaises(SystemExit):
                main(["--distro", "debian", "--release", "bookworm", "--architecture", "arm64"])

    def lifecycle(self, failure=None, cleanup_success=True):
        acceptance = self.acceptance
        stages = []
        original_step = acceptance.step
        def step(label, action):
            stages.append(label)
            if label == failure:
                return original_step(label, lambda: (_ for _ in ()).throw(AcceptanceTerminated()))
            return original_step(label, action)
        def report_ready():
            acceptance.report_ready = True
        with ExitStack() as stack:
            stack.enter_context(patch("scripts.accept_image.signal.signal"))
            timer = stack.enter_context(patch("scripts.accept_image.signal.setitimer"))
            stack.enter_context(patch("scripts.accept_image.import_paths", return_value=[Path("dist/a.tar.xz"), Path("dist/a.qcow2")]))
            stack.enter_context(patch("scripts.accept_image.check_os_release"))
            stack.enter_context(patch.object(acceptance, "step", side_effect=step))
            stack.enter_context(patch.object(acceptance, "prepare_report", side_effect=report_ready))
            for name in ("preflight", "create_project", "check_vm_config", "agent_ready", "check_packages",
                         "check_readme", "check_root_lock", "check_credential_backups"):
                stack.enter_context(patch.object(acceptance, name))
            incus = stack.enter_context(patch.object(acceptance, "incus", return_value=completed()))
            stack.enter_context(patch.object(acceptance, "network_ready", return_value={"ipv4": "10.20.30.40", "ipv6": "fd42::2"}))
            stack.enter_context(patch.object(acceptance, "ssh"))
            stack.enter_context(patch.object(acceptance, "sample_identity", side_effect=[identity(1), identity(1), identity(2)]))
            cleanup = stack.enter_context(patch.object(acceptance, "cleanup", side_effect=lambda: stages.append("cleanup") or cleanup_success))
            report = stack.enter_context(patch.object(acceptance, "write_report", side_effect=lambda: stages.append("report")))
            stack.enter_context(patch("builtins.print"))
            result = acceptance.run()
        return result, stages, incus, cleanup, report, timer

    def test_full_lifecycle_has_identity_gates_and_agent_each_boot(self):
        result, stages, incus, cleanup, report, timer = self.lifecycle()
        self.assertEqual(result, 0)
        for phase in ("cold", "restart", "clone"):
            self.assertLess(stages.index(phase + "-start"), stages.index(phase + "-agent"))
            self.assertLess(stages.index(phase + "-agent"), stages.index(phase + "-network"))
            self.assertLess(stages.index(phase + "-ssh-ipv6"), stages.index(phase + "-identity"))
        self.assertLess(stages.index("root-lock"), stages.index("test-password"))
        self.assertLess(stages.index("clone-root-lock"), stages.index("clone-test-password"))
        self.assertLess(stages.index("identity-stability"), stages.index("primary-stop"))
        self.assertLess(stages.index("primary-stop"), stages.index("create-clone"))
        self.assertEqual(stages[-2:], ["cleanup", "report"])
        cleanup.assert_called_once()
        report.assert_called_once()
        args = [item.args[0] for item in incus.call_args_list]
        init_calls = [entry for entry in args if entry[0] == "init"]
        self.assertEqual(len(init_calls), 2)
        self.assertTrue(all(entry[1] == self.acceptance.alias and "--vm" in entry for entry in init_calls))
        self.assertFalse(any("--force" in entry for entry in args))
        self.assertEqual([item.args[1] for item in timer.call_args_list], [1500, 0, 90, 0])

    def test_each_failure_still_cleans_up_before_reporting(self):
        for phase in ("verify-export", "import-image", "cold-agent", "restart-agent", "clone-agent", "identity-uniqueness"):
            self.setUp()
            with self.subTest(phase=phase):
                result, stages, incus, cleanup, report, timer = self.lifecycle(failure=phase)
                self.assertEqual(result, 1)
                self.assertEqual(stages[-2:], ["cleanup", "report"])
                cleanup.assert_called_once()
                report.assert_called_once()
                self.assertEqual(self.acceptance.report["error"]["stage"], phase)

    def test_cleanup_failure_prevents_success(self):
        result, stages, incus, cleanup, report, timer = self.lifecycle(cleanup_success=False)
        self.assertEqual(result, 1)
        self.assertEqual(self.acceptance.report["status"], "failed")


if __name__ == "__main__":
    unittest.main()
