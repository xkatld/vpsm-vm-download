import base64
import hashlib
import json
import subprocess
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import MagicMock, call, patch

from build_pipeline import COMMON_PACKAGES, ImageSpec, README_CONTENT
from scripts.image_cleanup import ACCOUNT_BACKUP_SUFFIXES, ACCOUNT_FILES, CREDENTIAL_PATHS, HISTORY_FILES
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

    def test_short_instance_names_preserve_full_project_isolation_and_socket_limits(self):
        suffixes = ["a" * 32, "b" * 32]
        with patch("scripts.accept_image.uuid.uuid4", side_effect=[MagicMock(hex=value) for value in suffixes]):
            acceptances = [Acceptance(self.spec, Path("dist"), Path("acceptance")) for _ in suffixes]
        self.assertNotEqual(acceptances[0].project, acceptances[1].project)
        for acceptance, suffix in zip(acceptances, suffixes):
            self.assertEqual(acceptance.project, "vpsm-vm-accept-" + suffix)
            self.assertEqual(acceptance.alias, "export-" + suffix)
            self.assertEqual(acceptance.instance, "accept")
            self.assertEqual(acceptance.clone_instance, "clone")
            self.assertEqual(acceptance.owned_instance_names, {"accept", "clone"})
            for directory in ("/var/log/incus", "/var/lib/incus/logs"):
                for name in (acceptance.instance, acceptance.clone_instance):
                    for socket in ("qemu.monitor", "qemu.spice"):
                        path = f"{directory}/{acceptance.project}_{name}/{socket}"
                        with self.subTest(path=path):
                            self.assertLessEqual(len(path.encode("utf-8")), 107)
                            old_path = f"{directory}/{acceptance.project}_{name}-{suffix}/{socket}"
                            self.assertGreater(len(old_path.encode("utf-8")), 107)

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
        args = incus.call_args_list[0].args[0]
        self.assertEqual(args[:4], ["init", acceptance.alias, acceptance.instance, "--vm"])
        self.assertEqual(incus.call_args_list[1], call(
            ["config", "device", "add", acceptance.instance, "agent", "disk", "source=agent:config"],
            diagnostic=True))
        self.assertTrue(incus.call_args_list[0].kwargs["diagnostic"])
        for setting in ("security.secureboot=false", "limits.cpu=2", "limits.memory=2GiB", "root,size=12GiB"):
            self.assertIn(setting, args)
        self.assertFalse(any("security.privileged" in arg for arg in args))

    def test_init_failure_never_adds_agent_disk(self):
        acceptance = self.acceptance
        with patch.object(acceptance, "incus", side_effect=CheckError("创建失败")) as incus:
            with self.assertRaises(CheckError):
                acceptance.init_instance()
        incus.assert_called_once()

    def test_agent_disk_precedes_primary_and_clone_start(self):
        acceptance = self.acceptance
        with ExitStack() as stack:
            incus = stack.enter_context(patch.object(acceptance, "incus", return_value=completed()))
            for method in ("agent_ready", "check_vm_config", "network_ready", "check_root_lock",
                           "check_credential_backups", "check_boot"):
                stack.enter_context(patch.object(acceptance, method))
            stack.enter_context(patch.object(acceptance, "sample_identity", return_value=identity(2)))
            acceptance.init_instance()
            acceptance.boot_ready("cold")
            acceptance.check_clone(identity(1))
        calls = [item.args[0] for item in incus.call_args_list]
        for name in (acceptance.instance, acceptance.clone_instance):
            init_index = next(index for index, args in enumerate(calls) if args[:3] == ["init", acceptance.alias, name])
            device_index = calls.index(["config", "device", "add", name, "agent", "disk", "source=agent:config"])
            self.assertEqual(device_index, init_index + 1)
            self.assertLess(device_index, calls.index(["start", name]))

    def test_opt_in_diagnostics_preserve_stderr_without_secrets(self):
        with patch.dict("scripts.accept_image.os.environ", {"SSHPASS": "继承登录口令", "IMAGE_ROOT_PASSWORD": "继承镜像口令"}):
            acceptance = Acceptance(self.spec, Path("dist"), Path("acceptance"))
        first = acceptance.password
        acceptance.password = "克隆随机口令"
        acceptance.diagnostic_secrets.add(acceptance.password)
        stderr = ("无法访问虚拟化设备\n" + "\n".join((first, acceptance.password, "继承登录口令", "继承镜像口令"))
                  + "\n\x1b[31m错误\x1b[0m\r\x00\n::error::命令注入\n" + chr(35) * 2 + "[标记\n" + "长" * 4000)
        exception = subprocess.CalledProcessError(42, ["绝不显示参数"], output="绝不显示标准输出", stderr=stderr)
        with patch("scripts.accept_image.subprocess.run", side_effect=exception):
            with patch("builtins.print") as output:
                with self.assertRaises(CheckError) as caught:
                    acceptance.step("cold-start", lambda: acceptance.incus(["start", acceptance.instance], diagnostic=True))
        message = str(caught.exception)
        self.assertIn("42", message)
        self.assertIn("无法访问虚拟化设备", message)
        self.assertLess(len(message), acceptance.STDERR_LIMIT + 100)
        emitted = message + json.dumps(acceptance.report, ensure_ascii=False) + str(output.call_args_list)
        for hidden in (first, acceptance.password, "继承登录口令", "继承镜像口令", "绝不显示参数", "绝不显示标准输出",
                       "::", chr(35) * 2 + "[", "\x1b", "\r", "\x00", "Traceback"):
            self.assertNotIn(hidden, emitted)
        self.assertTrue(caught.exception.__suppress_context__)
        self.assertEqual(acceptance.report["error"]["stage"], "cold-start")

    def test_import_diagnostics_reuse_safe_stderr_and_timeout_limits(self):
        acceptance = self.acceptance
        acceptance.deadline = 105
        stderr = ("镜像元数据缺少架构\n" + acceptance.password
                  + "\ntoken=禁止显示令牌\n\x1b[31m导入失败\x1b[0m\r\x00\n::error::禁止执行\n" + "长" * 4000)
        for error in (
            subprocess.CalledProcessError(42, ["禁止显示参数"], output="禁止显示输出", stderr=stderr),
            subprocess.TimeoutExpired(["禁止显示参数"], 5, output=b"hidden output", stderr=stderr.encode()),
        ):
            with self.subTest(error=type(error).__name__):
                with patch("scripts.accept_image.time.monotonic", return_value=100):
                    with patch("scripts.accept_image.subprocess.run", side_effect=error) as run:
                        with self.assertRaises(CheckError) as caught:
                            acceptance.incus(["image", "import", "dist/a.tar.xz", "dist/a.qcow2",
                                              "--alias", acceptance.alias], timeout=300, diagnostic=True)
                message = str(caught.exception)
                self.assertIn("镜像元数据缺少架构", message)
                self.assertIn("导入失败", message)
                self.assertIn("退出码 42" if isinstance(error, subprocess.CalledProcessError) else "命令执行超时", message)
                self.assertLess(len(message), acceptance.STDERR_LIMIT + 100)
                self.assertTrue(caught.exception.__suppress_context__)
                for hidden in (acceptance.password, "禁止显示令牌", "禁止显示参数", "禁止显示输出",
                               "hidden output", "::", "\x1b", "\r", "\x00"):
                    self.assertNotIn(hidden, message)
                self.assertEqual(run.call_args.kwargs["timeout"], 5)
        acceptance.deadline = None
        for error in (subprocess.CalledProcessError(1, []), subprocess.TimeoutExpired([], 300)):
            with self.subTest(error=type(error).__name__, stderr=None):
                with patch("scripts.accept_image.subprocess.run", side_effect=error):
                    with self.assertRaisesRegex(CheckError, "无标准错误输出"):
                        acceptance.incus(["image", "import", "dist/a.tar.xz", "dist/a.qcow2"], diagnostic=True)

    def test_import_diagnostics_require_exact_subcommand_and_project(self):
        acceptance = self.acceptance
        cases = (
            (["incus", "--project", acceptance.project, "image", "import", "镜像"], {}),
            (["incus", "--project", acceptance.project, "image", "import", "镜像"], {"diagnostic": True, "input": "输入"}),
            (["incus", "--project", acceptance.project, "image", "import", "镜像"], {"diagnostic": True, "password": True}),
            (["incus", "--project", "default", "image", "import", "镜像"], {"diagnostic": True}),
            (["incus", "--project", acceptance.project, "image", "import-extra", "镜像"], {"diagnostic": True}),
            (["incus", "--project", acceptance.project, "image", "show", "镜像"], {"diagnostic": True}),
            (["incus", "--project", acceptance.project, "image", "delete", "镜像"], {"diagnostic": True}),
        )
        for args, kwargs in cases:
            with self.subTest(args=args, kwargs=kwargs):
                error = subprocess.CalledProcessError(7, ["隐藏参数"], output="隐藏输出", stderr="隐藏错误")
                with patch("scripts.accept_image.subprocess.run", side_effect=error):
                    with self.assertRaises(subprocess.CalledProcessError) as caught:
                        acceptance.command(args, **kwargs)
                self.assertEqual(safe_error(caught.exception), "命令执行失败")

    def test_command_diagnostics_are_explicit_and_forbid_credentials(self):
        acceptance = self.acceptance
        cases = (
            (["start", acceptance.instance], {}),
            (["exec", acceptance.instance, "--", "chpasswd"], {"diagnostic": True, "input": "绝不显示输入"}),
            (["start", acceptance.instance], {"diagnostic": True, "password": True}),
            (["exec", acceptance.instance, "--", "cat", "/etc/shadow"], {"diagnostic": True}),
        )
        for args, kwargs in cases:
            with self.subTest(args=args):
                error = subprocess.CalledProcessError(7, ["绝不显示参数"], output="绝不显示输出", stderr="绝不显示错误")
                with patch("scripts.accept_image.subprocess.run", side_effect=error):
                    with patch("builtins.print") as output:
                        with self.assertRaises(subprocess.CalledProcessError):
                            acceptance.step("test-password", lambda: acceptance.incus(args, **kwargs))
                emitted = json.dumps(acceptance.report, ensure_ascii=False) + str(output.call_args_list)
                self.assertNotIn("绝不显示", emitted)
        with patch("scripts.accept_image.subprocess.run", side_effect=error):
            with self.assertRaises(subprocess.CalledProcessError):
                acceptance.command(["sshpass", "-e", "ssh", "root@主机"], diagnostic=True)

    def test_diagnostic_timeout_retains_safe_stderr_only(self):
        acceptance = self.acceptance
        error = subprocess.TimeoutExpired(["禁止显示参数"], 10, output=b"hidden output", stderr="等待虚拟化设备".encode())
        with patch("scripts.accept_image.subprocess.run", side_effect=error):
            with self.assertRaises(CheckError) as caught:
                acceptance.incus(["start", acceptance.instance], diagnostic=True)
        self.assertIn("等待虚拟化设备", str(caught.exception))
        self.assertNotIn("禁止显示参数", str(caught.exception))
        self.assertNotIn("hidden output", str(caught.exception))

    def test_diagnostics_only_collect_owned_instances_and_safe_config(self):
        acceptance = self.acceptance
        acceptance.project_created = True
        acceptance.report_ready = True
        acceptance.deadline = 145
        row = vm_row(acceptance.instance)
        row["expanded_config"].update({"user.certificate": "配置证书机密", "volatile.token": "配置令牌机密",
                                       "image.os": "Debian", "image.custom": "镜像任意机密"})
        row["expanded_devices"]["agent"] = {"type": "disk", "source": "agent:config"}
        row["expanded_devices"]["root"]["source"] = "磁盘敏感来源"
        rows = [row, vm_row("external-vm"), vm_row("../路径逃逸"), vm_row("remote:vm")]
        log = ("固件启动失败\n" + acceptance.password + "\n配置证书机密\n配置令牌机密\n镜像任意机密\n"
               "token=日志令牌机密\n\x1b[31m设备错误\x1b[0m\r\x00\n::error::不执行\n"
               + chr(35) * 2 + "[不执行\n" + "长" * 20000)
        def respond(args, **kwargs):
            self.assertEqual(args[:3], ["incus", "--project", acceptance.project])
            self.assertLessEqual(kwargs["timeout"], 10)
            return completed(json.dumps(rows) if args[3:] == ["list", "--format", "json"] else log)
        with ExitStack() as stack:
            stack.enter_context(patch("scripts.accept_image.time.monotonic", return_value=100))
            run = stack.enter_context(patch("scripts.accept_image.subprocess.run", side_effect=respond))
            stack.enter_context(patch.object(Path, "mkdir"))
            write = stack.enter_context(patch.object(Path, "write_text"))
            acceptance.collect_diagnostics()
        self.assertEqual([item.args[0][3:] for item in run.call_args_list], [
            ["list", "--format", "json"], ["info", acceptance.instance, "--show-log"],
            ["console", acceptance.instance, "--show-log"],
        ])
        self.assertEqual(write.call_count, 3)
        config = json.loads(write.call_args_list[0].args[0])
        self.assertEqual(config["config"]["security.secureboot"], "false")
        self.assertEqual(config["config"]["image.os"], "Debian")
        self.assertEqual(config["devices"]["agent"]["source"], "agent:config")
        emitted = "\n".join(item.args[0] for item in write.call_args_list)
        for hidden in (acceptance.password, "user.certificate", "volatile.token", "配置证书机密", "配置令牌机密",
                       "镜像任意机密", "日志令牌机密", "磁盘敏感来源", "::", chr(35) * 2 + "[", "\x1b", "\r", "\x00"):
            self.assertNotIn(hidden, emitted)
        self.assertIn("固件启动失败", emitted)
        self.assertIn("\\u000d", emitted)
        self.assertIn("\\u0000", emitted)
        self.assertTrue(all(len(item.args[0].encode()) <= 65536 for item in write.call_args_list))
        self.assertTrue(all(path.startswith("diagnostics/") for path in acceptance.report["diagnostics"]["files"]))

    def test_diagnostics_skip_uncreated_project_and_unready_report(self):
        acceptance = self.acceptance
        for project_created, report_ready in ((False, True), (True, False), (False, False)):
            acceptance.project_created, acceptance.report_ready = project_created, report_ready
            with patch.object(acceptance, "incus") as incus:
                with patch.object(Path, "mkdir") as mkdir:
                    acceptance.collect_diagnostics()
            incus.assert_not_called()
            mkdir.assert_not_called()

    def test_diagnostics_continue_after_log_failure_and_respect_deadline(self):
        acceptance = self.acceptance
        acceptance.project_created = acceptance.report_ready = True
        acceptance.deadline = 145
        rows = json.dumps([vm_row(acceptance.instance)])
        for expired in (False, True):
            with self.subTest(expired=expired):
                with ExitStack() as stack:
                    stack.enter_context(patch.object(Path, "mkdir"))
                    stack.enter_context(patch.object(Path, "write_text"))
                    stack.enter_context(patch("scripts.accept_image.time.monotonic", return_value=146 if expired else 100))
                    incus = stack.enter_context(patch.object(acceptance, "incus", side_effect=[
                        completed(rows), subprocess.CalledProcessError(1, ["隐藏"], stderr="隐藏"), completed("控制台错误"),
                    ]))
                    acceptance.collect_diagnostics()
                self.assertEqual(incus.call_count, 1 if expired else 3)
        self.assertNotIn("隐藏", json.dumps(acceptance.report, ensure_ascii=False))

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
        for account in ACCOUNT_FILES:
            for suffix in ACCOUNT_BACKUP_SUFFIXES:
                self.assertIn(f"/etc/{account}{suffix}", script)
            self.assertIn(f"/var/backups/{account}*", script)
        for path in (*HISTORY_FILES, "/root/.ssh"):
            self.assertIn(path, script)
        self.assertIn('[ -L "$path" ]', script)
        for forbidden in ("rm ", "cat ", "head ", "tail ", "sed ", "awk "):
            self.assertNotIn(forbidden, script)

    def test_backup_hits_report_only_fixed_rule_and_exit_code(self):
        for stage in ("credential-backups", "clone-credential-backups"):
            for rule in ("/etc/shadow-", "/var/backups/passwd*", "/root/.ssh"):
                with self.subTest(stage=stage, rule=rule):
                    acceptance = Acceptance(self.spec, Path("dist"), Path("acceptance"))
                    number = f"{CREDENTIAL_PATHS.index(rule) + 1:03d}"
                    error = subprocess.CalledProcessError(1, ["秘密参数"], output=number + "\n", stderr="秘密错误")
                    with patch.object(acceptance, "guest", side_effect=error):
                        with patch("builtins.print") as output:
                            with self.assertRaises(CheckError) as caught:
                                acceptance.step(stage, acceptance.check_credential_backups)
                    self.assertIn(f"命中规则 {number}：{rule}", str(caught.exception))
                    self.assertIn("退出码 1", str(caught.exception))
                    self.assertEqual(acceptance.report["error"]["stage"], stage)
                    emitted = json.dumps(acceptance.report, ensure_ascii=False) + str(output.call_args_list)
                    self.assertNotIn("秘密", emitted)
                    self.assertTrue(caught.exception.__suppress_context__)

    def test_backup_execution_faults_preserve_code_without_untrusted_output(self):
        for code, stdout in ((1, ""), (1, "999\n"), (1, "001\n秘密"), (1, "/etc/shadow-\n"),
                             (2, "001\n"), (126, ""), (127, "秘密输出"), (-15, "")):
            with self.subTest(code=code, stdout=stdout):
                error = subprocess.CalledProcessError(code, ["秘密参数"], output=stdout, stderr="秘密错误")
                with patch.object(self.acceptance, "guest", side_effect=error):
                    with self.assertRaisesRegex(CheckError, f"执行故障，退出码 {code}") as caught:
                        self.acceptance.check_credential_backups()
                self.assertNotIn("命中规则", str(caught.exception))
                self.assertNotIn("秘密", str(caught.exception))

    def test_backup_unexpected_success_output_is_not_a_hit(self):
        with patch.object(self.acceptance, "guest", return_value=completed("秘密输出")):
            with self.assertRaisesRegex(CheckError, "无效结果，退出码 0") as caught:
                self.acceptance.check_credential_backups()
        self.assertNotIn("秘密", str(caught.exception))

    def test_backup_timeout_is_not_a_hit(self):
        error = subprocess.TimeoutExpired(["秘密参数"], 10, output="001\n", stderr="秘密错误")
        with patch.object(self.acceptance, "guest", side_effect=error):
            with patch("builtins.print"):
                with self.assertRaises(subprocess.TimeoutExpired):
                    self.acceptance.step("credential-backups", self.acceptance.check_credential_backups)
        self.assertEqual(self.acceptance.report["error"]["message"], "命令执行超时")

    def test_backup_probe_shell_reports_fixed_rules_without_reading_files(self):
        with patch.object(self.acceptance, "guest", return_value=completed()) as guest:
            self.acceptance.check_credential_backups()
        script = guest.call_args.args[0][2].replace('[ -e "$path" ]', 'probe -e "$path"').replace(
            '[ -L "$path" ]', 'probe -L "$path"')
        for rule in (None, "/etc/shadow-", "/root/.ssh"):
            with self.subTest(rule=rule):
                prefix = 'probe() { return 1; }; ' if rule is None else (
                    f'probe() {{ test "$2" = {rule} && test "$1" = -L; }}; '
                )
                result = subprocess.run(["sh", "-c", prefix + script], text=True, capture_output=True, check=False)
                self.assertEqual(result.returncode, 0 if rule is None else 1)
                self.assertEqual(result.stdout, "" if rule is None else f"{CREDENTIAL_PATHS.index(rule) + 1:03d}\n")
                self.assertEqual(result.stderr, "")

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
        clone_password = next(item.kwargs["input"].removeprefix("root:").rstrip("\n")
                              for item in incus.call_args_list if "input" in item.kwargs)
        self.assertNotEqual(clone_password, password)
        self.assertIn(clone_password, acceptance.diagnostic_secrets)
        self.assertIn(password, acceptance.diagnostic_secrets)
        self.assertNotIn(clone_password, acceptance.diagnostic_text(clone_password, 2048))

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

    def test_import_failure_reports_safe_error_and_cleans_partial_image(self):
        acceptance = self.acceptance
        paths = [Path("dist/a.tar.xz"), Path("dist/a.qcow2")]
        events = []
        fingerprint = "a" * 64
        def respond(args, **kwargs):
            if args[2] == "default":
                self.assertEqual(args[3:6], ["project", "create", acceptance.project])
                return completed()
            self.assertEqual(args[:3], ["incus", "--project", acceptance.project])
            command = args[3:]
            events.append(command)
            if command[:2] == ["image", "import"]:
                self.assertEqual(command, ["image", "import", *map(str, paths), "--alias", acceptance.alias])
                self.assertEqual(kwargs["timeout"], 300)
                raise subprocess.CalledProcessError(42, args, output="禁止显示输出",
                                                    stderr="镜像缺少架构\n" + acceptance.password)
            if command == ["list", "--format", "json"]:
                return completed("[]")
            if command == ["image", "list", "--format", "json"]:
                return completed(json.dumps([{"fingerprint": fingerprint}]))
            if command == ["profile", "list", "--format", "json"]:
                return completed('[{"name":"default"}]')
            return completed()
        def prepare_report():
            acceptance.report_ready = True
        with ExitStack() as stack:
            stack.enter_context(patch("scripts.accept_image.signal.signal"))
            stack.enter_context(patch("scripts.accept_image.signal.setitimer"))
            stack.enter_context(patch("scripts.accept_image.time.monotonic", return_value=100))
            stack.enter_context(patch("scripts.accept_image.import_paths", return_value=paths))
            stack.enter_context(patch.object(acceptance, "preflight"))
            stack.enter_context(patch.object(acceptance, "prepare_report", side_effect=prepare_report))
            diagnostics = stack.enter_context(patch.object(acceptance, "collect_diagnostics",
                                                           side_effect=lambda: events.append("diagnostics")))
            report = stack.enter_context(patch.object(acceptance, "write_report",
                                                      side_effect=lambda: events.append("report")))
            stack.enter_context(patch("scripts.accept_image.subprocess.run", side_effect=respond))
            output = stack.enter_context(patch("builtins.print"))
            result = acceptance.run()
        self.assertEqual(result, 1)
        self.assertFalse(acceptance.project_created)
        self.assertEqual(acceptance.report["error"]["stage"], "import-image")
        self.assertIn("退出码 42", acceptance.report["error"]["message"])
        self.assertIn("镜像缺少架构", acceptance.report["error"]["message"])
        emitted = json.dumps(acceptance.report, ensure_ascii=False) + str(output.call_args_list)
        self.assertNotIn(acceptance.password, emitted)
        self.assertNotIn("禁止显示输出", emitted)
        diagnostics.assert_called_once()
        report.assert_called_once()
        self.assertLess(events.index("diagnostics"), events.index(["image", "delete", fingerprint]))
        self.assertEqual(events[-2:], [["project", "delete", acceptance.project], "report"])
        self.assertFalse(any(isinstance(event, list) and event[0] in {"init", "start"} for event in events))
        stages = {item["stage"]: item["status"] for item in acceptance.report["steps"]}
        self.assertEqual(stages["import-image"], "FAIL")
        self.assertEqual(stages["create-instance"], "NOT_RUN")
        self.assertEqual(stages["cleanup-images-0"], "PASS")
        self.assertEqual(stages["cleanup-project"], "PASS")

    def test_failed_cleanup_deletes_both_short_names_in_owned_project(self):
        acceptance = self.acceptance
        acceptance.project_created = True
        def respond(args, **kwargs):
            self.assertEqual(args[:3], ["incus", "--project", acceptance.project])
            if args[3:] == ["list", "--format", "json"]:
                return completed(json.dumps([vm_row("accept"), vm_row("clone")]))
            if args[3:] in (["image", "list", "--format", "json"], ["profile", "list", "--format", "json"]):
                return completed("[]")
            return completed()
        with patch("scripts.accept_image.subprocess.run", side_effect=respond) as run:
            self.assertTrue(acceptance.cleanup())
        commands = [item.args[0][3:] for item in run.call_args_list]
        self.assertIn(["delete", "accept", "--force"], commands)
        self.assertIn(["delete", "clone", "--force"], commands)
        self.assertEqual(commands[-1], ["project", "delete", acceptance.project])
        self.assertFalse(acceptance.project_created)

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

    def lifecycle(self, failure=None, cleanup_success=True, diagnostic_error=None):
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
        def project_created():
            acceptance.project_created = True
        def collect_diagnostics():
            stages.append("diagnostics")
            if diagnostic_error is not None:
                raise diagnostic_error
        with ExitStack() as stack:
            stack.enter_context(patch("scripts.accept_image.signal.signal"))
            timer = stack.enter_context(patch("scripts.accept_image.signal.setitimer"))
            stack.enter_context(patch("scripts.accept_image.import_paths", return_value=[Path("dist/a.tar.xz"), Path("dist/a.qcow2")]))
            stack.enter_context(patch("scripts.accept_image.check_os_release"))
            stack.enter_context(patch.object(acceptance, "step", side_effect=step))
            stack.enter_context(patch.object(acceptance, "prepare_report", side_effect=report_ready))
            stack.enter_context(patch.object(acceptance, "create_project", side_effect=project_created))
            stack.enter_context(patch.object(acceptance, "collect_diagnostics", side_effect=collect_diagnostics))
            for name in ("preflight", "check_vm_config", "agent_ready", "check_packages",
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

    def test_failure_collects_diagnostics_before_cleanup_without_overwriting_error(self):
        for error in (None, OSError("诊断私密异常"), AcceptanceTerminated()):
            self.setUp()
            with self.subTest(error=type(error).__name__):
                result, stages, incus, cleanup, report, timer = self.lifecycle(failure="cold-start", diagnostic_error=error)
                self.assertEqual(result, 1)
                self.assertEqual(stages[-3:], ["diagnostics", "cleanup", "report"])
                self.assertEqual(self.acceptance.report["error"]["stage"], "cold-start")
                self.assertEqual([item.args[1] for item in timer.call_args_list], [1500, 0, 45, 0, 90, 0])
                self.assertNotIn("诊断私密异常", json.dumps(self.acceptance.report, ensure_ascii=False))
                cleanup.assert_called_once()
                report.assert_called_once()

    def test_failed_project_creation_and_success_skip_diagnostics(self):
        for failure in (None, "create-project", "verify-export"):
            self.setUp()
            result, stages, incus, cleanup, report, timer = self.lifecycle(failure=failure)
            self.assertNotIn("diagnostics", stages)
            cleanup.assert_called_once()

    def test_cleanup_failure_prevents_success(self):
        result, stages, incus, cleanup, report, timer = self.lifecycle(cleanup_success=False)
        self.assertEqual(result, 1)
        self.assertEqual(self.acceptance.report["status"], "failed")


if __name__ == "__main__":
    unittest.main()
