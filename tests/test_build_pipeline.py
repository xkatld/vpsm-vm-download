import contextlib
import hashlib
import io
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import build_pipeline


RELEASES = (
    ("almalinux", "10"), ("almalinux", "8"), ("almalinux", "9"),
    ("alpine", "3.21"), ("alpine", "3.22"), ("alpine", "3.23"), ("alpine", "3.24"),
    ("centos", "10-Stream"), ("centos", "9-Stream"),
    ("debian", "bookworm"), ("debian", "forky"), ("debian", "trixie"),
    ("ubuntu", "jammy"), ("ubuntu", "noble"), ("ubuntu", "resolute"),
)
HEADER = (
    "Distribution: 发行版\tRelease: 版本\tArchitecture: 架构\tVariant: 变体\t"
    "Build date: 构建日期\tLXC (privileged): LXC (特权容器)\t"
    "LXC (unprivileged): LXC (非特权容器)\tIncus (container): Incus (容器)\tIncus (VM): Incus (虚拟机)\n"
)


def manifest_row(distro, release, architecture="amd64", variant="default", vm="YES"):
    return f"{distro}\t{release}\t{architecture}\t{variant}\t20260930_05:24\tYES\tYES\tYES\t{vm}\n"


def spec_for(distro="debian", release="bookworm", architecture="amd64"):
    return build_pipeline.ImageSpec(distro, release, architecture, "default", "20260930_05:24")


def completed(stdout="", returncode=0):
    return subprocess.CompletedProcess(["测试命令"], returncode, stdout, "")


class PipelineTestCase(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.output = self.root / "dist"
        self.manifest = self.root / "manifest.tsv"
        self.manifest.write_text(HEADER + "".join(manifest_row(*item) for item in RELEASES), encoding="utf-8")
        self.spec = spec_for()
        self.password = "temporary-'$(never-run); password"
        self.subprocess = self.enterContext(patch("build_pipeline.subprocess.run", return_value=completed()))
        self.enterContext(patch.dict(os.environ, {}, clear=True))
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.enterContext(contextlib.redirect_stderr(io.StringIO()))

    def pipeline(self, **kwargs):
        return build_pipeline.Pipeline(kwargs.pop("specs", [self.spec]), kwargs.pop("output_dir", self.output),
                                       root_password=kwargs.pop("root_password", self.password), **kwargs)

    def clock(self):
        now = [0.0]
        self.enterContext(patch("build_pipeline.time.monotonic", side_effect=lambda: now[0]))

        def sleep(seconds):
            now[0] += seconds
            self.assertLess(now[0], 1000)

        self.enterContext(patch("build_pipeline.time.sleep", side_effect=sleep))
        return now

    def native_host(self):
        self.enterContext(patch("build_pipeline.platform.machine", return_value="x86_64"))
        self.enterContext(patch("build_pipeline.shutil.which", return_value="/usr/bin/工具"))
        self.enterContext(patch("build_pipeline.os.cpu_count", return_value=4))
        self.enterContext(patch("build_pipeline.os.access", return_value=True))
        self.enterContext(patch("build_pipeline.shutil.disk_usage", return_value=SimpleNamespace(free=100 * 1024 ** 3)))
        original_stat = Path.stat
        original_read = Path.read_text

        def path_stat(path, *args, **kwargs):
            if path == Path("/dev/kvm"):
                return SimpleNamespace(st_mode=stat.S_IFCHR | 0o660)
            return original_stat(path, *args, **kwargs)

        def read_text(path, *args, **kwargs):
            if path == Path("/proc/meminfo"):
                return "MemAvailable:    8000000 kB\n"
            return original_read(path, *args, **kwargs)

        self.enterContext(patch.object(Path, "stat", path_stat))
        self.enterContext(patch.object(Path, "read_text", read_text))

    def export_pipeline(self):
        pipeline = self.pipeline()
        self.output.mkdir()
        pipeline.sanitized_containers.add(pipeline.container_name(self.spec))

        def execute(command, **kwargs):
            if command[1:2] == ["list"]:
                return completed(json.dumps([{"name": pipeline.container_name(self.spec),
                                              "type": "virtual-machine", "status_code": 102}]))
            return completed()

        self.subprocess.side_effect = execute
        return pipeline

    def normalized_files(self, directory, prefix):
        nested = directory / "normalized-test"
        nested.mkdir()
        metadata = nested / (prefix + ".tar.xz")
        disk = nested / (prefix + ".qcow2")
        metadata.write_bytes(b"metadata")
        disk.write_bytes(b"disk-before-sanitize")
        return metadata, disk


class ManifestTests(PipelineTestCase):
    def test_fifteen_versions_and_single_architecture(self):
        specs = build_pipeline.load_manifest(self.manifest)
        self.assertEqual([(spec.distro, spec.release) for spec in specs], list(RELEASES))
        self.assertEqual({spec.architecture for spec in specs}, {"amd64"})
        self.assertEqual(build_pipeline.RUNNERS, {"amd64": "ubuntu-24.04"})

    def test_repository_manifest_contract(self):
        path = Path(build_pipeline.__file__).parent / "镜像.md"
        specs = build_pipeline.load_manifest(path)
        self.assertEqual([(spec.distro, spec.release) for spec in specs], list(RELEASES))
        for line in path.read_text(encoding="utf-8").splitlines()[1:]:
            self.assertEqual(len(line.split("\t")), 9)
            self.assertEqual(line.split("\t")[-1], "YES")

    def test_filters_vm_support_architecture_and_variant(self):
        with self.manifest.open("a", encoding="utf-8") as handle:
            handle.write(manifest_row("debian", "ignored", vm="NO"))
            handle.write(manifest_row("debian", "ignored", architecture="arm64"))
            handle.write(manifest_row("debian", "ignored", variant="cloud"))
        self.assertEqual(len(build_pipeline.load_manifest(self.manifest)), 15)

    def test_invalid_manifests(self):
        for text in ("", HEADER, "Distribution\tRelease\n", HEADER + "debian\tbookworm\n",
                     HEADER + manifest_row("debian", "bookworm") * 2,
                     HEADER + manifest_row("debian", "bad;command")):
            with self.subTest(text=text):
                self.manifest.write_text(text, encoding="utf-8")
                with self.assertRaises(ValueError):
                    build_pipeline.load_manifest(self.manifest)

    def test_arm64_is_rejected(self):
        with self.assertRaises(ValueError):
            build_pipeline.load_manifest(self.manifest, "arm64")

    def test_image_spec_api(self):
        for distro, release in RELEASES:
            spec = spec_for(distro, release)
            display = build_pipeline.RELEASE_DISPLAY.get(distro, {}).get(release, release).replace(".", "").lower()
            self.assertEqual(spec.container_name(), f"{distro}{display}-amd64-kvm")
            self.assertEqual(spec.image_alias, f"{distro}-{release}".lower())
            self.assertEqual(spec.remote_path(), f"images:{distro}/{release}/amd64")
        self.assertEqual(len(build_pipeline.COMMON_PACKAGES.split()), 9)
        self.assertIn("vpsm91.com", build_pipeline.README_CONTENT)


class CliTests(PipelineTestCase):
    def invoke(self, args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            try:
                status = build_pipeline.main(["--manifest", str(self.manifest), *args])
            except SystemExit as exc:
                status = exc.code
        return status, output.getvalue()

    def test_matrix_requires_no_tools_credentials_or_vm(self):
        with patch.object(build_pipeline.Pipeline, "run") as run, patch("build_pipeline.shutil.which") as which:
            status, output = self.invoke(["--matrix"])
        self.assertEqual(status, 0)
        jobs = json.loads(output)["include"]
        self.assertEqual(len(jobs), 15)
        self.assertEqual({(job["distro"], job["release"]) for job in jobs}, set(RELEASES))
        self.assertTrue(all(job["architecture"] == "amd64" and job["runner"] == "ubuntu-24.04" for job in jobs))
        run.assert_not_called()
        which.assert_not_called()
        self.subprocess.assert_not_called()

    def test_single_build_selection(self):
        with patch.object(build_pipeline.Pipeline, "run", autospec=True) as run:
            status, _ = self.invoke(["--distro", "debian", "--release", "bookworm", "--architecture", "amd64",
                                     "--output-dir", str(self.output)])
        self.assertEqual(status, 0)
        pipeline = run.call_args.args[0]
        self.assertEqual(pipeline.specs, [self.spec])
        self.assertEqual(pipeline.output_dir, self.output)
        self.assertTrue(pipeline.root_password)
        self.subprocess.assert_not_called()

    def test_missing_selection_or_unsupported_architecture(self):
        for args in ([], ["--distro", "debian"], ["--architecture", "arm64"],
                     ["--architecture", "amd64", "--distro", "missing", "--release", "missing"]):
            with self.subTest(args=args), patch.object(build_pipeline.Pipeline, "run") as run:
                status, _ = self.invoke(args)
                self.assertNotEqual(status, 0)
                run.assert_not_called()


class PreflightTests(PipelineTestCase):
    def test_supported_host(self):
        self.native_host()
        pipeline = self.pipeline()
        pipeline.preflight()
        self.assertEqual(self.subprocess.call_args.args[0], ["incus", "version"])
        self.assertFalse(self.output.exists())

    def test_insufficient_memory(self):
        self.native_host()
        with patch.object(Path, "read_text", return_value="MemAvailable: 1024 kB\n"):
            with self.assertRaises(RuntimeError):
                self.pipeline().preflight()
        self.subprocess.assert_not_called()

    def test_insufficient_cpu_disk_or_kvm_access(self):
        self.native_host()
        cases = (
            ("build_pipeline.os.cpu_count", 1),
            ("build_pipeline.os.access", False),
            ("build_pipeline.shutil.disk_usage", SimpleNamespace(free=1)),
        )
        for target, value in cases:
            with self.subTest(target=target), patch(target, return_value=value):
                with self.assertRaises(RuntimeError):
                    self.pipeline().preflight()
        self.subprocess.assert_not_called()

    def test_foreign_architecture(self):
        self.native_host()
        with patch("build_pipeline.platform.machine", return_value="aarch64"):
            with self.assertRaises(RuntimeError):
                self.pipeline().preflight()
        self.subprocess.assert_not_called()

    def test_missing_tools(self):
        self.native_host()
        for missing in ("incus", "sshpass", "ssh", "qemu-img", "guestfish"):
            with self.subTest(missing=missing), patch("build_pipeline.shutil.which", side_effect=lambda name: None if name == missing else "/tool"):
                with self.assertRaises(RuntimeError):
                    self.pipeline().preflight()
        self.subprocess.assert_not_called()

    def test_requires_empty_output_one_spec_and_finite_timeouts(self):
        self.native_host()
        self.output.mkdir()
        sentinel = self.output / "existing"
        sentinel.write_text("旧文件", encoding="utf-8")
        with self.assertRaises(RuntimeError):
            self.pipeline().preflight()
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "旧文件")
        for kwargs in ({"specs": []}, {"specs": [self.spec, self.spec]}, {"ssh_timeout": float("nan")},
                       {"agent_timeout": 0}, {"root_password": "invalid\npassword"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.pipeline(**kwargs).preflight()
        self.subprocess.assert_not_called()


class ResourceTests(PipelineTestCase):
    def test_vm_copy_init_and_resource_limits(self):
        for distro, release in RELEASES:
            with self.subTest(distro=distro, release=release):
                self.subprocess.reset_mock()
                spec = spec_for(distro, release)
                pipeline = self.pipeline(specs=[spec])
                name = pipeline.container_name(spec)
                with patch.object(pipeline, "wait_for_container") as wait:
                    pipeline.download_images()
                    pipeline.launch_containers()
                commands = [item.args[0] for item in self.subprocess.call_args_list]
                self.assertEqual(commands, [
                    ["incus", "image", "copy", spec.remote_path(), "local:", "--alias",
                     pipeline.base_alias(spec), "--vm", "--quiet"],
                    ["incus", "init", pipeline.base_alias(spec), name, "--vm",
                     "--config", "security.secureboot=false", "--config", "limits.cpu=2",
                     "--config", "limits.memory=2GiB", "--device", "root,size=12GiB"],
                    ["incus", "config", "device", "add", name, "agent", "disk", "source=agent:config"],
                    ["incus", "start", name],
                ])
                wait.assert_called_once_with(name)
                self.assertEqual(pipeline.created_containers, [name])

    def test_unique_bounded_names(self):
        first, second = self.pipeline(), self.pipeline()
        self.assertNotEqual(first.container_name(self.spec), second.container_name(self.spec))
        self.assertLessEqual(len(first.resource_name("long-name-" * 100)), 63)

    def test_failed_creation_is_not_owned(self):
        pipeline = self.pipeline()
        self.subprocess.side_effect = subprocess.CalledProcessError(1, ["incus"])
        with self.assertRaises(build_pipeline.IncusCommandError):
            pipeline.launch_containers()
        self.assertEqual(pipeline.created_containers, [])
        self.subprocess.reset_mock(side_effect=True)
        pipeline.final_cleanup()
        self.subprocess.assert_not_called()

    def test_device_failure_blocks_start_and_run_cleans_owned_instance(self):
        pipeline = self.pipeline(specs=[spec_for("almalinux", "10")])
        name = pipeline.container_name(pipeline.specs[0])
        device_command = ["incus", "config", "device", "add", name, "agent", "disk", "source=agent:config"]

        def execute(command, **kwargs):
            if command[1] == "init":
                self.assertEqual(pipeline.created_containers, [])
            if command == device_command:
                self.assertEqual(pipeline.created_containers, [name])
                raise subprocess.CalledProcessError(1, command, stderr="代理配置盘添加失败")
            return completed()

        self.subprocess.side_effect = execute
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(pipeline, "preflight"))
            stack.enter_context(patch.object(pipeline, "download_images"))
            wait = stack.enter_context(patch.object(pipeline, "wait_for_container"))
            setup = stack.enter_context(patch.object(pipeline, "setup_containers"))
            summary = stack.enter_context(patch.object(pipeline, "write_summary"))
            with self.assertRaisesRegex(RuntimeError, "代理配置盘添加失败"):
                pipeline.run()
        commands = [item.args[0] for item in self.subprocess.call_args_list]
        self.assertEqual(commands, [
            ["incus", "init", pipeline.base_alias(pipeline.specs[0]), name, "--vm",
             "--config", "security.secureboot=false", "--config", "limits.cpu=2",
             "--config", "limits.memory=2GiB", "--device", "root,size=12GiB"],
            device_command,
            ["incus", "delete", name, "--force"],
        ])
        wait.assert_not_called()
        setup.assert_not_called()
        summary.assert_called_once()
        self.assertEqual(summary.call_args.args[0], "failed")
        self.assertEqual(pipeline.created_containers, [])

    def test_start_failure_preserves_owned_instance_for_cleanup(self):
        pipeline = self.pipeline()
        self.subprocess.side_effect = [completed(), completed(), subprocess.CalledProcessError(1, ["incus"])]
        with self.assertRaises(build_pipeline.IncusCommandError):
            pipeline.launch_containers()
        self.assertEqual(self.subprocess.call_args.args[0], ["incus", "start", pipeline.container_name(self.spec)])
        self.assertEqual(pipeline.created_containers, [pipeline.container_name(self.spec)])

    def test_cleanup_deletes_only_recorded_instances_and_aliases(self):
        pipeline = self.pipeline()
        pipeline.created_containers = ["owned-vm"]
        pipeline.created_base_aliases = ["owned-base"]
        pipeline.created_published_aliases = ["owned-published"]
        pipeline.final_cleanup()
        self.assertEqual([item.args[0] for item in self.subprocess.call_args_list], [
            ["incus", "delete", "owned-vm", "--force"],
            ["incus", "image", "alias", "delete", "owned-published"],
            ["incus", "image", "alias", "delete", "owned-base"],
        ])

    def test_agent_timeout_is_bounded_and_uses_exec_true(self):
        now = self.clock()
        pipeline = self.pipeline(agent_timeout=3)
        with patch.object(pipeline, "incus", side_effect=build_pipeline.IncusCommandError("尚未启动")) as incus:
            with self.assertRaises(RuntimeError):
                pipeline.wait_for_container("vm")
        self.assertEqual(now[0], 3)
        self.assertTrue(all(item.args[0] == ["exec", "vm", "--", "true"] for item in incus.call_args_list))
        self.assertTrue(all(0 < item.kwargs["timeout"] <= 3 for item in incus.call_args_list))


class SetupTests(PipelineTestCase):
    def test_password_uses_stdin_only(self):
        pipeline = self.pipeline()
        pipeline.setup_step("vm", "临时密码")
        command = self.subprocess.call_args
        self.assertEqual(command.args[0], ["incus", "exec", "vm", "--", "chpasswd"])
        self.assertEqual(command.kwargs["input"], f"root:{self.password}\n")
        self.assertNotIn(self.password, str(command.args))

    def test_inherited_credentials_are_not_forwarded(self):
        with patch.dict(os.environ, {"SSHPASS": "旧密码", "IMAGE_ROOT_PASSWORD": "旧密码", "PATH": "/bin"}):
            self.pipeline().incus(["version"])
        environment = self.subprocess.call_args.kwargs["env"]
        self.assertNotIn("SSHPASS", environment)
        self.assertNotIn("IMAGE_ROOT_PASSWORD", environment)
        self.assertEqual(environment["PATH"], "/bin")

    def test_command_failures_do_not_expose_credentials(self):
        self.subprocess.side_effect = subprocess.CalledProcessError(1, [self.password], self.password, self.password)
        with self.assertRaises(build_pipeline.SetupStepError) as raised:
            self.pipeline().setup_step("vm", "临时密码")
        self.assertNotIn(self.password, str(raised.exception))

    def test_bounded_package_diagnostics_redact_credentials(self):
        pipeline = self.pipeline()
        self.subprocess.side_effect = subprocess.CalledProcessError(1, ["incus"], stderr=self.password + "\n::error::" + "错误" * 4000)
        with self.assertRaises(build_pipeline.SetupStepError) as raised:
            pipeline.setup_step("vm", "安装软件包", "apk add bash")
        message = str(raised.exception)
        self.assertIn("安装软件包", message)
        self.assertIn("诊断：", message)
        self.assertNotIn(self.password, message)
        self.assertNotIn("::error::", message)
        self.assertLess(len(message), 2200)

    def index_result(self, command, returncode=0, stdout="", stderr=""):
        marker = command[-1].split("printf '\\n", 1)[1].split("%s", 1)[0]
        result = completed(f"{stdout}\n{marker}{returncode}\n")
        result.stderr = stderr
        return result

    def test_index_retries_before_installation(self):
        now = self.clock()
        pipeline = self.pipeline()
        events = []

        def execute(command, **kwargs):
            events.append("索引开始")
            now[0] += 40
            result = self.index_result(command, 1 if len(events) == 1 else 0)
            events.append("索引结束")
            return result

        self.subprocess.side_effect = execute
        with patch.object(pipeline, "setup_step", side_effect=lambda *args: events.append(args[1])):
            pipeline.setup_one(self.spec, "vm")
        self.assertEqual(events[:5], ["索引开始", "索引结束", "索引开始", "索引结束", "安装远程登录"])
        self.assertEqual(events.count("安装远程登录"), 1)
        self.assertEqual(events[-1], "设置临时密码")
        self.assertEqual(now[0], 82)
        self.assertEqual([item.kwargs["timeout"] for item in self.subprocess.call_args_list], [615, 573])

    def test_index_timeout_blocks_installation(self):
        now = self.clock()
        pipeline = self.pipeline(package_index_timeout=3)
        self.subprocess.side_effect = lambda command, **kwargs: self.index_result(command, 1)
        with patch.object(pipeline, "setup_step") as step:
            with self.assertRaisesRegex(build_pipeline.SetupStepError, "软件源索引准备超时"):
                pipeline.setup_one(self.spec, "vm")
        self.assertEqual(now[0], 3)
        self.assertEqual(self.subprocess.call_count, 2)
        step.assert_not_called()

    def test_index_has_independent_budget_and_host_margin(self):
        now = self.clock()
        pipeline = self.pipeline(ssh_timeout=3)

        def execute(command, **kwargs):
            args = build_pipeline.shlex.split(command[-1])
            self.assertEqual(args[:6], ["timeout", "-k", "5", "600", "sh", "-c"])
            self.assertEqual(kwargs["timeout"], 615)
            now[0] += 180
            return self.index_result(command)

        self.subprocess.side_effect = execute
        pipeline.wait_for_package_index("vm", "exec dnf makecache")
        self.subprocess.assert_called_once()
        self.assertEqual(now[0], 180)
        self.assertEqual(pipeline.ssh_timeout, 3)

    def test_index_native_timeout_and_exec_for_all_releases(self):
        self.clock()
        self.subprocess.side_effect = lambda command, **kwargs: self.index_result(command)
        for distro, release in RELEASES:
            with self.subTest(distro=distro, release=release):
                pipeline = self.pipeline(specs=[spec_for(distro, release)])
                with patch.object(pipeline, "setup_step"):
                    pipeline.setup_one(pipeline.specs[0], "vm")
                args = build_pipeline.shlex.split(self.subprocess.call_args.args[0][-1])
                self.assertEqual(args[:6], ["timeout", "-k", "5", "600", "sh", "-c"])
                expected = ("apk update" if distro == "alpine" else
                            "apt-get -o APT::Update::Error-Mode=any update" if distro in {"debian", "ubuntu"}
                            else "dnf makecache")
                self.assertTrue(args[6].endswith("exec " + expected))
                self.assertNotIn("--foreground", args)

    def test_index_guest_timeout_or_signal_never_retries(self):
        self.clock()
        pipeline = self.pipeline()
        for returncode in (124, 125, 126, 127, 137, 143):
            with self.subTest(returncode=returncode):
                self.subprocess.reset_mock()
                self.subprocess.side_effect = lambda command, **kwargs: self.index_result(command, returncode)
                with patch.object(pipeline, "setup_step") as step:
                    with self.assertRaisesRegex(build_pipeline.SetupStepError, "停止重试"):
                        pipeline.setup_one(self.spec, "vm")
                self.subprocess.assert_called_once()
                step.assert_not_called()

    def test_index_execution_failure_never_retries(self):
        self.clock()
        pipeline = self.pipeline()
        failures = (
            subprocess.TimeoutExpired([self.password], 615, output=self.password, stderr="连接中断"),
            subprocess.CalledProcessError(1, [self.password], stderr="代理连接中断"),
            OSError("执行层失败"),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                self.subprocess.reset_mock()
                self.subprocess.side_effect = failure
                output = io.StringIO()
                with patch.object(pipeline, "setup_step") as step, contextlib.redirect_stderr(output):
                    with self.assertRaisesRegex(build_pipeline.SetupStepError, "未确认客户机命令结束"):
                        pipeline.setup_one(self.spec, "vm")
                self.subprocess.assert_called_once()
                step.assert_not_called()
                self.assertIn("耗时 0.0 秒", output.getvalue())
                self.assertIn("退出码未知", output.getvalue())
                self.assertNotIn(self.password, output.getvalue())

    def test_index_missing_or_forged_completion_never_retries(self):
        self.clock()
        pipeline = self.pipeline()
        marker = "VPSM_INDEX_EXIT_" + "a" * 32 + "="
        outputs = ("", "\nVPSM_INDEX_EXIT=0\n", "\nVPSM_INDEX_EXIT_伪造=0\n",
                   f"\n{marker}0\n额外输出", f"\n{marker}错误\n")
        for output in outputs:
            with self.subTest(output=output), patch("build_pipeline.secrets.token_hex", return_value="a" * 32):
                self.subprocess.reset_mock()
                self.subprocess.return_value = completed(output)
                with self.assertRaisesRegex(build_pipeline.SetupStepError, "结束状态异常"):
                    pipeline.wait_for_package_index("vm", "exec dnf makecache")
                self.subprocess.assert_called_once()

    def test_index_logs_elapsed_status_and_bounded_redacted_diagnostics(self):
        now = self.clock()
        with patch.dict(os.environ, {"SSHPASS": "继承凭据"}):
            pipeline = self.pipeline()

        def execute(command, **kwargs):
            now[0] += 75
            return self.index_result(command, stdout=self.password + " 继承凭据\n::error::" + "内容" * 3000,
                                     stderr="诊断尾部\n" * 30)

        self.subprocess.side_effect = execute
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            pipeline.wait_for_package_index("vm", "exec dnf makecache")
        message = output.getvalue()
        self.assertIn("第 1 轮，耗时 75.0 秒，退出码 0", message)
        self.assertIn("[已截断]", message)
        self.assertNotIn(self.password, message)
        self.assertNotIn("继承凭据", message)
        self.assertNotIn("::error::", message)
        self.assertNotIn("exec dnf makecache", message)
        self.assertLess(len(message), 2200)

    def test_index_success_after_deadline_is_rejected(self):
        now = self.clock()
        pipeline = self.pipeline(package_index_timeout=3)

        def execute(command, **kwargs):
            now[0] += 4
            return self.index_result(command)

        self.subprocess.side_effect = execute
        with self.assertRaisesRegex(build_pipeline.SetupStepError, "软件源索引准备超时"):
            pipeline.wait_for_package_index("vm", "exec dnf makecache")
        self.subprocess.assert_called_once()

    def test_index_fractional_budget_uses_portable_integer_duration(self):
        self.clock()
        pipeline = self.pipeline(package_index_timeout=0.5)
        self.subprocess.side_effect = lambda command, **kwargs: self.index_result(command)
        pipeline.wait_for_package_index("vm", "exec apk update")
        args = build_pipeline.shlex.split(self.subprocess.call_args.args[0][-1])
        self.assertEqual(args[:4], ["timeout", "-k", "5", "1"])
        self.assertEqual(self.subprocess.call_args.kwargs["timeout"], 16)

    def test_index_timeout_configuration(self):
        self.assertEqual(build_pipeline.parse_args(["--matrix"]).package_index_timeout, 600)
        args = ["--architecture", "amd64", "--distro", "debian", "--release", "bookworm",
                "--manifest", str(self.manifest), "--package-index-timeout", "900"]
        with patch.object(build_pipeline.Pipeline, "run", autospec=True) as run:
            self.assertEqual(build_pipeline.main(args), 0)
        self.assertEqual(run.call_args.args[0].package_index_timeout, 900)
        self.assertEqual(run.call_args.args[0].ssh_timeout, 120)

    def test_index_timeout_must_be_finite_and_positive(self):
        self.native_host()
        for timeout in (0, -1, float("nan"), float("inf")):
            with self.subTest(timeout=timeout), self.assertRaisesRegex(ValueError, "等待期限"):
                self.pipeline(package_index_timeout=timeout).preflight()
        self.subprocess.assert_not_called()

    def test_common_packages_and_enterprise_repositories(self):
        for distro, release in RELEASES:
            command = build_pipeline.Pipeline.package_install_command(spec_for(distro, release))
            self.assertIn(build_pipeline.COMMON_PACKAGES, command)
            self.assertIn("test -s", command)
        self.assertIn("powertools", build_pipeline.Pipeline.package_install_command(spec_for("almalinux", "8")))
        self.assertIn("crb", build_pipeline.Pipeline.package_install_command(spec_for("centos", "10-Stream")))
        self.assertIn("epel-release-latest-10.noarch.rpm", build_pipeline.Pipeline.package_install_command(spec_for("centos", "10-Stream")))

    def test_ssh_uses_ipv4_and_password_stdin(self):
        pipeline = self.pipeline()
        self.subprocess.return_value = completed("root\n")
        with patch.object(pipeline, "container_ip", return_value="10.1.2.3"):
            pipeline.test_ssh()
        invocation = self.subprocess.call_args
        self.assertEqual(invocation.args[0][:5], ["sshpass", "-d", "0", "ssh", "-4"])
        self.assertIn("root@10.1.2.3", invocation.args[0])
        self.assertEqual(invocation.kwargs["input"], self.password + "\n")
        self.assertNotIn(self.password, str(invocation.args))
        self.assertNotIn("SSHPASS", invocation.kwargs["env"])

    def test_ssh_timeout_is_bounded(self):
        now = self.clock()
        pipeline = self.pipeline(ssh_timeout=3)
        with patch.object(pipeline, "container_ip", return_value=None):
            with self.assertRaises(RuntimeError):
                pipeline.test_ssh()
        self.assertEqual(now[0], 3)
        self.subprocess.assert_not_called()

    def test_ip_selection_excludes_non_ipv4_addresses(self):
        for value in ("127.0.0.1", "0.0.0.0", "169.254.10.1", "2001:db8::1"):
            self.assertIsNone(build_pipeline.Pipeline.extract_ip(value))
        self.assertEqual(build_pipeline.Pipeline.extract_ip("10.20.30.40 (eth0)"), "10.20.30.40")

    def test_systemd_identity_helper_is_missing_only_and_ordered(self):
        command = build_pipeline.Pipeline.first_boot_identity_command(self.spec)
        self.assertIn("/usr/bin/ssh-keygen -A", command)
        self.assertIn("ExecStart=/bin/sh /usr/local/libexec/vpsm-firstboot", command)
        self.assertIn("DefaultDependencies=no", command)
        self.assertIn("sshd-keygen@.service", command)
        self.assertIn("Requires=vpsm-firstboot.service", command)
        self.assertIn("After=vpsm-firstboot.service", command)
        self.assertNotIn("systemctl start vpsm-firstboot", command)
        self.assertNotIn("rm -f", command)

    def test_openrc_initializes_only_missing_identity(self):
        command = build_pipeline.Pipeline.first_boot_identity_command(spec_for("alpine", "3.24"))
        self.assertIn("#!/sbin/openrc-run", command)
        self.assertIn("if ! test -s /etc/machine-id; then", command)
        self.assertIn("/bin/sh /usr/local/libexec/vpsm-firstboot", command)
        self.assertIn("before networking sshd dbus machine-id", command)
        self.assertIn('rc_need="${rc_need:-} vpsm-firstboot"', command)

    def test_live_cleanup_preserves_machine_id_and_host_keys(self):
        pipeline = self.pipeline()
        with patch.object(pipeline, "exec_container") as execute:
            pipeline.cleanup_containers()
        command = execute.call_args.args[1]
        self.assertIn("root:!", command)
        self.assertIn("/etc/shadow.bak", command)
        self.assertIn("/var/backups/group*", command)
        self.assertIn('"$directory"/.[!.]*', command)
        self.assertIn('"$directory"/..?*', command)
        self.assertNotIn("/etc/ssh/ssh_host_*", command)
        self.assertNotIn("/var/lib/dbus/machine-id", command)
        self.assertNotIn("> /etc/machine-id", command)
        self.assertIn(pipeline.container_name(self.spec), pipeline.sanitized_containers)


class ExportTests(PipelineTestCase):
    def test_stop_normalize_sanitize_link_and_checksum_order(self):
        pipeline = self.export_pipeline()
        events = []

        def normalize(directory, prefix):
            events.append("normalize")
            metadata, disk = self.normalized_files(directory, prefix)
            metadata.write_bytes(b"metadata-after-normalize")
            return metadata, disk

        def sanitize(path):
            events.append("sanitize")
            self.assertFalse((self.output / (self.spec.container_name() + ".tar.xz")).exists())
            path.write_bytes(b"disk-after-sanitize")

        with patch("build_pipeline.normalize_export", side_effect=normalize), patch("build_pipeline.sanitize_disk", side_effect=sanitize):
            pipeline.publish_and_export()
        self.assertEqual(events, ["normalize", "sanitize"])
        commands = [item.args[0] for item in self.subprocess.call_args_list]
        name = pipeline.container_name(self.spec)
        self.assertEqual(commands[0], ["incus", "stop", name, "--timeout", "120"])
        self.assertEqual(commands[1], ["incus", "list", name, "--format", "json"])
        self.assertEqual(commands[2], ["incus", "publish", name, "--alias", name])
        self.assertFalse(any("--force" in command or "push" in command for command in commands))
        prefix = self.spec.container_name()
        self.assertEqual(pipeline.exported_files, [prefix + ".qcow2", prefix + ".tar.xz"])
        checksum = (self.output / "SHA256SUMS").read_text(encoding="utf-8")
        self.assertIn(hashlib.sha256(b"disk-after-sanitize").hexdigest(), checksum)
        self.assertIn(hashlib.sha256(b"metadata-after-normalize").hexdigest(), checksum)
        self.assertNotIn(hashlib.sha256(b"disk-before-sanitize").hexdigest(), checksum)
        self.assertEqual({path.name for path in self.output.iterdir()}, {prefix + ".qcow2", prefix + ".tar.xz", "SHA256SUMS"})

    def test_sanitizer_failure_exposes_no_artifacts(self):
        pipeline = self.export_pipeline()
        with patch("build_pipeline.normalize_export", side_effect=self.normalized_files), patch("build_pipeline.sanitize_disk", side_effect=RuntimeError("离线清理失败")):
            with self.assertRaises(RuntimeError):
                pipeline.publish_and_export()
        self.assertEqual(pipeline.exported_files, [])
        self.assertEqual(list(self.output.iterdir()), [])

    def test_normalizer_failure_never_calls_sanitizer(self):
        pipeline = self.export_pipeline()
        with patch("build_pipeline.normalize_export", side_effect=RuntimeError("格式错误")), patch("build_pipeline.sanitize_disk") as sanitize:
            with self.assertRaises(RuntimeError):
                pipeline.publish_and_export()
        sanitize.assert_not_called()
        self.assertEqual(list(self.output.iterdir()), [])

    def test_stop_failure_blocks_publish_and_export(self):
        pipeline = self.export_pipeline()
        self.subprocess.side_effect = subprocess.TimeoutExpired(["incus"], 150)
        with patch("build_pipeline.normalize_export") as normalize:
            with self.assertRaises(build_pipeline.IncusCommandError):
                pipeline.publish_and_export()
        self.assertEqual(self.subprocess.call_count, 1)
        normalize.assert_not_called()
        self.assertEqual(pipeline.created_published_aliases, [])

    def test_running_or_non_vm_instance_blocks_publish(self):
        pipeline = self.export_pipeline()
        for instance_type, status_code in (("virtual-machine", 103), ("container", 102)):
            self.subprocess.reset_mock(side_effect=True)
            self.subprocess.side_effect = [completed(), completed(json.dumps([
                {"name": pipeline.container_name(self.spec), "type": instance_type, "status_code": status_code},
            ]))]
            with self.subTest(instance_type=instance_type, status_code=status_code), self.assertRaises(RuntimeError):
                pipeline.publish_and_export()
            self.assertEqual(self.subprocess.call_count, 2)
            self.assertEqual(pipeline.created_published_aliases, [])

    def test_unclean_guest_cannot_be_published(self):
        with self.assertRaises(RuntimeError):
            self.pipeline().publish_and_export()
        self.subprocess.assert_not_called()

    def test_paths_outside_export_directory_are_rejected(self):
        pipeline = self.export_pipeline()
        prefix = self.spec.container_name()
        metadata = self.root / (prefix + ".tar.xz")
        disk = self.root / (prefix + ".qcow2")
        metadata.write_bytes(b"metadata")
        disk.write_bytes(b"disk")
        with patch("build_pipeline.normalize_export", return_value=(metadata, disk)), patch("build_pipeline.sanitize_disk") as sanitize:
            with self.assertRaises(RuntimeError):
                pipeline.publish_and_export()
        sanitize.assert_not_called()
        self.assertEqual(list(self.output.iterdir()), [])

    def test_output_collisions_are_never_overwritten(self):
        pipeline = self.export_pipeline()
        sentinel = self.output / (self.spec.container_name() + ".qcow2")
        sentinel.write_bytes(b"existing")
        with patch("build_pipeline.normalize_export", side_effect=self.normalized_files), patch("build_pipeline.sanitize_disk") as sanitize:
            with self.assertRaises(RuntimeError):
                pipeline.publish_and_export()
        sanitize.assert_not_called()
        self.assertEqual(sentinel.read_bytes(), b"existing")

    def test_summary_declares_vm_type_and_two_artifacts(self):
        pipeline = self.export_pipeline()
        pipeline.exported_files = [self.spec.container_name() + extension for extension in (".qcow2", ".tar.xz")]
        pipeline.write_summary("success")
        payload = json.loads((self.output / "build-summary.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["image_type"], "virtual-machine")
        self.assertEqual(payload["architecture"], "amd64")
        self.assertEqual(payload["exported_files"], pipeline.exported_files)
        self.assertNotIn(self.password, json.dumps(payload))


class LifecycleTests(PipelineTestCase):
    def test_preflight_failure_never_cleans_or_writes(self):
        pipeline = self.pipeline()
        with patch.object(pipeline, "preflight", side_effect=RuntimeError("预检失败")), patch.object(pipeline, "final_cleanup") as cleanup, patch.object(pipeline, "write_summary") as summary:
            with self.assertRaises(RuntimeError):
                pipeline.run()
        cleanup.assert_not_called()
        summary.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_stage_failure_stops_later_stages_and_writes_failed_summary(self):
        pipeline = self.pipeline()
        with patch.object(pipeline, "preflight"), patch.object(pipeline, "download_images", side_effect=RuntimeError("下载失败")), patch.object(pipeline, "launch_containers") as launch, patch.object(pipeline, "final_cleanup") as cleanup:
            with self.assertRaises(RuntimeError):
                pipeline.run()
        launch.assert_not_called()
        cleanup.assert_called_once_with()
        payload = json.loads((self.output / "build-summary.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "failed")
        self.assertEqual(payload["exported_files"], [])

    def test_successful_stage_order(self):
        pipeline = self.pipeline()
        stages = ["preflight", "download_images", "launch_containers", "setup_containers", "install_common_packages",
                  "write_readmes", "test_ssh", "cleanup_containers", "publish_and_export", "final_cleanup"]
        events = []
        for stage in stages:
            self.enterContext(patch.object(pipeline, stage, side_effect=lambda selected=stage: events.append(selected)))
        pipeline.run()
        self.assertEqual(events, stages)
        payload = json.loads((self.output / "build-summary.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "success")


if __name__ == "__main__":
    unittest.main()
