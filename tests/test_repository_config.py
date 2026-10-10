import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class RepositoryConfigTests(unittest.TestCase):
    def test_one_native_workflow(self):
        files = list((ROOT / ".github/workflows").glob("*.yml"))
        files += list((ROOT / ".github/workflows").glob("*.yaml"))
        self.assertEqual([path.name for path in files], ["build-images.yml"])
        text = files[0].read_text()
        self.assertNotIn("self-hosted", text)
        self.assertNotIn("ubuntu-24.04-arm", text)
        self.assertNotIn("continue-on-error", text)
        self.assertIn("max-parallel: 3", text)
        self.assertIn("LIBGUESTFS_BACKEND: direct", text)
        build = text.index("python3 build_pipeline.py --manifest", text.index("  build:"))
        ipv6 = text.index("incus network set incusbr0 ipv6.address auto")
        acceptance = text.index("python3 -I scripts/accept_image.py")
        upload = text.index("name: images-${{ matrix.distro }}")
        self.assertLess(build, ipv6)
        self.assertLess(ipv6, acceptance)
        self.assertLess(acceptance, upload)
        self.assertIn("steps.acceptance.outcome != 'skipped'", text)
        self.assertIn("path: acceptance/", text)
        self.assertIn("scripts/verify_artifacts.py --matrix", text)

    def test_yaml_dependency_available_in_every_job(self):
        text = (ROOT / ".github/workflows/build-images.yml").read_text()
        validation = text.split("  validate:", 1)[1].split("  build:", 1)[0]
        verification = text.split("  verify:", 1)[1]
        self.assertLess(validation.index("apt-get install -y python3-yaml"), validation.index("python3 -m unittest"))
        self.assertLess(verification.index("qemu-utils python3-yaml"), verification.index("python3 -I scripts/verify_artifacts.py"))
        commands = (ROOT / "scripts/setup-incus.sh").read_text().replace("\\\n", " ").splitlines()
        install = next(shlex.split(line) for line in commands if "apt-get install" in line)
        self.assertIn("python3-yaml", install)

    def test_setup_rejects_missing_hardware_virtualization(self):
        text = (ROOT / "scripts/setup-incus.sh").read_text()
        self.assertIn('"$(uname -m)" != x86_64', text)
        self.assertIn("sudo test -c /dev/kvm", text)
        self.assertIn("0xAE00", text)
        self.assertIn("0xAE01", text)
        self.assertLess(text.index("0xAE01"), text.index("apt-get update"))
        for package in ("qemu-system-x86", "qemu-utils", "ovmf", "python3-guestfs", "libguestfs-tools"):
            self.assertIn(package, text)
        self.assertIn("ipv6.address: none", text)
        self.assertIn("driver: dir", text)
        self.assertIn("remote list --format=json", text)

    def test_setup_installs_and_checks_config_disk_tools(self):
        text = (ROOT / "scripts/setup-incus.sh").read_text()
        commands = [shlex.split(line) for line in text.replace("\\\n", " ").splitlines()]
        installs = [command for command in commands if command[:4] == [
            "sudo", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install"
        ]]
        self.assertEqual(len(installs), 1)
        self.assertIn("genisoimage", installs[0])
        check = text.index("if ! sudo sh -c")
        self.assertLess(text.index("apt-get install"), check)
        self.assertLess(check, text.index("sudo systemctl start incus"))
        self.assertLess(check, text.index("sudo incus admin init"))

    def test_setup_config_disk_tool_availability(self):
        wrapper = "\n".join([
            "uname() { printf '%s\\n' x86_64; }",
            "sudo() {",
            '  printf \'%s\\n\' "$*" >> "$command_log"',
            '  if [ "$1" = sh ]; then',
            "    shift",
            '    /usr/bin/env PATH="$tool_dir" /bin/sh "$@"',
            '  elif [ "$*" = \'incus remote list --format=json\' ]; then',
            "    printf '%s\\n' '{}'",
            "  fi",
            "}",
            "qemu-img() { :; }",
            "df() { :; }",
            'source "$1"',
        ])
        for tools in ((), ("mkisofs",), ("genisoimage",), ("mkisofs", "genisoimage")):
            with self.subTest(tools=tools), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                tool_dir = root / "tools"
                tool_dir.mkdir()
                for tool in tools:
                    (tool_dir / tool).symlink_to("/bin/true")
                command_log = root / "commands"
                result = subprocess.run(
                    ["bash", "--noprofile", "--norc", "-c", wrapper, "setup_test",
                     str(ROOT / "scripts/setup-incus.sh")],
                    env={**os.environ, "tool_dir": str(tool_dir), "command_log": str(command_log)},
                    capture_output=True, text=True, timeout=15,
                )
                commands = command_log.read_text().splitlines()
                install = next(i for i, command in enumerate(commands) if "apt-get install" in command)
                check = next(i for i, command in enumerate(commands) if command.startswith("sh -c command -v"))
                self.assertLess(install, check)
                if tools:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertLess(check, commands.index("systemctl start incus"))
                    self.assertLess(check, commands.index("incus admin init --preseed"))
                    self.assertNotIn("代理配置盘生成工具缺失", result.stderr)
                else:
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn("代理配置盘生成工具缺失", result.stderr)
                    self.assertNotIn("systemctl start incus", commands)
                    self.assertNotIn("incus admin init --preseed", commands)


if __name__ == "__main__":
    unittest.main()
