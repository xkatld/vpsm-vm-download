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


if __name__ == "__main__":
    unittest.main()
