#!/usr/bin/env python3
"""Exercise the real helper's Unix file permissions without a VNC/service change."""
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

if os.name == "posix":
    import grp

HELPER = Path(sys.argv.pop(1)) if len(sys.argv) > 1 else Path(__file__).with_name("swbadge-vnc-set-password.sh")


@unittest.skipUnless(os.name == "posix" and os.geteuid() == 0, "requires isolated Unix root fixtures")
class PasswordHelperContract(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="vnc-helper-contract-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = self.root / "config"
        self.calls = self.root / "calls"
        binaries = self.root / "bin"
        binaries.mkdir()
        # Keep real install/mktemp/chmod, but never call real VNC or systemd.
        (binaries / "x11vnc").write_text(
            '#!/bin/sh\n[ "$1" = "-storepasswd" ] || exit 91\n'
            'printf "x11vnc\\n" >> "$CONTRACT_CALLS"\n'
            'printf TESTONLY > "$2"\n'
        )
        (binaries / "systemctl").write_text(
            '#!/bin/sh\nprintf "systemctl\\n" >> "$CONTRACT_CALLS"\n'
        )
        for executable in binaries.iterdir():
            executable.chmod(0o755)
        self.environment = dict(os.environ, PATH=f"{binaries}:/usr/bin:/bin", CONTRACT_CALLS=str(self.calls))
        self.script = self.root / "helper.sh"
        # Relocate the fixed deployment path only inside the disposable copy.
        self.script.write_text(HELPER.read_text().replace("/etc/stumpfworks-badge", str(self.config)))

    def invoke(self):
        return subprocess.run(["sh", str(self.script)], env=self.environment, capture_output=True, text=True)

    def assert_private_password(self):
        password = self.config / "vnc.passwd"
        self.assertEqual(password.read_bytes(), b"TESTONLY")
        info = password.stat()
        self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (0, 0, 0o600))

    def test_preserves_existing_shared_directory_and_config(self):
        self.config.mkdir()
        os.chown(self.config, 0, grp.getgrnam("daemon").gr_gid)
        self.config.chmod(0o750)
        config_file = self.config / "client.conf"
        config_file.write_bytes(b"TEST_CONFIG_UNCHANGED\n")
        config_file.chmod(0o640)
        before = self.config.stat()
        self.assertEqual(self.invoke().returncode, 0)
        after = self.config.stat()
        self.assertEqual((after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)),
                         (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)))
        self.assertEqual(config_file.read_bytes(), b"TEST_CONFIG_UNCHANGED\n")
        self.assertEqual(stat.S_IMODE(config_file.stat().st_mode), 0o640)
        self.assert_private_password()

    def test_creates_new_directory_privately(self):
        self.assertEqual(self.invoke().returncode, 0)
        info = self.config.stat()
        self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (0, 0, 0o700))
        self.assert_private_password()

    def test_rejects_symlink_without_side_effects(self):
        target = self.root / "untouched"
        target.mkdir()
        self.config.symlink_to(target, target_is_directory=True)
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertEqual(list(target.iterdir()), [])
        self.assertFalse(self.calls.exists())

    def test_rejects_non_directory_without_side_effects(self):
        self.config.write_bytes(b"UNTOUCHED")
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertEqual(self.config.read_bytes(), b"UNTOUCHED")
        self.assertFalse(self.calls.exists())

    def test_rejects_untrusted_directory_owner(self):
        self.config.mkdir()
        os.chown(self.config, 65534, 65534)
        self.config.chmod(0o750)
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertFalse(self.calls.exists())
        self.assertEqual(self.config.stat().st_uid, 65534)

    def test_rejects_group_writable_directory(self):
        self.config.mkdir()
        self.config.chmod(0o770)
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertFalse(self.calls.exists())
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o770)


if __name__ == "__main__":
    unittest.main()
