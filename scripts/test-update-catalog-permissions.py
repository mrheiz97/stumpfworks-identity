#!/usr/bin/env python3
"""Real Unix access checks in disposable fixtures; no service calls or secrets."""
import grp
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0,
                     "requires an isolated Unix root test environment")
class CatalogPermissions(unittest.TestCase):
    def setUp(self):
        self.fixture = tempfile.TemporaryDirectory(prefix="identity-catalog-permissions-")
        self.addCleanup(self.fixture.cleanup)
        self.root = Path(self.fixture.name)
        self.root.chmod(0o755)
        self.uid = pwd.getpwnam("daemon").pw_uid
        self.gid = grp.getgrnam("daemon").gr_gid

    def as_service(self, *args):
        return subprocess.run(["runuser", "-u", "daemon", "--", *map(str, args)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def catalog(self, parent):
        path = parent / "releases"
        old_umask = os.umask(0o077)
        try:
            path.mkdir(mode=0o750)
        finally:
            os.umask(old_umask)
        # Final mode is explicit: umask077 would otherwise remove group access.
        os.chown(path, 0, self.gid)
        path.chmod(0o750)
        approval = path / "approved.json"
        approval.write_text("[]\n")
        os.chown(approval, 0, self.gid)
        approval.chmod(0o640)
        return path

    def rename_as_service(self, path):
        return self.as_service(sys.executable, "-c",
                               "import os,sys; os.rename(sys.argv[1],sys.argv[2])",
                               path, path.with_name("replaced"))

    def test_service_can_read_but_cannot_rewrite_approval(self):
        path = self.catalog(self.root)
        self.assertEqual(self.as_service("cat", path / "approved.json").returncode, 0)
        self.assertNotEqual(self.as_service(sys.executable, "-c",
                            "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('changed')",
                            path / "approved.json").returncode, 0)
        self.assertEqual((path / "approved.json").read_text(), "[]\n")

    def test_root_controlled_parent_prevents_catalog_replacement(self):
        path = self.catalog(self.root)
        self.assertNotEqual(self.rename_as_service(path).returncode, 0)
        self.assertTrue(path.is_dir())

    def test_service_writable_parent_demonstrates_replacement_regression(self):
        parent = self.root / "runtime"
        parent.mkdir(mode=0o750)
        os.chown(parent, self.uid, self.gid)
        path = self.catalog(parent)
        self.assertEqual(self.rename_as_service(path).returncode, 0)
        self.assertFalse(path.exists())
        self.assertTrue((parent / "replaced" / "approved.json").is_file())


if __name__ == "__main__":
    unittest.main(verbosity=2)
