"""Executable state model for the proposed Create authority. Uses only fixture SQLite."""
from concurrent.futures import ThreadPoolExecutor
import re
import sqlite3
import tempfile
import unittest
from pathlib import Path


class Denied(Exception):
    pass


class Authority:
    def __init__(self, path):
        self.db = sqlite3.connect(path, isolation_level="IMMEDIATE")

    def initialize_fixture(self):
        self.db.executescript("""
            CREATE TABLE route (id INTEGER PRIMARY KEY CHECK(id=1), epoch INTEGER,
                dc TEXT, phase TEXT);
            INSERT INTO route VALUES (1, 1, 'invocation-a', 'active');
            CREATE TABLE names (upn TEXT PRIMARY KEY, job TEXT UNIQUE, epoch INTEGER,
                state TEXT CHECK(state IN ('applying', 'uncertain', 'confirmed')));
        """)

    def apply(self, dc, epoch, local_part, job):
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9-]{0,19}", local_part):
            raise Denied("invalid local part")
        with self.db:
            # Serialize the route read and claim with freeze and promotion.
            self.db.execute("UPDATE route SET epoch=epoch WHERE id=1")
            if self.route() != (epoch, dc, "active"):
                raise Denied("stale or closed route")
            try:
                self.db.execute("INSERT INTO names VALUES (?, ?, ?, 'applying')",
                                (local_part.lower() + "@managed.profile.test", job, epoch))
            except sqlite3.IntegrityError:
                raise Denied("UPN or job already reserved") from None

    def route(self):
        return self.db.execute("SELECT epoch,dc,phase FROM route WHERE id=1").fetchone()

    def freeze(self, epoch, dc):
        with self.db:
            self.transition("""UPDATE route SET phase='frozen'
                WHERE epoch=? AND dc=? AND phase='active'""", (epoch, dc))

    def settle(self, dc, epoch, job, *, matching_receipt):
        with self.db:
            self.db.execute("UPDATE route SET epoch=epoch WHERE id=1")
            if self.route()[:2] != (epoch, dc):
                raise Denied("wrong receipt origin")
            # The boolean abstracts full signature, original-wire and object proof.
            state = "confirmed" if matching_receipt else "uncertain"
            self.transition("""UPDATE names SET state=? WHERE job=? AND epoch=?
                AND state IN ('applying','uncertain')""", (state, job, epoch))

    def transition(self, sql, args):
        if self.db.execute(sql, args).rowcount != 1:
            raise Denied("invalid transition")

    def promote(self, old, new, epoch, *, fence, replicated, namespace_exclusive):
        # These are external proofs, deliberately not inferred from time or LDAP reads.
        if old == new or not all((fence, replicated, namespace_exclusive)):
            raise Denied("missing independent handoff evidence")
        with self.db:
            self.db.execute("UPDATE route SET epoch=epoch WHERE id=1")
            if self.db.execute("SELECT 1 FROM names WHERE state!='confirmed'").fetchone():
                raise Denied("unresolved dispatch")
            self.transition("""UPDATE route SET epoch=epoch+1,dc=?,phase='active'
                WHERE epoch=? AND dc=? AND phase='frozen'""", (new, epoch, old))


class HandoffTests(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.path = Path(workspace.name) / "authority.sqlite"
        self.a = Authority(self.path)
        self.addCleanup(self.a.db.close)
        self.a.initialize_fixture()

    def promote(self, **overrides):
        proofs = dict(fence=True, replicated=True, namespace_exclusive=True)
        proofs.update(overrides)
        self.a.promote("invocation-a", "invocation-b", 1, **proofs)

    def test_reservation_survives_handoff_and_reopen(self):
        self.a.apply("invocation-a", 1, "Alice", "job-a")
        self.a.freeze(1, "invocation-a")
        self.a.settle("invocation-a", 1, "job-a", matching_receipt=True)
        self.promote()
        reopened = Authority(self.path)
        self.addCleanup(reopened.db.close)
        for dc, epoch, name, job in [
            ("invocation-b", 2, "ALICE", "job-b"),
            ("invocation-b", 2, "Bob", "job-a"),
            ("invocation-a", 1, "Bob", "job-b"),
            ("invocation-b", 1, "Bob", "job-b"),
        ]:
            with self.assertRaises(Denied):
                reopened.apply(dc, epoch, name, job)
        reopened.apply("invocation-b", 2, "Bob", "job-b")

    def test_uncertain_blocks_handoff_even_with_replication(self):
        self.a.apply("invocation-a", 1, "Alice", "job-a")
        self.a.freeze(1, "invocation-a")
        with self.assertRaises(Denied):
            self.promote()
        with self.assertRaises(Denied):
            self.a.settle("invocation-b", 1, "job-a", matching_receipt=True)
        self.a.settle("invocation-a", 1, "job-a", matching_receipt=False)
        with self.assertRaises(Denied):
            self.promote()
        self.assertEqual(self.a.route(), (1, "invocation-a", "frozen"))

    def test_frozen_and_missing_evidence_fail_closed(self):
        with self.assertRaises(Denied):
            self.promote()
        self.a.freeze(1, "invocation-a")
        with self.assertRaises(Denied):
            self.a.apply("invocation-a", 1, "Alice", "job-a")
        for key in ("fence", "replicated", "namespace_exclusive"):
            with self.subTest(missing=key), self.assertRaises(Denied):
                self.promote(**{key: False})
        self.promote()
        with self.assertRaises(Denied):
            self.promote()


    def test_concurrent_case_alias_has_one_winner(self):
        def submit(name):
            replica = Authority(self.path)
            try:
                replica.apply("invocation-a", 1, name, name)
                return True
            except Denied:
                return False
            finally:
                replica.db.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(submit, ("Alice", "ALICE"))), [False, True])
        self.assertEqual(self.a.db.execute("SELECT count(*) FROM names").fetchone(), (1,))


if __name__ == "__main__":
    unittest.main(verbosity=2)
