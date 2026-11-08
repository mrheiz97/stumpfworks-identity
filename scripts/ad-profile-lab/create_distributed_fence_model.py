"""Safety contract model for a future cross-host fence. No network or deployment."""
import unittest


class Denied(Exception):
    pass


class Fence:
    def __init__(self):
        self.route = (1, "dc1", "boot-a")
        self.frozen = False
        self.quorum = True
        self.claims = {}
        self.pending = None

    def require_quorum(self):
        if not self.quorum:
            raise Denied("quorum unavailable")

    def claim(self, route, upn, digest):
        self.require_quorum()
        if self.frozen or route != self.route or self.pending or upn in self.claims:
            raise Denied("dispatch denied")
        self.claims[upn] = (route, digest)
        self.pending = (upn, route, digest)

    def receipt(self, upn, route, digest):
        self.require_quorum()
        if self.pending is None or self.pending != (upn, route, digest):
            raise Denied("no matching authenticated terminal receipt")
        self.pending = None

    def freeze(self, route):
        self.require_quorum()
        if route != self.route or self.frozen:
            raise Denied("wrong route")
        self.frozen = True

    def promote(self, target, *, fence_proof, replication_proof):
        self.require_quorum()
        proof_scope = (self.route, target)
        if (not self.frozen or self.pending or target[0] <= self.route[0]
                or target[1] == self.route[1] or target[2] == self.route[2]
                or fence_proof != proof_scope or replication_proof != proof_scope):
            raise Denied("incomplete handoff")
        self.route = target
        self.frozen = False


class FenceTests(unittest.TestCase):
    def test_partition_does_not_grant_or_promote(self):
        f = Fence()
        old = f.route
        target = (2, "dc2", "boot-b")
        f.freeze(old)
        f.quorum = False
        with self.assertRaises(Denied):
            f.claim(old, "user", "digest")
        with self.assertRaises(Denied):
            f.promote(target, fence_proof=(old, target), replication_proof=(old, target))
        self.assertEqual(f.route, old)

    def test_lost_commit_response_keeps_claim_and_blocks_transition(self):
        f = Fence()
        old = f.route
        f.claim(old, "user", "digest")
        f.freeze(old)
        target = (2, "dc2", "boot-b")
        with self.assertRaises(Denied):
            f.receipt("user", old, "wrong")
        with self.assertRaises(Denied):
            f.promote(target, fence_proof=(old, target), replication_proof=(old, target))
        f.receipt("user", old, "digest")
        f.promote(target, fence_proof=(old, target), replication_proof=(old, target))
        with self.assertRaises(Denied):
            f.claim(target, "user", "other")

    def test_no_promotion_without_exact_fence_and_replication_proofs(self):
        f = Fence()
        old = f.route
        f.freeze(old)
        target = (2, "dc2", "boot-b")
        with self.assertRaises(Denied):
            f.promote(target, fence_proof=None, replication_proof=(old, target))
        with self.assertRaises(Denied):
            f.promote(target, fence_proof=(old, target), replication_proof=None)
        with self.assertRaises(Denied):
            f.promote(target, fence_proof=(old, (2, "dc2", "wrong-boot")), replication_proof=(old, target))
        f.promote(target, fence_proof=(old, target), replication_proof=(old, target))
        for stale in (old, (2, "dc2", "restarted-b")):
            with self.assertRaises(Denied):
                f.claim(stale, "fresh", "digest")
        f.claim(target, "fresh", "digest")


if __name__ == "__main__":
    unittest.main(verbosity=2)
