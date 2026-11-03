"""Execution-boundary and signed-request contracts, synthetic isolated DC only."""
import copy
import ctypes
import json
import multiprocessing
import os
import resource
import subprocess
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

import ldb

from broker_candidate import Candidate, DB, Denied, FIELDS, fixture, initialize_journal, journal_path, modify, one
from broker_envelope import AUDIENCE, POLICY, Gate, canonical
from samba import auth
from samba.samdb import SamDB
from broker_candidate import loadparm


def unprivileged_probe(paths, result):
    # Child starts without any inherited SamDB, credentials or signing key.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    if ctypes.CDLL(None, use_errno=True).prctl(38, 1, 0, 0, 0) != 0:
        raise RuntimeError("no_new_privs unavailable")
    os.setgroups([]); os.setgid(65534); os.setuid(65534)
    denied = []
    for path in paths:
        for flags in (os.O_RDONLY, os.O_WRONLY):
            try:
                fd = os.open(path, flags)
            except PermissionError:
                denied.append(True)
            else:
                os.close(fd); denied.append(False)
    with open("/proc/self/status", encoding="ascii") as stream:
        status = stream.read()
    result.send((os.getuid(), os.getgroups(), denied,
                 "CapEff:\t0000000000000000" in status, "NoNewPrivs:\t1" in status,
                 json.loads('{"request":"untrusted"}')))
    result.close()


class BoundaryResearch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = fixture()
        cls.root = SamDB(url=DB, lp=loadparm(), session_info=auth.system_session(loadparm()))
        cls.target = one(cls.root, cls.data["Config"]["ManagedOU"], "(sAMAccountName=casprobe)", scope=ldb.SCOPE_ONELEVEL)
        cls.original = {a: list(cls.target.get(a, [])) for a in FIELDS}
        cls.keys = tempfile.TemporaryDirectory(prefix="broker-issuer-")
        os.chmod(cls.keys.name, 0o700)
        cls.key = cls.keys.name + "/issuer.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", cls.key], check=True, capture_output=True)
        os.chmod(cls.key, 0o600)
        cls.public = subprocess.check_output(["openssl", "pkey", "-in", cls.key, "-pubout"])

    @classmethod
    def tearDownClass(cls):
        modify(cls.root, cls.target.dn, cls.original)
        restored = one(cls.root, cls.target.dn)
        assert all(list(restored.get(a, [])) == cls.original[a] for a in FIELDS)
        cls.keys.cleanup()
        print("Boundary research: original profile values restored; USN/history retained", flush=True)

    def setUp(self):
        os.environ["IDENTITY_BROKER_CASE"] = uuid.uuid4().hex
        initialize_journal()
        self.candidate = Candidate()
        self.gate = Gate(self.public)
        self.request = dict(self.candidate.snapshot(), id=uuid.uuid4().hex, changes={"displayName": ["Signed-Lab"]})
        actor = self.candidate.authenticate("operator", self.data["Password"])
        now = int(time.time())
        self.proof = dict(request=self.request, actor=actor, issued=now, expires=now + 60, policy=POLICY, audience=AUDIENCE)

    def sign(self, proof=None, raw=None):
        payload = canonical(self.proof if proof is None else proof) if raw is None else raw
        with tempfile.TemporaryDirectory(prefix="issuer-sign-") as directory:
            path = directory + "/payload"
            with open(path, "wb") as stream:
                stream.write(payload)
            signature = subprocess.check_output(["openssl", "pkeyutl", "-sign", "-inkey", self.key, "-rawin", "-in", path])
        return payload, signature

    def execute(self, signed, username="operator", password=None):
        return self.gate.execute(self.candidate, *signed, username, password or self.data["Password"])

    def unchanged(self, signed, **kwargs):
        before = self.candidate.snapshot()
        with self.assertRaises(Denied):
            self.execute(signed, **kwargs)
        self.assertEqual(before, self.candidate.snapshot())

    def test_01_signed_success_restart_no_replay(self):
        signed = self.sign()
        self.assertEqual(self.execute(signed), "succeeded")
        after = self.candidate.snapshot()
        self.gate = Gate(self.public); self.candidate = Candidate()
        self.assertEqual(self.execute(signed), "succeeded")
        self.assertEqual(after, self.candidate.snapshot())

    def test_02_all_fields_bound(self):
        payload, signature = self.sign()
        mutations = [("actor", "S-1-0-0"), ("audience", "other"), ("policy", "other"), ("expires", self.proof["expires"] + 1)]
        for field, value in mutations:
            changed = copy.deepcopy(self.proof); changed[field] = value
            self.unchanged((canonical(changed), signature))
        for field in self.request:
            changed = copy.deepcopy(self.proof)
            changed["request"][field] = {"mail": ["other@profile.test"]} if field == "changes" else "changed"
            self.unchanged((canonical(changed), signature))
        self.unchanged((payload, bytes(64)))
        other = self.keys.name + "/other.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", other], check=True, capture_output=True)
        os.chmod(other, 0o600)
        self.gate = Gate(subprocess.check_output(["openssl", "pkey", "-in", other, "-pubout"]))
        self.unchanged((payload, signature))

    def test_03_valid_signature_wrong_context_lifetime(self):
        now = int(time.time())
        for field, value in (("audience", "other"), ("policy", "other"), ("issued", now + 30),
                             ("expires", now - 1), ("expires", now + 120), ("issued", True), ("actor", "S-1-0-0")):
            proof = copy.deepcopy(self.proof); proof[field] = value
            self.unchanged(self.sign(proof))

    def test_04_parser_bounds_duplicates_unknown_fields(self):
        for payload, signature in ((b"x" * 8193, bytes(64)), (b"", bytes(64)), (b"{}", b"x")):
            self.unchanged((payload, signature))
        for raw in (b'{"request":1,"request":2}', b'[]', b'{', b'\xff', canonical(self.proof) + b' '):
            self.unchanged(self.sign(raw=raw))
        proof = copy.deepcopy(self.proof); proof["key"] = self.key
        self.unchanged(self.sign(proof))

    def test_05_signature_does_not_replace_fresh_auth(self):
        signed = self.sign()
        before = self.candidate.snapshot()
        with self.assertRaises(ldb.LdbError) as error:
            self.execute(signed, password="definitely-wrong-lab-password")
        self.assertEqual(error.exception.args[0], 49)
        self.assertEqual(before, self.candidate.snapshot())
        self.unchanged(signed, username="ordinary")

    def test_06_signed_id_rebinding_and_uncertain_target(self):
        signed = self.sign()
        # Real crash semantics already covered by broker tests; here deliberately
        # lose acknowledgement after a real commit through the unchanged candidate.
        with self.assertRaises(OSError):
            self.candidate.execute(self.request, "operator", self.data["Password"], fault="commit_ack_error")
        after = self.candidate.snapshot()
        self.assertEqual(self.execute(signed), "applying")
        changed = copy.deepcopy(self.proof); changed["request"]["changes"] = {"givenName": ["Rebound"]}
        self.unchanged(self.sign(changed))
        changed["request"].update(self.candidate.snapshot(), id=uuid.uuid4().hex)
        self.unchanged(self.sign(changed))
        self.assertEqual(after, self.candidate.snapshot())

    def test_07_unprivileged_preprocess_cannot_read_or_write_authority(self):
        parent, child = multiprocessing.get_context("spawn").Pipe(duplex=False)
        process = multiprocessing.get_context("spawn").Process(target=unprivileged_probe,
            args=([DB, self.key, journal_path(), "/tmp/lab-config.json", "/tmp/lab-password"], child))
        process.start(); child.close()
        self.assertTrue(parent.poll(10))
        uid, groups, denied, no_caps, no_privs, parsed = parent.recv()
        process.join(10)
        self.assertEqual(process.exitcode, 0)
        self.assertEqual(uid, 65534); self.assertEqual(groups, [])
        self.assertTrue(all(denied)); self.assertTrue(no_caps); self.assertTrue(no_privs)
        self.assertEqual(parsed, {"request": "untrusted"})

    def test_08_expiry_rechecked_inside_transaction(self):
        signed = self.sign()
        with patch("broker_envelope.time.time", side_effect=[self.proof["issued"], self.proof["expires"]]):
            self.unchanged(signed)

    def test_09_signed_proof_does_not_freeze_group_authority(self):
        signed = self.sign()
        group = one(self.root, self.data["Config"]["OperatorGroupDN"], attrs=["member"])
        members = list(group.get("member", []))
        try:
            modify(self.root, group.dn, {"member": []})
            self.unchanged(signed)
        finally:
            modify(self.root, group.dn, {"member": members})


if __name__ == "__main__":
    unittest.main(verbosity=2)
