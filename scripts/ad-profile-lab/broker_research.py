"""Real Samba/DSDB laboratory contracts. Never run against an installed DC."""
import multiprocessing
import os
import sqlite3
import socket
import unittest
import uuid

import ldb
from samba import auth
from samba.samdb import SamDB
from samba.credentials import Credentials, DONT_USE_KERBEROS
from samba.dcerpc import security
from samba.ndr import ndr_pack, ndr_unpack
import re

from broker_candidate import Candidate, Conflict, Denied, DB, FIELDS, JOURNAL, fixture, initialize_journal, loadparm, modify, one, text


def worker(request, result, start=None, fault=None):
    try:
        candidate = Candidate()
        if start is not None:
            start.wait(10)
        value = candidate.execute(request, "operator", candidate.fixture["Password"], fault=fault)
        if result is not None:
            result.put(value)
    except Conflict:
        result.put("conflict")
    except Exception:
        if result is not None:
            result.put("unexpected-error")
        raise


def ldap_writer(ready, start, entered, done, result):
    data=fixture();lp=loadparm();credentials=Credentials();credentials.guess(lp);credentials.set_bind_dn(data["Config"]["WriterDN"]);credentials.set_password(data["Password"]);credentials.set_kerberos_state(DONT_USE_KERBEROS)
    remote=SamDB(url="ldaps://dc1.profile.test:636",lp=lp,credentials=credentials)
    target=one(remote,data["Config"]["ManagedOU"],"(sAMAccountName=casprobe)",None,ldb.SCOPE_ONELEVEL)
    ready.set()
    if not start.wait(10): raise RuntimeError("missing lab barrier")
    entered.set();modify(remote,target.dn,{"displayName":["External-LDAP"]});done.set();result.put("external-complete")


class BrokerResearch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = fixture(); initialize_journal()
        cls.root = SamDB(url=DB, lp=loadparm(), session_info=auth.system_session(loadparm()))
        cls.target = one(cls.root, cls.data["Config"]["ManagedOU"], "(sAMAccountName=casprobe)", None, ldb.SCOPE_ONELEVEL)
        cls.original = {a: list(cls.target.get(a, [])) for a in FIELDS}
        cls.mp = multiprocessing.get_context("spawn")

    @classmethod
    def tearDownClass(cls):
        modify(cls.root, cls.target.dn, cls.original)
        restored = one(cls.root, cls.target.dn)
        assert all(list(restored.get(a, [])) == cls.original[a] for a in FIELDS)
        print("Broker research: original four profile values restored; object versions/history retained", flush=True)

    def setUp(self):
        modify(self.root, self.target.dn, {"displayName": ["Broker-Baseline"], "givenName": []})
        self.candidate = Candidate()

    def request(self, value="Broker-After"):
        return dict(self.candidate.snapshot(), id=uuid.uuid4().hex, changes={"displayName": [value]})

    def call(self, request, **kwargs):
        return self.candidate.execute(request, "operator", self.data["Password"], **kwargs)

    def row(self):
        return one(self.root, self.target.dn)

    def test_01_positive_inverse_and_no_replay(self):
        before = self.request(); self.assertEqual(self.call(before), "succeeded")
        committed = text(self.row(), "uSNChanged")
        self.assertEqual(self.call(before), "succeeded")
        self.assertEqual(text(self.row(), "uSNChanged"), committed)
        inverse = self.request("Broker-Baseline")
        self.assertEqual(self.call(inverse), "succeeded")
        self.assertEqual(text(self.row(), "displayName"), "Broker-Baseline")

    def test_02_stale_ABA_and_unrelated_change(self):
        stale = self.request(); modify(self.root, self.target.dn, {"displayName": ["B"]}); modify(self.root, self.target.dn, {"displayName": ["Broker-Baseline"]})
        with self.assertRaises(Conflict): self.call(stale)
        stale = self.request(); modify(self.root, self.target.dn, {"givenName": ["Other-writer"]})
        with self.assertRaises(Conflict): self.call(stale)
        self.assertEqual(text(self.row(), "givenName"), "Other-writer")

    def test_03_two_processes_one_version_winner(self):
        first = self.request("Winner1"); second = dict(first, id=uuid.uuid4().hex, changes={"displayName": ["Winner2"]})
        result = self.mp.Queue(); start = self.mp.Event()
        processes = [self.mp.Process(target=worker, args=(r, result, start)) for r in (first, second)]
        try:
            for p in processes: p.start()
            start.set()
            values = [result.get(timeout=15), result.get(timeout=15)]
            self.assertCountEqual(values, ["succeeded", "conflict"])
            for p in processes: p.join(10); self.assertEqual(p.exitcode, 0)
        finally:
            for p in processes:
                if p.is_alive(): p.kill(); p.join(5)

    def test_04_backend_ACL_rejects_nonprofile_and_outside(self):
        # Direct normal-token DSDB calls deliberately bypass only the candidate's
        # attribute filter, proving backend enforcement rather than a Python check.
        for attr in ("description", "userAccountControl", "servicePrincipalName"):
            self.candidate.db.transaction_start()
            try:
                modify(self.candidate.db, self.target.dn, {"displayName": ["must-rollback"]})
                with self.assertRaises(ldb.LdbError) as error:
                    modify(self.candidate.db, self.target.dn, {attr: ["514" if attr == "userAccountControl" else "forbidden"]})
                self.assertEqual(error.exception.args[0], 50)
            finally: self.candidate.db.transaction_cancel()
            self.assertEqual(text(self.row(), "displayName"), "Broker-Baseline")
        outside = one(self.root, self.data["Config"]["BaseDN"], "(sAMAccountName=outside)", None, ldb.SCOPE_SUBTREE)
        with self.assertRaises(ldb.LdbError) as error:
            modify(self.candidate.db, outside.dn, {"displayName": ["forbidden"]})
        self.assertEqual(error.exception.args[0], 50)
        with self.assertRaises(Denied): self.candidate.check_token(auth.system_session(loadparm()))

    def test_05_typed_requests_and_identity_binding(self):
        for extra in ("dn", "filter", "url", "controls", "session_info", "as_system"):
            with self.assertRaises(Denied): self.call(dict(self.request(), **{extra: "untrusted"}))
        for key in ("target", "sid", "domain", "dc"):
            with self.assertRaises(Denied): self.call(dict(self.request(), **{key: "0" * 32}))
        with self.assertRaises(Denied): self.call(dict(self.request(), changes={"userAccountControl": ["514"]}))
        self.assertEqual(text(self.row(), "displayName"), "Broker-Baseline")

    def test_06_wrong_password_and_nonoperator(self):
        with self.assertRaises(Exception): self.candidate.execute(self.request(), "operator", "synthetic-wrong-password")
        with self.assertRaises(Denied): self.candidate.execute(self.request(), "ordinary", self.data["Password"])
        self.assertEqual(text(self.row(), "displayName"), "Broker-Baseline")

    def test_07_current_role_revocation(self):
        request = self.request(); group = one(self.root, self.data["Config"]["OperatorGroupDN"], attrs=["member"])
        members = list(group["member"])
        try:
            modify(self.root, group.dn, {"member": []})
            with self.assertRaises(Denied): self.call(request)
        finally: modify(self.root, group.dn, {"member": members})
        self.assertEqual(text(self.row(), "displayName"), "Broker-Baseline")

    def test_08_crash_before_commit_and_lost_result_after_commit(self):
        for fault, code, value in (("before_commit", 73, "Broker-Baseline"), ("after_commit", 74, "Crash-After")):
            request = self.request("Crash-After")
            process = self.mp.Process(target=worker, args=(request, None), kwargs={"fault": fault})
            try:
                process.start(); process.join(15)
                self.assertEqual(process.exitcode, code)
            finally:
                if process.is_alive(): process.kill(); process.join(5)
            self.assertEqual(text(self.row(), "displayName"), value)
            if fault=="before_commit":self.assertEqual(text(self.row(),"uSNChanged"),request["version"])
            else:self.assertNotEqual(text(self.row(),"uSNChanged"),request["version"])
            version = text(self.row(), "uSNChanged")
            self.assertEqual(self.call(request), "applying")
            self.assertEqual(text(self.row(), "uSNChanged"), version)
            with sqlite3.connect(JOURNAL) as journal:
                self.assertEqual(journal.execute("SELECT state FROM operations WHERE id=?", (request["id"],)).fetchone()[0], "applying")

    def test_09_idempotency_conflict_and_audit_no_values(self):
        request = self.request("Profile-value-not-in-audit"); self.call(request)
        with self.assertRaises(Denied): self.call(dict(request, changes={"displayName": ["Different"]}))
        with self.assertRaises(Denied): self.candidate.execute(request,"ordinary",self.data["Password"])
        with sqlite3.connect(JOURNAL) as journal:
            audit = repr(journal.execute("SELECT * FROM audit WHERE id=?", (request["id"],)).fetchall())
            self.assertNotIn("Profile-value-not-in-audit", audit)
            self.assertNotIn(self.data["Password"], audit)
            self.assertEqual(journal.execute("SELECT event FROM audit WHERE id=?", (request["id"],)).fetchall(), [("applying",), ("succeeded",)])

    def test_10_external_LDAP_writer_serialized_by_DSDB_transaction(self):
        ready=self.mp.Event();start=self.mp.Event();entered=self.mp.Event();done=self.mp.Event();result=self.mp.Queue()
        process=self.mp.Process(target=ldap_writer,args=(ready,start,entered,done,result))
        try:
            process.start();self.assertTrue(ready.wait(10))
            def hold():
                start.set();self.assertTrue(entered.wait(3));self.assertFalse(done.wait(0.25),"external LDAP write completed inside local transaction")
            self.assertEqual(self.call(self.request(),hold=hold),"succeeded")
            self.assertEqual(result.get(timeout=10),"external-complete")
            process.join(5);self.assertEqual(process.exitcode,0)
            self.assertEqual(text(self.row(),"displayName"),"External-LDAP")
        finally:
            if process.is_alive():process.kill();process.join(5)

    def test_11_revoked_attribute_ACL_is_rechecked(self):
        request=self.request();sd=one(self.root,self.target.dn,attrs=["nTSecurityDescriptor"]);original=bytes(sd["nTSecurityDescriptor"][0])
        descriptor=ndr_unpack(security.descriptor,original);domain=security.dom_sid(self.data["Config"]["DomainSID"])
        sddl=descriptor.as_sddl(domain)
        restricted=re.sub(r"\([^()]*;"+re.escape(self.candidate.writer_sid)+r"\)","",sddl)
        self.assertNotEqual(sddl,restricted)
        try:
            modify(self.root,self.target.dn,{"nTSecurityDescriptor":[ndr_pack(security.descriptor.from_sddl(restricted,domain))]})
            # Snapshot after the ACL mutation: rejection must be ACL-based,
            # not merely an earlier stale-version check.
            request=self.request()
            with self.assertRaises(ldb.LdbError) as error:self.call(request)
            self.assertEqual(error.exception.args[0],50)
        finally:modify(self.root,self.target.dn,{"nTSecurityDescriptor":[original]})
        self.assertEqual(bytes(one(self.root,self.target.dn,attrs=["nTSecurityDescriptor"])["nTSecurityDescriptor"][0]),original)
        self.assertEqual(text(self.row(),"displayName"),"Broker-Baseline")
        self.assertEqual(self.call(self.request()),"succeeded")

    def test_12_protected_target_and_scope_change(self):
        spn=list(self.row().get("servicePrincipalName",[]))
        try:
            modify(self.root,self.target.dn,{"servicePrincipalName":["HOST/broker-fixture.profile.test"]})
            with self.assertRaises(Denied):self.call(self.request())
        finally:modify(self.root,self.target.dn,{"servicePrincipalName":spn})
        old=str(self.target.dn);moved="CN=casprobe,OU=Outside,"+self.data["Config"]["BaseDN"]
        request=self.request()
        try:
            self.root.rename(old,moved)
            with self.assertRaises(Denied):self.call(request)
        finally:self.root.rename(moved,old)

    def test_13_native_auth_rejects_wrong_TLS_name(self):
        with open("/etc/hosts","a") as hosts:hosts.write("\n127.0.0.1 wrong-broker.profile.test\n")
        with socket.create_connection(("wrong-broker.profile.test",636),timeout=2) as connection:self.assertEqual(connection.getpeername()[0],"127.0.0.1")
        lp=loadparm();credentials=Credentials();credentials.guess(lp);credentials.set_bind_dn(self.data["Config"]["WriterDN"]);credentials.set_password(self.data["Password"]);credentials.set_kerberos_state(DONT_USE_KERBEROS)
        with self.assertRaises(ldb.LdbError):SamDB(url="ldaps://wrong-broker.profile.test:636",lp=lp,credentials=credentials)

    def test_14_SYSTEM_counterexample_is_not_least_privilege(self):
        before=self.row();self.root.transaction_start()
        try:
            modify(self.root,self.target.dn,{"description":["SYSTEM-can-bypass-the-writer-limit"]})
            self.assertEqual(text(one(self.root,self.target.dn),"description"),"SYSTEM-can-bypass-the-writer-limit")
        finally:self.root.transaction_cancel()
        self.assertEqual(text(self.row(),"uSNChanged"),text(before,"uSNChanged"))
        self.assertEqual(list(self.row().get("description",[])),list(before.get("description",[])))
        with self.assertRaises(Denied):self.candidate.check_token(auth.system_session(loadparm()))

    def test_15_commit_ack_error_remains_uncertain(self):
        request=self.request("Commit-ack-lost")
        with self.assertRaises(OSError):self.call(request,fault="commit_ack_error")
        self.assertEqual(text(self.row(),"displayName"),"Commit-ack-lost")
        version=text(self.row(),"uSNChanged")
        self.assertEqual(self.call(request),"applying")
        self.assertEqual(text(self.row(),"uSNChanged"),version)

    def test_16_disabled_writer_and_pinned_identity(self):
        writer=one(self.root,self.data["Config"]["WriterDN"],attrs=["userAccountControl"])
        try:
            modify(self.root,writer.dn,{"userAccountControl":["514"]})
            with self.assertRaises(Denied):self.call(self.request())
            with self.assertRaises(Denied):Candidate()
        finally:modify(self.root,writer.dn,{"userAccountControl":list(writer["userAccountControl"])})
        self.assertEqual(text(self.row(),"displayName"),"Broker-Baseline")
        self.assertEqual(self.call(self.request()),"succeeded")

    def test_17_current_privileged_group_membership_denied(self):
        group=one(self.root,self.data["Config"]["BaseDN"],"(sAMAccountName=Domain Admins)",["member"],ldb.SCOPE_SUBTREE)
        members=list(group.get("member",[]))
        try:
            modify(self.root,group.dn,{"member":members+[str(self.target.dn)]})
            with self.assertRaises(Denied):self.call(self.request())
        finally:modify(self.root,group.dn,{"member":members})
        self.assertEqual(text(self.row(),"displayName"),"Broker-Baseline")

    def test_18_remote_transaction_wrapper_is_not_atomic(self):
        lp=loadparm();credentials=Credentials();credentials.guess(lp);credentials.set_bind_dn(self.data["Config"]["WriterDN"]);credentials.set_password(self.data["Password"]);credentials.set_kerberos_state(DONT_USE_KERBEROS)
        remote=SamDB(url="ldaps://dc1.profile.test:636",lp=lp,credentials=credentials)
        remote.transaction_start()
        try:modify(remote,self.target.dn,{"displayName":["Remote-cancel-does-not-undo"]})
        finally:remote.transaction_cancel()
        self.assertEqual(text(self.row(),"displayName"),"Remote-cancel-does-not-undo")


if __name__ == "__main__":
    fixture()  # explicit guard before unittest or any database opening
    unittest.main(verbosity=2)
