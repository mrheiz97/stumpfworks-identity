"""Independent protocol-v2 wire/authorization contracts. Synthetic DC only."""
import hashlib
import fcntl
import json
import os
import pathlib
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
import tdb

import ldb
from samba import auth
from samba.credentials import Credentials
from samba.samdb import SamDB
from broker_candidate import DB, FIELDS, fixture, loadparm, modify, one
import native_research as legacy


def values_hash(values):
    raw=b""
    for field in FIELDS:
        values_for_field=values[field]
        if len(values_for_field)>1:raise RuntimeError("non-single-valued laboratory profile")
        value=bytes.fromhex(values_for_field[0]) if values_for_field else b""
        raw+=struct.pack(">H",len(value))+value
    return hashlib.sha256(raw).digest()


def packet(db,changes=None,parent=bytes(16),plan=None,policy=None,before_hash=None,after_hash=None,**overrides):
    changes={"displayName":b"Protocol-Two"} if changes is None else changes
    before=legacy.snapshot(db)["values"]
    after=dict(before)
    for field,value in changes.items():after[field]=[value.hex()] if value else []
    original=legacy.packet(db,changes,**overrides)[:-64]
    policy=hashlib.sha256(fixture()["Config"]["Revision"].encode()).digest() if policy is None else policy
    plan=hashlib.sha256(b"synthetic approved plan"+original[8:24]+values_hash(after)).digest() if plan is None else plan
    binding=plan+policy+parent+(values_hash(before) if before_hash is None else before_hash)+(values_hash(after) if after_hash is None else after_hash)
    return legacy.sign(b"SWCAS002"+original[8:144]+binding+original[144:])


def query(payload,**overrides):
    data=fixture();pins=legacy.pins();now=int(time.time())
    parts=dict(id=payload[8:24],plan=payload[144:176],wire=hashlib.sha256(payload[:-64]).digest(),nonce=uuid.uuid4().bytes,
        domain=bytes.fromhex(data["Config"]["DomainGUID"]),dc=bytes.fromhex(data["Config"]["DCIdentity"]),
        target=bytes.fromhex(pins["target_guid"]),actor=bytes.fromhex(pins["actor_guid"]),
        policy=hashlib.sha256(data["Config"]["Revision"].encode()).digest(),scope=bytes.fromhex(pins["scope"]),issued=now,expires=now+30)
    parts.update(overrides)
    body=b"SWSTAT02"+b"".join(parts[k] for k in ("id","plan","wire","nonce","domain","dc","target","actor","policy","scope"))
    body+=struct.pack(">QQ",parts["issued"],parts["expires"])
    assert len(body)==248
    return legacy.sign(body)


def read(db,q,scope=ldb.SCOPE_BASE,attrs=None):
    base="CN=NativeCASReceipt,"+fixture()["Config"]["BaseDN"]
    result=db.search(base=base,scope=scope,expression="(identityLabStatus="+q.hex()+")",attrs=attrs or ["identityLabReceipt"])
    if len(result)!=1 or len(result[0].get("identityLabReceipt",[]))!=1:raise RuntimeError("wrong receipt shape")
    return bytes(result[0]["identityLabReceipt"][0])


def verify(q,raw):
    if len(raw)!=457 or raw[:8]!=b"SWRECP02" or raw[8:256]!=q[:248]:raise ValueError("receipt binding")
    public=bytes.fromhex(legacy.pins()["receipt_public"])
    with tempfile.TemporaryDirectory(prefix="receipt-verify-") as directory:
        for name,value in (("key",bytes.fromhex("302a300506032b6570032100")+public),("body",raw[:393]),("sig",raw[393:])):
            pathlib.Path(directory+"/"+name).write_bytes(value)
        result=subprocess.run(["openssl","pkeyutl","-verify","-pubin","-keyform","DER","-inkey",directory+"/key","-rawin","-in",directory+"/body","-sigfile",directory+"/sig"],capture_output=True,timeout=3)
        if result.returncode:raise ValueError("receipt signature")
    now=int(time.time());issued,expires=struct.unpack(">QQ",raw[377:393])
    if not issued<=now<expires or expires-issued>30 or expires>struct.unpack(">Q",q[240:248])[0]:raise ValueError("receipt freshness")
    state=raw[256];version=int.from_bytes(raw[257:265],"big")
    if state>3 or (state==2)!=(version>0):raise ValueError("receipt state")
    reference=q[8:88]+raw[265:281]+raw[256:265]
    if hashlib.sha256(reference).digest()!=raw[345:377]:raise ValueError("audit reference")
    return state,version


class ProtocolResearch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=fixture();cls.pins=legacy.pins()
        assert cls.pins["protocol"]==2
        cls.root=SamDB(url=DB,lp=loadparm(),session_info=auth.system_session(loadparm()))
        cls.original=legacy.snapshot(cls.root)["values"]

    @classmethod
    def tearDownClass(cls):
        modify(cls.root,cls.pins["target_dn"],{a:[bytes.fromhex(v) for v in values] for a,values in cls.original.items()})
        assert legacy.snapshot(cls.root)["values"]==cls.original
        print("Protocol2: original profile values restored; versions/history retained",flush=True)

    def setUp(self):self.db=legacy.connection()

    def denied(self,payload):
        before=legacy.snapshot(self.db)
        with self.assertRaises(ldb.LdbError):legacy.send(self.db,payload)
        self.assertEqual(before,legacy.snapshot(self.db))

    def test_01_success_signed_readonly_receipt_and_replay(self):
        p=packet(self.db);legacy.send(self.db,p)
        before=legacy.snapshot(self.db);journal=pathlib.Path("/tmp/native-cas/journal.tdb").read_bytes()
        old=None
        for _ in range(3):
            q=query(p);r=read(self.db,q)
            self.assertEqual(verify(q,r),(2,before["version"]))
            self.assertEqual(r[281:345],p[224:288])
            if old:
                with self.assertRaises(ValueError):verify(q,old)
            old=r
        self.assertEqual(journal,pathlib.Path("/tmp/native-cas/journal.tdb").read_bytes())
        self.assertEqual(before,legacy.snapshot(self.db));legacy.send(self.db,p);self.assertEqual(before,legacy.snapshot(self.db))

    def test_02_signed_fields_policy_and_downgrade(self):
        p=packet(self.db)
        for offset in (8,24,40,56,72,88,104,120,128,136,144,176,208,224,256,len(p)-1):
            changed=bytearray(p);changed[offset]^=1;self.denied(bytes(changed))
        self.denied(packet(self.db,policy=bytes(32)))
        self.denied(packet(self.db,plan=bytes(32)))
        self.denied(legacy.packet(self.db))
        legacy.send(self.db,p)
        self.denied(legacy.sign(p[:144]+bytes([1])*32+p[176:-64]))
        for change in ({"plan":bytes(32)},{"wire":bytes(32)}):
            with self.assertRaises(ldb.LdbError):read(self.db,query(p,**change))

    def test_03_native_before_after_contract_and_cancel(self):
        for name in ("before_hash","after_hash"):
            p=packet(self.db,**{name:bytes(32)})
            self.denied(p);q=query(p);self.assertEqual(verify(q,read(self.db,q)),(3,0))

    def test_04_native_parent_inverse_and_foreign_ABA(self):
        before=legacy.snapshot(self.db)["values"];p=packet(self.db,{"displayName":b"Parent-Owned"});legacy.send(self.db,p)
        inverse={a:bytes.fromhex(v[0]) if v else b"" for a,v in before.items()}
        child=packet(self.db,inverse,parent=p[8:24]);legacy.send(self.db,child)
        q=query(child);r=read(self.db,q);self.assertEqual(verify(q,r)[0],2);self.assertEqual(r[265:281],p[8:24])
        self.assertEqual(legacy.snapshot(self.db)["values"],before)
        p=packet(self.db,{"displayName":b"Parent-ABA"});legacy.send(self.db,p)
        modify(self.root,self.pins["target_dn"],{"displayName":[b"External"]});modify(self.root,self.pins["target_dn"],{"displayName":[b"Parent-ABA"]})
        self.denied(packet(self.db,inverse,parent=p[8:24]))
        self.denied(packet(self.db,parent=uuid.uuid4().bytes))

    def test_05_status_authentication_context_and_bounds(self):
        p=packet(self.db);legacy.send(self.db,p);q=query(p)
        for changed in (q[:-1],bytes(312),q+b"x"):
            with self.assertRaises(ldb.LdbError):read(self.db,changed)
        for field in ("domain","dc","target","actor","nonce","policy","scope"):
            size=32 if field in ("policy","scope") else 16
            with self.assertRaises(ldb.LdbError):read(self.db,query(p,**{field:bytes(size)}))
        for extra in ({"expires":int(time.time())},{"expires":int(time.time())+60},{"issued":int(time.time())+30}):
            with self.assertRaises(ldb.LdbError):read(self.db,query(p,**extra))
        for db in (legacy.connection("operator"),self.root):
            with self.assertRaises(ldb.LdbError):read(db,q)
        credentials=Credentials();credentials.set_anonymous()
        anonymous=SamDB(url=self.data["Config"]["URL"],lp=loadparm(),credentials=credentials)
        with self.assertRaises(ldb.LdbError):read(anonymous,q)
        with self.assertRaises(ldb.LdbError):read(self.db,q,scope=ldb.SCOPE_SUBTREE)
        with self.assertRaises(ldb.LdbError):read(self.db,q,attrs=["*"])

    def test_06_fresh_role_and_writer_status_for_receipts(self):
        p=packet(self.db);legacy.send(self.db,p);q=query(p)
        group=one(self.root,self.data["Config"]["OperatorGroupDN"],attrs=["member"]);members=list(group["member"])
        try:
            modify(self.root,group.dn,{"member":[]})
            with self.assertRaises(ldb.LdbError):read(self.db,q)
        finally:modify(self.root,group.dn,{"member":members})
        try:
            modify(self.root,self.data["Config"]["WriterDN"],{"userAccountControl":[b"514"]})
            with self.assertRaises(ldb.LdbError):read(self.db,q)
        finally:modify(self.root,self.data["Config"]["WriterDN"],{"userAccountControl":[b"512"]})
        self.assertEqual(verify(q,read(self.db,q))[0],2)

    def test_07_key_separation_unknown_and_signing_failure(self):
        self.assertNotEqual(bytes.fromhex(self.pins["public"])[12:],bytes.fromhex(self.pins["receipt_public"]))
        p=packet(self.db);q=query(p);before=legacy.snapshot(self.db);journal=pathlib.Path("/tmp/native-cas/journal.tdb").read_bytes()
        self.assertEqual(verify(q,read(self.db,q)),(0,0))
        self.assertEqual(before,legacy.snapshot(self.db));self.assertEqual(journal,pathlib.Path("/tmp/native-cas/journal.tdb").read_bytes())
        key=pathlib.Path("/tmp/native-cas/receipt.pem")
        try:
            key.chmod(0o644)
            with self.assertRaises(ldb.LdbError):read(self.db,q)
        finally:key.chmod(0o600)

    def test_08_journal_fence_and_terminal_consistency(self):
        p=packet(self.db);legacy.send(self.db,p);q=query(p)
        path="/tmp/native-cas/journal.tdb"
        before=legacy.snapshot(self.db);journal=pathlib.Path(path).read_bytes()
        with open(path,"rb") as fence:
            fcntl.flock(fence,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(ldb.LdbError):read(self.db,q)
            self.denied(packet(self.db))
        self.assertEqual(before,legacy.snapshot(self.db))
        self.assertEqual(journal,pathlib.Path(path).read_bytes())
        # Privileged corruption injection is a fixture probe, never a client API.
        # Every inconsistent terminal record must fail closed, not sign success.
        for prefix in (b"F",b"V"):
            key=prefix+p[8:24]
            db=tdb.Tdb(path,0,tdb.DEFAULT,os.O_RDWR);original=db[key];del db[key];db.close()
            try:
                with self.assertRaises(ldb.LdbError):read(self.db,q)
            finally:
                db=tdb.Tdb(path,0,tdb.DEFAULT,os.O_RDWR);db[key]=original;db.close()
        self.assertEqual(verify(q,read(self.db,q))[0],2)

    def test_99_uncertain_is_signed_but_never_replayed(self):
        p=packet(self.db,{"displayName":b"Protocol-Unclear"});fault=pathlib.Path("/tmp/native-cas/fault")
        try:
            fault.write_text("commit_ack_error",encoding="ascii");fault.chmod(0o600)
            with self.assertRaises(ldb.LdbError):legacy.send(self.db,p)
        finally:fault.unlink(missing_ok=True)
        q=query(p);self.assertEqual(verify(q,read(self.db,q)),(1,0))
        self.denied(p);self.denied(packet(self.db))
        q=query(p);self.assertEqual(verify(q,read(self.db,q)),(1,0))


def crash_trigger(case):
    if case not in ("before_commit","after_commit"):raise RuntimeError("invalid crash phase")
    db=legacy.connection();p=packet(db,{"displayName":b"Protocol-Crash"})
    pathlib.Path("/tmp/native-cas/v2-crash.json").write_text(json.dumps({"case":case,"payload":p.hex(),"before":legacy.snapshot(db)}),encoding="ascii")
    fault=pathlib.Path("/tmp/native-cas/fault");fault.write_text(case,encoding="ascii");fault.chmod(0o600)
    try:legacy.send(db,p)
    except ldb.LdbError:pass
    else:raise AssertionError("crash returned success")


def crash_verify():
    saved=json.loads(pathlib.Path("/tmp/native-cas/v2-crash.json").read_text(encoding="ascii"));p=bytes.fromhex(saved["payload"])
    db=legacy.connection();current=legacy.snapshot(db)
    if saved["case"]=="before_commit":assert current==saved["before"]
    else:assert current["values"]["displayName"]==[b"Protocol-Crash".hex()] and current["version"]!=saved["before"]["version"]
    q=query(p);assert verify(q,read(db,q))==(1,0)
    for attempt in (p,packet(db)):
        try:legacy.send(db,attempt)
        except ldb.LdbError:pass
        else:raise AssertionError("uncertain replay")
        assert legacy.snapshot(db)==current
    root=SamDB(url=DB,lp=loadparm(),session_info=auth.system_session(loadparm()))
    modify(root,legacy.pins()["target_dn"],{a:[bytes.fromhex(v) for v in values] for a,values in saved["before"]["values"].items()})
    assert legacy.snapshot(db)["values"]==saved["before"]["values"]
    q=query(p);assert verify(q,read(db,q))==(1,0)
    print("Protocol2 "+saved["case"]+": signed uncertainty after actual DC restart, no replay, exact fixture restoration",flush=True)


if __name__=="__main__":
    if len(sys.argv)==3 and sys.argv[1]=="crash-trigger":crash_trigger(sys.argv[2])
    elif sys.argv[1:]==["crash-verify"]:crash_verify()
    else:unittest.main(verbosity=2)
