"""Synthetic native Create tests. Privileged fixture access is never a client API."""
import hashlib
import fcntl
import json
import pathlib
import struct
import sys
import threading
import time
import unittest
import subprocess
import tempfile
import uuid
import ldb
import tdb
from samba import auth
from samba.samdb import SamDB
from broker_candidate import DB,fixture,loadparm,modify,one
import native_research as legacy

def packet(name,display=b"Created User",identifier=None,*,epoch=None,key=None,**replace):
    cfg=fixture()["Config"];pins=legacy.pins();now=int(time.time())
    fields=dict(id=identifier or uuid.uuid4().bytes,domain=bytes.fromhex(cfg["DomainGUID"]),dc=bytes.fromhex(cfg["DCIdentity"]),
        ou=bytes.fromhex(pathlib.Path("/tmp/native-cas/create-ou").read_text()),actor=bytes.fromhex(pins["actor_guid"]),
        writer=bytes.fromhex(pins["writer_guid"]),group=bytes.fromhex(cfg["OperatorGroupGUID"]),issued=now,expires=now+60,
        plan=hashlib.sha256(b"approved create plan"+name.encode()).digest(),policy=hashlib.sha256(cfg["Revision"].encode()).digest())
    fields.update(replace)
    body=(b"SWNEW001" if epoch is None else b"SWNEW002")+b"".join(fields[k] for k in ("id","domain","dc","ou","actor","writer","group"))
    body+=struct.pack(">QQ",fields["issued"],fields["expires"])+fields["plan"]+fields["policy"]
    if epoch is not None:body+=struct.pack(">Q",epoch)
    for value in (name.encode(),display):body+=struct.pack(">H",len(value))+value
    return legacy.sign(body) if key is None else legacy.sign(body,key)
def send(db,name,body,extra=None,outside=False):
    msg=ldb.Message();msg.dn=ldb.Dn(db,"CN="+name+","+("OU=Outside,"+fixture()["Config"]["BaseDN"] if outside else fixture()["Config"]["ManagedOU"]))
    msg["identityLabCreate"]=ldb.MessageElement([body],0,"identityLabCreate")
    for key,value in (extra or {}).items():msg[key]=ldb.MessageElement([value],0,key)
    db.add(msg)
def count(db,name):
    return db.search(base=fixture()["Config"]["BaseDN"],scope=ldb.SCOPE_SUBTREE,expression="(sAMAccountName="+ldb.binary_encode(name)+")",attrs=["objectGUID"])

def status(db,p,nonce=None,*,native_dir=pathlib.Path("/tmp/native-cas")):
    pins=json.loads((native_dir/"pins.json").read_text())
    version=b"2" if p[:8]==b"SWNEW002" else b"1"
    now=int(time.time());q=b"SWCSTAT"+version+p[8:24]+p[136:168]+hashlib.sha256(p[:-64]).digest()+(nonce or uuid.uuid4().bytes)+p[24:88]+p[168:200]+bytes.fromhex(pins["scope"])+struct.pack(">QQ",now,now+30)
    assert len(q)==248
    rows=db.search(base="CN=NativeCreateReceipt,"+fixture()["Config"]["BaseDN"],scope=ldb.SCOPE_BASE,
        expression="(identityLabCreateStatus="+legacy.sign(q,native_dir/"issuer.pem").hex()+")",attrs=["identityLabCreateReceipt"])
    assert len(rows)==1
    raw=bytes(rows[0]["identityLabCreateReceipt"][0]);assert len(raw)==430 and raw[:8]==b"SWCRECP"+version and raw[8:256]==q
    with tempfile.TemporaryDirectory() as path:
        for name,value in (("key",bytes.fromhex("302a300506032b6570032100")+bytes.fromhex(pins["receipt_public"])),("body",raw[:366]),("sig",raw[366:])):pathlib.Path(path+"/"+name).write_bytes(value)
        result=subprocess.run(["openssl","pkeyutl","-verify","-pubin","-keyform","DER","-inkey",path+"/key","-rawin","-in",path+"/body","-sigfile",path+"/sig"],capture_output=True,timeout=3)
        assert result.returncode==0
    issued,expires=struct.unpack(">QQ",raw[350:366]);assert issued<=int(time.time())<expires and expires-issued<=30
    if raw[256]!=2:assert raw[257:350]==bytes(93)
    return raw

class CreateResearch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.root=SamDB(url=DB,lp=loadparm(),session_info=auth.system_session(loadparm()))
    def setUp(self):self.db=legacy.connection()
    def denied(self,name,payload,**options):
        with self.assertRaises(ldb.LdbError):send(self.db,name,payload,**options)
        self.assertEqual(len(count(self.db,name)),0)
    def test_01_template_and_replay(self):
        p=packet("nativeone");send(self.db,"nativeone",p)
        row=one(self.db,"CN=nativeone,"+fixture()["Config"]["ManagedOU"],attrs=["objectGUID","objectSid","uSNChanged","userAccountControl","userPrincipalName","memberOf","servicePrincipalName"])
        self.assertEqual(bytes(row["userAccountControl"][0]),b"514")
        self.assertEqual(bytes(row["userPrincipalName"][0]),b"nativeone@profile.test")
        self.assertFalse(row.get("memberOf"));self.assertFalse(row.get("servicePrincipalName"))
        version=bytes(row["uSNChanged"][0]);send(self.db,"nativeone",p)
        self.assertEqual(version,bytes(one(self.db,row.dn,attrs=["uSNChanged"])["uSNChanged"][0]))
        with self.assertRaises(ldb.LdbError):send(self.db,"nativeone",packet("nativeone",identifier=p[8:24],display=b"Altered"))
    def test_02_signature_scope_shape_and_bounds(self):
        p=packet("invalidnew")
        for offset in (0,8,24,40,56,72,88,104,120,136,168,202,len(p)-1):
            q=bytearray(p);q[offset]^=1;self.denied("invalidnew",bytes(q))
        for field in ("domain","dc","ou","actor","writer","group","policy","plan"):
            self.denied("invalidnew",packet("invalidnew",**{field:bytes(32 if field in ("policy","plan") else 16)}))
        for extra in ({"expires":int(time.time())},{"expires":int(time.time())+120}):self.denied("invalidnew",packet("invalidnew",**extra))
        self.denied("invalidnew",p,extra={"userAccountControl":b"512"})
        self.denied("invalidnew",p,outside=True)
        for display in (b"",b"x"*257,b"bad\n",b"\xff"):self.denied("invalidnew",packet("invalidnew",display=display))
        self.denied("invalidnew",p[:-1]);self.denied("invalidnew",p+b"x")
    def test_03_external_sam_and_upn_conflicts(self):
        cfg=fixture()["Config"]
        self.root.add({"dn":"CN=foreign,"+cfg["ManagedOU"],"objectClass":"user","sAMAccountName":"foreignsam","userPrincipalName":"UPNCONFLICT@PROFILE.TEST","userAccountControl":"514"})
        self.denied("upnconflict",packet("upnconflict"))
        with self.assertRaises(ldb.LdbError):send(self.db,"foreignsam",packet("foreignsam"))
        self.assertEqual(len(count(self.db,"foreignsam")),1)
    def test_04_current_role_and_acl(self):
        cfg=fixture()["Config"];p=packet("revokednew")
        group=one(self.root,cfg["OperatorGroupDN"],attrs=["member"]);members=list(group["member"])
        try:
            modify(self.root,group.dn,{"member":[]});self.denied("revokednew",p)
        finally:modify(self.root,group.dn,{"member":members})
        ou=one(self.root,cfg["ManagedOU"],attrs=["nTSecurityDescriptor"]);descriptor=bytes(ou["nTSecurityDescriptor"][0])
        from samba.dcerpc import security
        from samba.ndr import ndr_pack,ndr_unpack
        sd=ndr_unpack(security.descriptor,descriptor)
        sd.dacl.aces=[a for a in sd.dacl.aces if str(a.trustee)!=fixture()["BrokerWriterSID"]]
        try:
            modify(self.root,ou.dn,{"nTSecurityDescriptor":[ndr_pack(sd)]});self.denied("revokednew",packet("revokednew"))
        finally:modify(self.root,ou.dn,{"nTSecurityDescriptor":[descriptor]})
    def test_05_concurrent_add(self):
        packets=[packet("raceuser"),packet("raceuser")];results=[];barrier=threading.Barrier(2)
        def run(p):
            db=legacy.connection();barrier.wait()
            try:send(db,"raceuser",p);results.append(True)
            except ldb.LdbError:results.append(False)
        threads=[threading.Thread(target=run,args=(p,)) for p in packets]
        for t in threads:t.start()
        for t in threads:t.join(10);self.assertFalse(t.is_alive())
        self.assertEqual(sorted(results),[False,True]);self.assertEqual(len(count(self.db,"raceuser")),1)
    def test_06_signed_own_identity_and_readonly_status(self):
        p=packet("receiptuser");unknown=status(self.db,p);self.assertEqual(unknown[256],0)
        send(self.db,"receiptuser",p);before=pathlib.Path("/tmp/native-cas/journal.tdb").read_bytes()
        r=status(self.db,p);self.assertEqual(r[256],2);self.assertNotEqual(r[257:265],bytes(8))
        self.assertEqual(before,pathlib.Path("/tmp/native-cas/journal.tdb").read_bytes())
        self.assertEqual(r[265:281],bytes(count(self.db,"receiptuser")[0]["objectGUID"][0]))
        # Ordinary names cannot establish ownership after foreign delete/recreate.
        dn="CN=receiptuser,"+fixture()["Config"]["ManagedOU"];self.root.delete(dn)
        self.root.add({"dn":dn,"objectClass":"user","sAMAccountName":"receiptuser","userAccountControl":"514"})
        self.assertNotEqual(r[265:281],bytes(count(self.db,"receiptuser")[0]["objectGUID"][0]))
        self.assertEqual(r[265:281],status(self.db,p)[265:281])
        with self.assertRaises(ldb.LdbError):status(self.db,p,bytes(16))
        with self.assertRaises(ldb.LdbError):status(legacy.connection("operator"),p)
    def test_07_receipt_fence_records_and_action_separation(self):
        p=packet("recorduser");send(self.db,"recorduser",p);path="/tmp/native-cas/journal.tdb"
        before=pathlib.Path(path).read_bytes()
        with open(path,"rb") as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(ldb.LdbError):status(self.db,p)
        self.assertEqual(before,pathlib.Path(path).read_bytes())
        for prefix in (b"A",b"B",b"C",b"F",b"N",b"V"):
            key=prefix+p[8:24];db=tdb.Tdb(path,0,tdb.DEFAULT,2);original=db[key];del db[key];db.close()
            try:
                with self.assertRaises(ldb.LdbError):status(self.db,p)
            finally:
                db=tdb.Tdb(path,0,tdb.DEFAULT,2);db[key]=original;db.close()
        import native_protocol_research as profile
        q=profile.query(p,plan=p[136:168],wire=hashlib.sha256(p[:-64]).digest())
        with self.assertRaises(ldb.LdbError):profile.read(self.db,q)
        self.assertEqual(status(self.db,p)[256],2)

    def test_08_fixed_dc_writer_effective_permissions(self):
        cfg=fixture()["Config"]
        name="fixedrights"
        send(self.db,name,packet(name))
        dn="CN="+name+","+cfg["ManagedOU"]
        attributes=["objectGUID","userAccountControl","userPrincipalName","memberOf",
                    "pwdLastSet","servicePrincipalName"]
        def snapshot():
            row=one(self.db,dn,attrs=attributes)
            return {attr:tuple(bytes(v) for v in row.get(attr,[])) for attr in attributes}
        before=snapshot()
        self.assertEqual(before["userAccountControl"],(b"514",))
        self.assertEqual(before["pwdLastSet"],(b"0",))
        for attr,value in (("userAccountControl",b"512"),("pwdLastSet",b"-1"),
                           ("unicodePwd",b'"\x00A\x00b\x001\x00!\x00"\x00'),
                           ("userPrincipalName",b"changed@profile.test"),
                           ("servicePrincipalName",b"HOST/changed.profile.test")):
            with self.subTest(attribute=attr),self.assertRaises(ldb.LdbError):
                modify(self.db,dn,{attr:[value]})
        with self.assertRaises(ldb.LdbError):
            modify(self.db,cfg["OperatorGroupDN"],{"member":[dn.encode()]})
        with self.assertRaises(ldb.LdbError):
            self.db.rename(dn,"CN=moved,OU=Outside,"+cfg["BaseDN"])
        with self.assertRaises(ldb.LdbError):
            self.db.delete(dn)
        for parent in (cfg["ManagedOU"],"OU=Outside,"+cfg["BaseDN"]):
            with self.assertRaises(ldb.LdbError):
                self.db.add({"dn":"CN=plainwriter,"+parent,"objectClass":"user",
                             "sAMAccountName":"plainwriter","userAccountControl":"514"})
        self.assertEqual(before,snapshot())
        self.assertFalse(count(self.db,"plainwriter"))

def crash_trigger(case):
    db=legacy.connection();p=packet("crashuser")
    pathlib.Path("/tmp/native-cas/create-crash.json").write_text(json.dumps({"case":case,"payload":p.hex()}))
    fault=pathlib.Path("/tmp/native-cas/fault");fault.write_text(case);fault.chmod(0o600)
    try:send(db,"crashuser",p)
    except ldb.LdbError:pass
    else:raise AssertionError("crash returned success")
def crash_verify():
    saved=json.loads(pathlib.Path("/tmp/native-cas/create-crash.json").read_text());p=bytes.fromhex(saved["payload"]);db=legacy.connection()
    assert len(count(db,"crashuser"))==(0 if saved["case"]=="before_commit" else 1)
    assert status(db,p)[256]==1
    for name,payload in (("crashuser",p),("freshuser",packet("freshuser"))):
        try:send(db,name,payload)
        except ldb.LdbError:pass
        else:raise AssertionError("uncertain create replay")
    assert not count(db,"freshuser")
    print("Create "+saved["case"]+": real DC restart; no replay or fresh-ID bypass; uncertain journal retained",flush=True)
if __name__=="__main__":
    if len(sys.argv)==3 and sys.argv[1]=="crash-trigger":crash_trigger(sys.argv[2])
    elif sys.argv[1:]==["crash-verify"]:crash_verify()
    else:unittest.main(verbosity=2)
