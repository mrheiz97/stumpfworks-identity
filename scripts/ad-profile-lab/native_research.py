"""Real LDAP requests executed by the compiled module inside the synthetic DC."""
import json
import multiprocessing
import os
import pathlib
import re
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

import ldb
import tdb
from samba import auth
from samba.credentials import Credentials, DONT_USE_KERBEROS
from samba.samdb import SamDB

from broker_candidate import DB, FIELDS, fixture, loadparm, modify, one, text

ATTRIBUTE = "identityLabCAS"


def pins():
    return json.loads(pathlib.Path("/tmp/native-cas/pins.json").read_text(encoding="ascii"))


def connection(username="writer", password=None):
    data=fixture(); lp=loadparm(); credentials=Credentials();credentials.guess(lp)
    credentials.set_bind_dn(data["Config"]["WriterDN"] if username=="writer" else "CN="+username+",OU=Outside,"+data["Config"]["BaseDN"])
    credentials.set_password(password or data["Password"]); credentials.set_kerberos_state(DONT_USE_KERBEROS)
    return SamDB(url=data["Config"]["URL"], lp=lp, credentials=credentials)


def snapshot(db):
    row=one(db,pins()["target_dn"],attrs=list(FIELDS)+["uSNChanged"])
    return {"values":{a:[bytes(v).hex() for v in row.get(a,[])] for a in FIELDS},"version":int(text(row,"uSNChanged"))}


def sign(body):
    with tempfile.TemporaryDirectory(prefix="native-sign-") as directory:
        path=directory+"/body";pathlib.Path(path).write_bytes(body)
        return body+subprocess.check_output(["openssl","pkeyutl","-sign","-inkey","/tmp/native-cas/issuer.pem","-rawin","-in",path])


def packet(db, changes=None, **overrides):
    data=fixture();p=pins();now=int(time.time())
    # Trusted synthetic issuer authenticates the fixed actor before signing.
    # The native server never accepts a password or a client-created token.
    actor=connection("operator")
    row=one(actor,p["actor_dn"],attrs=["objectSid"])
    if bytes(row["objectSid"][0]).hex()!=p["actor_sid"]:raise RuntimeError("issuer actor mismatch")
    request=dict(id=uuid.uuid4().bytes,domain=bytes.fromhex(data["Config"]["DomainGUID"]),
        dc=bytes.fromhex(data["Config"]["DCIdentity"]),target=bytes.fromhex(p["target_guid"]),
        actor=bytes.fromhex(p["actor_guid"]),writer=bytes.fromhex(p["writer_guid"]),
        group=bytes.fromhex(data["Config"]["OperatorGroupGUID"]),version=snapshot(db)["version"],issued=now,expires=now+60)
    request.update(overrides)
    body=b"SWCAS001"+b"".join(request[k] for k in ("id","domain","dc","target","actor","writer","group"))
    body+=struct.pack(">QQQ",request["version"],request["issued"],request["expires"])
    changes={"displayName":b"Native-Lab"} if changes is None else changes
    for field in FIELDS:
        value=changes.get(field)
        body+=b"\xff\xff" if value is None else struct.pack(">H",len(value))+value
    return sign(body)


def send(db, payload, dn=None, controls=None, extra=None):
    msg=ldb.Message();msg.dn=ldb.Dn(db,dn or pins()["target_dn"])
    msg[ATTRIBUTE]=ldb.MessageElement([payload],ldb.FLAG_MOD_REPLACE,ATTRIBUTE)
    if extra:
        msg["description"]=ldb.MessageElement([b"forbidden"],ldb.FLAG_MOD_REPLACE,"description")
    db.modify(msg, controls=controls)


def tlv(tag, value):
    n=len(value)
    length=bytes([n]) if n<128 else bytes([0x82])+struct.pack(">H",n)
    return bytes([tag])+length+value


def raw_modify(payload, control):
    """Test actual LDAP controls: remote SamDB's wrapper can omit controls."""
    data=fixture()
    context=ssl.create_default_context(cafile=data["Config"]["CAFile"])
    def exact(stream,n):
        value=b""
        while len(value)<n:
            chunk=stream.recv(n-len(value))
            if not chunk:raise RuntimeError("truncated LDAP response")
            value+=chunk
        return value
    def take(value,offset=0):
        tag=value[offset];length=value[offset+1];offset+=2
        if length&128:
            count=length&127
            if not 0<count<=2:raise RuntimeError("unbounded test BER")
            length=int.from_bytes(value[offset:offset+count],"big");offset+=count
        end=offset+length
        if end>len(value):raise RuntimeError("truncated test BER")
        return tag,value[offset:end],end
    def result(stream,expected):
        header=exact(stream,2)
        if header[0]!=0x30:raise RuntimeError("unexpected LDAP envelope")
        length=header[1]
        if length&128:
            count=length&127
            if not 0<count<=2:raise RuntimeError("unbounded test response")
            length=int.from_bytes(exact(stream,count),"big")
        if length>16384:raise RuntimeError("oversized test response")
        value=exact(stream,length)
        _,_,offset=take(value);tag,body,_=take(value,offset)
        if tag!=expected:raise RuntimeError("unexpected LDAP operation")
        tag,code,_=take(body)
        if tag!=0x0a:raise RuntimeError("missing LDAP result")
        return int.from_bytes(code,"big")
    with socket.create_connection(("dc1.profile.test",636),timeout=3) as tcp:
        with context.wrap_socket(tcp,server_hostname="dc1.profile.test") as stream:
            bind=tlv(0x02,b"\x03")+tlv(0x04,data["Config"]["WriterDN"].encode())+tlv(0x80,data["Password"].encode())
            stream.sendall(tlv(0x30,tlv(0x02,b"\x01")+tlv(0x60,bind)))
            if result(stream,0x61)!=0:raise RuntimeError("raw laboratory bind failed")
            change=tlv(0x30,tlv(0x0a,b"\x02")+tlv(0x30,tlv(0x04,ATTRIBUTE.encode())+tlv(0x31,tlv(0x04,payload))))
            operation=tlv(0x66,tlv(0x04,pins()["target_dn"].encode())+tlv(0x30,change))
            controls=tlv(0xa0,tlv(0x30,tlv(0x04,control.encode())+tlv(0x01,b"\xff")))
            stream.sendall(tlv(0x30,tlv(0x02,b"\x02")+operation+controls))
            return result(stream,0x67)


def status(payload):
    journal=tdb.Tdb("/tmp/native-cas/journal.tdb",0,tdb.DEFAULT,os.O_RDONLY)
    try:
        value=journal.get(b"O"+payload[8:24]);return value[-1] if value else None
    finally:
        journal.close()


def racer(payload, ready, start, output):
    db=connection();ready.set()
    if not start.wait(10):raise RuntimeError("missing race barrier")
    try:
        send(db,payload);output.put("success")
    except ldb.LdbError as error:
        output.put(error.args[0])


def external_admin(ready,start,entered,done,output):
    data=fixture();credentials=Credentials();credentials.guess(loadparm())
    credentials.set_bind_dn("CN=Administrator,CN=Users,"+data["Config"]["BaseDN"])
    credentials.set_password(data["Password"]);credentials.set_kerberos_state(DONT_USE_KERBEROS)
    db=SamDB(url=data["Config"]["URL"],lp=loadparm(),credentials=credentials)
    ready.set()
    if not start.wait(10):raise RuntimeError("missing external writer barrier")
    entered.set();modify(db,pins()["target_dn"],{"displayName":[b"External-After-Native"]})
    done.set();output.put("external-complete")


class NativeResearch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=fixture();cls.pins=pins()
        cls.root=SamDB(url=DB,lp=loadparm(),session_info=auth.system_session(loadparm()))
        cls.original=one(cls.root,cls.pins["target_dn"],attrs=list(FIELDS))
        cls.values={a:list(cls.original.get(a,[])) for a in FIELDS}

    @classmethod
    def tearDownClass(cls):
        modify(cls.root,cls.pins["target_dn"],cls.values)
        row=one(cls.root,cls.pins["target_dn"],attrs=list(FIELDS))
        assert all(list(row.get(a,[]))==cls.values[a] for a in FIELDS)
        print("Native operation: four original values restored; USN/history retained",flush=True)

    def setUp(self):
        self.db=connection()

    def denied(self,payload,db=None,**kwargs):
        before=snapshot(self.db)
        with self.assertRaises(ldb.LdbError):send(db or self.db,payload,**kwargs)
        self.assertEqual(before,snapshot(self.db))

    def test_01_real_LDAPS_native_success_inverse_replay(self):
        before=snapshot(self.db)
        payload=packet(self.db,{"displayName":b"Native-Success","givenName":b"Native","sn":b"Test","mail":b"native@profile.test"})
        send(self.db,payload)
        self.assertEqual(status(payload),2)
        after=snapshot(self.db);self.assertNotEqual(before["version"],after["version"])
        send(connection(),payload);self.assertEqual(after,snapshot(self.db))
        inverse=packet(self.db,{k:bytes.fromhex(v[0]) if v else b"" for k,v in before["values"].items()})
        send(self.db,inverse);self.assertEqual(before["values"],snapshot(self.db)["values"])

    def test_02_tamper_signature_and_fixed_bindings(self):
        payload=packet(self.db)
        for offset in (0,8,24,40,56,72,88,104,120,128,136,146,len(payload)-1):
            changed=bytearray(payload);changed[offset]^=1;self.denied(bytes(changed))
        for field in ("domain","dc","target","actor","writer","group"):
            self.denied(packet(self.db,**{field:bytes(16)}))
        send(self.db,payload)
        self.denied(packet(self.db,{"givenName":b"Rebound"},id=payload[8:24]))

    def test_03_parser_bounds_no_extra_attributes_or_controls(self):
        for value in (b"",b"x"*1025,packet(self.db)[:-1],packet(self.db,{"displayName":b"\x00"}),packet(self.db,{"displayName":b"x"*257}),packet(self.db,{})):
            self.denied(value)
        payload=packet(self.db)
        self.denied(payload,extra=True)
        before=snapshot(self.db)
        self.assertEqual(raw_modify(payload,"1.2.840.113556.1.4.1413"),53)
        self.assertEqual(before,snapshot(self.db))
        self.denied(payload,dn=self.data["Config"]["WriterDN"])

    def test_04_fresh_actor_role_writer_and_protected_target(self):
        payload=packet(self.db)
        group=one(self.root,self.data["Config"]["OperatorGroupDN"],attrs=["member"])
        members=list(group.get("member",[]))
        try:
            modify(self.root,group.dn,{"member":[]});self.denied(payload)
        finally:modify(self.root,group.dn,{"member":members})
        for dn,field,value in ((self.data["Config"]["WriterDN"],"userAccountControl",[b"514"]),(self.pins["target_dn"],"servicePrincipalName",[b"host/native.profile.test"])):
            row=one(self.root,dn,attrs=[field]);old=list(row.get(field,[]))
            try:modify(self.root,dn,{field:value});self.denied(packet(self.db))
            finally:modify(self.root,dn,{field:old})
        self.denied(packet(self.db),db=connection("operator"))
        self.denied(packet(self.db),db=self.root)
        try:
            self.root.add_remove_group_members("Domain Admins",["Profile Operators"],add_members_operation=True)
            self.denied(packet(self.db))
        finally:self.root.add_remove_group_members("Domain Admins",["Profile Operators"],add_members_operation=False)

    def test_05_stale_ABA_and_other_attribute(self):
        payload=packet(self.db)
        row=one(self.root,self.pins["target_dn"],attrs=["displayName","givenName"])
        values={a:list(row.get(a,[])) for a in ("displayName","givenName")}
        modify(self.root,row.dn,{"displayName":[b"ABA-temp"]});modify(self.root,row.dn,values)
        self.denied(payload);self.assertEqual(status(payload),3)
        payload=packet(self.db);modify(self.root,row.dn,{"givenName":[b"Other-field"]})
        self.denied(payload);modify(self.root,row.dn,values)

    def test_06_current_backend_ACL(self):
        from samba.dcerpc import security
        from samba.ndr import ndr_pack,ndr_unpack
        row=one(self.root,self.pins["target_dn"],attrs=["nTSecurityDescriptor"])
        original=bytes(row["nTSecurityDescriptor"][0]);descriptor=ndr_unpack(security.descriptor,original)
        domain=security.dom_sid(self.data["Config"]["DomainSID"])
        sddl=descriptor.as_sddl(domain)
        schema=one(self.root,self.root.get_schema_basedn(),"(lDAPDisplayName=displayName)",attrs=["schemaIDGUID"],scope=ldb.SCOPE_SUBTREE)
        allowed=str(uuid.UUID(bytes_le=bytes(schema["schemaIDGUID"][0]))).lower()
        restricted=re.sub(r"\([^()]*;"+re.escape(self.data["BrokerWriterSID"])+r"\)",
            lambda match:match.group(0) if allowed in match.group(0).lower() else "",sddl)
        self.assertNotEqual(sddl,restricted)
        payload=None
        try:
            modify(self.root,row.dn,{"nTSecurityDescriptor":[ndr_pack(security.descriptor.from_sddl(restricted,domain))]})
            payload=packet(self.db,{"displayName":b"Allowed-first-field","mail":b"denied@profile.test"})
            before=snapshot(self.db)
            with self.assertRaises(ldb.LdbError) as error:send(self.db,payload)
            self.assertEqual(error.exception.args[0],50);self.assertEqual(before,snapshot(self.db));self.assertEqual(status(payload),3)
        finally:
            modify(self.root,row.dn,{"nTSecurityDescriptor":[original]})
        self.assertEqual(bytes(one(self.root,row.dn,attrs=["nTSecurityDescriptor"])["nTSecurityDescriptor"][0]),original)
        send(self.db,packet(self.db))

    def test_07_two_authenticated_LDAP_clients_one_winner(self):
        context=multiprocessing.get_context("spawn");start=context.Event();output=context.Queue()
        ready=[context.Event(),context.Event()]
        payloads=[packet(self.db,{"displayName":value}) for value in (b"Race-One",b"Race-Two")]
        processes=[context.Process(target=racer,args=(payloads[i],ready[i],start,output)) for i in range(2)]
        for process in processes:process.start()
        self.assertTrue(all(event.wait(10) for event in ready));start.set()
        results=[output.get(timeout=10),output.get(timeout=10)]
        for process in processes:process.join(10);self.assertEqual(process.exitcode,0)
        self.assertEqual(results.count("success"),1)
        self.assertTrue(all(r in ("success",5,51) for r in results),results)
        self.denied(packet(self.db,version=int.from_bytes(payloads[0][120:128],"big")))

    def test_08_expiry_and_audit_without_values(self):
        now=int(time.time())
        for args in ({"expires":now},{"issued":now+30},{"expires":now+120}):self.denied(packet(self.db,**args))
        payload=packet(self.db,{"displayName":b"Do-not-log-native-value"});send(self.db,payload)
        journal=tdb.Tdb("/tmp/native-cas/journal.tdb",0,tdb.DEFAULT,os.O_RDONLY)
        try:
            self.assertIsNotNone(journal.get(b"C"+payload[8:24]));self.assertEqual(journal.get(b"F"+payload[8:24]),b"\x02")
            for key in journal.keys():self.assertNotIn(b"Do-not-log-native-value",journal.get(key))
        finally:journal.close()

    def test_09_deadline_inside_transaction(self):
        now=int(time.time());payload=packet(self.db,issued=now,expires=now+2)
        fault=pathlib.Path("/tmp/native-cas/fault");fault.write_text("expire_before_modify",encoding="ascii");fault.chmod(0o600)
        try:self.denied(payload)
        finally:fault.unlink()
        self.assertEqual(status(payload),3,"must have passed initial expiry check and reached durable claim")

    def test_10_writer_cannot_bypass_operation_with_plain_modify(self):
        before=snapshot(self.db)
        with self.assertRaises(ldb.LdbError) as error:
            modify(self.db,self.pins["target_dn"],{"displayName":[b"Bypass"]})
        self.assertEqual(error.exception.args[0],53);self.assertEqual(before,snapshot(self.db))
        newdn="CN=native-bypass,"+self.data["Config"]["ManagedOU"]
        msg=ldb.Message.from_dict(self.db,{"dn":newdn,"objectClass":[b"person"],"cn":[b"native-bypass"],"sn":[b"Bypass"]})
        for operation in (lambda:self.db.add(msg),lambda:self.db.delete(self.pins["target_dn"]),
                          lambda:self.db.rename(self.pins["target_dn"],newdn)):
            with self.assertRaises(ldb.LdbError) as error:operation()
            self.assertEqual(error.exception.args[0],53)
            self.assertEqual(before,snapshot(self.db))

    def test_14_bounded_parser_corpus(self):
        # Deterministic truncation/length corpus plus unpredictable invalid
        # signatures. Fixed size/count; this is not a claim of exhaustive fuzzing.
        valid=packet(self.db)
        corpus=[valid[:n] for n in (1,7,23,119,143,144,151,152,215,len(valid)-65)]
        corpus += [sign(valid[:144]+struct.pack(">H",n)+b"x"*8) for n in (0,1,257,65534,65535)]
        corpus += [os.urandom(n) for n in (216,300,1024)]
        for payload in corpus:self.denied(payload)

    def test_15_account_restrictions_after_signed_proof(self):
        for dn in (self.pins["actor_dn"],self.data["Config"]["WriterDN"]):
            for field,value in (("lockoutTime",str((int(time.time())+11644473600)*10000000).encode()),("accountExpires",b"1")):
                payload=packet(self.db)
                row=one(self.root,dn,attrs=[field]);original=list(row.get(field,[]))
                try:
                    modify(self.root,dn,{field:[value]});self.denied(payload)
                finally:modify(self.root,dn,{field:original})

    def test_16_existing_external_LDAP_writer_waits_for_native_commit(self):
        context=multiprocessing.get_context("spawn")
        native_ready=context.Event();native_start=context.Event();output=context.Queue()
        ready=context.Event();start=context.Event();entered=context.Event();done=context.Event()
        payload=packet(self.db)
        native=context.Process(target=racer,args=(payload,native_ready,native_start,output))
        external=context.Process(target=external_admin,args=(ready,start,entered,done,output))
        fault=pathlib.Path("/tmp/native-cas/fault");holding=pathlib.Path("/tmp/native-cas/holding")
        try:
            external.start();native.start()
            self.assertTrue(ready.wait(10));self.assertTrue(native_ready.wait(10))
            fault.write_text("hold_before_modify",encoding="ascii");fault.chmod(0o600);native_start.set()
            deadline=time.monotonic()+5
            while not holding.exists() and time.monotonic()<deadline:time.sleep(0.01)
            self.assertTrue(holding.exists());start.set();self.assertTrue(entered.wait(3))
            self.assertFalse(done.wait(0.25),"external writer completed during native DSDB transaction")
            self.assertCountEqual([output.get(timeout=10),output.get(timeout=10)],["success","external-complete"])
            for process in (native,external):process.join(10);self.assertEqual(process.exitcode,0)
            self.assertEqual(snapshot(self.db)["values"]["displayName"],[b"External-After-Native".hex()])
        finally:
            for process in (native,external):
                if process.is_alive():process.kill();process.join(5)
            fault.unlink(missing_ok=True);holding.unlink(missing_ok=True)

    def test_11_target_scope_move_is_denied(self):
        original=self.pins["target_dn"]
        outside="CN=casprobe,OU=Outside,"+self.data["Config"]["BaseDN"]
        payload=packet(self.db)
        original_values=snapshot(self.db)["values"]
        try:
            self.root.rename(original,outside)
            before=one(self.root,outside,attrs=list(FIELDS)+["uSNChanged"])
            with self.assertRaises(ldb.LdbError):send(self.db,payload)
            row=one(self.root,outside,attrs=list(FIELDS)+["uSNChanged"])
            self.assertEqual(text(row,"uSNChanged"),text(before,"uSNChanged"))
            self.assertEqual({a:[bytes(v).hex() for v in row.get(a,[])] for a in FIELDS},original_values)
            self.assertIsNone(status(payload))
        finally:self.root.rename(outside,original)

    def test_12_anonymous_and_wrong_password(self):
        credentials=Credentials();credentials.set_anonymous()
        anonymous=SamDB(url=self.data["Config"]["URL"],lp=loadparm(),credentials=credentials)
        self.denied(packet(self.db),db=anonymous)
        with self.assertRaises(ldb.LdbError) as error:connection(password="wrong-native-lab-password")
        self.assertEqual(error.exception.args[0],49)

    def test_13_insecure_journal_fails_closed(self):
        path=pathlib.Path("/tmp/native-cas/journal.tdb");payload=packet(self.db)
        try:path.chmod(0o644);self.denied(payload)
        finally:path.chmod(0o600)
        self.assertIsNone(status(payload))

    def test_99_commit_ack_error_blocks_all_new_ids(self):
        payload=packet(self.db,{"displayName":b"Native-Unclear"})
        fault=pathlib.Path("/tmp/native-cas/fault");fault.write_text("commit_ack_error",encoding="ascii");fault.chmod(0o600)
        try:
            with self.assertRaises(ldb.LdbError):send(self.db,payload)
        finally:fault.unlink()
        self.assertEqual(snapshot(self.db)["values"]["displayName"],[b"Native-Unclear".hex()])
        self.assertEqual(status(payload),1)
        self.denied(payload)
        self.denied(packet(self.db))


def crash_trigger(case):
    if case not in ("before_commit","after_commit"):raise RuntimeError("invalid lab crash case")
    db=connection();before=snapshot(db);payload=packet(db,{"displayName":b"Native-Actual-Crash"})
    pathlib.Path("/tmp/native-cas/crash.json").write_text(json.dumps({"before":before,"payload":payload.hex(),"case":case}),encoding="ascii")
    fault=pathlib.Path("/tmp/native-cas/fault");fault.write_text(case,encoding="ascii");fault.chmod(0o600)
    try:send(db,payload)
    except ldb.LdbError:pass
    else:raise AssertionError("native process crash unexpectedly returned success")
    if status(payload)!=1:raise AssertionError("crash must preserve applying")
    print("Native process interrupted at "+case+"; durable claim remains applying",flush=True)


def crash_verify():
    saved=json.loads(pathlib.Path("/tmp/native-cas/crash.json").read_text(encoding="ascii"))
    payload=bytes.fromhex(saved["payload"]);db=connection();current=snapshot(db)
    if saved["case"]=="before_commit":
        assert current==saved["before"],"precommit process death must roll back values AND version"
    else:
        assert current["values"]["displayName"]==[b"Native-Actual-Crash".hex()]
        assert current["version"]!=saved["before"]["version"]
    for attempt in (payload,packet(db)):
        try:send(db,attempt)
        except ldb.LdbError as error:assert error.args[0]==51,error
        else:raise AssertionError("uncertain target replayed after DC restart")
        assert snapshot(db)==current
    assert status(payload)==1
    root=SamDB(url=DB,lp=loadparm(),session_info=auth.system_session(loadparm()))
    original={a:[bytes.fromhex(v) for v in values] for a,values in saved["before"]["values"].items()}
    modify(root,pins()["target_dn"],original)
    assert snapshot(db)["values"]==saved["before"]["values"]
    assert status(payload)==1,"fixture restoration must never unlock or reconcile the claim"
    print("Native "+saved["case"]+": real DC restart, exact effect classification, no old/new-ID replay; fixture values restored, unclear claim retained",flush=True)


if __name__=="__main__":
    if len(sys.argv)==3 and sys.argv[1]=="crash-trigger":crash_trigger(sys.argv[2])
    elif sys.argv[1:]==["crash-verify"]:crash_verify()
    else:unittest.main(verbosity=2)
